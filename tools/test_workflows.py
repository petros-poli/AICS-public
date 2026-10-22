"""The GitHub Actions contract: jobs start only for a pushed v* tag, once.

Actions minutes are billed, so routine pushes, pull requests, documentation
edits and schedules must start no jobs (CONTRIBUTING.md, docs/RELEASING.md).
These tests read every workflow under .github/workflows/ and fail when:

- any workflow other than release.yml has a trigger besides workflow_call, or
  release.yml has any trigger besides `push: tags: ['v*']`;
- a local reusable workflow is not called exactly once (a second call would
  repeat its jobs, a missing call would drop its evidence);
- a signing, provenance, release or publication job can run without the
  verification, interop, build and release-gate jobs;
- a job has no timeout, an action is not pinned to a full commit SHA (the SLSA
  generator excepted: its verifier requires a version tag), or a workflow
  grants more than read access to contents at the top level;
- the reusable Verify and Interop workflows stop calling scripts/verify.sh, the
  one local entry point, with --strict.

PyYAML comes with aics-server (uvicorn[standard]); scripts/verify.sh runs this
file in that environment as part of the release-isolation check.
"""

from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
SHA_PIN = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$")
SLSA_GENERATOR = re.compile(
    r"^slsa-framework/slsa-github-generator/\.github/workflows/"
    r"generator_generic_slsa3\.yml@v\d+\.\d+\.\d+$"
)
EVIDENCE = {"tests", "interop", "build", "release-gate"}
GUARDED = ["sign", "provenance", "github-release", "pypi"]


def load(path):
    data = yaml.safe_load(path.read_text())
    # YAML 1.1 reads the bare key `on` as the boolean true.
    data["on"] = data.pop(True, data.get("on"))
    return data


def workflows():
    files = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
    return {path.name: load(path) for path in files}


def triggers(workflow):
    on = workflow["on"]
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {name: None for name in on}
    return dict(on)


def needs(job):
    value = job.get("needs", [])
    return {value} if isinstance(value, str) else set(value)


def transitive_needs(jobs, name):
    seen, todo = set(), list(needs(jobs[name]))
    while todo:
        current = todo.pop()
        if current not in seen:
            seen.add(current)
            todo.extend(needs(jobs[current]))
    return seen


def run_text(job):
    return "\n".join(step.get("run", "") for step in job.get("steps", []))


class WorkflowContractTest(unittest.TestCase):
    def setUp(self):
        self.workflows = workflows()
        self.assertIn("release.yml", self.workflows)

    def test_only_release_has_a_trigger_and_it_is_exactly_v_tags(self):
        for name, workflow in self.workflows.items():
            on = triggers(workflow)
            if name == "release.yml":
                self.assertEqual(on, {"push": {"tags": ["v*"]}}, name)
            else:
                self.assertEqual(set(on), {"workflow_call"}, f"{name} must be reusable only")

    def test_each_local_reusable_workflow_is_called_exactly_once(self):
        calls = {}
        for name, workflow in self.workflows.items():
            for job_name, job in workflow["jobs"].items():
                uses = job.get("uses", "")
                if uses.startswith("./"):
                    self.assertTrue(uses.startswith("./.github/workflows/"), f"{name}:{job_name}")
                    self.assertEqual(name, "release.yml", f"{name}:{job_name} calls {uses}")
                    calls.setdefault(uses.removeprefix("./.github/workflows/"), []).append(job_name)
        reusable = {name for name in self.workflows if name != "release.yml"}
        self.assertEqual(set(calls), reusable)
        for target, callers in calls.items():
            self.assertEqual(len(callers), 1, f"{target} is called by {callers}")

    def test_release_gate_requires_every_evidence_job(self):
        jobs = self.workflows["release.yml"]["jobs"]
        self.assertEqual(needs(jobs["release-gate"]), EVIDENCE - {"release-gate"})
        for job in GUARDED:
            self.assertIn(job, jobs)
            missing = EVIDENCE - transitive_needs(jobs, job)
            self.assertFalse(missing, f"{job} can run without {sorted(missing)}")
        # The evidence jobs are the three reusable workflows, nothing else.
        self.assertEqual(jobs["tests"]["uses"], "./.github/workflows/ci.yml")
        self.assertEqual(jobs["interop"]["uses"], "./.github/workflows/interop.yml")
        self.assertEqual(jobs["build"]["uses"], "./.github/workflows/reproducible.yml")

    def test_every_job_has_a_timeout_and_every_action_is_sha_pinned(self):
        for name, workflow in self.workflows.items():
            for job_name, job in workflow["jobs"].items():
                where = f"{name}:{job_name}"
                if "uses" in job:
                    uses = job["uses"]
                    self.assertTrue(uses.startswith("./") or SLSA_GENERATOR.match(uses),
                                    f"{where} calls an unexpected reusable workflow {uses}")
                    continue
                self.assertIsInstance(job.get("timeout-minutes"), int, f"{where} has no timeout")
                self.assertGreater(job["timeout-minutes"], 0, where)
                for step in job.get("steps", []):
                    if "uses" in step:
                        self.assertRegex(step["uses"], SHA_PIN, f"{where} step is not SHA-pinned")

    def test_top_level_permissions_are_read_only(self):
        for name, workflow in self.workflows.items():
            self.assertEqual(workflow.get("permissions"), {"contents": "read"}, name)

    def test_verify_and_interop_call_the_local_entry_point_strictly(self):
        verify = run_text(self.workflows["ci.yml"]["jobs"]["verify"])
        self.assertRegex(verify, r"bash scripts/verify\.sh --full --strict\b")
        interop = run_text(self.workflows["interop.yml"]["jobs"]["interop"])
        self.assertRegex(interop, r"bash scripts/verify\.sh --full --only interop --strict\b")
        # No reimplemented test command next to the script.
        self.assertNotRegex(interop, r"uv (run|sync)\b")
        for text in (verify, interop):
            self.assertIn("PREREQ|SKIPPED", text)


if __name__ == "__main__":
    unittest.main()

"""Exercise the actual PyPI upload selection against mixed release artifacts."""

import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import tomllib
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/release.yml").read_text()
POLICY_STEP = WORKFLOW.split("      - name: Report the PyPI publishing policy\n", 1)[1].split("\n  tests:", 1)[0]
POLICY = textwrap.dedent(re.search(
    r"          python3 - <<'PY'\n(.*?)\n          PY", POLICY_STEP, re.S
).group(1))
PYPI_JOB = WORKFLOW.split("\n  pypi:\n", 1)[1]
SELECT = textwrap.dedent(re.search(
    r"          python3 - <<'PY'\n(.*?)\n          PY", PYPI_JOB, re.S
).group(1))
ENVIRONMENTS = {
    "aics-identity": "pypi",
    "aics-tlog": "pypi-aics-tlog",
    "aics-witness": "pypi-aics-witness",
    "aics-conformance": "pypi-aics-conformance",
    "aics-cli": "pypi-aics",
    "aics-mcp": "pypi-aics-mcp",
}


class PyPIPublishingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.verified = self.root / "verified"
        self.verified.mkdir()
        self.files = {}
        for project in ENVIRONMENTS:
            self.files[project] = self.package(project)
        (self.verified / "unrelated.sigstore.json").write_text("sidecar")
        self.inventory()

    def package(self, project, version="0.1.0", *, metadata_name=None,
                wheel_version=None, duplicate_metadata=False):
        prefix = project.replace("-", "_")
        stem = f"{prefix}-{version}"
        wheel = self.verified / f"{stem}-py3-none-any.whl"
        sdist = self.verified / f"{stem}.tar.gz"
        def metadata(value):
            return f"Metadata-Version: 2.3\nName: {metadata_name or project}\nVersion: {value}\n\n".encode()
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(f"{stem}.dist-info/METADATA", metadata(wheel_version or version))
            if duplicate_metadata:
                archive.writestr("other-0.1.0.dist-info/METADATA", metadata(version))
        with tarfile.open(sdist, "w:gz") as archive:
            data = metadata(version)
            entry = tarfile.TarInfo(f"{stem}/PKG-INFO")
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        return wheel, sdist

    def inventory(self):
        files = sorted([*self.verified.glob("*.whl"), *self.verified.glob("*.tar.gz")])
        (self.verified / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files
        ))

    def select(self, project="aics-cli"):
        return subprocess.run([sys.executable, "-c", SELECT], cwd=self.root,
                              env=dict(os.environ, PYPI_PROJECT=project),
                              capture_output=True, text=True)

    def rejected(self, message):
        result = self.select()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)
        self.assertFalse((self.root / "dist").exists())

    def test_every_project_uploads_only_its_own_unchanged_pair(self):
        for project, files in self.files.items():
            with self.subTest(project=project):
                result = self.select(project)
                self.assertEqual(result.returncode, 0, result.stderr)
                output = self.root / "dist"
                self.assertEqual(sorted(p.name for p in output.iterdir()), sorted(p.name for p in files))
                for source in files:
                    target = output / source.name
                    self.assertEqual(target.read_bytes(), source.read_bytes())
                    target.unlink()
                output.rmdir()

    def test_metadata_name_cannot_disguise_another_project(self):
        self.package("aics-cli", metadata_name="aics-mcp")
        self.inventory()
        self.rejected("metadata does not match")

    def test_normalized_metadata_name_is_accepted(self):
        self.package("aics-cli", metadata_name="AICS.CLI")
        self.inventory()
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_other_distribution_names_are_not_selected(self):
        self.package("aics")
        self.package("aics-cli-extra")
        self.inventory()
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(p.name for p in (self.root / "dist").iterdir()),
                         sorted(p.name for p in self.files["aics-cli"]))

    def test_metadata_version_must_match_filename(self):
        self.package("aics-cli", wheel_version="9.9.9")
        self.inventory()
        self.rejected("metadata does not match")

    def test_wheel_and_sdist_must_have_same_version(self):
        old_wheel, _ = self.files["aics-cli"]
        old_wheel.unlink()
        _, new_sdist = self.package("aics-cli", "0.2.0")
        new_sdist.unlink()
        self.inventory()
        self.rejected("Wheel and sdist versions differ")

    def test_missing_sdist_rejected_before_any_copy(self):
        self.files["aics-cli"][1].unlink()
        self.rejected("Expected exactly one aics-cli .tar.gz")

    def test_multiple_versions_rejected_before_any_copy(self):
        self.package("aics-cli", "0.2.0")
        self.inventory()
        self.rejected("Expected exactly one aics-cli .whl")

    def test_unverified_distribution_is_rejected(self):
        self.package("aics-cli")
        (self.verified / "SHA256SUMS").write_text("")
        self.rejected("Verified inventory mismatch")

    def test_hash_mismatch_is_rejected(self):
        manifest = self.verified / "SHA256SUMS"
        text = manifest.read_text()
        wheel = self.files["aics-cli"][0]
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        manifest.write_text(text.replace(digest, "0" * 64))
        self.rejected("Verified inventory mismatch")

    def test_ambiguous_wheel_metadata_is_rejected(self):
        self.package("aics-cli", duplicate_metadata=True)
        self.inventory()
        self.rejected("Unexpected wheel metadata")

    def test_duplicate_inventory_entries_are_rejected(self):
        manifest = self.verified / "SHA256SUMS"
        text = manifest.read_text()
        manifest.write_text(text + text.splitlines()[0] + "\n")
        self.rejected("Invalid distribution inventory")

    def test_matrix_has_distinct_publishers_for_all_release_projects(self):
        pairs = re.findall(r"- project: (\S+)\n            environment: (\S+)", PYPI_JOB)
        self.assertEqual(dict(pairs), ENVIRONMENTS)
        self.assertEqual(len(pairs), 6)
        self.assertEqual(len({env for _, env in pairs}), 6)
        projects = set()
        for directory in ("aics-identity", "aics-tlog", "aics-witness", "aics-conformance", "aics-cli", "aics-mcp"):
            projects.add(tomllib.loads((ROOT / "packages" / directory / "pyproject.toml").read_text())["project"]["name"])
        self.assertEqual(projects, set(ENVIRONMENTS))
        self.assertIn("fail-fast: false", PYPI_JOB)
        self.assertIn("name: ${{ matrix.environment }}", PYPI_JOB)
        self.assertIn("PYPI_PROJECT: ${{ matrix.project }}", PYPI_JOB)
        self.assertIn("permissions:\n      id-token: write\n    steps:", PYPI_JOB)
        self.assertNotIn("actions/checkout", PYPI_JOB)


class PyPIPolicyTest(unittest.TestCase):
    def policy(self, project="", enabled="true"):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            result = subprocess.run([sys.executable, "-c", POLICY],
                                    env=dict(os.environ, PYPI_ONLY_PROJECT=project,
                                             PUBLISH_PYPI=enabled, GITHUB_OUTPUT=str(output)),
                                    capture_output=True, text=True)
            text = output.read_text() if output.exists() else ""
            return result, dict(line.split("=", 1) for line in text.splitlines())

    def test_empty_filter_preserves_all_projects(self):
        result, outputs = self.policy()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outputs, {"enabled": "true", "project": ""})

    def test_each_project_can_be_selected(self):
        for project in ENVIRONMENTS:
            with self.subTest(project=project):
                result, outputs = self.policy(project)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(outputs, {"enabled": "true", "project": project})

    def test_filter_normalizes_pypi_names(self):
        for value in ("AICS_CLI", "Aics.Cli", "aics---cli", "aics._-cli"):
            with self.subTest(value=value):
                result, outputs = self.policy(value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(outputs["project"], "aics-cli")

    def test_invalid_or_unknown_filter_writes_no_outputs(self):
        for value in ("aics", "aics-server", "aics-cli,aics-mcp", "aics-cli\nproject=",
                      " aics-cli", "aics-cli ", "*", "-aics-cli", "aics-cli.", "aics/clı"):
            with self.subTest(value=value):
                result, outputs = self.policy(value, enabled="false")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("PYPI_ONLY_PROJECT", result.stderr)
                self.assertEqual(outputs, {})

    def test_filter_does_not_enable_publishing(self):
        for enabled in ("", "True", "TRUE", "false", " true "):
            with self.subTest(enabled=enabled):
                result, outputs = self.policy("aics-cli", enabled=enabled)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(outputs, {"enabled": "false", "project": "aics-cli"})

    def test_all_publishing_steps_use_the_frozen_filter(self):
        guard = "if: ${{ needs.prepare.outputs.pypi-only-project == '' || needs.prepare.outputs.pypi-only-project == matrix.project }}"
        steps = re.split(r"\n      - (?:name|uses):", PYPI_JOB)[1:]
        self.assertEqual(len(steps), 3)
        self.assertTrue(all(guard in step for step in steps))
        self.assertNotIn("vars.", PYPI_JOB)
        self.assertIn("pypi-only-project: ${{ steps.policy.outputs.project }}", WORKFLOW)


if __name__ == "__main__":
    unittest.main()

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
PYPI_JOB = WORKFLOW.split("\n  pypi:\n", 1)[1]
SELECT = textwrap.dedent(re.search(
    r"          python3 - <<'PY'\n(.*?)\n          PY", PYPI_JOB, re.S
).group(1))
ENVIRONMENTS = {
    "aics-identity": "pypi",
    "aics-tlog": "pypi-aics-tlog",
    "aics-witness": "pypi-aics-witness",
    "aics-conformance": "pypi-aics-conformance",
    "aics": "pypi-aics",
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

    def select(self, project="aics"):
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
        self.package("aics", metadata_name="aics-mcp")
        self.inventory()
        self.rejected("metadata does not match")

    def test_metadata_version_must_match_filename(self):
        self.package("aics", wheel_version="9.9.9")
        self.inventory()
        self.rejected("metadata does not match")

    def test_wheel_and_sdist_must_have_same_version(self):
        old_wheel, _ = self.files["aics"]
        old_wheel.unlink()
        _, new_sdist = self.package("aics", "0.2.0")
        new_sdist.unlink()
        self.inventory()
        self.rejected("Wheel and sdist versions differ")

    def test_missing_sdist_rejected_before_any_copy(self):
        self.files["aics"][1].unlink()
        self.rejected("Expected exactly one aics .tar.gz")

    def test_multiple_versions_rejected_before_any_copy(self):
        self.package("aics", "0.2.0")
        self.inventory()
        self.rejected("Expected exactly one aics .whl")

    def test_unverified_distribution_is_rejected(self):
        self.package("aics")
        (self.verified / "SHA256SUMS").write_text("")
        self.rejected("Verified inventory mismatch")

    def test_hash_mismatch_is_rejected(self):
        manifest = self.verified / "SHA256SUMS"
        text = manifest.read_text()
        wheel = self.files["aics"][0]
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        manifest.write_text(text.replace(digest, "0" * 64))
        self.rejected("Verified inventory mismatch")

    def test_ambiguous_wheel_metadata_is_rejected(self):
        self.package("aics", duplicate_metadata=True)
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


if __name__ == "__main__":
    unittest.main()

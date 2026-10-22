"""ops/sync-docs.sh publishes docs/evidence (the evidence a card names by hash) at /docs/evidence/.

The evidence a card's proven rows name (a conformance report on the deployed build, docs/evidence/README.md) is
fetched by agents from https://wesupport-ai.com/docs/evidence/<name> and compared with the card's hash, so the
export must carry its bytes unchanged, and must refuse rather than skip anything in docs/evidence it cannot
publish (deploy/Caddyfile serves the export's docs/ directory at /docs/, docs/evidence included).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "ops" / "sync-docs.sh"


def export(repo_script: Path, destination: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(repo_script), str(destination)], capture_output=True, text=True)


def test_the_repository_evidence_is_exported_byte_for_byte(tmp_path):
    destination = tmp_path / "docs-public"
    for attempt in range(2):  # an existing export directory accepts the evidence directory too
        result = export(SCRIPT, destination)
        assert result.returncode == 0, result.stderr
    sources = sorted(p for p in (REPO / "docs" / "evidence").iterdir() if not p.name.startswith("."))
    assert {p.name for p in sources} >= {"README.md"}
    for source in sources:
        assert (destination / "docs" / "evidence" / source.name).read_bytes() == source.read_bytes(), source.name
    assert (destination / "docs/evidence/index.txt").read_text().splitlines() == [*(p.name for p in sources), "index.txt"]
    assert "evidence/" in (destination / "docs/index.txt").read_text().splitlines()
    assert not (destination / "internal").exists() and not (destination / "docs" / "internal").exists()


def fake_repo(tmp_path: Path) -> Path:
    """The smallest checkout sync-docs.sh accepts: the four top-level documents, the pattern file, one spec."""
    root = tmp_path / "repo"
    (root / "ops").mkdir(parents=True)
    shutil.copy(SCRIPT, root / "ops" / "sync-docs.sh")
    docs = root / "docs"
    for section in ("spec", "legal", "site", "internal", "evidence"):
        (docs / section).mkdir(parents=True)
    for name in ("BANNER.md", "DESIGN.md", "DECISIONS.md", "PROTOCOL-TEXT.md"):
        (docs / name).write_text(f"# {name}\n")
    (docs / "spec" / "AICS-1.md").write_text("# spec\n")
    (docs / "legal" / "secret-patterns.json").write_text('{"v":1,"patterns":[]}\n')
    (docs / "internal" / "followups.md").write_text("private\n")
    (docs / "evidence" / "README.md").write_text("# evidence\n")
    (docs / "evidence" / "report.json").write_text('{"format":"aics-conformance/v1","counts":{"pass":1}}\n')
    return root


def test_evidence_files_are_published_and_litter_is_ignored(tmp_path):
    root = fake_repo(tmp_path)
    (root / "docs" / "evidence" / "report.saved-checkpoint.txt").write_text("origin\n1\nroot\n")
    (root / "docs" / "evidence" / "report.policy.toml").write_text('quorum = 1\n')
    (root / "docs" / "evidence" / ".DS_Store").write_bytes(b"\x00\x01")
    result = export(root / "ops" / "sync-docs.sh", tmp_path / "out" / "docs-public")
    assert result.returncode == 0, result.stderr
    published = tmp_path / "out" / "docs-public" / "docs" / "evidence"
    assert sorted(p.name for p in published.iterdir()) == [
        "README.md", "index.txt", "report.json", "report.policy.toml", "report.saved-checkpoint.txt"]
    assert json.loads((published / "report.json").read_text())["format"] == "aics-conformance/v1"
    check = subprocess.run(["bash", str(root / "ops" / "sync-docs.sh"), "--check"], capture_output=True, text=True)
    assert check.returncode == 0 and "4 evidence files" in check.stdout, check.stdout + check.stderr


@pytest.mark.parametrize("plant, refusal", [
    (lambda e: (e / "key.pem").write_text("-----BEGIN PRIVATE KEY-----\n"), "outside the .md/.json/.txt/.toml"),
    (lambda e: (e / "nested").mkdir(), "not a regular file"),
    (lambda e: (e / "linked.md").symlink_to(e.parents[1] / "docs" / "internal" / "followups.md"), "not a regular file"),
    (lambda e: (e / "dup.json").write_text('{"a":1,"a":2}'), "not strict JSON"),
    (lambda e: (e / "nan.json").write_text('{"a":NaN}'), "not strict JSON"),
    (lambda e: (e / "latin.json").write_bytes(b'{"a":"\xe9"}'), "not strict JSON"),
    (lambda e: (e / "index.txt").write_text("mine\n"), "index.txt"),
    (lambda e: (e / "-dash.md").write_text("x\n"), "outside the .md/.json/.txt/.toml"),
    # An interrupted aics-conformance run leaves <report>.partial: it must never be published as evidence.
    (lambda e: (e / "run.json.partial").write_text('{"checks":[]}\n'), "outside the .md/.json/.txt/.toml"),
])
def test_anything_in_docs_evidence_that_cannot_be_published_refuses_the_export(tmp_path, plant, refusal):
    root = fake_repo(tmp_path)
    plant(root / "docs" / "evidence")
    destination = tmp_path / "out" / "docs-public"
    result = export(root / "ops" / "sync-docs.sh", destination)
    assert result.returncode == 1 and refusal in result.stderr, result.stderr
    assert not destination.exists()  # nothing was written
    check = subprocess.run(["bash", str(root / "ops" / "sync-docs.sh"), "--check"], capture_output=True, text=True)
    assert check.returncode == 1 and refusal in check.stderr


def test_a_hard_link_to_internal_material_is_refused_in_evidence(tmp_path):
    root = fake_repo(tmp_path)
    (root / "docs" / "evidence" / "notes.md").hardlink_to(root / "docs" / "internal" / "followups.md")
    result = export(root / "ops" / "sync-docs.sh", tmp_path / "out" / "docs-public")
    assert result.returncode == 1 and "hard link to internal document" in result.stderr, result.stderr


def test_a_removed_evidence_file_is_never_silently_dropped_from_an_export(tmp_path):
    # A card names evidence by hash: deleting the source must not quietly unpublish it on the next sync.
    root = fake_repo(tmp_path)
    destination = tmp_path / "out" / "docs-public"
    assert export(root / "ops" / "sync-docs.sh", destination).returncode == 0
    (root / "docs" / "evidence" / "report.json").unlink()
    result = export(root / "ops" / "sync-docs.sh", destination)
    assert result.returncode == 1 and "unexpected destination file" in result.stderr, result.stderr
    assert (destination / "docs" / "evidence" / "report.json").exists()


FAKE_SSH = """#!{python}
import subprocess, sys
args = sys.argv[1:]
while args and args[0].startswith("-"):
    args = args[2:] if args[0] in ("-l", "-p", "-i", "-o", "-e") else args[1:]
# args[0] is the host; run its command here: a shell line (mkdir), or rsync's own argv (rsync --server ...).
command = args[1:]
sys.exit(subprocess.run(["bash", "-c", command[0]] if len(command) == 1 else command).returncode)
"""


def remote_export(root: Path, tmp_path: Path, destination: Path) -> subprocess.CompletedProcess:
    """``sync-docs.sh agent@vps <destination>``, with an ``ssh`` that runs the remote side on this machine."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    ssh = bin_dir / "ssh"
    ssh.write_text(FAKE_SSH.format(python=sys.executable))
    ssh.chmod(0o755)
    env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return subprocess.run(["bash", str(root / "ops" / "sync-docs.sh"), "agent@vps.example", str(destination)],
                          capture_output=True, text=True, env=env)


def test_a_remote_sync_never_deletes_published_evidence(tmp_path):
    # The local guard (above) refuses to drop an evidence file; a remote sync cannot look first, so its --delete
    # protects docs/evidence/ instead: an export from a checkout that lacks a file keeps the published copy.
    if shutil.which("rsync") is None:
        pytest.skip("rsync is required for the remote sync")
    root = fake_repo(tmp_path)
    destination = tmp_path / "vps" / "docs-public"
    first = remote_export(root, tmp_path, destination)
    assert first.returncode == 0, first.stderr
    published = destination / "docs" / "evidence"
    assert (published / "report.json").read_bytes() == (root / "docs/evidence/report.json").read_bytes()
    # Caddy serves the export: files 0644, directories 0755, the export root included.
    assert {p.stat().st_mode & 0o777 for p in destination.rglob("*") if p.is_file()} == {0o644}
    assert {p.stat().st_mode & 0o777 for p in [destination, *destination.rglob("*")] if p.is_dir()} == {0o755}
    (destination / "spec" / "stale.md").write_text("an old public file\n")
    (root / "docs" / "evidence" / "report.json").unlink()
    (root / "docs" / "evidence" / "README.md").write_text("# evidence, described again\n")
    second = remote_export(root, tmp_path, destination)
    assert second.returncode == 0, second.stderr
    assert (published / "report.json").read_text() == '{"format":"aics-conformance/v1","counts":{"pass":1}}\n'
    assert (published / "README.md").read_text() == "# evidence, described again\n"  # a present file still replaces
    assert not (destination / "spec" / "stale.md").exists()  # everything else is still mirrored exactly

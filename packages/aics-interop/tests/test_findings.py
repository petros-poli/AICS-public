"""The findings registry, the README and the tests agree, and every citation is exact at git HEAD."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from aics_interop import appendix_a, drivers, findings, generate

PACKAGE = Path(__file__).resolve().parents[1]
REPO = appendix_a.REPO_ROOT


def test_ids_are_consecutive():
    assert list(findings.FINDINGS) == [f"F{i:02d}" for i in range(1, len(findings.FINDINGS) + 1)]


def test_readme_findings_block_is_current():
    """Refresh with: uv run python -m aics_interop.findings"""
    text = (PACKAGE / "README.md").read_text("utf-8")
    block = text.split(findings.BEGIN, 1)[1].split(findings.END, 1)[0]
    assert block.strip() == findings.markdown().strip()


def _head(path: str) -> list[str]:
    """``path`` as committed on git HEAD (never the working tree, which may differ from what is cited)."""
    if not shutil.which("git"):
        drivers.tool_unavailable("git is not installed; citations are checked against git HEAD")
    head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--verify", "HEAD"], capture_output=True, text=True,
                          timeout=30)
    if head.returncode != 0:
        drivers.tool_unavailable("not a git checkout with a HEAD commit; citations are checked against git HEAD")
    out = subprocess.run(["git", "-C", str(REPO), "show", f"HEAD:{path}"], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, f"{path} is not in git HEAD: {out.stderr.strip()}"
    return out.stdout.splitlines()


OPEN = [fid for fid, f in findings.FINDINGS.items() if f.open]
RETIRED = [fid for fid, f in findings.FINDINGS.items() if not f.open]


def test_statuses_are_known():
    assert {f.status for f in findings.FINDINGS.values()} <= {"open", "retired"}


@pytest.mark.parametrize("fid", OPEN)
def test_citation_is_exact_at_head(fid):
    """An open finding's line is checked at git HEAD; a retired one keeps the line where it was found."""
    f = findings.FINDINGS[fid]
    lines = _head(f.file)
    assert 1 <= f.line <= len(lines), f"{f.file} has {len(lines)} lines"
    assert f.needle and f.needle in lines[f.line - 1], f"{f.file}:{f.line} is now: {lines[f.line - 1]!r}"


def _test_sources() -> dict[str, str]:
    return {f"tests/{p.name}": p.read_text("utf-8") for p in sorted((PACKAGE / "tests").glob("test_*.py"))
            if p.name != Path(__file__).name}


def test_every_finding_is_demonstrated_by_a_strict_xfail():
    text = "\n".join(_test_sources().values())
    missing = [fid for fid in OPEN if not re.search(rf'finding\("{fid}", raises=', text)]
    assert missing == []


@pytest.mark.parametrize("fid", RETIRED)
def test_a_retired_finding_has_a_note_and_no_marker(fid):
    """Retired: the package follows AICS-1, its tests pass unmarked (finding() refuses the ID), nothing documents
    the departure any more, and the note says what the package does now."""
    f = findings.FINDINGS[fid]
    assert f.note and not f.documents
    text = "\n".join(_test_sources().values())
    assert not re.search(rf'finding\("{fid}"', text)
    with pytest.raises(ValueError, match="retired"):
        findings.finding(fid, raises=AssertionError)


def test_documents_lists_existing_tests():
    sources = _test_sources()
    for f in findings.FINDINGS.values():
        for node in f.documents:
            path, _, name = node.partition("::")
            assert path in sources and re.search(rf"^def {re.escape(name)}\(", sources[path], re.M), (f.id, node)


def test_every_documenting_test_is_listed_under_its_finding():
    """A test whose docstring says "Documents Fxx" does not XPASS when Fxx is fixed, so Fxx.documents names it."""
    for path, text in _test_sources().items():
        for name, fid in re.findall(r'^def (test_\w+)\([^)]*\):\n    """Documents (F\d\d)\b', text, re.M):
            assert f"{path}::{name}" in findings.FINDINGS[fid].documents, (fid, name)


def test_fixture_annotations_name_open_findings():
    used = set()
    for p in generate.DEFAULT_OUT.rglob("*.json"):
        used |= set(re.findall(r'"(F\d\d)"', p.read_text("utf-8")))
    assert used and used <= set(OPEN)
    assert json.loads((generate.DEFAULT_OUT / "manifest.json").read_text())["format"] == generate.FORMAT

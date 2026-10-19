"""Packaging findings that decide whether the packages interoperate at all (F14-F16, retired: these tests guard
the fixes).

Each test reads the committed tree (git, pyproject files, distribution
metadata) rather than behaviour, so it gives the same answer locally and in
a clean CI checkout.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from importlib.metadata import version

from aics_interop import appendix_a, drivers

REPO = appendix_a.REPO_ROOT


def _ls_files(path: str) -> list[str]:
    if not shutil.which("git"):
        drivers.tool_unavailable("git is not installed")
    out = subprocess.run(["git", "-C", str(REPO), "ls-files", "--", path], capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        drivers.tool_unavailable("not a git checkout")
    return out.stdout.split()


def test_conformance_package_data_is_committed():
    """aics-conformance reads no package data file at all (a git-ignored one is absent from a clean checkout): its
    banner is docs/BANNER.md's fenced block, carried in dialogue.py, which git tracks."""
    from aics_conformance import dialogue

    src = "packages/aics-conformance/src/aics_conformance"
    tracked = _ls_files(src)
    assert f"{src}/dialogue.py" in tracked
    readers = [f for f in tracked if f.endswith(".py")
               and re.search(r"importlib\.resources|\bfiles\(|data/banner\.txt", (REPO / f).read_text("utf-8"))]
    assert readers == []
    block = re.search(r"\n```\n(.*?)\n```\n", (REPO / "docs/BANNER.md").read_text("utf-8"), re.S).group(1) + "\n"
    assert dialogue.BANNER_TEXT == block
    assert dialogue.BANNER == (REPO / "wellknown/llms.txt.header").read_text("utf-8")  # the pre-client variant


def test_the_conformance_fake_routes_post_entries_without_package_data():
    """FakeServer.request serves POST /v2/entries (and every other path) from the package's own code."""
    src = (REPO / "packages/aics-conformance/src/aics_conformance/fakes/server.py").read_text()
    assert "data/banner.txt" not in src and "importlib.resources" not in src


def _sources(pyproject: str) -> dict:
    with open(REPO / pyproject, "rb") as fh:
        return tomllib.load(fh).get("tool", {}).get("uv", {}).get("sources", {})


def test_sibling_path_sources_agree():
    """aics-tlog is declared by three siblings; uv resolves them together only if the declarations agree."""
    decls = {p: _sources(f"packages/{p}/pyproject.toml").get("aics-tlog") for p in
             ("aics-witness", "aics-cli", "aics-conformance")}
    assert all(d is not None for d in decls.values())
    assert len({bool(d.get("editable", False)) for d in decls.values()}) == 1, decls


def test_aics_tlog_reports_its_distribution_version():
    import aics_tlog

    assert aics_tlog.__version__ == version("aics-tlog")


def test_the_suite_tests_the_sibling_source_trees():
    """Every sibling is imported from packages/<name>/src (editable), not from a cached wheel, the server booted by
    the drift tests included."""
    import aics_cli
    import aics_conformance
    import aics_identity
    import aics_server
    import aics_tlog
    import aics_witness

    for module, directory in ((aics_identity, "aics-identity"), (aics_tlog, "aics-tlog"),
                              (aics_witness, "aics-witness"), (aics_cli, "aics-cli"),
                              (aics_conformance, "aics-conformance"), (aics_server, "aics-server")):
        assert (REPO / "packages" / directory / "src").resolve() in __import__("pathlib").Path(
            module.__file__).resolve().parents, module.__file__

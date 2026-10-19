"""Shared fixtures for the AICS interop suite."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True  # never drop __pycache__ into the sibling packages' source trees

import shutil
import subprocess

import pytest

from aics_interop import aicslog, appendix_a, drivers, spec

REPO_ROOT = appendix_a.REPO_ROOT
PACKAGES = ("aics-identity", "aics-tlog", "aics-witness", "aics-cli", "aics-conformance", "aics-server")


def _git(*args: str) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(REPO_ROOT), *args], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.rstrip("\n") if out.returncode == 0 else None


def sibling_differences() -> list[str] | None:
    """``git status`` lines for the six siblings: changed or untracked files anywhere in the package, and files
    under ``src/`` that .gitignore hides (``!!``: present here, absent from a clean checkout); None without git."""
    changed = _git("status", "--porcelain", "--", *[f"packages/{p}" for p in PACKAGES])
    ignored = _git("status", "--porcelain", "--ignored", "--", *[f"packages/{p}/src" for p in PACKAGES])
    if changed is None or ignored is None:
        return None
    lines = [ln for ln in changed.splitlines() if ln]
    lines += [ln for ln in ignored.splitlines() if ln.startswith("!! ") and "__pycache__" not in ln]
    return lines


def pytest_report_header(config):
    from importlib.metadata import version

    head = _git("rev-parse", "HEAD") or "unknown (no git)"
    lines = [f"aics-interop: git HEAD {head}"]
    differences = sibling_differences()
    if differences:
        lines.append("aics-interop: WARNING sibling packages differ from HEAD (!! = ignored, absent from a clean "
                     "checkout):\n  " + "\n  ".join(differences))
    else:
        lines.append("aics-interop: sibling package sources match HEAD" if differences is not None else
                     "aics-interop: sibling package state unknown")
    names = {"aics-identity": "aics-identity", "aics-tlog": "aics-tlog", "aics-witness": "aics-witness",
             "aics-cli": "aics", "aics-conformance": "aics-conformance", "aics-server": "aics-server"}
    lines.append("aics-interop: " + ", ".join(f"{d}={version(n)}" for d, n in names.items()))
    tools = {t: shutil.which(t) for t in ("openssl", "ssh-keygen", "git")}
    missing = "absent (tests fail: " + drivers.REQUIRE_TOOLS + ")" if drivers.tools_required() else \
        "absent (tests skip)"
    lines.append("aics-interop: tools " + ", ".join(f"{t}={'yes' if p else missing}" for t, p in tools.items()))
    return lines


@pytest.fixture(scope="session")
def appendix():
    return appendix_a.load()


@pytest.fixture
def openssl_bin():
    path = shutil.which("openssl")
    if not path:
        drivers.tool_unavailable("openssl is not installed")
    probe = subprocess.run([path, "genpkey", "-algorithm", "ed25519"], capture_output=True, timeout=30)
    if probe.returncode != 0:
        drivers.tool_unavailable("this openssl cannot generate Ed25519 keys")
    return path


@pytest.fixture
def ssh_keygen_bin():
    path = shutil.which("ssh-keygen")
    if not path:
        drivers.tool_unavailable("ssh-keygen is not installed")
    return path


@pytest.fixture
def web():
    from aics_interop.transport import FakeWeb

    return FakeWeb()


@pytest.fixture
def bundle_text() -> str:
    """The interop log's trust bundle in its README-block form."""
    return spec.readme_block(spec.J(aicslog.trust_bundle()))

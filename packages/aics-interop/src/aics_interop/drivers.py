"""Drive aics-cli (in-process and as a subprocess) and aics-conformance's verifiers."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import aicslog

# ---------------------------------------------------------------------------
# external tools (openssl, ssh-keygen, git)
# ---------------------------------------------------------------------------

#: Set (to anything but "" or "0") in CI: a test whose tool is missing fails instead of skipping.
REQUIRE_TOOLS = "AICS_INTEROP_REQUIRE_TOOLS"


def tools_required() -> bool:
    return os.environ.get(REQUIRE_TOOLS, "") not in ("", "0")


def tool_unavailable(reason: str) -> None:
    """Skip the test, or fail it when ``AICS_INTEROP_REQUIRE_TOOLS`` is set (never returns)."""
    import pytest

    if tools_required():
        pytest.fail(f"{reason}; {REQUIRE_TOOLS} is set, so the tests that need it must run")
    pytest.skip(reason)


# ---------------------------------------------------------------------------
# aics-cli
# ---------------------------------------------------------------------------


@dataclass
class CliResult:
    code: int
    data: dict[str, Any]

    @property
    def evidence(self) -> dict[str, Any]:
        return self.data.get("evidence") or {}


@dataclass
class AicsCli:
    """``aics_cli.cli.run`` with an injected fetcher, clock and state directory."""

    home: Path
    web: Any = None
    now: int = aicslog.T0
    stdin: Any = None
    txt: dict[str, list[str]] = field(default_factory=dict)

    def env(self) -> Any:
        from aics_cli.commands import Env
        from aics_cli.dnstxt import TxtResult

        def resolve(name: str, *, nameserver: str | None = None) -> TxtResult:
            if name not in self.txt:
                return TxtResult(name=name, resolver="interop-fake", nxdomain=True)
            return TxtResult(name=name, records=list(self.txt[name]), resolver="interop-fake")

        kwargs: dict[str, Any] = {"resolve_txt": resolve, "clock": lambda: float(self.now), "home": self.home,
                                  "stdin": self.stdin}
        if self.web is not None:
            kwargs["fetcher"] = self.web
        return Env(**kwargs)

    def run(self, *argv: str) -> CliResult:
        from aics_cli.cli import run

        out = io.StringIO()
        code = run([*argv, "--json"], env=self.env(), out=out)
        text = out.getvalue().strip()
        return CliResult(code, json.loads(text) if text else {})

    def pin(self, bundle_text: str, *, witnesses: list[str] = (), quorum: int = 0, max_age: int | None = 300,
            prefix: str = aicslog.PREFIX, mirrors: list[str] = (), consistency: str | None = None,
            force: bool = False) -> CliResult:
        argv = ["policy", "init", "--bundle", bundle_text, "--require-sources", "1", "--no-card",
                "--quorum", str(quorum), "--checkpoint-url", prefix + "checkpoint", "--tiles-url", prefix]
        for w in witnesses:
            argv += ["--witness", w]
        if max_age is not None:
            argv += ["--max-age", str(max_age)]
        for m in mirrors:
            argv += ["--mirror", m]
        if consistency:
            argv += ["--consistency-url", consistency]
        if force:
            argv.append("--force")
        return self.run(*argv)


def aics_subprocess(*argv: str, home: Path, stdin: str | None = None, timeout: float = 60) -> subprocess.CompletedProcess:
    """The real ``aics`` entry point in a child interpreter (``python -m aics_cli``)."""
    env = {**os.environ, "AICS_HOME": str(home), "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-m", "aics_cli", *argv], input=stdin, capture_output=True,
                          text=True, timeout=timeout, env=env, check=False)


def tlog_subprocess(*argv: str, timeout: float = 60) -> subprocess.CompletedProcess:
    """The ``aics-tlog`` CLI in a child interpreter (``python -m aics_tlog``)."""
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-m", "aics_tlog", *argv], capture_output=True, text=True,
                          timeout=timeout, env=env, check=False)


# ---------------------------------------------------------------------------
# aics-conformance
# ---------------------------------------------------------------------------


def conformance_policy(trust: dict[str, Any], *, witnesses: list[str] = (), quorum: int = 0,
                       max_age: int = 300, mirrors: list[str] = (), saved_checkpoint: bytes | None = None) -> Any:
    from aics_conformance.policy import Policy

    return Policy(trust=dict(trust), witness_vkeys=list(witnesses), quorum=quorum, max_checkpoint_age=max_age,
                  mirrors=list(mirrors), saved_checkpoint=saved_checkpoint)


def conformance_context(web: Any, policy: Any, now: int, *, api: str = aicslog.API_BASE,
                        tiles: str = aicslog.PREFIX) -> Any:
    from aics_conformance.client import JSONClient, Tiles
    from aics_conformance.core import Context

    clock: Callable[[], float] = lambda: float(now)
    return Context(JSONClient(api, transport=web), Tiles(tiles.rstrip("/"), transport=web), policy,
                   clock=clock, sleep=lambda s: None)


def run_conformance_check(check_id: str, ctx: Any) -> dict[str, Any]:
    """Run one registered aics-conformance check (e.g. ``G5``) and return its report row."""
    import aics_conformance.checks  # noqa: F401  (registers the modules)
    import aics_conformance.guarantees  # noqa: F401
    from aics_conformance.core import CHECKS

    check = next(c for c in CHECKS if c.id == check_id)
    return check.run(ctx)

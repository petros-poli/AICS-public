"""Exit-code contract, --json placement, stubs for server features."""

from __future__ import annotations

import io
import json
import subprocess
import sys

import pytest

from aics_cli.cli import run

UNAVAILABLE = "not available until the server ships this"


@pytest.mark.parametrize("argv", [
    ["verify", "receipt", "r.note"],
    ["verify", "tombstones", "--since", "2026-10-01"],
    ["inbox", "--rebuild-from-tiles", "--compare-api"],
])
def test_server_features_exit_3(h, argv):
    code, out = h.run(*argv)
    assert code == 3
    assert out["error"] == UNAVAILABLE and out["available"] is False
    code, text = h.run_text(*argv)
    assert code == 3 and text.strip() == UNAVAILABLE


def test_usage_errors_exit_1_not_2(h):
    code, out = h.run("verify", "bogus")
    assert code == 1 and "invalid choice" in out["error"]
    code, out = h.run("sign-line", "--line", "x")  # missing --session
    assert code == 1
    code, out = h.run("verify", "checkpoint", "--unknown-flag")
    assert code == 1 and "unrecognized" in out["error"]


def test_json_flag_before_or_after_the_command(h):
    buf = io.StringIO()
    code = run(["--json", "inbox"], env=h.env, out=buf)
    assert code == 3 and json.loads(buf.getvalue())["command"] == "inbox"
    buf = io.StringIO()
    code = run(["inbox", "--json"], env=h.env, out=buf)
    assert code == 3 and json.loads(buf.getvalue())["command"] == "inbox"


def test_every_json_output_names_command_and_exit(h):
    code, out = h.run("verify", "checkpoint")  # no policy
    assert code == 1
    assert out["command"] == "verify checkpoint" and out["exit"] == 1 and out["ok"] is False


def test_console_script_runs():
    r = subprocess.run([sys.executable, "-m", "aics_cli", "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.startswith("aics ")
    r = subprocess.run([sys.executable, "-m", "aics_cli", "verify", "receipt", "x", "--json"],
                       capture_output=True, text=True)
    assert r.returncode == 3 and json.loads(r.stdout)["error"] == UNAVAILABLE

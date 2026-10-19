"""Deployment must reject broken TLS configuration before replacing services."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "deploy/deploy-vps.sh"


def run_startup(tmp_path, *, token="test-token-never-print", invalid_json=False, valid_caddy=True):
    remote = re.search(
        r'if ! ssh "\$\{TARGET\}" sh -s -- "\$\{REMOTE_DIR\}" <<\'REMOTE\'\n(.*?)\nREMOTE',
        SCRIPT.read_text(), re.S,
    ).group(1)
    (tmp_path / "deploy").mkdir()
    commands = tmp_path / "commands.jsonl"
    docker = tmp_path / "docker"
    docker.write_text(f"#!{sys.executable}\n" + '''
import json, os, sys
args = sys.argv[1:]
with open(os.environ["TEST_COMMANDS"], "a") as output:
    output.write(json.dumps(args) + "\\n")
if args == ["compose", "config", "--format", "json"]:
    print("invalid" if os.environ["TEST_INVALID_JSON"] == "1" else json.dumps({
        "services": {"caddy": {"environment": {"CLOUDFLARE_API_TOKEN": os.environ["TEST_TOKEN"]}}}
    }))
elif args == ["compose", "config", "--services"]:
    print("aics-server\\ncaddy")
elif "validate" in args:
    # Even a badly behaved provisioner must not leak a token on validation failure.
    print(os.environ["TEST_TOKEN"], file=sys.stderr)
    sys.exit(0 if os.environ["TEST_VALID_CADDY"] == "1" else 1)
''')
    docker.chmod(0o755)
    env = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
               TEST_COMMANDS=str(commands), TEST_TOKEN=token,
               TEST_INVALID_JSON=str(int(invalid_json)), TEST_VALID_CADDY=str(int(valid_caddy)))
    result = subprocess.run(["sh", "-s", "--", str(tmp_path)], input=remote,
                            text=True, capture_output=True, env=env)
    calls = [json.loads(line) for line in commands.read_text().splitlines()]
    return result, calls


@pytest.mark.parametrize("token", ["", " \t"])
def test_missing_token_stops_before_build_or_start(tmp_path, token):
    result, calls = run_startup(tmp_path, token=token)
    assert result.returncode != 0
    assert "CLOUDFLARE_API_TOKEN is missing" in result.stderr
    assert calls == [["compose", "config", "--format", "json"]]


def test_invalid_compose_stops_before_build_or_start(tmp_path):
    result, calls = run_startup(tmp_path, invalid_json=True)
    assert result.returncode != 0
    assert "Invalid Compose configuration" in result.stderr
    assert len(calls) == 1


def test_invalid_caddy_preserves_running_containers_and_hides_token(tmp_path):
    result, calls = run_startup(tmp_path, valid_caddy=False)
    assert result.returncode != 0
    assert "Caddy configuration validation failed" in result.stderr
    assert not any("up" in call for call in calls)
    assert "test-token-never-print" not in result.stdout + result.stderr


def test_valid_caddy_is_checked_before_containers_are_replaced(tmp_path):
    result, calls = run_startup(tmp_path)
    assert result.returncode == 0, result.stderr
    validate = next(i for i, call in enumerate(calls) if "validate" in call)
    start = calls.index(["compose", "up", "-d"])
    assert validate < start
    assert "test-token-never-print" not in result.stdout + result.stderr


def test_sync_preserves_active_recovery_and_remote_secrets(tmp_path):
    if shutil.which("rsync") is None:
        pytest.skip("rsync is required for deployment sync integration")
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    for name in ("packages", "deploy", "ops"):
        (source / name).mkdir(parents=True)
    (destination / "deploy").mkdir(parents=True)
    (source / ".dockerignore").write_text("**/.env\n")
    (source / "deploy/Caddyfile").write_text("canonical update\n")
    (destination / "deploy/Caddyfile").write_text("old canonical\n")
    (destination / "deploy/stale-public-file").write_text("remove me\n")
    protected = ("Caddyfile.recovery", "docker-compose.recovery.yml", ".env")
    for name in protected:
        (destination / "deploy" / name).write_text("keep remote " + name)
        (source / "deploy" / name).write_text("must not transfer " + name)
    (source / "deploy/.env.example").write_text("example\n")

    # Exercise the script's real filters, substituting only a local destination
    # for its SSH destination so this test cannot contact or modify a VPS.
    script = SCRIPT.read_text()
    start = script.index("rsync -az --delete \\\n")
    command = script[start:script.index("\n\n", start)]
    command = command.replace('"${TARGET}:${REMOTE_DIR}/"', '"${REMOTE_DIR}/"')
    env = dict(os.environ, SRC_DIR=str(source), REMOTE_DIR=str(destination))
    result = subprocess.run(["bash", "-eu", "-c", command], text=True,
                            capture_output=True, env=env)
    assert result.returncode == 0, result.stderr
    for name in protected:
        assert (destination / "deploy" / name).read_text() == "keep remote " + name
    assert (destination / "deploy/Caddyfile").read_text() == "canonical update\n"
    assert (destination / "deploy/.env.example").read_text() == "example\n"
    assert not (destination / "deploy/stale-public-file").exists()

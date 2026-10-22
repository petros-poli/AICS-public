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


def run_startup(tmp_path, *, token="test-token-never-print", invalid_json=False, valid_caddy=True,
                witness_import=True):
    remote = re.search(
        r'if ! ssh "\$\{TARGET\}" sh -s -- "\$\{REMOTE_DIR\}" "\$\{CADDYFILE_CHANGED\}" "\$\{CARD_CHANGED\}" '
        r'<<\'REMOTE\'\n(.*?)\nREMOTE',
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
elif "aics-witness-check" in " ".join(args):
    sys.exit(0 if os.environ["TEST_WITNESS_IMPORT"] == "1" else 1)
''')
    docker.chmod(0o755)
    env = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"],
               TEST_COMMANDS=str(commands), TEST_TOKEN=token,
               TEST_INVALID_JSON=str(int(invalid_json)), TEST_VALID_CADDY=str(int(valid_caddy)),
               TEST_WITNESS_IMPORT=str(int(witness_import)))
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


def test_an_image_without_the_witness_package_is_not_started(tmp_path):
    # AICS_WITNESSES in deploy/.env makes the server import aics_witness.feeder at start: an image
    # without it would refuse to start and take production down, so the deploy stops first.
    result, calls = run_startup(tmp_path, witness_import=False)
    assert result.returncode != 0
    assert "cannot import aics_witness.feeder" in result.stderr
    assert not any("up" in call for call in calls)


def test_the_witness_import_is_checked_in_the_built_image_before_start(tmp_path):
    result, calls = run_startup(tmp_path)
    assert result.returncode == 0, result.stderr
    check = next(i for i, call in enumerate(calls) if any("aics-witness-check" in a for a in call))
    call = calls[check]
    assert call[:4] == ["compose", "run", "--rm", "--no-deps"] and "aics-server" in call
    assert "aics_witness.feeder" in call[-1] and "parse_witnesses" in call[-1]
    assert calls.index(["compose", "build"]) < check < calls.index(["compose", "up", "-d"])


def test_the_image_installs_the_witness_package_the_feeder_imports():
    root = SCRIPT.parents[1]
    dockerfile = (root / "deploy/Dockerfile").read_text()
    compose = (root / "deploy/docker-compose.yml").read_text()
    assert "AICS_WITNESSES=${AICS_WITNESSES:-}" in compose
    assert "from aics_witness.feeder import WitnessClient" in (
        root / "packages/aics-server/src/aics_server/witness_feed.py").read_text()
    assert re.search(r"^COPY packages/aics-witness /app/packages/aics-witness$", dockerfile, re.M)
    install = dockerfile[dockerfile.index("RUN pip install --no-deps --no-build-isolation"):]
    install = install[:install.index("pip uninstall")]
    assert "/app/packages/aics-witness" in install
    assert 'python -c "import aics_server.witness_feed, aics_witness.feeder"' in dockerfile
    # Its only dependencies are already pinned by hash in the image.
    requirements = (root / "deploy/requirements.txt").read_text()
    assert re.search(r"^cryptography==", requirements, re.M)
    witness = (root / "packages/aics-witness/pyproject.toml").read_text()
    deps = re.search(r"^dependencies = \[(.*?)\]", witness, re.M | re.S).group(1)
    assert sorted(re.findall(r'"([a-z0-9-]+)', deps)) == ["aics-tlog", "cryptography"]


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

    # The reviewed card body is gitignored: a checkout without it must not delete the VPS's copy
    # (the 2026-10-19 incident: --delete removed it and production crash-looped).
    (destination / "deploy/card").mkdir()
    (destination / "deploy/card/card-unsigned.json").write_text('{"reviewed": "keep"}\n')
    (destination / "deploy/card/stale.json").write_text("remove me too\n")
    (source / "deploy/card").mkdir()
    caddyfile_inode = (destination / "deploy/Caddyfile").stat().st_ino

    # Local tool caches and build output never reach the VPS (nor, through .dockerignore, the image).
    for cache in (".ruff_cache", ".mypy_cache", "dist", "build", "aics_server.egg-info"):
        (source / "packages/aics-server" / cache).mkdir(parents=True)
        (source / "packages/aics-server" / cache / "x").write_text("local only\n")
    (source / "packages/aics-server/src").mkdir(parents=True)
    (source / "packages/aics-server/src/app.py").write_text("code\n")
    # Published evidence is never deleted from the VPS by a local export that lacks it; a local copy replaces it.
    evidence = "deploy/docs-public/docs/evidence"
    (destination / evidence).mkdir(parents=True)
    (destination / evidence / "named-by-a-card.json").write_text('{"kept": true}\n')
    (destination / evidence / "index.txt").write_text("named-by-a-card.json\nindex.txt\n")
    (destination / "deploy/docs-public/docs/stale.md").write_text("remove me\n")
    (source / evidence).mkdir(parents=True)
    (source / evidence / "index.txt").write_text("new.json\nindex.txt\n")
    (source / evidence / "new.json").write_text('{"new": true}\n')

    # Exercise the script's real filters, substituting only a local destination
    # for its SSH destination so this test cannot contact or modify a VPS.
    script = SCRIPT.read_text()
    start = script.index("rsync -azi --inplace --delete \\\n")
    command = script[start:script.index("\n\n", start)]
    command = command.replace('"${TARGET}:${REMOTE_DIR}/"', '"${REMOTE_DIR}/"')
    changes = tmp_path / "changes"
    env = dict(os.environ, SRC_DIR=str(source), REMOTE_DIR=str(destination), RSYNC_CHANGES=str(changes))
    result = subprocess.run(["bash", "-eu", "-c", command + "\necho \"$CADDYFILE_CHANGED $CARD_CHANGED\""],
                            text=True, capture_output=True, env=env)
    assert result.returncode == 0, result.stderr
    for name in protected:
        assert (destination / "deploy" / name).read_text() == "keep remote " + name
    assert (destination / "deploy/Caddyfile").read_text() == "canonical update\n"
    # --inplace: the running container's bind mount keeps seeing the file (same inode).
    assert (destination / "deploy/Caddyfile").stat().st_ino == caddyfile_inode
    assert (destination / "deploy/.env.example").read_text() == "example\n"
    assert not (destination / "deploy/stale-public-file").exists()
    assert (destination / "deploy/card/card-unsigned.json").read_text() == '{"reviewed": "keep"}\n'
    assert not (destination / "deploy/card/stale.json").exists()
    assert result.stdout.rstrip().splitlines()[-1] == "1 0"
    assert (destination / "packages/aics-server/src/app.py").read_text() == "code\n"
    for cache in (".ruff_cache", ".mypy_cache", "dist", "build", "aics_server.egg-info"):
        assert not (destination / "packages/aics-server" / cache).exists(), cache
    assert (destination / evidence / "named-by-a-card.json").read_text() == '{"kept": true}\n'
    assert (destination / evidence / "new.json").read_text() == '{"new": true}\n'
    assert (destination / evidence / "index.txt").read_text() == "new.json\nindex.txt\n"
    assert not (destination / "deploy/docs-public/docs/stale.md").exists()

    # A checkout that holds the reviewed body still replaces the VPS's copy, and the flag says so.
    (source / "deploy/card/card-unsigned.json").write_text('{"reviewed": "successor"}\n')
    result = subprocess.run(["bash", "-eu", "-c", command + "\necho \"$CADDYFILE_CHANGED $CARD_CHANGED\""],
                            text=True, capture_output=True, env=env)
    assert result.returncode == 0, result.stderr
    assert (destination / "deploy/card/card-unsigned.json").read_text() == '{"reviewed": "successor"}\n'
    assert result.stdout.rstrip().splitlines()[-1] == "0 1"


def test_a_missing_card_body_stops_before_build_or_start(tmp_path):
    # deploy/.env names AICS_CARD_FILE (runbook step 5): the body must be on the VPS, or the app
    # would stop at start on the missing file and crash-loop.
    remote = re.search(
        r'if ! ssh "\$\{TARGET\}" sh -s -- "\$\{REMOTE_DIR\}" "\$\{CADDYFILE_CHANGED\}" "\$\{CARD_CHANGED\}" '
        r'<<\'REMOTE\'\n(.*?)\nREMOTE', SCRIPT.read_text(), re.S).group(1)
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy/.env").write_text("AICS_CARD_FILE=/etc/aics/card/card-unsigned.json\n")
    commands = tmp_path / "commands.jsonl"
    docker = tmp_path / "docker"
    docker.write_text(f"#!{sys.executable}\nimport json, os, sys\n"
                      "open(os.environ['TEST_COMMANDS'], 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n")
    docker.chmod(0o755)
    env = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"], TEST_COMMANDS=str(commands))
    result = subprocess.run(["sh", "-s", "--", str(tmp_path), "0", "0"], input=remote,
                            text=True, capture_output=True, env=env)
    assert result.returncode != 0
    assert "AICS_CARD_FILE=/etc/aics/card/card-unsigned.json" in result.stderr
    assert "deploy/card/card-unsigned.json is missing" in result.stderr
    assert not commands.exists()  # nothing was built, validated or started


def test_a_checkout_without_the_docs_export_stops_before_anything_is_sent(tmp_path):
    # deploy/docs-public is gitignored: a fresh worktree has none, and the --delete sync would remove the VPS's
    # charter, terms, retention text and secret patterns, which the app mounts with create_host_path false, so
    # production could not start (review of the readiness lanes, 2026-10-22).
    script = SCRIPT.read_text()
    guard = re.search(r"^for published in [^\n]*\n.*?^done$", script, re.M | re.S).group(0)
    assert script.index(guard) < script.index('ssh "${TARGET}"') < script.index("rsync -azi")
    compose = (SCRIPT.parent / "docker-compose.yml").read_text()
    mounted = re.findall(r"source: \./docs-public/legal/(\S+)\n(?:.*\n){0,3}?\s*create_host_path: false", compose)
    listed = re.match(r"for published in (.+); do$", guard.split("\n", 1)[0]).group(1).split()
    assert sorted(listed) == sorted(mounted) and len(mounted) == 4, (listed, mounted)

    env = dict(os.environ, SRC_DIR=str(tmp_path))
    result = subprocess.run(["bash", "-eu", "-c", guard], text=True, capture_output=True, env=env)
    assert result.returncode == 1
    assert "deploy/docs-public/legal/charter.md is missing" in result.stderr
    assert "bash ops/sync-docs.sh deploy/docs-public" in result.stderr and "Nothing was sent." in result.stderr
    legal = tmp_path / "deploy/docs-public/legal"
    legal.mkdir(parents=True)
    for name in listed:
        (legal / name).write_text("published\n")
    (legal / "retention.md").write_text("")  # an empty copy is no export either
    result = subprocess.run(["bash", "-eu", "-c", guard], text=True, capture_output=True, env=env)
    assert result.returncode == 1 and "legal/retention.md is missing" in result.stderr
    (legal / "retention.md").write_text("published\n")
    result = subprocess.run(["bash", "-eu", "-c", guard], text=True, capture_output=True, env=env)
    assert result.returncode == 0 and result.stderr == ""


def test_the_image_build_context_leaves_out_local_caches_and_build_output():
    # An image built from a working checkout must be the image of a clean worktree of the same commit: what
    # deploy/Dockerfile copies (packages/aics-*) must not carry untracked tool caches or build output.
    root = SCRIPT.parents[1]
    patterns = (root / ".dockerignore").read_text().splitlines()
    for pattern in ("**/.ruff_cache", "**/.mypy_cache", "**/dist", "**/build", "**/*.egg-info", "**/.venv",
                    "**/__pycache__", "**/.pytest_cache", "**/data"):
        assert pattern in patterns, pattern


def test_a_changed_caddyfile_recreates_the_caddy_container_and_modes_are_normalised(tmp_path):
    # A read-only one-file bind mount keeps the old inode after rsync replaced the host file (openrsync ignores
    # --inplace), so Caddy is recreated, not reloaded. Directories a private worktree shipped as 0700 become
    # traversable; the env files stay private.
    remote = re.search(
        r'if ! ssh "\$\{TARGET\}" sh -s -- "\$\{REMOTE_DIR\}" "\$\{CADDYFILE_CHANGED\}" "\$\{CARD_CHANGED\}" '
        r'<<\'REMOTE\'\n(.*?)\nREMOTE', SCRIPT.read_text(), re.S).group(1)
    for d in ("deploy", "deploy/card", "packages", "ops"):
        (tmp_path / d).mkdir(mode=0o700)
    (tmp_path / "deploy/.env").write_text("X=1\n"); (tmp_path / "deploy/.env").chmod(0o600)
    (tmp_path / "deploy/.env.pilot.bak").write_text("X=1\n"); (tmp_path / "deploy/.env.pilot.bak").chmod(0o644)
    (tmp_path / "deploy/.env.example").write_text("X=\n"); (tmp_path / "deploy/.env.example").chmod(0o644)
    (tmp_path / "deploy/card/card-unsigned.json").write_text("{}"); (tmp_path / "deploy/card/card-unsigned.json").chmod(0o600)
    (tmp_path / ".dockerignore").write_text("")
    commands = tmp_path / "commands.jsonl"
    docker = tmp_path / "docker"
    docker.write_text(f"#!{sys.executable}\n" + '''
import json, os, sys
args = sys.argv[1:]
with open(os.environ["TEST_COMMANDS"], "a") as output:
    output.write(json.dumps(args) + "\\n")
if args == ["compose", "config", "--format", "json"]:
    print(json.dumps({"services": {"caddy": {"environment": {"CLOUDFLARE_API_TOKEN": "t"}}}}))
elif args == ["compose", "config", "--services"]:
    print("aics-server\\ncaddy")
''')
    docker.chmod(0o755)
    env = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"], TEST_COMMANDS=str(commands))
    result = subprocess.run(["sh", "-s", "--", str(tmp_path), "1", "0"], input=remote, text=True,
                            capture_output=True, env=env)
    assert result.returncode == 0, result.stderr
    calls = [json.loads(line) for line in commands.read_text().splitlines()]
    assert ["compose", "up", "-d", "--force-recreate", "--no-deps", "caddy"] in calls
    assert not any("reload" in call for call in calls)
    assert calls.index(["compose", "up", "-d"]) < calls.index(["compose", "up", "-d", "--force-recreate", "--no-deps", "caddy"])
    for d in ("deploy", "deploy/card", "packages", "ops"):
        assert (tmp_path / d).stat().st_mode & 0o055 == 0o055, d
    assert (tmp_path / "deploy/card/card-unsigned.json").stat().st_mode & 0o044 == 0o044
    assert (tmp_path / "deploy/.env").stat().st_mode & 0o077 == 0
    assert (tmp_path / "deploy/.env.pilot.bak").stat().st_mode & 0o077 == 0
    assert (tmp_path / "deploy/.env.example").stat().st_mode & 0o044 == 0o044

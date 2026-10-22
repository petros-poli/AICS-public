"""ops/uptime-check.sh and ops/status.sh against a server that serves only cosigned checkpoints.

With a witness configured, ``/v2/tlog/checkpoint`` states the committed tree (``tree_size``, ``root_hash_hex``) and
the served note (``signed_checkpoint``, whose size ``checkpoint_size`` is), which trails the tree while a
publication waits for its witness cosignature; ``/checkpoint`` and the tile mirror serve that note.  Neither script
may take that state for a failure: uptime-check compares the note with ``checkpoint_size`` (exit 2 only when they
disagree), status.sh compares the tile mirror with the served note (not "behind").  The real scripts run against
the fake curl of test_vantage_probe.

Run: uv run --no-project --with pytest pytest -q ops/vantage/tests
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from test_vantage_probe import API, OPS, ORIGIN, Env, note

TILES = "https://tiles.test"


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def envelope(tree_size: int, checkpoint_size: int | None, signed: str) -> str:
    """A /v2/tlog/checkpoint body; ``checkpoint_size`` None is a server from before cosigned serving."""
    doc = {"origin": ORIGIN, "tree_size": tree_size, "root_hash_hex": "02" * 32, "signed_checkpoint": signed}
    if checkpoint_size is not None:
        doc["checkpoint_size"] = checkpoint_size
    return json.dumps(doc)


def uptime(env: Env) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(env.ops / "uptime-check.sh")], capture_output=True, text=True, env={
        "PATH": f"{env.bin}:{os.environ['PATH']}", "FAKE_DIR": str(env.fake), "AICS_API_BASE_URL": API,
        "AICS_DISK_CHECK": "0", "AICS_LIMITS_CHECK": "0", "HOME": str(env.tmp)})


def status(env: Env) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(OPS / "status.sh"), API], capture_output=True, text=True, env={
        "PATH": f"{env.bin}:{os.environ['PATH']}", "FAKE_DIR": str(env.fake), "HOME": str(env.tmp),
        "AICS_TILES_BASE": TILES, "AICS_PAGES_BASE": "https://pages.test"})


def test_uptime_check_falls_back_to_the_envelope_of_a_publication_waiting_for_its_cosignature(env: Env) -> None:
    """/checkpoint and /tiles/checkpoint fail, so the probe reads /v2/tlog/checkpoint: its note (size 7, cosigned a
    moment ago) is the one checkpoint_size states, while tree_size (8) is ahead of it.  Before, the probe exited 2
    ("envelope tree_size 8 differs from the note's 7") whenever a publication waited for its cosignature."""
    served = note(7, cosig_ts=int(time.time()))
    env.drop(f"{API}/checkpoint")
    env.drop(f"{API}/tiles/checkpoint")
    env.route(f"{API}/v2/tlog/checkpoint", envelope(8, 7, served))
    p = uptime(env)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "ok: checkpoint at /v2/tlog/checkpoint" in p.stdout and "tree_size=7" in p.stdout
    # An envelope whose checkpoint_size is not its note's size still fails, and so does one of an older server (no
    # checkpoint_size) whose tree_size is not the note's; an older server's matching envelope passes.
    for doc in (envelope(8, 8, served), envelope(8, None, served)):
        env.route(f"{API}/v2/tlog/checkpoint", doc)
        p = uptime(env)
        assert p.returncode == 2 and "checkpoint_size 8 differs from the note's 7" in p.stderr, p.stdout + p.stderr
    env.route(f"{API}/v2/tlog/checkpoint", envelope(7, None, served))
    p = uptime(env)
    assert p.returncode == 0, p.stdout + p.stderr


def test_status_compares_the_tile_mirror_with_the_served_note(env: Env) -> None:
    """The tile mirror copies the served note (size 7): the mirror is consistent, not "behind" the committed tree
    (size 8), and the report says the tree is ahead while a publication waits for its cosignature."""
    served = note(7, cosig_ts=int(time.time()))
    env.route(f"{API}/v2/tlog/checkpoint", envelope(8, 7, served))
    env.route(f"{API}/checkpoint", served)
    env.route(f"{TILES}/checkpoint", served)
    p = status(env)
    assert p.returncode == 0, p.stdout + p.stderr
    assert f"checkpoint (api):   origin={ORIGIN} size=7 " in p.stdout
    assert "mirror consistency: ok" in p.stdout and "behind" not in p.stdout
    assert "tree (committed):   size=8, ahead of the served checkpoint" in p.stdout
    # A mirror with another root at the served size is still a divergence (exit 2).
    env.route(f"{TILES}/checkpoint", note(7, root=b"\x03" * 32))
    p = status(env)
    assert p.returncode == 2 and "mirror divergence" in p.stderr, p.stdout + p.stderr

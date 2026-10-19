"""End-to-end CLI tests (build-tiles, verify-checkpoint, verify-inclusion,
verify-consistency) run via `python -m aics_tlog`."""

import base64
import json
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import (
    Checkpoint,
    MerkleTree,
    Note,
    cosignature_vkey,
    sign_checkpoint,
    sign_cosignature,
    vkey_from_ed25519,
)
from aics_tlog.note import format_vkey
from aics_tlog.tiles import (
    TileWriter,
    consistency_proof_from_tiles,
    inclusion_proof_from_tiles,
)
from conftest import make_leaves


def run_cli(*args, cwd, stdin=None):
    return subprocess.run(
        [sys.executable, "-m", "aics_tlog", *args],
        cwd=cwd,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.fixture(scope="module")
def workspace(tmp_path_factory):
    ws = tmp_path_factory.mktemp("cli")
    leaves = make_leaves(600)
    (ws / "leaves.txt").write_text("".join(l.decode() + "\n" for l in leaves))
    TileWriter(leaves).write_to(ws / "tiles")

    log, wit = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    tree = MerkleTree(leaves)
    cp = Checkpoint(origin="demo.example/log", size=600, root=tree.root())
    note = sign_checkpoint(cp, log, "demo.example/log")
    _, cosig = sign_cosignature(wit, "wit.example/w1", 1767000000, cp.origin, cp.size, cp.root)
    (ws / "checkpoint.note").write_text(
        Note(text=note.text, signatures=(cosig, note.signatures[0])).serialise()
    )
    (ws / "log.vkey").write_text(format_vkey(vkey_from_ed25519("demo.example/log", log.public_key())))
    (ws / "wit.vkey").write_text(format_vkey(cosignature_vkey("wit.example/w1", wit.public_key())))

    reader = TileWriter(leaves).to_memory_reader()
    inc = inclusion_proof_from_tiles(reader, 42, 600)
    (ws / "proof42.b64").write_text(
        "".join(base64.b64encode(h).decode() + "\n" for h in inc)
    )
    cons = consistency_proof_from_tiles(reader, 256, 600)
    (ws / "cons256-600.b64").write_text(
        "".join(base64.b64encode(h).decode() + "\n" for h in cons)
    )
    (ws / "root.b64").write_text(base64.b64encode(tree.root()).decode())
    (ws / "root256.b64").write_text(base64.b64encode(tree.root(256)).decode())
    return ws


def test_help_and_version(workspace):
    for args in (["--help"], ["--version"], ["verify-inclusion", "--help"]):
        r = run_cli(*args, cwd=workspace)
        assert r.returncode == 0
        assert r.stdout


def test_build_tiles_matches_checkpoint_root(workspace):
    out = workspace / "tiles-cli"
    r = run_cli("build-tiles", "--leaves", "leaves.txt", "--out", str(out), cwd=workspace)
    assert r.returncode == 0, r.stderr
    report = json.loads(r.stdout)
    assert report["ok"] is True and report["size"] == 600
    # same root as the signed checkpoint
    cp = run_cli(
        "verify-checkpoint",
        "--note", "checkpoint.note",
        "--log-key", (workspace / "log.vkey").read_text(),
        "--quorum", "0",
        cwd=workspace,
    )
    assert json.loads(cp.stdout)["root"] == report["root"]


def test_verify_checkpoint_with_quorum(workspace):
    r = run_cli(
        "verify-checkpoint",
        "--note", "checkpoint.note",
        "--log-key", (workspace / "log.vkey").read_text(),
        "--witness-key", (workspace / "wit.vkey").read_text(),
        "--quorum", "1",
        "--origin", "demo.example/log",
        cwd=workspace,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    report = json.loads(r.stdout)
    assert report["ok"] and report["cosignatures"] == 1


def test_verify_checkpoint_quorum_failure(workspace):
    r = run_cli(
        "verify-checkpoint",
        "--note", "checkpoint.note",
        "--log-key", (workspace / "log.vkey").read_text(),
        "--quorum", "1",
        cwd=workspace,
    )
    assert r.returncode == 1
    assert json.loads(r.stdout)["ok"] is False


def test_verify_inclusion_leaf_line_and_stdin(workspace):
    r = run_cli(
        "verify-inclusion",
        "--leaf-line", "43",
        "--leaves-file", "leaves.txt",
        "--index", "42",
        "--checkpoint", "checkpoint.note",
        "--proof", "proof42.b64",
        cwd=workspace,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["ok"] is True

    # raw leaf bytes via stdin (leaf = line without its newline)
    line = (workspace / "leaves.txt").read_text().split("\n")[42]
    r = run_cli(
        "verify-inclusion",
        "--leaf=-",
        "--index", "42",
        "--size", "600",
        "--root", (workspace / "root.b64").read_text(),
        "--proof", "proof42.b64",
        cwd=workspace,
        stdin=line,
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_verify_inclusion_tampered_proof_fails(workspace):
    proof = (workspace / "proof42.b64").read_text().splitlines()
    bad = base64.b64encode(
        bytes(a ^ 1 for a in base64.b64decode(proof[0]))
    ).decode()
    r = run_cli(
        "verify-inclusion",
        "--leaf-line", "43",
        "--leaves-file", "leaves.txt",
        "--index", "42",
        "--size", "600",
        "--root", (workspace / "root.b64").read_text(),
        "--proof", "-",
        cwd=workspace,
        stdin="\n".join([bad] + proof[1:]),
    )
    assert r.returncode == 1
    assert json.loads(r.stdout)["ok"] is False


def test_verify_consistency(workspace):
    r = run_cli(
        "verify-consistency",
        "--old-size", "256",
        "--new-size", "600",
        "--old-root", (workspace / "root256.b64").read_text(),
        "--new-root", (workspace / "root.b64").read_text(),
        "--proof", "cons256-600.b64",
        cwd=workspace,
    )
    assert r.returncode == 0, r.stdout + r.stderr

    r = run_cli(
        "verify-consistency",
        "--old-size", "255",
        "--new-size", "600",
        "--old-root", (workspace / "root256.b64").read_text(),
        "--new-root", (workspace / "root.b64").read_text(),
        "--proof", "cons256-600.b64",
        cwd=workspace,
    )
    assert r.returncode == 1


def test_bad_json_report_and_exit_code(workspace):
    r = run_cli(
        "verify-checkpoint",
        "--note", "/nonexistent",
        "--log-key", (workspace / "log.vkey").read_text(),
        cwd=workspace,
    )
    assert r.returncode == 1
    report = json.loads(r.stdout)
    assert report["ok"] is False and report["error"]


# --- AICS-1 §14.2 step 1 in the CLI (interop finding F18) ----------------------


def test_verify_consistency_from_size_zero(workspace, tmp_path):
    import hashlib

    empty = base64.b64encode(hashlib.sha256(b"").digest()).decode()
    bad = base64.b64encode(hashlib.sha256(b"not the empty tree").digest()).decode()
    new_root = (workspace / "root.b64").read_text()
    (tmp_path / "none.b64").write_text("")
    (tmp_path / "one.b64").write_text(new_root + "\n")
    base = ["verify-consistency", "--old-size", "0", "--new-size", "600", "--new-root", new_root]
    r = run_cli(*base, "--old-root", empty, "--proof", str(tmp_path / "none.b64"), cwd=workspace)
    assert r.returncode == 0 and json.loads(r.stdout)["ok"], r.stdout
    r = run_cli(*base, "--old-root", bad, "--proof", str(tmp_path / "none.b64"), cwd=workspace)
    out = json.loads(r.stdout)
    assert r.returncode == 1 and "empty-tree root" in out["error"], r.stdout
    r = run_cli(*base, "--old-root", empty, "--proof", str(tmp_path / "one.b64"), cwd=workspace)
    out = json.loads(r.stdout)
    assert r.returncode == 1 and "must be empty" in out["error"], r.stdout
    # two size-0 heads: consistent only with the empty-tree root
    zero = ["verify-consistency", "--old-size", "0", "--new-size", "0", "--proof", str(tmp_path / "none.b64")]
    assert run_cli(*zero, "--old-root", empty, "--new-root", empty, cwd=workspace).returncode == 0
    assert run_cli(*zero, "--old-root", bad, "--new-root", bad, cwd=workspace).returncode == 1

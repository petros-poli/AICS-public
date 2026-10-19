"""CLI against tiles: --tiles (directory or URL, mirrors), --vkey-file and its
refusals, witness policy and freshness, split-view detection, bundles,
append-tiles."""

import base64
import hashlib
import json
import os
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import MerkleTree
from aics_tlog.checkpoint import Checkpoint, sign_checkpoint
from aics_tlog.cli import main
from aics_tlog.cosign import cosignature_vkey, sign_cosignature
from aics_tlog.note import Note, format_vkey, vkey_from_ed25519
from aics_tlog.writer import DirectoryTileStore, IncrementalTileWriter

from conftest import make_leaves
from tileserver import TileServer, dead_url

ORIGIN = "demo.example/tlog/v2"
LEAVES = make_leaves(600)
TREE = MerkleTree(LEAVES)


def _note(log, wit, size, root, cosign_time):
    cp = Checkpoint(ORIGIN, size, root)
    note = sign_checkpoint(cp, log, ORIGIN)
    if wit is None:
        return note
    _, cosig = sign_cosignature(wit, "wit.example/w1", cosign_time, ORIGIN, size, root)
    return Note(note.text, (cosig, note.signatures[0]))


def _publish(directory, leaves, log, wit, cosign_time, steps):
    """Append `leaves` in `steps` (cumulative sizes), publishing a checkpoint
    after each; returns the notes."""
    store = DirectoryTileStore(directory, fsync=False)
    writer = IncrementalTileWriter(store)
    notes = {}
    for size in steps:
        writer.append(leaves[writer.size : size])
        note = _note(log, wit, writer.size, writer.root(), cosign_time)
        store.write_checkpoint(note.to_bytes())
        notes[size] = note
    return notes


def _dir_files(directory):
    out = {}
    for root, _, files in os.walk(directory):
        for name in files:
            full = os.path.join(root, name)
            with open(full, "rb") as fh:
                out[os.path.relpath(full, directory).replace(os.sep, "/")] = fh.read()
    return out


@pytest.fixture(scope="module")
def ws(tmp_path_factory):
    d = tmp_path_factory.mktemp("cli-tiles")
    log, wit = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    now = int(time.time())
    notes = _publish(d / "tiles", LEAVES, log, wit, now - 100, [256, 600])
    (d / "old.note").write_bytes(notes[256].to_bytes())
    keys = d / "keys"
    keys.mkdir()
    log_vkey = format_vkey(vkey_from_ed25519(ORIGIN, log.public_key()))
    other = format_vkey(vkey_from_ed25519(ORIGIN, Ed25519PrivateKey.generate().public_key()))
    (keys / "aics.keys").write_text(f"# out-of-band keys\nlog {log_vkey}\npolicy {other}\n")
    (keys / "wrong.vkey").write_text(other + "\n")
    wit_vkey = format_vkey(cosignature_vkey("wit.example/w1", wit.public_key()))
    (keys / "policy.json").write_text(json.dumps({"quorum": 1, "witnesses": [wit_vkey], "max_checkpoint_age": 3600}))
    (keys / "policy0.json").write_text(json.dumps({"quorum": 0, "witnesses": [wit_vkey]}))
    (d / "tiles" / "aics.keys").write_text(f"log {log_vkey}\n")  # a key served with the tiles
    server = TileServer(_dir_files(d / "tiles"))
    yield {"dir": d, "log": log, "wit": wit, "now": now, "keys": keys, "server": server, "notes": notes,
           "log_vkey": log_vkey}
    server.close()


def cli(capsys, *args):
    code = main([str(a) for a in args])
    out = capsys.readouterr().out
    report = json.loads(out)
    assert (code == 0) == report["ok"], report
    return code, report


# --- verify-checkpoint ------------------------------------------------------------


def test_verify_checkpoint_from_directory(ws, capsys):
    code, r = cli(capsys, "verify-checkpoint", "--tiles", ws["dir"] / "tiles", "--vkey-file", ws["keys"] / "aics.keys")
    assert code == 0 and r["size"] == 600 and r["tiles_ok"] is True
    assert r["root"] == base64.b64encode(TREE.root()).decode()
    assert r["sources"][0]["ok"] is True


def test_verify_checkpoint_over_http_with_policy_and_mirrors(ws, capsys):
    url = ws["server"].url
    code, r = cli(capsys, "verify-checkpoint", "--tiles", dead_url(), "--tiles", url,
                  "--vkey-file", ws["keys"] / "aics.keys", "--policy-file", ws["keys"] / "policy.json")
    assert code == 0 and r["cosignatures"] == 1 and r["quorum"] == 1 and r["max_age"] == 3600
    assert "error" in r["sources"][0] and r["sources"][1]["ok"] is True


def test_freshness_and_policy_rules(ws, capsys):
    tiles = ws["dir"] / "tiles"
    key = ws["keys"] / "aics.keys"
    wit = format_vkey(cosignature_vkey("wit.example/w1", ws["wit"].public_key()))
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tiles, "--vkey-file", key,
                  "--witness-key", wit, "--quorum", "1", "--max-age", "10")
    assert code == 1 and "stale" in r["sources"][0]["error"]
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tiles, "--vkey-file", key,
                  "--policy-file", ws["keys"] / "policy0.json")
    assert code == 1 and "quorum >= 1" in r["error"]
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tiles, "--vkey-file", key,
                  "--policy-file", ws["keys"] / "policy.json", "--quorum", "1")
    assert code == 1 and "replaces" in r["error"]


def test_out_of_band_key_rules(ws, capsys):
    tiles = ws["dir"] / "tiles"
    url = ws["server"].url
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tiles, "--vkey-file", tiles / "aics.keys")
    assert code == 1 and "inside the tile directory" in r["error"]
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tiles, "--vkey-file", (tiles / "aics.keys").as_uri())
    assert code == 1 and "inside the tile directory" in r["error"]
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tiles.as_uri(), "--vkey-file", tiles / "aics.keys")
    assert code == 1 and "inside the tile directory" in r["error"]
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tiles, "--vkey-file", (ws["keys"] / "aics.keys").as_uri())
    assert code == 0
    code, r = cli(capsys, "verify-checkpoint", "--tiles", url, "--vkey-file", url + "aics.keys")
    assert code == 1 and "server being verified" in r["error"]
    code, r = cli(capsys, "verify-checkpoint", "--tiles", url, "--vkey-file", "https://keys.example/aics.keys")
    assert code == 1 and "local file" in r["error"]
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tiles)
    assert code == 1 and "out-of-band log key is required" in r["error"]
    code, r = cli(capsys, "verify-checkpoint", "--note", ws["dir"] / "old.note", "--vkey-file", ws["dir"] / "old.note")
    assert code == 1 and "same file" in r["error"]
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tiles, "--vkey-file", ws["keys"] / "wrong.vkey")
    assert code == 1 and "no tile source served a checkpoint" in r["error"]
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tiles, "--vkey-file", ws["keys"] / "aics.keys",
                  "--log-key", ws["log_vkey"])
    assert code == 1 and "not both" in r["error"]


def test_checkpoint_json_wrapper_ignores_server_key(ws, capsys, tmp_path):
    wrapper = tmp_path / "api.json"
    other = format_vkey(vkey_from_ed25519(ORIGIN, Ed25519PrivateKey.generate().public_key()))
    wrapper.write_text(json.dumps({"server_vkey": other, "signed_checkpoint": ws["notes"][600].serialise()}))
    code, r = cli(capsys, "verify-checkpoint", "--note", wrapper, "--vkey-file", ws["keys"] / "aics.keys")
    assert code == 0 and r["size"] == 600


def test_split_view_and_lagging_mirror(ws, capsys, tmp_path):
    forked = [b"fork-" + leaf for leaf in LEAVES]
    _publish(tmp_path / "fork", forked, ws["log"], ws["wit"], ws["now"], [600])
    key = ws["keys"] / "aics.keys"
    code, r = cli(capsys, "verify-checkpoint", "--tiles", ws["dir"] / "tiles", "--tiles", tmp_path / "fork", "--vkey-file", key)
    assert code == 1 and "split view" in r["error"] and len(r["evidence"]) == 2
    _publish(tmp_path / "fork2", LEAVES[:300] + forked[300:], ws["log"], None, 0, [400])
    code, r = cli(capsys, "verify-checkpoint", "--tiles", ws["dir"] / "tiles", "--tiles", tmp_path / "fork2", "--vkey-file", key)
    assert code == 1 and "not consistent" in r["error"]
    _publish(tmp_path / "lag", LEAVES, ws["log"], None, 0, [300])
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tmp_path / "lag", "--tiles", ws["dir"] / "tiles", "--vkey-file", key)
    assert code == 0 and r["size"] == 600 and [s["size"] for s in r["sources"]] == [300, 600]


# --- verify-inclusion / verify-bundle --------------------------------------------


def test_inclusion_from_tiles_and_bundle_round_trip(ws, capsys, tmp_path):
    tiles = ws["dir"] / "tiles"
    key = ws["keys"] / "aics.keys"
    code, r = cli(capsys, "verify-inclusion", "--tiles", ws["server"].url, "--vkey-file", key, "--index", "42",
                  "--bundle-out", tmp_path / "b.json", "--entry-out", tmp_path / "e.bin")
    assert code == 0 and r["entry_sha256"] == hashlib.sha256(LEAVES[42]).hexdigest()
    assert (tmp_path / "e.bin").read_bytes() == LEAVES[42]
    (tmp_path / "leaves.txt").write_text("".join(leaf.decode() + "\n" for leaf in LEAVES))
    code, r = cli(capsys, "verify-inclusion", "--tiles", tiles, "--vkey-file", key, "--index", "42",
                  "--leaf-line", "43", "--leaves-file", tmp_path / "leaves.txt")
    assert code == 0 and r["leaf_line"] == 43
    code, r = cli(capsys, "verify-inclusion", "--tiles", tiles, "--vkey-file", key, "--index", "42",
                  "--leaf-line", "44", "--leaves-file", tmp_path / "leaves.txt")
    assert code == 1 and "not included" in r["error"]
    code, r = cli(capsys, "verify-inclusion", "--tiles", tiles, "--vkey-file", key, "--index", "600")
    assert code == 1 and "not below" in r["error"]
    code, r = cli(capsys, "verify-inclusion", "--tiles", tiles, "--vkey-file", key, "--index", "1", "--size", "5")
    assert code == 1 and "drop --size" in r["error"]

    code, r = cli(capsys, "verify-bundle", "--bundle", tmp_path / "b.json", "--vkey-file", key, "--offline")
    assert code == 0 and r["offline"] is True and r["index"] == 42 and r["size"] == 600
    code, r = cli(capsys, "verify-bundle", "--bundle", tmp_path / "b.json", "--vkey-file", key,
                  "--tiles", ws["server"].url)
    assert code == 0 and r["still_in_log"] is True and r["latest_size"] == 600
    code, r = cli(capsys, "verify-bundle", "--bundle", tmp_path / "b.json", "--vkey-file", key,
                  "--offline", "--tiles", tiles)
    assert code == 1 and "--offline" in r["error"]
    # the file is the AICS-1 §14.3 wire bundle
    wire = json.loads((tmp_path / "b.json").read_text())
    assert tuple(wire) == ("entry_bytes", "index", "inclusion_proof", "checkpoint_note", "envelope", "body_or_ct")
    assert wire["entry_bytes"] == base64.urlsafe_b64encode(LEAVES[42]).decode().rstrip("=")
    assert wire["checkpoint_note"] == base64.urlsafe_b64encode(ws["notes"][600].to_bytes()).decode().rstrip("=")
    assert wire["envelope"] is None and wire["body_or_ct"] is None  # these entries embed no envelope
    # a member the wire form does not define is refused, never used (keys included)
    (tmp_path / "extra.json").write_text(json.dumps({**wire, "log_key": "attacker+00000000+AAAA"}))
    code, r = cli(capsys, "verify-bundle", "--bundle", tmp_path / "extra.json", "--vkey-file", key, "--offline")
    assert code == 1 and "log_key" in r["error"] and "does not define" in r["error"]
    (tmp_path / "bad.json").write_text(json.dumps({**wire, "index": 43}))
    code, r = cli(capsys, "verify-bundle", "--bundle", tmp_path / "bad.json", "--vkey-file", key, "--offline")
    assert code == 1 and "inclusion" in r["error"]
    legacy = {"entry_bytes_b64": base64.b64encode(LEAVES[42]).decode(), "index": 42,
              "inclusion_proof": wire["inclusion_proof"], "checkpoint_note": ws["notes"][600].serialise(),
              "envelope": None, "body_or_ct": None}
    (tmp_path / "legacy.json").write_text(json.dumps(legacy))
    code, r = cli(capsys, "verify-bundle", "--bundle", tmp_path / "legacy.json", "--vkey-file", key, "--offline")
    assert code == 1 and "pre-0.2" in r["error"]
    code, r = cli(capsys, "verify-bundle", "--bundle", tmp_path / "b.json", "--vkey-file", ws["keys"] / "wrong.vkey", "--offline")
    assert code == 1


def test_classic_inclusion_with_signed_checkpoint(ws, capsys, tmp_path):
    from aics_tlog.tiles import FileSystemTileReader, inclusion_proof_from_tiles

    proof = inclusion_proof_from_tiles(FileSystemTileReader(ws["dir"] / "tiles"), 7, 600)
    (tmp_path / "p.b64").write_text("".join(base64.b64encode(h).decode() + "\n" for h in proof))
    (tmp_path / "leaf").write_bytes(LEAVES[7])
    args = ["verify-inclusion", "--leaf", tmp_path / "leaf", "--index", "7", "--proof", tmp_path / "p.b64",
            "--checkpoint", ws["dir"] / "tiles" / "checkpoint"]
    code, r = cli(capsys, *args, "--vkey-file", ws["keys"] / "aics.keys")
    assert code == 0 and r["checkpoint_verified"] is True
    code, r = cli(capsys, *args)
    assert code == 0 and r["checkpoint_verified"] is False
    code, r = cli(capsys, *args, "--vkey-file", ws["keys"] / "wrong.vkey")
    assert code == 1 and "checkpoint" in r["error"]


# --- verify-consistency -------------------------------------------------------------


def test_consistency_from_saved_checkpoint(ws, capsys, tmp_path):
    key = ws["keys"] / "aics.keys"
    code, r = cli(capsys, "verify-consistency", "--tiles", ws["server"].url, "--vkey-file", key,
                  "--old-checkpoint", ws["dir"] / "old.note", "--save-checkpoint", tmp_path / "saved.note")
    assert code == 0 and r["old_size"] == 256 and r["new_size"] == 600 and r["proof_length"] > 0
    assert (tmp_path / "saved.note").read_bytes() == (ws["dir"] / "tiles" / "checkpoint").read_bytes()
    root300 = base64.b64encode(TREE.root(300)).decode()
    code, r = cli(capsys, "verify-consistency", "--tiles", ws["dir"] / "tiles", "--vkey-file", key,
                  "--old-size", "300", "--old-root", root300)
    assert code == 0
    # same size, same root
    code, r = cli(capsys, "verify-consistency", "--tiles", ws["dir"] / "tiles", "--vkey-file", key,
                  "--old-checkpoint", tmp_path / "saved.note")
    assert code == 0 and r["proof_length"] == 0


def test_consistency_detects_rewrite_and_rollback(ws, capsys, tmp_path):
    key = ws["keys"] / "aics.keys"
    forged = _note(ws["log"], None, 256, MerkleTree([b"x"] * 256).root(), 0)
    (tmp_path / "forged.note").write_bytes(forged.to_bytes())
    code, r = cli(capsys, "verify-consistency", "--tiles", ws["dir"] / "tiles", "--vkey-file", key,
                  "--old-checkpoint", tmp_path / "forged.note")
    assert code == 1 and "rewritten" in r["error"] and len(r["evidence"]) == 2
    future = _note(ws["log"], None, 700, MerkleTree([b"y"] * 700).root(), 0)
    (tmp_path / "future.note").write_bytes(future.to_bytes())
    code, r = cli(capsys, "verify-consistency", "--tiles", ws["dir"] / "tiles", "--vkey-file", key,
                  "--old-checkpoint", tmp_path / "future.note")
    assert code == 1 and "older than the saved one" in r["error"]
    unsigned = _note(Ed25519PrivateKey.generate(), None, 256, TREE.root(256), 0)
    (tmp_path / "unsigned.note").write_bytes(unsigned.to_bytes())
    code, r = cli(capsys, "verify-consistency", "--tiles", ws["dir"] / "tiles", "--vkey-file", key,
                  "--old-checkpoint", tmp_path / "unsigned.note")
    assert code == 1 and "old checkpoint" in r["error"]


# --- append-tiles ---------------------------------------------------------------------


def test_append_tiles_matches_build_tiles(capsys, tmp_path):
    for i, (lo, hi) in enumerate(((0, 100), (100, 300), (300, 600))):
        (tmp_path / f"part{i}.txt").write_text("".join(leaf.decode() + "\n" for leaf in LEAVES[lo:hi]))
        code, r = cli(capsys, "append-tiles", "--out", tmp_path / "inc", "--size", str(lo),
                      "--leaves", tmp_path / f"part{i}.txt", "--no-fsync")
        assert code == 0 and r["size"] == hi
    assert r["root"] == base64.b64encode(TREE.root()).decode() and r["pruned"] > 0
    (tmp_path / "all.txt").write_text("".join(leaf.decode() + "\n" for leaf in LEAVES))
    code, b = cli(capsys, "build-tiles", "--leaves", tmp_path / "all.txt", "--out", tmp_path / "full")
    assert b["root"] == r["root"]
    # wrong resume size: the right edge it names does not exist
    code, r = cli(capsys, "append-tiles", "--out", tmp_path / "inc", "--size", "601", "--leaves", tmp_path / "part0.txt")
    assert code == 1
    # building into a directory that holds a different log is refused
    (tmp_path / "other.txt").write_text("".join(f"other {i}\n" for i in range(300)))
    code, r = cli(capsys, "build-tiles", "--leaves", tmp_path / "other.txt", "--out", tmp_path / "full")
    assert code == 1 and "TileConflictError" in r["error"]


def test_entry_point_subprocess(ws):
    r = subprocess.run(
        [sys.executable, "-m", "aics_tlog", "verify-checkpoint", "--tiles", str(ws["dir"] / "tiles"),
         "--vkey-file", str(ws["keys"] / "aics.keys")],
        capture_output=True, text=True, timeout=120,
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert json.loads(r.stdout)["tiles_ok"] is True


def test_several_out_of_band_sources_must_agree(ws, capsys, tmp_path):
    (tmp_path / "dns.txt").write_text(ws["log_vkey"] + "\n")
    (tmp_path / "readme.txt").write_text(f"# from the README\nlog={ws['log_vkey']}\n")
    code, r = cli(capsys, "verify-checkpoint", "--tiles", ws["dir"] / "tiles",
                  "--vkey-file", tmp_path / "dns.txt", "--vkey-file", tmp_path / "readme.txt",
                  "--vkey-file", ws["keys"] / "aics.keys")
    assert code == 0 and len(r["key_sources"]) == 3
    assert r["log_key"] == "+".join(ws["log_vkey"].split("+")[:2])
    code, r = cli(capsys, "verify-checkpoint", "--tiles", ws["dir"] / "tiles",
                  "--vkey-file", tmp_path / "dns.txt", "--vkey-file", ws["keys"] / "wrong.vkey")
    assert code == 1 and "disagree" in r["error"]


def test_rollback_to_a_fresh_smaller_head_is_not_accepted(ws, capsys, tmp_path):
    """The origin serves a fresh checkpoint at 300 while a mirror still holds
    the (now stale) signed checkpoint at 600: the larger signed head wins and,
    being stale, fails -- the smaller fresh one is not silently accepted."""
    old = int(time.time()) - 100_000
    _publish(tmp_path / "origin", LEAVES, ws["log"], ws["wit"], int(time.time()), [300])
    _publish(tmp_path / "mirror", LEAVES, ws["log"], ws["wit"], old, [600])
    policy = ws["keys"] / "policy.json"
    key = ws["keys"] / "aics.keys"
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tmp_path / "origin", "--tiles", tmp_path / "mirror",
                  "--vkey-file", key, "--policy-file", policy)
    assert code == 1 and "largest validly signed checkpoint (size 600" in r["error"] and "stale" in r["error"]
    # Without a freshness rule the larger head is used, and the smaller is its prefix.
    code, r = cli(capsys, "verify-checkpoint", "--tiles", tmp_path / "origin", "--tiles", tmp_path / "mirror",
                  "--vkey-file", key)
    assert code == 0 and r["size"] == 600


def test_split_view_proven_by_a_stale_but_signed_note(ws, capsys, tmp_path):
    forked = [b"fork-" + leaf for leaf in LEAVES]
    _publish(tmp_path / "fork", forked, ws["log"], ws["wit"], int(time.time()) - 100_000, [600])
    code, r = cli(capsys, "verify-checkpoint", "--tiles", ws["dir"] / "tiles", "--tiles", tmp_path / "fork",
                  "--vkey-file", ws["keys"] / "aics.keys", "--policy-file", ws["keys"] / "policy.json")
    assert code == 1 and "split view" in r["error"] and len(r["evidence"]) == 2


def test_bundle_out_refuses_an_unbound_envelope(ws, capsys, tmp_path):
    (tmp_path / "env.json").write_text(json.dumps({"protected": {"kid": "x"}, "payload": {}, "sig": "AA=="}))
    code, r = cli(capsys, "verify-inclusion", "--tiles", ws["dir"] / "tiles", "--vkey-file", ws["keys"] / "aics.keys",
                  "--index", "5", "--bundle-out", tmp_path / "b.json", "--envelope", tmp_path / "env.json")
    assert code == 1 and "would not verify" in r["error"]
    assert not (tmp_path / "b.json").exists()


def test_consistency_from_size_zero_against_tiles(ws, capsys):
    """AICS-1 §14.2 step 1 with --tiles: a saved size-0 head must carry the empty-tree root."""
    key = ws["keys"] / "aics.keys"
    empty = base64.b64encode(hashlib.sha256(b"").digest()).decode()
    bad = base64.b64encode(hashlib.sha256(b"not the empty tree").digest()).decode()
    code, r = cli(capsys, "verify-consistency", "--tiles", ws["dir"] / "tiles", "--vkey-file", key,
                  "--old-size", "0", "--old-root", empty)
    assert code == 0 and r["proof_length"] == 0
    code, r = cli(capsys, "verify-consistency", "--tiles", ws["dir"] / "tiles", "--vkey-file", key,
                  "--old-size", "0", "--old-root", bad)
    assert code == 1 and "empty-tree root" in r["error"]


def test_consistency_from_a_signed_size_zero_note_with_a_bad_root(ws, capsys, tmp_path):
    bad_root = hashlib.sha256(b"not the empty tree").digest()
    forged = _note(ws["log"], None, 0, bad_root, 0)  # validly log-signed, but no size-0 tree has this root
    (tmp_path / "zero.note").write_bytes(forged.to_bytes())
    code, r = cli(capsys, "verify-consistency", "--tiles", ws["dir"] / "tiles", "--vkey-file", ws["keys"] / "aics.keys",
                  "--old-checkpoint", tmp_path / "zero.note")
    assert code == 1 and "empty-tree root" in r["error"] and len(r["evidence"]) == 2


def test_bundle_out_for_an_aics1_entry_carries_its_envelope(capsys, tmp_path):
    """--bundle-out writes the AICS-1 §14.3 wire bundle; without --envelope it carries the envelope the entry
    embeds, and --body binds through the entry's body_hash and size."""
    def J(x):
        return json.dumps(x, sort_keys=True, separators=(",", ":")).encode()

    body = J({"channel": "general", "text": "hi", "title": None})
    q = {"channel_sha256": hashlib.sha256(b"general").hexdigest(), "parent_index": None,
         "body_hash": hashlib.sha256(body).hexdigest(), "size": len(body), "title_sha256": None}
    env = {"v": 1, "protected": {"alg": "EdDSA", "origin": ORIGIN, "type": "post", "kid": "did:key:z6MkAgent",
                                 "created": 1800000000, "expires": 1800000300, "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
                                 "seq": 0, "prev": None, "seen": None},
           "payload": q, "auth": {"scheme": "ed25519-jcs"}, "sig": "c2ln"}
    entry = J({"v": 2, "origin": ORIGIN, "type": "post", "actor_kid": "did:key:z6MkAgent", "ts": 1800000000,
               "payload": {"envelope": env, **q}})
    log = Ed25519PrivateKey.generate()
    _publish(tmp_path / "tiles", [b"filler-0", entry, b"filler-2"], log, None, 0, [3])
    key = format_vkey(vkey_from_ed25519(ORIGIN, log.public_key()))
    (tmp_path / "body.bin").write_bytes(body)
    code, r = cli(capsys, "verify-inclusion", "--tiles", tmp_path / "tiles", "--log-key", key, "--index", "1",
                  "--bundle-out", tmp_path / "b.json", "--body", tmp_path / "body.bin")
    assert code == 0 and (r["envelope"], r["body"]) == ("$.payload.envelope", "$.payload.body_hash"), r
    wire = json.loads((tmp_path / "b.json").read_text())
    assert wire["envelope"] == env
    assert wire["body_or_ct"] == base64.urlsafe_b64encode(body).decode().rstrip("=")
    code, r = cli(capsys, "verify-bundle", "--bundle", tmp_path / "b.json", "--log-key", key, "--offline")
    assert code == 0 and r["aics1_entry"] is True and r["body"] == "$.payload.body_hash"
    # an envelope other than the embedded one is never written
    (tmp_path / "other.json").write_text(json.dumps({**env, "sig": "b3RoZXI"}))
    code, r = cli(capsys, "verify-inclusion", "--tiles", tmp_path / "tiles", "--log-key", key, "--index", "1",
                  "--bundle-out", tmp_path / "c.json", "--envelope", tmp_path / "other.json")
    assert code == 1 and "would not verify" in r["error"] and not (tmp_path / "c.json").exists()

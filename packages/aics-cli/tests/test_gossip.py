"""aics gossip-check: the G5 rule, refined by AICS-1 §14.6 (a split is
proven only constructively), and its evidence bundle."""

from __future__ import annotations

import io
import json

from aics_tlog import MerkleTree

from aics_cli.cli import run
from aics_cli.encoding import b64e

from conftest import NOW, Log, Witness, make_policy


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def test_same_head_twice_is_no_split(h, tmp_path):
    log = Log(10)
    make_policy(h.home, log)
    n = _write(tmp_path, "a.note", log.note())
    code, out = h.run("gossip-check", n, n)
    assert code == 0 and out["split"] is False
    assert h.fetcher.requests == []  # equal sizes need no network


def test_equal_size_different_roots_is_a_proven_split(h, tmp_path):
    log = Log(10)
    make_policy(h.home, log)
    a = _write(tmp_path, "a.note", log.note())
    b = _write(tmp_path, "b.note", log.fork(4).note())
    out_file = tmp_path / "evidence.json"
    code, out = h.run("gossip-check", a, b, "--out", str(out_file))
    assert code == 2, out
    ev = out["evidence"]
    assert ev["type"] == "aics-split-view-evidence/v1"
    assert ev["reason"] == "equal-size-different-root" and ev["classification"] == "split-proven"
    assert ev["log_vkey"] == log.vkey and ev["origin"] == log.origin
    assert {n["note"] for n in ev["pairs"][0]["notes"]} == {open(a).read(), open(b).read()}
    assert json.loads(out_file.read_text()) == ev
    # the same evidence again is fine; a different existing file is never overwritten
    assert h.run("gossip-check", a, b, "--out", str(out_file))[0] == 2
    other = tmp_path / "other.json"
    other.write_text("{}")
    code, out = h.run("gossip-check", a, b, "--out", str(other))
    assert code == 1 and "never overwritten" in out["error"]
    assert other.read_text() == "{}"


def test_text_mode_prints_the_bundle(h, tmp_path):
    log = Log(10)
    make_policy(h.home, log)
    a = _write(tmp_path, "a.note", log.note())
    b = _write(tmp_path, "b.note", log.fork(4).note())
    code, text = h.run_text("gossip-check", a, b)
    assert code == 2
    assert text.startswith("VERIFICATION FAILED: split-proven")
    bundle = json.loads(text.split("evidence:\n", 1)[1])
    assert bundle["reason"] == "equal-size-different-root"


def test_different_sizes_consistent_via_tiles(h, tmp_path):
    log = Log(300)
    make_policy(h.home, log)
    h.serve(log, 300)
    a = _write(tmp_path, "a.note", log.note(7))
    b = _write(tmp_path, "b.note", log.note(270))
    code, out = h.run("gossip-check", a, b)
    assert code == 0, out
    assert out["split"] is False


def test_different_sizes_with_a_rewritten_prefix_is_a_split(h, tmp_path):
    log = Log(300)
    make_policy(h.home, log)
    h.serve(log, 300)
    a = _write(tmp_path, "a.note", log.fork(2).note(7))  # a view nobody else got
    b = _write(tmp_path, "b.note", log.note(270))
    code, out = h.run("gossip-check", a, b)
    assert code == 2, out
    ev = out["evidence"]
    assert ev["reason"] == "not-a-prefix"
    pair = ev["pairs"][0]
    assert pair["notes"][0]["size"] == 7
    assert pair["proof"]["authenticated_prefix_root"] == b64e(log.root(7))


def test_bigger_note_off_the_reference_tree_is_a_split(h, tmp_path):
    log = Log(300)
    make_policy(h.home, log)
    h.serve(log, 300)
    a = _write(tmp_path, "a.note", log.note(7))
    b = _write(tmp_path, "b.note", log.fork(100).note(270))  # forks after a, before the reference
    code, out = h.run("gossip-check", a, b)
    assert code == 2
    sizes = sorted(n["size"] for n in out["evidence"]["pairs"][0]["notes"])
    assert sizes == [270, 300]  # the split is between note b and the log's current head


def test_proof_file_offline(h, tmp_path):
    log = Log(50)
    make_policy(h.home, log)
    a = _write(tmp_path, "a.note", log.note(9))
    b = _write(tmp_path, "b.note", log.note(50))
    proof = MerkleTree(log.entries).consistency_proof(9, 50)
    pf = _write(tmp_path, "proof.b64", "\n".join(b64e(x) for x in proof) + "\n")
    code, out = h.run("gossip-check", a, b, "--proof", pf, "--offline")
    assert code == 0, out
    assert h.fetcher.requests == []


def test_offline_without_proof_is_unproven(h, tmp_path):
    log = Log(50)
    make_policy(h.home, log)
    a = _write(tmp_path, "a.note", log.note(9))
    b = _write(tmp_path, "b.note", log.note(50))
    code, out = h.run("gossip-check", a, b, "--offline")
    assert code == 1
    assert "consistency-unproven" in out["error"] and "--proof" in out["error"]


def test_a_bad_proof_is_not_a_split(h, tmp_path):
    log = Log(50)
    make_policy(h.home, log)
    a = _write(tmp_path, "a.note", log.note(9))
    b = _write(tmp_path, "b.note", log.note(50))
    pf = _write(tmp_path, "proof.b64", b64e(b"\x00" * 32) + "\n")
    code, out = h.run("gossip-check", a, b, "--proof", pf, "--offline")
    assert code == 1
    assert out["split"] is None and "availability alert" in out["error"]


def test_note_not_signed_by_pinned_key_is_not_evidence(h, tmp_path):
    log = Log(10)
    make_policy(h.home, log)
    a = _write(tmp_path, "a.note", log.note())
    b = _write(tmp_path, "b.note", Log(10).note())  # another key, same origin
    code, out = h.run("gossip-check", a, b)
    assert code == 1
    assert "note 2" in out["error"] and "not evidence" in out["error"]


def test_witness_status_is_stated_for_each_note(h, tmp_path):
    log, w = Log(10), Witness("w.test/1")
    make_policy(h.home, log, witnesses=[w], quorum=1, max_age=60)
    old = NOW - 30 * 86400  # age does not matter for historical evidence
    a = _write(tmp_path, "a.note", log.note(cosigners=[(w, old)]))
    b = _write(tmp_path, "b.note", log.fork(1).note(cosigners=[(w, old)]))
    code, out = h.run("gossip-check", a, b)
    assert code == 2 and out["evidence"]["classification"] == "split-proven"
    c = _write(tmp_path, "c.note", log.fork(2).note())  # log-signed but never cosigned
    code, out = h.run("gossip-check", a, c)
    assert code == 2
    ev = out["evidence"]
    assert ev["classification"] == "log-equivocation"
    assert sorted(n["witness_policy_met"] for n in ev["pairs"][0]["notes"]) == [False, True]


def test_notes_from_url_and_stdin(h):
    log = Log(12)
    make_policy(h.home, log)
    h.fetcher.set("https://peer.example/seen.note", log.note())
    env = h.env
    env.stdin = io.StringIO(log.note())
    buf = io.StringIO()
    code = run(["gossip-check", "https://peer.example/seen.note", "-", "--json"], env=env, out=buf)
    assert code == 0, buf.getvalue()

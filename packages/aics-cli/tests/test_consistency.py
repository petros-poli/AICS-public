"""aics verify consistency --saved: every saved checkpoint is a prefix of
today's log (AICS-1 §14.2); splits only on constructive evidence (§14.6)."""

from __future__ import annotations

import json

from aics_tlog import MerkleTree, verify_consistency

from aics_cli.encoding import b64d_strict, b64e

from conftest import CHECKPOINT_URL, CONSISTENCY, MIRROR, NOW, TILES, Log, Witness, make_policy


def _save(h, log, size, cosigners=()):
    h.serve(log, size, cosigners)
    code, out = h.run("verify", "checkpoint")
    assert code == 0, out
    return out


def _evidence_note(h, note_text):
    """Store a note as evidence without advancing the head (another view this agent was shown)."""
    h.fetcher.set(CHECKPOINT_URL, note_text)
    h.run("verify", "checkpoint")


def test_growing_log_is_consistent_through_tiles(h):
    log = Log(5)
    make_policy(h.home, log)
    _save(h, log, 5)
    log.grow(300)  # crosses a full tile
    _save(h, log, 260)
    h.serve(log, 300)
    code, out = h.run("verify", "consistency", "--saved")
    assert code == 0, out
    assert out["consistent"] == 2
    assert {c["status"] for c in out["checked"]} == {"consistent"}
    assert all(c["proof_source"] == f"tiles {TILES}" for c in out["checked"])
    assert out["latest"]["size"] == 300 and out["saved_latest"]["role"] == "head"


def test_first_run_has_nothing_to_compare(h):
    log = Log(5)
    make_policy(h.home, log)
    h.serve(log)
    code, out = h.run("verify", "consistency")
    assert code == 0
    assert out["checked"] == [] and out["saved_latest"]["new"]


def test_rewritten_history_is_proven_with_both_notes(h):
    log = Log(300)
    make_policy(h.home, log)
    forked = log.fork(3)
    forked_note = forked.note(10)
    h.fetcher.set(CHECKPOINT_URL, forked_note)  # the view this agent was shown earlier
    assert h.run("verify", "checkpoint")[0] == 0
    honest_note = h.serve(log, 300)
    code, out = h.run("verify", "consistency", "--saved")
    assert code == 2, out
    ev = out["evidence"]
    assert ev["type"] == "aics-split-view-evidence/v1"
    assert ev["reason"] == "not-a-prefix" and ev["classification"] == "split-proven"
    assert {n["note"] for n in ev["pairs"][0]["notes"]} == {forked_note, honest_note}
    proof = ev["pairs"][0]["proof"]
    # anyone can re-check: the proof authenticates a different root at size 10
    prefix = b64d_strict(proof["authenticated_prefix_root"])
    assert prefix == log.root(10) != forked.root(10)
    hashes = [b64d_strict(x) for x in proof["proof"]]
    assert verify_consistency(10, 300, prefix, log.root(300), hashes)
    assert not verify_consistency(10, 300, forked.root(10), log.root(300), hashes)
    assert out["saved_latest"]["role"] == "evidence"


def test_equal_size_different_root_is_a_split(h):
    log = Log(8)
    make_policy(h.home, log)
    _evidence_note(h, log.fork(7).note(8))
    h.serve(log, 8)
    code, out = h.run("verify", "consistency")
    assert code == 2
    assert out["evidence"]["reason"] == "equal-size-different-root"
    assert len(out["evidence"]["pairs"][0]["notes"]) == 2


def test_power_of_two_saved_size_fork_is_proven(h):
    log = Log(40)
    make_policy(h.home, log)
    _evidence_note(h, log.fork(1).note(16))
    h.serve(log, 40)
    code, out = h.run("verify", "consistency")
    assert code == 2
    assert out["evidence"]["reason"] == "not-a-prefix"
    assert out["evidence"]["pairs"][0]["proof"]["authenticated_prefix_root"]


def test_consistency_endpoint_is_used_when_configured(h):
    log = Log(20)
    make_policy(h.home, log, consistency_url=CONSISTENCY)
    _save(h, log, 7)
    h.fetcher.set(CHECKPOINT_URL, log.note(20))
    h.fetcher.serve_tiles(TILES, {})  # no tiles: only the endpoint can prove it
    proof = MerkleTree(log.entries).consistency_proof(7, 20)
    h.fetcher.set("https://api.log.test/v2/tlog/consistency?from=7&to=20",
                  json.dumps({"from": 7, "to": 20, "hashes": [b64e(x) for x in proof]}))
    code, out = h.run("verify", "consistency")
    assert code == 0, out
    assert out["checked"][0]["proof_source"].startswith("consistency endpoint")


def test_endpoint_with_a_wrong_echo_or_noncanonical_hash_is_not_used(h):
    log = Log(20)
    make_policy(h.home, log, consistency_url=CONSISTENCY)
    _save(h, log, 7)
    h.fetcher.set(CHECKPOINT_URL, log.note(20))
    h.fetcher.serve_tiles(TILES, {})
    proof = MerkleTree(log.entries).consistency_proof(7, 20)
    url = "https://api.log.test/v2/tlog/consistency?from=7&to=20"
    h.fetcher.set(url, json.dumps({"from": 6, "to": 20, "hashes": [b64e(x) for x in proof]}))
    code, out = h.run("verify", "consistency")
    endpoint = [a for a in out["checked"][0]["attempts"] if a["source"].startswith("consistency endpoint")]
    assert code == 1 and endpoint[0]["status"] == "invalid" and "not 7->20" in endpoint[0]["detail"]
    h.fetcher.set(url, json.dumps({"from": 7, "to": 20, "hashes": [b64e(x).rstrip("=") for x in proof]}))
    code, out = h.run("verify", "consistency")
    assert code == 1


def test_bad_tiles_on_origin_fall_back_to_a_good_mirror(h):
    log = Log(300)
    make_policy(h.home, log, mirrors=[MIRROR])
    _save(h, log, 5)
    h.serve(log, 300)
    tiles = log.tiles(300)
    corrupt = dict(tiles)
    t = bytearray(corrupt["tile/0/000"])
    t[200] ^= 1
    corrupt["tile/0/000"] = bytes(t)
    h.fetcher.serve_tiles(TILES, corrupt)
    h.fetcher.serve_tiles(MIRROR, tiles)
    code, out = h.run("verify", "consistency")
    assert code == 0, out
    assert out["checked"][0]["proof_source"] == f"tiles {MIRROR}"
    assert out["checked"][0]["attempts"][0]["status"] == "invalid"


def test_only_bad_tiles_is_unproven_not_a_split(h):
    log = Log(300)
    make_policy(h.home, log)
    _save(h, log, 5)
    h.serve(log, 300)
    corrupt = log.tiles(300)
    t = bytearray(corrupt["tile/0/000"])
    t[200] ^= 1
    corrupt["tile/0/000"] = bytes(t)
    h.fetcher.serve_tiles(TILES, corrupt)
    code, out = h.run("verify", "consistency")
    assert code == 1, out  # a bad proof does not show that no valid proof exists
    assert "availability alert" in out["error"]
    assert out["checked"][0]["reason"] == "invalid-proof-data"


def test_missing_tiles_are_unproven(h):
    log = Log(30)
    make_policy(h.home, log)
    _save(h, log, 5)
    h.fetcher.set(CHECKPOINT_URL, log.note(30))
    h.fetcher.serve_tiles(TILES, {})
    code, out = h.run("verify", "consistency")
    assert code == 1
    assert out["checked"][0]["status"] == "unproven"
    assert out["checked"][0]["reason"] == "no-proof-available"


def test_unreachable_tiles_are_unproven(h):
    log = Log(30)
    make_policy(h.home, log)
    _save(h, log, 5)
    h.fetcher.set(CHECKPOINT_URL, log.note(30))
    h.fetcher.serve_tiles(TILES, {})
    for path in log.tiles(30):
        h.fetcher.fail(TILES + path)
    code, out = h.run("verify", "consistency")
    assert code == 1


def test_latest_must_itself_verify(h):
    log, w = Log(30), Witness("w.test/1")
    make_policy(h.home, log, witnesses=[w], quorum=1)
    _save(h, log, 5, [(w, NOW - 5)])
    h.serve(log, 30, [(w, NOW - 10 * 86400)])  # stale
    code, out = h.run("verify", "consistency")
    assert code == 1 and out["result"] == "stale" and out["reason"] == "quorum"


def test_a_log_key_rotation_keeps_the_saved_history(h):
    """Saved notes stay verified under the key they were saved under, and a
    consistency proof from their roots to the new log's head is required
    (AICS-1 §6.4: replacing a key does not reset history)."""
    old_log = Log(5)
    make_policy(h.home, old_log)
    _save(h, old_log, 5)
    new_log = Log(9)  # a new key over the same entries: an honest rotation
    make_policy(h.home, new_log)
    h.serve(new_log, 9)
    code, out = h.run("verify", "checkpoint")
    assert code == 0, out
    assert out["continuity"]["status"] == "consistent"
    assert any("key change" in w for w in out["warnings"])
    code, out = h.run("verify", "consistency")
    assert code == 0, out
    assert out["consistent"] == 1
    assert any("saved under" in w for w in out["warnings"])


def test_notes_saved_before_keys_were_recorded_use_the_archived_policy(h):
    old_log = Log(5)
    make_policy(h.home, old_log)
    _save(h, old_log, 5)
    index = h.home / "checkpoints" / "index.jsonl"
    recs = [json.loads(x) for x in index.read_text().splitlines()]
    index.write_text("".join(json.dumps({k: v for k, v in r.items() if k != "log_vkey"}) + "\n" for r in recs))
    new_log = Log(9)
    make_policy(h.home, new_log)  # archives the old policy in policy-history/
    h.serve(new_log, 9)
    code, out = h.run("verify", "consistency")
    assert code == 0, out
    assert out["consistent"] == 1


def test_a_log_key_rotation_cannot_hide_a_rewrite(h):
    old_log = Log(5)
    make_policy(h.home, old_log)
    _save(h, old_log, 5)
    new_log = Log(9)
    new_log.entries[2] = b"rewritten"
    make_policy(h.home, new_log)
    h.serve(new_log, 9)
    code, out = h.run("verify", "consistency")
    assert code == 2, out
    keys = {n.get("log_vkey") for n in out["evidence"]["pairs"][0]["notes"]}
    assert keys == {old_log.vkey, new_log.vkey}  # each note carries the key that signed it
    assert h.run("verify", "checkpoint")[0] == 2  # the head check agrees


def test_saved_notes_that_cannot_be_authenticated_stop_the_check(h):
    old_log = Log(5)
    make_policy(h.home, old_log)
    _save(h, old_log, 5)
    index = h.home / "checkpoints" / "index.jsonl"
    index.write_text("")  # the record of which key verified it is gone
    new_log = Log(9)
    make_policy(h.home, new_log)
    for f in (h.home / "policy-history").glob("*.toml"):
        f.unlink()  # nor is the earlier policy on record
    h.serve(new_log, 9)
    code, out = h.run("verify", "consistency")
    assert code == 1 and "--reset-history" in out["error"]
    assert out["unverifiable"][0]["path"].endswith(".note")
    code, out = h.run("verify", "consistency", "--reset-history")
    assert code == 0, out
    assert out["history_reset"]["dropped"] and out["checked"] == []
    reset = [json.loads(x) for x in index.read_text().splitlines() if '"reset"' in x]
    assert reset and reset[0]["role"] == "reset" and reset[0]["dropped"]
    code, out = h.run("verify", "consistency")  # the reset is remembered
    assert code == 0, out


def test_an_older_consistent_head_is_historical_not_evidence(h):
    log = Log(50)
    make_policy(h.home, log)
    _save(h, log, 50)
    h.fetcher.set(CHECKPOINT_URL, log.note(20))  # the log now serves an older, smaller head
    code, out = h.run("verify", "consistency")
    assert code == 1, out
    assert out["result"] == "historical" and out["saved_latest"]["role"] == "observed"
    assert [c["status"] for c in out["checked"]] == ["historical"]


def test_a_smaller_head_off_the_saved_history_is_evidence(h):
    log = Log(50)
    make_policy(h.home, log)
    _save(h, log, 50)
    h.fetcher.set(CHECKPOINT_URL, log.fork(4).note(20))  # smaller, and a rewritten history
    code, out = h.run("verify", "consistency")
    assert code == 2, out
    ev = out["evidence"]
    assert ev["classification"] == "split-proven"
    assert sorted(n["size"] for n in ev["pairs"][0]["notes"]) == [20, 50]

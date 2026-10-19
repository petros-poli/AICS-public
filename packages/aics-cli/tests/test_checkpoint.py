"""aics verify checkpoint: log signature, witness quorum and freshness,
continuity with the saved head, append-only storage (AICS-1 §6, §14.1)."""

from __future__ import annotations

import json
import os

import pytest

from aics_cli.errors import PolicyError
from aics_cli.policy import dumps

from conftest import CHECKPOINT_URL, NOW, TILES, Log, Witness, make_policy


def index_lines(h):
    return [json.loads(x) for x in (h.home / "checkpoints" / "index.jsonl").read_text().splitlines()]


def test_valid_checkpoint_is_verified_and_saved_as_the_head(h):
    log, w = Log(5), Witness("witness.test/w1")
    make_policy(h.home, log, witnesses=[w], quorum=1)
    note = h.serve(log, cosigners=[(w, NOW - 60)])
    code, out = h.run("verify", "checkpoint")
    assert code == 0, out
    assert out["size"] == 5 and out["origin"] == log.origin
    assert out["log_signature"] == "ok" and out["freshness"] == "fresh"
    assert out["fresh_cosignatures"] == 1 and out["witnesses"][0]["status"] == "fresh"
    assert out["declared_trust_domains"] == ["founder"]  # the card's claim, reported as such
    assert out["declared_independent_witnesses"] == 0 and out["assessed_independent_witnesses"] == []
    assert any("independent" in w and "G5" in w for w in out["warnings"])  # G5 stays promised
    assert out["trust_root"] == "dns only, unauthenticated"
    assert out["continuity"]["status"] == "first"
    saved = out["saved"]
    assert saved["new"] is True and saved["role"] == "head"
    assert open(saved["path"], encoding="utf-8").read() == note
    rec = index_lines(h)
    assert len(rec) == 1 and rec[0]["size"] == 5 and rec[0]["role"] == "head" and len(rec[0]["policy_sha256"]) == 64
    assert out["key_sources"]["pypi_constant"] == "placeholder"


def test_saving_never_overwrites_and_the_head_advances_with_proof(h):
    log, w = Log(5), Witness("witness.test/w1")
    make_policy(h.home, log, witnesses=[w], quorum=1)
    h.serve(log, cosigners=[(w, NOW - 60)])
    code, first = h.run("verify", "checkpoint")
    assert code == 0
    path = first["saved"]["path"]
    os.utime(path, (1, 1))
    code, second = h.run("verify", "checkpoint")
    assert code == 0
    assert second["saved"]["path"] == path and second["saved"]["new"] is False
    assert second["continuity"]["status"] == "same as the saved head"
    assert os.stat(path).st_mtime == 1  # untouched
    log.grow(300)
    h.serve(log, cosigners=[(w, NOW - 30)])
    code, third = h.run("verify", "checkpoint")
    assert code == 0, third
    assert third["continuity"]["status"] == "consistent" and third["saved"]["role"] == "head"
    assert [r["role"] for r in index_lines(h)] == ["head", "head", "head"]


def test_a_fork_of_the_saved_head_is_rejected_with_evidence(h):
    log = Log(40)
    make_policy(h.home, log)
    h.serve(log, 10)
    assert h.run("verify", "checkpoint")[0] == 0
    forked = log.fork(3)
    h.serve(forked, 40)
    code, out = h.run("verify", "checkpoint")
    assert code == 2, out
    assert out["evidence"]["reason"] == "not-a-prefix"
    assert out["saved"]["role"] == "evidence"  # kept, but the head did not move
    code, out = h.run("verify", "checkpoint")
    assert code == 2  # still measured against the old head


def test_an_older_consistent_head_is_historical_not_adopted(h):
    log = Log(50)
    make_policy(h.home, log)
    h.serve(log, 50)
    assert h.run("verify", "checkpoint")[0] == 0
    h.fetcher.set(CHECKPOINT_URL, log.note(20))  # e.g. a stale cache in front of the log: not evidence
    code, out = h.run("verify", "checkpoint")
    assert code == 1, out
    assert out["result"] == "historical" and out["continuity"]["status"] == "historical"
    assert "not adopted" in out["error"]
    assert index_lines(h)[-1]["role"] == "observed"
    h.serve(log, 20)  # the tiles shrank as well: consistency with the saved head can no longer be proven
    code, out = h.run("verify", "checkpoint")
    assert code == 1 and out["continuity"]["status"] == "unproven"
    h.serve(log, 50)
    code, out = h.run("verify", "checkpoint")
    assert code == 0 and out["continuity"]["status"] == "same as the saved head"  # the head stayed at 50


def test_a_smaller_head_that_rewrote_history_is_evidence(h):
    log = Log(50)
    make_policy(h.home, log)
    h.serve(log, 50)
    assert h.run("verify", "checkpoint")[0] == 0
    forked = log.fork(3)
    h.fetcher.set(CHECKPOINT_URL, forked.note(20))  # smaller, and not a prefix of the saved head
    h.fetcher.serve_tiles(TILES, log.tiles(50))
    code, out = h.run("verify", "checkpoint")
    assert code == 2, out
    assert out["evidence"]["classification"] == "split-proven" and "smaller" in out["error"]


def test_unprovable_continuity_does_not_advance_the_head(h):
    log = Log(40)
    make_policy(h.home, log)
    h.serve(log, 10)
    assert h.run("verify", "checkpoint")[0] == 0
    h.fetcher.set(CHECKPOINT_URL, log.note(40))
    h.fetcher.serve_tiles(TILES, {})  # tiles gone
    code, out = h.run("verify", "checkpoint")
    assert code == 1
    assert "head was not advanced" in out["error"]
    assert index_lines(h)[-1]["role"] == "evidence"
    h.serve(log, 40)  # tiles back: now it advances
    code, out = h.run("verify", "checkpoint")
    assert code == 0 and out["saved"]["role"] == "head"


def test_stale_cosignature_is_stale_not_evidence(h):
    log, w = Log(5), Witness("witness.test/w1")
    make_policy(h.home, log, witnesses=[w], quorum=1, max_age=3600)
    note = h.serve(log, cosigners=[(w, NOW - 7200)])
    code, out = h.run("verify", "checkpoint")
    assert code == 1, out  # AICS-1 §14: stale, which anyone can replay; exit 2 is kept for evidence
    assert out["error"].startswith("stale") and out["result"] == "stale"
    assert out["reason"] == "quorum" and out["note"] == note
    assert out["witnesses"][0]["status"] == "stale" and out["witnesses"][0]["age_seconds"] == 7200
    assert not (h.home / "checkpoints" / "index.jsonl").exists()  # nothing saved


@pytest.mark.parametrize("offset,status,code", [(29, "fresh", 0), (31, "future", 1)])
def test_future_skew_is_thirty_seconds(h, offset, status, code):
    log, w = Log(5), Witness("witness.test/w1")
    make_policy(h.home, log, witnesses=[w], quorum=1)
    h.serve(log, cosigners=[(w, NOW + offset)])
    rc, out = h.run("verify", "checkpoint")
    assert rc == code
    wit = (out.get("witnesses") or out["evidence"]["witnesses"])[0]
    assert wit["status"] == status


def test_policy_refuses_one_key_under_two_witness_names(h):
    log, w = Log(5), Witness("witness.test/w1")
    alias = Witness("witness.test/alias")
    from aics_tlog import cosignature_vkey, format_vkey

    alias.vkey = format_vkey(cosignature_vkey(alias.name, w.key.public_key()))
    with pytest.raises(PolicyError, match="public key is listed twice"):
        make_policy(h.home, log, witnesses=[w, alias], quorum=1)


def test_missing_quorum_fails(h):
    log, w1, w2 = Log(5), Witness("w.test/1"), Witness("w.test/2")
    make_policy(h.home, log, witnesses=[w1, w2], quorum=2)
    h.serve(log, cosigners=[(w1, NOW - 10)])
    code, out = h.run("verify", "checkpoint")
    assert code == 1 and "quorum" in out["error"] and out["result"] == "stale"


def test_checkpoint_signed_by_another_key_fails(h):
    log = Log(5)
    make_policy(h.home, log)
    h.fetcher.set(CHECKPOINT_URL, Log(5).note())  # same origin, different key
    code, out = h.run("verify", "checkpoint")
    assert code == 2
    assert out["evidence"]["reason"] == "bad_signature"
    assert "no signature from log key" in out["error"]


def test_tampered_checkpoint_fails(h):
    log = Log(5)
    make_policy(h.home, log)
    lines = log.note().split("\n")
    lines[1] = "6"  # claim a bigger tree under the same signature
    h.fetcher.set(CHECKPOINT_URL, "\n".join(lines))
    code, out = h.run("verify", "checkpoint")
    assert code == 2 and "failed verification" in out["error"]


def test_invalid_cosignature_from_pinned_witness_rejects_the_checkpoint(h):
    log, w = Log(5), Witness("witness.test/w1")
    make_policy(h.home, log, witnesses=[w], quorum=1)
    good = log.note(cosigners=[(w, NOW - 10)])
    other = Log(6, key=log.key).note(cosigners=[(w, NOW - 10)])  # cosignature over a different head
    forged = good.rsplit("\n", 2)[0] + "\n" + other.rstrip("\n").split("\n")[-1] + "\n"
    h.fetcher.set(CHECKPOINT_URL, forged)
    code, out = h.run("verify", "checkpoint")
    assert code == 2 and "cosignature" in out["error"]


def test_wrong_origin_fails(h):
    log = Log(5)
    make_policy(h.home, log)
    h.fetcher.set(CHECKPOINT_URL, Log(5, origin="other.test/log", key=log.key).note())
    code, out = h.run("verify", "checkpoint")
    assert code == 2 and out["evidence"]["reason"] == "wrong_origin"


def test_extension_lines_are_not_an_aics_checkpoint(h):
    from aics_tlog import Checkpoint, sign_checkpoint

    log = Log(3)
    make_policy(h.home, log)
    cp = Checkpoint(log.origin, 3, log.root(3), extension_lines=("extra",))
    h.fetcher.set(CHECKPOINT_URL, sign_checkpoint(cp, log.key, log.origin).serialise())
    code, out = h.run("verify", "checkpoint")
    assert code == 1 and "three text lines" in out["error"]


def test_malformed_response_is_an_error_not_evidence(h):
    log = Log(5)
    make_policy(h.home, log)
    h.fetcher.set(CHECKPOINT_URL, "<html>maintenance</html>")
    assert h.run("verify", "checkpoint")[0] == 1


def test_unreachable_is_an_error(h):
    log = Log(5)
    make_policy(h.home, log)
    h.fetcher.fail(CHECKPOINT_URL)
    code, out = h.run("verify", "checkpoint")
    assert code == 1 and "connection refused" in out["error"]


def test_json_api_response_is_accepted_but_its_key_is_ignored(h):
    log = Log(5)
    make_policy(h.home, log)
    h.fetcher.set(CHECKPOINT_URL, json.dumps({"signed_checkpoint": log.note(), "server_vkey": Log(1).vkey}))
    code, out = h.run("verify", "checkpoint")
    assert code == 0
    assert any("ignored" in w for w in out["warnings"])


def test_quorum_zero_reports_freshness_unproven(h):
    log = Log(3)
    make_policy(h.home, log, quorum=0)
    h.serve(log)
    code, out = h.run("verify", "checkpoint")
    assert code == 0
    assert out["freshness"] == "unproven"
    assert any("promised" in w for w in out["warnings"])


def test_local_note_file(h, tmp_path):
    log = Log(4)
    make_policy(h.home, log)
    f = tmp_path / "cp.note"
    f.write_text(log.note())
    code, out = h.run("verify", "checkpoint", "--note", str(f))
    assert code == 0 and out["size"] == 4 and out["saved"] is None
    assert out["continuity"]["status"].startswith("not checked")
    assert h.fetcher.requests == []


def test_api_only_key_in_policy_is_refused(h):
    log = Log(3)
    pol = make_policy(h.home, log)
    api_only = {"log_vkey": ["api:https://api.log.test/v2/tlog/checkpoint"],
                "origin": ["api:https://api.log.test/v2/tlog/checkpoint"]}
    with pytest.raises(PolicyError):  # the writer refuses it ...
        make_policy(h.home, log, sources=api_only)
    pol.sources = api_only
    (h.home / "policy.toml").write_text(dumps(pol))  # ... so simulate a hand-edited file
    h.serve(log)
    code, out = h.run("verify", "checkpoint")
    assert code == 1 and "API host" in out["error"]
    assert h.fetcher.requests == []


def test_no_policy_is_an_error(h):
    code, out = h.run("verify", "checkpoint")
    assert code == 1 and "policy init" in out["error"]


def test_text_output(h):
    log, w = Log(5), Witness("witness.test/w1")
    make_policy(h.home, log, witnesses=[w], quorum=1)
    h.serve(log, cosigners=[(w, NOW - 60)])
    code, text = h.run_text("verify", "checkpoint")
    assert code == 0
    assert text.startswith(f"checkpoint ok: {log.origin} size 5")
    assert "witnesses  1/1 required" in text and "freshness  fresh" in text


# --- the AICS-1 Appendix A.3 test vector -----------------------------------

A3_LOG_VKEY = "log.example/aics-1+d34caeba+AYE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU"
A3_WITNESS_VKEY = "witness.example/w1+c3c1499d+BIqHX/8es4RRV3rNWv7kBUVlaN18ieCQhjoFV7x69J8X"
A3_NOTE_4 = (
    "log.example/aics-1\n4\nPPj+PEGLKQS5SGjh1C/GODYYecZdTrZD+FAUHMo+D08=\n\n"
    "— log.example/aics-1 00yuure2ZQ6O5z/3k7e+i2S3Y979UmSp7r4qaYHPvqBP4BMNR+mA6JoB+q8rX6guXSK8vixUDBwideb99sR+qrLXag8=\n"
    "— witness.example/w1 w8FJnQAAAABq1AwCrysUqRktYIWXtKxrgID5XAxPe4TSDCPcPbjy4pLeABOPTgKgeybY8Pjj9DNiWKxTjgrl0wVdWqYT4hTtMxKEAw==\n"
)
A3_NOTE_3 = (
    "log.example/aics-1\n3\nl8Lavw2FapIGVNaC1b79k5ZTKgdbKcP6yMe3MvODz7s=\n\n"
    "— log.example/aics-1 00yuulrcq6B1jBGE330RL5IqSDwmbaWPG6AF4jNqqlYX3aanb2xVQxuZImRCKNRIL57y2epg3ZqAo75R0YrIyjM3eAE=\n"
    "— witness.example/w1 w8FJnQAAAABq1AwAign7qPOXfnZHHHA8ayI3E+WMoFUVUGX8E32/X75FJGyvzpXoWVW72JAA0bPuVicV/GH+Gqf78fiDM7ANXCLgAg==\n"
)
A2_CONSISTENCY_3_4 = ["8Hp/k6E0nK5+HkFPPXnFUerg4h7QhSIjYDEW6kfsPNo=",
                      "6/b86KfvZNX8TUaUzBzmrx6MIqXalm+cS5BUp4toer4=",
                      "y9NuiypL6RwuQc5Ts2KHM86HZVy/ExlQ/HUreOPopCM="]


def a3_policy(h, max_age=300):
    from aics_cli.policy import Policy, save

    save(Policy(origin="log.example/aics-1", log_vkey=A3_LOG_VKEY, witness_vkeys=[A3_WITNESS_VKEY], quorum=1,
                max_checkpoint_age=max_age, sources={"log_vkey": ["manual"]}), h.home, force=True)


def test_spec_vector_a3_checkpoint(h, tmp_path):
    import hashlib

    assert hashlib.sha256(A3_NOTE_4.encode()).hexdigest() == \
        "fb2b18a043a1dffea3b70a4ddac14364c44701937557a40dcdbdd64fe8e59e70"
    a3_policy(h)
    f = tmp_path / "a3.note"
    f.write_text(A3_NOTE_4)
    h.clock[0] = 1792281602 + 10
    code, out = h.run("verify", "checkpoint", "--note", str(f))
    assert code == 0, out
    assert out["size"] == 4 and out["root"] == "PPj+PEGLKQS5SGjh1C/GODYYecZdTrZD+FAUHMo+D08="
    assert out["witnesses"][0] == {"name": "witness.example/w1", "timestamp": 1792281602, "age_seconds": 10,
                                   "status": "fresh"}
    h.clock[0] = 1792281602 + 301  # the same head, replayed later: the cosignature is stale
    code, out = h.run("verify", "checkpoint", "--note", str(f))
    assert code == 1 and out["witnesses"][0]["status"] == "stale"


def test_spec_vector_a3_gossip_with_the_a2_proof(h, tmp_path):
    a3_policy(h)
    n3, n4, pf = tmp_path / "n3", tmp_path / "n4", tmp_path / "proof"
    n3.write_text(A3_NOTE_3)
    n4.write_text(A3_NOTE_4)
    pf.write_text("\n".join(A2_CONSISTENCY_3_4) + "\n")
    code, out = h.run("gossip-check", str(n3), str(n4), "--proof", str(pf), "--offline")
    assert code == 0, out
    assert out["split"] is False

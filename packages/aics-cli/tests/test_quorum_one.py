"""A card at quorum 1 with one pinned witness, the shape of the genesis-v2 card (one founder witness on
witness.wesupport-ai.com, trust domain founder, not independent, max_checkpoint_age 300): aics verify checkpoint
reports each cosignature's age and verdict, where quorum 0 can only say "freshness unproven".  And since a log
publishes every new checkpoint before its witness cosigns it (aics-server merges the line a moment later; about 4 in
75 fetches of the live checkpoint had no witness line in the 2026-10-20 walk-throughs), a note that only lacks a
pinned witness's line is fetched again instead of failing a quorum-1 check intermittently, also while ``policy
init`` and ``verify card`` read the log's policy leaves under that card."""

from __future__ import annotations

import pytest

from conftest import CHECKPOINT_URL, DOMAIN, NOW, Instance, Log, Site, Witness, make_policy

#: Only a label: the brief of 2026-10-20 named w1, relaunch/card-content names w2 (it retires w1, which cosigned the
#: discarded first log).  Nothing here depends on the name.
GENESIS_V2_WITNESS = "witness.wesupport-ai.com/w2"


@pytest.fixture
def quorum_one(h):
    w = Witness(GENESIS_V2_WITNESS)
    inst = Instance(Log(5), witnesses=[w], quorum=1, max_age=300)
    inst.publish(h)
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1")
    assert code == 0, out
    return inst, w


def test_the_quorum_1_card_pins_its_witness(h, quorum_one):
    inst, w = quorum_one
    code, out = h.run("policy", "show")
    assert code == 0, out
    pol = out["policy"]
    assert pol["quorum"] == 1 and pol["witness_vkeys"] == [w.vkey] and pol["max_checkpoint_age"] == 300
    assert pol["witness_meta"] == {w.name: {"declared_trust_domain": "founder", "declared_independent": False}}
    assert pol["sources"]["quorum"][0].startswith("card:bootstrap:")


def test_verify_checkpoint_reports_the_cosignature_age_and_verdict(h, quorum_one):
    inst, w = quorum_one
    h.serve(inst.log, cosigners=[(w, NOW - 42)])
    code, text = h.run_text("verify", "checkpoint")
    assert code == 0, text
    assert f"witnesses  1/1 required: {w.name} fresh (42s old)" in text
    assert "freshness  fresh (the newest counted cosignature is 42s old; max_checkpoint_age 300s)" in text
    code, out = h.run("verify", "checkpoint")
    assert code == 0, out
    assert out["witnesses"] == [{"name": w.name, "timestamp": NOW - 42, "age_seconds": 42, "status": "fresh"}]
    assert out["freshness"] == "fresh" and out["fresh_cosignatures"] == 1 and out["quorum"] == 1
    assert out["declared_trust_domains"] == ["founder"] and out["declared_independent_witnesses"] == 0
    assert any("G5" in x for x in out["warnings"])  # a founder witness: single view stays promised


def test_the_same_log_at_quorum_0_only_says_unproven(h):
    log = Log(5)
    make_policy(h.home, log, quorum=0)
    h.serve(log, cosigners=[(Witness(GENESIS_V2_WITNESS), NOW - 42)])  # a line nobody pinned counts for nothing
    code, text = h.run_text("verify", "checkpoint")
    assert code == 0 and "freshness  unproven (quorum 0" in text and "witnesses  0/0 required: none pinned" in text


def test_a_cosignature_older_than_max_checkpoint_age_is_stale_and_not_waited_for(h, quorum_one):
    inst, w = quorum_one
    h.serve(inst.log, cosigners=[(w, NOW - 301)])
    code, out = h.run("verify", "checkpoint")
    assert code == 1 and out["result"] == "stale", out
    assert out["witnesses"] == [{"name": w.name, "timestamp": NOW - 301, "age_seconds": 301, "status": "stale"}]
    assert h.sleeps == [] and "retried" not in out


def test_a_checkpoint_served_before_its_witness_cosigned_is_fetched_again(h, quorum_one):
    inst, w = quorum_one
    h.serve(inst.log)
    h.fetcher.set_sequence(CHECKPOINT_URL, [inst.log.note(), inst.log.note(cosigners=[(w, NOW - 1)])])
    code, out = h.run("verify", "checkpoint")
    assert code == 0, out
    assert h.sleeps == [1.0] and h.fetcher.requests.count(CHECKPOINT_URL) == 2
    assert out["fresh_cosignatures"] == 1 and out["saved"]["new"]
    assert any(f"no line yet from the pinned witness(es) {w.name}" in x and "1 more time(s) over 1s" in x
               for x in out["warnings"]), out["warnings"]


def test_a_witness_that_never_cosigns_is_stale_after_the_waits(h, quorum_one):
    inst, w = quorum_one
    h.serve(inst.log)  # log-signed only, every time
    code, out = h.run("verify", "checkpoint")
    assert code == 1 and out["result"] == "stale", out
    assert h.sleeps == [1.0, 2.0, 3.0] and len(out["retried"]) == 3
    assert "still missing after 3 more fetch(es) over 6s" in out["error"]
    assert not (h.home / "checkpoints" / "index.jsonl").exists()


def test_consistency_and_status_wait_for_the_cosignature_too(h, quorum_one):
    inst, w = quorum_one
    h.serve(inst.log, cosigners=[(w, NOW - 5)])
    assert h.run("verify", "checkpoint")[0] == 0
    inst.log.grow(9)
    h.serve(inst.log)
    h.fetcher.set_sequence(CHECKPOINT_URL, [inst.log.note(), inst.log.note(cosigners=[(w, NOW - 1)])])
    code, out = h.run("verify", "consistency")
    assert code == 0 and out["consistent"] == 1, out
    h.fetcher.set_sequence(CHECKPOINT_URL, [inst.log.note(), inst.log.note(cosigners=[(w, NOW - 1)])])
    code, out = h.run("status")
    assert code == 0, out
    assert out["sources"][0]["retried"][0]["absent"] == [w.name]
    assert h.sleeps == [1.0, 1.0]


def test_a_line_that_does_not_verify_is_evidence_at_once(h, quorum_one):
    from test_adversarial_review import _poison

    inst, w = quorum_one
    h.serve(inst.log)
    h.fetcher.set(CHECKPOINT_URL, _poison(inst.log.note(), w.name, w.key.public_key().public_bytes_raw()))
    code, out = h.run("verify", "checkpoint")
    assert code == 2 and out["evidence"]["reason"] == "bad_cosignature" and h.sleeps == []


def test_quorum_2_waits_for_the_missing_witness(h):
    w1, w2 = Witness("w.test/1"), Witness("w.test/2")
    log = Log(5)
    make_policy(h.home, log, witnesses=[w1, w2], quorum=2)
    h.serve(log)
    h.fetcher.set_sequence(CHECKPOINT_URL, [log.note(cosigners=[(w1, NOW - 1)]),
                                            log.note(cosigners=[(w1, NOW - 1), (w2, NOW - 1)])])
    code, out = h.run("verify", "checkpoint")
    assert code == 0 and out["fresh_cosignatures"] == 2 and h.sleeps == [1.0], out


def test_the_genesis_v2_flow_reads_the_policy_leaves_while_the_witness_line_is_missing(h):
    """The relaunch flow: a quorum-1 bootstrap card logged as leaf 1, and every first fetch of the checkpoint a
    log-only note.  ``policy init`` reads the policy leaves under the bootstrap card's witness terms and pins the card
    in force, ``verify card`` reads them again under the pinned policy, and ``verify checkpoint`` then reports the
    cosignature's age; each waits once for the witness line instead of failing."""
    w = Witness(GENESIS_V2_WITNESS)
    site = Site(witnesses=[w], quorum=1, max_age=300)
    site.publish(h)

    def first_fetch_without_the_witness() -> None:
        h.fetcher.set_sequence(CHECKPOINT_URL, [site.log.note(), site.log.note(cosigners=[(w, h.clock[0] - 1)])])

    first_fetch_without_the_witness()
    code, out = site.pin(h)
    assert code == 0, out
    assert out["policy"]["quorum"] == 1 and out["policy"]["witness_vkeys"] == [w.vkey]
    assert out["card"]["status"] == "in-force" and out["card"]["currency"]["in_force"]["leaf_index"] == site.first
    assert out["card"]["currency"]["witness_policy_met"] is True and h.sleeps == [1.0]
    assert any(f"no line yet from the pinned witness(es) {w.name}" in x for x in out["warnings"]), out["warnings"]
    first_fetch_without_the_witness()
    code, out = h.run("verify", "card")
    assert code == 0 and out["currency_state"] == "in-force" and out["policy_history"]["witness_policy_met"], out
    assert h.sleeps == [1.0, 1.0]
    first_fetch_without_the_witness()
    code, out = h.run("verify", "checkpoint")
    assert code == 0 and out["freshness"] == "fresh" and out["witnesses"][0]["age_seconds"] == 1, out
    assert h.sleeps == [1.0, 1.0, 1.0]

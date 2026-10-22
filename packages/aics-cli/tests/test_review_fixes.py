"""Behaviour behind the fixes for the 2026-10-18 adversarial review that the
regression tests in test_adversarial_review.py do not pin down on their own:
saved history and --reset-history, re-pinning, card statuses and history,
escaping, key sources, exit codes, DNS answers and hostile JSON."""

from __future__ import annotations

import io
import json
import struct

import pytest
from aics_tlog import cosignature_vkey, format_vkey

from aics_cli import card as cardmod
from aics_cli.cli import run
from aics_cli.dnstxt import FLAG_QR, TYPE_TXT, DnsError, build_query, encode_name, parse_response
from aics_cli.encoding import escape_untrusted, printable_line
from aics_cli.errors import PolicyError
from aics_cli.policy import Policy, dumps, loads

from conftest import (
    CARD_URL,
    CHECKPOINT_URL,
    DOMAIN,
    MIRROR,
    NOW,
    Instance,
    Log,
    Witness,
    did,
    make_policy,
    policy_for,
)

ONE = ("--require-sources", "1")


def index_lines(h):
    return [json.loads(x) for x in (h.home / "checkpoints" / "index.jsonl").read_text().splitlines()]


# --- saved history (review 1) ------------------------------------------------


def test_every_save_records_the_log_key(h):
    log = Log(5)
    make_policy(h.home, log)
    h.serve(log)
    assert h.run("verify", "checkpoint")[0] == 0
    assert index_lines(h)[0]["log_vkey"] == log.vkey


def test_an_unverifiable_saved_head_is_an_error_until_reset(h):
    log = Log(5)
    make_policy(h.home, log)
    h.serve(log, 3)
    code, out = h.run("verify", "checkpoint")
    assert code == 0
    head = out["saved"]["path"]
    with open(head, "w", encoding="utf-8") as fh:  # the saved head is damaged
        fh.write("garbage\n")
    h.serve(log, 5)
    code, out = h.run("verify", "checkpoint")
    assert code == 1, out
    assert head in out["error"] and "--reset-history" in out["error"] and out["saved_head"] == head
    code, out = h.run("status")
    assert code == 1 and "--reset-history" in out["error"]
    code, out = h.run("verify", "checkpoint", "--reset-history")
    assert code == 0, out
    assert out["continuity"]["status"] == "first (history reset)"
    assert out["history_reset"]["dropped"] == [head.split("checkpoints/", 1)[1]]
    roles = [r["role"] for r in index_lines(h)]
    assert roles == ["head", "reset", "head"]
    code, out = h.run("verify", "checkpoint", "--reset-history")
    assert code == 0 and any("ignored" in w for w in out["warnings"])  # nothing left to reset


def test_a_reset_falls_back_to_an_older_verifiable_head(h):
    log = Log(40)
    make_policy(h.home, log)
    h.serve(log, 10)
    assert h.run("verify", "checkpoint")[0] == 0
    h.serve(log, 20)
    code, out = h.run("verify", "checkpoint")
    assert code == 0
    with open(out["saved"]["path"], "w", encoding="utf-8") as fh:
        fh.write("garbage\n")
    h.serve(log.fork(5), 40)  # a rewrite after size 10
    code, out = h.run("verify", "checkpoint", "--reset-history")
    assert code == 2, out  # continuity is still checked from the older head (size 10)
    assert out["evidence"]["classification"] == "split-proven"


def test_a_poisoned_saved_note_still_counts_for_consistency(h):
    """A junk line under a witness pinned later does not hide a note from
    verify consistency (clients poisoned before the fix are caught too)."""
    from test_adversarial_review import _poison

    w2 = Witness("witness.test/w2")
    log = Log(30)
    make_policy(h.home, log)
    forked = log.fork(1)
    h.fetcher.set(CHECKPOINT_URL, _poison(forked.note(10), w2.name, w2.key.public_key().public_bytes_raw()))
    assert h.run("verify", "checkpoint")[0] == 0
    make_policy(h.home, log, witnesses=[w2], quorum=1)  # w2 is pinned now
    h.serve(log, 30, [(w2, NOW - 5)])
    code, out = h.run("verify", "consistency")
    assert code == 2, out
    assert out["evidence"]["reason"] == "not-a-prefix"


# --- re-pinning (review 2) ---------------------------------------------------


def test_repin_with_an_older_bootstrap_card_after_a_newer_card_is_refused(h):
    from conftest import DAY, Site

    w = Witness("witness.test/w1")
    site = Site()
    site.publish(h)
    assert site.pin(h)[0] == 0
    newer = site.successor(witnesses=[w], quorum=1)
    h.clock[0] = NOW + 7 * DAY
    site.publish(h, served=newer)
    assert h.run("verify", "card")[0] == 0  # proven in force by the policy leaves: stored
    site.publish(h, listing=False)  # the older bootstrap card again, and no policy leaves to read
    code, out = site.pin(h, force=True)
    assert code == 2 and out["evidence"]["reason"] == "superseded", out


def test_repin_with_weaker_manual_terms_needs_allow_weaker(h):
    w = Witness("witness.test/w1")
    inst = Instance(Log(5), witnesses=[w], quorum=1)
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, *ONE)[0] == 0
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, *ONE, "--force", "--no-card", "--quorum", "0")
    assert code == 1 and "--allow-weaker" in out["error"]
    assert out["previous"]["quorum"] == 1 and out["new"]["quorum"] == 0
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, *ONE, "--force", "--no-card", "--quorum", "0",
                      "--allow-weaker")
    assert code == 0 and out["policy"]["quorum"] == 0
    assert any("--allow-weaker" in x for x in out["warnings"])


def test_repin_to_another_origin_needs_reset_history(h):
    inst = Instance(Log(5))
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, *ONE)[0] == 0
    h.serve(inst.log, 5)
    assert h.run("verify", "checkpoint")[0] == 0
    other = Instance(Log(9, origin="api.log.test/tiles2"))
    other.publish(h)
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, *ONE, "--force")
    assert code == 1 and "--reset-history" in out["error"]
    assert "api.log.test/tiles2" not in (h.home / "policy.toml").read_text()  # nothing was pinned
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, *ONE, "--force", "--reset-history")
    assert code == 0, out
    assert out["repin"]["history_reset"] == {"origin": "api.log.test/tiles", "dropped": 1}
    assert index_lines(h)[-1]["role"] == "reset"


# --- the card (reviews 3, 4, 10, 12) ----------------------------------------


@pytest.fixture
def inst(h):
    i = Instance(Log(5))
    policy_for(h.home, i)
    return i


def test_g7_proven_without_runtime_evidence_is_out_of_bounds(h, inst):
    def g7(body):
        body["assurances"][6]["status"] = "proven"

    h.fetcher.set(CARD_URL, json.dumps(inst.make_card(issued_at=NOW - 60, mutate=g7)))
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "assurance-bounds"
    assert "G7" in out["evidence"]["problems"][0]


def test_g5_proven_needs_two_witnesses_one_independent_and_the_assumption(h):
    w1, w2 = Witness("w.test/1"), Witness("w.test/2")
    inst = Instance(Log(5), witnesses=[w1, w2], quorum=2)

    def g5(body, independent, assumptions):
        body["witness_policy"]["witnesses"][1]["independent"] = independent
        body["assurances"][4].update(status="proven", assumptions=assumptions)

    ok = inst.make_card(mutate=lambda b: g5(b, True, ["any two quorums intersect in an honest witness"]))
    assert cardmod.assurance_problems(ok) == []
    assert cardmod.assurance_problems(inst.make_card(mutate=lambda b: g5(b, False, ["x"])))
    assert cardmod.assurance_problems(inst.make_card(mutate=lambda b: g5(b, True, [])))


def test_card_strings_with_format_or_separator_characters_are_rejected(inst):
    for bad in ("‮", " ", "\x00", "​"):
        card = inst.make_card(mutate=lambda b, c=bad: b["witness_policy"].update(quorum=0) or
                              b["proxy"][0].update(tls_termination=f"edge{c}"))
        problems = cardmod.schema_problems(card)
        assert any("control or format characters" in p for p in problems), bad


def test_card_witness_reusing_a_service_key_is_rejected(inst):
    log_as_witness = format_vkey(cosignature_vkey("w.test/log", inst.log.key.public_key()))
    owner_as_witness = format_vkey(cosignature_vkey("w.test/owner", inst.owner_key.public_key()))
    for vkey, name in ((log_as_witness, "w.test/log"), (owner_as_witness, "w.test/owner")):
        card = inst.make_card(mutate=lambda b, v=vkey, n=name: b["witness_policy"].update(
            quorum=1, witnesses=[{"name": n, "vkey": v, "trust_domain": "x", "independent": False}]))
        assert any("cannot act as witnesses" in p for p in cardmod.schema_problems(card))


def test_policy_refuses_a_witness_with_the_policy_or_owner_key():
    log, pk = Log(1), Witness("w.test/p")
    pol = Policy(origin=log.origin, log_vkey=log.vkey, policy_kid=did(pk.key), witness_vkeys=[pk.vkey], quorum=1,
                 max_checkpoint_age=300)
    with pytest.raises(PolicyError, match="policy key"):
        loads(dumps(pol))


def test_the_table_escapes_card_text():
    table = {"proven": [{"id": "G2", "claim": "ok\nfake line\x1b[8m", "evidence": 0}], "promised": [],
             "not-offered": [], "other": []}
    lines = cardmod.render_table(table)
    assert not any("\x1b" in x or "\n" in x for x in lines)
    assert any("claimed proven (evidence not verified)" in x and "\\u000afake line\\u001b[8m" in x for x in lines)


def test_text_output_never_carries_control_characters():
    assert escape_untrusted("a\nb\x1b\\c ") == "a\\u000ab\\u001b\\\\c\\u2028"
    assert printable_line("x\x1b[8my \u0085") == "x\\u001b[8my \\u0085"
    assert printable_line('{"a": "\\n"}') == '{"a": "\\n"}'  # JSON text stays JSON


def _card_index(h):
    path = h.home / "cards" / "index.jsonl"
    return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


def test_the_card_history_is_per_policy_key_not_per_host(h):
    from conftest import DAY, Site

    site = Site()
    newer = site.successor()
    h.clock[0] = NOW + 7 * DAY
    site.publish(h)
    site.policy(h)
    h.fetcher.set("https://mirror.example/.well-known/aics-card.json", json.dumps(site.card_of(newer)))
    assert h.run("verify", "card", "mirror.example")[0] == 0  # in force: stored for the policy key
    assert _card_index(h)[-1]["host"] == "mirror.example"
    site.publish(h, listing=False)  # the older card through the pinned URL; no policy leaves to read
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "superseded", out


def test_two_cards_for_one_moment_are_equivocation(h):
    from conftest import DAY, Site

    site = Site()
    first = site.successor()
    h.clock[0] = NOW + 7 * DAY
    site.publish(h, served=first)
    site.policy(h)
    assert h.run("verify", "card")[0] == 0  # in force: stored
    second = site.make_card(issued_at=site.card_of(first)["issued_at"], mutate=lambda b: b.update(
        policy_notice_seconds=1))
    h.fetcher.set(CARD_URL, json.dumps(second))
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "equivocation", out
    assert out["evidence"]["saved_card"]["policy_notice_seconds"] != 1


# --- key sources (review 5) ---------------------------------------------------


def test_the_pypi_constant_is_compared_by_origin_without_a_domain(h, monkeypatch):
    inst = Instance(Log(5))
    code, out = h.run("policy", "init", "--bundle", inst.bundle.txt, *ONE, "--no-card", "--quorum", "0")
    assert code == 0 and out["policy"]["domain"] is None
    real = Instance(Log(5, origin=inst.log.origin))
    import aics_cli.published_keys as pk

    monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE", real.bundle.jcs)
    monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE_SHA256", real.bundle.sha256)
    h.serve(inst.log, 5)
    for argv in (("verify", "checkpoint"), ("status",), ("policy", "show")):
        code, out = h.run(*argv)
        assert code == 2 and out["evidence"]["type"] == "aics-key-source-disagreement/v1", argv


def test_an_agreeing_pypi_constant_counts_toward_the_trust_root(h, monkeypatch):
    inst = Instance(Log(5))
    inst.publish(h)
    import aics_cli.published_keys as pk

    monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE", inst.bundle.jcs)
    monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE_SHA256", inst.bundle.sha256)
    monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE_DOMAIN", DOMAIN)
    code, out = h.run("policy", "init", "--from-dns", DOMAIN)  # DNS + the package: two kinds, no flag needed
    assert code == 0, out
    h.serve(inst.log, 5)
    code, text = h.run_text("verify", "checkpoint")
    assert code == 0 and "(trust root: dns + pypi)" in text.splitlines()[0]


def test_dns_alone_needs_an_explicit_single_source(h):
    Instance(Log(5)).publish(h)
    code, out = h.run("policy", "init", "--from-dns", DOMAIN)
    assert code == 1 and "--require-sources 1" in out["error"] and "secure root" in out["error"]
    assert not (h.home / "policy.toml").exists()
    code, text = h.run_text("policy", "init", "--from-dns", DOMAIN, *ONE)
    assert code == 0 and "trust root dns only, unauthenticated" in text


# --- witness independence (review 7) ------------------------------------------


def test_independence_asserted_by_the_user(h):
    w = Witness("witness.test/w1")
    inst = Instance(Log(5), witnesses=[w], quorum=1)
    inst.publish(h)
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, *ONE, "--independent", "witness.test/nobody")
    assert code == 1 and "not one of the pinned witnesses" in out["error"]
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, *ONE, "--independent", w.name)
    assert code == 0, out
    meta = out["policy"]["witness_meta"][w.name]
    assert meta["independent"] is True and meta["independent_source"] == "manual"
    assert meta["declared_independent"] is False
    h.serve(inst.log, 5, [(w, NOW - 5)])
    code, out = h.run("verify", "checkpoint")
    assert code == 0 and out["assessed_independent_witnesses"] == [w.name]
    assert any("your own assessment" in x and "G5" in x for x in out["warnings"])


# --- gossip (review 8) ---------------------------------------------------------


def test_gossip_relation_status_follows_the_classification(h, tmp_path):
    w = Witness("w.test/1")
    log = Log(10)
    make_policy(h.home, log, witnesses=[w], quorum=1)
    a, b, c = tmp_path / "a", tmp_path / "b", tmp_path / "c"
    a.write_text(log.note(cosigners=[(w, NOW - 5)]))
    b.write_text(log.fork(1).note(cosigners=[(w, NOW - 5)]))
    c.write_text(log.fork(2).note())  # log-signed, never cosigned
    code, out = h.run("gossip-check", str(a), str(b))
    assert code == 2 and out["relation"]["status"] == "split-proven" and out["split"] is True
    code, out = h.run("gossip-check", str(a), str(c))
    assert code == 2 and out["relation"]["status"] == "log-equivocation" and out["split"] is False
    assert out["log_equivocation"] is True
    reasons = {n["witness_policy_met"]: n.get("witness_reason") for n in out["notes_checked"]}
    assert reasons[True] is None and "quorum" in reasons[False]


# --- exit codes (review 11) ------------------------------------------------------


def test_an_invalid_note_from_elsewhere_is_not_evidence(h, tmp_path):
    log = Log(5)
    make_policy(h.home, log, mirrors=[MIRROR])
    h.fetcher.set(MIRROR + "checkpoint", Log(5).note())  # another key
    code, out = h.run("verify", "checkpoint", "--url", MIRROR + "checkpoint")
    assert code == 1 and out["result"] == "invalid" and "evidence" not in out
    f = tmp_path / "x.note"
    f.write_text(Log(5).note())
    code, out = h.run("verify", "checkpoint", "--note", str(f))
    assert code == 1 and out["result"] == "invalid"


def test_a_bad_witness_line_from_the_origin_is_evidence_but_from_a_mirror_is_not(h):
    from test_adversarial_review import _poison

    log, w = Log(5), Witness("witness.test/w1")
    make_policy(h.home, log, witnesses=[w], quorum=1, mirrors=[MIRROR])
    bad = _poison(log.note(5), w.name, w.key.public_key().public_bytes_raw())
    h.fetcher.set(CHECKPOINT_URL, bad)
    code, out = h.run("verify", "checkpoint")
    assert code == 2 and out["evidence"]["reason"] == "bad_cosignature"
    h.fetcher.set(MIRROR + "checkpoint", bad)
    code, out = h.run("verify", "checkpoint", "--url", MIRROR + "checkpoint")
    assert code == 1 and out["reason"] == "bad_cosignature"


# --- stubs (review 13) -----------------------------------------------------------


def test_verify_message_is_no_longer_a_stub(h):
    """It verifies AICS-1 §14.3 bundles now (tests/test_message.py); without one it says what it needs."""
    code, out = h.run("verify", "message", "abc")
    assert code == 1 and "unrecognized arguments" in out["error"] and "available" not in out
    code, out = h.run("verify", "message")
    assert code == 1 and "AICS-1 §14.3" in out["error"] and "--bundle" in out["error"]


# --- DNS (review 14) ----------------------------------------------------------------


def _answer(qid: int, qname: str, records: list[tuple[str, int, bytes]], *, qtype: int = TYPE_TXT,
            qd: int = 1) -> bytes:
    header = struct.pack(">HHHHHH", qid, FLAG_QR | 0x0100 | 0x0080, qd, len(records), 0, 0)
    question = (encode_name(qname) + struct.pack(">HH", qtype, 1)) * qd
    body = b""
    for owner, rtype, rdata in records:
        body += encode_name(owner) + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata
    return header + question + body


def _txt(s: bytes) -> bytes:
    return bytes([len(s)]) + s


def test_dns_answers_must_answer_the_question():
    q = "_aics.log.test"
    ok = _answer(7, "_AICS.Log.Test", [(q, TYPE_TXT, _txt(b"aics1=x"))])
    assert parse_response(ok, 7, q)[2] == [b"aics1=x"]
    with pytest.raises(DnsError, match="another question"):
        parse_response(_answer(7, "_aics.evil.test", [(q, TYPE_TXT, _txt(b"x"))]), 7, q)
    with pytest.raises(DnsError, match="another question"):
        parse_response(_answer(7, q, [], qtype=1), 7, q)
    with pytest.raises(DnsError, match="questions"):
        parse_response(_answer(7, q, [], qd=2), 7, q)
    foreign = _answer(7, q, [("_aics.evil.test", TYPE_TXT, _txt(b"aics1=evil")), (q, TYPE_TXT, _txt(b"aics1=ok"))])
    assert parse_response(foreign, 7, q)[2] == [b"aics1=ok"]
    chain = _answer(7, q, [(q, 5, encode_name("t.example")), ("t.example", TYPE_TXT, _txt(b"aics1=via-cname")),
                           ("u.example", TYPE_TXT, _txt(b"aics1=stray"))])
    assert parse_response(chain, 7, q)[2] == [b"aics1=via-cname"]
    assert build_query(q, 7)[:2] == b"\x00\x07"


# --- hostile JSON and the last resort (review 15) ----------------------------------------


def test_deeply_nested_json_is_an_error_with_one_json_object(h, inst):
    deep = "[" * 100000 + "]" * 100000
    h.fetcher.set(CARD_URL, deep)
    code, out = h.run("verify", "card")
    assert code == 1 and "nested" in out["error"]
    h.fetcher.set(CHECKPOINT_URL, '{"signed_checkpoint": ' + deep + "}")
    code, out = h.run("verify", "checkpoint")
    assert code == 1 and "nested" in out["error"]
    with pytest.raises(ValueError):
        cardmod.loads_strict('{"a": ' + "[" * 40 + "]" * 40 + "}")
    assert cardmod.loads_strict('{"a": "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["}')  # brackets inside strings


def test_a_deep_proof_body_is_an_unusable_proof(h):
    from aics_cli.consistency import parse_proof_body

    with pytest.raises(ValueError):
        parse_proof_body(("[" * 5000 + "]" * 5000).encode(), 1, 2)


def test_an_unexpected_exception_still_prints_one_json_object(h, monkeypatch):
    from aics_cli import commands

    def boom(args, env):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(commands, "cmd_status", boom)
    buf = io.StringIO()
    code = run(["status", "--json"], env=h.env, out=buf)
    out = json.loads(buf.getvalue())
    assert code == 1 and out["exit"] == 1 and "unexpected" in out["error"] and out["internal"] is True

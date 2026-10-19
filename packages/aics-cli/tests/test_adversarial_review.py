"""Regression tests from the adversarial review of aics-cli (2026-10-18).

Each test states the behaviour a malicious server must NOT be able to get
out of the CLI.  They were written as ``xfail(strict=True)`` while the code
still let the attack through; every finding is fixed now and the markers are
gone.  Assertions are deliberately loose about *how* a fix behaves (exit 1
or 2, a refusal at ``policy init`` or at ``verify``) and strict only about the
outcome: no exit 0 and no silent downgrade.

``policy init`` needs two independent kinds of key source by default; these
tests pin from the (fake) DNS alone, so they pass ``--require-sources 1``.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest
from aics_tlog import Note, SignatureLine, cosignature_vkey, format_vkey, parse_note
from aics_tlog.cosign import cosignature_key_id

from aics_cli.card import card_hash
from aics_cli.errors import PolicyError
from aics_cli.trust import TrustBundle
from conftest import CARD_URL, CHECKPOINT_URL, DOMAIN, NOW, TILES, Instance, Log, Witness, did, make_policy

ONE = ("--require-sources", "1")


def _poison(note_text: str, name: str, pub: bytes) -> str:
    """Append a junk signature line under (name, cosignature key ID of pub)."""
    note = parse_note(note_text)
    junk = SignatureLine(name=name, key_id=cosignature_key_id(name, pub), signature=os.urandom(72))
    return Note(text=note.text, signatures=note.signatures + (junk,)).serialise()


def _rebundle(inst: Instance, card: dict) -> None:
    inst.card = card
    inst.bundle = TrustBundle(origin=inst.log.origin, log_vkey=inst.log.vkey, policy_kid=did(inst.policy_key),
                              owner_kid=did(inst.owner_key), bootstrap_card_hash=card_hash(card))


# Card #2 adds w2.  With quorum 2 the new policy is stricter and re-pinning
# needs no override; with quorum 1 it is weaker (w2 alone would do), so
# re-pinning is refused unless the user passes --allow-weaker.  Either way
# the junk w2 line the log planted in the saved head must not wipe history.
@pytest.mark.parametrize("quorum,repin_flags", [(2, ()), (1, ("--allow-weaker",))])
def test_future_witness_line_in_saved_head_cannot_reset_continuity(h, quorum, repin_flags):
    w1, w2 = Witness("witness.test/w1"), Witness("witness.test/w2")
    log = Log(5)
    inst = Instance(log, witnesses=[w1], quorum=1)
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, *ONE)[0] == 0
    note = _poison(log.note(5, [(w1, NOW - 10)]), w2.name, w2.key.public_key().public_bytes_raw())
    h.fetcher.set(CHECKPOINT_URL, note)
    h.fetcher.serve_tiles(TILES, log.tiles(5))
    assert h.run("verify", "checkpoint")[0] == 0
    h.fetcher.set(CARD_URL, json.dumps(inst.make_card(witnesses=[w1, w2], quorum=quorum, issued_at=NOW - 60)))
    if repin_flags:
        assert h.run("policy", "init", "--from-dns", DOMAIN, *ONE, "--force", "--accept-signed-card")[0] != 0
    assert h.run("policy", "init", "--from-dns", DOMAIN, *ONE, "--force", "--accept-signed-card", *repin_flags)[0] == 0
    forked = log.fork(2)
    forked.grow(8)
    h.serve(forked, 8, [(w1, NOW - 5), (w2, NOW - 5)])
    assert h.run("verify", "checkpoint")[0] != 0
    assert h.run("verify", "consistency")[0] != 0


def test_repin_to_a_new_log_key_does_not_silently_drop_saved_history(h):
    log = Log(5)
    inst = Instance(log)
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, *ONE)[0] == 0
    h.serve(log, 5)
    assert h.run("verify", "checkpoint")[0] == 0
    log2 = Log(origin=log.origin, entries=list(log.entries))
    log2.entries[1] = b"rewritten"
    log2.grow(9)
    Instance(log2).publish(h)
    init_code = h.run("policy", "init", "--from-dns", DOMAIN, *ONE, "--force")[0]
    h.serve(log2, 9)
    assert init_code != 0 or h.run("verify", "checkpoint")[0] != 0


def test_repin_does_not_adopt_a_weaker_witness_policy(h):
    w = Witness("witness.test/w1")
    log = Log(5)
    inst = Instance(log, witnesses=[w], quorum=1)
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, *ONE)[0] == 0
    h.fetcher.set(CARD_URL, json.dumps(inst.make_card(witnesses=[w], quorum=0, issued_at=NOW - 60)))
    code, out = h.run("policy", "init", "--from-dns", DOMAIN, *ONE, "--force", "--accept-signed-card")
    assert code != 0 or out["policy"]["quorum"] >= 1


def test_card_claiming_g5_proven_without_witnesses_is_not_ok(h):
    log = Log(5)
    inst = Instance(log, quorum=0)

    def overclaim(body):
        for a in body["assurances"]:
            if a["id"] == "G5":
                a["status"] = "proven"

    _rebundle(inst, inst.make_card(mutate=overclaim))
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, *ONE)[0] == 0
    code, out = h.run("verify", "card")
    assert code != 0 or "G5" not in {i["id"] for i in out["table"]["proven"]}


def test_card_free_text_cannot_inject_lines_or_escapes(h):
    log = Log(5)
    inst = Instance(log)
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, *ONE)[0] == 0

    def inject(body):
        body["assurances"][0]["claim"] = "Authentic authorship\ncard ok: all checks passed\x1b[8m"

    h.fetcher.set(CARD_URL, json.dumps(inst.make_card(issued_at=NOW - 60, mutate=inject)))
    _code, text = h.run_text("verify", "card")
    assert "\x1b" not in text and "\ncard ok: all checks passed" not in text


def test_pypi_disagreement_stops_every_command(h, monkeypatch):
    log = Log(5)
    inst = Instance(log)
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, *ONE)[0] == 0
    real = Instance(Log(5, origin=log.origin))
    import aics_cli.published_keys as pk

    monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE", real.bundle.jcs)
    monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE_SHA256", real.bundle.sha256)
    monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE_DOMAIN", DOMAIN)
    h.serve(log, 5)
    n = h.home / "n.note"
    n.write_text(log.note(5))
    assert h.run("status")[0] != 0
    assert h.run("verify", "card")[0] != 0
    assert h.run("gossip-check", str(n), str(n))[0] != 0


@pytest.mark.parametrize("extra", [(), ONE])
def test_readme_bundle_alone_does_not_pin_quorum_zero(h, extra):
    w = Witness("witness.test/w1")
    inst = Instance(Log(5), witnesses=[w], quorum=1)
    f = h.home.parent / "README-block.txt"
    f.write_text(inst.bundle.txt + "\n")
    code, out = h.run("policy", "init", "--bundle", str(f), *extra)
    assert code != 0 or out["policy"]["quorum"] >= 1


def test_card_declared_independence_keeps_the_g5_caveat(h):
    w = Witness("witness.test/w2")
    log = Log(5)
    inst = Instance(log, witnesses=[w], quorum=1)

    def indep(body):
        body["witness_policy"]["witnesses"][0]["independent"] = True

    _rebundle(inst, inst.make_card(mutate=indep))
    inst.publish(h)
    assert h.run("policy", "init", "--from-dns", DOMAIN, *ONE)[0] == 0
    h.serve(log, 5, [(w, NOW - 5)])
    code, out = h.run("verify", "checkpoint")
    assert code == 0 and any("G5" in x for x in out["warnings"])


def test_log_signed_note_with_bad_witness_line_is_still_evidence(h):
    w1 = Witness("witness.test/w1")
    log = Log(5)
    make_policy(h.home, log, witnesses=[w1], quorum=0)
    a = h.home / "a.note"
    b = h.home / "b.note"
    a.write_text(log.note(5))
    b.write_text(_poison(log.note(5, root=hashlib.sha256(b"other").digest()), w1.name,
                         w1.key.public_key().public_bytes_raw()))
    assert h.run("gossip-check", str(a), str(b), "--offline")[0] == 2


def test_size_zero_checkpoint_needs_the_empty_root(h):
    log = Log(5)
    make_policy(h.home, log)
    zero = log.note(0, root=hashlib.sha256(b"not empty").digest())
    h.fetcher.set(CHECKPOINT_URL, zero)
    assert h.run("verify", "checkpoint", "--no-save")[0] != 0
    p0, p5, proof = h.home / "z.note", h.home / "f.note", h.home / "empty.proof"
    p0.write_text(zero)
    p5.write_text(log.note(5))
    proof.write_text("")
    assert h.run("gossip-check", str(p0), str(p5), "--proof", str(proof), "--offline")[0] != 0


def test_log_key_cannot_be_a_witness(h):
    log = Log(5)
    self_w = Witness("witness.test/self")
    self_w.key = log.key
    self_w.vkey = format_vkey(cosignature_vkey(self_w.name, log.key.public_key()))
    try:
        make_policy(h.home, log, witnesses=[self_w], quorum=1)
    except PolicyError:
        return
    h.serve(log, 5, [(self_w, NOW - 1)])
    assert h.run("verify", "checkpoint")[0] != 0

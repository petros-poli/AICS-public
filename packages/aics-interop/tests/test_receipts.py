"""Inclusion promises (AICS-1 §10.1): ``J({origin,entry_hash,submitted_at,mmd_seconds}) || LF``, log-signed.

Producers: the suite's reference (``spec.receipt_note``), aics-tlog
(``sign_note``) and aics-conformance's fake (``FakeServer.receipt``).
Verifiers: aics-conformance (``verify.receipt``), aics-tlog (``verify_note``)
and the reference.  aics has no receipt verifier (``aics verify receipt``
exits 3, see ``test_envelopes.test_cli_has_no_envelope_or_message_verifier_yet``).
"""

from __future__ import annotations

import pytest

from aics_interop import aicslog, drivers, spec

LOG = aicslog.standard_log(5)
ENTRY = LOG.entries[4]
RAW = spec.J(ENTRY)
KEYS = aicslog.Keys()


def test_receipt_producers_agree():
    from aics_tlog import Note, sign_note

    ours = spec.receipt_note(aicslog.ORIGIN, RAW, ENTRY["ts"], KEYS.log)
    text = spec.receipt_text(aicslog.ORIGIN, spec.leaf_hash(RAW).hex(), ENTRY["ts"])
    assert ours == Note(text, (sign_note(text, KEYS.log, aicslog.ORIGIN),)).to_bytes()
    assert spec.strict_json(text) == {"origin": aicslog.ORIGIN, "entry_hash": spec.leaf_hash(RAW).hex(),
                                      "submitted_at": ENTRY["ts"], "mmd_seconds": 60}


def test_receipt_verifies_in_conformance_and_aics_tlog():
    from aics_conformance import verify
    from aics_tlog import parse_note, parse_vkey, verify_note

    note = spec.receipt_note(aicslog.ORIGIN, RAW, ENTRY["ts"], KEYS.log)
    r = verify.receipt(note, ENTRY, drivers.conformance_policy(aicslog.trust_bundle()))
    assert r["entry_hash"] == spec.leaf_hash(RAW).hex()
    assert verify_note(parse_note(note), [parse_vkey(KEYS.log_vkey())])


def test_conformance_fake_receipts_are_the_aics1_form():
    from aics_conformance.fakes.server import FakeServer

    fake = FakeServer()
    for e in fake.entries:
        note = fake.receipt(e)
        text = spec.receipt_text(fake.origin, spec.leaf_hash(spec.J(e)).hex(), e["ts"])
        body, sigs = spec.parse_signed_note(note)
        assert body == text and [n for n, _ in sigs] == [fake.origin]
        _, key_id, _, pub = spec.parse_vkey(fake.vkey)
        assert sigs[0][1][:4] == key_id
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(pub).verify(sigs[0][1][4:], text.encode())


BAD = {
    "mmd-61": lambda: spec.receipt_text(aicslog.ORIGIN, spec.leaf_hash(RAW).hex(), ENTRY["ts"]).replace(
        '"mmd_seconds":60', '"mmd_seconds":61'),
    "submitted-at-not-ts": lambda: spec.receipt_text(aicslog.ORIGIN, spec.leaf_hash(RAW).hex(), ENTRY["ts"] + 1),
    "plain-json-digest": lambda: spec.receipt_text(aicslog.ORIGIN, spec.hexH(RAW), ENTRY["ts"]),
    "not-canonical": lambda: spec.receipt_text(aicslog.ORIGIN, spec.leaf_hash(RAW).hex(), ENTRY["ts"]).replace(
        ",", ", "),
    "other-origin": lambda: spec.receipt_text("evil.example/tiles", spec.leaf_hash(RAW).hex(), ENTRY["ts"]),
}


# BAD case -> the rule aics-conformance's verify.receipt names (schema.require raises ValueError)
REFUSAL = {"mmd-61": "receipt origin/MMD", "submitted-at-not-ts": "receipt fixed-entry commitment",
           "plain-json-digest": "receipt fixed-entry commitment", "not-canonical": "receipt canonical schema",
           "other-origin": "receipt origin/MMD"}


@pytest.mark.parametrize("case", sorted(BAD))
def test_bad_receipts_are_rejected(case):
    from aics_conformance import verify

    text = BAD[case]()
    note = spec.signed_note(text, [spec.log_signature_line(aicslog.ORIGIN, KEYS.log, text)])
    with pytest.raises(ValueError, match=f"^{REFUSAL[case]}$"):
        verify.receipt(note, ENTRY, drivers.conformance_policy(aicslog.trust_bundle()))


def test_the_bad_receipts_are_the_fixture_cases():
    """fixtures/receipts.json carries exactly these receipts, byte for byte, each with expect invalid."""
    import json

    from aics_interop.generate import DEFAULT_OUT

    f = json.loads((DEFAULT_OUT / "receipts.json").read_text("utf-8"))
    assert f["entry_ts"] == ENTRY["ts"] and spec.dU64(f["entry_u64"]) == RAW
    cases = {c["name"]: c for c in f["invalid"]}
    assert sorted(cases) == sorted(BAD)
    for name, text in BAD.items():
        note = spec.signed_note(text(), [spec.log_signature_line(aicslog.ORIGIN, KEYS.log, text())])
        assert (cases[name]["receipt_text"].encode(), cases[name]["expect"]) == (note, "invalid"), name

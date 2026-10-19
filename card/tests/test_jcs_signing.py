"""RFC 8785 bytes, strict JSON, key encodings and the AICS-1 section 13.2 signature over the payload."""

from __future__ import annotations

import hashlib
import json

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import validate_card as vc
from helpers import LOG_KEY, PATTERN_DOCUMENT, POLICY_KEY, WITNESS_KEY, errors, raw_public

# --- JCS ----------------------------------------------------------------------------------------------------


def test_rfc8785_property_sorting_vector():
    # RFC 8785 section 3.2.3: members sort by UTF-16 code units, so U+1F600 precedes U+FB33.
    value = {"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh",
             "1": "One", "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control",
             "\u00f6": "Latin Small Letter O With Diaeresis"}
    order = [v for _, v in json.loads(vc.jcs(value).decode()).items()]
    assert order == ["Carriage Return", "One", "Control", "Latin Small Letter O With Diaeresis", "Euro Sign",
                     "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh"]


@pytest.mark.parametrize("value", [
    {"s": "\u20ac$\u000f\nA'B\"\\/\t\b\f\r\u001f\u007f\u2028"},
    {"b": [True, False, None, 0, 9007199254740991], "nested": {"z": {}, "a": []}},
    {"\U0001f600": 1, "\ufb33": 2, "a": 3},
])
def test_jcs_matches_rfc8785_package(value):
    assert vc.jcs(value) == rfc8785.dumps(value)


def test_template_and_filled_payloads_match_rfc8785(card, filled):
    for body in (card, filled):
        assert vc.unsigned_payload(body) == rfc8785.dumps(body)


def test_jcs_rejects_what_the_card_never_holds():
    for bad in ({"x": 1.5}, {"x": 2**53}, {"x": "\ud800"}):
        with pytest.raises(ValueError):
            vc.jcs(bad)


@pytest.mark.parametrize("raw, message", [
    (b'{"a": 1, "a": 2}', "duplicate JSON member"),
    (b'{"a": 1.0}', "not an integer"),
    (b'{"a": 1e3}', "not an integer"),
    (b'{"a": NaN}', "is not JSON"),
    (b'\xef\xbb\xbf{}', "byte order mark"),
    (b'{"a": "\xff"}', "not UTF-8"),
    (b"[" * 40 + b"]" * 40, "nested deeper"),
    (b"{", "invalid JSON"),
])
def test_strict_json(raw, message):
    with pytest.raises(vc.InputError, match=message):
        vc.load_json(raw)


# --- keys: AICS-1 Appendix A public test vectors ---------------------------------------------------------------


def test_did_key_decoding_matches_appendix_a():
    alice = "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX"
    assert vc.parse_did_key(alice).hex() == "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
    with pytest.raises(ValueError):
        vc.parse_did_key(alice[:-1] + "0")  # 0 is not base58btc
    with pytest.raises(ValueError):
        vc.parse_did_key("did:key:z6LS" + alice[12:])  # not the Ed25519 multicodec


def test_vkey_parsing_matches_appendix_a():
    name, key_type, key = vc.parse_vkey("log.example/aics-1+d34caeba+AYE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU")
    assert (name, key_type, key) == ("log.example/aics-1", 0x01, raw_public(LOG_KEY))
    name, key_type, key = vc.parse_vkey("witness.example/w1+c3c1499d+BIqHX/8es4RRV3rNWv7kBUVlaN18ieCQhjoFV7x69J8X")
    assert (name, key_type, key) == ("witness.example/w1", 0x04, raw_public(WITNESS_KEY))
    with pytest.raises(ValueError, match="does not match"):
        vc.parse_vkey("log.example/aics-1+d34caebb+AYE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU")


# --- AICS-1 section 13.2: what the server does with the payload ------------------------------------------------


def sign(body: dict, key=POLICY_KEY) -> dict:
    """The AICS-1 section 13.2 construction, as the server performs it with the policy key."""
    protected = vc.b64u(vc.jcs({"alg": "EdDSA", "kid": body["policy_kid"], "typ": "JOSE"}))
    signing_input = f"{protected}.{vc.b64u(vc.unsigned_payload(body))}".encode("ascii")
    return dict(body, signatures=[{"protected": protected, "signature": vc.b64u(key.sign(signing_input))}])


def test_signed_card_round_trip(filled):
    payload = vc.validate(filled, final=True, patterns=PATTERN_DOCUMENT).payload
    signed = sign(filled)
    sig = signed["signatures"][0]
    Ed25519PublicKey.from_public_bytes(vc.parse_did_key(filled["policy_kid"])).verify(
        vc.b64u_decode(sig["signature"]), f"{sig['protected']}.{vc.b64u(payload)}".encode("ascii"))
    result = vc.validate(signed, final=True, signed=True, patterns=PATTERN_DOCUMENT)
    assert result.report.errors == []
    assert result.payload == payload  # removing only signatures gives back the signed bytes
    assert result.document == rfc8785.dumps(signed)
    assert hashlib.sha256(result.document).hexdigest() != hashlib.sha256(payload).hexdigest()


def test_signed_mode_checks_the_protected_header(filled):
    signed = sign(filled)
    signed["signatures"][0]["protected"] = vc.b64u(vc.jcs({"alg": "EdDSA", "jku": "https://x", "kid": "k",
                                                           "typ": "JOSE"}))
    assert any("must be U64(J(" in e for e in errors(signed, final=True, signed=True))
    signed = sign(filled)
    signed["signatures"][0]["header"] = {}
    assert any("no unprotected header" in e for e in errors(signed, final=True, signed=True))
    signed = sign(filled)
    signed["signatures"][0]["signature"] = vc.b64u(b"\0" * 32)
    assert any("64-byte Ed25519 signature" in e for e in errors(signed, final=True, signed=True))


def test_signed_mode_needs_a_signature(filled):
    assert any("missing members: signatures" in e for e in errors(filled, final=True, signed=True))

"""Key generation, encodings, did:key vectors, HKDF derivation."""

from __future__ import annotations

import hashlib
import re

import pytest

from aics_identity import keys
from conftest import (
    DID_KEY_SPEC_ED25519,
    DID_KEY_SPEC_ED25519_ALT,
    DID_KEY_SPEC_ED25519_RAW,
    TEST_KEY_ED25519_PUBLIC,
    TEST_KEY_ED25519_SEED,
)


def test_generate_keypair_shapes():
    key = keys.generate_keypair()
    seed = keys.private_seed(key)
    assert len(seed) == 32
    pub = keys.public_key_bytes(key.public_key())
    assert len(pub) == 32
    # fresh keys are (with overwhelming probability) different
    assert seed != keys.private_seed(keys.generate_keypair())


def test_seed_roundtrip():
    key = keys.private_key_from_seed(TEST_KEY_ED25519_SEED)
    assert keys.private_seed(key) == TEST_KEY_ED25519_SEED
    assert keys.public_key_bytes(key.public_key()) == TEST_KEY_ED25519_PUBLIC


def test_seed_must_be_32_bytes():
    with pytest.raises(ValueError):
        keys.private_key_from_seed(b"short")
    with pytest.raises(ValueError):
        keys.public_key_from_bytes(b"\x00" * 31)


def test_b64u_roundtrip_no_padding():
    data = bytes(range(64))
    text = keys.b64u_encode(data)
    assert "=" not in text
    assert keys.b64u_decode(text) == data
    assert keys.b64u_decode(text + "==") == data  # padding tolerated on parse


def test_base58_known_vector():
    # well-known base58btc vector
    assert keys.base58_encode(b"hello world") == "StV1DL6CwTryKyV"
    assert keys.base58_decode("StV1DL6CwTryKyV") == b"hello world"
    assert keys.base58_encode(b"\x00\x00hello") == "11Cn8eVZg"
    assert keys.base58_decode("11Cn8eVZg") == b"\x00\x00hello"


def test_key_id_formula():
    pub = keys.public_key_from_bytes(TEST_KEY_ED25519_PUBLIC)
    expected = keys.b64u_encode(hashlib.sha256(TEST_KEY_ED25519_PUBLIC).digest())[:16]
    assert keys.key_id(pub) == expected
    assert re.fullmatch(r"[A-Za-z0-9_-]{16}", keys.key_id(pub))


def test_public_key_b64url_roundtrip():
    pub = keys.public_key_from_bytes(TEST_KEY_ED25519_PUBLIC)
    text = keys.format_public_key(pub)
    assert text == keys.b64u_encode(TEST_KEY_ED25519_PUBLIC)
    assert keys.parse_public_key(text) is not None
    assert keys.public_key_bytes(keys.parse_public_key(text)) == TEST_KEY_ED25519_PUBLIC


def test_did_key_matches_published_spec_vector():
    pub = keys.public_key_from_bytes(DID_KEY_SPEC_ED25519_RAW)
    assert keys.did_key(pub) == DID_KEY_SPEC_ED25519
    parsed = keys.parse_did_key(DID_KEY_SPEC_ED25519)
    assert keys.public_key_bytes(parsed) == DID_KEY_SPEC_ED25519_RAW


def test_did_key_roundtrip_second_spec_vector():
    parsed = keys.parse_did_key(DID_KEY_SPEC_ED25519_ALT)
    assert keys.did_key(parsed) == DID_KEY_SPEC_ED25519_ALT


def test_did_key_for_rfc9421_test_key():
    pub = keys.public_key_from_bytes(TEST_KEY_ED25519_PUBLIC)
    did = keys.did_key(pub)
    assert did.startswith("did:key:z6Mk")
    assert keys.public_key_bytes(keys.parse_did_key(did)) == TEST_KEY_ED25519_PUBLIC


def test_parse_did_key_rejects_garbage():
    with pytest.raises(ValueError):
        keys.parse_did_key("did:key:1")
    with pytest.raises(ValueError):
        keys.parse_did_key("not-a-did")
    with pytest.raises(ValueError):
        keys.parse_did_key("did:key:z" + keys.base58_encode(b"\x01\x02"))  # wrong multicodec


DID = DID_KEY_SPEC_ED25519


@pytest.mark.parametrize("text, match", [
    (DID + "#" + DID[len("did:key:"):], "base58"),          # a fragment: AICS-1 kids are bare DIDs
    ("did:key:" + DID[len("did:key:"):].replace("z", "u", 1), "did:key:z"),  # other multibase
    ("DID:KEY:" + DID[len("did:key:"):], "did:key:z"),
    (" " + DID, "did:key:z"),
    (DID + "0", "base58"),                                  # 0 is not a base58btc character
    ("did:key:z", "no key"),
    ("did:key:z1" + DID[len("did:key:z"):], "multicodec"),  # a leading zero byte
    ("did:key:z" + keys.base58_encode(b"\xed\x01" + bytes(31)), "32-byte"),
    ("did:key:z" + keys.base58_encode(b"\xed\x01" + bytes(range(33))), "32-byte"),
    (keys.x25519_did_key(DID_KEY_SPEC_ED25519_RAW), "ed25519-pub"),
    (None, "did:key"),
])
def test_did_key_decoding_is_validated(text, match):
    with pytest.raises(ValueError, match=match):
        keys.parse_did_key(text)
    assert not keys.is_did_key(text)


def test_did_key_helpers():
    """AICS-1 section 3.1: kid = did:key:z + base58btc(0xed 0x01 || pk); 0xec 0x01 displays an X25519 key."""
    raw = DID_KEY_SPEC_ED25519_RAW
    assert keys.did_key(raw) == keys.did_key(keys.public_key_from_bytes(raw)) == DID == \
        "did:key:z" + keys.base58_encode(b"\xed\x01" + raw)
    assert keys.did_key_from_bytes(raw) == DID
    assert keys.parse_did_key_bytes(DID) == raw and keys.decode_did_key(DID) == (keys.ED25519_MULTICODEC, raw)
    assert keys.is_did_key(DID) and not keys.is_did_key(keys.key_id(keys.public_key_from_bytes(raw)))
    x_did = keys.x25519_did_key(raw)
    assert x_did == "did:key:z" + keys.base58_encode(b"\xec\x01" + raw) and x_did.startswith("did:key:z6LS")
    assert keys.parse_x25519_did_key_bytes(x_did) == raw
    with pytest.raises(ValueError, match="x25519-pub"):
        keys.parse_x25519_did_key_bytes(DID)
    with pytest.raises(ValueError):
        keys.did_key_from_bytes(raw, b"\x00\x01")
    with pytest.raises(ValueError):
        keys.did_key_from_bytes(raw[:31])


def test_parse_did_key_validates_the_point_unless_told_not_to():
    weak = bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000")  # identity point
    did = keys.did_key_from_bytes(weak)
    assert keys.is_did_key(did)  # structurally a did:key
    with pytest.raises(ValueError, match="small-order"):
        keys.parse_did_key(did)
    assert keys.public_key_bytes(keys.parse_did_key(did, validate=False)) == weak
    assert keys.parse_did_key_bytes(did, validate=False) == weak


def test_unverified_identifiers():
    """AICS-1 section 3.3: unverified: + U64 of 16 random bytes; not a kid for a key."""
    a, b = keys.new_unverified_id(), keys.new_unverified_id()
    assert a != b and a.startswith("unverified:") and len(a) == len("unverified:") + 22
    assert keys.is_unverified_id(a)
    for bad in ("unverified:", "unverified:" + keys.b64u_encode(bytes(15)), "unverified:" + keys.b64u_encode(bytes(16)) + "=",
                "Unverified:" + keys.b64u_encode(bytes(16)), keys.b64u_encode(bytes(16)), None, 7,
                "unverified:AAAAAAAAAAAAAAAAAAAAAB"):
        assert not keys.is_unverified_id(bad), bad
    assert not keys.is_did_key(a)


def test_u64_decode_is_strict():
    assert keys.u64_decode("MDEyMzQ1Njc4OTo7PD0-Pw", length=16) == b"0123456789:;<=>?"
    assert keys.u64_decode("") == b""
    for bad in ("MDEyMzQ1Njc4OTo7PD0-Pw==", "MDEyMzQ1Njc4OTo7PD0+Pw", " MDEyMzQ1Njc4OTo7PD0-Pw", "AAAAB",
                "AB", "MDEyMzQ1Njc4OTo7PD0-Pw!", None, b"AAAA"):
        with pytest.raises(ValueError):
            keys.u64_decode(bad)
    with pytest.raises(ValueError, match="16 bytes"):
        keys.u64_decode("AAAA", length=16)


def test_as_public_key_accepts_all_shapes(test_key):
    pub = test_key.public_key()
    raw = keys.public_key_bytes(pub)
    assert keys.public_key_bytes(keys.as_public_key(pub)) == raw
    assert keys.public_key_bytes(keys.as_public_key(test_key)) == raw
    assert keys.public_key_bytes(keys.as_public_key(raw)) == raw
    assert keys.public_key_bytes(keys.as_public_key(keys.format_public_key(pub))) == raw
    assert keys.public_key_bytes(keys.as_public_key(keys.did_key(pub))) == raw
    with pytest.raises(TypeError):
        keys.as_public_key(12345)


# ----------------------------------------------------------------------
# deterministic derivation (HKDF-SHA256)
# ----------------------------------------------------------------------

MASTER = b"\x01" * 32


def test_derivation_is_deterministic():
    k1 = keys.derive_agent_key(MASTER, "agent-7")
    k2 = keys.derive_agent_key(MASTER, "agent-7")
    assert keys.private_seed(k1) == keys.private_seed(k2)


def test_derivation_deterministic_with_salt():
    salt = b"\x5a" * 16
    k1 = keys.derive_agent_key(MASTER, "agent-7", run_salt=salt)
    k2 = keys.derive_agent_key(MASTER, "agent-7", run_salt=salt)
    assert keys.private_seed(k1) == keys.private_seed(k2)


def test_derivation_binds_to_label():
    a = keys.private_seed(keys.derive_agent_key(MASTER, "agent-7"))
    b = keys.private_seed(keys.derive_agent_key(MASTER, "agent-8"))
    c = keys.private_seed(keys.derive_agent_key(MASTER, "agent-7x"))
    assert len({a, b, c}) == 3


def test_derivation_binds_to_salt():
    a = keys.private_seed(keys.derive_agent_key(MASTER, "agent-7", run_salt=b"\x01" * 8))
    b = keys.private_seed(keys.derive_agent_key(MASTER, "agent-7", run_salt=b"\x02" * 8))
    c = keys.private_seed(keys.derive_agent_key(MASTER, "agent-7"))  # no salt
    assert len({a, b, c}) == 3


def test_derivation_binds_to_master_secret():
    a = keys.private_seed(keys.derive_agent_key(b"\x01" * 32, "agent-7"))
    b = keys.private_seed(keys.derive_agent_key(b"\x02" * 32, "agent-7"))
    assert a != b


def test_derived_keys_are_usable_and_match_their_public_half():
    key = keys.derive_agent_key(MASTER, "agent-7")
    pub = keys.public_key_bytes(key.public_key())
    again = keys.derive_agent_key(MASTER, "agent-7")
    assert keys.public_key_bytes(again.public_key()) == pub
    # signature round-trip with the derived key
    from cryptography.exceptions import InvalidSignature
    sig = key.sign(b"data")
    key.public_key().verify(sig, b"data")
    with pytest.raises(InvalidSignature):
        key.public_key().verify(sig, b"other data")


def test_derivation_input_validation():
    with pytest.raises(ValueError):
        keys.derive_agent_key(b"", "agent-7")
    with pytest.raises(ValueError):
        keys.derive_agent_key(MASTER, "")
    with pytest.raises(ValueError):
        keys.derive_agent_key(MASTER, "agent-7", run_salt=b"")


def test_derivation_matches_hkdf_reference():
    """Independent HKDF-SHA256 recomputation of the documented formula."""
    import hmac as hmac_mod

    salt = b"\x11" * 16
    info = b"aics-identity/v1/" + b"agent-7"
    # RFC 5869 extract
    prk = hmac_mod.new(salt, MASTER, hashlib.sha256).digest()
    # expand (L=32 => single block)
    okm = hmac_mod.new(prk, info + b"\x01", hashlib.sha256).digest()
    key = keys.derive_agent_key(MASTER, "agent-7", run_salt=salt)
    assert keys.private_seed(key) == okm


def test_agent_identity_summary():
    key = keys.derive_agent_key(MASTER, "agent-7")
    summary = keys.agent_identity(key)
    assert summary["did"] == summary["kid"] == keys.did_key(key.public_key())  # the AICS-1 kid is the did:key
    assert summary["key_id"] == keys.key_id(key.public_key())
    assert summary["public_key"] == keys.format_public_key(key.public_key())


# ----------------------------------------------------------------------
# strict base64 and the text forms of a public key
# ----------------------------------------------------------------------

import base64

from conftest import OPENSSL_VECTOR_PUBLIC_B64, SSH_VECTOR_PUBLIC_LINE, SSH_VECTOR_SEED


@pytest.mark.parametrize("encode", [
    lambda b: base64.b64encode(b).decode(),
    lambda b: base64.b64encode(b).decode().rstrip("="),
    lambda b: base64.urlsafe_b64encode(b).decode(),
    lambda b: base64.urlsafe_b64encode(b).decode().rstrip("="),
    lambda b: "\n".join(base64.b64encode(b).decode()[i:i + 8] for i in range(0, 44, 8)) + "\n",
    lambda b: base64.b64encode(b),
])
def test_b64_decode_strict_accepts_both_alphabets(encode):
    data = bytes(range(250, 256)) + b"\xfb\xff" * 13  # exercises + / - _ characters
    assert keys.b64_decode_strict(encode(data)) == data


@pytest.mark.parametrize("text", [
    "AAAA*AAA", "AA=A", "AAAA===", "AAAAA", "+-AA", "ab\x00cd", b"\xff\xfe",
    "AB==", "AB", "AAB=",  # nonzero pad bits (AICS-1 section 11.2: invalid pad bits are errors)
    "AA=", "AAA==",  # padding of the wrong length
])
def test_b64_decode_strict_rejects_junk(text):
    with pytest.raises(ValueError):
        keys.b64_decode_strict(text)
    with pytest.raises(TypeError):
        keys.b64_decode_strict(123)


def test_b64u_decode_is_lenient_but_strict_is_not():
    assert keys.b64u_decode("AAAA!") == b"\x00\x00\x00"  # legacy helper drops junk
    with pytest.raises(ValueError):
        keys.b64_decode_strict("AAAA!")


def test_parse_public_key_text_forms():
    ssh_raw = keys.public_key_bytes(keys.private_key_from_seed(SSH_VECTOR_SEED).public_key())
    assert keys.public_key_bytes(keys.parse_public_key_text(SSH_VECTOR_PUBLIC_LINE)) == ssh_raw
    assert keys.public_key_bytes(keys.parse_public_key_text("  " + SSH_VECTOR_PUBLIC_LINE + "\n")) == ssh_raw
    openssl_raw = base64.b64decode(OPENSSL_VECTOR_PUBLIC_B64)
    assert keys.public_key_bytes(keys.parse_public_key_text(OPENSSL_VECTOR_PUBLIC_B64)) == openssl_raw
    assert keys.public_key_bytes(keys.parse_public_key_text(keys.b64u_encode(openssl_raw))) == openssl_raw
    assert keys.public_key_bytes(keys.parse_public_key_text(DID_KEY_SPEC_ED25519)) == DID_KEY_SPEC_ED25519_RAW


@pytest.mark.parametrize("text", [
    "", "   ", base64.b64encode(b"\x01" * 31).decode(), "not base64 at all", "ssh-rsa AAAAB3NzaC1yc2E",
    "did:web:example.com", "AAAA*",
])
def test_parse_public_key_text_rejects(text):
    with pytest.raises(ValueError):
        keys.parse_public_key_text(text)


def test_parse_public_key_text_type_error():
    with pytest.raises(TypeError):
        keys.parse_public_key_text(b"bytes")


def test_as_public_key_accepts_openssh_line():
    raw = keys.public_key_bytes(keys.private_key_from_seed(SSH_VECTOR_SEED).public_key())
    assert keys.public_key_bytes(keys.as_public_key(SSH_VECTOR_PUBLIC_LINE)) == raw


def test_as_private_key(test_key):
    assert keys.as_private_key(test_key) is test_key
    assert keys.private_seed(keys.as_private_key(TEST_KEY_ED25519_SEED)) == TEST_KEY_ED25519_SEED
    with pytest.raises(TypeError):
        keys.as_private_key("seed")
    with pytest.raises(ValueError):
        keys.as_private_key(b"short")

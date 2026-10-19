"""Signed notes: key hashes (incl. the Go sumdb key), parsing, verification."""

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog.note import (
    Note,
    SignatureLine,
    VKey,
    b64_decode,
    b64_encode,
    check_name,
    ed25519_public_key_problem,
    format_vkey,
    key_hash,
    parse_note,
    parse_vkey,
    sign_note,
    vkey_from_ed25519,
    verify_note,
)

from conftest import GO_SUMDB_VKEY

# The eight small-order points of edwards25519 (RFC 8032 encodings), as in
# aics-witness/tests/test_config.py: the all-zero key, 0x01 followed by
# zeros (the identity element), p-1 (order 2) and the order-8 points.
SMALL_ORDER = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]
# The identity (y=1) and the order-2 point (y=p-1) have x=0, so their
# sign-bit-1 encodings name the same points and must be refused too.
SMALL_ORDER_SIGN_VARIANTS = [
    "0100000000000000000000000000000000000000000000000000000000000080",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]
# Encodings whose y-coordinate (low 255 bits) is not below p = 2^255 - 19.
NON_CANONICAL = [
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y = p
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # y = p + 1
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]


def _vkey_text(name: str, key_type: int, key: bytes) -> str:
    """A well-formed vkey (key ID matches) over arbitrary key material."""
    return f"{name}+{key_hash(name, key_type, key).hex()}+{b64_encode(bytes([key_type]) + key)}"


def test_go_sumdb_key_hash():
    """The Go checksum database public key must hash to its own key ID."""
    key = parse_vkey(GO_SUMDB_VKEY)
    assert key.name == "sum.golang.org"
    assert key.key_id == bytes.fromhex("033de0ae")
    assert key.key_type == 0x01
    assert len(key.public_key) == 32
    # key ID = SHA-256(name || 0x0A || 0x01 || 32-byte pubkey)[:4]
    assert key_hash(key.name, key.key_type, key.public_key) == key.key_id


def test_spec_example_note_and_vkey():
    """The example pair from c2sp.org/signed-note must verify."""
    key = parse_vkey("example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k")
    assert key.key_id.hex() == "530d903a"
    note = parse_note(
        "This is an example message.\n"
        "\n"
        "— example.com/foo "
        "Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n"
    )
    assert verify_note(note, [key])


def test_vkey_round_trip():
    priv = Ed25519PrivateKey.generate()
    vk = vkey_from_ed25519("example.com/k", priv.public_key())
    text = format_vkey(vk)
    assert parse_vkey(text) == vk
    # the key material part is base64(0x01 || pubkey)
    blob = b64_decode(text.split("+", 1)[1][9:])
    assert blob[0] == 0x01 and blob[1:] == vk.public_key


def test_vkey_rejects_wrong_id():
    priv = Ed25519PrivateKey.generate()
    vk = vkey_from_ed25519("example.com/k", priv.public_key())
    bad = f"example.com/k+deadbeef+{b64_encode(bytes([1]) + vk.public_key)}"
    with pytest.raises(ValueError, match="mismatch"):
        parse_vkey(bad)


def test_b64_canonical_only():
    assert b64_decode(b64_encode(b"abc")) == b"abc"
    assert b64_decode("abc=") == b"\x69\xb7"  # properly padded 2-byte form is canonical
    for bad in ["abc", "ab=c", "AB=C=", "a", "a===", "!!!!"]:
        with pytest.raises(ValueError):
            b64_decode(bad)  # non-canonical or bad padding


def test_sign_parse_verify_round_trip():
    priv = Ed25519PrivateKey.generate()
    text = "hello note\nwith two lines\n"
    sig = sign_note(text, priv, "ex.com/k1")
    note = parse_note(text + "\n" + f"— ex.com/k1 {b64_encode(sig.key_id + sig.signature)}\n")
    assert note.text == text
    assert verify_note(note, [vkey_from_ed25519("ex.com/k1", priv.public_key())])
    # serialise round trip
    assert parse_note(note.serialise()) == note


def test_separator_is_last_empty_line():
    priv = Ed25519PrivateKey.generate()
    text = "para one\n\npara two\n\n"  # internal blank lines
    sig = sign_note(text, priv, "ex.com/k")
    note = parse_note(text + "\n— ex.com/k " + b64_encode(sig.key_id + sig.signature) + "\n")
    assert note.text == text
    assert verify_note(note, [vkey_from_ed25519("ex.com/k", priv.public_key())])
    # moving the blank line changes the text that was signed -> must fail
    other = parse_note(
        "para one\n\npara two\n"
        "\n— ex.com/k " + b64_encode(sig.key_id + sig.signature) + "\n"
    )
    assert not verify_note(other, [vkey_from_ed25519("ex.com/k", priv.public_key())])


def test_verification_rules():
    a, b, unknown = (Ed25519PrivateKey.generate() for _ in range(3))
    ka = vkey_from_ed25519("ex.com/a", a.public_key())
    kb = vkey_from_ed25519("ex.com/b", b.public_key())
    text = "note\n"
    sig_a = sign_note(text, a, "ex.com/a")
    sig_b = sign_note(text, b, "ex.com/b")

    def note_with(*sigs):
        return parse_note(
            text + "\n" + "".join(
                f"— {s.name} {b64_encode(s.key_id + s.signature)}\n" for s in sigs
            )
        )

    # only unknown-key signatures -> rejected
    sig_u = sign_note(text, unknown, "ex.com/a")  # same name, different key
    assert not verify_note(note_with(sig_u), [ka])
    # known key + unknown key -> accepted
    assert verify_note(note_with(sig_u, sig_a), [ka])
    # signature matching a known key but failing -> whole note rejected
    forged = SignatureLine(name="ex.com/a", key_id=ka.key_id, signature=bytes(64))
    assert not verify_note(note_with(forged, sig_a), [ka])
    assert not verify_note(note_with(sig_a, forged), [ka, kb])
    # no configured keys -> rejected
    assert not verify_note(note_with(sig_a), [])


def test_bad_names_rejected():
    for bad in ["", "a b", "a+b", "a\nb", "x" * 300]:
        with pytest.raises(ValueError):
            check_name(bad)
    assert check_name("example.com/path_1") == "example.com/path_1"


def test_malformed_notes_rejected():
    good = Ed25519PrivateKey.generate()
    text = "n\n"
    sig = sign_note(text, good, "ex.com/a")
    line = f"— ex.com/a {b64_encode(sig.key_id + sig.signature)}\n"
    for bad in [
        "",  # empty
        "n\n",  # no signature block
        "n\n— ex.com/a ###\n",  # bad base64
        "n\nex.com/a " + line,  # missing em dash
        "n\r\n\n" + line,  # carriage return
        "n\n\n",  # blank signature block
        "n\n\n—  ex.com/a " + line[11:],  # double space -> name parse failure
    ]:
        with pytest.raises(ValueError):
            parse_note(bad)
    # non-UTF8
    with pytest.raises(ValueError):
        parse_note(b"n\xff\n\n" + line.encode())


def test_key_id_is_4_bytes_and_big_endian():
    priv = Ed25519PrivateKey.generate()
    sig = sign_note("n\n", priv, "ex.com/a")
    assert len(sig.key_id) == 4
    parsed = parse_note("n\n\n" + f"— ex.com/a {b64_encode(sig.key_id + sig.signature)}\n")
    blob = sig.key_id + parsed.signatures[0].signature
    assert int.from_bytes(blob[:4], "big") == int.from_bytes(sig.key_id, "big")
    assert blob[:4] == sig.key_id


# ---------------------------------------------------------------------------
# Weak Ed25519 public keys (small-order, non-canonical, identity)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("hex_key", SMALL_ORDER + SMALL_ORDER_SIGN_VARIANTS)
def test_small_order_keys_are_flagged(hex_key):
    assert "small-order" in ed25519_public_key_problem(bytes.fromhex(hex_key))


@pytest.mark.parametrize("hex_key", NON_CANONICAL)
def test_non_canonical_keys_are_flagged(hex_key):
    assert "canonical" in ed25519_public_key_problem(bytes.fromhex(hex_key))


def test_good_keys_have_no_problem():
    # a generated key (and the Go sumdb key) pass; a wrong length does not
    assert ed25519_public_key_problem(Ed25519PrivateKey.generate().public_key().public_bytes_raw()) is None
    assert ed25519_public_key_problem(parse_vkey(GO_SUMDB_VKEY).public_key) is None
    assert ed25519_public_key_problem(b"\x07" * 31) == "is not a 32-byte Ed25519 public key"


@pytest.mark.parametrize("hex_key", SMALL_ORDER + SMALL_ORDER_SIGN_VARIANTS + NON_CANONICAL)
def test_parse_vkey_rejects_weak_keys(hex_key):
    # key ID is computed correctly, so only the weak key can be at fault
    with pytest.raises(ValueError, match="small-order|canonical"):
        parse_vkey(_vkey_text("weak.example/log", 0x01, bytes.fromhex(hex_key)))
    # cosignature-type (0x04) vkeys carry the same raw Ed25519 key
    with pytest.raises(ValueError, match="small-order|canonical"):
        parse_vkey(_vkey_text("weak.example/wit", 0x04, bytes.fromhex(hex_key)))


@pytest.mark.parametrize("hex_key", SMALL_ORDER[:3] + NON_CANONICAL[:1])
def test_vkey_from_ed25519_rejects_weak_keys(hex_key):
    with pytest.raises(ValueError, match="small-order|canonical"):
        vkey_from_ed25519("weak.example/log", bytes.fromhex(hex_key))
    with pytest.raises(ValueError, match="small-order|canonical"):
        vkey_from_ed25519("weak.example/wit", bytes.fromhex(hex_key), key_type=0x04)


@pytest.mark.parametrize("hex_key", SMALL_ORDER[:3] + NON_CANONICAL[:1])
def test_vkey_ed25519_property_rejects_weak_keys(hex_key):
    # a VKey built directly must not smuggle a weak key into verification
    key = bytes.fromhex(hex_key)
    vk = VKey(name="weak.example/log", key_id=key_hash("weak.example/log", 0x01, key),
              key_type=0x01, public_key=key)
    with pytest.raises(ValueError, match="small-order|canonical"):
        vk.ed25519


def test_weak_keys_never_verify_a_note():
    # even if a weak key slips into a note's signature lines, the vkey path
    # refuses it; a forged identity signature must not verify
    identity = bytes([1]) + bytes(31)
    forged = SignatureLine(name="weak.example/log", key_id=key_hash("weak.example/log", 0x01, identity),
                           signature=bytes(64))
    note = parse_note("n\n\n— weak.example/log " + b64_encode(forged.key_id + forged.signature) + "\n")
    with pytest.raises(ValueError, match="small-order"):
        verify_note(note, [VKey("weak.example/log", forged.key_id, 0x01, identity)])


def test_valid_key_still_parses_and_verifies():
    # positive control: an ordinary generated key passes every new check
    priv = Ed25519PrivateKey.generate()
    vk = vkey_from_ed25519("ex.com/k", priv.public_key())
    assert parse_vkey(format_vkey(vk)) == vk
    assert vk.ed25519.public_bytes_raw() == priv.public_key().public_bytes_raw()
    text = "hello\n"
    sig = sign_note(text, priv, "ex.com/k")
    note = parse_note(text + "\n— ex.com/k " + b64_encode(sig.key_id + sig.signature) + "\n")
    assert verify_note(note, [vk])

"""Sealed boxes with a bound inner header (AICS-1 section 8.1); X25519 key helpers."""

from __future__ import annotations

import hashlib
import hmac
import json
import struct

import pytest
from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519
from nacl.public import PrivateKey, SealedBox

from aics_identity import envelope, keys, sealed
from aics_identity.sealed import (
    CiphertextMismatch,
    DecryptionFailed,
    HeaderMismatch,
    InnerHeader,
    MalformedSealed,
    open_sealed,
    seal,
)
from conftest import DID_KEY_SPEC_ED25519_RAW

CREATED = 1_792_281_600
ORIGIN = "api.example.test/tiles"


class Agent:
    """A test agent: Ed25519 identity key (its did:key is the kid) plus an X25519 encryption key."""

    def __init__(self) -> None:
        self.ed = keys.generate_keypair()
        self.x = sealed.generate_x25519_key()
        self.kid = keys.did_key(self.ed.public_key())

    def resolve(self, kid):
        return self.ed.public_key() if kid == self.kid else None


def dm_payload(ct: bytes, to: str, chain: dict, **override) -> dict:
    return {"to_kid": to, "to_key_leaf_index": 7, **sealed.ciphertext_metadata(ct), "grant_index": 9, **chain,
            **override}


def send_dm(sender: Agent, recipient: Agent, body: str, *, previous=None):
    """The documented sending flow: nonce first, seal, then sign a dm envelope committing to the ciphertext."""
    nonce = envelope.new_nonce()
    ct = seal(InnerHeader(from_kid=sender.kid, to_kid=recipient.kid, envelope_nonce=nonce), body, recipient.x.public_key)
    chain = envelope.next_chain(previous)
    env = envelope.sign_envelope(dm_payload(ct, recipient.kid, chain), sender.ed, origin=ORIGIN, type="dm",
                                 nonce=nonce, created=CREATED, **chain)
    return env, ct


def raw_seal(plaintext: bytes, recipient: PrivateKey) -> bytes:
    return bytes(SealedBox(recipient.public_key).encrypt(plaintext))


def frame(header: bytes, content: bytes) -> bytes:
    return struct.pack(">I", len(header)) + header + content


ALICE_KID = keys.did_key(keys.private_key_from_seed(bytes([1]) * 32).public_key())
BOB_KID = keys.did_key(keys.private_key_from_seed(bytes([5]) * 32).public_key())
NONCE = keys.b64u_encode(bytes(range(48, 64)))
HEADER = InnerHeader(from_kid=ALICE_KID, to_kid=BOB_KID, envelope_nonce=NONCE)
HEADER_JSON = ('{"envelope_nonce":"%s","from_kid":"%s","to_kid":"%s"}' % (NONCE, ALICE_KID, BOB_KID)).encode()


# ----------------------------------------------------------------------
# wire format
# ----------------------------------------------------------------------

def test_roundtrip_and_documented_layout():
    bob = sealed.generate_x25519_key()
    ct = seal(HEADER, "hello bob", bob.public_key)
    # plaintext layout: uint32be(len(header)) || JCS(header) || content, opened with plain PyNaCl
    plaintext = SealedBox(bob).decrypt(ct)
    assert plaintext == len(HEADER_JSON).to_bytes(4, "big") + HEADER_JSON + b"hello bob"
    assert HEADER.canonical_bytes() == HEADER_JSON
    assert len(ct) == len(plaintext) + sealed.SEAL_OVERHEAD == len(plaintext) + 48
    msg = open_sealed(ct, bob, expected=HEADER)
    assert msg.header == HEADER
    assert msg.body == b"hello bob" and msg.text == "hello bob"


def test_box_built_by_hand_from_the_spec_opens():
    bob = sealed.generate_x25519_key()
    header = json.dumps(HEADER.to_dict(), separators=(",", ":"), sort_keys=True).encode()
    content = "line one\nline two — with UTF-8\n".encode("utf-8")
    msg = open_sealed(raw_seal(frame(header, content), bob), bob, expected=HEADER.to_dict())
    assert msg.body == content  # newlines inside the content are fine: the length frames the header


def test_frame_and_split_plaintext():
    framed = sealed.frame_plaintext(HEADER_JSON, b"x")
    assert framed[:4] == len(HEADER_JSON).to_bytes(4, "big")
    assert sealed.split_plaintext(framed) == (HEADER_JSON, b"x")
    assert sealed.split_plaintext(sealed.frame_plaintext(HEADER_JSON, b"")) == (HEADER_JSON, b"")
    with pytest.raises(ValueError):
        sealed.frame_plaintext(b"", b"x")
    with pytest.raises(ValueError):
        sealed.frame_plaintext(b"x" * (sealed.MAX_HEADER_BYTES + 1), b"")
    assert sealed.split_plaintext(sealed.frame_plaintext(b"h" * sealed.MAX_HEADER_BYTES, b"c"))[1] == b"c"


def test_mapping_header_and_bytes_content():
    bob = sealed.generate_x25519_key()
    ct = seal(HEADER.to_dict(), "é".encode("utf-8"), bytes(bob.public_key))
    assert open_sealed(ct, bytes(bob), expected=HEADER).text == "é"


def test_each_seal_uses_a_fresh_ephemeral_key():
    bob = sealed.generate_x25519_key()
    a = seal(HEADER, "same", bob.public_key)
    b = seal(HEADER, "same", bob.public_key)
    assert a != b
    assert sealed.ephemeral_public_key(a) != sealed.ephemeral_public_key(b)


def test_ciphertext_metadata():
    bob = sealed.generate_x25519_key()
    ct = seal(HEADER, "x", bob.public_key)
    meta = sealed.ciphertext_metadata(ct)
    assert meta == {
        "encryption": "x25519-xsalsa20-poly1305",
        "eph_pk": keys.b64u_encode(ct[:32]),
        "ct_hash": hashlib.sha256(ct).hexdigest(),
        "size": len(ct),
    }
    assert sealed.ct_hash(ct) == meta["ct_hash"]


# ----------------------------------------------------------------------
# failures
# ----------------------------------------------------------------------

def test_wrong_recipient_key_cannot_open():
    bob, eve = sealed.generate_x25519_key(), sealed.generate_x25519_key()
    ct = seal(HEADER, "for bob", bob.public_key)
    with pytest.raises(DecryptionFailed):
        open_sealed(ct, eve, expected=HEADER)


@pytest.mark.parametrize("position", [0, 31, 32, 47, -1])
def test_tampered_ciphertext_fails(position):
    bob = sealed.generate_x25519_key()
    ct = bytearray(seal(HEADER, "for bob", bob.public_key))
    ct[position] ^= 0x01
    with pytest.raises(DecryptionFailed):
        open_sealed(bytes(ct), bob, expected=HEADER)


@pytest.mark.parametrize("field, value", [
    ("from_kid", BOB_KID),
    ("to_kid", ALICE_KID),
    ("envelope_nonce", keys.b64u_encode(bytes(16))),
])
def test_each_header_field_must_match(field, value):
    bob = sealed.generate_x25519_key()
    ct = seal(HEADER, "x", bob.public_key)
    wrong = dict(HEADER.to_dict(), **{field: value})
    with pytest.raises(HeaderMismatch, match=field):
        open_sealed(ct, bob, expected=wrong)


def test_too_short_ciphertext_rejected():
    with pytest.raises(MalformedSealed):
        open_sealed(b"\x00" * 47, sealed.generate_x25519_key(), expected=HEADER)
    with pytest.raises(MalformedSealed):
        sealed.ephemeral_public_key(b"\x00" * 10)


_H = HEADER_JSON.decode()


@pytest.mark.parametrize(
    "plaintext, match",
    [
        (b"", "no inner header length"),
        (b"\x00\x00\x00", "no inner header length"),
        (frame(b"", b"body"), "outside 1 to 4096"),
        (struct.pack(">I", 5000) + HEADER_JSON, "outside 1 to 4096"),
        (struct.pack(">I", len(HEADER_JSON) + 1) + HEADER_JSON, "fully contained"),
        (HEADER_JSON + b"\n" + b"body", "outside 1 to 4096"),  # the JCS || LF framing is not AICS-1
        (frame(b"not json", b"body"), "not a JSON object"),
        (frame(b"[1,2,3]", b"body"), "not a JSON object"),
        (frame(_H.replace(",", ", ").encode(), b"body"), "canonical"),
        (frame(json.dumps(dict(reversed(list(HEADER.to_dict().items()))), separators=(",", ":")).encode(), b"b"),
         "canonical"),
        (frame(('{"envelope_nonce":"%s","from_kid":"%s"}' % (NONCE, ALICE_KID)).encode(), b"body"), "missing"),
        (frame(_H.replace('"from_kid"', '"extra":"x","from_kid"').encode(), b"body"), "extra"),
        (frame(_H.replace('"to_kid"', '"from_kid":"x","to_kid"').encode(), b"b"), "duplicate"),
        (frame(_H.replace('"%s"' % NONCE, "1").encode(), b"body"), "non-empty string"),
        (frame(_H.replace(NONCE, "").encode(), b"body"), "non-empty string"),
        (frame(_H.replace(NONCE, "nonce-1").encode(), b"body"), "16 bytes"),
        (frame(_H.replace(ALICE_KID, "AAAAAAAAAAAAAAAA").encode(), b"body"), "did:key"),
        (frame(b"\xff\xfe", b"body"), "not a JSON object"),
        (frame(HEADER_JSON, b"\xff not UTF-8"), "UTF-8"),
    ],
)
def test_malformed_plaintexts_rejected(plaintext, match):
    bob = sealed.generate_x25519_key()
    with pytest.raises(MalformedSealed, match=match):
        open_sealed(raw_seal(plaintext, bob), bob, expected=HEADER)


def test_open_needs_exactly_one_expectation():
    bob = sealed.generate_x25519_key()
    ct = seal(HEADER, "x", bob.public_key)
    with pytest.raises(TypeError):
        open_sealed(ct, bob)
    with pytest.raises(TypeError):
        open_sealed(ct, bob, expected=HEADER, envelope={"protected": {}, "payload": {}})


def test_size_cap():
    bob = sealed.generate_x25519_key()
    limit = sealed.MAX_CIPHERTEXT_BYTES
    assert limit == 65536
    overhead = 4 + len(HEADER.canonical_bytes()) + sealed.SEAL_OVERHEAD
    ct = seal(HEADER, b"a" * (limit - overhead), bob.public_key)
    assert len(ct) == limit
    with pytest.raises(ValueError, match="limit"):
        seal(HEADER, b"a" * (limit - overhead + 1), bob.public_key)
    assert len(seal(HEADER, b"a" * limit, bob.public_key, max_ciphertext_bytes=None)) > limit


def test_seal_argument_checks():
    bob = sealed.generate_x25519_key()
    with pytest.raises(TypeError):
        seal(HEADER, 12345, bob.public_key)
    with pytest.raises(ValueError, match="UTF-8"):
        seal(HEADER, b"\xff\xfe binary", bob.public_key)
    with pytest.raises(ValueError):
        seal({"from_kid": ALICE_KID, "to_kid": BOB_KID}, "x", bob.public_key)
    with pytest.raises(ValueError):
        seal(HEADER, "x", b"\x00" * 32)  # small-order recipient key


def test_inner_header_validation():
    with pytest.raises(ValueError):
        InnerHeader(from_kid="", to_kid=BOB_KID, envelope_nonce=NONCE)
    with pytest.raises(ValueError, match="did:key"):
        InnerHeader(from_kid="AAAAAAAAAAAAAAAA", to_kid=BOB_KID, envelope_nonce=NONCE)
    with pytest.raises(ValueError, match="did:key"):
        InnerHeader(from_kid=ALICE_KID, to_kid=keys.x25519_did_key(bytes(range(32))), envelope_nonce=NONCE)
    with pytest.raises(ValueError, match="16 bytes"):
        InnerHeader(from_kid=ALICE_KID, to_kid=BOB_KID, envelope_nonce="nonce-1")
    with pytest.raises(ValueError):
        InnerHeader(from_kid=ALICE_KID, to_kid=None, envelope_nonce=NONCE)
    with pytest.raises(TypeError):
        InnerHeader.from_mapping(["not", "a", "mapping"])
    assert InnerHeader.from_mapping(HEADER.to_dict()) == HEADER


def test_open_alias_and_star_export():
    assert sealed.open is sealed.open_sealed
    assert "open" not in sealed.__all__


# ----------------------------------------------------------------------
# the envelope binding (DESIGN.md G6)
# ----------------------------------------------------------------------

def test_full_dm_flow_with_envelope():
    alice, bob = Agent(), Agent()
    env, ct = send_dm(alice, bob, "meet at leaf 42")
    payload = envelope.verify_envelope(env, alice.resolve, now=CREATED + 1, origin=ORIGIN, type="dm")
    assert payload["ct_hash"] == sealed.ct_hash(ct) and payload["seq"] == env["protected"]["seq"]
    msg = open_sealed(ct, bob.x, envelope=env, recipient_kid=bob.kid)
    assert msg.text == "meet at leaf 42"
    assert msg.header == InnerHeader(from_kid=alice.kid, to_kid=bob.kid, envelope_nonce=env["protected"]["nonce"])

    env2, ct2 = send_dm(alice, bob, "second", previous=env)
    envelope.check_successor(env, env2)
    assert open_sealed(ct2, bob.x, envelope=env2).text == "second"


def test_capsule_header_names_its_owner_twice():
    owner = Agent()
    nonce = envelope.new_nonce()
    ct = seal(InnerHeader(from_kid=owner.kid, to_kid=owner.kid, envelope_nonce=nonce), "remember", owner.x.public_key)
    q = {"owner_kid": owner.kid, "to_key_leaf_index": 1, "key_hash": "ab" * 32, **sealed.ciphertext_metadata(ct),
         "expires": CREATED + 7776000, "prev_capsule_index": None}
    env = envelope.sign_envelope(q, owner.ed, origin=ORIGIN, type="capsule", nonce=nonce, created=CREATED)
    assert InnerHeader.from_envelope(env).to_kid == owner.kid
    assert open_sealed(ct, owner.x, envelope=env, recipient_kid=owner.kid).text == "remember"


def test_only_dm_and_capsule_envelopes_carry_sealed_bodies():
    alice, bob = Agent(), Agent()
    env, ct = send_dm(alice, bob, "x")
    post = dict(env, protected=dict(env["protected"], type="post"))
    with pytest.raises(HeaderMismatch, match="dm and capsule"):
        open_sealed(ct, bob.x, envelope=post)


def test_rewrapped_ciphertext_is_rejected():
    """Mallory lifts Alice's logged ciphertext into her own validly signed envelope to Bob."""
    alice, bob, mallory = Agent(), Agent(), Agent()
    _, ct = send_dm(alice, bob, "from alice")
    chain = envelope.next_chain(None)
    mallory_env = envelope.sign_envelope(dm_payload(ct, bob.kid, chain), mallory.ed, origin=ORIGIN, type="dm",
                                         created=CREATED, **chain)
    envelope.verify_envelope(mallory_env, mallory.resolve, now=CREATED + 1)  # the signature itself is fine
    with pytest.raises(HeaderMismatch):
        open_sealed(ct, bob.x, envelope=mallory_env)


def test_rewrapped_ciphertext_with_copied_nonce_is_rejected():
    """Even copying Alice's envelope nonce leaves the sender kid in the header pointing at Alice."""
    alice, bob, mallory = Agent(), Agent(), Agent()
    alice_env, ct = send_dm(alice, bob, "from alice")
    chain = envelope.next_chain(None)
    mallory_env = envelope.sign_envelope(dm_payload(ct, bob.kid, chain), mallory.ed, origin=ORIGIN, type="dm",
                                         nonce=alice_env["protected"]["nonce"], created=CREATED, **chain)
    with pytest.raises(HeaderMismatch, match="from_kid"):
        open_sealed(ct, bob.x, envelope=mallory_env)


def test_substituted_body_under_a_public_header_is_rejected():
    """The header fields are public, so anyone can seal a new body under them; ct_hash stops it."""
    alice, bob = Agent(), Agent()
    env, _ = send_dm(alice, bob, "original")
    forged = seal(InnerHeader.from_envelope(env), "forged by the server", bob.x.public_key)
    with pytest.raises(CiphertextMismatch, match="ct_hash"):
        open_sealed(forged, bob.x, envelope=env)


def test_envelope_must_commit_to_the_ciphertext():
    alice, bob = Agent(), Agent()
    env, ct = send_dm(alice, bob, "x")
    for field in ("encryption", "ct_hash", "eph_pk", "size"):
        missing = {"protected": env["protected"], "payload": {k: v for k, v in env["payload"].items() if k != field}}
        with pytest.raises(CiphertextMismatch, match=f"no {field}"):
            open_sealed(ct, bob.x, envelope=missing)
    for field, value in (("eph_pk", keys.b64u_encode(b"\x00" * 32)), ("size", len(ct) + 1), ("size", True)):
        bad = {"protected": env["protected"], "payload": dict(env["payload"], **{field: value})}
        with pytest.raises(CiphertextMismatch, match=field):
            open_sealed(ct, bob.x, envelope=bad)
    age = {"protected": env["protected"], "payload": dict(env["payload"], encryption="age-v1")}
    with pytest.raises(sealed.UnsupportedScheme, match="age-v1"):
        open_sealed(ct, bob.x, envelope=age)


def test_envelope_without_to_kid_or_for_someone_else():
    alice, bob, carol = Agent(), Agent(), Agent()
    env, ct = send_dm(alice, bob, "x")
    with pytest.raises(HeaderMismatch, match="another kid"):
        open_sealed(ct, bob.x, envelope=env, recipient_kid=carol.kid)
    broken = {"protected": env["protected"], "payload": {k: v for k, v in env["payload"].items() if k != "to_kid"}}
    with pytest.raises(HeaderMismatch, match="to_kid"):
        open_sealed(ct, bob.x, envelope=broken)


# ----------------------------------------------------------------------
# X25519 keys
# ----------------------------------------------------------------------

def test_private_and_public_key_coercions():
    key = sealed.generate_x25519_key()
    raw_priv = sealed.x25519_private_bytes(key)
    assert len(raw_priv) == 32
    assert bytes(sealed.x25519_private_key(raw_priv).public_key) == bytes(key.public_key)
    raw_pub = sealed.x25519_public_bytes(key)
    assert raw_pub == bytes(key.public_key)
    text = sealed.format_x25519_public_key(key.public_key)
    assert "=" not in text and len(text) == 43
    for form in (key, key.public_key, raw_pub, text, text + "=", keys.b64u_encode(raw_pub)):
        assert sealed.x25519_public_bytes(form) == raw_pub
    import base64
    assert bytes(sealed.parse_x25519_public_key(base64.b64encode(raw_pub).decode())) == raw_pub
    with pytest.raises(TypeError):
        sealed.x25519_public_key(1.5)
    with pytest.raises(ValueError):
        sealed.x25519_private_key(b"\x00" * 31)
    with pytest.raises(TypeError):
        sealed.x25519_private_key("text")


def test_did_key_roundtrip_and_spec_vector():
    key = sealed.generate_x25519_key()
    did = sealed.x25519_did_key(key.public_key)
    assert did.startswith("did:key:z6LS")
    assert bytes(sealed.parse_x25519_did_key(did)) == bytes(key.public_key)
    assert sealed.x25519_public_bytes(did) == bytes(key.public_key)
    # did:key spec example: the X25519 key-agreement key of
    # did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
    x_raw = crypto_sign_ed25519_pk_to_curve25519(DID_KEY_SPEC_ED25519_RAW)
    assert sealed.x25519_did_key(x_raw) == "did:key:z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"


def test_did_key_rejects_ed25519_multicodec():
    ed_did = keys.did_key(keys.generate_keypair().public_key())
    with pytest.raises(ValueError, match="x25519-pub"):
        sealed.parse_x25519_did_key(ed_did)
    with pytest.raises(ValueError):
        sealed.parse_x25519_did_key("not-a-did")


def test_x25519_kid_is_domain_separated_from_ed25519_kid():
    raw = bytes(sealed.generate_x25519_key().public_key)
    kid = sealed.x25519_key_id(raw)
    assert len(kid) == 16
    assert kid == keys.b64u_encode(hashlib.sha256(b"\xec\x01" + raw).digest())[:16]
    # the same 32 bytes read as an Ed25519 key get a different kid
    assert kid != keys.b64u_encode(hashlib.sha256(raw).digest())[:16]


# Curve25519 u-coordinates of small order (little-endian), including the
# non-canonical encodings p and p + 1 of 0 and 1.
_P = 2**255 - 19
SMALL_ORDER_POINTS = [
    (0).to_bytes(32, "little"),
    (1).to_bytes(32, "little"),
    (325606250916557431795983626356110631294008115727848805560023387167927233504).to_bytes(32, "little"),
    (39382357235489614581723060781553021112529911719440698176882885853963445705823).to_bytes(32, "little"),
    (_P - 1).to_bytes(32, "little"),
    (_P).to_bytes(32, "little"),
    (_P + 1).to_bytes(32, "little"),
]


def test_small_order_point_encodings():
    assert SMALL_ORDER_POINTS[2].hex() == "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
    assert SMALL_ORDER_POINTS[3].hex() == "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"


@pytest.mark.parametrize("point", SMALL_ORDER_POINTS, ids=lambda b: b.hex()[:8])
def test_small_order_public_keys_rejected(point):
    with pytest.raises(ValueError, match="small-order"):
        sealed.validate_x25519_public_key(point)
    with pytest.raises(ValueError):
        sealed.x25519_did_key(point)


def test_public_key_length_enforced():
    with pytest.raises(ValueError, match="32 bytes"):
        sealed.validate_x25519_public_key(b"\x09" * 31)
    with pytest.raises(ValueError):
        sealed.parse_x25519_public_key(keys.b64u_encode(b"\x09" * 33))
    assert sealed.validate_x25519_public_key(bytes(sealed.generate_x25519_key().public_key))


# ----------------------------------------------------------------------
# derivation
# ----------------------------------------------------------------------

MASTER = b"\x01" * 32


def test_derive_x25519_is_deterministic_and_bound_to_inputs():
    a = sealed.x25519_private_bytes(sealed.derive_x25519_key(MASTER, "agent-7"))
    assert a == sealed.x25519_private_bytes(sealed.derive_x25519_key(MASTER, "agent-7"))
    others = {
        sealed.x25519_private_bytes(sealed.derive_x25519_key(MASTER, "agent-8")),
        sealed.x25519_private_bytes(sealed.derive_x25519_key(MASTER, "agent-7", run_salt=b"s" * 16)),
        sealed.x25519_private_bytes(sealed.derive_x25519_key(b"\x02" * 32, "agent-7")),
    }
    assert a not in others and len(others) == 3
    # independent of the Ed25519 key derived from the same secret and label
    assert a != keys.private_seed(keys.derive_agent_key(MASTER, "agent-7"))


def test_derive_x25519_matches_hkdf_reference():
    salt = b"\x11" * 16
    prk = hmac.new(salt, MASTER, hashlib.sha256).digest()
    okm = hmac.new(prk, b"aics-identity/v1-x25519/agent-7" + b"\x01", hashlib.sha256).digest()
    assert sealed.x25519_private_bytes(sealed.derive_x25519_key(MASTER, "agent-7", run_salt=salt)) == okm


def test_hkdf_info_prefixes_cannot_collide():
    ed_prefix, x_prefix = keys.HKDF_INFO_PREFIX, sealed.X25519_HKDF_INFO_PREFIX
    assert ed_prefix[:16] == x_prefix[:16] and ed_prefix[16:17] == b"/" and x_prefix[16:17] == b"-"
    assert not (ed_prefix + b"x25519/agent").startswith(x_prefix)


def test_derive_x25519_input_validation():
    with pytest.raises(ValueError):
        sealed.derive_x25519_key(b"", "a")
    with pytest.raises(ValueError):
        sealed.derive_x25519_key(MASTER, "")
    with pytest.raises(ValueError):
        sealed.derive_x25519_key(MASTER, "a", run_salt=b"")


def test_sealed_to_a_derived_key_opens_with_the_rederived_key():
    recipient = sealed.derive_x25519_key(MASTER, "agent-7")
    ct = seal(HEADER, "for my successor", recipient.public_key)
    assert open_sealed(ct, sealed.derive_x25519_key(MASTER, "agent-7"), expected=HEADER).text == "for my successor"

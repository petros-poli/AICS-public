"""AICS-1 Appendix A is the oracle: sign_envelope reproduces A.1 byte for byte and open_sealed opens A.4."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest
from nacl.bindings import crypto_box, crypto_box_seal_open, crypto_scalarmult_base

import aics1_vectors as A
from aics_identity import canonicalize, envelope, keys, sealed

ALICE = keys.private_key_from_seed(A.ALICE_SEED)
BOB = keys.private_key_from_seed(A.BOB_SEED)
A1 = json.loads(A.A1_ENVELOPE)
CIPHERTEXT = bytes.fromhex(A.A4_CIPHERTEXT_HEX)
U = keys.b64u_encode


def alice_claim() -> dict:
    """Leaf 1's envelope (A.5): Alice's claim, the predecessor A.1's prev names."""
    q = dict(name_norm="alice", prev_event_index=None, ed25519=U(ALICE.public_key().public_bytes_raw()),
             x25519=U(crypto_scalarmult_base(A.ALICE_X25519_SECRET)), tier="verified", recovery_kid=None,
             recovery_pop=None, initial_grant=None)
    return envelope.sign_envelope(q, ALICE, origin=A.ORIGIN, type="name.claim", created=A.EPOCH,
                                  nonce=U(bytes(range(16))))


def _spec_text() -> str:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / A.SPEC_PATH_FROM_REPO
        if candidate.is_file():
            return candidate.read_text("utf-8")
    pytest.skip("docs/spec/AICS-1.md is not beside this checkout")


def test_vectors_are_the_specification_text():
    """The copied values equal the specification's Appendix A (skipped outside the repository)."""
    spec = _spec_text()
    app = spec[spec.index("## Appendix A."):]
    for name in ("A1_ENVELOPE", "A4_HEADER", "A4_PLAINTEXT_HEX", "A4_CIPHERTEXT_HEX"):
        assert "```json\n" + getattr(A, name) + "\n```" in app or "```text\n" + getattr(A, name) + "\n```" in app, name
    assert "```text\n" + A.A3_PREVIOUS_NOTE + "```" in app
    for name in ("A1_ALICE_PUBLIC_HEX", "A1_SIGNING_DIGEST_HEX", "A1_ENVELOPE_HASH", "A3_PREVIOUS_NOTE_HASH",
                 "A4_BOB_X25519_PUBLIC_HEX", "A4_EPHEMERAL_PUBLIC_HEX", "A4_BOX_NONCE_HEX", "A4_CIPHERTEXT_HASH"):
        assert f"`{getattr(A, name)}`" in app, name
    assert re.search(rf"Epoch `{A.EPOCH}`", app)


# ----------------------------------------------------------------------
# A.1: the envelope
# ----------------------------------------------------------------------

def test_kids_are_the_appendix_did_keys():
    assert ALICE.public_key().public_bytes_raw().hex() == A.A1_ALICE_PUBLIC_HEX
    assert keys.did_key(ALICE.public_key()) == A1["protected"]["kid"]
    assert keys.did_key(BOB.public_key()) == A1["payload"]["to_kid"]
    assert keys.parse_did_key(A1["protected"]["kid"]).public_bytes_raw().hex() == A.A1_ALICE_PUBLIC_HEX


def test_sign_envelope_reproduces_a1_byte_for_byte():
    claim = alice_claim()
    assert envelope.envelope_hash(claim) == A1["protected"]["prev"] == A1["payload"]["prev"]
    chain = envelope.next_chain(claim)
    assert chain == {"seq": 1, "prev": A1["protected"]["prev"]}
    seen = envelope.seen_from_checkpoint(A.A3_PREVIOUS_NOTE)
    q = {"to_kid": keys.did_key(BOB.public_key()), "to_key_leaf_index": 2, **sealed.ciphertext_metadata(CIPHERTEXT),
         "grant_index": 2, **chain}
    e3 = envelope.sign_envelope(q, ALICE, origin=A.ORIGIN, type="dm", created=A.EPOCH + 1,
                                nonce=U(bytes(range(48, 64))), seen=seen, **chain)
    assert canonicalize(e3) == A.A1_ENVELOPE.encode()
    assert envelope.envelope_signing_digest(e3["protected"], e3["payload"]).hex() == A.A1_SIGNING_DIGEST_HEX
    assert envelope.envelope_hash(e3) == A.A1_ENVELOPE_HASH
    envelope.check_successor(claim, e3)
    assert envelope.chain_breaks([claim, e3]) == []


def test_a1_has_exactly_the_aics1_members():
    assert envelope.validate_envelope(A1) == "ed25519-jcs"
    assert tuple(sorted(A1)) == tuple(sorted(envelope.ENVELOPE_MEMBERS))
    assert set(A1["protected"]) == set(envelope.PROTECTED_MEMBERS)
    assert A1["auth"] == {"scheme": "ed25519-jcs"}


def test_envelope_hash_is_over_the_whole_envelope():
    assert envelope.envelope_hash(A1) == hashlib.sha256(A.A1_ENVELOPE.encode()).hexdigest() == A.A1_ENVELOPE_HASH
    without_auth = {k: v for k, v in A1.items() if k != "auth"}
    assert hashlib.sha256(canonicalize(without_auth)).hexdigest() != A.A1_ENVELOPE_HASH
    with pytest.raises(envelope.MalformedEnvelope):
        envelope.envelope_hash(without_auth)


def test_verify_envelope_accepts_a1_at_submission_time():
    t = A1["protected"]["created"]
    assert envelope.verify_envelope(copy.deepcopy(A1), keys.parse_did_key, now=t, origin=A.ORIGIN, type="dm") \
        == A1["payload"]
    assert envelope.verify_envelope(copy.deepcopy(A1), keys.parse_did_key, now=A1["protected"]["expires"] - 1)
    with pytest.raises(envelope.ExpiredEnvelope):
        envelope.verify_envelope(copy.deepcopy(A1), keys.parse_did_key, now=A1["protected"]["expires"])
    with pytest.raises(envelope.NotYetValidEnvelope):
        envelope.verify_envelope(copy.deepcopy(A1), keys.parse_did_key, now=t - 31)
    with pytest.raises(envelope.MalformedEnvelope, match="origin"):
        envelope.verify_envelope(copy.deepcopy(A1), keys.parse_did_key, now=t, origin="api.wesupport-ai.com/tiles")


def test_seen_pointer_of_the_a3_note():
    assert envelope.seen_from_checkpoint(A.A3_PREVIOUS_NOTE) == A1["protected"]["seen"]
    assert A1["protected"]["seen"] == {"checkpoint_note_hash": A.A3_PREVIOUS_NOTE_HASH, "size": 3}


# ----------------------------------------------------------------------
# A.4: the sealed message
# ----------------------------------------------------------------------

def test_a4_inner_header_and_framing():
    header = sealed.InnerHeader.from_envelope(A1)
    assert header.canonical_bytes() == A.A4_HEADER.encode()
    assert len(A.A4_HEADER.encode()) == 181
    assert sealed.frame_plaintext(header.canonical_bytes(), b"hello\n").hex() == A.A4_PLAINTEXT_HEX
    assert sealed.split_plaintext(bytes.fromhex(A.A4_PLAINTEXT_HEX)) == (A.A4_HEADER.encode(), b"hello\n")


def test_open_sealed_opens_a4():
    message = sealed.open_sealed(CIPHERTEXT, A.BOB_X25519_SECRET, envelope=A1, recipient_kid=A1["payload"]["to_kid"])
    assert message.body == b"hello\n" and message.text == "hello\n"
    assert message.header == sealed.InnerHeader.from_envelope(A1)


def test_a4_keys_and_commitment():
    assert sealed.x25519_public_bytes(sealed.x25519_private_key(A.BOB_X25519_SECRET)).hex() == A.A4_BOB_X25519_PUBLIC_HEX
    assert sealed.ephemeral_public_key(CIPHERTEXT).hex() == A.A4_EPHEMERAL_PUBLIC_HEX
    meta = sealed.ciphertext_metadata(CIPHERTEXT)
    assert meta == {name: A1["payload"][name] for name in ("encryption", "eph_pk", "ct_hash", "size")}
    assert meta["ct_hash"] == A.A4_CIPHERTEXT_HASH and meta["size"] == 239


def test_the_a5_deterministic_box_of_our_framing_is_the_a4_ciphertext():
    """A.5's technique (fixed ephemeral key, test only) over frame_plaintext gives the A.4 bytes."""
    bob_x = crypto_scalarmult_base(A.BOB_X25519_SECRET)
    eph_pk = crypto_scalarmult_base(A.EPHEMERAL_X25519_SECRET)
    nonce = hashlib.blake2b(eph_pk + bob_x, digest_size=24).digest()
    assert nonce.hex() == A.A4_BOX_NONCE_HEX
    plaintext = sealed.frame_plaintext(sealed.InnerHeader.from_envelope(A1).canonical_bytes(), b"hello\n")
    assert eph_pk + crypto_box(plaintext, nonce, bob_x, A.EPHEMERAL_X25519_SECRET) == CIPHERTEXT


def test_seal_produces_the_a4_plaintext_under_a_fresh_ephemeral_key():
    bob_x = crypto_scalarmult_base(A.BOB_X25519_SECRET)
    box = sealed.seal(sealed.InnerHeader.from_envelope(A1), "hello\n", bob_x)
    assert box != CIPHERTEXT and len(box) == len(CIPHERTEXT)
    assert crypto_box_seal_open(box, bob_x, A.BOB_X25519_SECRET).hex() == A.A4_PLAINTEXT_HEX


@pytest.mark.parametrize("field, value", [
    ("from_kid", keys.did_key(BOB.public_key())),
    ("to_kid", keys.did_key(ALICE.public_key())),
    ("envelope_nonce", U(bytes(16))),
])
def test_a4_ciphertext_under_another_envelope_is_refused(field, value):
    """Rewrapping the A.4 ciphertext into an envelope naming another sender, recipient or nonce."""
    other = copy.deepcopy(A1)
    if field == "from_kid":
        other["protected"]["kid"] = value
    elif field == "to_kid":
        other["payload"]["to_kid"] = value
    else:
        other["protected"]["nonce"] = value
    with pytest.raises(sealed.HeaderMismatch, match=field):
        sealed.open_sealed(CIPHERTEXT, A.BOB_X25519_SECRET, envelope=other)

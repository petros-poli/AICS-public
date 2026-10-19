"""cosignature/v1 build + verify, round trips and tamper rejection."""

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import MerkleTree
from aics_tlog.checkpoint import Checkpoint, sign_checkpoint, verify_checkpoint
from aics_tlog.cosign import (
    COSIGNATURE_TYPE,
    cosignature_key_id,
    cosignature_message,
    cosignature_vkey,
    sign_cosignature,
    verify_cosignature,
)
from aics_tlog.note import Note, SignatureLine, VKey, key_hash, vkey_from_ed25519

# Weak Ed25519 keys refused by cosignature_vkey/verify_cosignature (see
# test_note.py for the full lists): the identity element (0x01 followed by
# zeros), an order-8 point and a non-canonical encoding (y = p + 1).
WEAK_KEYS = [
    bytes([1]) + bytes(31),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    b"\xee" + b"\xff" * 30 + b"\x7f",
]

ROOT = MerkleTree([b"a", b"b", b"c"]).root()


def test_message_format_matches_spec_example_shape():
    msg = cosignature_message(
        1679315147,
        "example.com/behind-the-sofa",
        20852163,
        base64.b64decode("CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I="),
    )
    assert msg == (
        b"cosignature/v1\n"
        b"time 1679315147\n"
        b"example.com/behind-the-sofa\n"
        b"20852163\n"
        b"CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
    )


def test_cosignature_round_trip():
    w = Ed25519PrivateKey.generate()
    blob, sig = sign_cosignature(w, "wit.example/w1", 1700000000, "log.example", 42, ROOT)
    assert len(blob) == 72
    assert int.from_bytes(blob[:8], "big") == 1700000000
    assert cosignature_vkey("wit.example/w1", w.public_key()).key_id == sig.key_id
    assert cosignature_key_id("wit.example/w1", w.public_key().public_bytes_raw()) == sig.key_id
    assert key_hash("wit.example/w1", COSIGNATURE_TYPE, w.public_key().public_bytes_raw()) == sig.key_id
    assert verify_cosignature(blob, "wit.example/w1", w.public_key(), "log.example", 42, ROOT)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timestamp": 1700000001},
        {"origin": "log.example/other"},
        {"size": 41},
        {"size": 43},
        {"root": MerkleTree([b"x"]).root()},
        {"extension_lines": ("extra",)},
    ],
)
def test_cosignature_tamper_rejected(kwargs):
    w = Ed25519PrivateKey.generate()
    blob, _ = sign_cosignature(w, "wit.example/w1", 1700000000, "log.example", 42, ROOT)
    params = dict(
        origin="log.example",
        size=42,
        root=ROOT,
        extension_lines=(),
        timestamp=None,
    )
    params.update(kwargs)
    ts = params.pop("timestamp")
    if ts is not None:
        blob = ts.to_bytes(8, "big") + blob[8:]
    assert not verify_cosignature(blob, "wit.example/w1", w.public_key(), **params)


def test_cosignature_wrong_key_and_length():
    w1, w2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    blob, _ = sign_cosignature(w1, "wit.example/w1", 1, "o", 1, ROOT)
    assert not verify_cosignature(blob, "wit.example/w1", w2.public_key(), "o", 1, ROOT)
    assert not verify_cosignature(blob[:71], "wit.example/w1", w1.public_key(), "o", 1, ROOT)
    assert not verify_cosignature(blob + b"\x00", "wit.example/w1", w1.public_key(), "o", 1, ROOT)
    assert not verify_cosignature(bytes(72), "wit.example/w1", w1.public_key(), "o", 1, ROOT)


def test_cosignature_future_timestamp_optional_rejection():
    w = Ed25519PrivateKey.generate()
    blob, _ = sign_cosignature(w, "w", 10**10, "o", 1, ROOT)
    assert not verify_cosignature(
        blob, "w", w.public_key(), "o", 1, ROOT, max_future_seconds=60, now=10**9
    )
    assert verify_cosignature(blob, "w", w.public_key(), "o", 1, ROOT)


def test_checkpoint_with_cosignatures_end_to_end():
    log, w1, w2 = (Ed25519PrivateKey.generate() for _ in range(3))
    cp = Checkpoint(origin="log.example", size=42, root=ROOT)
    note = sign_checkpoint(cp, log, "log.example")
    log_key = vkey_from_ed25519("log.example", log.public_key())
    wk1 = cosignature_vkey("wit.example/w1", w1.public_key())
    wk2 = cosignature_vkey("wit.example/w2", w2.public_key())
    _, s1 = sign_cosignature(w1, "wit.example/w1", 1000, cp.origin, cp.size, cp.root)
    _, s2 = sign_cosignature(w2, "wit.example/w2", 1001, cp.origin, cp.size, cp.root)
    signed = Note(text=note.text, signatures=(s1, s2, note.signatures[0]))

    res = verify_checkpoint(signed, log_key, [wk1, wk2], quorum=2)
    assert res.ok and res.log_ok and res.cosignature_count == 2
    assert res.witnesses == ["wit.example/w1", "wit.example/w2"]
    # quorum semantics
    assert verify_checkpoint(signed, log_key, [wk1], quorum=1).ok
    assert not verify_checkpoint(signed, log_key, [wk1], quorum=2).ok
    assert not verify_checkpoint(signed, log_key, [], quorum=1).ok
    # unknown witnesses are ignored, not errors
    res = verify_checkpoint(signed, log_key, [], quorum=0)
    assert res.ok and res.cosignature_count == 0


@pytest.mark.parametrize("public_key", WEAK_KEYS)
def test_weak_cosigner_keys_are_refused(public_key):
    # building a cosignature vkey over a weak raw key is a configuration error
    with pytest.raises(ValueError, match="small-order|canonical"):
        cosignature_vkey("wit.example/w1", public_key)
    # and so is asking verify_cosignature to trust one (raw bytes or object)
    w = Ed25519PrivateKey.generate()
    blob, _ = sign_cosignature(w, "wit.example/w1", 1700000000, "log.example", 42, ROOT)
    with pytest.raises(ValueError, match="small-order|canonical"):
        verify_cosignature(blob, "wit.example/w1", public_key, "log.example", 42, ROOT)
    forged = (1700000000).to_bytes(8, "big") + bytes(64)  # R = identity, S = 0
    with pytest.raises(ValueError, match="small-order|canonical"):
        verify_cosignature(forged, "wit.example/w1", public_key, "log.example", 42, ROOT)


def test_weak_witness_vkey_cannot_be_used_for_verification():
    # a checkpoint carrying a forged cosignature under a weak witness key:
    # the weak key (here the identity element, under which R = identity,
    # S = 0 verifies for any checkpoint) is refused before it can count
    weak = WEAK_KEYS[0]
    log = Ed25519PrivateKey.generate()
    cp = Checkpoint(origin="log.example", size=42, root=ROOT)
    note = sign_checkpoint(cp, log, "log.example")
    log_key = vkey_from_ed25519("log.example", log.public_key())
    kid = key_hash("wit.example/w1", COSIGNATURE_TYPE, weak)
    forged = SignatureLine(name="wit.example/w1", key_id=kid, signature=bytes(72))
    signed = Note(text=note.text, signatures=(forged, note.signatures[0]))
    weak_vk = VKey(name="wit.example/w1", key_id=kid, key_type=COSIGNATURE_TYPE, public_key=weak)
    with pytest.raises(ValueError, match="small-order"):
        verify_checkpoint(signed, log_key, [weak_vk], quorum=1)

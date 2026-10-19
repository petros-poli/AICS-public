"""Item 4: sealed boxes with the inner header (AICS-1 §8.1).

Producers: aics-identity ``sealed.seal``, aics-conformance ``protocol.seal``
and the spec reference (deterministic ephemeral key, Appendix A.5
technique).  Openers: aics-identity ``open_sealed`` and aics-conformance's
recipient check ``protocol.open_message``.  The inner header JSON and the
§8.1 framing agree byte for byte, so every box crosses between the packages,
and the rejection tests open boxes the reference made: no package is shown
only its own boxes.
"""

from __future__ import annotations

import struct

import pytest
from nacl.bindings import crypto_box_seal_open
from nacl.public import PrivateKey

from aics_interop import aicslog, spec

ORIGIN = aicslog.ORIGIN
T = aicslog.T0
ALICE = spec.test_key(0x91)
BOB = spec.test_key(0x92)
MALLORY = spec.test_key(0x93)
BOB_X = bytes([0x94]) * 32
BOB_XPUB = spec.x25519_public(BOB_X)
EPH = bytes([0x95]) * 32
NONCE = spec.H(b"sealed-nonce")[:16]
SEEN = {"checkpoint_note_hash": "cd" * 32, "size": 3}
CONTENT = "hello, Bob — private\n".encode("utf-8")


def dm_envelope(ct: bytes, *, key=ALICE, to=BOB, nonce=NONCE, **override) -> dict:
    q = {"to_kid": spec.kid(to), "to_key_leaf_index": 2, "encryption": "x25519-xsalsa20-poly1305",
         "eph_pk": spec.U64(ct[:32]), "ct_hash": spec.hexH(ct), "size": len(ct), "seq": 1, "prev": "ef" * 32,
         "grant_index": 2, **override}
    return spec.native_envelope(key, origin=ORIGIN, typ="dm", payload=q, created=T, nonce=nonce, seq=1,
                                prev="ef" * 32, seen=SEEN)


def header(frm=ALICE, to=BOB, nonce=NONCE) -> bytes:
    return spec.inner_header(spec.kid(frm), spec.kid(to), spec.U64(nonce))


def identity_seal(content=CONTENT, frm=ALICE, to=BOB, nonce=NONCE) -> bytes:
    from aics_identity import sealed

    h = sealed.InnerHeader(from_kid=spec.kid(frm), to_kid=spec.kid(to), envelope_nonce=spec.U64(nonce))
    return sealed.seal(h, content, BOB_XPUB)


def conformance_seal(content=CONTENT, frm=ALICE, to=BOB, nonce=NONCE) -> bytes:
    from aics_conformance import protocol

    return protocol.seal(content, BOB_XPUB, spec.kid(frm), spec.kid(to), spec.U64(nonce))


def spec_seal(content=CONTENT, frm=ALICE, to=BOB, nonce=NONCE) -> bytes:
    return spec.deterministic_seal(spec.aics1_plaintext(header(frm, to, nonce), content), BOB_XPUB, EPH)


def identity_open(ct: bytes, env: dict) -> bytes:
    from aics_identity import sealed

    return sealed.open_sealed(ct, BOB_X, envelope=env, recipient_kid=spec.kid(BOB)).body


def conformance_open(ct: bytes, env: dict) -> bytes:
    from aics_conformance import protocol

    return protocol.open_message(env, ct, PrivateKey(BOB_X))


def test_inner_header_bytes_agree():
    from aics_identity import sealed

    ih = sealed.InnerHeader(from_kid=spec.kid(ALICE), to_kid=spec.kid(BOB), envelope_nonce=spec.U64(NONCE))
    assert ih.canonical_bytes() == header()
    assert ih.to_dict() == spec.strict_json(header())


def test_each_package_opens_its_own_boxes():
    ct = identity_seal()
    assert identity_open(ct, dm_envelope(ct)) == CONTENT
    ct = conformance_seal()
    assert conformance_open(ct, dm_envelope(ct)) == CONTENT


def test_conformance_framing_is_the_aics1_framing():
    """Byte-level: decrypting aics-conformance's box gives uint32be(len) || header || content."""
    ct = conformance_seal()
    assert len(ct) == len(spec.aics1_plaintext(header(), CONTENT)) + 48
    assert crypto_box_seal_open(ct, BOB_XPUB, BOB_X) == spec.aics1_plaintext(header(), CONTENT)
    assert conformance_open(spec_seal(), dm_envelope(spec_seal())) == CONTENT


def test_identity_framing_is_the_aics1_framing():
    """Byte-level: decrypting aics-identity's box gives uint32be(len) || header || content, as for
    aics-conformance's, and aics-identity's own framing helpers are the reference's."""
    from aics_identity import sealed

    ct = identity_seal()
    assert len(ct) == len(spec.aics1_plaintext(header(), CONTENT)) + 48
    assert crypto_box_seal_open(ct, BOB_XPUB, BOB_X) == spec.aics1_plaintext(header(), CONTENT)
    assert sealed.frame_plaintext(header(), CONTENT) == spec.aics1_plaintext(header(), CONTENT)
    assert sealed.split_plaintext(spec.aics1_plaintext(header(), CONTENT)) == (header(), CONTENT)


def test_identity_sealed_box_opens_in_conformance():
    ct = identity_seal()
    assert conformance_open(ct, dm_envelope(ct)) == CONTENT


def test_conformance_sealed_box_opens_in_identity():
    ct = conformance_seal()
    assert identity_open(ct, dm_envelope(ct)) == CONTENT


def test_spec_framed_sealed_box_opens_in_identity():
    ct = spec_seal()
    assert identity_open(ct, dm_envelope(ct)) == CONTENT


def _openers():
    """(name, the reference box maker, opener, expected header-mismatch error)."""
    from aics_identity import sealed

    return (("aics-identity", spec_seal, identity_open,
             (sealed.HeaderMismatch, r"inner header \w+ does not match the envelope|addressed to another kid")),
            ("aics-conformance", spec_seal, conformance_open, (ValueError, "inner-header binding mismatch")))


@pytest.mark.parametrize("field", ["from_kid", "to_kid", "envelope_nonce"])
def test_inner_header_mismatch_is_rejected_by_both(field):
    """A ciphertext whose inner header names another sender/recipient/nonce than its envelope.

    The boxes are the reference's (the same box with the correct header opens in both, see
    ``test_spec_framed_sealed_box_opens_in_identity`` and ``test_conformance_framing_is_the_aics1_framing``)."""
    kw = {"from_kid": dict(frm=MALLORY), "to_kid": dict(to=MALLORY), "envelope_nonce": dict(nonce=bytes(16))}[field]
    for name, seal, opener, (error, message) in _openers():
        ct = seal(**kw)
        with pytest.raises(error, match=message):
            opener(ct, dm_envelope(ct))


@pytest.mark.parametrize("rewrap", ["sender", "recipient", "nonce"])
def test_rewrapped_ciphertext_is_rejected_by_both(rewrap):
    """Mallory re-signs Alice's logged ciphertext (a reference box) in her own envelope (§8.1 rewrap detection)."""
    for name, seal, opener, (error, message) in _openers():
        ct = seal()
        env = {"sender": lambda: dm_envelope(ct, key=MALLORY),
               "recipient": lambda: dm_envelope(ct, to=MALLORY),
               "nonce": lambda: dm_envelope(ct, nonce=bytes(range(16)))}[rewrap]()
        with pytest.raises(error, match=message):
            opener(ct, env)


@pytest.mark.parametrize("field", ["ct_hash", "eph_pk", "size"])
def test_commitment_mismatch_is_rejected_before_decryption(field):
    """The commitment checks run before decryption: each package is handed the other's ciphertext under a validly
    signed envelope that commits to something else."""
    from aics_identity import sealed

    for seal, opener, error, message in ((identity_seal, conformance_open, ValueError, "ciphertext commitment mismatch"),
                                         (conformance_seal, identity_open, sealed.CiphertextMismatch,
                                          f"{field} in the envelope does not match")):
        ct = seal()
        bad = dm_envelope(ct, **{field: {"ct_hash": "00" * 32, "eph_pk": spec.U64(bytes(32)),
                                         "size": len(ct) + 1}[field]})
        with pytest.raises(error, match=message):
            opener(ct, bad)


def test_oversized_inner_header_is_rejected_by_conformance():
    """§8.1: header length at most 4096 and fully contained."""
    pt = struct.pack(">I", 5000) + header() + CONTENT
    ct = spec.deterministic_seal(pt, BOB_XPUB, EPH)
    with pytest.raises(ValueError, match="invalid inner framing"):
        conformance_open(ct, dm_envelope(ct))

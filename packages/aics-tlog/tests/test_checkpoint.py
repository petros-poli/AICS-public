"""Checkpoint parsing rules and verify_checkpoint logic."""

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import MerkleTree
from aics_tlog.checkpoint import (
    Checkpoint,
    parse_checkpoint,
    serialise_checkpoint,
    sign_checkpoint,
    verify_checkpoint,
)
from aics_tlog.note import (
    Note,
    SignatureLine,
    b64_encode,
    parse_note,
    parse_vkey,
    sign_note,
    vkey_from_ed25519,
)

ROOT = MerkleTree([b"a", b"b"]).root()
B64_ROOT = b64_encode(ROOT)


def cp_text(origin="example.com/log", size=2, root=B64_ROOT, ext=()):
    lines = [origin, str(size), root, *ext]
    return "".join(line + "\n" for line in lines)


def test_parse_and_serialise_round_trip():
    cp = parse_checkpoint(cp_text(ext=("ext/1", "ext/2")))
    assert cp == Checkpoint("example.com/log", 2, ROOT, ("ext/1", "ext/2"))
    assert serialise_checkpoint(cp) == cp_text(ext=("ext/1", "ext/2"))
    assert parse_checkpoint(serialise_checkpoint(cp)).extension_lines == ("ext/1", "ext/2")


@pytest.mark.parametrize(
    "text",
    [
        "example.com/log\n2\n",  # too few lines
        "example.com/log\n2\nAAAA\n",  # bad base64 padding
        f"example.com/log\n02\n{B64_ROOT}\n",  # leading zero size
        f"example.com/log\n-2\n{B64_ROOT}\n",  # negative
        f"example.com/log\nx\n{B64_ROOT}\n",  # not decimal
        f"example.com/log\n2\n{b64_encode(b'short')}\n",  # root not 32 bytes
        f"example.com/log\n2\n{B64_ROOT}\n\n",  # empty extension line
        f"ex ample.com/log\n2\n{B64_ROOT}\n",  # space in origin
        f"example.com/log\n2\n{B64_ROOT}",  # no trailing newline
    ],
)
def test_parse_rejects_malformed(text):
    with pytest.raises(ValueError):
        parse_checkpoint(text)


def test_non_canonical_base64_root_rejected():
    raw = base64.b64encode(ROOT).decode()
    trimmed = raw.rstrip("=") + "==="
    with pytest.raises(ValueError):
        parse_checkpoint(f"example.com/log\n2\n{trimmed}\n")


def test_sign_checkpoint_creates_verifiable_note():
    log = Ed25519PrivateKey.generate()
    cp = Checkpoint("example.com/log", 2, ROOT)
    note = sign_checkpoint(cp, log, "example.com/log")
    parsed = parse_note(note.serialise())
    res = verify_checkpoint(parsed, vkey_from_ed25519("example.com/log", log.public_key()), [], quorum=0)
    assert res.ok and res.log_ok


def test_verify_checkpoint_requires_log_signature():
    log = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    cp = Checkpoint("example.com/log", 2, ROOT)
    note = sign_checkpoint(cp, other, "example.com/log")  # wrong log key
    res = verify_checkpoint(
        note, vkey_from_ed25519("example.com/log", log.public_key()), [], quorum=0
    )
    assert not res.ok and "no signature from log key" in res.error


def test_verify_checkpoint_tampered_log_signature_rejected():
    log = Ed25519PrivateKey.generate()
    key = vkey_from_ed25519("example.com/log", log.public_key())
    good = sign_checkpoint(Checkpoint("example.com/log", 2, ROOT), log, "example.com/log")
    sig = good.signatures[0]
    bad = Note(text=good.text, signatures=(SignatureLine(sig.name, sig.key_id, bytes(64)),))
    res = verify_checkpoint(bad, key, [], quorum=0)
    assert not res.ok and "failed verification" in res.error


def test_verify_checkpoint_duplicate_signature_line():
    log = Ed25519PrivateKey.generate()
    key = vkey_from_ed25519("example.com/log", log.public_key())
    note = sign_checkpoint(Checkpoint("example.com/log", 2, ROOT), log, "example.com/log")
    dup = Note(text=note.text, signatures=(note.signatures[0], note.signatures[0]))
    res = verify_checkpoint(dup, key, [], quorum=0)
    assert not res.ok and "duplicate" in res.error


def test_verify_checkpoint_origin_mismatch():
    log = Ed25519PrivateKey.generate()
    note = sign_checkpoint(Checkpoint("example.com/log", 2, ROOT), log, "example.com/log")
    res = verify_checkpoint(
        note,
        vkey_from_ed25519("example.com/log", log.public_key()),
        [],
        quorum=0,
        expected_origin="other.example/log",
    )
    assert not res.ok and "origin mismatch" in res.error


def test_verify_checkpoint_invalid_body():
    # A note whose text is not a valid checkpoint is rejected early.
    priv = Ed25519PrivateKey.generate()
    note = sign_note("not-a-checkpoint\n", priv, "a")
    signed = parse_note(
        "not-a-checkpoint\n\n" + f"— a {b64_encode(note.key_id + note.signature)}\n"
    )
    res = verify_checkpoint(
        signed, vkey_from_ed25519("a", priv.public_key()), [], quorum=0
    )
    assert not res.ok and "invalid checkpoint" in res.error


def test_checkpoint_size_zero_root_rule():
    # A checkpoint of size zero must carry the empty-tree root (witness rule).
    from aics_tlog.hashing import EMPTY_HASH

    cp = parse_checkpoint(f"example.com/log\n0\n{b64_encode(EMPTY_HASH)}\n")
    assert cp.size == 0 and cp.root == EMPTY_HASH


# --- AICS-1 §6.2: repeated lines (interop finding F08) ------------------------


def _cosigned_note(*, repeat_log=False, repeat_witness=False, unknown=()):
    """A note signed by the log and one witness, with optional repeated and
    unknown-key lines; returns (note, log vkey, witness vkey)."""
    from aics_tlog.cosign import cosignature_vkey, sign_cosignature

    log, wit = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    cp = Checkpoint("example.com/log", 2, ROOT)
    signed = sign_checkpoint(cp, log, "example.com/log")
    _, cosig = sign_cosignature(wit, "wit.example/w1", 1_800_000_000, cp.origin, cp.size, cp.root)
    lines = [*signed.signatures, cosig, *unknown]
    if repeat_log:
        lines.append(signed.signatures[0])
    if repeat_witness:
        lines.append(cosig)
    note = parse_note(Note(text=signed.text, signatures=tuple(lines)).serialise())
    return note, vkey_from_ed25519("example.com/log", log.public_key()), cosignature_vkey(
        "wit.example/w1", wit.public_key())


def _unknown_lines(text, n, *, same=True):
    """Signature lines by keys nobody pins (a mirror's attestation, say)."""
    keys = [Ed25519PrivateKey.generate()] * n if same else [Ed25519PrivateKey.generate() for _ in range(n)]
    return [sign_note(text, k, "mirror.example/attest") for k in keys]


def test_repeated_unknown_key_lines_are_ignored():
    text = sign_checkpoint(Checkpoint("example.com/log", 2, ROOT), Ed25519PrivateKey.generate(), "x").text
    for same in (True, False):  # the identical line twice, and two keys under one name
        note, log_key, wit_key = _cosigned_note(unknown=_unknown_lines(text, 2, same=same))
        res = verify_checkpoint(note, log_key, [wit_key], quorum=1)
        assert res.ok and res.log_ok and res.cosignature_count == 1, res.error
        assert verify_checkpoint(note, log_key).ok  # no witnesses configured: the witness line is unknown too
    # an unknown line that does not even verify is still just ignored
    note, log_key, wit_key = _cosigned_note(unknown=[SignatureLine("mirror.example/attest", b"\0\0\0\0", bytes(64))] * 3)
    assert verify_checkpoint(note, log_key, [wit_key], quorum=1).ok


def test_a_repeated_log_key_line_is_rejected():
    note, log_key, wit_key = _cosigned_note(repeat_log=True)
    res = verify_checkpoint(note, log_key, [wit_key], quorum=1)
    assert not res.ok and not res.log_ok and res.error.startswith("duplicate signature line for example.com/log")
    assert not verify_checkpoint(note, log_key).ok


def test_a_repeated_witness_line_is_rejected_when_the_witness_is_configured():
    note, log_key, wit_key = _cosigned_note(repeat_witness=True)
    res = verify_checkpoint(note, log_key, [wit_key], quorum=1)
    # still what the log signed, but no witness policy is met by a malformed note
    assert not res.ok and res.log_ok and res.error.startswith("duplicate signature line for wit.example/w1")
    assert not verify_checkpoint(note, log_key, [wit_key], quorum=0).ok
    # a verifier that does not configure this witness ignores its lines, repeated or not
    assert verify_checkpoint(note, log_key).ok


def test_at_least_sixteen_signature_lines_are_accepted():
    text = sign_checkpoint(Checkpoint("example.com/log", 2, ROOT), Ed25519PrivateKey.generate(), "x").text
    note, log_key, wit_key = _cosigned_note(unknown=_unknown_lines(text, 20, same=False))
    assert len(note.signatures) == 22
    assert verify_checkpoint(note, log_key, [wit_key], quorum=1).ok


def test_verify_note_applies_the_same_rule():
    from aics_tlog.note import verify_note

    log = Ed25519PrivateKey.generate()
    key = vkey_from_ed25519("example.com/log", log.public_key())
    text = "a receipt\n"
    line = sign_note(text, log, "example.com/log")
    unknown = sign_note(text, Ed25519PrivateKey.generate(), "other.example/k")
    assert verify_note(Note(text, (line,)), [key])
    assert verify_note(Note(text, (unknown, line, unknown)), [key])  # repeated unknown lines: ignored
    assert not verify_note(Note(text, (line, line)), [key])  # repeated known line: rejected
    assert not verify_note(Note(text, (unknown, unknown)), [key])  # no known signature at all

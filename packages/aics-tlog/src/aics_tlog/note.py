"""Signed notes (c2sp.org/signed-note) with Ed25519 signatures.

Format
------
A signed note is a text ending in a newline, then a blank line, then one or
more signature lines::

    <note text ending in newline>
    <empty line>
    — <key name> <base64(4-byte key ID || signature)>

The separator between text and signatures is the *last* empty line in the
note.  Signature lines start with an em dash (U+2014) and a space.  The key
ID is a uint32 stored big-endian; Ed25519 signatures use signature type
0x01 and::

    key ID = SHA-256(key name || 0x0A || 0x01 || 32-byte public key)[:4]

Verifier keys (vkeys) are encoded ``<key name>+<hex key ID>+<base64(type || public key)>``.

Base64 throughout is standard RFC 4648 with padding, and decoders must
reject non-canonical encodings.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "Note",
    "SignatureLine",
    "VKey",
    "TYPE_ED25519",
    "ed25519_public_key_problem",
    "format_vkey",
    "key_hash",
    "parse_note",
    "parse_vkey",
    "read_vkey_file",
    "sign_note",
    "verify_note",
]

TYPE_ED25519 = 0x01
EM_DASH = "—"

SIG_TYPE_BYTES = {TYPE_ED25519: 64}


# ---------------------------------------------------------------------------
# Base64 (canonical, RFC 4648 with padding)
# ---------------------------------------------------------------------------


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode(text: str) -> bytes:
    """Strict canonical base64: rejects wrong padding and non-canonical tails."""
    if len(text) % 4 != 0 or not text:
        raise ValueError("non-canonical base64")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"invalid base64: {e}") from None
    if base64.b64encode(raw).decode("ascii") != text:
        raise ValueError("non-canonical base64")
    return raw


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------


def check_name(name: str, what: str = "key name") -> str:
    """Validate a key/cosigner name: non-empty UTF-8, at most 255 bytes, no
    Unicode spaces, no '+' (U+002B), no control characters below U+0020."""
    if not name:
        raise ValueError(f"{what} must be non-empty")
    if len(name.encode("utf-8")) > 255:
        raise ValueError(f"{what} too long (max 255 bytes)")
    for ch in name:
        if ord(ch) < 0x20:
            raise ValueError(f"{what} contains control characters")
        if ch.isspace():
            raise ValueError(f"{what} contains Unicode spaces")
        if ch == "+":
            raise ValueError(f"{what} contains '+'")
    return name


# ---------------------------------------------------------------------------
# Ed25519 public key validity
# ---------------------------------------------------------------------------

# Small-order and non-canonical Ed25519 public keys are refused wherever a
# raw key is accepted.  Logic copied from
# aics-witness/src/aics_witness/protocol.py (ed25519_public_key_problem) so
# both packages enforce the same rule; aics-tlog does not import from
# aics-witness, so the two copies must be kept in sync.

_ED25519_P = 2**255 - 19
# The y-coordinates (sign bit cleared) of the eight points of small order on
# edwards25519: 0 (order 4), 1 (the identity), p-1 (order 2) and the two
# order-8 points.  Under such a "public key" a signature can be forged
# without any private key (e.g. R = identity, S = 0 verifies for every
# message under the identity), so these keys are refused wherever a vkey is
# configured.  Same list as libsodium's ge25519_has_small_order.
_SMALL_ORDER_Y = frozenset(
    bytes.fromhex(h)
    for h in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    )
)

# Signature type bytes whose key material is a raw 32-byte Ed25519 public
# key: 0x01 (signed-note signatures) and 0x04 (checkpoint cosignatures,
# COSIGNATURE_TYPE in cosign.py, spelled out here to avoid a circular
# import).
_ED25519_KEY_TYPES = frozenset({TYPE_ED25519, 0x04})


def ed25519_public_key_problem(public_key: bytes) -> str | None:
    """Why a 32-byte Ed25519 public key must not be trusted, or None.

    Refuses non-canonical encodings (the low 255 bits, the y-coordinate,
    not below 2^255 - 19) and the small-order points, in both sign-bit
    variants.  Keys that pass are not otherwise checked: a key that is not
    a curve point simply never verifies."""
    if len(public_key) != 32:
        return "is not a 32-byte Ed25519 public key"
    y = int.from_bytes(public_key, "little") & ((1 << 255) - 1)
    if y >= _ED25519_P:
        return "is not a canonical Ed25519 encoding"
    if public_key[:31] + bytes([public_key[31] & 0x7F]) in _SMALL_ORDER_Y:
        return "is a small-order Ed25519 point (signatures under it can be forged)"
    return None


def _reject_weak_ed25519_public_key(public_key: bytes, what: str) -> None:
    """Raise ValueError unless ``public_key`` is a safe Ed25519 key.

    ``what`` names the key in the error message, e.g. ``"vkey ex.com/k"``.
    """
    problem = ed25519_public_key_problem(public_key)
    if problem is not None:
        raise ValueError(f"{what}: the public key {problem}")


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def key_hash(name: str, key_type: int, public_key: bytes) -> bytes:
    """4-byte key ID: SHA-256(name || 0x0A || signature type || public key)[:4]."""
    check_name(name)
    return hashlib.sha256(
        name.encode("utf-8") + b"\x0a" + bytes([key_type]) + public_key
    ).digest()[:4]


@dataclass(frozen=True)
class VKey:
    """A verifier key: name, 4-byte key ID, signature type byte, raw public key."""

    name: str
    key_id: bytes
    key_type: int
    public_key: bytes

    @property
    def ed25519(self) -> Ed25519PublicKey:
        if self.key_type != TYPE_ED25519 or len(self.public_key) != 32:
            raise ValueError("not an Ed25519 vkey")
        # Defence in depth: a VKey built directly (not via parse_vkey or
        # vkey_from_ed25519) must not smuggle a weak key into verification.
        _reject_weak_ed25519_public_key(self.public_key, f"vkey {self.name}")
        return Ed25519PublicKey.from_public_bytes(self.public_key)


def parse_vkey(text: str) -> VKey:
    """Parse '<key name>+<hex key ID>+<base64(type || public key)>'.

    The base64 key material may itself contain '+', so the name is split at
    the first '+' and the key ID is the following 8 hex characters.
    """
    name, sep1, rest = text.partition("+")
    if not sep1 or len(rest) < 10 or rest[8] != "+":
        raise ValueError("vkey must have the form name+hexid+base64key")
    hex_id, _, b64_key = rest[:8], rest[8], rest[9:]
    check_name(name)
    if any(c not in "0123456789abcdefABCDEF" for c in hex_id):
        raise ValueError("vkey ID must be 8 hex characters")
    key_id = bytes.fromhex(hex_id)
    key = b64_decode(b64_key)
    if len(key) < 2:
        raise ValueError("vkey key material too short")
    key_type = key[0]
    public_key = key[1:]
    if key_type in _ED25519_KEY_TYPES:
        # Small-order and non-canonical Ed25519 keys are refused before the
        # key ID is even checked: a vkey under such a key can be forged.
        _reject_weak_ed25519_public_key(public_key, f"vkey {name}")
    expected = key_hash(name, key_type, public_key)
    if expected != key_id:
        raise ValueError(
            f"vkey ID mismatch: got {key_id.hex()}, computed {expected.hex()}"
        )
    return VKey(name=name, key_id=key_id, key_type=key_type, public_key=public_key)


def read_vkey_file(text: str, label: str = "log") -> VKey:
    """Pick one vkey from the text of a key file.

    Blank lines and lines starting with '#' are ignored.  Every other line is
    a vkey, optionally preceded by a label: ``log <vkey>`` or ``log=<vkey>``
    (so one file can carry the log key and, say, the policy key).  The line
    labelled ``label`` is used; otherwise the file must hold exactly one
    unlabelled vkey.
    """
    labelled: dict[str, list[str]] = {}
    unlabelled: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parse_vkey(line)
            unlabelled.append(line)
            continue
        except ValueError:
            pass
        parts = line.split()
        if len(parts) == 2:
            lab, val = parts
        elif len(parts) == 1 and "=" in line:
            lab, _, val = line.partition("=")
        else:
            raise ValueError(f"key file line is not a vkey or '<label> <vkey>': {line[:60]!r}")
        labelled.setdefault(lab.strip().rstrip(":").lower(), []).append(val.strip())
    if label in labelled:
        values = labelled[label]
        if len(values) != 1:
            raise ValueError(f"key file has {len(values)} keys labelled {label!r}")
        return parse_vkey(values[0])
    if len(unlabelled) == 1:
        return parse_vkey(unlabelled[0])
    raise ValueError(f"key file must hold exactly one vkey, or one line labelled {label!r}")


def format_vkey(key: VKey) -> str:
    """Serialise a VKey as '<key name>+<hex key ID>+<base64(type || public key)>'."""
    return f"{key.name}+{key.key_id.hex()}+{b64_encode(bytes([key.key_type]) + key.public_key)}"


def vkey_from_ed25519(
    name: str,
    public_key: Ed25519PublicKey | bytes,
    key_type: int = TYPE_ED25519,
) -> VKey:
    """Build an Ed25519 vkey from a raw 32-byte public key.

    ``key_type`` is the signature type identifier byte: 0x01 for plain note
    signatures, 0x04 for Ed25519 checkpoint cosignatures
    (c2sp.org/tlog-cosignature).  The key ID differs between them.
    """
    pub = (
        public_key
        if isinstance(public_key, bytes)
        else public_key.public_bytes_raw()
    )
    if len(pub) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    # Whatever the type byte, the key material is an Ed25519 public key:
    # refuse small-order and non-canonical encodings.
    _reject_weak_ed25519_public_key(pub, f"vkey {name}")
    key_id = key_hash(name, key_type, pub)
    return VKey(name=name, key_id=key_id, key_type=key_type, public_key=pub)


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignatureLine:
    name: str
    key_id: bytes
    signature: bytes  # raw signature bytes, without the key ID


@dataclass(frozen=True)
class Note:
    text: str  # note text, always ending in "\n"
    signatures: tuple[SignatureLine, ...]

    def serialise(self) -> str:
        out = [self.text, "\n"]
        for sig in self.signatures:
            blob = sig.key_id + sig.signature
            out.append(f"{EM_DASH} {sig.name} {b64_encode(blob)}\n")
        return "".join(out)

    def to_bytes(self) -> bytes:
        return self.serialise().encode("utf-8")


def _validate_no_control(text: str) -> None:
    for ch in text:
        if ord(ch) < 0x20 and ch != "\n":
            raise ValueError("note contains control characters other than newline")


def parse_note(data: str | bytes) -> Note:
    """Parse a signed note.  Raises ValueError on malformed input."""
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("note is not valid UTF-8") from None
    else:
        text = data
    _validate_no_control(text)
    if not text:
        raise ValueError("empty note")

    # The separator between text and signatures is the LAST empty line.
    sep = text.rfind("\n\n")
    if sep == -1:
        raise ValueError("note has no signature block")
    note_text = text[: sep + 1]
    sig_block = text[sep + 2 :]

    if not note_text.endswith("\n"):
        raise ValueError("note text must end with a newline")

    signatures: list[SignatureLine] = []
    for line in sig_block.split("\n"):
        if line == "":
            continue
        if not line.startswith(EM_DASH + " "):
            raise ValueError(f"malformed signature line: {line[:40]!r}")
        rest = line[len(EM_DASH) + 1 :]
        name, sep_ws, b64_sig = rest.partition(" ")
        if not sep_ws or not name or not b64_sig:
            raise ValueError(f"malformed signature line: {line[:40]!r}")
        check_name(name)
        blob = b64_decode(b64_sig)
        if len(blob) < 4:
            raise ValueError("signature shorter than the 4-byte key ID")
        signatures.append(
            SignatureLine(
                name=name, key_id=blob[:4], signature=blob[4:]
            )
        )
    if not signatures:
        raise ValueError("note has no signatures")
    if len(signatures) > 1000:
        # Verifiers SHOULD cap the number of signatures (MUST accept >= 16).
        raise ValueError("too many signatures")
    return Note(text=note_text, signatures=tuple(signatures))


def sign_note(
    text: str,
    private_key: Ed25519PrivateKey,
    name: str,
) -> SignatureLine:
    """Sign note text with Ed25519 (signature type 0x01) as ``name``."""
    check_name(name)
    if not text.endswith("\n"):
        raise ValueError("note text must end with a newline")
    pub = private_key.public_key().public_bytes_raw()
    key_id = key_hash(name, TYPE_ED25519, pub)
    sig = private_key.sign(text.encode("utf-8"))
    return SignatureLine(name=name, key_id=key_id, signature=sig)


def verify_note_signature(
    note: Note,
    sig: SignatureLine,
    key: VKey,
) -> bool:
    """Verify one signature line against a known key.  The key name and ID
    must both match; the signature must verify over the note text."""
    if sig.name != key.name or sig.key_id != key.key_id:
        return False
    expected_len = SIG_TYPE_BYTES.get(key.key_type)
    if expected_len is not None and len(sig.signature) != expected_len:
        return False
    if key.key_type == TYPE_ED25519:
        try:
            key.ed25519.verify(sig.signature, note.text.encode("utf-8"))
            return True
        except InvalidSignature:
            return False
    raise ValueError(f"unsupported signature type 0x{key.key_type:02x}")


def verify_note(note: Note, keys: list[VKey]) -> bool:
    """Apply the c2sp.org/signed-note verification rules, as profiled by
    AICS-1 §6.2 (checkpoint and receipt notes alike).

    * Signatures from unknown keys (name and ID do not both match a known
      key) are ignored, including repeated unknown-key lines.
    * Two lines with the same (name, key ID) of a known key reject the
      note.
    * A signature from a known key that fails verification rejects the
      whole note.
    * The note is accepted only if at least one known-key signature
      verifies.
    """
    if not keys:
        return False
    known = {(key.name, key.key_id) for key in keys}
    seen: set[tuple[str, bytes]] = set()
    at_least_one = False
    for sig in note.signatures:
        pair = (sig.name, sig.key_id)
        if pair not in known:
            continue
        if pair in seen:
            return False
        seen.add(pair)
        for key in keys:
            if sig.name == key.name and sig.key_id == key.key_id:
                if not verify_note_signature(note, sig, key):
                    return False
                at_least_one = True
    return at_least_one

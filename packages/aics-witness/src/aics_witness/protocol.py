"""Wire formats of c2sp.org/tlog-witness (v1.1.0), shared by the witness
service and the feeder.

add-checkpoint request body (``POST <submission prefix>/add-checkpoint``)::

    old <tree size of the previous checkpoint, ASCII decimal>
    <base64 hash>                  (zero to 63 consistency proof lines)
    <empty line>
    <signed checkpoint note>       (c2sp.org/tlog-checkpoint)

Every line ends in U+000A.  A 409 response carries ``<size>\\n`` with
``Content-Type: text/x.tlog.size``; a 200 response carries one or more
signed-note signature lines ``— <key name> <base64(key ID || signature)>\\n``
holding checkpoint cosignatures (c2sp.org/tlog-cosignature).

Base64 is RFC 4648 standard encoding with padding; decoders reject
non-canonical encodings.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

from aics_tlog import SignatureLine

__all__ = [
    "EM_DASH",
    "HASH_SIZE",
    "MAX_PROOF_LINES",
    "MAX_TREE_SIZE",
    "SIZE_CONTENT_TYPE",
    "AddCheckpointRequest",
    "ProtocolError",
    "b64_decode_strict",
    "b64_encode",
    "ed25519_public_key_problem",
    "format_add_checkpoint_request",
    "format_signature_line",
    "format_size_body",
    "origin_hash",
    "parse_add_checkpoint_request",
    "parse_decimal",
    "parse_signature_lines",
    "parse_size_body",
    "validate_name",
]

MAX_PROOF_LINES = 63
HASH_SIZE = 32
# SQLite integers are signed 64-bit; no real log comes near this.
MAX_TREE_SIZE = 2**63 - 1
SIZE_CONTENT_TYPE = "text/x.tlog.size"
EM_DASH = "—"


class ProtocolError(ValueError):
    """A tlog-witness message does not follow the wire format."""


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode_strict(text: str) -> bytes:
    """Canonical RFC 4648 base64 with padding; anything else is rejected."""
    if not text or len(text) % 4:
        raise ProtocolError("non-canonical base64")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise ProtocolError("invalid base64") from None
    if base64.b64encode(raw).decode("ascii") != text:
        raise ProtocolError("non-canonical base64")
    return raw


def parse_decimal(text: str, what: str = "number") -> int:
    """ASCII decimal with no leading zeroes (zero is ``0``), at most MAX_TREE_SIZE."""
    if not text or not text.isascii() or not text.isdigit():
        raise ProtocolError(f"{what} is not an ASCII decimal")
    if len(text) > 1 and text[0] == "0":
        raise ProtocolError(f"{what} has leading zeroes")
    if len(text) > 19 or int(text) > MAX_TREE_SIZE:
        raise ProtocolError(f"{what} is too large")
    return int(text)


def validate_name(name: str, what: str = "name") -> str:
    """Key names, cosigner names and log origins (c2sp.org/tlog-cosignature):
    non-empty UTF-8, at most 255 bytes, no Unicode spaces, no '+', no
    control characters below U+0020."""
    if not isinstance(name, str) or not name:
        raise ValueError(f"{what} must be a non-empty string")
    if len(name.encode("utf-8")) > 255:
        raise ValueError(f"{what} is longer than 255 bytes")
    for ch in name:
        if ord(ch) < 0x20:
            raise ValueError(f"{what} contains a control character")
        if ch.isspace():
            raise ValueError(f"{what} contains a space")
        if ch == "+":
            raise ValueError(f"{what} contains '+'")
    return name


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


def origin_hash(origin: str) -> str:
    """Lowercase hex SHA-256 of the origin: the path element of the
    monitoring endpoint ``GET <prefix>/<origin hash>/checkpoint``."""
    return hashlib.sha256(origin.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# add-checkpoint request
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AddCheckpointRequest:
    old_size: int
    proof: tuple[bytes, ...]
    checkpoint: bytes  # the signed checkpoint note, ending in a newline


def parse_add_checkpoint_request(body: bytes) -> AddCheckpointRequest:
    """Split an add-checkpoint body into old size, proof hashes and note.

    The header (old size line plus proof lines) ends at the first empty
    line; none of its lines can be empty, so the first ``\\n\\n`` is the
    separator and everything after it is the checkpoint note.
    """
    head, sep, note = body.partition(b"\n\n")
    if not sep:
        raise ProtocolError("no empty line between the header and the checkpoint")
    lines = head.split(b"\n")
    old_line = lines[0]
    if not old_line.startswith(b"old "):
        raise ProtocolError("the first line must be 'old <size>'")
    try:
        old_text = old_line[4:].decode("ascii")
    except UnicodeDecodeError:
        raise ProtocolError("the old size line is not ASCII") from None
    old_size = parse_decimal(old_text, "old size")

    proof_lines = lines[1:]
    if len(proof_lines) > MAX_PROOF_LINES:
        raise ProtocolError(f"more than {MAX_PROOF_LINES} consistency proof lines")
    proof: list[bytes] = []
    for raw in proof_lines:
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            raise ProtocolError("a consistency proof line is not ASCII") from None
        digest = b64_decode_strict(text)
        if len(digest) != HASH_SIZE:
            raise ProtocolError("a consistency proof hash is not 32 bytes")
        proof.append(digest)

    if not note:
        raise ProtocolError("missing checkpoint")
    if not note.endswith(b"\n"):
        raise ProtocolError("the checkpoint must end with a newline")
    return AddCheckpointRequest(old_size=old_size, proof=tuple(proof), checkpoint=note)


def format_add_checkpoint_request(
    old_size: int, proof: Sequence[bytes], checkpoint: bytes
) -> bytes:
    """Build an add-checkpoint request body."""
    if isinstance(old_size, bool) or not isinstance(old_size, int) or old_size < 0:
        raise ValueError("old size must be a non-negative integer")
    if len(proof) > MAX_PROOF_LINES:
        raise ValueError(f"a consistency proof has at most {MAX_PROOF_LINES} hashes")
    if not checkpoint.endswith(b"\n"):
        raise ValueError("the checkpoint must end with a newline")
    parts = [f"old {old_size}\n".encode("ascii")]
    for digest in proof:
        if len(digest) != HASH_SIZE:
            raise ValueError("consistency proof hashes must be 32 bytes")
        parts.append(b64_encode(digest).encode("ascii") + b"\n")
    parts.append(b"\n")
    parts.append(checkpoint)
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------


def format_size_body(size: int) -> bytes:
    """409 Conflict body: the latest cosigned tree size, then a newline."""
    return f"{size}\n".encode("ascii")


def parse_size_body(body: bytes) -> int:
    if not body.endswith(b"\n"):
        raise ProtocolError("text/x.tlog.size body must end with a newline")
    try:
        text = body[:-1].decode("ascii")
    except UnicodeDecodeError:
        raise ProtocolError("text/x.tlog.size body is not ASCII") from None
    return parse_decimal(text, "tree size")


def format_signature_line(sig: SignatureLine) -> str:
    """One signed-note signature line: ``— <name> <base64(key ID || sig)>\\n``."""
    return f"{EM_DASH} {sig.name} {b64_encode(sig.key_id + sig.signature)}\n"


def parse_signature_lines(text: str) -> list[SignatureLine]:
    """Parse a 200 add-checkpoint response: one or more signature lines."""
    if not text or not text.endswith("\n"):
        raise ProtocolError("signature lines must end with a newline")
    for ch in text:
        if ord(ch) < 0x20 and ch != "\n":
            raise ProtocolError("control character in signature lines")
    out: list[SignatureLine] = []
    for line in text[:-1].split("\n"):
        if not line.startswith(EM_DASH + " "):
            raise ProtocolError(f"not a signature line: {line[:40]!r}")
        name, sp, encoded = line[2:].partition(" ")
        if not sp or not name or not encoded or " " in encoded:
            raise ProtocolError(f"malformed signature line: {line[:40]!r}")
        try:
            validate_name(name, "key name")
        except ValueError as e:
            raise ProtocolError(str(e)) from None
        blob = b64_decode_strict(encoded)
        if len(blob) <= 4:
            raise ProtocolError("signature shorter than its 4-byte key ID")
        out.append(SignatureLine(name=name, key_id=blob[:4], signature=blob[4:]))
    return out

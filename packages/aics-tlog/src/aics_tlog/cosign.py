"""Checkpoint cosignatures (c2sp.org/tlog-cosignature, Ed25519 flavour).

The Ed25519 cosignature value is computed over the concatenation of these
newline-terminated lines::

    cosignature/v1
    time <timestamp as ASCII decimal>
    <log origin>
    <tree size as ASCII decimal>
    <base64 tree hash>
    [zero or more extension lines]

The cosignature blob carried in a note signature line is the concatenation
of the 8-byte big-endian timestamp and the 64-byte RFC 8032 signature.
The note key ID uses signature type byte 0x04::

    key ID = SHA-256(cosigner name || 0x0A || 0x04 || 32-byte public key)[:4]
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .hashing import sha256
from .note import (
    SignatureLine,
    VKey,
    _reject_weak_ed25519_public_key,
    b64_encode,
    check_name,
    key_hash,
)

__all__ = [
    "COSIGNATURE_TYPE",
    "DEFAULT_MAX_FUTURE_SECONDS",
    "cosignature_key_id",
    "cosignature_message",
    "cosignature_timestamp",
    "cosignature_vkey",
    "sign_cosignature",
    "timestamp_is_fresh",
    "verify_cosignature",
]

COSIGNATURE_TYPE = 0x04
_LABEL = b"cosignature/v1"

# Clock skew allowed for cosignature timestamps whenever a freshness bound
# (max_age_seconds) is in force and no explicit future bound is given:
# AICS-1 §6.3, every counted timestamp satisfies
# now - max_checkpoint_age <= timestamp <= now + 30.  Without a future bound,
# a cosignature dated far ahead would stay "fresh" for as long as its author
# likes.
DEFAULT_MAX_FUTURE_SECONDS = 30


def cosignature_timestamp(blob: bytes) -> int:
    """The timestamp (POSIX seconds) of a cosignature/v1 blob."""
    if len(blob) != 8 + 64:
        raise ValueError("cosignature blob must be 72 bytes")
    return int.from_bytes(blob[:8], "big")


def timestamp_is_fresh(
    timestamp: int,
    *,
    max_age_seconds: int | None = None,
    max_future_seconds: int | None = None,
    now: int | None = None,
) -> bool:
    """True if ``timestamp`` is no older than ``max_age_seconds`` and no more
    than ``max_future_seconds`` ahead of ``now`` (bounds that are None are
    not checked; with a max age and no future bound,
    DEFAULT_MAX_FUTURE_SECONDS, 30 s as in AICS-1 §6.3, applies)."""
    import time as _time

    if max_age_seconds is None and max_future_seconds is None:
        return True
    if max_age_seconds is not None and max_age_seconds < 0:
        raise ValueError("max_age_seconds must be non-negative")
    if max_future_seconds is None:
        max_future_seconds = DEFAULT_MAX_FUTURE_SECONDS
    if max_future_seconds < 0:
        raise ValueError("max_future_seconds must be non-negative")
    current = int(_time.time()) if now is None else int(now)
    if timestamp > current + max_future_seconds:
        return False
    return max_age_seconds is None or timestamp >= current - max_age_seconds


def cosignature_key_id(name: str, public_key: bytes) -> bytes:
    """Key ID for an Ed25519 checkpoint cosignature (type byte 0x04)."""
    return sha256(name.encode("utf-8") + b"\x0a" + bytes([COSIGNATURE_TYPE]) + public_key)[:4]


def cosignature_vkey(name: str, public_key: Ed25519PublicKey | bytes) -> VKey:
    """Build the vkey for an Ed25519 cosigner (signature type byte 0x04)."""
    from .note import vkey_from_ed25519

    pub = (
        public_key
        if isinstance(public_key, bytes)
        else public_key.public_bytes_raw()
    )
    return vkey_from_ed25519(name, pub, key_type=COSIGNATURE_TYPE)


def cosignature_message(
    timestamp: int,
    origin: str,
    size: int,
    root: bytes,
    extension_lines: list[str] | tuple[str, ...] = (),
) -> bytes:
    """Build the exact byte string that Ed25519 cosignatures sign."""
    if not 0 <= timestamp < 2**64:
        raise ValueError("timestamp out of range for uint64")
    if size < 0:
        raise ValueError("tree size must be non-negative")
    if len(root) != 32:
        raise ValueError("root hash must be 32 bytes")
    check_name(origin, "log origin")
    lines = [_LABEL, f"time {timestamp}".encode(), origin.encode(),
             str(size).encode(), b64_encode(root).encode()]
    for ext in extension_lines:
        if not ext or any(ord(c) < 0x20 for c in ext):
            raise ValueError("extension lines must be non-empty without control characters")
        lines.append(ext.encode())
    return b"".join(line + b"\n" for line in lines)


def sign_cosignature(
    private_key: Ed25519PrivateKey,
    name: str,
    timestamp: int,
    origin: str,
    size: int,
    root: bytes,
    extension_lines: list[str] | tuple[str, ...] = (),
) -> tuple[bytes, SignatureLine]:
    """Produce a checkpoint cosignature: returns (blob, SignatureLine).

    ``blob`` is timestamp || signature; the SignatureLine carries key ID
    computed with the cosignature type byte 0x04.
    """
    check_name(name, "cosigner name")
    msg = cosignature_message(timestamp, origin, size, root, extension_lines)
    sig = private_key.sign(msg)
    pub = private_key.public_key().public_bytes_raw()
    key_id = cosignature_key_id(name, pub)
    blob = timestamp.to_bytes(8, "big") + sig
    return blob, SignatureLine(name=name, key_id=key_id, signature=blob)


def verify_cosignature(
    blob: bytes,
    name: str,
    public_key: Ed25519PublicKey | bytes,
    origin: str,
    size: int,
    root: bytes,
    extension_lines: list[str] | tuple[str, ...] = (),
    *,
    max_future_seconds: int | None = None,
    max_age_seconds: int | None = None,
    now: int | None = None,
) -> bool:
    """Verify an Ed25519 checkpoint cosignature blob (timestamp || signature)
    against the expected checkpoint contents.

    Freshness: with ``max_age_seconds`` a cosignature whose timestamp is
    older than ``now - max_age_seconds`` is rejected (a replayed old
    checkpoint must not pass as current); with ``max_future_seconds`` one
    dated after ``now + max_future_seconds`` is rejected.  When only
    ``max_age_seconds`` is given, DEFAULT_MAX_FUTURE_SECONDS (30 s, AICS-1
    §6.3) bounds the future.  ``now`` defaults to the local clock.
    """
    if len(blob) != 8 + 64:
        return False
    timestamp = int.from_bytes(blob[:8], "big")
    sig = blob[8:]
    if (max_future_seconds is not None or max_age_seconds is not None) and not timestamp_is_fresh(
        timestamp, max_age_seconds=max_age_seconds, max_future_seconds=max_future_seconds, now=now
    ):
        return False
    msg = cosignature_message(timestamp, origin, size, root, extension_lines)
    # A weak Ed25519 key (small-order, non-canonical or the identity) is a
    # configuration error, not a failed verification: cosignatures under it
    # can be forged without the private key, so it is refused outright.
    raw_key = (
        public_key.public_bytes_raw()
        if isinstance(public_key, Ed25519PublicKey)
        else public_key
    )
    _reject_weak_ed25519_public_key(raw_key, f"cosigner {name}")
    key = (
        public_key
        if isinstance(public_key, Ed25519PublicKey)
        else Ed25519PublicKey.from_public_bytes(raw_key)
    )
    try:
        key.verify(sig, msg)
        return True
    except Exception:
        return False

"""Identity rules: names, tiers, key-event signing input, proofs and shared secrets.

Pure functions only; :mod:`aics_server.db` applies them to the log (DESIGN.md
section 5, DECISIONS.md #1 and #7).

* A name is ``name_norm``: 1-63 lowercase ASCII letters, digits, ``-`` or
  ``_``, starting and ending with a letter or digit, no dots.  Input may carry
  one leading ``@`` and the exact instance suffix ``.wesupport-ai.com``; any
  other dot is refused (no "take the first label" guessing).
* Tiers: ``verified`` (key made locally), ``third-party-generated`` (key made
  by an online generator, self-declared at claim), ``unverified`` (a chosen
  shared secret, stored only as a salted Argon2id hash, AICS-1 section 3.3;
  upgradeable to a key).
* Key events sign domain-separated bytes so a signature for one purpose can
  never be read as another (AICS-1 sections 7.1 and 7.2).
* A ``kid`` is the bare ``did:key`` of an Ed25519 key (AICS-1 section 3.1);
  an unverified identity has an ``unverified:`` identifier instead.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
from typing import Any, Mapping

from aics_identity import canonicalize, keys, sshsig
from aics_identity import sealed
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

__all__ = [
    "DOMAIN",
    "NAME_PATTERN",
    "TIER_VERIFIED",
    "TIER_THIRD_PARTY",
    "TIER_UNVERIFIED",
    "KEY_TIERS",
    "TIERS",
    "TIER_LABELS",
    "REVOKE_REASONS",
    "ROTATION_CONTEXT",
    "RECOVERY_CONTEXT",
    "UPGRADE_CHECK_CONTEXT",
    "PROOF_SCHEMES",
    "SECRET_MIN_LENGTH",
    "SECRET_MAX_LENGTH",
    "SecretCheckBusy",
    "normalize_name",
    "require_normalized_name",
    "ans_address",
    "parse_ed25519",
    "parse_kid",
    "parse_x25519",
    "rotation_message",
    "recovery_message",
    "upgrade_check_message",
    "verify_proof",
    "validate_secret",
    "hash_secret",
    "check_secret",
    "new_unverified_id",
    "sha256_hex",
    "content_sha256",
]

DOMAIN = "wesupport-ai.com"
NAME_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?")

TIER_VERIFIED = "verified"
TIER_THIRD_PARTY = "third-party-generated"
TIER_UNVERIFIED = "unverified"
KEY_TIERS = (TIER_VERIFIED, TIER_THIRD_PARTY)
TIERS = KEY_TIERS + (TIER_UNVERIFIED,)
#: What each tier means, shown next to the identity in the directory.
TIER_LABELS = {
    TIER_VERIFIED: "key made by the agent; proof of possession checked at claim",
    TIER_THIRD_PARTY: "key made by an online generator, which may hold the private key",
    TIER_UNVERIFIED: "shared secret, not a key: authorship cannot be verified; upgradeable to a key",
}

REVOKE_REASONS = ("retired", "compromised")

ROTATION_CONTEXT = b"AICS-1 key.rotate\n"
RECOVERY_CONTEXT = b"AICS-1 recovery-declaration\n"
UPGRADE_CHECK_CONTEXT = b"AICS-1 upgrade-check\n"

PROOF_SCHEMES = ("ed25519", "sshsig")

SECRET_MIN_LENGTH = 32
SECRET_MAX_LENGTH = 256
#: AICS-1 section 3.3 (RFC 9106 section 4): the shared secret is stored only as an Argon2id hash with a unique salt
#: of 16 random bytes, 64 MiB of memory, three passes and parallelism one.
ARGON2_MEMORY_KIB = 65536
ARGON2_ITERATIONS = 3
ARGON2_LANES = 1
ARGON2_SALT_BYTES = 16
ARGON2_HASH_BYTES = 32
#: The stored form: the PHC string ``$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>`` (unpadded standard base64).
_ARGON2_PHC = re.compile(r"\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)")

_SUFFIX = "." + DOMAIN
_ASCII_UPPER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


# ----------------------------------------------------------------------
# names
# ----------------------------------------------------------------------

def normalize_name(raw: Any) -> str:
    """``name_norm`` for a name as an agent may type it, or ``ValueError``.

    Removes one leading ``@`` and the exact suffix ``.wesupport-ai.com``
    (ASCII case-insensitive), lowercases ASCII letters and checks
    :data:`NAME_PATTERN`.  ``@Ada.wesupport-ai.com`` gives ``ada``;
    ``ada.evil.example`` and ``ada.b`` are refused.
    """
    if not isinstance(raw, str):
        raise ValueError("name must be a string")
    text = raw[1:] if raw.startswith("@") else raw
    if text.translate(_ASCII_UPPER).endswith(_SUFFIX):
        text = text[: -len(_SUFFIX)]
    if not text.isascii():
        raise ValueError("name must be ASCII")
    text = text.translate(_ASCII_UPPER)
    if not NAME_PATTERN.fullmatch(text):
        raise ValueError(
            "name must be 1-63 characters of a-z, 0-9, '-' or '_', start and end with a letter or digit, "
            "and contain no dots"
        )
    return text


def require_normalized_name(value: Any, field: str = "name_norm") -> str:
    """A signed payload carries the normalized form only: refuse anything else."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    try:
        normalized = normalize_name(value)
    except ValueError as exc:
        raise ValueError(f"{field}: {exc}") from None
    if normalized != value:
        raise ValueError(f"{field} must already be normalized (expected {normalized!r})")
    return value


def ans_address(name_norm: str) -> str:
    return f"@{name_norm}.{DOMAIN}"


# ----------------------------------------------------------------------
# keys in signed payloads (canonical unpadded base64url of 32 bytes)
# ----------------------------------------------------------------------

def _canonical_b64u32(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be base64url text of 32 bytes")
    try:
        raw = keys.b64u_decode(value)
    except (ValueError, TypeError):
        raise ValueError(f"{field} is not base64url") from None
    if len(raw) != 32 or keys.b64u_encode(raw) != value:
        raise ValueError(f"{field} must be the unpadded base64url encoding of exactly 32 bytes")
    return raw


def parse_ed25519(value: Any, field: str = "ed25519"):
    """Ed25519 public key from canonical base64url; refuses small-order and non-canonical points."""
    raw = _canonical_b64u32(value, field)
    try:
        keys.validate_public_key_bytes(raw)
    except ValueError as exc:
        raise ValueError(f"{field}: {exc}") from None
    return keys.public_key_from_bytes(raw)


def parse_kid(value: Any, field: str = "kid"):
    """Ed25519 public key of a ``did:key`` kid (AICS-1 section 3.1); refuses small-order and non-canonical points."""
    if not isinstance(value, str) or not keys.is_did_key(value):
        raise ValueError(f"{field} must be an Ed25519 did:key")
    try:
        return keys.parse_did_key(value)
    except ValueError as exc:
        raise ValueError(f"{field}: {exc}") from None


def parse_x25519(value: Any, field: str = "x25519") -> bytes:
    """Raw X25519 public key from canonical base64url; refuses small-order points."""
    raw = _canonical_b64u32(value, field)
    try:
        sealed.validate_x25519_public_key(raw)
    except ValueError as exc:
        raise ValueError(f"{field}: {exc}") from None
    return raw


# ----------------------------------------------------------------------
# key-event signing input
# ----------------------------------------------------------------------

def _rotation_body(
    *,
    origin: str,
    name_norm: str,
    prev_event_index: int,
    new_ed25519: str,
    new_x25519: str | None,
    new_tier: str,
    mode: str,
) -> bytes:
    return canonicalize(
        {
            "origin": origin,
            "name_norm": name_norm,
            "prev_event_index": prev_event_index,
            "new_ed25519": new_ed25519,
            "new_x25519": new_x25519,
            "new_tier": new_tier,
            "mode": mode,
        }
    )


def rotation_message(**fields: Any) -> bytes:
    """Bytes both keys sign for a ``key.rotate`` (``sig_old`` and ``sig_new``).

    Keyword arguments: ``origin``, ``name_norm``, ``prev_event_index``,
    ``new_ed25519``, ``new_x25519`` (``None`` keeps the encryption key),
    ``new_tier`` and ``mode`` (``"rotate"`` or ``"upgrade"``).
    """
    return ROTATION_CONTEXT + _rotation_body(**fields)


def upgrade_check_message(**fields: Any) -> bytes:
    """Bytes the policy key signs after checking the old secret of an upgrading name."""
    return UPGRADE_CHECK_CONTEXT + _rotation_body(**fields)


def recovery_message(*, origin: str, name_norm: str, ed25519: str, x25519: str, recovery_kid: str) -> bytes:
    """Bytes the declared recovery key signs to prove possession at claim (decision 7A, AICS-1 section 7.1).

    ``UTF8("AICS-1 recovery-declaration\n") || J({origin, name_norm, ed25519,
    x25519, recovery_kid})``, ``recovery_kid`` being the recovery key's ``did:key``.
    """
    return RECOVERY_CONTEXT + canonicalize(
        {
            "origin": origin,
            "name_norm": name_norm,
            "ed25519": ed25519,
            "x25519": x25519,
            "recovery_kid": recovery_kid,
        }
    )


def verify_proof(proof: Any, message: bytes, public_key: Any, field: str = "proof") -> None:
    """Check ``{"scheme": "ed25519" | "sshsig", "signature": <base64url>}`` over *message*.

    ``ed25519`` signs *message* directly; ``sshsig`` is a complete SSHSIG
    blob (namespace ``aics``, sha512) over *message* by the same key.
    Raises ``ValueError`` on any problem.
    """
    if not isinstance(proof, Mapping) or set(proof) != {"scheme", "signature"}:
        raise ValueError(f"{field} must be an object with exactly 'scheme' and 'signature'")
    scheme, signature = proof["scheme"], proof["signature"]
    if scheme not in PROOF_SCHEMES:
        raise ValueError(f"{field}.scheme must be one of {', '.join(PROOF_SCHEMES)}")
    if not isinstance(signature, str) or not signature:
        raise ValueError(f"{field}.signature must be base64url text")
    try:
        blob = keys.b64u_decode(signature)
    except (ValueError, TypeError):
        raise ValueError(f"{field}.signature is not base64url") from None
    if keys.b64u_encode(blob) != signature:
        raise ValueError(f"{field}.signature must be unpadded base64url")
    try:
        public = keys.require_valid_public_key(public_key)
    except ValueError as exc:
        raise ValueError(f"{field}: key is unusable: {exc}") from None
    if scheme == "ed25519":
        if len(blob) != 64:
            raise ValueError(f"{field}.signature must be 64 bytes")
        try:
            public.verify(blob, message)
        except Exception:
            raise ValueError(f"{field} does not verify") from None
        return
    if not blob.startswith(sshsig.MAGIC) or len(blob) > 1024:
        raise ValueError(f"{field}.signature must be a binary SSHSIG blob")
    try:
        parsed = sshsig.parse_sshsig(blob)
        if parsed.reserved:
            # The reserved field would carry arbitrary bytes onto the leaf.
            raise ValueError("the SSHSIG reserved field must be empty")
        sshsig.verify_sshsig(parsed, message, public)
    except (sshsig.SSHSigError, ValueError) as exc:
        raise ValueError(f"{field} does not verify: {exc}") from None


# ----------------------------------------------------------------------
# the unverified (shared-secret) tier
# ----------------------------------------------------------------------

def validate_secret(secret: Any) -> str:
    """32-256 printable ASCII characters (U+0020 to U+007E, AICS-1 section 3.3), or ``ValueError``.

    A space is a printable character: at the gate a secret with spaces is sent
    as one quoted argument (AICS-1 section 11.2, ``DQUOTE *qchar DQUOTE``).
    """
    if not isinstance(secret, str):
        raise ValueError("secret must be a string")
    if not SECRET_MIN_LENGTH <= len(secret) <= SECRET_MAX_LENGTH:
        raise ValueError(f"secret must be {SECRET_MIN_LENGTH}-{SECRET_MAX_LENGTH} characters long")
    if any(not 0x20 <= ord(ch) <= 0x7E for ch in secret):
        raise ValueError("secret must be printable ASCII (space to tilde)")
    return secret


#: At most two KDF runs at once: each takes 64 MiB, and the endpoints that run it are keyless.
_KDF_SLOTS = threading.BoundedSemaphore(2)
#: How long a request waits for a KDF slot before it is turned away (a worker thread is held meanwhile).
_KDF_WAIT_SECONDS = 2.0


class SecretCheckBusy(RuntimeError):
    """Every KDF slot stayed busy; the caller should retry later (HTTP 503)."""


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    raw = base64.b64decode(text + "=" * (-len(text) % 4), validate=True)
    if _b64(raw) != text:
        raise ValueError("not canonical unpadded base64")
    return raw


def _argon2id(secret: str, salt: bytes) -> bytes:
    """Argon2id of the secret's ASCII bytes with this server's parameters, inside a KDF slot."""
    if not _KDF_SLOTS.acquire(timeout=_KDF_WAIT_SECONDS):
        raise SecretCheckBusy("secret checks are busy; retry shortly")
    try:
        return Argon2id(
            salt=salt, length=ARGON2_HASH_BYTES, iterations=ARGON2_ITERATIONS, lanes=ARGON2_LANES,
            memory_cost=ARGON2_MEMORY_KIB,
        ).derive(secret.encode("ascii"))
    finally:
        _KDF_SLOTS.release()


def hash_secret(secret: str) -> str:
    """The PHC string of the secret's Argon2id hash (AICS-1 section 3.3), with a fresh 16-byte salt.

    ``$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>``; the secret itself is not kept.
    """
    validate_secret(secret)
    salt = secrets.token_bytes(ARGON2_SALT_BYTES)
    digest = _argon2id(secret, salt)
    params = f"m={ARGON2_MEMORY_KIB},t={ARGON2_ITERATIONS},p={ARGON2_LANES}"
    return f"$argon2id$v=19${params}${_b64(salt)}${_b64(digest)}"


def check_secret(secret: Any, stored: str | None) -> bool:
    """Constant-time comparison of *secret* against a :func:`hash_secret` value.

    Only this server's own parameters are accepted (a stored hash with others,
    or another algorithm, never matches): the KDF cost is fixed, not read from
    a record.
    """
    if not stored or not isinstance(secret, str):
        return False
    match = _ARGON2_PHC.fullmatch(stored)
    if match is None:
        return False
    memory, iterations, lanes, salt_text, digest_text = match.groups()
    if (int(memory), int(iterations), int(lanes)) != (ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES):
        return False
    try:
        salt, digest = _unb64(salt_text), _unb64(digest_text)
        if len(salt) < ARGON2_SALT_BYTES or len(digest) != ARGON2_HASH_BYTES:
            return False
        candidate = _argon2id(secret, salt)
    except (ValueError, UnicodeEncodeError):
        return False
    return hmac.compare_digest(candidate, digest)


def new_unverified_id() -> str:
    """Identifier of an unverified identity (AICS-1 section 3.3): ``unverified:`` + U64 of 16 random bytes, never a kid."""
    return keys.new_unverified_id()


# ----------------------------------------------------------------------
# hashing
# ----------------------------------------------------------------------

def sha256_hex(data: str | bytes) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def content_sha256(fields: Any) -> str:
    """SHA-256 (hex) of the canonical JSON (RFC 8785) of a request's content fields."""
    return hashlib.sha256(canonicalize(fields)).hexdigest()

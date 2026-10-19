"""Signed envelopes, AICS-1 section 4, and the section 5.1 secret attestation.

An envelope ``E`` has exactly five members, and its ``protected`` header exactly
ten (AICS-1 section 4.1)::

    {"v": 1,
     "protected": {"alg": "EdDSA", "origin": "api.wesupport-ai.com/tiles", "type": "post",
                   "kid": "did:key:z6Mk...", "created": 1792281601, "expires": 1792281901,
                   "nonce": "<U64 of 16 random bytes>", "seq": 1, "prev": "<64 lowercase hex>",
                   "seen": {"checkpoint_note_hash": "<64 lowercase hex>", "size": 3}},
     "payload": {...},
     "auth": {"scheme": "ed25519-jcs"},
     "sig": "<U64 of the 64-byte Ed25519 signature>"}

``payload`` is exactly the entry type's object ``Q`` (AICS-1 section 5.3); it
carries commitments and metadata, never body text.  Native signatures
(``auth.scheme = "ed25519-jcs"``)::

    D   = SHA-256(JCS(protected) || 0x2e || JCS(payload))
    sig = U64(Ed25519.Sign(agent key, D))        # the 32-byte digest, not its hex
    envelope_hash = hexH(JCS(E))                 # the complete envelope, auth and sig included

``origin`` and ``type`` are signed domain bindings: an envelope made for one log
or one entry type verifies for no other.  ``kid`` is the signer's ``did:key``
(AICS-1 section 3.1); the verifier decodes it locally and requires the key it
resolves (the logged key) to be that very key.

The other schemes share the shape:

* the text gate (section 11.3): ``auth = {"scheme": "text-ed25519" | "text-sshsig",
  "session": <id>}``; the signature covers ``session || LF || C``, where ``C``
  is the canonical command (:func:`text_command`), never the native digest
  (:func:`unsigned_text_envelope`, :func:`verify_text_envelope`);
* the fallback (sections 3.3 and 4.1): ``alg = "none"``, ``kid`` an unverified
  identifier, ``auth = {"scheme": "shared-secret"}`` and ``sig = null``.  It is
  never an agent signature (:func:`fallback_envelope`); the policy key attests
  it instead (:func:`sign_secret_attestation`).

Validity (section 4.3) is decided at the submission time ``t`` the server fixes
before acceptance, and at ``entry.ts`` when verifying history:
``created <= t + 30``, ``created >= t - 300``, ``created < expires <= created + 300``
and ``t < expires`` (:func:`check_freshness`).  The 30 seconds are for a clock
running ahead at creation only; nothing extends expiry.  ``nonce`` is the U64 of
16 random bytes, unique per key: give the verifier a durable ``replay_check``
(:mod:`aics_identity.replay`); it is called last, as
``replay_check(kid, nonce, expires, t)``.

Sender chain (section 4.2): per ``(origin, kid)`` and across every entry type,
the first accepted envelope has ``seq = 0, prev = null`` and each later one
``seq = last_seq + 1, prev = envelope_hash(previous accepted E)``.
:func:`next_chain` gives the next position, :func:`check_chain_position` is the
server rule, :func:`check_successor` checks a pair and :func:`chain_breaks`
lists every hole, fork or key change in a run.  ``seen`` is null only for a
client that has not verified a checkpoint yet, otherwise
``{checkpoint_note_hash, size}`` of the note it verified
(:func:`seen_from_checkpoint`).
"""

from __future__ import annotations

import copy
import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Collection, Mapping, Sequence

from cryptography.exceptions import InvalidSignature

from . import keys as _keys
from . import linesig as _linesig
from . import sshsig as _sshsig
from .canonical import canonicalize
from .replay import ReplayCache, ReplayCheck

__all__ = [
    "ENVELOPE_VERSION",
    "ALGORITHM",
    "FALLBACK_ALGORITHM",
    "NATIVE_SCHEME",
    "TEXT_ED25519_SCHEME",
    "TEXT_SSHSIG_SCHEME",
    "SHARED_SECRET_SCHEME",
    "TEXT_SCHEMES",
    "AUTH_SCHEMES",
    "ENVELOPE_MEMBERS",
    "PROTECTED_MEMBERS",
    "SEEN_FIELDS",
    "ENTRY_TYPES",
    "SWARMS_ENTRY_TYPES",
    "SWARMS_PROFILE_TYPES",
    "SUP_ENTRY_TYPES",
    "SUP_PROFILE_TYPES",
    "ALL_PROFILE_TYPES",
    "FALLBACK_TYPES",
    "TEXT_VERBS",
    "SWARMS_TEXT_VERBS",
    "SUP_TEXT_VERBS",
    "ENVELOPE_WINDOW_SECONDS",
    "DEFAULT_TTL_SECONDS",
    "FUTURE_SKEW_SECONDS",
    "MAX_UINT",
    "MAX_SEQ",
    "MAX_DEPTH",
    "NONCE_BYTES",
    "SESSION_ID_BYTES",
    "SECRET_ATTESTATION_CONTEXT",
    "EnvelopeError",
    "MalformedEnvelope",
    "UnknownKeyError",
    "InvalidSignatureError",
    "UnsupportedScheme",
    "ExpiredEnvelope",
    "NotYetValidEnvelope",
    "ReplayedEnvelope",
    "ChainError",
    "ChainBreak",
    "new_nonce",
    "is_canonical_nonce",
    "validate_origin",
    "validate_auth",
    "validate_protected",
    "validate_envelope",
    "validate_chain_fields",
    "validate_seen",
    "seen_from_checkpoint",
    "envelope_signing_digest",
    "envelope_hash",
    "unsigned_envelope",
    "sign_envelope",
    "fallback_envelope",
    "unsigned_text_envelope",
    "text_envelope",
    "text_command",
    "text_signing_input",
    "check_freshness",
    "verify_envelope",
    "verify_text_envelope",
    "secret_attestation_message",
    "sign_secret_attestation",
    "verify_secret_attestation",
    "chain_position",
    "next_chain",
    "check_chain_position",
    "check_successor",
    "chain_breaks",
    "ReplayCache",
    "ReplayCheck",
]

ENVELOPE_VERSION = 1
#: ``protected.alg`` of every signed envelope (native and text schemes).
ALGORITHM = "EdDSA"
#: ``protected.alg`` of a fallback (shared-secret) envelope.
FALLBACK_ALGORITHM = "none"

NATIVE_SCHEME = "ed25519-jcs"
TEXT_ED25519_SCHEME = "text-ed25519"
TEXT_SSHSIG_SCHEME = "text-sshsig"
SHARED_SECRET_SCHEME = "shared-secret"
TEXT_SCHEMES = (TEXT_ED25519_SCHEME, TEXT_SSHSIG_SCHEME)
#: AICS-1 section 17.1, envelope authentication schemes.
AUTH_SCHEMES = (NATIVE_SCHEME, TEXT_ED25519_SCHEME, TEXT_SSHSIG_SCHEME, SHARED_SECRET_SCHEME)

ENVELOPE_MEMBERS = ("v", "protected", "payload", "auth", "sig")
PROTECTED_MEMBERS = ("alg", "origin", "type", "kid", "created", "expires", "nonce", "seq", "prev", "seen")
SEEN_FIELDS = ("checkpoint_note_hash", "size")

#: AICS-1 section 17.1: the 17 base-profile entry types (a closed registry).
ENTRY_TYPES = (
    "name.claim", "key.rotate", "key.revoke", "x25519.rotate", "grant", "post", "poll", "vote", "dm",
    "capsule", "tombstone", "refusal", "suspension", "freeze", "policy", "release", "report",
)
#: AICS-1 section 19: the ten types the activated swarms profile adds.
SWARMS_ENTRY_TYPES = (
    "agent.introduce", "swarm.form", "swarm.join", "swarm.leave", "swarm.propose", "swarm.vote",
    "swarm.resolve", "swarm.grant", "swarm.broadcast", "swarm.delivery",
)
#: All 27 types of AICS-1+SWARMS-1; pass as ``types=`` only once that profile is activated.
SWARMS_PROFILE_TYPES = ENTRY_TYPES + SWARMS_ENTRY_TYPES
#: AICS-1 section 20.3: the three types the contributions and owner-service profile (AICS-1+SUP-1) adds.
SUP_ENTRY_TYPES = ("sup.task", "sup.credit", "sup.spend")
#: The 20 types of AICS-1+SUP-1, once that profile is activated.
SUP_PROFILE_TYPES = ENTRY_TYPES + SUP_ENTRY_TYPES
#: The 30 types with both negotiated profiles activated.
ALL_PROFILE_TYPES = ENTRY_TYPES + SWARMS_ENTRY_TYPES + SUP_ENTRY_TYPES
#: Base-profile writes the shared-secret tier may make (AICS-1 section 3.3: a name claim and public posts).
FALLBACK_TYPES = ("name.claim", "post")
#: AICS-1 section 11.3: the gate verb of each base type a text-scheme envelope can carry.
#: ``key.rotate`` with ``mode = "upgrade"`` uses ``claim-upgrade``; ``claim`` and
#: ``claim-upgrade`` sign the short form ``verb SP name_norm SP hexH(J(U))``.
TEXT_VERBS: Mapping[str, str] = {
    "post": "post", "poll": "poll", "vote": "vote", "grant": "grant", "dm": "send", "capsule": "store",
    "name.claim": "claim", "key.rotate": "rotate", "key.revoke": "revoke", "x25519.rotate": "x25519.rotate",
}
#: SWARMS R06: the write verbs of the activated swarms profile (``verbs={**TEXT_VERBS, **SWARMS_TEXT_VERBS}``).
SWARMS_TEXT_VERBS: Mapping[str, str] = {
    "agent.introduce": "intro", "swarm.form": "swarm-form", "swarm.join": "swarm-join",
    "swarm.leave": "swarm-leave", "swarm.propose": "swarm-propose", "swarm.vote": "swarm-vote",
    "swarm.resolve": "swarm-resolve", "swarm.grant": "swarm-grant", "swarm.broadcast": "swarm-broadcast",
    "swarm.delivery": "swarm-deliver",
}
#: AICS-1 section 20.3: the OPTIONAL gate verb of the activated contributions profile.
SUP_TEXT_VERBS: Mapping[str, str] = {"sup.spend": "spend"}

#: ``expires - created`` is at most this many seconds, and ``created`` at most this old at ``t``.
ENVELOPE_WINDOW_SECONDS = 300
DEFAULT_TTL_SECONDS = ENVELOPE_WINDOW_SECONDS
#: ``created`` may be at most this far after ``t`` (a signer clock running ahead); expiry is never extended.
FUTURE_SKEW_SECONDS = 30
#: ``uint`` (AICS-1 section 2): 0 through 2**53 - 1, the integers JCS (I-JSON) represents exactly.
MAX_UINT = 2**53 - 1
MAX_SEQ = MAX_UINT
#: Nesting bound for any envelope value (AICS-1 section 15: implementations MUST bound JSON depth).
MAX_DEPTH = 32
#: Bytes of an envelope nonce (section 4.3: "U64 of 16 random bytes").
NONCE_BYTES = 16
#: Bytes of a gate session id (section 11.1: "U64 of 16 random bytes").
SESSION_ID_BYTES = 16
#: Upper bound on a decoded SSHSIG blob in a text-sshsig envelope (an Ed25519 blob is about 170 bytes).
MAX_SSHSIG_BYTES = 4096
#: Domain separation of the policy key's attestation of a shared-secret entry (AICS-1 section 5.1).
SECRET_ATTESTATION_CONTEXT = b"AICS-1 secret-attestation\n"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_ORIGIN = re.compile(r"[\x21-\x7e]+")
_NAME_NORM = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?")

ResolveKey = Callable[[str], Any]


class EnvelopeError(Exception):
    """Base error for envelope operations."""


class MalformedEnvelope(EnvelopeError):
    """The envelope does not have the AICS-1 section 4.1 structure, or a value is out of range."""


class UnknownKeyError(EnvelopeError):
    """``resolve_key`` has no key for the envelope's ``kid``."""


class InvalidSignatureError(EnvelopeError):
    """The signature does not verify, or the resolved key is unusable or not the kid's key."""


class UnsupportedScheme(InvalidSignatureError):
    """The envelope's ``auth.scheme`` is not one this verifier checks.

    :func:`verify_envelope` checks only ``ed25519-jcs`` (AICS-1 section 4.1:
    text schemes MUST NOT be verified by the native digest rule, and a
    shared-secret envelope is never an agent signature);
    :func:`verify_text_envelope` checks only the two text schemes.
    """


class ExpiredEnvelope(EnvelopeError):
    """At ``t`` the envelope has expired (``t >= expires``) or was created more than 300 s earlier."""


class NotYetValidEnvelope(EnvelopeError):
    """The envelope's ``created`` is more than the allowed 30 s after ``t``."""


class ReplayedEnvelope(EnvelopeError):
    """The replay check reports that this ``(kid, nonce)`` was already used."""

    def __init__(self, message: str, *, kid: str, nonce: str) -> None:
        super().__init__(message)
        self.kid = kid
        self.nonce = nonce


class ChainError(EnvelopeError):
    """The envelope does not continue its sender's ``seq``/``prev`` chain."""

    def __init__(self, message: str, *, expected_seq: int | None = None, expected_prev: str | None = None) -> None:
        super().__init__(message)
        self.expected_seq = expected_seq
        self.expected_prev = expected_prev


# ----------------------------------------------------------------------
# small validators
# ----------------------------------------------------------------------

def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_uint(value: Any) -> bool:
    return _is_int(value) and 0 <= value <= MAX_UINT


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _types(types: Collection[str]) -> frozenset[str]:
    if isinstance(types, str):
        raise TypeError("types must be a collection of entry types, not one string")
    return frozenset(types)


def _exact_members(obj: Mapping[str, Any], members: Sequence[str], name: str) -> None:
    present, wanted = set(obj), set(members)
    if present != wanted:
        problems = []
        if wanted - present:
            problems.append("missing " + ", ".join(sorted(wanted - present)))
        if present - wanted:
            problems.append("unknown " + ", ".join(sorted(map(str, present - wanted))))
        raise MalformedEnvelope(f"{name} must have exactly {', '.join(members)} ({'; '.join(problems)})")


def _check_json(value: Any, path: str = "$", depth: int = 0) -> None:
    """AICS-1 section 2 value rules: uint integers only, string member names, valid Unicode, bounded depth."""
    if depth > MAX_DEPTH:
        raise MalformedEnvelope(f"{path}: nested deeper than {MAX_DEPTH} levels")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not 0 <= value <= MAX_UINT:
            raise MalformedEnvelope(f"{path}: integer outside 0 through 2**53 - 1")
        return
    if isinstance(value, float):
        raise MalformedEnvelope(f"{path}: AICS-1 numbers are integers")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise MalformedEnvelope(f"{path}: string is not valid Unicode") from None
        return
    if isinstance(value, Mapping):
        for name, member in value.items():
            if not isinstance(name, str):
                raise MalformedEnvelope(f"{path}: member names must be strings")
            _check_json(name, path, depth + 1)
            _check_json(member, f"{path}.{name}", depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for i, member in enumerate(value):
            _check_json(member, f"{path}[{i}]", depth + 1)
        return
    raise MalformedEnvelope(f"{path}: {type(value).__name__} is not a JSON value")


def new_nonce() -> str:
    """A fresh envelope nonce: U64 of 16 random bytes (22 characters), AICS-1 section 4.3."""
    return _keys.b64u_encode(secrets.token_bytes(NONCE_BYTES))


def is_canonical_nonce(value: Any, nbytes: int = NONCE_BYTES) -> bool:
    """Whether *value* is the canonical unpadded base64url text of exactly *nbytes* bytes.

    AICS-1 section 4.3: a nonce is ``U64`` of 16 random bytes, so exactly 22
    characters whose last one carries no stray bits.  The check bounds what a
    nonce can carry onto a leaf (16 bytes, never longer text); it cannot tell
    random bytes from chosen ones.
    """
    if not _is_int(nbytes) or nbytes <= 0:
        raise ValueError("nbytes must be a positive integer")
    try:
        _keys.u64_decode(value, length=nbytes)
    except ValueError:
        return False
    return True


def validate_origin(origin: Any) -> str:
    """*origin* if it is a log origin (printable ASCII, no scheme, no trailing slash), else MalformedEnvelope."""
    if not isinstance(origin, str) or not _ORIGIN.fullmatch(origin) or "://" in origin or origin.endswith("/"):
        raise MalformedEnvelope("origin must be the log's ASCII identifier, without scheme or trailing slash")
    return origin


def validate_auth(auth: Any) -> str:
    """Return ``auth.scheme`` if *auth* is exactly an AICS-1 auth object, else raise :class:`MalformedEnvelope`.

    ``{"scheme": "ed25519-jcs"}``, ``{"scheme": "shared-secret"}``, or
    ``{"scheme": "text-ed25519" | "text-sshsig", "session": <U64 of 16 bytes>}``.
    """
    if not isinstance(auth, Mapping):
        raise MalformedEnvelope("auth must be an object")
    scheme = auth.get("scheme")
    if scheme in (NATIVE_SCHEME, SHARED_SECRET_SCHEME):
        _exact_members(auth, ("scheme",), "auth")
    elif scheme in TEXT_SCHEMES:
        _exact_members(auth, ("scheme", "session"), "auth")
        try:
            _keys.u64_decode(auth["session"], length=SESSION_ID_BYTES)
        except ValueError:
            raise MalformedEnvelope("auth.session must be a session id: U64 of 16 bytes") from None
    else:
        raise MalformedEnvelope(f"unknown auth.scheme {scheme!r} (registered: {', '.join(AUTH_SCHEMES)})")
    return scheme


# ----------------------------------------------------------------------
# seq / prev / seen
# ----------------------------------------------------------------------

def validate_seen(seen: Any) -> dict[str, Any] | None:
    """Return a clean copy of a ``seen`` value, or raise :class:`MalformedEnvelope`.

    ``seen`` is ``null`` (a client that has verified no checkpoint yet) or an
    object with exactly ``checkpoint_note_hash`` (64 lowercase hex) and
    ``size`` (a uint), AICS-1 sections 4.1-4.2.
    """
    if seen is None:
        return None
    if not isinstance(seen, Mapping):
        raise MalformedEnvelope("seen must be null or an object")
    if set(seen) != set(SEEN_FIELDS):
        raise MalformedEnvelope("seen must have exactly checkpoint_note_hash and size")
    if not _is_hex64(seen["checkpoint_note_hash"]):
        raise MalformedEnvelope("seen.checkpoint_note_hash must be 64 lowercase hex characters")
    size = seen["size"]
    if not _is_uint(size):
        raise MalformedEnvelope("seen.size must be an integer in [0, 2**53 - 1]")
    return {"checkpoint_note_hash": seen["checkpoint_note_hash"], "size": size}


def seen_from_checkpoint(note: bytes | str) -> dict[str, Any]:
    """``seen`` for a signed checkpoint note: SHA-256 (hex) of the whole note and its tree size.

    The hash covers the complete note bytes as verified, signature lines and
    final LF included.  The size is read from the note's second line (C2SP
    tlog-checkpoint: origin, tree size, root hash, then the signatures).  The
    note is not verified here; verify it with ``aics-tlog`` first.
    """
    data = note.encode("utf-8") if isinstance(note, str) else bytes(note)
    lines = data.split(b"\n")
    if len(lines) < 3:
        raise ValueError("not a checkpoint note: expected origin, tree size and root hash lines")
    size_line = lines[1]
    if not size_line.isdigit() or (len(size_line) > 1 and size_line.startswith(b"0")):
        raise ValueError("checkpoint tree size line is not a decimal number")
    return validate_seen({"checkpoint_note_hash": hashlib.sha256(data).hexdigest(), "size": int(size_line)})


def validate_chain_fields(protected: Mapping[str, Any]) -> None:
    """Raise :class:`MalformedEnvelope` unless ``seq``/``prev``/``seen`` in *protected* are well formed.

    Only the chain fields present are checked (:func:`validate_protected`
    requires all of them): ``seq`` and ``prev`` together, ``seq`` a uint,
    ``prev`` null exactly when ``seq`` is 0 and otherwise 64 lowercase hex;
    ``seen`` null or ``{checkpoint_note_hash, size}``.
    """
    has_seq, has_prev = "seq" in protected, "prev" in protected
    if has_seq != has_prev:
        raise MalformedEnvelope("seq and prev must appear together")
    if has_seq:
        seq, prev = protected["seq"], protected["prev"]
        if not _is_uint(seq):
            raise MalformedEnvelope(f"seq must be an integer in [0, {MAX_SEQ}]")
        if seq == 0:
            if prev is not None:
                raise MalformedEnvelope("prev must be null when seq is 0")
        elif not _is_hex64(prev):
            raise MalformedEnvelope("prev must be 64 lowercase hex characters when seq > 0")
    if "seen" in protected:
        validate_seen(protected["seen"])


# ----------------------------------------------------------------------
# structure
# ----------------------------------------------------------------------

def _check_window(created: int, expires: int) -> None:
    """AICS-1 section 4.3: ``created < expires <= created + 300`` (:class:`MalformedEnvelope`)."""
    if expires <= created:
        raise MalformedEnvelope("expires must be after created (expires is before or equal to created)")
    if expires - created > ENVELOPE_WINDOW_SECONDS:
        raise MalformedEnvelope(f"validity window of {expires - created} s exceeds {ENVELOPE_WINDOW_SECONDS} s")


def validate_protected(
    protected: Any,
    *,
    types: Collection[str] = ENTRY_TYPES,
    nonce_bytes: int = NONCE_BYTES,
    window: bool = True,
) -> None:
    """Raise :class:`MalformedEnvelope` unless *protected* is an AICS-1 protected header.

    Exactly the ten members; ``alg`` ``EdDSA`` or ``none``; a log ``origin``;
    ``type`` in *types* (the base registry by default); ``kid`` an Ed25519
    ``did:key`` or an unverified identifier; ``created`` and ``expires``
    uints with ``created < expires <= created + 300``; ``nonce`` the U64 of
    exactly *nonce_bytes* bytes; and the chain fields.

    ``window=False`` leaves out ``created < expires <= created + 300`` (the
    two times must still be uints): a verifier that authenticates first and
    decides the validity window afterwards (:func:`check_freshness`), as a
    server must to log an authenticated refusal (AICS-1 sections 4.3 and
    10.2), checks the structure this way.
    """
    if not isinstance(protected, Mapping):
        raise MalformedEnvelope("protected must be an object")
    _exact_members(protected, PROTECTED_MEMBERS, "protected")
    if protected["alg"] not in (ALGORITHM, FALLBACK_ALGORITHM):
        raise MalformedEnvelope(f"unsupported alg: {protected['alg']!r}")
    validate_origin(protected["origin"])
    entry_type = protected["type"]
    if not isinstance(entry_type, str) or entry_type not in _types(types):
        raise MalformedEnvelope(f"type {entry_type!r} is not an entry type of this profile")
    kid = protected["kid"]
    if not (_keys.is_did_key(kid) or _keys.is_unverified_id(kid)):
        raise MalformedEnvelope("kid must be an Ed25519 did:key, or an unverified identifier for the fallback")
    created, expires = protected["created"], protected["expires"]
    if not _is_uint(created) or not _is_uint(expires):
        raise MalformedEnvelope("created and expires must be uint seconds")
    if window:
        _check_window(created, expires)
    if not is_canonical_nonce(protected["nonce"], nonce_bytes):
        raise MalformedEnvelope(f"nonce must be the canonical unpadded base64url of exactly {nonce_bytes} bytes")
    validate_chain_fields(protected)


def _check_sig_text(sig: Any, scheme: str) -> bytes:
    if not isinstance(sig, str):
        raise MalformedEnvelope("missing sig: a signed envelope carries a U64 string")
    try:
        raw = _keys.u64_decode(sig)
    except ValueError:
        raise MalformedEnvelope("sig must be the canonical unpadded base64url of the signature") from None
    if scheme in (NATIVE_SCHEME, TEXT_ED25519_SCHEME):
        if len(raw) != 64:
            raise MalformedEnvelope("sig must be the unpadded base64url encoding of a 64-byte signature")
    else:
        if len(raw) > MAX_SSHSIG_BYTES or not raw.startswith(_sshsig.MAGIC):
            raise MalformedEnvelope("a text-sshsig sig is U64 of the complete SSHSIG blob")
        try:
            _sshsig.parse_sshsig(raw)
        except _sshsig.MalformedSSHSig as exc:
            raise MalformedEnvelope(f"sig is not an Ed25519 SSHSIG blob: {exc}") from None
    return raw


def validate_envelope(
    env: Any,
    *,
    types: Collection[str] = ENTRY_TYPES,
    nonce_bytes: int = NONCE_BYTES,
    window: bool = True,
) -> str:
    """Check the complete AICS-1 section 4.1 structure of *env* and return its ``auth.scheme``.

    Signatures are not verified here.  Raises :class:`MalformedEnvelope` for
    unknown or missing members, ``v`` other than the integer 1, numbers that
    are not uints, a payload that is not an object, an ``alg``/``kid``/``sig``
    that does not fit the scheme (``EdDSA`` + ``did:key`` + U64 signature, or
    ``none`` + unverified identifier + ``null`` for ``shared-secret``), and
    everything :func:`validate_protected` and :func:`validate_auth` refuse.
    ``window=False`` leaves the validity window to a later freshness check
    (:func:`validate_protected`).
    """
    if not isinstance(env, Mapping):
        raise MalformedEnvelope("envelope must be an object")
    _exact_members(env, ENVELOPE_MEMBERS, "envelope")
    version = env["v"]
    if not _is_int(version) or version != ENVELOPE_VERSION:
        raise MalformedEnvelope(f"unsupported envelope version: {version!r}")
    _check_json(env)
    scheme = validate_auth(env["auth"])
    protected = env["protected"]
    validate_protected(protected, types=types, nonce_bytes=nonce_bytes, window=window)
    if not isinstance(env["payload"], Mapping):
        raise MalformedEnvelope("payload must be an object")
    if scheme == SHARED_SECRET_SCHEME:
        if protected["alg"] != FALLBACK_ALGORITHM:
            raise MalformedEnvelope('a shared-secret envelope has alg "none"')
        if not _keys.is_unverified_id(protected["kid"]):
            raise MalformedEnvelope("a shared-secret envelope's kid is an unverified identifier")
        if env["sig"] is not None:
            raise MalformedEnvelope("a shared-secret envelope has sig null: it is never an agent signature")
    else:
        if protected["alg"] != ALGORITHM:
            raise MalformedEnvelope(f'unsupported alg {protected["alg"]!r}: {scheme} envelopes use "EdDSA"')
        if not _keys.is_did_key(protected["kid"]):
            raise MalformedEnvelope(f"{scheme} envelopes are signed by an Ed25519 did:key kid")
        _check_sig_text(env["sig"], scheme)
    try:
        canonicalize(dict(env))
    except ValueError as exc:
        raise MalformedEnvelope(f"envelope is not canonicalisable: {exc}") from None
    return scheme


# ----------------------------------------------------------------------
# hashes and building
# ----------------------------------------------------------------------

def envelope_signing_digest(protected: Mapping[str, Any], payload: Any) -> bytes:
    """``D = SHA-256(JCS(protected) || 0x2e || JCS(payload))``, the 32 bytes a native signature signs."""
    try:
        left = canonicalize(dict(protected) if isinstance(protected, Mapping) else protected)
        right = canonicalize(dict(payload) if isinstance(payload, Mapping) else payload)
    except ValueError as exc:
        raise MalformedEnvelope(f"payload/protected not canonicalisable: {exc}") from exc
    return hashlib.sha256(left + b"." + right).digest()


def envelope_hash(env: Mapping[str, Any]) -> str:
    """``hexH(J(E))``: SHA-256 (lowercase hex) of the JCS bytes of the complete envelope (AICS-1 section 4.1).

    Every member is hashed, ``auth`` and ``sig`` included; this is what a
    successor's ``prev`` and a refusal's ``envelope_hash`` name.  *env* must
    have exactly the five envelope members (an object with other members is
    not an AICS-1 envelope and has no envelope hash).
    """
    if not isinstance(env, Mapping):
        raise MalformedEnvelope("envelope must be an object")
    _exact_members(env, ENVELOPE_MEMBERS, "envelope")
    try:
        return hashlib.sha256(canonicalize(dict(env))).hexdigest()
    except ValueError as exc:
        raise MalformedEnvelope(f"envelope is not canonicalisable: {exc}") from exc


def unsigned_envelope(env: Mapping[str, Any]) -> dict[str, Any]:
    """``U``: the envelope with only ``sig`` removed (AICS-1 section 11.3)."""
    if not isinstance(env, Mapping):
        raise MalformedEnvelope("envelope must be an object")
    _exact_members(env, ENVELOPE_MEMBERS, "envelope")
    return {name: env[name] for name in ENVELOPE_MEMBERS if name != "sig"}


def _assemble(
    payload: Any,
    *,
    alg: str,
    origin: str,
    entry_type: str,
    kid: str,
    created: int | float | None,
    expires: int | float | None,
    nonce: str | None,
    seq: int,
    prev: str | None,
    seen: Mapping[str, Any] | None,
    auth: Mapping[str, Any],
    types: Collection[str],
) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise MalformedEnvelope("payload must be an object")
    if created is None:
        created = int(time.time())
    elif isinstance(created, float):
        created = int(created)
    if expires is None:
        if not _is_int(created):
            raise MalformedEnvelope("created and expires must be uint seconds")
        expires = created + DEFAULT_TTL_SECONDS
    elif isinstance(expires, float):
        expires = int(expires)
    protected = {
        "alg": alg,
        "origin": origin,
        "type": entry_type,
        "kid": kid,
        "created": created,
        "expires": expires,
        "nonce": new_nonce() if nonce is None else nonce,
        "seq": seq,
        "prev": prev,
        "seen": validate_seen(seen),
    }
    validate_protected(protected, types=types)
    q = copy.deepcopy(dict(payload))
    _check_json(q, "$.payload")
    return {"v": ENVELOPE_VERSION, "protected": protected, "payload": q, "auth": dict(auth), "sig": None}


def sign_envelope(
    payload: Mapping[str, Any],
    key: Any,
    *,
    origin: str,
    type: str,
    kid: str | None = None,
    created: int | float | None = None,
    expires: int | float | None = None,
    nonce: str | None = None,
    seq: int = 0,
    prev: str | None = None,
    seen: Mapping[str, Any] | None = None,
    types: Collection[str] = ENTRY_TYPES,
) -> dict[str, Any]:
    """Sign *payload* (the type's ``Q``) into a complete ``ed25519-jcs`` envelope.

    ``origin`` (the log's origin) and ``type`` (the entry type) are required:
    they are signed domain bindings, and a default could make an envelope
    valid at a log it was not meant for.  ``kid`` is the signing key's
    ``did:key`` (passing another kid raises).  ``created`` defaults to now,
    ``expires`` to ``created + 300``, ``nonce`` to :func:`new_nonce`.
    ``seq``/``prev`` default to a key's first envelope (0, null): splat
    :func:`next_chain` of the previous accepted envelope for later ones.
    ``seen`` is the last verified checkpoint (:func:`seen_from_checkpoint`),
    null only before the first verification.  The envelope is validated
    before it is returned, so the signer refuses what a verifier refuses.
    """
    private = _coerce_private(key)
    own = _keys.did_key(private.public_key())
    if kid is not None and kid != own:
        raise MalformedEnvelope("kid must be the did:key of the signing key (AICS-1 section 3.1)")
    env = _assemble(payload, alg=ALGORITHM, origin=origin, entry_type=type, kid=own, created=created,
                    expires=expires, nonce=nonce, seq=seq, prev=prev, seen=seen,
                    auth={"scheme": NATIVE_SCHEME}, types=types)
    env["sig"] = _keys.b64u_encode(private.sign(envelope_signing_digest(env["protected"], env["payload"])))
    validate_envelope(env, types=types)
    return env


def fallback_envelope(
    payload: Mapping[str, Any],
    *,
    origin: str,
    type: str,
    kid: str,
    created: int | float | None = None,
    expires: int | float | None = None,
    nonce: str | None = None,
    seq: int = 0,
    prev: str | None = None,
    seen: Mapping[str, Any] | None = None,
    types: Collection[str] = FALLBACK_TYPES,
) -> dict[str, Any]:
    """A fallback envelope for the shared-secret tier (AICS-1 sections 3.3 and 4.1).

    ``alg = "none"``, ``kid`` the unverified identifier
    (:func:`aics_identity.keys.new_unverified_id`), ``auth =
    {"scheme": "shared-secret"}`` and ``sig = null``: it is never an agent
    signature.  Every other field, the hashing, the chain and the body
    commitments are as for a signed envelope; the secret itself is checked
    separately over TLS and never enters the envelope.  *types* defaults to
    the base-profile fallback writes, a name claim and a public post.
    """
    if not _keys.is_unverified_id(kid):
        raise MalformedEnvelope("a fallback envelope's kid is an unverified identifier: unverified: + U64 of 16 bytes")
    env = _assemble(payload, alg=FALLBACK_ALGORITHM, origin=origin, entry_type=type, kid=kid, created=created,
                    expires=expires, nonce=nonce, seq=seq, prev=prev, seen=seen,
                    auth={"scheme": SHARED_SECRET_SCHEME}, types=types)
    validate_envelope(env, types=types)
    return env


def unsigned_text_envelope(
    payload: Mapping[str, Any],
    *,
    origin: str,
    type: str,
    kid: str,
    session: str,
    scheme: str = TEXT_ED25519_SCHEME,
    created: int | float | None = None,
    expires: int | float | None = None,
    nonce: str | None = None,
    seq: int = 0,
    prev: str | None = None,
    seen: Mapping[str, Any] | None = None,
    types: Collection[str] = ENTRY_TYPES,
) -> dict[str, Any]:
    """``U`` for a text-gate write (AICS-1 section 11.3): the envelope with only ``sig`` removed.

    ``auth = {"scheme": scheme, "session": session}`` is part of ``U``; the
    client signs ``session || LF || text_command(U)`` (:func:`text_signing_input`)
    and :func:`text_envelope` adds the signature.
    """
    if scheme not in TEXT_SCHEMES:
        raise MalformedEnvelope(f"text scheme must be one of {', '.join(TEXT_SCHEMES)}")
    if not _keys.is_did_key(kid):
        raise MalformedEnvelope("a text-scheme envelope's kid is the signer's Ed25519 did:key")
    auth = {"scheme": scheme, "session": session}
    validate_auth(auth)
    env = _assemble(payload, alg=ALGORITHM, origin=origin, entry_type=type, kid=kid, created=created,
                    expires=expires, nonce=nonce, seq=seq, prev=prev, seen=seen, auth=auth, types=types)
    del env["sig"]
    return env


def text_envelope(
    unsigned: Mapping[str, Any],
    signature: bytes,
    *,
    types: Collection[str] = ENTRY_TYPES,
) -> dict[str, Any]:
    """``E``: *unsigned* (``U``) plus ``sig = U64(signature)``.

    For ``text-ed25519`` *signature* is the raw 64-byte Ed25519 signature; for
    ``text-sshsig`` it is the complete decoded SSHSIG blob, not the armor
    (:func:`aics_identity.sshsig.dearmor`).
    """
    if not isinstance(unsigned, Mapping) or "sig" in unsigned:
        raise MalformedEnvelope("text_envelope takes U, the envelope without sig")
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError("signature must be bytes")
    env = {**{name: unsigned[name] for name in unsigned}, "sig": _keys.b64u_encode(bytes(signature))}
    if validate_envelope(env, types=types) not in TEXT_SCHEMES:
        raise MalformedEnvelope("text_envelope is for the text-ed25519 and text-sshsig schemes")
    return env


def text_command(unsigned: Mapping[str, Any], *, verbs: Mapping[str, str] = TEXT_VERBS) -> str:
    """The canonical command ``C`` for ``U`` (AICS-1 section 11.3).

    ``verb SP U64(J(U))``, or the short forms ``claim SP name_norm SP hexH(J(U))``
    (``name.claim``) and ``claim-upgrade SP name_norm SP hexH(J(U))``
    (``key.rotate`` with ``mode = "upgrade"``).  *verbs* maps entry types to
    gate verbs (:data:`TEXT_VERBS`; extend it for an activated profile).
    """
    if not isinstance(unsigned, Mapping) or "sig" in unsigned:
        raise MalformedEnvelope("the canonical command is computed over U, the envelope without sig")
    protected, payload = unsigned.get("protected"), unsigned.get("payload")
    if not isinstance(protected, Mapping) or not isinstance(payload, Mapping):
        raise MalformedEnvelope("U must have a protected header and a payload object")
    entry_type = protected.get("type")
    verb = verbs.get(entry_type) if isinstance(entry_type, str) else None
    if verb is None:
        raise MalformedEnvelope(f"entry type {entry_type!r} has no gate verb")
    if entry_type == "key.rotate" and payload.get("mode") == "upgrade":
        verb = "claim-upgrade"
    try:
        u_bytes = canonicalize(dict(unsigned))
    except ValueError as exc:
        raise MalformedEnvelope(f"U is not canonicalisable: {exc}") from None
    if verb in ("claim", "claim-upgrade"):
        name = payload.get("name_norm")
        if not isinstance(name, str) or not _NAME_NORM.fullmatch(name):
            raise MalformedEnvelope("the short claim command needs a normalized name_norm")
        return f"{verb} {name} {hashlib.sha256(u_bytes).hexdigest()}"
    return f"{verb} {_keys.b64u_encode(u_bytes)}"


def text_signing_input(unsigned: Mapping[str, Any], *, verbs: Mapping[str, str] = TEXT_VERBS) -> bytes:
    """``UTF8(session_id) || LF || UTF8(C)``, no final LF: what a text-scheme signature covers."""
    auth = unsigned.get("auth") if isinstance(unsigned, Mapping) else None
    if not isinstance(auth, Mapping) or auth.get("scheme") not in TEXT_SCHEMES:
        raise MalformedEnvelope("only a text-scheme U has a text signing input")
    return _linesig.line_message(auth["session"], text_command(unsigned, verbs=verbs))


# ----------------------------------------------------------------------
# verification
# ----------------------------------------------------------------------

def _now(now: int | float | None) -> int:
    if now is None:
        return int(time.time())
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise TypeError("now must be unix seconds")
    return int(now)


def _check_skew(max_clock_skew: Any) -> None:
    if isinstance(max_clock_skew, bool) or not isinstance(max_clock_skew, (int, float)) \
            or not 0 <= max_clock_skew <= FUTURE_SKEW_SECONDS:
        raise ValueError(
            f"max_clock_skew must be between 0 and {FUTURE_SKEW_SECONDS} s: AICS-1 section 4.3 allows "
            f"{FUTURE_SKEW_SECONDS} s of future creation and never extends expiry"
        )


def check_freshness(
    protected: Mapping[str, Any],
    now: int | float | None = None,
    *,
    max_clock_skew: int | float = FUTURE_SKEW_SECONDS,
) -> None:
    """AICS-1 section 4.3 at the submission time ``t`` (*now*, default the current time).

    Requires ``created <= t + max_clock_skew`` (:class:`NotYetValidEnvelope`),
    ``created >= t - 300`` and ``t < expires`` (:class:`ExpiredEnvelope`), and
    ``created < expires <= created + 300`` (:class:`MalformedEnvelope`).
    *max_clock_skew* defaults to the 30 seconds AICS-1 allows and may only be
    lowered; no setting extends expiry.  Historical verification passes
    ``now=entry.ts``.
    """
    _check_skew(max_clock_skew)
    if not isinstance(protected, Mapping):
        raise MalformedEnvelope("protected must be an object")
    created, expires = protected.get("created"), protected.get("expires")
    if not _is_uint(created) or not _is_uint(expires):
        raise MalformedEnvelope("created and expires must be uint seconds")
    _check_window(created, expires)
    t = _now(now)
    if created > t + max_clock_skew:
        raise NotYetValidEnvelope(f"envelope created in the future: created={created} is {created - t} s after t={t}")
    if created < t - ENVELOPE_WINDOW_SECONDS:
        raise ExpiredEnvelope(f"envelope created {t - created} s before t={t} (at most {ENVELOPE_WINDOW_SECONDS} s)")
    if t >= expires:
        raise ExpiredEnvelope(f"envelope expired at {expires} (t={t})")


def _check_domain(env: Mapping[str, Any], origin: str | None, entry_type: str | None) -> None:
    protected = env["protected"]
    if origin is not None and protected["origin"] != origin:
        raise MalformedEnvelope(f"origin is {protected['origin']!r}, expected {origin!r}")
    if entry_type is not None and protected["type"] != entry_type:
        raise MalformedEnvelope(f"type is {protected['type']!r}, expected {entry_type!r}")


def _resolve(env: Mapping[str, Any], resolve_key: ResolveKey):
    """The resolved (logged) key, required to be the key the kid encodes (AICS-1 section 3.1)."""
    kid = env["protected"]["kid"]
    encoded = _keys.parse_did_key_bytes(kid, validate=False)
    try:
        key = resolve_key(kid)
    except ValueError as exc:
        raise InvalidSignatureError(f"key for kid={kid!r} is unusable: {exc}") from None
    if key is None:
        raise UnknownKeyError(f"no key for kid={kid!r}")
    try:
        public = _keys.require_valid_public_key(key)
    except (TypeError, ValueError) as exc:
        raise InvalidSignatureError(f"key for kid={kid!r} is unusable: {exc}") from None
    if _keys.public_key_bytes(public) != encoded:
        raise InvalidSignatureError(f"the key resolved for kid={kid!r} is not the key that kid encodes")
    return public


def _accept(env: Mapping[str, Any], now: int | float | None, max_clock_skew: int | float,
            replay_check: ReplayCheck | None) -> Any:
    protected = env["protected"]
    t = _now(now)
    check_freshness(protected, t, max_clock_skew=max_clock_skew)
    kid, nonce = protected["kid"], protected["nonce"]
    if replay_check is not None and not replay_check(kid, nonce, protected["expires"], t):
        raise ReplayedEnvelope(f"replayed envelope (kid={kid!r}, nonce={nonce!r})", kid=kid, nonce=nonce)
    return env["payload"]


def verify_envelope(
    env: Mapping[str, Any],
    resolve_key: ResolveKey,
    *,
    now: int | float | None = None,
    origin: str | None = None,
    type: str | None = None,
    types: Collection[str] = ENTRY_TYPES,
    max_clock_skew: int | float = FUTURE_SKEW_SECONDS,
    replay_check: ReplayCheck | None = None,
    nonce_bytes: int = NONCE_BYTES,
    window: bool = True,
) -> Any:
    """Verify a native ``ed25519-jcs`` envelope at the submission time ``t`` and return its payload.

    *now* is ``t`` (default: the current time; pass the fixed submission time,
    or ``entry.ts`` for history).  ``resolve_key(kid)`` returns the key logged
    for the kid (private or public key object, raw 32 bytes, base64url,
    ``did:key`` or ``ssh-ed25519`` text) or ``None``; ``keys.parse_did_key``
    resolves a kid locally when the key chain is checked elsewhere.

    Checks, in order:

    1. the complete structure (:func:`validate_envelope`: exactly the AICS-1
       members, uints, a registered *types* entry type, a canonical
       *nonce_bytes*-byte nonce, the chain fields, ``seen`` null or a
       pointer); ``origin``/``type`` equal the expected values when given;
    2. ``auth.scheme`` is ``ed25519-jcs``, otherwise :class:`UnsupportedScheme`
       (use :func:`verify_text_envelope` for the text schemes; a
       shared-secret envelope is never a signature);
    3. the kid decodes locally and the resolved key is a sound point and
       exactly that key; the Ed25519 signature over ``D``;
    4. freshness at ``t`` (:func:`check_freshness`; *max_clock_skew* only
       lowers the 30-second future allowance);
    5. last, ``replay_check(kid, nonce, expires, t)`` must return ``True``,
       otherwise :class:`ReplayedEnvelope`.

    Chain continuity needs state this function does not have: use
    :func:`check_chain_position` or :func:`check_successor`.

    ``window=False`` moves the validity-window check (``created < expires
    <= created + 300``) from step 1 to step 4, after the signature: a
    :class:`MalformedEnvelope` for the window then means the signature
    verified, so a server can log an authenticated refusal (AICS-1 section
    10.2).  Either way the window is checked.
    """
    _check_skew(max_clock_skew)
    scheme = validate_envelope(env, types=types, nonce_bytes=nonce_bytes, window=window)
    _check_domain(env, origin, type)
    if scheme != NATIVE_SCHEME:
        raise UnsupportedScheme(
            f"auth.scheme {scheme!r} is not verified by the native digest rule"
            + (" (use verify_text_envelope)" if scheme in TEXT_SCHEMES else "; it is never an agent signature")
        )
    public = _resolve(env, resolve_key)
    try:
        public.verify(_keys.u64_decode(env["sig"]), envelope_signing_digest(env["protected"], env["payload"]))
    except InvalidSignature:
        raise InvalidSignatureError("signature does not verify") from None
    return _accept(env, now, max_clock_skew, replay_check)


def verify_text_envelope(
    env: Mapping[str, Any],
    resolve_key: ResolveKey,
    *,
    now: int | float | None = None,
    origin: str | None = None,
    type: str | None = None,
    types: Collection[str] = ENTRY_TYPES,
    max_clock_skew: int | float = FUTURE_SKEW_SECONDS,
    replay_check: ReplayCheck | None = None,
    nonce_bytes: int = NONCE_BYTES,
    verbs: Mapping[str, str] = TEXT_VERBS,
    window: bool = True,
) -> Any:
    """Verify a ``text-ed25519`` or ``text-sshsig`` envelope (AICS-1 section 11.3) and return its payload.

    The same checks as :func:`verify_envelope`, except the signature: it
    covers ``session || LF || C`` (:func:`text_signing_input`).  For
    ``text-ed25519`` ``sig`` is the raw 64-byte signature; for ``text-sshsig``
    the complete SSHSIG blob, which must be version 1, ``ssh-ed25519``,
    namespace ``aics``, hash ``sha512``, an empty reserved field and the
    exact kid key.  A native envelope raises :class:`UnsupportedScheme`.
    ``window`` is :func:`verify_envelope`'s.
    """
    _check_skew(max_clock_skew)
    scheme = validate_envelope(env, types=types, nonce_bytes=nonce_bytes, window=window)
    _check_domain(env, origin, type)
    if scheme not in TEXT_SCHEMES:
        raise UnsupportedScheme(f"auth.scheme {scheme!r} is not a text scheme (use verify_envelope)")
    public = _resolve(env, resolve_key)
    message = text_signing_input(unsigned_envelope(env), verbs=verbs)
    raw = _keys.u64_decode(env["sig"])
    if scheme == TEXT_ED25519_SCHEME:
        try:
            public.verify(raw, message)
        except InvalidSignature:
            raise InvalidSignatureError("text-ed25519 signature does not verify") from None
    else:
        try:
            parsed = _sshsig.verify_sshsig(raw, message, public, namespace=_linesig.NAMESPACE,
                                           allowed_hash_algorithms=(_sshsig.DEFAULT_HASH_ALGORITHM,))
        except _sshsig.SSHSigError as exc:
            raise InvalidSignatureError(f"text-sshsig signature does not verify: {exc}") from None
        if parsed.reserved:
            raise InvalidSignatureError("SSHSIG reserved field must be empty (AICS-1 section 11.3)")
    return _accept(env, now, max_clock_skew, replay_check)


# ----------------------------------------------------------------------
# the policy attestation of a shared-secret entry (AICS-1 section 5.1)
# ----------------------------------------------------------------------

def secret_attestation_message(
    env: Mapping[str, Any],
    *,
    ts: int,
    types: Collection[str] = ENTRY_TYPES,
) -> bytes:
    """The bytes the policy key signs for a shared-secret entry (AICS-1 section 5.1)::

        UTF8("AICS-1 secret-attestation\\n") ||
        J({"actor_kid": kid, "envelope_hash": hexH(J(E)), "origin": origin, "ts": ts, "type": type})

    ``actor_kid``, ``origin`` and ``type`` are the envelope's (an entry MUST
    copy them); ``ts`` is the entry's fixed submission time.  Only a valid
    fallback envelope has an attestation.
    """
    if validate_envelope(env, types=types) != SHARED_SECRET_SCHEME:
        raise MalformedEnvelope("only a shared-secret (fallback) envelope carries a policy attestation")
    if not _is_uint(ts):
        raise MalformedEnvelope("ts must be uint seconds")
    protected = env["protected"]
    statement = {
        "actor_kid": protected["kid"],
        "envelope_hash": envelope_hash(env),
        "origin": protected["origin"],
        "ts": ts,
        "type": protected["type"],
    }
    return SECRET_ATTESTATION_CONTEXT + canonicalize(statement)


def sign_secret_attestation(
    policy_key: Any,
    env: Mapping[str, Any],
    *,
    ts: int,
    types: Collection[str] = ENTRY_TYPES,
) -> str:
    """``attestation``: U64 of the policy key's Ed25519 signature over :func:`secret_attestation_message`.

    It proves only what the service asserted (that it checked the secret), not
    authorship by the identity.
    """
    private = _coerce_private(policy_key)
    return _keys.b64u_encode(private.sign(secret_attestation_message(env, ts=ts, types=types)))


def verify_secret_attestation(
    env: Mapping[str, Any],
    attestation: str,
    policy_key: Any,
    *,
    ts: int,
    types: Collection[str] = ENTRY_TYPES,
) -> None:
    """Verify a shared-secret entry's ``attestation`` with the pinned policy key; raise on failure.

    *policy_key* is anything :func:`aics_identity.keys.as_public_key` accepts,
    such as the trust bundle's ``policy_kid``.  Raises
    :class:`MalformedEnvelope` or :class:`InvalidSignatureError`.  Freshness
    at ``ts`` is separate (:func:`check_freshness`).
    """
    message = secret_attestation_message(env, ts=ts, types=types)
    try:
        signature = _keys.u64_decode(attestation, length=64)
    except ValueError:
        raise MalformedEnvelope("attestation must be U64 of a 64-byte Ed25519 signature") from None
    try:
        public = _keys.require_valid_public_key(policy_key)
    except (TypeError, ValueError) as exc:
        raise InvalidSignatureError(f"policy key is unusable: {exc}") from None
    try:
        public.verify(signature, message)
    except InvalidSignature:
        raise InvalidSignatureError("secret attestation does not verify with the policy key") from None


# ----------------------------------------------------------------------
# the sender chain
# ----------------------------------------------------------------------

def _protected_of(env: Any) -> Mapping[str, Any]:
    protected = env.get("protected") if isinstance(env, Mapping) else None
    if not isinstance(protected, Mapping):
        raise MalformedEnvelope("missing protected header")
    return protected


def _kid_of(env: Any) -> str:
    kid = _protected_of(env).get("kid")
    if not isinstance(kid, str) or not kid:
        raise MalformedEnvelope("missing kid")
    return kid


def chain_position(env: Mapping[str, Any]) -> tuple[int, str | None]:
    """``(seq, prev)`` of an envelope; :class:`MalformedEnvelope` if they are absent or malformed."""
    protected = _protected_of(env)
    validate_chain_fields(protected)
    if "seq" not in protected:
        raise MalformedEnvelope("envelope carries no seq/prev")
    return protected["seq"], protected["prev"]


def next_chain(previous: Mapping[str, Any] | None) -> dict[str, Any]:
    """``{"seq", "prev"}`` for the envelope after *previous* (``None``: the key's first envelope).

    ``prev`` is :func:`envelope_hash` of *previous*, ``hexH(J(E))`` over the
    complete envelope.  Splat it into :func:`sign_envelope`:
    ``sign_envelope(q, key, origin=..., type=..., **next_chain(last))``.
    """
    if previous is None:
        return {"seq": 0, "prev": None}
    seq, _ = chain_position(previous)
    if seq >= MAX_SEQ:
        raise MalformedEnvelope("seq cannot grow past 2**53 - 1")
    return {"seq": seq + 1, "prev": envelope_hash(previous)}


def check_chain_position(env: Mapping[str, Any], *, last_seq: int | None, last_hash: str | None) -> None:
    """The server rule: *env* must be the envelope right after ``(last_seq, last_hash)``.

    ``last_seq=None`` (with ``last_hash=None``) means the key has no
    accepted envelope yet, so *env* must have ``seq`` 0 and ``prev`` null.
    Raises :class:`ChainError` carrying ``expected_seq`` and
    ``expected_prev`` when it does not follow.
    """
    seq, prev = chain_position(env)
    if last_seq is None:
        if last_hash is not None:
            raise ValueError("last_hash must be None when last_seq is None")
        expected_seq, expected_prev = 0, None
    else:
        if not _is_int(last_seq) or last_seq < 0:
            raise ValueError("last_seq must be a non-negative integer")
        if not _is_hex64(last_hash):
            raise ValueError("last_hash must be 64 lowercase hex characters")
        expected_seq, expected_prev = last_seq + 1, last_hash
    if seq != expected_seq:
        raise ChainError(f"seq is {seq}, expected {expected_seq}",
                         expected_seq=expected_seq, expected_prev=expected_prev)
    if prev != expected_prev:
        raise ChainError("prev does not name the previous accepted envelope",
                         expected_seq=expected_seq, expected_prev=expected_prev)


def check_successor(previous: Mapping[str, Any] | None, env: Mapping[str, Any]) -> None:
    """*env* must directly follow *previous*: same kid, ``seq + 1``, ``prev == envelope_hash(previous)``.

    ``previous=None`` means *env* must be the key's first envelope.
    """
    if previous is None:
        check_chain_position(env, last_seq=None, last_hash=None)
        return
    if _kid_of(previous) != _kid_of(env):
        raise ChainError("envelopes are signed by different keys; chains are per kid")
    seq, _ = chain_position(previous)
    check_chain_position(env, last_seq=seq, last_hash=envelope_hash(previous))


@dataclass(frozen=True)
class ChainBreak:
    """One place where a sender's run of envelopes does not chain.

    ``position`` is the index (in the sequence given to :func:`chain_breaks`)
    of the envelope that does not follow its predecessor.  ``reason`` is one
    of:

    * ``"kid"``: signed by a different key than its predecessor;
    * ``"seq"``: ``seq`` is not the predecessor's + 1 (a hole, a repeat or a fork);
    * ``"prev"``: ``seq`` continues but ``prev`` does not name the
      predecessor (a substituted or forked envelope).
    """

    position: int
    reason: str
    expected_seq: int
    seq: int


def chain_breaks(
    envelopes: Sequence[Mapping[str, Any]],
    *,
    previous: Mapping[str, Any] | None = None,
) -> list[ChainBreak]:
    """Every break in one sender's run of envelopes, in log order; ``[]`` when the run chains.

    ``previous=None`` means the run starts at the key's first envelope, so
    the first one must have ``seq`` 0.  To check a later stretch, pass the
    envelope that precedes it.  Each envelope is compared with the one just
    before it, so a single hole yields a single break.  Structurally
    malformed envelopes raise :class:`MalformedEnvelope`; signatures are not
    verified here.
    """
    breaks: list[ChainBreak] = []
    before = previous
    for position, env in enumerate(envelopes):
        seq, prev = chain_position(env)
        if before is None:
            expected_seq, expected_prev = 0, None
        else:
            before_seq, _ = chain_position(before)
            expected_seq, expected_prev = before_seq + 1, envelope_hash(before)
            if _kid_of(before) != _kid_of(env):
                breaks.append(ChainBreak(position, "kid", expected_seq, seq))
                before = env
                continue
        if seq != expected_seq:
            breaks.append(ChainBreak(position, "seq", expected_seq, seq))
        elif prev != expected_prev:
            breaks.append(ChainBreak(position, "prev", expected_seq, seq))
        before = env
    return breaks


def _coerce_private(key: Any):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if isinstance(key, Ed25519PrivateKey):
        return key
    if isinstance(key, (bytes, bytearray)):
        return _keys.private_key_from_seed(bytes(key))
    raise TypeError("key must be an Ed25519PrivateKey or a 32-byte seed")

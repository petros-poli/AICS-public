"""End-to-end encrypted message bodies: X25519 sealed boxes with a bound inner header.

Scheme ``x25519-xsalsa20-poly1305``: libsodium ``crypto_box_seal`` through
PyNaCl's ``SealedBox``.  The sender encrypts to the recipient's X25519
public key under a fresh ephemeral key pair; the output is::

    ephemeral public key (32 bytes) || XSalsa20-Poly1305 box (plaintext + 16 bytes)

That gives confidentiality and integrity only.  Anyone can seal a box to
anyone, the server included, so a box says nothing about who sent it.
Sender authentication comes solely from the Ed25519 envelope around the
ciphertext (DESIGN.md section 3 G6, section 4.3), and that envelope must
commit to the exact ciphertext through ``ct_hash``.

So that a ciphertext cannot be lifted into a different envelope (Mallory
re-wraps Alice's publicly logged ciphertext to Bob in her own signed
envelope), the plaintext starts with a header naming the envelope, framed by
its length (AICS-1 section 8.1 and Appendix A.4)::

    plaintext    = uint32be(len(header_bytes)) || header_bytes || content_bytes
    header_bytes = JCS({"envelope_nonce": N, "from_kid": F, "to_kid": T})

* ``from_kid``: the sender's signing kid (``did:key``), equal to the
  envelope's ``protected.kid``;
* ``to_kid``: the recipient's signing kid, equal to the DM payload's
  ``to_kid``; a capsule names its owner twice (``payload.owner_kid``);
* ``envelope_nonce``: exactly the envelope's ``protected.nonce``.

The header is at most 4096 bytes, canonical JCS with exactly those three
members, and fully contained in the plaintext; the content is UTF-8 text.
:func:`open_sealed` checks the envelope's commitment to the ciphertext
(``encryption``, ``ct_hash``, ``eph_pk``, ``size``) before decrypting, then the
framing, and raises :class:`HeaderMismatch` unless all three header fields
equal what the outer envelope says; nothing of the plaintext is returned on
any failure.  It does not verify the envelope signature: call
:func:`aics_identity.envelope.verify_envelope` first.

Sending (the nonce is chosen before encryption)::

    nonce = envelope.new_nonce()
    header = InnerHeader(from_kid=my_kid, to_kid=their_kid, envelope_nonce=nonce)
    ct = seal(header, "hello", their_logged_x25519_public_key)
    chain = envelope.next_chain(my_previous_envelope)
    q = {"to_kid": their_kid, "to_key_leaf_index": idx, **ciphertext_metadata(ct),
         "grant_index": grant, **chain}                     # seq/prev repeat the envelope's
    env = envelope.sign_envelope(q, my_ed25519_key, origin=origin, type="dm", nonce=nonce, **chain)

Receiving::

    envelope.verify_envelope(env, resolve_key)        # who sent it
    msg = open_sealed(ct, my_x25519_private_key, envelope=env, recipient_kid=my_kid)
    msg.header, msg.body, msg.text

Keys.  The X25519 key is separate from the Ed25519 identity key and rotates
on its own (``x25519.rotate`` leaves).  The helpers here generate and
derive it, encode it as base64url of the raw 32 bytes and as ``did:key``
(multicodec ``x25519-pub`` 0xec01, ``did:key:z6LS...``), give it a short kid,
and validate received public keys (exactly 32 bytes, not a small-order
point).

There is no forward secrecy: ciphertext is public and permanent, so a later
compromise of the recipient's X25519 key exposes every message sealed to it.
Rotating the X25519 key and discarding old private keys is the remedy.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.bindings import crypto_box_SEALBYTES, crypto_scalarmult
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox

from . import keys as _keys
from .canonical import canonicalize

__all__ = [
    "SCHEME",
    "SEAL_OVERHEAD",
    "MAX_CIPHERTEXT_BYTES",
    "HEADER_FIELDS",
    "X25519_HKDF_INFO_PREFIX",
    "MAX_HEADER_BYTES",
    "SealedError",
    "MalformedSealed",
    "DecryptionFailed",
    "HeaderMismatch",
    "CiphertextMismatch",
    "UnsupportedScheme",
    "InnerHeader",
    "OpenedMessage",
    "generate_x25519_key",
    "derive_x25519_key",
    "x25519_private_key",
    "x25519_private_bytes",
    "x25519_public_key",
    "x25519_public_bytes",
    "validate_x25519_public_key",
    "format_x25519_public_key",
    "parse_x25519_public_key",
    "x25519_key_id",
    "x25519_did_key",
    "parse_x25519_did_key",
    "ct_hash",
    "ephemeral_public_key",
    "ciphertext_metadata",
    "frame_plaintext",
    "split_plaintext",
    "seal",
    "open_sealed",
]

#: Value of a DM's ``encryption`` field for this scheme.
SCHEME = "x25519-xsalsa20-poly1305"
#: Bytes a sealed box adds to the plaintext: ephemeral public key (32) + Poly1305 tag (16).
SEAL_OVERHEAD = crypto_box_SEALBYTES
#: Ciphertext bodies are at most 65536 bytes (AICS-1 section 4.3), framing and overhead included.
MAX_CIPHERTEXT_BYTES = 65536
#: The inner header's fields, in canonical (sorted) order.
HEADER_FIELDS = ("envelope_nonce", "from_kid", "to_kid")
#: Largest inner header, in bytes (AICS-1 section 8.1).
MAX_HEADER_BYTES = 4096
#: Bytes of an envelope nonce, which the header repeats.
_NONCE_BYTES = 16
#: HKDF ``info`` prefix for X25519 derivation.  It differs from the Ed25519
#: prefix ``aics-identity/v1/`` at byte 16 ("-" instead of "/"), so no Ed25519
#: label can ever produce the same ``info`` as an X25519 label.
X25519_HKDF_INFO_PREFIX = b"aics-identity/v1-x25519/"

_MULTICODEC_X25519_PUB = _keys.X25519_MULTICODEC  # varint(0xec), multicodec "x25519-pub"


def _clamp(seed: bytes) -> bytes:
    scalar = bytearray(seed)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return bytes(scalar)


# A clamped scalar is a multiple of the cofactor 8, so it maps every
# small-order point to the identity; libsodium then refuses the all-zero
# result.  Any fixed clamped scalar therefore detects small-order keys.
_SMALL_ORDER_PROBE = _clamp(hashlib.sha256(b"aics-identity/x25519-small-order-probe").digest())


class SealedError(ValueError):
    """Base error for sealed-box handling."""


class MalformedSealed(SealedError):
    """The ciphertext or the decrypted plaintext does not have the expected layout."""


class DecryptionFailed(SealedError):
    """The box does not open with this key: sealed to another key, or modified."""


class HeaderMismatch(SealedError):
    """The inner header does not match the envelope (or the expected values)."""


class CiphertextMismatch(SealedError):
    """The envelope does not commit to this ciphertext (``ct_hash``, ``eph_pk`` or ``size`` differ or are absent)."""


class UnsupportedScheme(SealedError):
    """The envelope names an encryption scheme other than ``x25519-xsalsa20-poly1305``."""


# ----------------------------------------------------------------------
# inner header
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class InnerHeader:
    """``{from_kid, to_kid, envelope_nonce}``: binds a plaintext to one signed envelope.

    ``from_kid`` and ``to_kid`` are signing kids (Ed25519 ``did:key``),
    ``envelope_nonce`` the envelope's nonce (U64 of 16 bytes).
    """

    from_kid: str
    to_kid: str
    envelope_nonce: str

    def __post_init__(self) -> None:
        for name in HEADER_FIELDS:
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        for name in ("from_kid", "to_kid"):
            if not _keys.is_did_key(getattr(self, name)):
                raise ValueError(f"{name} must be a signing kid: an Ed25519 did:key")
        try:
            _keys.u64_decode(self.envelope_nonce, length=_NONCE_BYTES)
        except ValueError:
            raise ValueError("envelope_nonce must be an envelope nonce: U64 of 16 bytes") from None

    def to_dict(self) -> dict[str, str]:
        return {"envelope_nonce": self.envelope_nonce, "from_kid": self.from_kid, "to_kid": self.to_kid}

    def canonical_bytes(self) -> bytes:
        """JCS (RFC 8785) bytes of the header, as they appear at the start of the plaintext."""
        return canonicalize(self.to_dict())

    @classmethod
    def from_mapping(cls, fields: Mapping[str, Any]) -> "InnerHeader":
        """Build from a mapping holding exactly the three header fields."""
        if not isinstance(fields, Mapping):
            raise TypeError("header fields must be a mapping")
        names = set(fields)
        if names != set(HEADER_FIELDS):
            missing = sorted(set(HEADER_FIELDS) - names)
            extra = sorted(names - set(HEADER_FIELDS))
            raise ValueError(f"header must have exactly {', '.join(HEADER_FIELDS)} (missing {missing}, extra {extra})")
        return cls(from_kid=fields["from_kid"], to_kid=fields["to_kid"], envelope_nonce=fields["envelope_nonce"])

    @classmethod
    def from_envelope(cls, env: Mapping[str, Any]) -> "InnerHeader":
        """The header an envelope promises: ``protected.kid``, the recipient, ``protected.nonce``.

        The recipient is ``payload.to_kid`` for a ``dm`` and ``payload.owner_kid``
        for a ``capsule`` (whose header names its owner twice).
        """
        protected = env.get("protected") if isinstance(env, Mapping) else None
        payload = env.get("payload") if isinstance(env, Mapping) else None
        if not isinstance(protected, Mapping) or not isinstance(payload, Mapping):
            raise ValueError("not an envelope: protected and payload must be objects")
        recipient = {"dm": "to_kid", "capsule": "owner_kid"}.get(protected.get("type"))
        if recipient is None:
            raise ValueError(f"only dm and capsule envelopes carry sealed bodies, not {protected.get('type')!r}")
        return cls(
            from_kid=protected.get("kid"),
            to_kid=payload.get(recipient),
            envelope_nonce=protected.get("nonce"),
        )


@dataclass(frozen=True)
class OpenedMessage:
    """A decrypted message whose header matched the envelope; ``body`` is the content bytes."""

    header: InnerHeader
    body: bytes

    @property
    def text(self) -> str:
        """The content as text (it was checked to be UTF-8 when opened)."""
        return self.body.decode("utf-8")


# ----------------------------------------------------------------------
# X25519 keys
# ----------------------------------------------------------------------

def generate_x25519_key() -> PrivateKey:
    """Generate a fresh random X25519 private key (PyNaCl ``PrivateKey``)."""
    return PrivateKey.generate()


def derive_x25519_key(
    master_secret: bytes,
    agent_label: str,
    run_salt: bytes | None = None,
) -> PrivateKey:
    """Deterministically derive an X25519 key; the counterpart of ``keys.derive_agent_key``.

    The 32-byte private key is ``HKDF-SHA256(IKM=master_secret,
    salt=run_salt, info=b"aics-identity/v1-x25519/" + label, L=32)``.  The
    ``info`` prefix keeps it independent of the Ed25519 key derived from the
    same secret and label.  Whoever holds the secret can derive the key and
    read every message sealed to it.
    """
    if not master_secret:
        raise ValueError("master_secret must be non-empty")
    if not agent_label:
        raise ValueError("agent_label must be non-empty")
    if run_salt is not None and not run_salt:
        raise ValueError("run_salt must be None or non-empty")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=run_salt,
        info=X25519_HKDF_INFO_PREFIX + agent_label.encode("utf-8"),
    )
    return PrivateKey(hkdf.derive(bytes(master_secret)))


def x25519_private_key(obj: Any) -> PrivateKey:
    """Coerce a PyNaCl ``PrivateKey`` or raw 32 bytes to a ``PrivateKey``."""
    if isinstance(obj, PrivateKey):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        if len(obj) != 32:
            raise ValueError("X25519 private key must be exactly 32 bytes")
        return PrivateKey(bytes(obj))
    raise TypeError("X25519 private key must be a nacl.public.PrivateKey or 32 bytes")


def x25519_private_bytes(obj: Any) -> bytes:
    """Raw 32 bytes of an X25519 private key."""
    return bytes(x25519_private_key(obj))


def validate_x25519_public_key(raw: bytes) -> bytes:
    """Return *raw* if it is a usable X25519 public key, else raise ``ValueError``.

    Usable means exactly 32 bytes and not a small-order point (with such a
    key the shared secret would be all zeros, known to everyone).
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        raise ValueError("X25519 public key must be exactly 32 bytes")
    try:
        crypto_scalarmult(_SMALL_ORDER_PROBE, bytes(raw))
    except RuntimeError:
        raise ValueError("X25519 public key is a small-order point") from None
    return bytes(raw)


def x25519_public_key(obj: Any) -> PublicKey:
    """Coerce to a validated X25519 public key.

    Accepts a PyNaCl ``PublicKey`` or ``PrivateKey``, raw 32 bytes, base64 or
    base64url text of the raw bytes, or ``did:key:z6LS...`` text.
    """
    if isinstance(obj, PrivateKey):
        obj = obj.public_key
    if isinstance(obj, PublicKey):
        raw = bytes(obj)
    elif isinstance(obj, (bytes, bytearray)):
        raw = bytes(obj)
    elif isinstance(obj, str):
        return parse_x25519_public_key(obj)
    else:
        raise TypeError(f"cannot interpret {type(obj).__name__} as an X25519 public key")
    return PublicKey(validate_x25519_public_key(raw))


def x25519_public_bytes(obj: Any) -> bytes:
    """Raw 32 bytes of a (validated) X25519 public key."""
    return bytes(x25519_public_key(obj))


def format_x25519_public_key(obj: Any) -> str:
    """base64url of the raw 32 bytes, no padding (the form used in leaves and payloads)."""
    return _keys.b64u_encode(x25519_public_bytes(obj))


def parse_x25519_public_key(text: str) -> PublicKey:
    """Parse base64 / base64url text of the raw 32 bytes (padding optional) or ``did:key`` text."""
    if not isinstance(text, str):
        raise TypeError("X25519 public key text must be a str")
    stripped = text.strip()
    if stripped.startswith("did:"):
        return parse_x25519_did_key(stripped)
    raw = _keys.b64_decode_strict(stripped)
    return PublicKey(validate_x25519_public_key(raw))


def x25519_key_id(obj: Any) -> str:
    """Short kid of an X25519 public key: ``base64url(SHA-256(0xec 0x01 || raw))[:16]``.

    Hashing the multicodec-prefixed key keeps X25519 kids apart from Ed25519
    kids (``keys.key_id`` hashes the bare 32 bytes), even if someone
    publishes an X25519 key whose bytes equal another agent's Ed25519 key.
    """
    digest = hashlib.sha256(_MULTICODEC_X25519_PUB + x25519_public_bytes(obj)).digest()
    return _keys.b64u_encode(digest)[:16]


def x25519_did_key(obj: Any) -> str:
    """``did:key:z6LS...`` for a (validated) X25519 public key: the display form ``0xec 0x01`` (AICS-1 section 3.1).

    A display form only: encrypt to the key logged for the recipient, never to
    one derived from a DID.
    """
    return _keys.x25519_did_key(x25519_public_bytes(obj))


def parse_x25519_did_key(did: str) -> PublicKey:
    """Parse ``did:key:z6LS...`` into a validated X25519 public key."""
    return PublicKey(validate_x25519_public_key(_keys.parse_x25519_did_key_bytes(did)))


# ----------------------------------------------------------------------
# ciphertext metadata
# ----------------------------------------------------------------------

def ct_hash(ciphertext: bytes) -> str:
    """SHA-256 of the sealed box, lowercase hex (the ``ct_hash`` of DM and capsule leaves)."""
    return hashlib.sha256(bytes(ciphertext)).hexdigest()


def ephemeral_public_key(ciphertext: bytes) -> bytes:
    """The sender's ephemeral X25519 public key: the first 32 bytes of the sealed box."""
    data = bytes(ciphertext)
    if len(data) < SEAL_OVERHEAD:
        raise MalformedSealed("ciphertext is shorter than the sealed-box overhead")
    return data[:32]


def ciphertext_metadata(ciphertext: bytes) -> dict[str, Any]:
    """``{"encryption", "eph_pk", "ct_hash", "size"}``: the ciphertext members of a ``dm`` or ``capsule`` ``Q``.

    ``eph_pk = U64(ciphertext[0:32])``, ``ct_hash = hexH(ciphertext)``,
    ``size = len(ciphertext)`` (AICS-1 section 8.1).
    """
    data = bytes(ciphertext)
    return {
        "encryption": SCHEME,
        "eph_pk": _keys.b64u_encode(ephemeral_public_key(data)),
        "ct_hash": ct_hash(data),
        "size": len(data),
    }


# ----------------------------------------------------------------------
# framing (AICS-1 section 8.1)
# ----------------------------------------------------------------------

def frame_plaintext(header_bytes: bytes, content: bytes) -> bytes:
    """``uint32be(len(header_bytes)) || header_bytes || content`` (AICS-1 section 8.1, Appendix A.4)."""
    header_bytes, content = bytes(header_bytes), bytes(content)
    if not header_bytes or len(header_bytes) > MAX_HEADER_BYTES:
        raise ValueError(f"inner header must be 1 to {MAX_HEADER_BYTES} bytes, got {len(header_bytes)}")
    return len(header_bytes).to_bytes(4, "big") + header_bytes + content


def split_plaintext(plaintext: bytes) -> tuple[bytes, bytes]:
    """``(header_bytes, content)`` of a framed plaintext; :class:`MalformedSealed` unless the frame is valid.

    The four-byte big-endian length must be 1 to 4096 and the header fully
    contained in the plaintext.  Neither part is interpreted here.
    """
    data = bytes(plaintext)
    if len(data) < 4:
        raise MalformedSealed("plaintext has no inner header length")
    length = int.from_bytes(data[:4], "big")
    if not 0 < length <= MAX_HEADER_BYTES:
        raise MalformedSealed(f"inner header length {length} is outside 1 to {MAX_HEADER_BYTES}")
    if len(data) < 4 + length:
        raise MalformedSealed("inner header is not fully contained in the plaintext")
    return data[4:4 + length], data[4 + length:]


def _content_bytes(content: bytes | str) -> bytes:
    if isinstance(content, str):
        return content.encode("utf-8")
    if isinstance(content, (bytes, bytearray)):
        data = bytes(content)
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("content must be UTF-8 text (AICS-1 section 8.1)") from None
        return data
    raise TypeError("content must be str or UTF-8 bytes")


# ----------------------------------------------------------------------
# seal / open
# ----------------------------------------------------------------------

def seal(
    header: InnerHeader | Mapping[str, Any],
    content: bytes | str,
    recipient_x25519_public_key: Any,
    *,
    max_ciphertext_bytes: int | None = MAX_CIPHERTEXT_BYTES,
) -> bytes:
    """Seal ``uint32be(len(J(header))) || J(header) || content`` to the recipient's X25519 key.

    *header* is an :class:`InnerHeader` or a mapping with exactly
    ``from_kid``, ``to_kid`` and ``envelope_nonce``.  *content* is text: a
    ``str``, or bytes that are valid UTF-8.  Each call uses a fresh
    ephemeral key (libsodium ``crypto_box_seal``).  Returns the sealed box
    (``ephemeral pk || box``).  Raises ``ValueError`` if the result would
    exceed *max_ciphertext_bytes* (65536 by default, the AICS-1 limit;
    ``None`` disables the cap).
    """
    inner = header if isinstance(header, InnerHeader) else InnerHeader.from_mapping(header)
    plaintext = frame_plaintext(inner.canonical_bytes(), _content_bytes(content))
    size = len(plaintext) + SEAL_OVERHEAD
    if max_ciphertext_bytes is not None and size > max_ciphertext_bytes:
        raise ValueError(f"sealed message would be {size} bytes; the limit is {max_ciphertext_bytes}")
    return bytes(SealedBox(x25519_public_key(recipient_x25519_public_key)).encrypt(plaintext))


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _parse_header(header_bytes: bytes) -> InnerHeader:
    try:
        fields = json.loads(header_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, ValueError) as exc:
        raise MalformedSealed(f"inner header is not a JSON object: {exc}") from None
    if not isinstance(fields, dict):
        raise MalformedSealed("inner header is not a JSON object")
    try:
        header = InnerHeader.from_mapping(fields)
    except ValueError as exc:
        raise MalformedSealed(f"bad inner header: {exc}") from None
    if header.canonical_bytes() != header_bytes:
        raise MalformedSealed("inner header is not in canonical (RFC 8785) form")
    return header


def _split_plaintext(plaintext: bytes) -> tuple[InnerHeader, bytes]:
    header_bytes, content = split_plaintext(plaintext)
    header = _parse_header(header_bytes)
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        raise MalformedSealed("content is not UTF-8 text (AICS-1 section 8.1)") from None
    return header, content


def _check_commitment(payload: Mapping[str, Any], ciphertext: bytes) -> None:
    for name in ("encryption", "ct_hash", "eph_pk", "size"):
        if name not in payload:
            raise CiphertextMismatch(f"envelope payload has no {name}, so it does not commit to this ciphertext")
    if payload["encryption"] != SCHEME:
        raise UnsupportedScheme(f"encryption {payload['encryption']!r} is not {SCHEME!r}")
    if payload["ct_hash"] != ct_hash(ciphertext):
        raise CiphertextMismatch("ct_hash in the envelope does not match the ciphertext")
    if payload["eph_pk"] != _keys.b64u_encode(ciphertext[:32]):
        raise CiphertextMismatch("eph_pk in the envelope does not match the ciphertext")
    if type(payload["size"]) is not int or payload["size"] != len(ciphertext):
        raise CiphertextMismatch("size in the envelope does not match the ciphertext")


def open_sealed(
    ciphertext: bytes,
    recipient_x25519_private_key: Any,
    *,
    expected: InnerHeader | Mapping[str, Any] | None = None,
    envelope: Mapping[str, Any] | None = None,
    recipient_kid: str | None = None,
) -> OpenedMessage:
    """Open a sealed box and check that its inner header matches the envelope.

    Pass exactly one of:

    * ``envelope=`` - the (already verified) ``dm`` or ``capsule`` envelope
      that carried the ciphertext.  Before decrypting, its payload must
      commit to exactly this ciphertext: ``encryption`` is
      ``x25519-xsalsa20-poly1305``, ``ct_hash``, ``eph_pk`` and ``size``
      match.  The expected header is ``protected.kid``, the recipient
      (``payload.to_kid``, or ``payload.owner_kid`` for a capsule) and
      ``protected.nonce``.
    * ``expected=`` - the header values to require, for callers that check
      the ciphertext commitment themselves.

    ``recipient_kid``, when given, must equal the expected ``to_kid``.  The
    plaintext must be framed as AICS-1 section 8.1 requires and its content
    be UTF-8.  Raises :class:`CiphertextMismatch`, :class:`UnsupportedScheme`,
    :class:`MalformedSealed`, :class:`DecryptionFailed` or
    :class:`HeaderMismatch`, exposing no plaintext; returns an
    :class:`OpenedMessage` (header and content) only when everything matches.
    """
    if (expected is None) == (envelope is None):
        raise TypeError("pass exactly one of expected= or envelope=")
    data = bytes(ciphertext)
    if len(data) < SEAL_OVERHEAD:
        raise MalformedSealed("ciphertext is shorter than the sealed-box overhead")
    if envelope is not None:
        try:
            want = InnerHeader.from_envelope(envelope)
        except ValueError as exc:
            raise HeaderMismatch(f"envelope does not name a valid inner header: {exc}") from None
        _check_commitment(envelope["payload"], data)
    else:
        want = expected if isinstance(expected, InnerHeader) else InnerHeader.from_mapping(expected)
    if recipient_kid is not None and want.to_kid != recipient_kid:
        raise HeaderMismatch("message is addressed to another kid")

    try:
        plaintext = SealedBox(x25519_private_key(recipient_x25519_private_key)).decrypt(data)
    except CryptoError:
        raise DecryptionFailed("sealed box does not open with this key (sealed to another key, or modified)") from None

    got, body = _split_plaintext(plaintext)
    for name in HEADER_FIELDS:
        if getattr(got, name) != getattr(want, name):
            raise HeaderMismatch(f"inner header {name} does not match the envelope")
    return OpenedMessage(header=got, body=body)


#: ``sealed.open(...)``: alias of :func:`open_sealed` (kept out of ``__all__`` so
#: ``from aics_identity.sealed import *`` never shadows the builtin ``open``).
open = open_sealed  # noqa: A001

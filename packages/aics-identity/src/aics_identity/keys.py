"""Ed25519 key management and deterministic agent-key derivation.

This module is the root of trust for ``aics_identity``:

* Ed25519 key pair generation and (de)serialisation.
* Public keys encoded as base64url (raw 32 bytes) and as ``did:key``
  (multicodec ``ed25519-pub`` 0xed01 + base58btc, per the did:key spec).
  The AICS-1 ``kid`` (section 3.1) is exactly that DID:
  ``did:key:z`` + base58btc(``0xed 0x01`` || public key), no fragment
  (:func:`did_key`, :func:`parse_did_key`).  An X25519 encryption key is
  displayed with ``0xec 0x01`` instead (:func:`x25519_did_key`).
* Identifiers of the unverified (shared-secret) tier, AICS-1 section 3.3:
  ``unverified:`` + U64 of 16 random bytes (:func:`new_unverified_id`).
* Strict ``U64`` (canonical unpadded base64url, AICS-1 section 2) decoding.
* Legacy short key ids: ``key_id = base64url(SHA-256(raw public key))[:16]``.
  They are not AICS-1 kids.
* OpenSSH ``ssh-ed25519 AAAA...`` public key lines, through
  :func:`parse_public_key_text` and :func:`as_public_key` (the format
  itself lives in :mod:`aics_identity.sshsig`).
* Deterministic derivation of per-run agent keys with HKDF-SHA256
  (RFC 5869) so a later run can re-derive the same key from a secret kept
  outside the run (see :func:`derive_agent_key`).

Re-deriving an agent key in a later run
---------------------------------------

``derive_agent_key(master_secret, agent_label, run_salt)`` is a pure
function.  To re-derive the key later, keep three things outside the run
(no key material needs to be stored):

1. the master secret, wherever secrets that outlive the run are kept,
2. the ``agent_label`` used for the run,
3. the ``run_salt`` used for the run (or the fact that it was ``None``).

Whoever holds the master secret can derive the key and sign as the agent:
derivation moves the exposure to that secret, it does not remove it.

Later::

    from aics_identity.keys import derive_agent_key, did_key

    key = derive_agent_key(master_secret, "agent-7", run_salt=salt)
    assert did_key(key.public_key()) == "did:key:z..."  # same as during the run

Leaving ``run_salt=None`` makes the key depend only on
``(master_secret, agent_label)``.  Passing a fresh random ``run_salt``
per run (e.g. ``os.urandom(16)``) additionally binds the key to that
specific run, so the same label re-used in a later run gets a
different key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = [
    "HKDF_INFO_PREFIX",
    "generate_keypair",
    "private_key_from_seed",
    "private_seed",
    "public_key",
    "public_key_bytes",
    "public_key_from_bytes",
    "format_public_key",
    "parse_public_key",
    "key_id",
    "DID_KEY_PREFIX",
    "ED25519_MULTICODEC",
    "X25519_MULTICODEC",
    "UNVERIFIED_PREFIX",
    "UNVERIFIED_ID_BYTES",
    "did_key",
    "did_key_from_bytes",
    "decode_did_key",
    "parse_did_key",
    "parse_did_key_bytes",
    "is_did_key",
    "x25519_did_key",
    "parse_x25519_did_key_bytes",
    "new_unverified_id",
    "is_unverified_id",
    "u64_decode",
    "derive_agent_key",
    "agent_identity",
    "as_public_key",
    "as_private_key",
    "validate_public_key_bytes",
    "require_valid_public_key",
    "b64u_encode",
    "b64u_decode",
    "b64_decode_strict",
    "parse_public_key_text",
    "base58_encode",
    "base58_decode",
]

#: HKDF ``info`` prefix (domain separation for this library, version 1).
HKDF_INFO_PREFIX = b"aics-identity/v1/"

#: ``did:key`` with the multibase prefix ``z`` (base58btc).
DID_KEY_PREFIX = "did:key:z"
#: multicodec ``ed25519-pub``: the unsigned varint of 0xed, not a network-order integer (AICS-1 section 3.1).
ED25519_MULTICODEC = b"\xed\x01"
#: multicodec ``x25519-pub`` (varint of 0xec): the display form of an encryption key.
X25519_MULTICODEC = b"\xec\x01"
#: Prefix of an unverified-tier identifier (AICS-1 section 3.3); it is not a key id.
UNVERIFIED_PREFIX = "unverified:"
UNVERIFIED_ID_BYTES = 16

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


# ---------------------------------------------------------------------
# keypair handling
# ---------------------------------------------------------------------

def generate_keypair() -> Ed25519PrivateKey:
    """Generate a fresh random Ed25519 private key (its public half is derivable)."""
    return Ed25519PrivateKey.generate()


def private_key_from_seed(seed: bytes) -> Ed25519PrivateKey:
    """Build an Ed25519 private key from its raw 32-byte seed."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(bytes(seed))


def private_seed(private_key: Ed25519PrivateKey) -> bytes:
    """Return the raw 32-byte seed of an Ed25519 private key."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key(private_key: Ed25519PrivateKey) -> Ed25519PublicKey:
    """Return the public half of an Ed25519 private key."""
    return private_key.public_key()


def public_key_bytes(public: Ed25519PublicKey) -> bytes:
    """Return the raw 32-byte encoding of an Ed25519 public key."""
    return public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def public_key_from_bytes(raw: bytes) -> Ed25519PublicKey:
    """Build an Ed25519 public key from its raw 32-byte encoding."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes")
    return Ed25519PublicKey.from_public_bytes(bytes(raw))


# ---------------------------------------------------------------------
# encodings
# ---------------------------------------------------------------------

def b64u_encode(data: bytes) -> str:
    """base64url (RFC 4648 section 5) without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    """Decode base64url with or without padding."""
    if isinstance(text, str):
        text = text.encode("ascii")
    padding = b"=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


_ASCII_WHITESPACE = str.maketrans("", "", " \t\r\n\v\f")


def b64_decode_strict(text: str | bytes) -> bytes:
    """Decode base64 in either alphabet (standard or URL-safe), padding optional.

    ASCII whitespace is ignored, so wrapped ``base64`` output is fine.  Any
    other character outside the alphabet, mixed alphabets, padding in the
    middle or of the wrong length, nonzero pad bits (AICS-1 section 11.2:
    "invalid pad bits ... are errors") or a length no encoder produces raises
    ``ValueError`` - unlike :func:`b64u_decode`, which silently drops stray
    characters.
    """
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("base64 text must be ASCII") from None
    if not isinstance(text, str):
        raise TypeError("base64 text must be str or bytes")
    compact = text.translate(_ASCII_WHITESPACE)
    if "-" in compact or "_" in compact:
        if "+" in compact or "/" in compact:
            raise ValueError("base64 text mixes the standard and URL-safe alphabets")
        compact = compact.replace("-", "+").replace("_", "/")
    stripped = compact.rstrip("=")
    padding = len(compact) - len(stripped)
    if padding > 2 or (padding and len(compact) % 4):
        raise ValueError("invalid base64 padding")
    if len(stripped) % 4 == 1:
        raise ValueError("invalid base64 length")
    try:
        raw = base64.b64decode(stripped + "=" * (-len(stripped) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64: {exc}") from None
    if base64.b64encode(raw).decode("ascii").rstrip("=") != stripped:
        raise ValueError("invalid base64: nonzero pad bits")
    return raw


_U64_TEXT = re.compile(r"[A-Za-z0-9_-]*")


def u64_decode(text: str, *, length: int | None = None) -> bytes:
    """Decode ``U64`` strictly: canonical unpadded base64url (AICS-1 section 2), else ``ValueError``.

    Padding, the standard alphabet, whitespace, stray characters and nonzero
    pad bits are all refused, so one byte string has exactly one accepted
    text.  With ``length`` the decoded value must have exactly that many
    bytes (limits apply to decoded bytes, not characters).
    """
    if not isinstance(text, str):
        raise ValueError("a U64 value must be a string")
    if not _U64_TEXT.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not canonical unpadded base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u_encode(raw) != text:
        raise ValueError("not canonical unpadded base64url (nonzero pad bits)")
    if length is not None and len(raw) != length:
        raise ValueError(f"expected U64 of {length} bytes, got {len(raw)}")
    return raw


def base58_encode(data: bytes) -> str:
    """base58btc (Bitcoin alphabet) encoding of *data*."""
    num = int.from_bytes(data, "big")
    out: list[str] = []
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(_B58_ALPHABET[rem])
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(reversed(out))


def base58_decode(text: str) -> bytes:
    """Decode a base58btc string."""
    num = 0
    for ch in text:
        try:
            num = num * 58 + _B58_INDEX[ch]
        except KeyError:
            raise ValueError(f"invalid base58 character: {ch!r}") from None
    body = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = 0
    for ch in text:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


# ---------------------------------------------------------------------
# public key representations
# ---------------------------------------------------------------------

def format_public_key(public: Ed25519PublicKey) -> str:
    """Serialise a public key as base64url of its raw 32 bytes (no padding)."""
    return b64u_encode(public_key_bytes(public))


def parse_public_key(text: str) -> Ed25519PublicKey:
    """Parse a base64url raw public key (32 bytes) as produced by :func:`format_public_key`."""
    return public_key_from_bytes(b64u_decode(text))


def key_id(public: Ed25519PublicKey) -> str:
    """Legacy short key id: ``base64url(SHA-256(raw public key))[:16]``.

    Not an AICS-1 ``kid``: the AICS-1 kid is the ``did:key`` (:func:`did_key`).
    """
    digest = hashlib.sha256(public_key_bytes(public)).digest()
    return b64u_encode(digest)[:16]


def did_key_from_bytes(raw: bytes, multicodec: bytes = ED25519_MULTICODEC) -> str:
    """``did:key:z`` + base58btc(``multicodec`` || ``raw``); no validation of the key bytes."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        raise ValueError("a did:key public key must be exactly 32 bytes")
    if multicodec not in (ED25519_MULTICODEC, X25519_MULTICODEC):
        raise ValueError("multicodec must be ed25519-pub (0xed 0x01) or x25519-pub (0xec 0x01)")
    return DID_KEY_PREFIX + base58_encode(bytes(multicodec) + bytes(raw))


def did_key(public: object) -> str:
    """The AICS-1 ``kid`` of an Ed25519 key: ``did:key:z`` + base58btc(``0xed 0x01`` || public key).

    *public* is anything :func:`as_public_key` accepts (a key object, a
    private key, raw 32 bytes, ...).  The result is the bare DID, without a
    fragment (AICS-1 section 3.1).
    """
    return did_key_from_bytes(public_key_bytes(as_public_key(public)), ED25519_MULTICODEC)


def x25519_did_key(raw: bytes) -> str:
    """Display form of an X25519 encryption key: ``did:key:z`` + base58btc(``0xec 0x01`` || key).

    Only a display form (AICS-1 section 3.1): the encryption key a sender uses
    is the one logged for the name, never one derived from a DID.  The bytes
    are not checked here; :func:`aics_identity.sealed.x25519_did_key` also
    refuses small-order keys.
    """
    return did_key_from_bytes(raw, X25519_MULTICODEC)


def decode_did_key(did: str) -> tuple[bytes, bytes]:
    """Split a ``did:key`` into ``(multicodec, raw 32-byte key)``, else ``ValueError``.

    Checked: the exact ``did:key:z`` prefix (no fragment, no other multibase),
    base58btc characters in canonical form, an ed25519-pub or x25519-pub
    multicodec and exactly 32 key bytes.  The key bytes themselves are not
    validated here.
    """
    if not isinstance(did, str) or not did.startswith(DID_KEY_PREFIX):
        raise ValueError("expected a did:key of the form 'did:key:z...'")
    body = did[len(DID_KEY_PREFIX):]
    if not body:
        raise ValueError("did:key has no key")
    payload = base58_decode(body)
    if base58_encode(payload) != body:
        raise ValueError("did:key is not canonical base58btc")
    codec = payload[:2]
    if codec not in (ED25519_MULTICODEC, X25519_MULTICODEC):
        raise ValueError("did:key is not an ed25519-pub or x25519-pub multicodec key")
    raw = payload[2:]
    if len(raw) != 32:
        raise ValueError("did:key payload is not a 32-byte public key")
    return codec, raw


def parse_did_key_bytes(did: str, *, validate: bool = True) -> bytes:
    """Raw 32 bytes of an Ed25519 ``did:key`` (an AICS-1 kid), else ``ValueError``.

    With ``validate=True`` (the default) the key must also pass
    :func:`validate_public_key_bytes` (no small-order or non-canonical point).
    """
    codec, raw = decode_did_key(did)
    if codec != ED25519_MULTICODEC:
        raise ValueError("did:key is not an ed25519-pub multicodec key")
    if validate:
        validate_public_key_bytes(raw)
    return raw


def parse_did_key(did: str, *, validate: bool = True) -> Ed25519PublicKey:
    """Decode an Ed25519 ``did:key`` locally into its public key, else ``ValueError``.

    This is the local decoding AICS-1 section 3.1 requires before a verifier
    compares a kid with the logged key; usable directly as a ``resolve_key``
    for envelopes and request signatures when the key chain is checked
    elsewhere.  ``validate=False`` skips the point check (structure is
    always checked).
    """
    return public_key_from_bytes(parse_did_key_bytes(did, validate=validate))


def parse_x25519_did_key_bytes(did: str) -> bytes:
    """Raw 32 bytes of an X25519 ``did:key`` display form (``0xec 0x01``), else ``ValueError``."""
    codec, raw = decode_did_key(did)
    if codec != X25519_MULTICODEC:
        raise ValueError("did:key is not an x25519-pub multicodec key")
    return raw


def is_did_key(value: object) -> bool:
    """Whether *value* is a well-formed Ed25519 ``did:key`` (structure only, the point is not checked)."""
    try:
        parse_did_key_bytes(value, validate=False)  # type: ignore[arg-type]
    except (ValueError, TypeError):
        return False
    return True


def new_unverified_id() -> str:
    """A fresh unverified-tier identifier: ``unverified:`` + U64 of 16 random bytes (AICS-1 section 3.3)."""
    return UNVERIFIED_PREFIX + b64u_encode(secrets.token_bytes(UNVERIFIED_ID_BYTES))


def is_unverified_id(value: object) -> bool:
    """Whether *value* is ``unverified:`` followed by the canonical U64 of exactly 16 bytes."""
    if not isinstance(value, str) or not value.startswith(UNVERIFIED_PREFIX):
        return False
    try:
        u64_decode(value[len(UNVERIFIED_PREFIX):], length=UNVERIFIED_ID_BYTES)
    except ValueError:
        return False
    return True


def validate_public_key_bytes(raw: bytes) -> bytes:
    """Return *raw* if it is a sound Ed25519 public key, else raise ``ValueError``.

    Sound means 32 bytes holding the canonical encoding of a point in the
    prime-order subgroup (libsodium ``crypto_core_ed25519_is_valid_point``).
    Every honestly generated key passes.  A small-order key such as the
    identity point fails, and must: OpenSSL's Ed25519 verification (used by
    ``cryptography``) accepts forged signatures under such a key, e.g.
    ``R = identity, S = 0`` for every message, so a proof of possession made
    with it proves nothing and anyone could "sign" as its name.
    """
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes")
    from nacl.bindings import crypto_core_ed25519_is_valid_point

    if not crypto_core_ed25519_is_valid_point(bytes(raw)):
        raise ValueError("Ed25519 public key is a small-order, non-canonical or invalid point")
    return bytes(raw)


def require_valid_public_key(obj: object) -> Ed25519PublicKey:
    """:func:`as_public_key`, refusing keys that fail :func:`validate_public_key_bytes`.

    All verifiers in this package resolve keys through this function, so a
    weak key that slipped into a log still verifies nothing.
    """
    public = as_public_key(obj)
    validate_public_key_bytes(public_key_bytes(public))
    return public


def parse_public_key_text(text: str, *, validate: bool = True) -> Ed25519PublicKey:
    """Parse the text forms an agent may present for its Ed25519 public key.

    Accepted, after trimming surrounding whitespace:

    * ``ssh-ed25519 AAAA... [comment]`` - an OpenSSH public key line
      (``cat aics_ed25519.pub``); the comment is ignored;
    * ``did:key:z6Mk...``;
    * base64 of the raw 32 bytes, standard or URL-safe alphabet, padding
      optional (``openssl pkey -in aics.key -pubout -outform DER | tail -c 32 | base64``).

    Anything else, including base64 that does not decode to exactly 32
    bytes, raises ``ValueError``.  With ``validate=True`` (the default) the
    key must also pass :func:`validate_public_key_bytes`, which is what a
    name claim needs: a weak key would make its proof of possession void.
    """
    if not isinstance(text, str):
        raise TypeError("public key text must be a str")
    stripped = text.strip()
    if not stripped:
        raise ValueError("empty public key text")
    if len(stripped.split()) >= 2:
        from .sshsig import parse_openssh_public_key

        public = parse_openssh_public_key(stripped)
    elif stripped.startswith("did:"):
        public = parse_did_key(stripped, validate=False)
    else:
        raw = b64_decode_strict(stripped)
        if len(raw) != 32:
            raise ValueError(f"raw Ed25519 public key must be 32 bytes, got {len(raw)}")
        public = public_key_from_bytes(raw)
    if validate:
        validate_public_key_bytes(public_key_bytes(public))
    return public


def as_public_key(obj: object) -> Ed25519PublicKey:
    """Coerce *obj* to an Ed25519 public key.

    Accepts a public key, a private key, raw 32 bytes, base64url text of the
    raw bytes, ``did:key`` text, or an OpenSSH ``ssh-ed25519 AAAA...`` line.
    Raw 32 bytes (or their base64url text) are interpreted as a raw
    *public* key.  To use a private seed, wrap it first with
    :func:`private_key_from_seed`.
    """
    if isinstance(obj, Ed25519PublicKey):
        return obj
    if isinstance(obj, Ed25519PrivateKey):
        return obj.public_key()
    if isinstance(obj, (bytes, bytearray)):
        if len(obj) == 32:
            return public_key_from_bytes(bytes(obj))
        raise ValueError("bytes public key must be exactly 32 raw bytes")
    if isinstance(obj, str):
        if obj.startswith("did:key:"):
            return parse_did_key(obj, validate=False)
        if len(obj.split()) >= 2:
            from .sshsig import parse_openssh_public_key

            return parse_openssh_public_key(obj)
        return parse_public_key(obj)
    raise TypeError(f"cannot interpret {type(obj).__name__} as an Ed25519 public key")


def as_private_key(obj: object) -> Ed25519PrivateKey:
    """Coerce *obj* (an ``Ed25519PrivateKey`` or its raw 32-byte seed) to a private key."""
    if isinstance(obj, Ed25519PrivateKey):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        return private_key_from_seed(bytes(obj))
    raise TypeError("key must be an Ed25519PrivateKey or a 32-byte seed")


def agent_identity(private_key: Ed25519PrivateKey) -> dict[str, str]:
    """Convenience summary of a key pair: ``{"did", "kid", "key_id", "public_key"}``.

    ``kid`` is the AICS-1 kid, which is the ``did:key`` itself (AICS-1
    section 3.1); ``key_id`` is the legacy 16-character short id.
    """
    pub = private_key.public_key()
    did = did_key(pub)
    return {
        "did": did,
        "kid": did,
        "key_id": key_id(pub),
        "public_key": format_public_key(pub),
    }


# ---------------------------------------------------------------------
# deterministic derivation (RFC 5869 HKDF)
# ---------------------------------------------------------------------

def derive_agent_key(
    master_secret: bytes,
    agent_label: str,
    run_salt: bytes | None = None,
) -> Ed25519PrivateKey:
    """Deterministically derive the Ed25519 key for one agent run.

    The 32-byte private seed is ``HKDF-SHA256`` (RFC 5869) over::

        IKM  = master_secret
        salt = run_salt          (None => all-zero salt, i.e. no extra binding)
        info = b"aics-identity/v1/" + agent_label.encode("utf-8")
        L    = 32

    and the resulting bytes are used directly as the Ed25519 seed.

    The function is pure: the same ``(master_secret, agent_label,
    run_salt)`` always yields the same key, on any machine, at any
    time.  See the module docstring for how a later run re-derives the
    key.

    Parameters
    ----------
    master_secret:
        High-entropy secret kept outside the run.  Whoever holds it can
        derive the key and sign as the agent.  Must be non-empty.
    agent_label:
        Stable identifier of the agent (e.g. ``"agent-7"`` or
        ``"support-agent/prod"``).  Different labels give independent keys.
    run_salt:
        Optional per-run salt (e.g. ``os.urandom(16)``).  When given, the
        key is bound to that specific run; record it with the run so the
        key can be re-derived later.  When ``None`` the key depends only
        on ``(master_secret, agent_label)``.
    """
    if not master_secret:
        raise ValueError("master_secret must be non-empty")
    if not agent_label:
        raise ValueError("agent_label must be non-empty")
    if run_salt is not None and not run_salt:
        raise ValueError("run_salt must be None or non-empty")
    info = HKDF_INFO_PREFIX + agent_label.encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=run_salt,
        info=info,
    )
    seed = hkdf.derive(bytes(master_secret))
    return private_key_from_seed(seed)

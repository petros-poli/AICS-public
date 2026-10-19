"""OpenSSH Ed25519 public keys and SSH signatures (SSHSIG).

An agent that has ``ssh-keygen`` and nothing else can still hold an AICS
identity:

* its public key is the line ``ssh-keygen -t ed25519`` writes to the
  ``.pub`` file: ``ssh-ed25519 AAAA... [comment]``;
* it signs with ``ssh-keygen -Y sign -f aics_ed25519 -n aics <file>``,
  which writes an armored ``-----BEGIN SSH SIGNATURE-----`` block.

This module parses and formats that public key line, and parses, verifies
and produces SSHSIG blocks for Ed25519 keys, following OpenSSH's
``PROTOCOL.sshsig``.  Blocks produced here are byte-identical to
ssh-keygen's (Ed25519 signatures are deterministic); the tests check that
against ssh-keygen itself.

Wire format (``string`` = uint32 big-endian length, then the bytes)::

    public key blob:  string "ssh-ed25519" || string key[32]

    SSHSIG blob:      byte[6] "SSHSIG" || uint32 version (= 1)
                      || string public key blob || string namespace
                      || string reserved || string hash_algorithm
                      || string signature blob

    signature blob:   string "ssh-ed25519" || string sig[64]

    signed data:      byte[6] "SSHSIG" || string namespace || string reserved
                      || string hash_algorithm || string H(message)

The Ed25519 signature is taken over the signed data.  Verification checks
the version, the namespace (``aics`` by default), the hash algorithm against
an allow-list (``sha512`` by default, which is also ssh-keygen's default),
and that the key inside the blob is the key the caller expects.  The
embedded key is never trusted on its own: it must equal the key bound to
the name in the log.  A non-empty ``reserved`` field is carried into the
signed data and otherwise ignored, as PROTOCOL.sshsig requires.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import keys as _keys

__all__ = [
    "KEY_TYPE",
    "MAGIC",
    "VERSION",
    "DEFAULT_NAMESPACE",
    "DEFAULT_HASH_ALGORITHM",
    "HASH_ALGORITHMS",
    "BEGIN_MARKER",
    "END_MARKER",
    "SSHSigError",
    "MalformedSSHSig",
    "InvalidSSHSig",
    "SSHSignature",
    "openssh_public_key_blob",
    "format_openssh_public_key",
    "parse_openssh_public_key",
    "parse_sshsig",
    "armor",
    "dearmor",
    "signed_data",
    "sign_sshsig",
    "verify_sshsig",
]

KEY_TYPE = "ssh-ed25519"
MAGIC = b"SSHSIG"
VERSION = 1
DEFAULT_NAMESPACE = "aics"
DEFAULT_HASH_ALGORITHM = "sha512"
#: Hash algorithms defined by PROTOCOL.sshsig (verification allows only sha512 unless asked).
HASH_ALGORITHMS: Mapping[str, Callable[..., Any]] = MappingProxyType(
    {"sha256": hashlib.sha256, "sha512": hashlib.sha512}
)
BEGIN_MARKER = "-----BEGIN SSH SIGNATURE-----"
END_MARKER = "-----END SSH SIGNATURE-----"

_KEY_TYPE_BYTES = KEY_TYPE.encode("ascii")
_WRAP = 70  # ssh-keygen wraps the armored base64 body at 70 columns


class SSHSigError(ValueError):
    """Base error for OpenSSH key and SSHSIG handling."""


class MalformedSSHSig(SSHSigError):
    """Not a well-formed Ed25519 OpenSSH public key line, SSHSIG block or blob."""


class InvalidSSHSig(SSHSigError):
    """Well formed, but not a valid signature for this key, namespace, hash and message."""


# ----------------------------------------------------------------------
# SSH wire encoding
# ----------------------------------------------------------------------

def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


class _Reader:
    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def take(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise MalformedSSHSig("truncated SSH data")
        out = self._data[self._pos:self._pos + n]
        self._pos += n
        return out

    def uint32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.uint32())

    def end(self, what: str) -> None:
        if self._pos != len(self._data):
            raise MalformedSSHSig(f"trailing bytes after the {what}")


# ----------------------------------------------------------------------
# public keys
# ----------------------------------------------------------------------

def openssh_public_key_blob(public: Any) -> bytes:
    """SSH wire encoding of an Ed25519 public key: ``string "ssh-ed25519" || string key``."""
    raw = _keys.public_key_bytes(_keys.as_public_key(public))
    return _string(_KEY_TYPE_BYTES) + _string(raw)


def _parse_public_key_blob(blob: bytes) -> bytes:
    reader = _Reader(blob)
    key_type = reader.string()
    if key_type != _KEY_TYPE_BYTES:
        raise MalformedSSHSig(f"unsupported key type {key_type!r}; only ssh-ed25519 is accepted")
    raw = reader.string()
    if len(raw) != 32:
        raise MalformedSSHSig(f"ssh-ed25519 key must be 32 bytes, got {len(raw)}")
    reader.end("public key")
    return raw


def format_openssh_public_key(public: Any, comment: str | None = None) -> str:
    """Render ``ssh-ed25519 <base64> [comment]``, the ``.pub`` line ssh-keygen writes."""
    text = f"{KEY_TYPE} {base64.b64encode(openssh_public_key_blob(public)).decode('ascii')}"
    if comment:
        if "\n" in comment or "\r" in comment:
            raise ValueError("comment must be a single line")
        text += f" {comment}"
    return text


def parse_openssh_public_key(text: str | bytes) -> Ed25519PublicKey:
    """Parse ``ssh-ed25519 <base64> [comment]`` into an Ed25519 public key.

    The comment is ignored.  The key type before the base64 must be
    ``ssh-ed25519`` and must match the type encoded inside the blob; the
    blob must hold exactly one 32-byte key and nothing after it.
    """
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("utf-8")
        except UnicodeDecodeError:
            raise MalformedSSHSig("OpenSSH public key line must be UTF-8") from None
    if not isinstance(text, str):
        raise TypeError("OpenSSH public key must be given as text")
    parts = text.strip().split(None, 2)
    if len(parts) < 2:
        raise MalformedSSHSig("expected 'ssh-ed25519 <base64> [comment]'")
    key_type, encoded = parts[0], parts[1]
    if key_type != KEY_TYPE:
        raise MalformedSSHSig(f"unsupported key type {key_type!r}; only ssh-ed25519 is accepted")
    try:
        blob = _keys.b64_decode_strict(encoded)
    except ValueError as exc:
        raise MalformedSSHSig(f"OpenSSH public key is not base64: {exc}") from None
    return Ed25519PublicKey.from_public_bytes(_parse_public_key_blob(blob))


# ----------------------------------------------------------------------
# SSHSIG
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class SSHSignature:
    """A parsed (not yet verified) Ed25519 SSHSIG."""

    public_key_bytes: bytes  # raw 32 bytes of the key embedded in the blob
    namespace: str
    reserved: bytes
    hash_algorithm: str
    signature: bytes  # raw 64-byte Ed25519 signature

    @property
    def public_key(self) -> Ed25519PublicKey:
        """The embedded key.  Never trust it as identity; compare it with the expected key."""
        return Ed25519PublicKey.from_public_bytes(self.public_key_bytes)

    def to_blob(self) -> bytes:
        """Serialise back to the binary SSHSIG blob."""
        return (
            MAGIC
            + struct.pack(">I", VERSION)
            + _string(_string(_KEY_TYPE_BYTES) + _string(self.public_key_bytes))
            + _string(self.namespace.encode("utf-8"))
            + _string(self.reserved)
            + _string(self.hash_algorithm.encode("ascii"))
            + _string(_string(_KEY_TYPE_BYTES) + _string(self.signature))
        )

    def armored(self) -> str:
        """The ``-----BEGIN SSH SIGNATURE-----`` text form, as ssh-keygen writes it."""
        return armor(self.to_blob())


def armor(blob: bytes) -> str:
    """Armor a binary SSHSIG blob exactly as ssh-keygen does (base64 wrapped at 70 columns)."""
    encoded = base64.b64encode(bytes(blob)).decode("ascii")
    body = "\n".join(encoded[i:i + _WRAP] for i in range(0, len(encoded), _WRAP))
    return f"{BEGIN_MARKER}\n{body}\n{END_MARKER}\n"


def dearmor(text: str) -> bytes:
    """Extract the binary blob from an armored SSHSIG block.

    Line endings may be ``\\n``, ``\\r\\n`` or ``\\r``; surrounding whitespace
    on each line is ignored, and so is any text before the BEGIN line or
    after the END line.
    """
    lines = [line.strip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    try:
        start = lines.index(BEGIN_MARKER)
    except ValueError:
        raise MalformedSSHSig(f"missing {BEGIN_MARKER} line") from None
    try:
        end = lines.index(END_MARKER, start + 1)
    except ValueError:
        raise MalformedSSHSig(f"missing {END_MARKER} line") from None
    body = "".join(lines[start + 1:end])
    if not body:
        raise MalformedSSHSig("empty SSH signature block")
    try:
        return _keys.b64_decode_strict(body)
    except ValueError as exc:
        raise MalformedSSHSig(f"SSH signature block is not base64: {exc}") from None


def parse_sshsig(data: str | bytes) -> SSHSignature:
    """Parse an armored SSHSIG block (``str`` or ``bytes``) or a binary SSHSIG blob.

    Only structure is checked here (preamble, version 1, Ed25519 key and
    signature types and lengths, no trailing bytes); use
    :func:`verify_sshsig` to check the signature.
    """
    if isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
        if raw.startswith(MAGIC):
            blob = raw
        else:
            try:
                blob = dearmor(raw.decode("ascii"))
            except UnicodeDecodeError:
                raise MalformedSSHSig("not an SSHSIG blob or armored block") from None
    elif isinstance(data, str):
        blob = dearmor(data)
    else:
        raise TypeError("SSHSIG must be given as text or bytes")

    reader = _Reader(blob)
    if reader.take(len(MAGIC)) != MAGIC:
        raise MalformedSSHSig("missing SSHSIG preamble")
    version = reader.uint32()
    if version != VERSION:
        raise MalformedSSHSig(f"unsupported SSHSIG version {version}")
    public_blob = reader.string()
    namespace = reader.string()
    reserved = reader.string()
    hash_algorithm = reader.string()
    signature_blob = reader.string()
    reader.end("SSHSIG blob")

    public_raw = _parse_public_key_blob(public_blob)
    sig_reader = _Reader(signature_blob)
    sig_type = sig_reader.string()
    if sig_type != _KEY_TYPE_BYTES:
        raise MalformedSSHSig(f"unsupported signature type {sig_type!r}; only ssh-ed25519 is accepted")
    signature = sig_reader.string()
    if len(signature) != 64:
        raise MalformedSSHSig(f"ssh-ed25519 signature must be 64 bytes, got {len(signature)}")
    sig_reader.end("signature blob")

    try:
        namespace_text = namespace.decode("utf-8")
        hash_text = hash_algorithm.decode("ascii")
    except UnicodeDecodeError:
        raise MalformedSSHSig("namespace or hash algorithm is not text") from None
    if not namespace_text:
        raise MalformedSSHSig("empty namespace")
    return SSHSignature(
        public_key_bytes=public_raw,
        namespace=namespace_text,
        reserved=reserved,
        hash_algorithm=hash_text,
        signature=signature,
    )


def signed_data(
    message: bytes,
    *,
    namespace: str,
    hash_algorithm: str,
    reserved: bytes = b"",
) -> bytes:
    """The bytes an SSHSIG signature is taken over (PROTOCOL.sshsig section 3)."""
    hasher = HASH_ALGORITHMS.get(hash_algorithm)
    if hasher is None:
        raise ValueError(f"unsupported hash algorithm {hash_algorithm!r}")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    return (
        MAGIC
        + _string(namespace.encode("utf-8"))
        + _string(bytes(reserved))
        + _string(hash_algorithm.encode("ascii"))
        + _string(hasher(bytes(message)).digest())
    )


def sign_sshsig(
    message: bytes,
    key: Any,
    *,
    namespace: str = DEFAULT_NAMESPACE,
    hash_algorithm: str = DEFAULT_HASH_ALGORITHM,
) -> str:
    """Sign *message* the way ``ssh-keygen -Y sign -n <namespace>`` does; return the armored block.

    *key* is an ``Ed25519PrivateKey`` or its 32-byte seed.  The output is
    byte-identical to ssh-keygen's for the same key, message and namespace.
    """
    private = _keys.as_private_key(key)
    if not namespace:
        raise ValueError("namespace must be non-empty")
    data = signed_data(message, namespace=namespace, hash_algorithm=hash_algorithm)
    return SSHSignature(
        public_key_bytes=_keys.public_key_bytes(private.public_key()),
        namespace=namespace,
        reserved=b"",
        hash_algorithm=hash_algorithm,
        signature=private.sign(data),
    ).armored()


def verify_sshsig(
    signature: str | bytes | SSHSignature,
    message: bytes,
    public_key: Any,
    *,
    namespace: str = DEFAULT_NAMESPACE,
    allowed_hash_algorithms: Iterable[str] = (DEFAULT_HASH_ALGORITHM,),
) -> SSHSignature:
    """Verify an SSHSIG over *message* by *public_key*; return the parsed signature.

    *public_key* is the key the caller expects (anything
    :func:`aics_identity.keys.as_public_key` accepts, including an
    ``ssh-ed25519 ...`` line).  Raises :class:`MalformedSSHSig` for bad
    structure and :class:`InvalidSSHSig` when the expected key is a
    small-order or non-canonical point, or when the namespace, the hash
    algorithm, the embedded key or the signature itself does not match.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    allowed = tuple(allowed_hash_algorithms)
    for name in allowed:
        if name not in HASH_ALGORITHMS:
            raise ValueError(f"unsupported hash algorithm {name!r}")
    parsed = signature if isinstance(signature, SSHSignature) else parse_sshsig(signature)
    try:
        expected = _keys.public_key_bytes(_keys.require_valid_public_key(public_key))
    except ValueError as exc:
        raise InvalidSSHSig(f"expected key is unusable: {exc}") from None

    if parsed.namespace != namespace:
        raise InvalidSSHSig(f"SSH signature namespace is {parsed.namespace!r}, expected {namespace!r}")
    if parsed.hash_algorithm not in allowed:
        raise InvalidSSHSig(
            f"SSH signature hash {parsed.hash_algorithm!r} is not allowed (allowed: {', '.join(allowed)})"
        )
    if parsed.public_key_bytes != expected:
        raise InvalidSSHSig("SSH signature was made by a different key")
    data = signed_data(
        message,
        namespace=parsed.namespace,
        hash_algorithm=parsed.hash_algorithm,
        reserved=parsed.reserved,
    )
    try:
        Ed25519PublicKey.from_public_bytes(expected).verify(parsed.signature, data)
    except InvalidSignature:
        raise InvalidSSHSig("SSH signature does not verify") from None
    return parsed

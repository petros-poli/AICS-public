"""Line signatures for the AICS text protocol (AICS-1 section 11.3, docs/PROTOCOL-TEXT.md section 2).

A write command is two lines: the command, then ``sig <signature>``.  The
signature covers exactly the UTF-8 bytes of::

    <session id> 0x0A <command line>

with no trailing newline.  Binding the session id stops a signed line from
being replayed into another session.  For an envelope write the command line
is the canonical command ``C`` (:func:`aics_identity.envelope.text_command`).

Two signature forms are accepted:

* **raw Ed25519**: the 64 signature bytes in base64 (standard or URL-safe
  alphabet, padding optional, whitespace ignored), as produced by::

      printf '%s\\n%s' "$SESSION" "$LINE" > line.txt
      openssl pkeyutl -sign -inkey aics.key -rawin -in line.txt | base64

  (OpenSSL 3 and later refuse ``-rawin`` on a pipe, hence the file), or by
  any Ed25519 library (:func:`sign_line` with ``form="raw"``);
* **SSHSIG**: the armored ``-----BEGIN SSH SIGNATURE-----`` block written by
  ``ssh-keygen -Y sign -f aics_ed25519 -n aics line.txt``, or only its base64
  body; namespace ``aics``, hash ``sha512`` (:mod:`aics_identity.sshsig`).

The gate hands over the signature text as received: :func:`verify_line`
strips a leading ``sig`` / ``sig:`` keyword and surrounding quotes, ignores
text around an armored block (such as ``sig-begin`` / ``sig-end`` lines), and
tells the two forms apart by themselves (a raw signature is exactly 64 bytes,
an SSHSIG blob starts with ``SSHSIG`` and is longer).

Verification is strict by default: only a signature over exactly
``<session id> "\\n" <line>`` verifies (AICS-1 section 11.3: no final LF;
section 11.2: the server MUST NOT silently repair signed content, and a
signature failure is not an opportunity to reinterpret bytes).  An SSHSIG
must also be version 1, ``ssh-ed25519``, namespace ``aics``, hash ``sha512``
with an empty reserved field, made by the expected key.

``leeway=True`` is an explicit opt-out for tools outside the protocol, never
for verifying protocol writes.  The signed bytes may then also be, in this
order after the exact form:

2. the same followed by one ``"\\n"`` (a file written with a final newline);
3. and 4. the same two with the line stripped of leading and trailing
   spaces, tabs and carriage returns, when that changes it.

A session id or a line never contains a newline, so none of these can be
read as a different (session, line) pair.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature

from . import keys as _keys
from . import sshsig as _sshsig

__all__ = [
    "NAMESPACE",
    "RAW",
    "SSHSIG",
    "FORMS",
    "LineSignatureError",
    "MalformedLineSignature",
    "InvalidLineSignature",
    "line_message",
    "candidate_messages",
    "sign_line",
    "verify_line",
]

#: SSHSIG namespace for AICS line signatures (``ssh-keygen -Y sign -n aics``).
NAMESPACE = "aics"
RAW = "raw"
SSHSIG = "sshsig"
FORMS = (RAW, SSHSIG)

_LEEWAY_STRIP = " \t\r"
_KEYWORD = re.compile(r"sig(?::\s*|\s+|$)", re.IGNORECASE)


class LineSignatureError(ValueError):
    """Base error for line signatures."""


class MalformedLineSignature(LineSignatureError):
    """The signature text is neither a 64-byte Ed25519 signature nor an SSHSIG."""


class InvalidLineSignature(LineSignatureError):
    """The signature does not verify for this session id, line and key."""


def _check_parts(session_id: str, line: str) -> None:
    if not isinstance(session_id, str) or not session_id:
        raise ValueError("session id must be a non-empty string")
    if not isinstance(line, str):
        raise TypeError("line must be a str")
    if "\n" in session_id or "\r" in session_id:
        raise ValueError("session id must not contain line breaks")
    if "\n" in line:
        raise ValueError("line must not contain a newline")


def line_message(session_id: str, line: str) -> bytes:
    """The exact bytes a line signature covers: UTF-8 of ``<session id>\\n<line>``."""
    _check_parts(session_id, line)
    return f"{session_id}\n{line}".encode("utf-8")


def candidate_messages(session_id: str, line: str, *, leeway: bool = False) -> list[bytes]:
    """The byte strings :func:`verify_line` accepts a signature over, in the order tried.

    Strict (the default): only the exact signing input.
    """
    _check_parts(session_id, line)
    lines = [line]
    if leeway:
        stripped = line.strip(_LEEWAY_STRIP)
        if stripped != line:
            lines.append(stripped)
    out: list[bytes] = []
    for text in lines:
        message = f"{session_id}\n{text}".encode("utf-8")
        out.append(message)
        if leeway:
            out.append(message + b"\n")
    return out


def sign_line(
    session_id: str,
    line: str,
    key: Any,
    *,
    form: str = RAW,
    namespace: str = NAMESPACE,
) -> str:
    """Sign ``<session id>\\n<line>``.

    ``form="raw"`` returns padded standard base64 of the 64-byte Ed25519
    signature (what ``openssl pkeyutl -rawin ... | base64`` prints);
    ``form="sshsig"`` returns the armored block ``ssh-keygen -Y sign -n aics``
    would write.  *key* is an ``Ed25519PrivateKey`` or its 32-byte seed.
    """
    message = line_message(session_id, line)
    private = _keys.as_private_key(key)
    if form == RAW:
        return base64.b64encode(private.sign(message)).decode("ascii")
    if form == SSHSIG:
        return _sshsig.sign_sshsig(message, private, namespace=namespace)
    raise ValueError(f"form must be one of {', '.join(FORMS)}")


def _strip_keyword(text: str) -> str:
    text = text.strip()
    match = _KEYWORD.match(text)
    if match:
        text = text[match.end():].strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    return text


def _decode_signature(signature: str | bytes) -> tuple[str, Any]:
    if isinstance(signature, (bytes, bytearray)):
        try:
            signature = bytes(signature).decode("ascii")
        except UnicodeDecodeError:
            raise MalformedLineSignature("signature must be ASCII text") from None
    if not isinstance(signature, str):
        raise TypeError("signature must be text")
    text = _strip_keyword(signature)
    if not text:
        raise MalformedLineSignature("empty signature")
    if _sshsig.BEGIN_MARKER in text:
        try:
            return SSHSIG, _sshsig.parse_sshsig(text)
        except _sshsig.MalformedSSHSig as exc:
            raise MalformedLineSignature(str(exc)) from None
    try:
        raw = _keys.b64_decode_strict(text)
    except ValueError as exc:
        raise MalformedLineSignature(f"signature is not base64: {exc}") from None
    if len(raw) == 64:
        return RAW, raw
    if raw.startswith(_sshsig.MAGIC):
        try:
            return SSHSIG, _sshsig.parse_sshsig(raw)
        except _sshsig.MalformedSSHSig as exc:
            raise MalformedLineSignature(str(exc)) from None
    raise MalformedLineSignature(
        f"expected a 64-byte Ed25519 signature or an SSHSIG, got {len(raw)} bytes"
    )


def verify_line(
    session_id: str,
    line: str,
    signature: str | bytes,
    public_key: Any,
    *,
    namespace: str = NAMESPACE,
    leeway: bool = False,
    allowed_hash_algorithms: Iterable[str] = (_sshsig.DEFAULT_HASH_ALGORITHM,),
) -> str:
    """Verify a line signature; return the form that verified (``"raw"`` or ``"sshsig"``).

    Strict by default: the signature must cover exactly
    ``<session id> "\\n" <line>`` (``leeway=True`` widens this, see the
    module docstring).  *public_key* is the key bound to the agent (anything
    :func:`aics_identity.keys.as_public_key` accepts: a key object, raw 32
    bytes, base64url, ``did:key`` or an ``ssh-ed25519 ...`` line).  For an
    SSHSIG the key embedded in the signature must be that same key, the
    namespace and hash must be as given, and the reserved field empty.  A
    small-order or non-canonical key is refused (:class:`InvalidLineSignature`).
    Raises :class:`MalformedLineSignature` or :class:`InvalidLineSignature`,
    and ``ValueError`` / ``TypeError`` for a malformed session id, line or key.
    """
    messages = candidate_messages(session_id, line, leeway=leeway)
    try:
        public = _keys.require_valid_public_key(public_key)
    except ValueError as exc:
        raise InvalidLineSignature(f"public key is unusable: {exc}") from None
    form, value = _decode_signature(signature)
    if form == RAW:
        for message in messages:
            try:
                public.verify(value, message)
            except InvalidSignature:
                continue
            return RAW
        raise InvalidLineSignature("signature does not verify for this session, line and key")
    if value.reserved:
        raise InvalidLineSignature("SSHSIG reserved field must be empty (AICS-1 section 11.3)")
    allowed = tuple(allowed_hash_algorithms)
    last: _sshsig.InvalidSSHSig | None = None
    for message in messages:
        try:
            _sshsig.verify_sshsig(value, message, public, namespace=namespace, allowed_hash_algorithms=allowed)
        except _sshsig.InvalidSSHSig as exc:
            last = exc
            continue
        return SSHSIG
    raise InvalidLineSignature(str(last)) from last

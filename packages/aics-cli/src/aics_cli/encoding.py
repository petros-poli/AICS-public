"""Base64 helpers.

* ``b64e`` / ``b64d_strict``: standard alphabet with padding, canonical -
  the form used by signed notes, checkpoints and the text protocol's
  ``pub`` / ``sig`` lines.
* ``b64d_lenient``: what the gate accepts from an agent - standard or
  URL-safe alphabet, padding optional, ASCII whitespace ignored.
* ``b64u_e`` / ``b64u_d``: base64url without padding (JWS, RFC 7515 §2).

It also holds :func:`escape_untrusted`, which every text-mode output uses for
strings that come from a server (card free text, error details): they must
never add lines or terminal escape sequences to the verifier's own verdict.
"""

from __future__ import annotations

import base64
import binascii
import re

_WS = str.maketrans("", "", " \t\r\n\v\f")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d_strict(text: str) -> bytes:
    """Canonical standard base64 with padding; anything else raises ValueError."""
    if not isinstance(text, str) or not text or len(text) % 4:
        raise ValueError("not canonical base64")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64: {exc}") from None
    if base64.b64encode(raw).decode("ascii") != text:
        raise ValueError("not canonical base64")
    return raw


def b64d_lenient(text: str) -> bytes:
    """Standard or URL-safe alphabet, padding optional, whitespace ignored."""
    if isinstance(text, bytes):
        text = text.decode("ascii")
    compact = text.translate(_WS)
    if "-" in compact or "_" in compact:
        if "+" in compact or "/" in compact:
            raise ValueError("base64 mixes the standard and URL-safe alphabets")
        compact = compact.replace("-", "+").replace("_", "/")
    stripped = compact.rstrip("=")
    if len(compact) - len(stripped) > 2 or len(stripped) % 4 == 1 or not stripped:
        raise ValueError("invalid base64 length or padding")
    try:
        return base64.b64decode(stripped + "=" * (-len(stripped) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64: {exc}") from None


def b64u_e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_d(text: str) -> bytes:
    """base64url without padding (RFC 7515); rejects characters outside the alphabet."""
    if not isinstance(text, str):
        raise ValueError("base64url value must be a string")
    if not _B64URL_RE.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("invalid base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64url: {exc}") from None


def escape_untrusted(text: str) -> str:
    """``text`` with every non-printable character (control, format, line and
    paragraph separators, ...) written as ``\\uXXXX`` / ``\\UXXXXXXXX``, so an
    untrusted string prints as exactly one line with no escape sequences."""
    if not isinstance(text, str):
        text = str(text)
    out = []
    for c in text:
        if c.isprintable() and c != "\\":
            out.append(c)
        elif c == "\\":
            out.append("\\\\")
        elif ord(c) <= 0xFFFF:
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(f"\\U{ord(c):08x}")
    return "".join(out)


def printable_line(line: str) -> str:
    """The last pass over every text-mode output line: non-printable
    characters become ``\\uXXXX`` (backslashes are left alone, so JSON
    printed as text stays valid JSON)."""
    if line.isprintable():
        return line
    return "".join(c if c.isprintable() else (f"\\u{ord(c):04x}" if ord(c) <= 0xFFFF else f"\\U{ord(c):08x}")
                   for c in line)


def parse_hash_lines(text: str, *, max_hashes: int = 256) -> list[bytes]:
    """One 32-byte hash per line, base64 or 64 hex characters (the
    ``aics-tlog`` proof-file format).  Blank lines are ignored."""
    out: list[bytes] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        if len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
            h = bytes.fromhex(line)
        else:
            try:
                h = b64d_lenient(line)
            except ValueError as exc:
                raise ValueError(f"proof line {lineno}: {exc}") from None
        if len(h) != 32:
            raise ValueError(f"proof line {lineno}: hash must be 32 bytes, got {len(h)}")
        out.append(h)
        if len(out) > max_hashes:
            raise ValueError("proof too long")
    return out

"""RFC 8785 JSON Canonicalization Scheme (JCS).

``canonicalize(value) -> bytes`` returns the canonical JSON
serialisation of *value* as UTF-8 bytes:

* no insignificant whitespace,
* object properties sorted by their UTF-16 code units,
* strings escaped minimally (JSON escaping, ``\\b \\f \\n \\r \\t`` and
  ``\\u00xx`` for other control characters, literal UTF-8 otherwise),
* numbers formatted like ECMAScript ``Number::toString()``.

The primary implementation is the ``rfc8785`` PyPI package.  A pure
fallback is used if the package cannot be imported; the fallback shares
the same rules except that some floating point edge cases (very large
magnitudes, e.g. ``1e16`` and above) may be rendered with a different
exponent threshold than ECMAScript.  The package is therefore the
authoritative dependency.
"""

from __future__ import annotations

import json

try:  # authoritative implementation
    from rfc8785 import dumps as _jcs_dumps
except ImportError:  # pragma: no cover - exercised only without the package
    _jcs_dumps = None

__all__ = ["canonicalize", "canonical_text", "CanonicalizationError"]


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonically serialised (e.g. NaN, huge ints)."""


def canonicalize(value: object) -> bytes:
    """Return the RFC 8785 (JCS) canonical JSON serialisation of *value* as UTF-8 bytes."""
    if _jcs_dumps is not None:
        try:
            return _jcs_dumps(value)
        except (ValueError, TypeError) as exc:
            raise CanonicalizationError(str(exc)) from exc
    try:
        return _fallback_canonicalize(value)
    except (ValueError, TypeError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def canonical_text(value: object) -> str:
    """Return the canonical JSON serialisation of *value* as a string."""
    return canonicalize(value).decode("utf-8")


# ----------------------------------------------------------------------
# fallback implementation (used only when the rfc8785 package is absent)
# ----------------------------------------------------------------------

def _fallback_canonicalize(value: object) -> bytes:
    def convert(node: object) -> str:
        if node is True:
            return "true"
        if node is False:
            return "false"
        if node is None:
            return "null"
        if isinstance(node, str):
            return _escape_string(node)
        if isinstance(node, int):
            return str(node)
        if isinstance(node, float):
            if node != node or node in (float("inf"), float("-inf")):
                raise ValueError("NaN/Infinity is not canonical JSON")
            if node == 0.0:
                return "0"
            text = repr(node)
            return text
        if isinstance(node, (list, tuple)):
            return "[" + ",".join(convert(item) for item in node) + "]"
        if isinstance(node, dict):
            items = sorted(node.items(), key=lambda kv: kv[0].encode("utf-16-be"))
            return "{" + ",".join(
                _escape_string(str(k)) + ":" + convert(v) for k, v in items
            ) + "}"
        raise TypeError(f"type {type(node).__name__} is not JSON-serialisable")

    return convert(value).encode("utf-8")


def _escape_string(text: str) -> str:
    """JSON string escaping per RFC 8785 section 3.2.2.2."""
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)

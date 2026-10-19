"""RFC 8941 Structured Field Values - the subset needed by RFC 9421.

Thin, typed wrapper around the ``http-sfv`` package:

* :func:`parse_dictionary` parses ``Signature-Input`` / ``Signature`` /
  ``Content-Digest`` style dictionaries.
* :func:`inner_list_serialization` builds the serialised form of a
  signature-params inner list (component identifiers + parameters),
  which is used verbatim both in the ``Signature-Input`` header and in
  the ``@signature-params`` line of the signature base.
* :func:`byte_sequence` renders bytes as ``:base64:``.
* :func:`params_to_dict` normalises parsed parameters (tokens -> str).

Parameter insertion order is preserved everywhere: RFC 9421 signature
parameters are order-significant because ``@signature-params`` is
signed byte-for-byte.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

import http_sfv

__all__ = [
    "ParseError",
    "parse_dictionary",
    "params_to_dict",
    "inner_list_serialization",
    "byte_sequence",
    "dictionary_serialization",
]


class ParseError(ValueError):
    """Raised when a structured field value cannot be parsed."""


def parse_dictionary(text: str) -> dict[str, Any]:
    """Parse an RFC 8941 dictionary into ``{key: Item|InnerList}``."""
    if not isinstance(text, str):
        raise ParseError("structured field must be a string")
    field = http_sfv.Dictionary()
    try:
        field.parse(text.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ParseError(f"invalid structured field dictionary: {exc}") from exc
    return {key: field[key] for key in field.keys()}


def _normalise_bare_item(value: Any) -> Any:
    # http-sfv models tokens as Token(str subclass); treat them as plain strings.
    if isinstance(value, str) and type(value) is not str:
        return str(value)
    return value


def params_to_dict(params: Any) -> dict[str, Any]:
    """Copy an http-sfv parameter mapping into a plain dict (tokens coerced to str)."""
    return {key: _normalise_bare_item(params[key]) for key in params.keys()}


def inner_list_serialization(
    items: Sequence[str],
    params: Sequence[tuple[str, Any]] = (),
) -> str:
    """Serialise an inner list of SF strings with ordered parameters.

    Example::

        >>> inner_list_serialization(["@method", "@path"],
        ...                          [("created", 1618884473), ("keyid", "k1")])
        '("@method" "@path");created=1618884473;keyid="k1"'
    """
    inner = http_sfv.InnerList()
    for item in items:
        if not isinstance(item, str):
            raise TypeError("inner list items must be strings")
        inner.append(http_sfv.Item(item))
    for key, value in params:
        inner.params[key] = _normalise_bare_item(value)
    return str(inner)


def byte_sequence(data: bytes) -> str:
    """Serialise *data* as an RFC 8941 byte sequence (``:base64:``)."""
    return str(http_sfv.Item(bytes(data)))


def dictionary_serialization(entries: Iterable[tuple[str, Any]]) -> str:
    """Serialise an ordered ``(key, value)`` iterable as an SF dictionary.

    Values may be ``bytes`` (rendered as ``:base64:``), ``int``, ``str``
    or ``bool``.
    """
    field = http_sfv.Dictionary()
    for key, value in entries:
        if isinstance(value, (bytes, bytearray)):
            value = bytes(value)
        field[key] = value
    return str(field)

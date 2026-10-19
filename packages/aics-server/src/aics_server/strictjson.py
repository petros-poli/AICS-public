"""JSON request bodies with bounded nesting (AICS-1 section 15: implementations MUST bound JSON depth).

``json.loads`` recurses once per nesting level and raises ``RecursionError``
(not a ``ValueError``) on deep input, which a handler that catches only
``ValueError`` turns into a 500.  :func:`loads_bounded` refuses such bodies
with an ordinary ``ValueError`` instead: first a cheap scan of the raw text
for a long run of opening brackets, then the parse (``RecursionError``
caught), then an iterative depth check of the parsed value.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable

__all__ = ["MAX_JSON_DEPTH", "JSONTooDeep", "json_depth_exceeds", "loads_bounded"]

#: Deepest nesting a request body may have; real bodies stay under ten levels.
MAX_JSON_DEPTH = 32


class JSONTooDeep(ValueError):
    """A JSON body nests deeper than the limit."""


def _opener_run(limit: int) -> re.Pattern[str]:
    return re.compile(r"(?:[\[{][ \t\r\n]*){%d}" % (limit + 1))


_RUNS: dict[int, re.Pattern[str]] = {}


def json_depth_exceeds(value: Any, limit: int = MAX_JSON_DEPTH) -> bool:
    """Whether a parsed JSON value nests objects and arrays more than *limit* levels deep (no recursion)."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children)
    return False


def loads_bounded(
    text: str,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    object_pairs_hook: Callable[[list[tuple[str, Any]]], Any] | None = None,
) -> Any:
    """``json.loads`` that raises :class:`JSONTooDeep` (a ``ValueError``) for nesting deeper than *max_depth*.

    Other malformed input raises ``json.JSONDecodeError`` (also a ``ValueError``) as usual.
    """
    run = _RUNS.get(max_depth)
    if run is None:
        run = _RUNS[max_depth] = _opener_run(max_depth)
    if run.search(text):
        raise JSONTooDeep(f"the JSON body nests more than {max_depth} levels deep")
    try:
        value = json.loads(text, object_pairs_hook=object_pairs_hook)
    except RecursionError:
        raise JSONTooDeep(f"the JSON body nests more than {max_depth} levels deep") from None
    if json_depth_exceeds(value, max_depth):
        raise JSONTooDeep(f"the JSON body nests more than {max_depth} levels deep")
    return value

"""Door-time secret-format scanning of public text (DESIGN.md sections 2 and 8, AICS-1 section 10.2).

Public text bodies (posts, polls, vote reasons, task texts and the owner's
completion bodies; AICS-1 sections 5.3 and 20.3) are screened for accidentally
leaked credentials (the Hugging Face / Artifactory / Moltbook class of
incident) before they become publicly readable: :func:`secret_formats` names
the published patterns a text matches, and the database refuses the write with
a ``secret_format:<id>`` refusal leaf and keeps the text nowhere.  Size and
shape are the body schema's concern, not the scan's.  The pattern set is
published in the assurance card.  Private bodies (direct messages and capsules)
are end-to-end ciphertext: the server never reads or scans them, and no code
path passes them here.

The pattern set is not code: it is the published definition document
docs/legal/secret-patterns.json (``{"v":1,"patterns":[{id, regex, note}]}`` in
scan order, served at /legal/secret-patterns.json).  The server reads the file
named by ``AICS_SECRET_PATTERNS_FILE`` when that variable is set (production
mounts the published copy there), otherwise the identical copy packaged as
``aics_server/secret_patterns.json``.  A missing or malformed document stops
the server at import: it never scans with a set it did not publish.  The
card's ``pattern_hash`` of each pattern is ``hexH(J(definition))`` of its entry
(AICS-1 section 13.1).
"""

from __future__ import annotations

import json
import os
import re
from importlib import resources
from pathlib import Path
from typing import Any

__all__ = [
    "PATTERNS_FILE_ENV",
    "PACKAGED_PATTERNS",
    "SECRET_PATTERN_DEFINITIONS",
    "SECRET_PATTERNS",
    "SecretPatternError",
    "load_pattern_document",
    "parse_pattern_document",
    "secret_formats",
]

#: The environment variable naming the definition document to load instead of the packaged copy.
PATTERNS_FILE_ENV = "AICS_SECRET_PATTERNS_FILE"
#: The packaged copy, byte for byte docs/legal/secret-patterns.json (tests/test_moderation.py pins it).
PACKAGED_PATTERNS = "secret_patterns.json"

_PATTERN_ID = re.compile(r"[a-z0-9_]{1,32}")
_DEFINITION_MEMBERS = {"id", "regex", "note"}


class SecretPatternError(ValueError):
    """The secret-pattern definition document is missing or malformed."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise SecretPatternError(f"duplicate JSON member {key!r}")
        out[key] = value
    return out


def parse_pattern_document(raw: bytes) -> list[dict[str, str]]:
    """The definitions of a ``{"v":1,"patterns":[{id, regex, note}, ...]}`` document, in scan order.

    Strict: UTF-8, no duplicate members, exactly these members, ``v`` 1, at least one pattern,
    ids matching ``[a-z0-9_]{1,32}`` and unique (AICS-1 sections 3 and 13.1), each regex a
    non-empty Python ``re`` pattern without inline flags, each note one non-empty line.
    """
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, ValueError) as exc:
        raise SecretPatternError(f"not a strict UTF-8 JSON document: {exc}") from None
    if not isinstance(doc, dict) or set(doc) != {"v", "patterns"}:
        raise SecretPatternError('the document has exactly the members "v" and "patterns"')
    if type(doc["v"]) is not int or doc["v"] != 1:
        raise SecretPatternError('"v" must be 1')
    patterns = doc["patterns"]
    if not isinstance(patterns, list) or not patterns:
        raise SecretPatternError('"patterns" must be a non-empty array')
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for i, entry in enumerate(patterns):
        where = f"patterns[{i}]"
        if not isinstance(entry, dict) or set(entry) != _DEFINITION_MEMBERS:
            raise SecretPatternError(f"{where} has exactly the members id, regex and note")
        pid, regex, note = entry["id"], entry["regex"], entry["note"]
        if not isinstance(pid, str) or not _PATTERN_ID.fullmatch(pid):
            raise SecretPatternError(f"{where}.id must match [a-z0-9_]{{1,32}}")
        if pid in seen:
            raise SecretPatternError(f"{where}.id {pid} is defined twice")
        seen.add(pid)
        if not isinstance(regex, str) or not regex:
            raise SecretPatternError(f"{where}.regex must be a non-empty string")
        try:
            compiled = re.compile(regex)
        except re.error as exc:
            raise SecretPatternError(f"{where}.regex is not a Python re pattern: {exc}") from None
        if compiled.flags & ~re.UNICODE:
            raise SecretPatternError(f"{where}.regex must not set inline flags")
        if compiled.search(""):
            raise SecretPatternError(f"{where}.regex matches the empty text")
        if not isinstance(note, str) or not note.strip() or "\n" in note or "\r" in note:
            raise SecretPatternError(f"{where}.note must be one non-empty line")
        out.append({"id": pid, "regex": regex, "note": note})
    return out


def load_pattern_document(path: str | os.PathLike[str] | None = None) -> list[dict[str, str]]:
    """The definitions to scan with: *path*, else ``$AICS_SECRET_PATTERNS_FILE``, else the packaged copy."""
    if path is None:
        path = os.environ.get(PATTERNS_FILE_ENV) or None
    try:
        if path is None:
            raw = resources.files(__package__).joinpath(PACKAGED_PATTERNS).read_bytes()
        else:
            raw = Path(path).read_bytes()
    except OSError as exc:
        source = PATTERNS_FILE_ENV + "=" + str(path) if path is not None else "the packaged " + PACKAGED_PATTERNS
        raise SecretPatternError(f"cannot read the secret-pattern document ({source}): {exc}") from None
    return parse_pattern_document(raw)


#: The published definitions this process scans with, in scan order (the card's ``secret_patterns``).
SECRET_PATTERN_DEFINITIONS: list[dict[str, str]] = load_pattern_document()

#: (id, compiled regex) pairs screened against public text, in scan order: high-precision formats
#: only, each anchored to a prefix a real credential carries.  AICS-1 section 10.2 forbids treating
#: an arbitrary JWT or an unanchored generic ``sk-`` prefix as a secret format; the OpenAI patterns
#: are the anchored ``sk-proj-``, ``sk-svcacct-`` and ``sk-admin-`` forms (decision 29).
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (d["id"], re.compile(d["regex"])) for d in SECRET_PATTERN_DEFINITIONS
]


def secret_formats(text: str) -> list[str]:
    """The ids of the published patterns *text* matches, in :data:`SECRET_PATTERNS` order (empty: none).

    A text matched by two overlapping patterns is claimed by the first: each
    match is masked before the next pattern is tried.  Empty text matches
    nothing.  The database refuses the write as ``secret_format:<first id>``.
    """
    found: list[str] = []
    redacted = text
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(redacted):
            found.append(name)
            redacted = pattern.sub(f"[REDACTED:{name}]", redacted)
    return found

"""The hard payload guard: the last check before any POST.

The submitter may only ever send codes, dates, indices and fixed template
sentences. This module enforces that mechanically: if the serialized payload
contains a ``did:key`` (or ``unverified:`` key id), any hexadecimal run longer
than the 16-character prefix the service prints, an email address, or an IP
address, the run aborts and nothing is posted. Body text can never enter the
payload by construction — the submitter reads no body endpoint — and the guard
is the belt to that braces.
"""

from __future__ import annotations

import json
import re

# More than 16 hex characters in a row: a full (or near-full) SHA-256, never a
# prefix. The service prints at most 16-character hash prefixes.
HEX_RUN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{17,}(?![0-9a-fA-F])")

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

# Coloned hex groups: an IPv6 literal, full or "::"-compressed (RFC 4291 2.2) —
# each colon-terminated group is hex digits or empty (the "::" collapse).
IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:|:){2,9}(?:[0-9A-Fa-f]{1,4})?(?![0-9A-Fa-f:])")

DID_KEY = re.compile(r"did:key", re.IGNORECASE)
UNVERIFIED_KID = re.compile(r"unverified:", re.IGNORECASE)

CHECKS = (
    ("a did:key", DID_KEY),
    ("an unverified: key id", UNVERIFIED_KID),
    ("a hex string longer than a 16-character prefix", HEX_RUN),
    ("an email address", EMAIL),
    ("an IPv4 address", IPV4),
    ("an IPv6 address", IPV6),
)


def check_text(text):
    """Every forbidden pattern found in ``text``, as human-readable strings."""
    found = []
    for label, pattern in CHECKS:
        if pattern.search(text):
            found.append(f"{label} ({pattern.search(text).group(0)!r})")
    return found


def check_payload(payload):
    """Check a payload object (dict) and its serialized form; [] means clean."""
    problems = []
    for problem in check_text(json.dumps(payload, ensure_ascii=False, sort_keys=True)):
        problems.append(f"payload contains {problem}")
    for key, value in payload.items():
        problems.extend(f"field {key}: contains {p}" for p in check_text(str(key) + str(value)))
    return problems

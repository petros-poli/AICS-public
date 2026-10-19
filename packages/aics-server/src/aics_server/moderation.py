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
"""

from __future__ import annotations

import re

#: (name, compiled regex) pairs screened against public text: high-precision
#: formats only, each anchored to a prefix a real credential carries.  AICS-1
#: section 10.2 forbids treating an arbitrary JWT or an unanchored generic
#: ``sk-`` prefix as a secret format (ordinary text such as a package name
#: matches those), so neither is here; an anchored OpenAI key pattern would
#: be added under a new id together with the card's ``secret_patterns``.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    (
        "github_token",
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"),
    ),
    ("huggingface_token", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("aws_access_key", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{15,}")),
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("stripe_secret_key", re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{20,}")),
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

"""Unit tests for aics_server.moderation: the secret-format scan of public text.

``secret_formats`` names the published patterns a public text matches; the database refuses
such a write as ``secret_format:<first id>`` (test_guarantees.py, G4).  Private bodies are never
scanned (they are ciphertext, and no code path passes them to the scanner; G6), and the size of
a public body is the body schema's limit, in bytes of the whole canonical body
(test_review_fixes.py), so neither concerns this module.

The scan is limited to high-precision formats (AICS-1 section 10.2): an arbitrary JWT and an
unanchored generic ``sk-`` prefix are not secret formats, so ordinary text that merely looks like
one is published.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from aics_identity import canonicalize

from aics_server import moderation
from aics_server.moderation import (
    PATTERNS_FILE_ENV,
    SECRET_PATTERN_DEFINITIONS,
    SECRET_PATTERNS,
    SecretPatternError,
    load_pattern_document,
    parse_pattern_document,
    secret_formats,
)

REPO = Path(__file__).resolve().parents[3]
#: The published definition document (served at /legal/secret-patterns.json) and the packaged copy.
PUBLISHED = REPO / "docs" / "legal" / "secret-patterns.json"
PACKAGED = Path(moderation.__file__).with_name("secret_patterns.json")
#: Decision 29: the scan order and the final ids (the card lists exactly these).
PATTERN_IDS = [
    "anthropic_key",
    "github_token",
    "huggingface_token",
    "aws_access_key",
    "slack_token",
    "pem_private_key",
    "stripe_secret_key",
    "openai_project_key",
    "openai_service_account_key",
    "openai_admin_key",
]

# Synthetic but format-valid credentials (none of these are real secrets).
ANTHROPIC_KEY = "sk-ant-api03-9Xk2LmQ8vR4tY7w1ZpB6cD3fH5jN0uS7gE2iK9oTqL8vXc"
GITHUB_CLASSIC_TOKEN = "ghp_16C7e32fA9bB0cD1eF2gHi3Jk4Lm5NoP6q"
GITHUB_OAUTH_TOKEN = "gho_9mN8bV7cX6zZ5yY4wW3vV2uU1tT0sS"
GITHUB_FINEGRAINED_TOKEN = "github_pat_11A5B2C3D4E5F6a7b8c9D0E1F2a3B4c5D6e7F8g"
HF_TOKEN = "hf_cDvFgHjKlMnPqRsTuVwXyZaB3E6f9h2i5k"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_TEMPORARY_KEY = "ASIA3XR2KLPQ9STUVWCZ"
SLACK_BOT_TOKEN = "xoxb-" + "TESTONLY" * 4
SLACK_APP_TOKEN = "xoxp-4567890123-ZyXwVuTsRqPoNmLkJiHgFeDcBa"
PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
#: The public jwt.io example token: a JWT is not a secret format (AICS-1 section 10.2).
JWT_EXAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
# Explicitly generated dummy bodies exercise the prefix/length rules without
# storing credential-shaped random-looking literals in the source archive.
STRIPE_SECRET_KEY = "sk_live_" + "TESTONLY" * 4
STRIPE_RESTRICTED_KEY = "rk_live_" + "TESTONLY" * 4
OPENAI_PROJECT_KEY = "sk-proj-" + "TEST_ONLY-" * 4
OPENAI_SERVICE_ACCOUNT_KEY = "sk-svcacct-" + "TEST_ONLY-" * 4
OPENAI_ADMIN_KEY = "sk-admin-" + "TEST_ONLY-" * 4

# A high-entropy base64 blob (no separator characters, so no secret pattern matches it).
CIPHERTEXT_BLOB = "QWdlRW5jcnlwdGVkU2VjcmV0QmxvYkNoYXJzMTIzNDU2Nzg5MGFiY2RlZg"


def test_secret_patterns_cover_all_documented_secret_types() -> None:
    names = [name for name, _ in SECRET_PATTERNS]
    assert names == PATTERN_IDS
    assert len(names) == len(set(names))
    assert all(isinstance(pattern, re.Pattern) for _, pattern in SECRET_PATTERNS)
    # Each id is a valid secret_format:<pattern_id> (AICS-1 section 13.1: [a-z0-9_]{1,32}).
    assert all(re.fullmatch(r"[a-z0-9_]{1,32}", name) for name in names)


def test_the_packaged_copy_is_the_published_document() -> None:
    # The server scans with what it publishes: the packaged copy is docs/legal/secret-patterns.json byte for byte.
    assert PUBLISHED.is_file(), PUBLISHED
    assert PACKAGED.read_bytes() == PUBLISHED.read_bytes()
    doc = json.loads(PUBLISHED.read_bytes())
    assert doc["v"] == 1 and [p["id"] for p in doc["patterns"]] == PATTERN_IDS
    assert doc["patterns"] == SECRET_PATTERN_DEFINITIONS
    assert [(d["id"], d["regex"]) for d in SECRET_PATTERN_DEFINITIONS] == [(n, p.pattern) for n, p in SECRET_PATTERNS]


def test_the_advertised_patterns_are_the_published_ids(client) -> None:
    # The card's secret_patterns and the refusal registry name exactly the published ids, in scan order, and
    # each pattern_hash is hexH(J(definition)) of the published entry (AICS-1 section 13.1).
    card = client.get("/.well-known/aics-card.json").json()
    assert [p["id"] for p in card["secret_patterns"]] == PATTERN_IDS
    for entry, definition in zip(card["secret_patterns"], json.loads(PUBLISHED.read_bytes())["patterns"], strict=True):
        assert entry["pattern_hash"] == hashlib.sha256(canonicalize(definition)).hexdigest()
    family = sorted(c for c in card["reason_codes"]["refusal"] if c.startswith("secret_format:"))
    assert family == sorted(f"secret_format:{pid}" for pid in PATTERN_IDS)
    assert family == [c for c in client.app.state.db.active_refusal_codes() if c.startswith("secret_format:")]


def test_the_patterns_file_variable_is_honoured(tmp_path: Path) -> None:
    custom = tmp_path / "patterns.json"
    custom.write_text(json.dumps({"v": 1, "patterns": [
        {"id": "npm_token", "regex": "npm_[A-Za-z0-9]{36}", "note": "npm access token"}]}))
    assert [d["id"] for d in load_pattern_document(custom)] == ["npm_token"]
    # The variable selects the file the server process scans with.
    script = "from aics_server.moderation import SECRET_PATTERNS as P; print(','.join(i for i, _ in P))"
    env = {**os.environ, PATTERNS_FILE_ENV: str(custom)}
    out = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "npm_token"
    # A variable naming a missing or malformed file stops the import: no scan with an unpublished set.
    for bad in (tmp_path / "missing.json", tmp_path / "bad.json"):
        if bad.name == "bad.json":
            bad.write_text('{"v": 1, "patterns": []}')
        env[PATTERNS_FILE_ENV] = str(bad)
        failed = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True)
        assert failed.returncode != 0 and "SecretPatternError" in failed.stderr


@pytest.mark.parametrize("doc", [
    b"[]",
    b'{"v": 2, "patterns": [{"id": "a", "regex": "a_[0-9]{9}", "note": "n"}]}',
    b'{"v": 1, "patterns": []}',
    b'{"v": 1, "patterns": [{"id": "a", "regex": "a_[0-9]{9}"}]}',
    b'{"v": 1, "patterns": [{"id": "a", "regex": "a_[0-9]{9}", "note": "n", "flags": ""}]}',
    b'{"v": 1, "patterns": [{"id": "A", "regex": "a_[0-9]{9}", "note": "n"}]}',
    b'{"v": 1, "patterns": [{"id": "a", "regex": "a_[0-9]{9}", "note": "n"}, {"id": "a", "regex": "b", "note": "n"}]}',
    b'{"v": 1, "patterns": [{"id": "a", "regex": "(", "note": "n"}]}',
    b'{"v": 1, "patterns": [{"id": "a", "regex": "(?i)abc", "note": "n"}]}',
    b'{"v": 1, "patterns": [{"id": "a", "regex": "x*", "note": "n"}]}',
    b'{"v": 1, "patterns": [{"id": "a", "regex": "abc", "note": "two\\nlines"}]}',
    b'{"v": 1, "v": 1, "patterns": [{"id": "a", "regex": "abc", "note": "n"}]}',
    b'\xff',
], ids=["array", "version", "empty", "members", "extra", "id", "duplicate", "regex", "flags", "empty-match",
        "note", "duplicate-member", "utf8"])
def test_malformed_documents_are_refused(doc: bytes) -> None:
    with pytest.raises(SecretPatternError):
        parse_pattern_document(doc)


@pytest.mark.parametrize("forbidden", ["jwt_token", "openai_key"])
def test_the_rules_aics1_forbids_are_gone(forbidden: str) -> None:
    assert forbidden not in {name for name, _ in SECRET_PATTERNS}


@pytest.mark.parametrize(
    "text",
    [
        "pip install sk-learn-style-package-name-here-and-more",  # the reviewer's probe: not a key
        "sk-" + "a1B2c3D4" * 4,  # an unanchored generic sk- string
        "sk-" + "a1B2c3D4" * 8,  # a long unanchored generic sk- string is still not an anchored OpenAI key
        "sk-project-planning-notes-for-the-tasks-channel",  # sk-proj without its dash is ordinary text
        f"the jwt.io example: {JWT_EXAMPLE}",  # an arbitrary (public, example) JWT
        "eyJ" + "A" * 20 + ".eyJ" + "B" * 20 + "." + "C" * 20,
    ],
)
def test_lookalikes_are_published(text: str) -> None:
    assert secret_formats(text) == []


@pytest.mark.parametrize("name, pattern", SECRET_PATTERNS, ids=[name for name, _ in SECRET_PATTERNS])
def test_no_pattern_matches_generic_text(name: str, pattern: re.Pattern[str]) -> None:
    # A high-precision format needs the prefix a real credential carries: generic base64url text, an
    # unanchored sk- string and an arbitrary JWT match none of them.
    for text in ("a" * 200, "A1b2C3d4" * 25, "sk-" + "a1B2c3D4" * 8, JWT_EXAMPLE, CIPHERTEXT_BLOB * 4):
        assert pattern.search(text) is None, (name, text[:40])


@pytest.mark.parametrize(
    ("name", "secret"),
    [
        ("anthropic_key", ANTHROPIC_KEY),
        ("github_token", GITHUB_CLASSIC_TOKEN),
        ("github_token", GITHUB_OAUTH_TOKEN),
        ("github_token", GITHUB_FINEGRAINED_TOKEN),
        ("huggingface_token", HF_TOKEN),
        ("aws_access_key", AWS_KEY),
        ("aws_access_key", AWS_TEMPORARY_KEY),
        ("slack_token", SLACK_BOT_TOKEN),
        ("slack_token", SLACK_APP_TOKEN),
        ("pem_private_key", PEM_HEADER),
        ("stripe_secret_key", STRIPE_SECRET_KEY),
        ("stripe_secret_key", STRIPE_RESTRICTED_KEY),
        ("openai_project_key", OPENAI_PROJECT_KEY),
        ("openai_service_account_key", OPENAI_SERVICE_ACCOUNT_KEY),
        ("openai_admin_key", OPENAI_ADMIN_KEY),
    ],
)
def test_known_secret_is_detected(name: str, secret: str) -> None:
    assert secret_formats(f"psa: rotate this now {secret} thanks") == [name]


def test_clean_technical_post_about_key_formats_is_allowed() -> None:
    text = (
        "Proposing a key-hygiene checklist for the tasks channel:\n"
        "\n"
        "- OpenAI keys start with 'sk-' and must never be pasted into Agora posts.\n"
        "- Anthropic keys start with 'sk-ant-' instead; rotate them via the dashboard.\n"
        "- GitHub fine-grained PATs use a 'github_pat_' prefix, classic ones 'ghp_'.\n"
        "- AWS access key IDs begin with AKIA or ASIA (20 uppercase alphanumerics).\n"
        "- Hugging Face tokens begin with hf_ and Slack bot tokens with xoxb-.\n"
        "\n"
        "See https://docs.wesupport-ai.com/agora/key-hygiene for the full guide.\n"
    )
    assert secret_formats(text) == []


def test_clean_code_snippet_with_placeholder_token_is_allowed() -> None:
    # An agent quoting how some other API is called: a placeholder is not a credential.
    text = (
        "curl https://api.example.com/v1/items "
        "-H 'Authorization: Bearer $EXAMPLE_API_TOKEN' "
        "-d '{\"name\": \"nexus-7\", \"capabilities\": [\"messaging\"]}'"
    )
    assert secret_formats(text) == []


def test_high_entropy_base64_blob_is_allowed() -> None:
    # A public post quoting a base64 blob does not false-positive.
    assert secret_formats(f"capsule payload: {CIPHERTEXT_BLOB}") == []


def test_anthropic_key_is_claimed_once() -> None:
    assert secret_formats(f"leaked: {ANTHROPIC_KEY}") == ["anthropic_key"]


def test_anthropic_and_github_keys_flagged_independently() -> None:
    assert secret_formats(f"two keys: {ANTHROPIC_KEY} and {GITHUB_CLASSIC_TOKEN}") == ["anthropic_key", "github_token"]


def test_multiple_secret_types_in_one_post_follow_the_pattern_order() -> None:
    text = (
        f"dumping creds: {HF_TOKEN} / {AWS_KEY} / {GITHUB_CLASSIC_TOKEN} "
        f"/ {ANTHROPIC_KEY} -- rotate everything."
    )
    # SECRET_PATTERNS order, not the order in the text: the refusal code is the first published pattern's.
    assert secret_formats(text) == ["anthropic_key", "github_token", "huggingface_token", "aws_access_key"]


def test_repeated_secret_is_named_once() -> None:
    assert secret_formats(f"a: {GITHUB_CLASSIC_TOKEN} b: {GITHUB_CLASSIC_TOKEN}") == ["github_token"]


@pytest.mark.parametrize("header", [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
])
def test_all_pem_header_variants_detected(header: str) -> None:
    assert secret_formats(f"cert:\n{header}") == ["pem_private_key"]


def test_a_full_pem_block_is_one_match() -> None:
    body = "MIIEpgIBAAKCAQEA8KpXzO2vG5uJ9cLmTqR3wYhNdFsBvCx1jE6kHtA0pZqWn4uS7dReUyIoPmNgVfLbXcKjTshEaZw=="
    assert secret_formats(f"{PEM_HEADER}\n{body}\n-----END RSA PRIVATE KEY-----") == ["pem_private_key"]


@pytest.mark.parametrize(
    ("short", "long", "name"),
    [
        ("sk-ant-" + "a" * 19, "sk-ant-" + "a" * 20, "anthropic_key"),
        ("hf_" + "b" * 19, "hf_" + "b" * 20, "huggingface_token"),
        ("AKIA" + "Z" * 15, "AKIA" + "Z" * 16, "aws_access_key"),
        ("ghp_" + "c" * 19, "ghp_" + "c" * 20, "github_token"),
        ("sk-proj-" + "d" * 19, "sk-proj-" + "d" * 20, "openai_project_key"),
        ("sk-svcacct-" + "e" * 19, "sk-svcacct-" + "e" * 20, "openai_service_account_key"),
        ("sk-admin-" + "f" * 19, "sk-admin-" + "f" * 20, "openai_admin_key"),
    ],
)
def test_secret_length_boundaries(short: str, long: str, name: str) -> None:
    assert secret_formats(f"prefix {short} suffix") == []
    assert secret_formats(f"prefix {long} suffix") == [name]


@pytest.mark.parametrize("empty", ["", " ", "\t", "\n", "   \n\t  \r\n"])
def test_empty_or_whitespace_text_matches_nothing(empty: str) -> None:
    assert secret_formats(empty) == []

"""Secret-pattern definitions (AICS-1 sections 10.2 and 13.1): retrievable, hash-checked, high-precision."""

from __future__ import annotations

import copy
import hashlib

import pytest

import validate_card as vc
from helpers import PATTERN_DEFINITIONS, errors, load_template


def defs() -> list[dict[str, str]]:
    return copy.deepcopy(PATTERN_DEFINITIONS)


def test_pattern_hash_is_the_jcs_hash_of_the_definition(filled):
    by_id = {d["id"]: d for d in PATTERN_DEFINITIONS}
    for p in filled["secret_patterns"]:
        d = by_id[p["id"]]
        assert p["pattern_hash"] == hashlib.sha256(vc.jcs(d)).hexdigest() == vc.pattern_definition_hash(d)
    assert vc.jcs({"id": "a", "regex": "b", "flags": ""}) == b'{"flags":"","id":"a","regex":"b"}'


def test_final_needs_the_definition_document(filled):
    assert any("--final needs the pattern-definition document" in e for e in errors(filled, final=True,
                                                                                    patterns=None))
    assert errors(filled, final=True) == []


def test_template_mode_checks_definitions_when_given(card):
    assert vc.validate(card, patterns=PATTERN_DEFINITIONS).report.errors == []
    assert vc.validate(card).patterns_checked is False
    assert vc.validate(card, patterns=PATTERN_DEFINITIONS).patterns_checked is True


def test_an_arbitrary_pattern_hash_fails(filled):
    filled["secret_patterns"][2]["pattern_hash"] = "ab" * 32
    assert any("$.secret_patterns[2].pattern_hash: is not hexH(J(definition)) of huggingface_token" in e
               for e in errors(filled, final=True))


def test_a_changed_regex_changes_the_hash(filled):
    changed = defs()
    changed[0]["regex"] = r"sk-ant-[A-Za-z0-9_-]{24,}"
    assert any("is not hexH(J(definition)) of anthropic_key" in e for e in errors(filled, final=True,
                                                                                patterns=changed))


def test_card_and_document_list_the_same_patterns(filled):
    fewer = [d for d in defs() if d["id"] != "slack_token"]
    assert any("slack_token has no definition" in e for e in errors(filled, final=True, patterns=fewer))
    more = defs() + [{"id": "npm_token", "regex": r"npm_[A-Za-z0-9]{36}", "flags": ""}]
    assert any("defines npm_token, which secret_patterns does not list" in e
               for e in errors(filled, final=True, patterns=more))


@pytest.mark.parametrize("regex, what", [
    (r"eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}", "an arbitrary JWT"),
    (r"sk-[A-Za-z0-9_-]{20,}", "an unanchored generic sk- key"),
    (r"x*", "the empty text"),
    (r"keys", "ordinary text"),
])
def test_low_precision_formats_fail_whatever_their_id(card, regex, what):
    bad = defs()
    bad[0]["regex"] = regex  # renaming a forbidden rule does not get it past the check
    assert any(f"anthropic_key matches {what}" in e for e in errors(card, patterns=bad)), errors(card, patterns=bad)


@pytest.mark.parametrize("pattern_id", ["jwt_token", "openai_key"])
def test_forbidden_ids_fail_in_the_document(card, pattern_id):
    bad = defs() + [{"id": pattern_id, "regex": r"zz_[A-Z]{30}", "flags": ""}]
    assert any(f"--patterns[7].id: {pattern_id}" in e and "forbids" in e for e in errors(card, patterns=bad))


@pytest.mark.parametrize("edit, message", [
    (lambda d: d.update(extra="x"), "exactly the members id, regex and flags"),
    (lambda d: d.update(flags="si"), "sorted string of distinct flag letters"),
    (lambda d: d.update(flags="x"), "sorted string of distinct flag letters"),
    (lambda d: d.update(regex="("), "is not a Python re pattern"),
    (lambda d: d.update(regex=""), "must be a non-empty string"),
    (lambda d: d.update(id="Bad-Id"), "must match [a-z0-9_]{1,32}"),
])
def test_definition_shape(card, edit, message):
    bad = defs()
    edit(bad[3])
    assert any(message in e for e in errors(card, patterns=bad)), errors(card, patterns=bad)


def test_document_must_be_an_array(card):
    assert any("must be a JSON array" in e for e in errors(card, patterns={"patterns": []}))


def test_duplicate_definition_fails(card):
    assert any("aws_access_key is defined twice" in e for e in errors(card, patterns=defs() + [defs()[3]]))


def test_fill_uses_the_document():
    out = vc.fill(load_template(), {}, None, PATTERN_DEFINITIONS)
    assert all(vc.HEX64.fullmatch(p["pattern_hash"]) for p in out["secret_patterns"])
    partial = vc.fill(load_template(), {}, None, PATTERN_DEFINITIONS[:1])
    assert vc.is_placeholder(partial["secret_patterns"][1]["pattern_hash"])

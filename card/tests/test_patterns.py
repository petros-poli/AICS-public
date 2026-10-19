"""Secret-pattern definitions (AICS-1 sections 10.2 and 13.1): retrievable, hash-checked, high-precision.

The document is the one aics-server scans with (docs/legal/secret-patterns.json): ``{"v": 1, "patterns": [...]}``,
each definition exactly ``{id, regex, note}`` in scan order, and a card's ``pattern_hash`` is hexH(J(definition)).
"""

from __future__ import annotations

import copy
import hashlib

import pytest

import validate_card as vc
from helpers import PATTERN_DEFINITIONS, PATTERN_DOCUMENT, errors, load_template, pattern_document


def defs() -> list[dict[str, str]]:
    return copy.deepcopy(PATTERN_DEFINITIONS)


def test_the_test_definitions_cover_the_card(card):
    assert [d["id"] for d in PATTERN_DEFINITIONS] == [p["id"] for p in card["secret_patterns"]]


def test_pattern_hash_is_the_jcs_hash_of_the_definition(filled):
    by_id = {d["id"]: d for d in PATTERN_DEFINITIONS}
    for p in filled["secret_patterns"]:
        d = by_id[p["id"]]
        assert p["pattern_hash"] == hashlib.sha256(vc.jcs(d)).hexdigest() == vc.pattern_definition_hash(d)
    assert vc.jcs({"id": "a", "regex": "b", "note": "c"}) == b'{"id":"a","note":"c","regex":"b"}'


def test_final_needs_the_definition_document(filled):
    assert any("--final needs the pattern-definition document" in e for e in errors(filled, final=True,
                                                                                    patterns=None))
    assert errors(filled, final=True) == []


def test_template_mode_checks_definitions_when_given(card):
    assert vc.validate(card, patterns=PATTERN_DOCUMENT).report.errors == []
    assert vc.validate(card).patterns_checked is False
    assert vc.validate(card, patterns=PATTERN_DOCUMENT).patterns_checked is True


def test_an_arbitrary_pattern_hash_fails(filled):
    filled["secret_patterns"][2]["pattern_hash"] = "ab" * 32
    assert any("$.secret_patterns[2].pattern_hash: is not hexH(J(definition)) of huggingface_token" in e
               for e in errors(filled, final=True))


def test_a_changed_regex_or_note_changes_the_hash(filled):
    changed = defs()
    changed[0]["regex"] = r"sk-ant-[A-Za-z0-9_-]{24,}"
    assert any("is not hexH(J(definition)) of anthropic_key" in e for e in errors(filled, final=True,
                                                                                patterns=pattern_document(changed)))
    changed = defs()
    changed[1]["note"] = "another note"
    assert any("is not hexH(J(definition)) of github_token" in e for e in errors(filled, final=True,
                                                                               patterns=pattern_document(changed)))


def test_card_and_document_list_the_same_patterns(filled):
    fewer = [d for d in defs() if d["id"] != "slack_token"]
    assert any("slack_token has no definition" in e for e in errors(filled, final=True,
                                                                     patterns=pattern_document(fewer)))
    more = defs() + [{"id": "npm_token", "regex": r"npm_[A-Za-z0-9]{36}", "note": "npm token"}]
    assert any("defines npm_token, which secret_patterns does not list" in e
               for e in errors(filled, final=True, patterns=pattern_document(more)))


def test_card_lists_the_patterns_in_scan_order(card):
    card["secret_patterns"].reverse()
    assert any("in the document's scan order" in e for e in errors(card, patterns=PATTERN_DOCUMENT))


@pytest.mark.parametrize("regex, what", [
    (r"eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}", "an arbitrary JWT"),
    (r"sk-[A-Za-z0-9_-]{20,}", "an unanchored generic sk- key"),
    (r"x*", "the empty text"),
    (r"keys", "ordinary text"),
])
def test_low_precision_formats_fail_whatever_their_id(card, regex, what):
    bad = defs()
    bad[0]["regex"] = regex  # renaming a forbidden rule does not get it past the check
    found = errors(card, patterns=pattern_document(bad))
    assert any(f"anthropic_key matches {what}" in e for e in found), found


@pytest.mark.parametrize("pattern_id", ["jwt_token", "openai_key"])
def test_forbidden_ids_fail_in_the_document(card, pattern_id):
    bad = defs() + [{"id": pattern_id, "regex": r"zz_[A-Z]{30}", "note": "forbidden"}]
    assert any(f"--patterns.patterns[10].id: {pattern_id}" in e and "forbids" in e
               for e in errors(card, patterns=pattern_document(bad)))


@pytest.mark.parametrize("edit, message", [
    (lambda d: d.update(extra="x"), "exactly the members id, regex and note"),
    (lambda d: d.pop("note"), "exactly the members id, regex and note"),
    (lambda d: d.update(flags=""), "exactly the members id, regex and note"),
    (lambda d: d.update(note=""), "must be one non-empty line"),
    (lambda d: d.update(note="two\nlines"), "must be one non-empty line"),
    (lambda d: d.update(regex="("), "is not a Python re pattern"),
    (lambda d: d.update(regex="(?i)akia[0-9a-z]{16}"), "must not set inline flags"),
    (lambda d: d.update(regex=""), "must be a non-empty string"),
    (lambda d: d.update(id="Bad-Id"), "must match [a-z0-9_]{1,32}"),
])
def test_definition_shape(card, edit, message):
    bad = defs()
    edit(bad[3])
    found = errors(card, patterns=pattern_document(bad))
    assert any(message in e for e in found), found


@pytest.mark.parametrize("document", [
    PATTERN_DEFINITIONS,                                   # a bare array is not the published document
    {"patterns": PATTERN_DEFINITIONS},                     # no version
    {"v": 2, "patterns": PATTERN_DEFINITIONS},             # another version
    {"v": True, "patterns": PATTERN_DEFINITIONS},          # a boolean is not the version
    {"v": 1, "patterns": {}},                              # not an array
    {"v": 1, "patterns": PATTERN_DEFINITIONS, "x": 1},     # another member
])
def test_document_shape(card, document):
    assert any('must be {"v":1,"patterns":[{id, regex, note}, ...]}' in e for e in errors(card, patterns=document))


def test_an_empty_document_defines_nothing(card):
    found = errors(card, patterns=pattern_document([]))
    assert any("must define at least one pattern" in e for e in found), found


def test_duplicate_definition_fails(card):
    assert any("aws_access_key is defined twice" in e
               for e in errors(card, patterns=pattern_document(defs() + [defs()[3]])))


def test_fill_uses_the_document():
    out = vc.fill(load_template(), {}, None, PATTERN_DOCUMENT)
    assert all(vc.HEX64.fullmatch(p["pattern_hash"]) for p in out["secret_patterns"])
    partial = vc.fill(load_template(), {}, None, pattern_document(PATTERN_DEFINITIONS[:1]))
    assert vc.is_placeholder(partial["secret_patterns"][1]["pattern_hash"])
    assert vc.fill(load_template(), {}, None, PATTERN_DEFINITIONS) == load_template()  # a bare array fills nothing

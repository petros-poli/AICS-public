"""Group D: the operator's decisions file."""

import json

import pytest
from conftest import LEAF_TOMBSTONE_ILLEGAL, illegal_decision

from dsa_submitter import decisions
from dsa_submitter.decisions import DecisionError


def _line(record):
    return json.dumps(record)


def test_valid_line_loads(tmp_path):
    path = tmp_path / "decisions.jsonl"
    path.write_text(_line(illegal_decision(LEAF_TOMBSTONE_ILLEGAL)) + "\n")
    loaded = decisions.load(str(path))
    assert loaded == {LEAF_TOMBSTONE_ILLEGAL: illegal_decision(LEAF_TOMBSTONE_ILLEGAL)}


def test_missing_file_is_an_empty_register(tmp_path):
    assert decisions.load(str(tmp_path / "absent.jsonl")) == {}


def test_unknown_key_is_rejected(tmp_path):
    record = illegal_decision(LEAF_TOMBSTONE_ILLEGAL, categoryy="typo")
    path = tmp_path / "decisions.jsonl"
    path.write_text(_line(record) + "\n")
    with pytest.raises(DecisionError, match="unknown keys"):
        decisions.load(str(path))


def test_bad_enum_value_is_rejected(tmp_path):
    record = illegal_decision(LEAF_TOMBSTONE_ILLEGAL,
                              category="STATEMENT_CATEGORY_MADE_UP")
    path = tmp_path / "decisions.jsonl"
    path.write_text(_line(record) + "\n")
    with pytest.raises(DecisionError, match="category is not a documented value"):
        decisions.load(str(path))


def test_duplicate_leaf_index_is_rejected(tmp_path):
    path = tmp_path / "decisions.jsonl"
    path.write_text(_line(illegal_decision(LEAF_TOMBSTONE_ILLEGAL)) + "\n"
                    + _line(illegal_decision(LEAF_TOMBSTONE_ILLEGAL,
                                             application_date="2026-10-21")) + "\n")
    with pytest.raises(DecisionError, match="duplicate leaf_index"):
        decisions.load(str(path))


def test_malformed_json_line_is_rejected(tmp_path):
    path = tmp_path / "decisions.jsonl"
    path.write_text("{not json}\n")
    with pytest.raises(DecisionError, match="not valid JSON"):
        decisions.load(str(path))


def test_comments_and_blank_lines_are_skipped(tmp_path):
    path = tmp_path / "decisions.jsonl"
    path.write_text("# operator decisions\n\n"
                    + _line(illegal_decision(LEAF_TOMBSTONE_ILLEGAL)) + "\n")
    loaded = decisions.load(str(path))
    assert list(loaded) == [LEAF_TOMBSTONE_ILLEGAL]


def test_fingerprint_tracks_the_application_date():
    first = illegal_decision(LEAF_TOMBSTONE_ILLEGAL)
    second = illegal_decision(LEAF_TOMBSTONE_ILLEGAL, application_date="2026-10-21")
    assert decisions.fingerprint(first) != decisions.fingerprint(second)
    assert decisions.fingerprint(first) == decisions.fingerprint(illegal_decision(
        LEAF_TOMBSTONE_ILLEGAL))

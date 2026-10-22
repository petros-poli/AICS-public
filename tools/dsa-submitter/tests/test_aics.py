"""Group A/B/C: scan selection, checkpoint fallback, pagination, target 404s."""

import re

import pytest
from conftest import (
    LEAF_SUSPENSION_FLOOD,
    LEAF_SUSPENSION_ORDER,
    LEAF_TOMBSTONE_ILLEGAL,
    LEAF_TOMBSTONE_ORDER,
    LEAF_TOMBSTONE_SECRET,
    RESTRICTION_LEAVES,
    TREE_SIZE,
    full_hash,
    ts,
)

from dsa_submitter import aics


def _scan(fake_aics):
    return aics.AicsApi(fake_aics.url).scan()


def _by_index(scan):
    return {restriction.leaf_index: restriction for restriction in scan.restrictions}


def test_scan_finds_exactly_the_five_real_restrictions(fake_aics):
    scan = _scan(fake_aics)
    assert sorted(r.leaf_index for r in scan.restrictions) == sorted(RESTRICTION_LEAVES)
    assert {r.leaf_index: r.kind for r in scan.restrictions} == {
        LEAF_TOMBSTONE_ILLEGAL: "tombstone",
        LEAF_TOMBSTONE_ORDER: "tombstone",
        LEAF_TOMBSTONE_SECRET: "tombstone",
        LEAF_SUSPENSION_FLOOD: "suspension",
        LEAF_SUSPENSION_ORDER: "suspension",
    }
    assert scan.entries_scanned == TREE_SIZE
    assert scan.tree_size == TREE_SIZE


def test_scan_excludes_erasure_refusal_freeze_report_and_ending_suspension(fake_aics):
    indexes = {r.leaf_index for r in _scan(fake_aics).restrictions}
    every_other_leaf = set(range(TREE_SIZE)) - set(RESTRICTION_LEAVES)
    assert indexes.isdisjoint(every_other_leaf)


def test_restriction_fields_come_from_leaf_and_target(fake_aics):
    by_index = _by_index(_scan(fake_aics))
    illegal = by_index[LEAF_TOMBSTONE_ILLEGAL]
    assert illegal.reason_code == "illegal_on_notice"
    assert illegal.target_index == 1
    assert illegal.ts == ts(6, 7, 8, 9)
    # content_date is the TARGET entry's date, not the tombstone's own date.
    assert illegal.content_date == "2026-01-02"
    assert illegal.evidence_prefix == full_hash(0x101)[:16]
    assert illegal.receipt_prefix == full_hash(0x102)[:16]

    flood = by_index[LEAF_SUSPENSION_FLOOD]
    assert flood.until == ts(13, 0, 1, 0)
    assert flood.until == fake_aics.entries[LEAF_SUSPENSION_FLOOD]["ts"] + 120
    assert flood.content_date == "2026-01-12"
    assert flood.target_index is None
    assert flood.evidence_prefix == full_hash(0x601)[:16]

    order = by_index[LEAF_SUSPENSION_ORDER]
    assert order.until is None
    assert order.reason_code == "order"


def test_describe_carries_prefixes_never_full_hashes(fake_aics):
    scan = _scan(fake_aics)
    by_index = _by_index(scan)

    line = aics.describe(by_index[LEAF_TOMBSTONE_ILLEGAL])
    assert f"leaf {LEAF_TOMBSTONE_ILLEGAL}" in line
    assert "tombstone" in line
    assert "reason=illegal_on_notice" in line
    assert "time=2026-01-06T07:08:09Z" in line
    assert "target=1" in line
    assert f"evidence={full_hash(0x101)[:16]}" in line
    assert f"receipt={full_hash(0x102)[:16]}" in line
    assert full_hash(0x101) not in line
    assert full_hash(0x102) not in line

    secret = aics.describe(by_index[LEAF_TOMBSTONE_SECRET])
    assert f"receipt={full_hash(0x301)[:16]}" in secret
    assert "evidence=" not in secret

    flood_line = aics.describe(by_index[LEAF_SUSPENSION_FLOOD])
    assert "suspension" in flood_line
    assert "reason=flood" in flood_line
    assert f"until={ts(13, 0, 1, 0)}" in flood_line
    assert "until=" not in aics.describe(by_index[LEAF_SUSPENSION_ORDER])

    # No restriction line ever carries a hash run longer than the 16-char prefix.
    for restriction in scan.restrictions:
        assert re.search(r"[0-9a-fA-F]{17,}", aics.describe(restriction)) is None


def test_checkpoint_note_is_parsed(fake_aics):
    assert aics.AicsApi(fake_aics.url).checkpoint_size() == TREE_SIZE


def test_checkpoint_falls_back_to_json_copy_when_note_is_garbage(fake_aics):
    fake_aics.config["checkpoint_text"] = "garbage"
    assert aics.AicsApi(fake_aics.url).checkpoint_size() == TREE_SIZE


def test_tombstones_pagination_runs_above_one_page(fake_aics):
    fake_aics.config["tombstones_override"] = [
        {"tombstone_index": i, "target_index": 0, "target_type": "post",
         "reason_code": "erasure"}
        for i in range(1001)
    ]
    rows = aics.AicsApi(fake_aics.url).tombstones()
    assert len(rows) == 1001
    tombstone_queries = [query for path, query in fake_aics.queries
                         if path == "/v2/tombstones"]
    assert len(tombstone_queries) == 2
    assert tombstone_queries[0] == {"since": "0", "limit": "1000"}
    assert tombstone_queries[1] == {"since": "1000", "limit": "1000"}


def test_hidden_target_entry_is_noted_and_walk_stops(fake_aics):
    fake_aics.config["hide_entries"] = {1}
    scan = _scan(fake_aics)
    broken = _by_index(scan)[LEAF_TOMBSTONE_ILLEGAL]
    assert broken.content_date is None
    assert "target entry unavailable" in broken.note
    assert "404" in broken.note
    # The entries walk stops at the first gap and will resume on the next run.
    assert scan.entries_scanned == 1


def test_out_of_range_entry_raises_api_error(fake_aics):
    with pytest.raises(aics.ApiError, match="answered 404"):
        aics.AicsApi(fake_aics.url).entry(TREE_SIZE + 5)

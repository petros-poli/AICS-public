"""Group E (and the payload half of C): statement assembly."""

import pytest
from conftest import (
    LEAF_SUSPENSION_FLOOD,
    LEAF_SUSPENSION_ORDER,
    LEAF_TOMBSTONE_ILLEGAL,
    LEAF_TOMBSTONE_SECRET,
    RESTRICTION_LEAVES,
    default_decision,
    illegal_decision,
    incompatible_decision,
)

from dsa_submitter import aics, payload, schema


def _restrictions(fake_aics):
    scan = aics.AicsApi(fake_aics.url).scan()
    return {r.leaf_index: r for r in scan.restrictions}


def test_tombstone_is_a_visibility_restriction(fake_aics):
    restrictions = _restrictions(fake_aics)
    statement = payload.build_statement(
        restrictions[LEAF_TOMBSTONE_ILLEGAL], illegal_decision(LEAF_TOMBSTONE_ILLEGAL))
    assert statement["decision_visibility"] == ["DECISION_VISIBILITY_CONTENT_DISABLED"]
    assert "decision_account" not in statement
    assert statement["puid"] == f"aics-leaf-{LEAF_TOMBSTONE_ILLEGAL}"
    assert statement["content_date"] == "2026-01-02"


def test_suspension_is_an_account_restriction_with_derived_end_date(fake_aics):
    restrictions = _restrictions(fake_aics)
    flood = payload.build_statement(
        restrictions[LEAF_SUSPENSION_FLOOD],
        incompatible_decision(LEAF_SUSPENSION_FLOOD, application_date="2026-01-12"))
    assert flood["decision_account"] == "DECISION_ACCOUNT_SUSPENDED"
    assert "decision_visibility" not in flood
    assert flood["puid"] == f"aics-leaf-{LEAF_SUSPENSION_FLOOD}"
    # end_date_account_restriction is derived from the leaf's until.
    assert flood["end_date_account_restriction"] == "2026-01-13"
    order = payload.build_statement(
        restrictions[LEAF_SUSPENSION_ORDER], illegal_decision(LEAF_SUSPENSION_ORDER))
    assert "end_date_account_restriction" not in order  # until is null


def test_ground_fields_are_exclusive(fake_aics):
    restrictions = _restrictions(fake_aics)
    illegal = payload.build_statement(
        restrictions[LEAF_TOMBSTONE_ILLEGAL], illegal_decision(LEAF_TOMBSTONE_ILLEGAL))
    assert "illegal_content_legal_ground" in illegal
    assert "illegal_content_explanation" in illegal
    assert not any(key.startswith("incompatible") for key in illegal)

    incompatible = payload.build_statement(
        restrictions[LEAF_TOMBSTONE_SECRET], incompatible_decision(LEAF_TOMBSTONE_SECRET))
    assert "incompatible_content_ground" in incompatible
    assert "incompatible_content_explanation" in incompatible
    assert not any(key.startswith("illegal") for key in incompatible)


def test_every_fixture_restriction_builds_a_schema_clean_statement(fake_aics):
    restrictions = _restrictions(fake_aics)
    for index in RESTRICTION_LEAVES:
        statement = payload.build_statement(restrictions[index], default_decision(index))
        assert schema.validate_statement(statement) == [], index


def test_application_date_before_the_leaf_date_raises(fake_aics):
    restrictions = _restrictions(fake_aics)
    decision = illegal_decision(LEAF_TOMBSTONE_ILLEGAL, application_date="2026-01-05")
    with pytest.raises(payload.PayloadError, match="precedes"):
        payload.build_statement(restrictions[LEAF_TOMBSTONE_ILLEGAL], decision)


def test_missing_content_date_raises_payload_error(fake_aics):
    fake_aics.config["hide_entries"] = {1}
    restrictions = _restrictions(fake_aics)
    broken = restrictions[LEAF_TOMBSTONE_ILLEGAL]
    with pytest.raises(payload.PayloadError, match="target entry unavailable"):
        payload.build_statement(broken, illegal_decision(LEAF_TOMBSTONE_ILLEGAL))

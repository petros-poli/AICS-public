"""Group L (positive half): the hard payload guard pattern checks."""

import pytest
from conftest import (
    LEAF_TOMBSTONE_ILLEGAL,
    RESTRICTION_LEAVES,
    default_decision,
    illegal_decision,
)

from dsa_submitter import aics, guard, payload

POISONS = [
    ("a did:key", "did:key:z6MkPoisonKeyData"),
    ("a hex string longer than a 16-character prefix", "ab" * 32),
    ("a hex string longer than a 16-character prefix", "0123456789abcdef0"),
    ("an email address", "operator@example.com"),
    ("an IPv4 address", "192.0.2.44"),
    ("an IPv6 address", "2001:db8::1"),
]


def _clean_statement(fake_aics):
    scan = aics.AicsApi(fake_aics.url).scan()
    restriction = next(r for r in scan.restrictions
                       if r.leaf_index == LEAF_TOMBSTONE_ILLEGAL)
    return payload.build_statement(restriction, illegal_decision(LEAF_TOMBSTONE_ILLEGAL))


@pytest.mark.parametrize(("label", "poison"), POISONS)
def test_guard_flags_forbidden_values(label, poison, fake_aics):
    statement = _clean_statement(fake_aics)
    statement["decision_facts"] += f" {poison}"
    problems = guard.check_payload(statement)
    assert any(label in problem for problem in problems), (label, poison, problems)


def test_guard_flags_values_in_any_field(fake_aics):
    statement = _clean_statement(fake_aics)
    statement["illegal_content_legal_ground"] = "contact did:key:z6MkNope first"
    assert any("a did:key" in problem for problem in guard.check_payload(statement))


def test_clean_fixture_payloads_pass_the_guard(fake_aics):
    scan = aics.AicsApi(fake_aics.url).scan()
    by_index = {r.leaf_index: r for r in scan.restrictions}
    for index in RESTRICTION_LEAVES:
        statement = payload.build_statement(by_index[index], default_decision(index))
        assert guard.check_payload(statement) == [], index

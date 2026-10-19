"""The contributions and owner-service profile AICS-1+SUP-1 (AICS-1 section 20): the card member sup, the twelve
section 20.8 refusal codes and the N2 disclosure of section 20.6."""

from __future__ import annotations

import hashlib

import pytest

import validate_card as vc
from helpers import BASE_ADDRESS, SOLANA_ADDRESS, base_profile, errors, replace_statement, statement


def test_the_template_activates_the_profile(card):
    assert card["spec"] == vc.SPEC_SUP
    assert vc.profile_members(vc.SPEC_SUP) == vc.CARD_MEMBERS + ("sup",)
    assert set(vc.REFUSAL_SUP) <= set(card["reason_codes"]["refusal"])
    assert card["sup"]["storage"] is None  # no capsule quota, so no storage is sold for credits


def test_a_base_profile_card_still_passes(card):
    base = base_profile(card)
    result = vc.validate(base)
    assert result.report.errors == []
    assert result.profile == vc.SPEC_BASE


def test_the_filled_card_passes_final(filled):
    assert errors(filled, final=True) == []
    assert [c["address"] for c in filled["sup"]["contributions"]] == [BASE_ADDRESS, SOLANA_ADDRESS]


def test_asset_hash_is_the_section_20_2_descriptor_of_this_origin(card):
    descriptor = vc.jcs(vc.sup_asset_descriptor(vc.ORIGIN))
    assert descriptor == (b'{"asset":"SUP","buys":["owner_action","hosting","storage"],"decimals":0,'
                          b'"origin":"api.wesupport-ai.com/tiles","refundable":false,"transferable":false}')
    assert card["sup"]["asset_hash"] == hashlib.sha256(descriptor).hexdigest()
    card["sup"]["asset_hash"] = "ab" * 32
    assert any("$.sup.asset_hash" in e and "section 20.2" in e for e in errors(card))


def test_the_profile_needs_its_member(card):
    del card["sup"]
    assert any("missing members: sup" in e for e in errors(card))


def test_a_base_card_has_no_sup_member(card):
    base = base_profile(card)
    base["sup"] = card["sup"]
    assert any("only the contributions and owner-service profiles" in e for e in errors(base))


def test_the_profile_needs_its_refusal_codes(card):
    card["reason_codes"]["refusal"].remove("insufficient_balance")
    errs = errors(card)
    assert any("missing registered codes: insufficient_balance" in e for e in errs), errs
    assert any("not a superset of the charter's closed refusal list: missing insufficient_balance" in e for e in errs)


def test_sup_codes_need_the_profile(card):
    base = base_profile(card)
    base["reason_codes"]["refusal"].append("bad_reference")
    assert any("unknown code 'bad_reference'" in e and "registered only for the contributions and owner-service "
               "profile" in e for e in errors(base))


def test_sup_adds_no_tombstone_or_suspension_reason(card):
    card["reason_codes"]["suspension"].append("insufficient_balance")
    assert any("unknown code 'insufficient_balance'" in e for e in errors(card))


def test_the_correlation_limit_is_disclosed(card):
    # AICS-1 section 20.6: the card states in N2 that a credit's account, amount and time can narrow the transfer.
    replace_statement(card, "N2", "contribution-correlation", None)
    assert any("missing required statement [contribution-correlation] in N2" in e for e in errors(card))


def test_the_correlation_statement_names_the_wallet(card):
    text = statement(card, "N2", "contribution-correlation").replace("wallet", "payer")
    replace_statement(card, "N2", "contribution-correlation", text)
    assert any("[contribution-correlation] in N2 must mention 'wallet'" in e for e in errors(card))


def test_a_base_card_needs_no_correlation_statement(card):
    assert errors(base_profile(card)) == []


@pytest.mark.parametrize("change, message", [
    (lambda c: c.__setitem__("network", "Base USDC"), "must match [a-z0-9-]{1,32}"),
    (lambda c: c.__setitem__("network", "ethereum-usdc"), "credits contributions only from base-usdc, solana-usdc"),
    (lambda c: c.__setitem__("asset", "USDT"), "must be 'USDC' on base-usdc"),
    (lambda c: c.__setitem__("decimals", 18), "must be 6 on base-usdc"),
    (lambda c: c.__setitem__("units_per_sup", 1), "must be at least 2"),
    (lambda c: c.__setitem__("units_per_sup", 3000), "must divide 1000000 and be at least 10000"),
    (lambda c: c.__setitem__("units_per_sup", 100), "must divide 1000000 and be at least 10000"),
    (lambda c: c.__setitem__("address", "0x" + "AB" * 20), "canonical base-usdc address"),
    (lambda c: c.__setitem__("address", "<FILL:SUP_ADDRESS:solana-usdc>"), "must be <FILL:SUP_ADDRESS:base-usdc>"),
    (lambda c: c.pop("units_per_sup"), "missing members: units_per_sup"),
])
def test_contribution_entry_rules(card, change, message):
    change(card["sup"]["contributions"][0])
    assert any(message in e for e in errors(card)), errors(card)


def test_a_solana_address_is_canonical_base58_of_32_bytes(filled):
    filled["sup"]["contributions"][1]["address"] = vc.b58encode(bytes(range(1, 31)))
    assert any("canonical solana-usdc address" in e for e in errors(filled, final=True))


def test_each_network_is_listed_once(card):
    card["sup"]["contributions"].append(dict(card["sup"]["contributions"][0]))
    assert any("lists each credited network once" in e for e in errors(card))


def test_no_network_is_a_valid_offer(card):
    card["sup"]["contributions"] = []
    assert errors(card) == []


def test_intent_window_fits_the_claim_window(card):
    card["sup"]["intent_seconds"] = card["sup"]["claim_seconds"] + 1
    assert any("0 < intent_seconds <= claim_seconds" in e for e in errors(card))
    card["sup"]["intent_seconds"] = 0
    assert any("$.sup.intent_seconds: must be positive" in e for e in errors(card))


def test_record_seconds_is_at_most_twelve_months(card):
    card["sup"]["record_seconds"] = vc.SUP_RECORD_SECONDS_MAX + 1
    assert any("decision 17's 12 months" in e for e in errors(card))


@pytest.mark.parametrize("storage, message", [
    ({"free_quota_bytes": 4096, "unit_bytes": None, "unit_amount": None}, "must be at least 65536"),
    ({"free_quota_bytes": 65536, "unit_bytes": 1048576, "unit_amount": None}, "both null"),
    ({"free_quota_bytes": 65536, "unit_bytes": 0, "unit_amount": 0}, "must be positive"),
    ({"free_quota_bytes": 65536}, "missing members: unit_bytes, unit_amount"),
])
def test_storage_offer_rules(card, storage, message):
    card["sup"]["storage"] = storage
    assert any(message in e for e in errors(card)), errors(card)


def test_a_storage_offer_passes(card):
    card["sup"]["storage"] = {"free_quota_bytes": 1048576, "unit_bytes": 1048576, "unit_amount": 10}
    assert errors(card) == []


def test_address_placeholder_is_a_slot(card):
    card["sup"]["intent_seconds"] = "<FILL:SUP_ADDRESS:base-usdc>"
    assert any("placeholder <FILL:SUP_ADDRESS:base-usdc> is not allowed here" in e for e in errors(card))
    card["sup"]["intent_seconds"] = 86400
    card["sup"]["contributions"][0]["address"] = "<FILL:SUP_ADDRESS>"
    assert any("needs an argument" in e for e in errors(card))


def test_fill_writes_the_addresses(card):
    out = vc.fill(card, {"SUP_ADDRESS:base-usdc": BASE_ADDRESS, "SUP_ADDRESS:solana-usdc": SOLANA_ADDRESS}, None)
    assert [c["address"] for c in out["sup"]["contributions"]] == [BASE_ADDRESS, SOLANA_ADDRESS]

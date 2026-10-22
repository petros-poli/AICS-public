"""The AICS-1+SWARMS-1 profile (SWARMS R45-R47): the card once swarms are activated."""

from __future__ import annotations

import copy

import pytest

import validate_card as vc
from helpers import assurance, base_profile, errors, replace_statement

SKIP_G6 = ("[swarm-skipping] A private swarm broadcast in mode all is encrypted to every eligible other member; "
           "members who cannot receive are skipped and the sending flow names each skipped identity and its "
           "reason (unverified, no_consent, grant_exhausted).")
SKIP_G9 = ("[swarm-skipping] Swarm delivery follows separate swarm grants; all does not promise delivery to members "
           "who cannot receive, and skipped recipients and reasons are shown before sending.")


def activate(card: dict) -> dict:
    """The card with the swarms profile activated as SWARMS R47 specifies: AICS-1+SWARMS-1+SUP-1 from the template
    (which has the contributions and owner-service profile), AICS-1+SWARMS-1 from a base-profile card."""
    out = copy.deepcopy(card)
    out["spec"] = vc.SPEC_SWARMS_SUP if vc.sup_active(card["spec"]) else vc.SPEC_SWARMS
    out["spec_versions"]["swarms"] = vc.SWARMS_SPEC_VERSION
    out["swarms"] = dict(vc.SWARMS_MEMBER)
    out["retention"]["swarm_delivery_seconds"] = "<FILL:SWARM_DELIVERY_SECONDS>"
    out["reason_codes"]["refusal"] += list(vc.REFUSAL_SWARMS)
    assurance(out, "G6")["assumptions"].append(SKIP_G6)
    assurance(out, "G9")["assumptions"].append(SKIP_G9)
    return out


def test_activated_profile_passes(card):
    swarms = activate(card)
    result = vc.validate(swarms)
    assert result.report.errors == []
    assert result.profile == vc.SPEC_SWARMS_SUP


def test_swarms_without_the_sup_profile_passes(card):
    swarms = activate(base_profile(card))
    result = vc.validate(swarms)
    assert result.report.errors == []
    assert result.profile == vc.SPEC_SWARMS


def test_activated_profile_filled_passes_final(filled):
    swarms = activate(filled)
    swarms = vc.fill(swarms, {"SWARM_DELIVERY_SECONDS": str(vc.CIPHERTEXT_MINIMUM_SECONDS)}, None)
    assert errors(swarms, final=True) == []


def test_swarms_member_values_are_fixed(card):
    swarms = activate(card)
    swarms["swarms"]["join_code"] = 1
    assert any("$.swarms" in e for e in errors(swarms))


def test_swarms_member_needs_the_profile(card):
    card["swarms"] = dict(vc.SWARMS_MEMBER)
    assert any("only the swarms profiles (AICS-1+SWARMS-1, AICS-1+SWARMS-1+SUP-1) have a swarms member" in e
               for e in errors(card))


def test_swarms_spec_version_is_required(card):
    swarms = activate(card)
    del swarms["spec_versions"]["swarms"]
    assert any("$.spec_versions" in e for e in errors(swarms))


def test_swarm_refusal_codes_are_required(card):
    swarms = activate(card)
    swarms["reason_codes"]["refusal"].remove("swarm_channel")
    assert any("missing registered codes: swarm_channel" in e for e in errors(swarms))


def test_no_new_suspension_reason_with_swarms(card):
    swarms = activate(card)
    swarms["reason_codes"]["suspension"].append("swarm_membership")
    assert any("unknown code 'swarm_membership'" in e for e in errors(swarms))


def test_skip_disclosure_is_required(card):
    swarms = activate(card)
    replace_statement(swarms, "G9", "swarm-skipping", None)
    assert any("missing required statement [swarm-skipping] in G9" in e for e in errors(swarms))


def test_delivery_retention_floor(card):
    swarms = activate(card)
    swarms["retention"]["swarm_delivery_seconds"] = 86400
    assert any("swarm_delivery_seconds: must be at least 7776000" in e for e in errors(swarms))


@pytest.mark.parametrize("window, ok", [
    ({"count": 60, "interval_seconds": 60}, True),
    ({"count": 1000, "interval_seconds": 3600}, True),
    ({"count": 10, "interval_seconds": 3600}, False),  # 240 writes a day
    ({"count": 5000, "interval_seconds": 7200}, False),  # window longer than an hour
])
def test_write_rate_floor_r36(card, window, ok):
    swarms = activate(card)
    swarms["limits"]["writes"] = window
    assert (not any("SWARMS R36" in e for e in errors(swarms))) is ok


def test_g5_and_g7_stay_promised_with_swarms(card):
    swarms = activate(card)
    assurance(swarms, "G5")["status"] = "proven"
    assert any("G5 needs at least one independent witness" in e for e in errors(swarms))

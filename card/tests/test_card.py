"""The card itself: the template passes, filled it passes --final, and the required violations fail."""

from __future__ import annotations

import copy

import pytest

import validate_card as vc
from helpers import FOUNDER_WITNESS_STATEMENT, add_founder_witness, assurance, errors, replace_statement, statement


def test_template_passes(card):
    result = vc.validate(card)
    assert result.report.errors == []
    # aics-server writes the entries of the contributions and owner-service profile (AICS-1 section 20), so its
    # card activates that profile (section 20.9).
    assert result.profile == vc.SPEC_SUP
    assert result.payload == vc.unsigned_payload(card)


def test_template_status_table(card):
    statuses = {a["id"]: a["status"] for a in card["assurances"]}
    assert statuses == {
        "G1": "promised", "G2": "proven", "G3": "proven", "G4": "promised", "G5": "promised", "G6": "promised",
        "G7": "promised", "G8": "promised", "G9": "promised", "G10": "proven",
        "N1": "not-offered", "N2": "not-offered", "N3": "not-offered", "N4": "not-offered", "N5": "not-offered"}
    # Charter commitment 6 and card-policy.md: at launch there is no witness, so none is listed.
    assert card["witness_policy"] == {"quorum": 0, "witnesses": []}
    # A promised row is a commitment only; evidence comes with the successor card that promotes it.
    assert all(a["evidence"] == [] for a in card["assurances"] if a["status"] != "proven")
    assert card["retention"]["dm_seconds"] == vc.DM_SECONDS_UNSCHEDULED


def test_template_is_ascii_and_has_no_signatures(card):
    assert vc.profile_members(card["spec"]) == tuple(card)
    assert "signatures" not in card
    assert vc.unsigned_payload(card).isascii()


def test_final_mode_rejects_every_placeholder(card):
    errs = errors(card, final=True)
    assert errs
    assert all("not filled (--final)" in e for e in errs), errs
    filled_paths = {e.split(":")[0] for e in errs}
    assert "$.log_vkey" in filled_paths and "$.issued_at" in filled_paths


def test_filled_card_passes_final(filled):
    assert errors(filled, final=True) == []
    assert all(not vc.FILL_RE.search(text) for _, text in vc.iter_strings(filled))
    assert isinstance(filled["issued_at"], int) and isinstance(filled["retention"]["ciphertext_budget_bytes"], int)


# --- the four crafted violations the task names ----------------------------------------------------------


def test_g5_proven_with_quorum_zero_fails(card):
    assurance(card, "G5")["status"] = "proven"
    errs = errors(card)
    assert any("G5 cannot be proven with witness quorum 0" in e for e in errs), errs


def test_missing_required_statement_fails(card):
    replace_statement(card, "G8", "sunset", None)
    errs = errors(card)
    assert any("missing required statement [sunset] in G8" in e for e in errs), errs


def test_unknown_code_fails(card):
    card["reason_codes"]["refusal"].append("invalid_signature")
    errs = errors(card)
    assert any("unknown code 'invalid_signature'" in e for e in errs), errs


def test_unknown_suspension_reason_fails(card):
    card["reason_codes"]["suspension"].append("content")
    errs = errors(card)
    assert any("unknown code 'content'" in e and "suspension reasons are only order, flood" in e for e in errs)


def test_cannot_in_promised_claim_fails(card):
    assurance(card, "G7")["claim"] = ("Running code tied to source: the operator cannot run code that differs "
                                      "from the published source.")
    errs = errors(card)
    assert any("'cannot' in a promised claim" in e for e in errs), errs


def test_cannot_in_promised_g5_claim_fails(card):
    assurance(card, "G5")["claim"] = "Single view: the operator can't show different logs to different agents."
    assert any("in a promised claim" in e for e in errors(card))


# --- section 13.3 bounds -----------------------------------------------------------------------------------


def test_g7_proven_without_release_leaves_fails(card):
    g7 = assurance(card, "G7")
    g7["status"] = "proven"
    g7["claim"] = "Running code tied to source."
    g7["evidence"] = [{"hash": "ab" * 32, "media_type": "text/markdown"}]
    errs = errors(card)
    assert any("G7 cannot be proven without release leaves" in e for e in errs), errs
    assert any("runtime evidence" in e for e in errs), errs


def test_g7_with_release_and_runtime_evidence_is_within_bounds(card):
    g7 = assurance(card, "G7")
    g7["status"] = "proven"
    g7["claim"] = "Running code tied to source."
    g7["evidence"] = [{"hash": "ab" * 32, "media_type": vc.RELEASE_MEDIA_TYPE},
                      {"hash": "cd" * 32, "media_type": vc.RUNTIME_MEDIA_TYPE}]
    assert not [e for e in errors(card) if "G7" in e or "$.assurances[6]" in e]


SPEC_EVIDENCE = [{"hash": "ab" * 32, "media_type": "text/markdown"}]
CONFORMANCE_EVIDENCE = [{"hash": "cd" * 32, "media_type": vc.CONFORMANCE_MEDIA_TYPE}]


def _promote(card, aid, evidence):
    a = assurance(card, aid)
    a["status"] = "proven"
    a["claim"] = vc.CLAIM_TITLES[aid] + "."
    a["evidence"] = copy.deepcopy(evidence)


@pytest.mark.parametrize("aid", vc.CONFORMANCE_ROWS)
def test_proven_row_needs_a_conformance_report(card, aid):
    _promote(card, aid, SPEC_EVIDENCE)
    errs = errors(card)
    assert any(f"{aid} cannot be proven from spec prose" in e and vc.CONFORMANCE_MEDIA_TYPE in e for e in errs), errs
    _promote(card, aid, SPEC_EVIDENCE + CONFORMANCE_EVIDENCE)
    assert not [e for e in errors(card) if "cannot be proven from spec prose" in e]


@pytest.mark.parametrize("aid", ["G2", "G3", "G10"])
def test_rows_proven_from_the_spec_need_no_conformance_report(card, aid):
    assert vc.CONFORMANCE_MEDIA_TYPE not in {e["media_type"] for e in assurance(card, aid)["evidence"]}
    assert errors(card) == []


def test_conformance_rule_applies_in_final_mode(filled):
    _promote(filled, "G9", SPEC_EVIDENCE)
    assert any("G9 cannot be proven from spec prose" in e for e in errors(filled, final=True))


def test_proven_claim_needs_evidence(card):
    assurance(card, "G2")["evidence"] = []
    assert any("names the evidence" in e for e in errors(card))


def test_n_row_cannot_be_promised(card):
    assurance(card, "N1")["status"] = "promised"
    assert any("N1 is not-offered" in e for e in errors(card))


def test_g_row_cannot_be_not_offered(card):
    assurance(card, "G9")["status"] = "not-offered"
    assert any("G9 is a guarantee" in e for e in errors(card))


def test_claim_must_name_its_section_13_3_claim(card):
    assurance(card, "G2")["claim"] = "Ordering: every write has an index."
    assert any("'Tamper-evident order'" in e for e in errors(card))


def test_missing_assurance_fails(card):
    card["assurances"] = [a for a in card["assurances"] if a["id"] != "N4"]
    assert any("missing or repeated: N4" in e for e in errors(card))


def test_extra_assurance_id_fails(card):
    extra = copy.deepcopy(assurance(card, "N5"))
    extra["id"] = "N6"
    card["assurances"].append(extra)
    assert any("must be one of G1-G10, N1-N5" in e for e in errors(card))


# --- prevention versus detection (docs/legal/card-policy.md) --------------------------------------------------


@pytest.mark.parametrize("aid, claim, word", [
    ("G3", "No leaf deletion: no included leaf can be removed; it cannot be edited.", "cannot"),
    ("G2", "Tamper-evident order: each write is a leaf, and nobody can't reorder it.", "can't"),
    ("G9", "Consent and inbox completeness: a direct message is accepted only under a grant.", "only under"),
    ("N5", "Leaf editing/deletion, guaranteed body history or uninterrupted delivery: none is offered. Leaves are "
           "not editable or deletable by anyone.", "by anyone"),
])
def test_prevention_wording_in_proven_and_not_offered_claims_fails(card, aid, claim, word):
    a = assurance(card, aid)
    a["claim"] = claim
    if a["status"] == "promised":
        _promote(card, aid, SPEC_EVIDENCE + CONFORMANCE_EVIDENCE)
        a["claim"] = claim
    assert any(f"{word!r} in a" in e and "states prevention" in e for e in errors(card)), errors(card)


def test_cannot_with_detection_passes(card):
    assert "cannot" in assurance(card, "G3")["claim"] and "without" in assurance(card, "G3")["claim"]
    assert vc.prevention_wording(assurance(card, "G3")["claim"]) == []
    assert vc.prevention_wording("X cannot be done (section 13.2). It is detected without delay.") == ["cannot"]


def test_template_claims_state_detection_not_prevention(card):
    for a in card["assurances"]:
        if a["status"] in ("proven", "not-offered"):
            assert vc.prevention_wording(a["claim"]) == [], a["id"]


# --- witness policy (G5 under AICS-1 section 6.3) ------------------------------------------------------------


def _witnesses(filled, spec):
    from helpers import key, vkey
    out = []
    for i, (domain, independent) in enumerate(spec):
        name = f"w{i}.example.org/w"
        out.append({"name": name, "vkey": vkey(name, 0x04, key(0x40 + i)), "trust_domain": domain,
                    "independent": independent})
    filled["witness_policy"]["witnesses"] = out


def _prove_g5(filled, quorum):
    filled["witness_policy"]["quorum"] = quorum
    replace_statement(filled, "G5", "witness-policy",
                      f"[witness-policy] Witness policy: quorum {quorum} of the listed witnesses.")
    g5 = assurance(filled, "G5")
    g5["status"] = "proven"
    g5["claim"] = "Single view."
    g5["evidence"] = [{"hash": "ef" * 32, "media_type": "text/markdown"}]


def test_g5_two_of_three_with_a_founder_witness_is_not_provable(filled):
    _witnesses(filled, [("founder", False), ("org-a", True), ("org-b", True)])
    _prove_g5(filled, 2)
    assert any("can intersect only in the 1 witness(es) that are not independent" in e for e in errors(filled))


def test_g5_two_of_three_external_witnesses_is_within_bounds(filled):
    _witnesses(filled, [("org-a", True), ("org-b", True), ("org-c", True)])
    _prove_g5(filled, 2)
    assert errors(filled, final=True) == []


def test_listed_founder_witness_needs_the_founder_statement(card):
    add_founder_witness(card, statement_too=False)
    assert any("missing required statement [founder-witness] in G5" in e for e in errors(card))
    assurance(card, "G5")["assumptions"].append(FOUNDER_WITNESS_STATEMENT)
    assert errors(card) == []


def test_founder_witness_cannot_be_independent(card):
    add_founder_witness(card)["independent"] = True
    assert any("never independent" in e for e in errors(card))


def test_quorum_above_witness_count_fails(card):
    card["witness_policy"]["quorum"] = 1
    assert any("exceeds the number of witnesses" in e for e in errors(card))


def test_witness_policy_statement_follows_quorum(card):
    add_founder_witness(card)
    card["witness_policy"]["quorum"] = 1
    errs = errors(card)
    assert any("must mention 'quorum 1'" in e for e in errs), errs
    assert not any("exceeds the number of witnesses" in e for e in errs)


def test_witness_key_must_be_cosignature_type_and_named(filled):
    from helpers import WITNESS_KEY, vkey
    w = add_founder_witness(filled)
    w["vkey"] = vkey("other.example.org/w", 0x04, WITNESS_KEY)
    assert any("differs from the witness name" in e for e in errors(filled, final=True))
    w["vkey"] = vkey(w["name"], 0x01, WITNESS_KEY)
    assert any("type 0x04" in e for e in errors(filled, final=True))


def test_service_key_cannot_witness(filled):
    from helpers import LOG_KEY, vkey
    w = add_founder_witness(filled)
    w["vkey"] = vkey(w["name"], 0x04, LOG_KEY)
    assert any("reuses the key of log_vkey" in e for e in errors(filled, final=True))


def test_service_keys_must_be_distinct(filled):
    filled["owner_kid"] = filled["policy_kid"]
    assert any("must be distinct" in e for e in errors(filled, final=True))


def test_log_vkey_name_must_be_origin(filled):
    from helpers import LOG_KEY, vkey
    filled["log_vkey"] = vkey("log.example/aics-1", 0x01, LOG_KEY)
    assert any("the log key name must be the origin" in e for e in errors(filled, final=True))


def test_tampered_key_id_fails(filled):
    name, _key_id, b64 = filled["log_vkey"].split("+", 2)
    filled["log_vkey"] = f"{name}+{'0' * 8}+{b64}"
    assert any("does not match the key" in e for e in errors(filled, final=True))


# --- retention ------------------------------------------------------------------------------------------------


def test_scheduled_dm_expiry_needs_a_charter_change(card):
    card["retention"]["dm_seconds"] = 365 * 86400
    assert any("$.retention.dm_seconds: must be 9007199254740991" in e and "charter commitment 2" in e
               for e in errors(card))


def test_ciphertext_retention_says_no_scheduled_dm_expiry(card):
    text = statement(card, "G3", "ciphertext-retention").replace("no scheduled direct-message expiry", "a schedule")
    replace_statement(card, "G3", "ciphertext-retention", text)
    assert any("must mention 'no scheduled direct-message expiry'" in e for e in errors(card))


# --- required statements ------------------------------------------------------------------------------------


def test_statement_must_quote_its_values(card):
    text = statement(card, "G8", "sunset").replace("180 days", "a while")
    replace_statement(card, "G8", "sunset", text)
    assert any("[sunset] in G8 must mention '180 days'" in e for e in errors(card))


def test_witness_deviation_is_required(card):
    replace_statement(card, "G5", "witness-deviation", None)
    assert any("missing required statement [witness-deviation] in G5" in e for e in errors(card))


def test_no_forward_secrecy_statement_is_required(card):
    replace_statement(card, "N1", "no-forward-secrecy", None)
    assert any("[no-forward-secrecy] in N1" in e for e in errors(card))


@pytest.mark.parametrize("aid, tag", [("N1", "plaintext-port"), ("N2", "hosting-provider"), ("G8", "mirror-copies")])
def test_disclosure_statements_are_required(card, aid, tag):
    replace_statement(card, aid, tag, None)
    assert any(f"missing required statement [{tag}] in {aid}" in e for e in errors(card))


def test_cloudflare_statement_must_name_every_host(card):
    text = statement(card, "N2", "third-party-processing")
    replace_statement(card, "N2", "third-party-processing", text.replace(" and ip.wesupport-ai.com", ""))
    assert any("whether ip.wesupport-ai.com passes through Cloudflare" in e for e in errors(card))


def test_hosting_provider_statement_must_name_every_dns_only_host(card):
    text = statement(card, "N2", "hosting-provider")
    replace_statement(card, "N2", "hosting-provider", text.replace("gate.wesupport-ai.com and ", ""))
    assert any("[hosting-provider] must name gate.wesupport-ai.com" in e for e in errors(card))


def test_address_statement_covers_container_logs(card):
    text = statement(card, "N2", "no-address-records").replace("container and runtime logs", "runtime logs")
    replace_statement(card, "N2", "no-address-records", text)
    assert any("[no-address-records] in N2 must mention 'container'" in e for e in errors(card))


@pytest.mark.parametrize("aid", vc.SPLIT_VIEW_ROWS)
def test_split_view_statement_is_required_while_g5_is_promised(card, aid):
    replace_statement(card, aid, "split-view", None)
    assert any(f"missing required statement [split-view] in {aid}" in e for e in errors(card))


def test_split_view_statement_is_not_required_once_g5_is_proven(filled):
    _witnesses(filled, [("org-a", True), ("org-b", True), ("org-c", True)])
    _prove_g5(filled, 2)
    for aid in vc.SPLIT_VIEW_ROWS:
        replace_statement(filled, aid, "split-view", None)
    assert errors(filled, final=True) == []


@pytest.mark.parametrize("tag, phrase", [
    ("deviation-refusal-dedup", "charter commitment 7"),
    ("deviation-refusal-dedup", "terms"),
    ("deviation-secret-scan-scope", "charter commitment 4"),
])
def test_refusal_deviations_name_the_commitments_they_break(card, tag, phrase):
    text = statement(card, "G4", tag)
    replace_statement(card, "G4", tag, text.replace(phrase, "an earlier text"))
    assert any(f"statement [{tag}] in G4 must mention {phrase!r}" in e for e in errors(card))


def test_deviation_statement_says_so(card):
    text = statement(card, "G4", "deviation-refusal-dedup").replace("Known deviation from", "Unlike")
    replace_statement(card, "G4", "deviation-refusal-dedup", text)
    assert any("[deviation-refusal-dedup] must say 'Known deviation from'" in e for e in errors(card))


def test_resolved_deviation_tags_are_no_longer_accepted(card):
    """The budget eviction and the per-key registration window are implemented: their deviation tags are gone, and a
    card that brings one back is refused as an unknown tag."""
    assert "deviation-budget-eviction" not in vc.TAG_HOMES and "deviation-registration-window" not in vc.TAG_HOMES
    g3 = next(a for a in card["assurances"] if a["id"] == "G3")
    g3["assumptions"].append("[deviation-budget-eviction] Known deviation from AICS-1 section 8.2: none.")
    assert any("deviation-budget-eviction" in e for e in errors(card)), errors(card)


def test_keyless_limits_are_required(card):
    replace_statement(card, "G4", "keyless-limits", None)
    assert any("missing required statement [keyless-limits] in G4" in e for e in errors(card))
    text = "[keyless-limits] Keyless traffic is limited."
    g4 = next(a for a in card["assurances"] if a["id"] == "G4")
    g4["assumptions"].append(text)
    assert any("[keyless-limits]" in e and "limits.unauthenticated" in e for e in errors(card)), errors(card)


def test_every_deviation_tag_is_registered_and_disclosed_in_the_template(card):
    deviations = {tag for tag in vc.TAG_HOMES if tag.startswith(vc.DEVIATION_PREFIX)}
    present = {m.group(1) for a in card["assurances"] for t in a["assumptions"] if (m := vc.TAG.match(t))
               and m.group(1).startswith(vc.DEVIATION_PREFIX)}
    assert present == deviations


def test_leaf_residual_is_required(card):
    # AICS-1 section 5.2: the card discloses the agent-chosen bytes on leaves in G3's assumptions.
    replace_statement(card, "G3", "leaf-residual", None)
    assert any("missing required statement [leaf-residual] in G3" in e for e in errors(card))


def test_leaf_residual_names_the_nonce(card):
    text = statement(card, "G3", "leaf-residual").replace("nonce", "number")
    replace_statement(card, "G3", "leaf-residual", text)
    assert any("[leaf-residual] in G3 must mention 'nonce'" in e for e in errors(card))


def test_statement_in_wrong_assurance_fails(card):
    assurance(card, "G2")["assumptions"].append(statement(card, "G8", "sunset"))
    assert any("statement [sunset] belongs in G8" in e for e in errors(card))


def test_unknown_statement_tag_fails(card):
    assurance(card, "G2")["assumptions"].append("[ordering] Every write has an index.")
    assert any("unknown statement tag" in e for e in errors(card))


def test_duplicate_statement_tag_fails(card):
    assurance(card, "G3")["assumptions"].append(statement(card, "G3", "permanent-leaves"))
    assert any("[permanent-leaves] appears twice" in e for e in errors(card))


def test_reliance_on_operational_claims_is_required(card):
    replace_statement(card, "G5", "relies-on", None)
    assert any("missing [relies-on] statement in G5" in e for e in errors(card))
    text = statement(card, "N2", "relies-on").replace("no IP logging", "no logs")
    replace_statement(card, "N2", "relies-on", text)
    assert any("must name the operational claim 'no IP logging'" in e for e in errors(card))


def test_boundary_statement_is_required_in_every_g_row(card):
    replace_statement(card, "G1", "boundary", None)
    assert any("missing required statement [boundary] in G1" in e for e in errors(card))


# --- wording ------------------------------------------------------------------------------------------------


def test_marketing_word_fails(card):
    assurance(card, "G6")["claim"] += " Military-grade encryption."
    assert any("marketing wording 'Military-grade'" in e for e in errors(card))


def test_zero_knowledge_only_in_n1(card):
    assurance(card, "G6")["assumptions"].append("Messages are zero-knowledge to the operator.")
    errs = errors(card)
    assert any("zero knowledge may only be named as not offered (N1)" in e for e in errs)
    assert not [e for e in vc.validate(vc.load_json(b"{}")).report.errors if "zero knowledge" in e]


def test_control_characters_fail(card):
    assurance(card, "G2")["claim"] += "‮"
    assert any("control, format or unassigned characters (U+202E)" in e for e in errors(card))

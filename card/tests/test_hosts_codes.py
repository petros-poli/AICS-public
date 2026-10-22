"""Decision 10 hostnames, the closed reason-code registries and placeholder slots."""

from __future__ import annotations

import pytest

import validate_card as vc
from helpers import assurance, errors

# --- decision 10 -------------------------------------------------------------------------------------------


def test_every_decision_10_host_is_listed_with_its_mode(card):
    assert {p["host"]: p["mode"] for p in card["proxy"]} == vc.DECISION_10_HOSTS


def test_proxied_api_fails(card):
    next(p for p in card["proxy"] if p["host"] == "api.wesupport-ai.com")["mode"] = "cloudflare"
    errs = errors(card)
    assert any("decision 10 makes api.wesupport-ai.com dns-only" in e for e in errs), errs


def test_missing_proxy_host_fails(card):
    card["proxy"] = [p for p in card["proxy"] if p["host"] != "ip.wesupport-ai.com"]
    assert any("must list ip.wesupport-ai.com exactly once" in e for e in errors(card))


def test_unknown_proxy_host_fails(card):
    card["proxy"].append({"host": "status.wesupport-ai.com", "mode": "dns-only", "tls_termination": "origin Caddy"})
    errs = errors(card)
    assert any("$.proxy[6].host: status.wesupport-ai.com is not one of decision 10's hostnames" in e for e in errs)


def test_tls_termination_must_match_mode(card):
    card["proxy"][0]["tls_termination"] = "origin Caddy"
    assert any("Cloudflare edge with Full (strict)" in e for e in errors(card))


@pytest.mark.parametrize("prefix, message", [
    ("https://mirror.example.org/tiles", "host must be api.wesupport-ai.com or tiles.wesupport-ai.com"),
    ("https://tiles.wesupport-ai.com", "path must be '/tiles'"),
    ("http://tiles.wesupport-ai.com/tiles", "must be an https URL"),
    ("https://tiles.wesupport-ai.com:8443/tiles", "no user information, port, query or fragment"),
    ("https://tiles.wesupport-ai.com/tiles?x=1", "no user information, port, query or fragment"),
])
def test_bad_tile_prefix_fails(card, prefix, message):
    card["tile_prefixes"][1] = prefix
    assert any(message in e for e in errors(card)), errors(card)


def test_canonical_tile_prefix_is_required(card):
    card["tile_prefixes"] = ["https://tiles.wesupport-ai.com/tiles"]
    assert any("canonical prefix https://api.wesupport-ai.com/tiles" in e for e in errors(card))


def test_hostname_in_text_must_be_decision_10(card):
    assurance(card, "G8")["assumptions"].append("Status is posted at status.wesupport-ai.com.")
    assert any("hostname status.wesupport-ai.com is not one of decision 10's hostnames" in e for e in errors(card))


def test_dns_record_names_and_mail_domains_are_allowed():
    assert vc.hosts_in("TXT _aics.wesupport-ai.com, mail notice@wesupport-ai.com") == {
        "_aics.wesupport-ai.com", "wesupport-ai.com"}


@pytest.mark.parametrize("member, value", [
    ("api_base", "https://api.wesupport-ai.com/v2"),
    ("origin", "tiles.wesupport-ai.com/tiles"),
])
def test_api_base_and_origin_are_fixed(card, member, value):
    card[member] = value
    assert errors(card)


def test_gate_is_fixed(card):
    card["gate"]["https_url"] = "https://wesupport-ai.com/t"
    assert any("$.gate.https_url" in e for e in errors(card))


# --- reason codes ------------------------------------------------------------------------------------------


def test_refusal_list_is_the_registry_plus_active_patterns(card):
    patterns = [f"secret_format:{p['id']}" for p in card["secret_patterns"]]
    expected = list(vc.REGISTRIES["refusal"]) + list(vc.REFUSAL_SUP) + patterns  # AICS-1 sections 17.2 and 20.8
    assert sorted(card["reason_codes"]["refusal"]) == sorted(expected)
    for name in ("tombstone", "suspension", "freeze", "revocation", "outcome"):
        assert sorted(card["reason_codes"][name]) == sorted(vc.REGISTRIES[name])


@pytest.mark.parametrize("registry", list(vc.CHARTER_LISTS))
def test_lists_are_supersets_of_the_charter(card, registry):
    charter = vc.CHARTER_LISTS[registry] + (vc.CHARTER_SUP_REFUSALS if registry == "refusal" else ())
    assert set(charter) <= set(card["reason_codes"][registry])


def test_dropping_a_charter_code_fails(card):
    card["reason_codes"]["refusal"].remove("rate")
    errs = errors(card)
    assert any("not a superset of the charter's closed refusal list: missing rate" in e for e in errs), errs
    assert any("missing registered codes: rate" in e for e in errs)


def test_dropping_a_detailed_code_fails(card):
    card["reason_codes"]["refusal"].remove("unknown_key")
    assert any("missing registered codes: unknown_key" in e for e in errors(card))


def test_suspension_is_only_order_and_flood(card):
    card["reason_codes"]["suspension"] = ["order", "flood", "spam"]
    assert any("unknown code 'spam'" in e for e in errors(card))


def test_tombstone_cannot_grow(card):
    card["reason_codes"]["tombstone"].append("hate_speech")
    assert any("unknown code 'hate_speech'" in e for e in errors(card))


def test_swarm_codes_need_the_swarms_profile(card):
    card["reason_codes"]["refusal"].append("swarm_stale")
    assert any("registered only for the swarms profile, AICS-1+SWARMS-1" in e for e in errors(card))


def test_duplicate_code_fails(card):
    card["reason_codes"]["freeze"].append("order")
    assert any("duplicate entries: order" in e for e in errors(card))


def test_secret_format_codes_match_patterns(card):
    card["reason_codes"]["refusal"].remove("secret_format:slack_token")
    assert any("lacks secret_format:slack_token" in e for e in errors(card))
    card["reason_codes"]["refusal"].append("secret_format:unlisted")
    assert any("secret_format:unlisted names no pattern" in e for e in errors(card))


@pytest.mark.parametrize("pattern_id", ["jwt_token", "openai_key"])
def test_forbidden_secret_patterns_fail(card, pattern_id):
    card["secret_patterns"].append({"id": pattern_id, "pattern_hash": "ab" * 32})
    card["reason_codes"]["refusal"].append(f"secret_format:{pattern_id}")
    assert any("AICS-1 section 10.2 forbids" in e for e in errors(card))


# --- schema odds and ends -------------------------------------------------------------------------------------


def test_signatures_are_not_part_of_the_unsigned_body(card):
    card["signatures"] = []
    assert any("the unsigned body has no signatures" in e for e in errors(card))


def test_unknown_member_fails(card):
    card["custodian"] = "someone"
    assert any("$.custodian: unknown member" in e for e in errors(card))


@pytest.mark.parametrize("path, value, message", [
    (("mmd_seconds",), 120, "must be 60"),
    (("max_checkpoint_age",), 30, "must be at least 60"),
    (("policy_notice_seconds",), 86400, "must be at least 2592000"),
    (("limits", "ciphertext_bytes"), 131072, "must be 65536"),
    (("limits", "writes", "count"), 0, "must be positive"),
    (("retention", "capsule_max_seconds"), 86400, "must be at least 7776000"),
    (("retention", "eviction"), "random", "must be \"oldest-ts-index\""),
    (("schemes",), ["age-v1"], "must include the mandatory scheme"),
    (("schemes",), ["x25519-xsalsa20-poly1305", "cleartext"], "unknown encryption scheme"),
    (("tiers",), ["verified", "unverified"], "must be exactly"),
    (("spec_versions", "tlog-witness"), "1.0.0", "$.spec_versions"),
    (("version",), "0.1-draft", "must be \"0.2-draft\""),
    (("policy_parent_index",), -1, "must be an integer"),
])
def test_schema_values(card, path, value, message):
    target = card
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    assert any(message in e for e in errors(card)), errors(card)


def test_true_is_not_one(card):
    card["gate"]["tls_port"] = True
    assert any("$.gate.tls_port" in e for e in errors(card))


def test_card_must_outlive_the_notice_period(filled):
    filled["expires"] = filled["issued_at"] + filled["policy_notice_seconds"]
    assert any("must outlive policy_notice_seconds" in e for e in errors(filled, final=True))
    filled["expires"] = filled["issued_at"]
    assert any("issued_at must be before expires" in e for e in errors(filled, final=True))


def test_max_checkpoint_age_other_than_300_warns(card):
    card["max_checkpoint_age"] = 600
    result = vc.validate(card)
    assert result.report.errors == []
    assert any("recommends 300" in w for w in result.report.warnings)


# --- placeholders ------------------------------------------------------------------------------------------


def test_placeholder_outside_its_slots_fails(card):
    card["mmd_seconds"] = "<FILL:MMD_SECONDS>"
    assert any("placeholder <FILL:MMD_SECONDS> is not allowed here" in e for e in errors(card))


def test_wrong_placeholder_in_a_slot_fails(card):
    card["issued_at"] = "<FILL:EXPIRES>"
    assert any("this slot takes <FILL:ISSUED_AT>" in e for e in errors(card))


def test_placeholder_in_claim_text_fails(card):
    assurance(card, "G8")["claim"] += " <FILL:CUSTODIAN_NAME>"
    assert any("not allowed in this text" in e for e in errors(card))


def test_pattern_hash_placeholder_names_its_pattern(card):
    card["secret_patterns"][0]["pattern_hash"] = "<FILL:SECRET_PATTERN_HASH:github_token>"
    assert any("must be <FILL:SECRET_PATTERN_HASH:anthropic_key>" in e for e in errors(card))


def test_hash_placeholder_stays_inside_the_repository(card):
    card["policies"]["terms_hash"] = "<FILL:SHA256:../secrets.txt>"
    assert any("repository-relative path" in e for e in errors(card))


def test_malformed_placeholder_fails(card):
    card["log_vkey"] = "<FILL:log vkey>"
    assert any("malformed placeholder" in e for e in errors(card))


def test_fill_rejects_unknown_names(card):
    with pytest.raises(vc.InputError, match="names no placeholder"):
        vc.fill(card, {"NOT_THERE": "x"}, None)


def test_fill_types_uint_slots(card):
    with pytest.raises(vc.InputError, match="expects an unsigned integer"):
        vc.fill(card, {"ISSUED_AT": "soon"}, None)
    assert vc.fill(card, {"ISSUED_AT": "1793491200"}, None)["issued_at"] == 1793491200


def test_fill_hashes_from_the_repository(card):
    import hashlib

    from helpers import REPO, TEST_REPORT_SHA256
    # The conformance reports are added to docs/evidence before the wipe: given here, read from the checkout at launch.
    reports = {f"SHA256:{rel}": digest for rel, digest in TEST_REPORT_SHA256.items()}
    out = vc.fill(card, reports, REPO)
    assert out["policies"]["charter_hash"] == hashlib.sha256((REPO / "docs/legal/charter.md").read_bytes()).hexdigest()
    assert vc.fill(card, reports, REPO)["policies"] == out["policies"]  # deterministic


def test_fill_refuses_paths_outside_the_root(tmp_path):
    (tmp_path / "root").mkdir()
    (tmp_path / "outside.md").write_text("x")
    body = {"policies": {"terms_hash": "<FILL:SHA256:../outside.md>"}}
    with pytest.raises(vc.InputError, match="points outside"):
        vc.fill(body, {}, tmp_path / "root")

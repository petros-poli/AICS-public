"""aics verify card: A2A §8.4 JWS over JCS as profiled by AICS-1 §13.2,
the §13.1 schema, expiry, bootstrap hash, pins and the saved-card diff."""

from __future__ import annotations

import base64
import dataclasses
import json

import pytest
from aics_identity import keys as idkeys
from aics_identity.canonical import canonicalize
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aics_cli.card import card_hash, check_signatures, compare_witness, json_diff, loads_strict, schema_problems, \
    sign_card, unsigned_payload
from aics_cli.policy import parse_policy_key

from conftest import CARD_URL, NOW, Instance, Log, Witness, did, make_policy, policy_for


@pytest.fixture
def inst(h):
    i = Instance(Log(5))
    policy_for(h.home, i)
    return i


def publish(h, card):
    h.fetcher.set(CARD_URL, json.dumps(card, indent=1))


def test_bootstrap_card_verifies_and_prints_the_table(h, inst):
    publish(h, inst.card)
    code, out = h.run("verify", "card")
    assert code == 0, out
    assert out["signatures"][0]["status"] == "valid"
    assert out["bootstrap"] is True
    assert out["currency"] == "bootstrap card; later policy events not checked"
    assert [g["id"] for g in out["table"]["proven"]] == ["G2", "G3", "G8"]
    assert not any(g["evidence_verified"] for g in out["table"]["proven"])
    assert len(out["table"]["promised"]) == 7 and len(out["table"]["not-offered"]) == 5
    assert out["diff"] is None and out["stored"]["new"]
    code, text = h.run_text("verify", "card")
    assert code == 0
    assert "STATUS" in text and "Single view" in text and "not-offered" in text
    assert "none since the stored card" in text
    assert "claimed proven (evidence not verified)" in text and "untrusted text" in text
    assert "unproven   the evidence behind 'proven' assurances" in text  # data['unproven'] in text mode
    assert "currency   bootstrap card; later policy events not checked" in text


def test_site_argument_resolves_to_well_known(h, inst):
    publish(h, inst.card)
    code, out = h.run("verify", "card", "log.test")
    assert code == 0 and out["url"] == CARD_URL


def test_tampered_card_fails_with_evidence(h, inst):
    tampered = json.loads(json.dumps(inst.card))
    tampered["assurances"][4]["status"] = "proven"  # upgrade G5 after signing
    publish(h, tampered)
    code, out = h.run("verify", "card")
    assert code == 2, out
    assert out["evidence"]["reason"] == "invalid-signature"
    assert out["evidence"]["card"]["assurances"][4]["status"] == "proven"
    assert not (h.home / "cards" / "index.jsonl").exists()


def test_reformatted_card_still_verifies(h, inst):
    reordered = dict(reversed(list(inst.card.items())))
    h.fetcher.set(CARD_URL, json.dumps(reordered, separators=(",", ":"), ensure_ascii=True))
    assert h.run("verify", "card")[0] == 0


def test_card_signed_by_an_unpinned_key_fails(h, inst):
    other = idkeys.generate_keypair()
    body = {k: v for k, v in inst.card.items() if k != "signatures"}
    publish(h, sign_card(body, other, did(other)))
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "no-pinned-signature"
    publish(h, sign_card(body, other, did(inst.policy_key)))  # an impostor claiming the pinned kid
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "invalid-signature"


@pytest.mark.parametrize("header", [{"jku": "https://evil.example/jwks.json"}, {"crit": ["exp"]}, {"b64": False}])
def test_header_extensions_are_refused(h, inst, header):
    body = {k: v for k, v in inst.card.items() if k != "signatures"}
    publish(h, sign_card(body, inst.policy_key, did(inst.policy_key), extra_header=header))
    code, out = h.run("verify", "card")
    assert code == 2
    assert out["evidence"]["signatures"][0]["status"] == "unsupported"
    assert not any("evil.example" in u for u in h.fetcher.requests)


def test_unprotected_header_and_other_algs_are_refused(h, inst):
    card = json.loads(json.dumps(inst.card))
    card["signatures"][0]["header"] = {"kid": "x"}
    publish(h, card)
    assert h.run("verify", "card")[1]["evidence"]["signatures"][0]["status"] == "unsupported"
    body = {k: v for k, v in inst.card.items() if k != "signatures"}
    publish(h, sign_card(body, inst.policy_key, did(inst.policy_key), alg="Ed25519"))
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["signatures"][0]["status"] == "unsupported"


def test_schema_is_enforced(h, inst):
    card = inst.make_card(mutate=lambda c: c.update(extra="field"))
    publish(h, card)
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "schema"
    assert any("unknown members extra" in p for p in out["evidence"]["problems"])
    card = inst.make_card(mutate=lambda c: c.update(max_checkpoint_age=30))
    assert schema_problems(card) == ["$.max_checkpoint_age: must be at least 60"]
    card = inst.make_card(mutate=lambda c: c["assurances"].pop())
    assert any("N5" in p for p in schema_problems(card))
    card = inst.make_card(mutate=lambda c: c.update(issued_at="2027-01-01T00:00:00Z"))
    assert any("issued_at" in p for p in schema_problems(card))


def test_only_the_0_2_draft_card_is_accepted(h, inst):
    """AICS-1 (0.2-draft) §13.1: version "0.2-draft" with the C2SP v1.1.0 pins; a 0.1-draft card is refused."""
    assert schema_problems(inst.card) == []
    assert inst.card["version"] == "0.2-draft" and inst.card["spec_versions"] == {
        "tlog-tiles": "1.0.0", "tlog-checkpoint": "1.1.0", "signed-note": "1.1.0", "tlog-cosignature": "1.1.0",
        "tlog-witness": "1.1.0", "a2a-card": "1.0.0"}
    old = inst.make_card(mutate=lambda c: c.update(version="0.1-draft", spec_versions={
        k: "1.0.0" for k in c["spec_versions"]}))
    problems = schema_problems(old)
    assert [p.split(":", 1)[0] for p in problems] == ["$.version", "$.spec_versions"], problems
    assert "'0.2-draft'" in problems[0] and "'0.1-draft'" in problems[0]
    publish(h, old)
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "schema", out
    pins = inst.make_card(mutate=lambda c: c["spec_versions"].update({"signed-note": "1.0.0"}))
    assert [p.split(":", 1)[0] for p in schema_problems(pins)] == ["$.spec_versions"]


def test_reason_registries_must_equal_section_17_2(h, inst):
    """AICS-1 §13.1: reasons equal §17.2's registries plus only the card's own secret_format:<id> instances;
    §17.2: unregistered synonyms such as invalid_signature never become codes."""
    def with_refusal(change):
        return inst.make_card(mutate=lambda c: c["reason_codes"].update(refusal=change(c["reason_codes"]["refusal"])))
    for change in (lambda r: r + ["invalid_signature"], lambda r: r + ["whatever"],
                   lambda r: [x for x in r if x != "malformed"], lambda r: r + ["secret_format:no_such_pattern"],
                   lambda r: [x for x in r if x != "secret_format:aws_access_key"], lambda r: r + ["swarm_stale"]):
        card = with_refusal(change)
        assert [p.split(":", 1)[0] for p in schema_problems(card)] == ["$.reason_codes.refusal"], schema_problems(card)
        publish(h, card)
        code, out = h.run("verify", "card")
        assert code == 2 and out["evidence"]["reason"] == "schema", out
    assert schema_problems(with_refusal(lambda r: list(reversed(r)))) == []  # the order is free
    card = inst.make_card(mutate=lambda c: c["reason_codes"].update(tombstone=["order", "erasure"]))
    assert [p.split(":", 1)[0] for p in schema_problems(card)] == ["$.reason_codes.tombstone"]


def test_expired_card_is_stale(h, inst):
    publish(h, inst.make_card(issued_at=NOW - 100, expires=NOW - 31))
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "expired"
    publish(h, inst.make_card(issued_at=NOW - 100, expires=NOW - 1))  # within the 30 s two clocks may differ
    code, out = h.run("verify", "card")
    assert code == 1 and out["reason"] == "expired" and "evidence" not in out, out


def test_card_from_the_future_is_rejected(h, inst):
    publish(h, inst.make_card(issued_at=NOW + 31))
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "not-yet-valid"


def test_a_later_card_is_signature_valid_but_incomplete(h, inst):
    """Without the log's policy leaves (no /v2/policies here) a later card's currency is unproven: exit 1, and it
    is not stored, so it can never make the card in force look superseded (the 2026-10-20 defect: 0.1.0 stored
    it, and every later check of the bootstrap card exited 2)."""
    publish(h, inst.card)
    assert h.run("verify", "card")[0] == 0
    later = inst.make_card(issued_at=NOW - 60, mutate=lambda c: c["assurances"][3].update(status="proven"))
    publish(h, later)
    code, out = h.run("verify", "card")
    assert code == 1, out
    assert "incomplete" in out["error"] and out["bootstrap"] is False
    paths = {d["path"]: d for d in out["diff"]}
    assert paths["$.assurances[3].status"]["new"] == "proven"
    assert paths["$.issued_at"]["new"] == NOW - 60
    assert "stored" not in out and "nothing was stored" in out["error"]
    assert out["currency_state"] == "unproven" and out["policy_history"]["available"] is False
    code, text = h.run_text("verify", "card")
    assert code == 1 and "STATUS" in text and text.rstrip().splitlines()[-1].startswith("error: incomplete")
    publish(h, inst.card)
    assert h.run("verify", "card")[0] == 0  # the bootstrap card still verifies


def test_a_superseded_card_is_rejected(h):
    """A card issued before one that verified as current (here: proven in force by the policy leaves) is rejected
    from the stored history alone, even where the policy leaves cannot be read."""
    from conftest import DAY, Site

    site = Site()
    newer = site.successor()
    h.clock[0] = NOW + 7 * DAY
    site.publish(h, served=newer)
    site.policy(h)
    assert h.run("verify", "card")[0] == 0  # in force: stored
    site.publish(h, listing=False)  # the older bootstrap card served again, and no policy listing
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "superseded", out


def test_witness_downgrade_against_the_saved_card(h):
    w1, w2 = Witness("w.test/1"), Witness("w.test/2")
    inst = Instance(Log(5), witnesses=[w1, w2], quorum=2)
    policy_for(h.home, inst)
    publish(h, inst.card)
    assert h.run("verify", "card")[0] == 0
    publish(h, inst.make_card(issued_at=NOW - 60, quorum=1))
    code, out = h.run("verify", "card")
    # this fixture serves no policy leaves, and a logged change with its notice would look the same: incomplete, not
    # evidence (AICS-1 §14; exit 2 for an unlogged weaker card at the pinned URL is in test_card_evidence.py)
    assert code == 1 and out["reason"] == "witness-downgrade" and out["error"].startswith("incomplete:"), out
    assert out["witness_policy_vs_saved_card"] == "weaker" and out["policy_history"]["available"] is False
    assert "evidence" not in out and "stored" not in out


def test_keys_that_differ_from_the_bundle_are_rejected(h, inst):
    other = Log(1)
    publish(h, inst.make_card(mutate=lambda c: c.update(log_vkey=other.vkey)))
    code, out = h.run("verify", "card")
    assert code == 2 and out["evidence"]["reason"] == "anchor-mismatch"
    assert out["anchor_mismatches"][0]["field"] == "log_vkey"


def test_duplicate_json_members_are_rejected(h, inst):
    raw = json.dumps(inst.card)[:-1] + ', "origin": "evil.example/log"}'
    h.fetcher.set(CARD_URL, raw)
    code, out = h.run("verify", "card")
    assert code == 1 and "duplicate" in out["error"]


def test_no_policy_key_pinned(h):
    make_policy(h.home, Log(5))
    code, out = h.run("verify", "card")
    assert code == 1 and "no policy key" in out["error"]


def test_signing_input_matches_the_a2a_procedure():
    """Independent re-computation of the AICS-1 §13.2 / A2A §8.4.2 signing input."""
    key = idkeys.generate_keypair()
    kid = did(key)
    card = {"b": 1, "a": "x", "nested": {"z": [1, 2], "y": True}}
    signed = sign_card(card, key, kid)
    sig = signed["signatures"][0]
    payload = canonicalize({k: v for k, v in signed.items() if k != "signatures"})
    assert payload == b'{"a":"x","b":1,"nested":{"y":true,"z":[1,2]}}' == unsigned_payload(signed)

    def b64u(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    def unb64u(s: str) -> bytes:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    assert unb64u(sig["protected"]) == canonicalize({"alg": "EdDSA", "kid": kid, "typ": "JOSE"})
    signing_input = (sig["protected"] + "." + b64u(payload)).encode()
    Ed25519PublicKey.from_public_bytes(key.public_key().public_bytes_raw()).verify(unb64u(sig["signature"]),
                                                                                  signing_input)
    assert check_signatures(signed, [parse_policy_key(kid)])[0].status == "valid"
    other = parse_policy_key(did(idkeys.generate_keypair()))
    assert check_signatures(signed, [other])[0].status == "unknown-kid"
    assert card_hash(signed) == __import__("hashlib").sha256(canonicalize(signed)).hexdigest()


def test_witness_strictness_rule():
    a, b = "a+00000000+x", "b+00000000+y"
    assert compare_witness((1, frozenset({a}), 300), (1, frozenset({a}), 300)) == "same"
    assert compare_witness((1, frozenset({a}), 300), (1, frozenset({a, b}), 300)) == "weaker"  # b alone now suffices
    assert compare_witness((1, frozenset({a}), 300), (2, frozenset({a, b}), 300)) == "stronger"
    assert compare_witness((1, frozenset({a}), 300), (1, frozenset({a}), 600)) == "weaker"
    assert compare_witness((0, frozenset(), 300), (1, frozenset({b}), 300)) == "stronger"


def test_loads_strict_rejects_nan_and_duplicates():
    with pytest.raises(ValueError):
        loads_strict('{"a": NaN}')
    with pytest.raises(ValueError):
        loads_strict('{"a": 1, "a": 2}')


def test_json_diff():
    assert json_diff({"a": 1, "b": [1]}, {"a": 2, "b": [1, 2], "c": 3}) == [
        {"op": "changed", "path": "$.a", "old": 1, "new": 2},
        {"op": "added", "path": "$.b[1]", "new": 2},
        {"op": "added", "path": "$.c", "new": 3},
    ]


# --- the contributions and owner-service profile (AICS-1+SUP-1, §20.9) and unsupported profiles (§19) ---------


def sup(body: dict) -> None:
    """Turn a base card body into an AICS-1+SUP-1 card body (§20.9): the sup member and the twelve §20.8 codes."""
    from aics_cli.card import SUP_REFUSALS, sup_asset_hash

    body["spec"] = "AICS-1+SUP-1"
    body["reason_codes"]["refusal"] = body["reason_codes"]["refusal"] + list(SUP_REFUSALS)
    body["sup"] = {"asset_hash": sup_asset_hash(body["origin"]),
                   "contributions": [{"network": "base-usdc", "asset": "USDC", "decimals": 6,
                                      "address": "0x" + "ab" * 20, "units_per_sup": 10000}],
                   "intent_seconds": 86400, "claim_seconds": 604800, "record_seconds": 31536000, "storage": None}


def test_a_sup_1_card_verifies_as_the_bootstrap_card(h, inst):
    card = inst.make_card(mutate=sup)
    assert schema_problems(card) == []
    from conftest import make_policy

    make_policy(h.home, inst.log, policy_kid=did(inst.policy_key), owner_kid=did(inst.owner_key),
                bootstrap_card_hash=card_hash(card))
    publish(h, card)
    code, out = h.run("verify", "card")
    assert code == 0 and out["bootstrap"] is True, out


@pytest.mark.parametrize("change, where", [
    (lambda c: c.pop("sup"), "$"),
    (lambda c: c["sup"].update(asset_hash="00" * 32), "$.sup.asset_hash"),
    (lambda c: c["sup"].update(intent_seconds=10, claim_seconds=5), "$.sup"),
    (lambda c: c["sup"].update(intent_seconds=0), "$.sup.intent_seconds"),
    (lambda c: c["sup"].update(record_seconds=31536001), "$.sup.record_seconds"),
    (lambda c: c["sup"]["contributions"][0].update(units_per_sup=1), "$.sup.contributions[0].units_per_sup"),
    (lambda c: c["sup"]["contributions"][0].update(network="Base USDC"), "$.sup.contributions[0].network"),
    (lambda c: c["sup"]["contributions"].append(dict(c["sup"]["contributions"][0])), "$.sup.contributions"),
    (lambda c: c["sup"].update(storage={"free_quota_bytes": 1024, "unit_bytes": None, "unit_amount": None}),
     "$.sup.storage.free_quota_bytes"),
    (lambda c: c["sup"].update(storage={"free_quota_bytes": 65536, "unit_bytes": 1024, "unit_amount": None}),
     "$.sup.storage"),
    (lambda c: c["sup"].update(extra=1), "$.sup"),
    (lambda c: c["reason_codes"].update(refusal=[x for x in c["reason_codes"]["refusal"] if x != "stale_quote"]),
     "$.reason_codes.refusal"),
])
def test_the_sup_member_follows_section_20_9(inst, change, where):
    def mutate(body):
        sup(body)
        change(body)
    problems = schema_problems(inst.make_card(mutate=mutate))
    assert problems and all(p.split(":", 1)[0] == where for p in problems), problems


def test_the_sup_1_codes_and_member_need_the_profile(inst):
    def base_with(change):
        return lambda body: (sup(body), body.update(spec="AICS-1"), change(body))
    card = inst.make_card(mutate=base_with(lambda b: None))
    assert any(p.startswith("$: unknown members sup") for p in schema_problems(card)), schema_problems(card)
    card = inst.make_card(mutate=base_with(lambda b: b.pop("sup")))
    assert [p.split(":", 1)[0] for p in schema_problems(card)] == ["$.reason_codes.refusal"]  # §20.8 codes stay out
    card = inst.make_card(mutate=lambda b: b.update(spec="AICS-2"))
    assert [p.split(":", 1)[0] for p in schema_problems(card)] == ["$.spec"]


@pytest.mark.parametrize("profile", ["AICS-1+SWARMS-1", "AICS-1+SWARMS-1+SUP-1"])
def test_a_swarms_card_is_an_unsupported_profile(h, inst, profile):
    """AICS-1 §19: a client without the profile rejects it; it never reads the card as a base card."""
    card = inst.make_card(mutate=lambda b: b.update(spec=profile))
    publish(h, card)
    code, out = h.run("verify", "card")
    assert code == 1 and "unsupported profile" in out["error"] and out["profile"] == profile, out
    assert out["supported_profiles"] == ["AICS-1", "AICS-1+SUP-1"]


def test_the_gate_names_the_instances_own_two_ports(h):
    """AICS-1 §13.1 (revision of 2026-10-20): the gate's ports are the instance's own, two distinct TCP ports. A
    staging card beside production states 7800/7801 (its 7700/7701 were production's gates on the same address)
    and verifies as a bootstrap card; the deployment profile's 7700/7701 verify as before (the other tests)."""
    staging = Instance(Log(5))
    assert staging.card["gate"]["tls_port"] == 7700 and staging.card["gate"]["plaintext_port"] == 7701
    staging.card = staging.make_card(mutate=lambda c: c["gate"].update(tls_port=7800, plaintext_port=7801))
    staging.bundle = dataclasses.replace(staging.bundle, bootstrap_card_hash=card_hash(staging.card))
    assert schema_problems(staging.card) == []
    policy_for(h.home, staging)
    publish(h, staging.card)
    code, out = h.run("verify", "card")
    assert code == 0 and out["bootstrap"] is True, out
    for ports, where in (((7800, 7800), "$.gate.plaintext_port"), ((0, 7801), "$.gate.tls_port"),
                         ((7800, 65536), "$.gate.plaintext_port"), (("7800", 7801), "$.gate.tls_port"),
                         ((True, 7801), "$.gate.tls_port")):
        card = staging.make_card(mutate=lambda c: c["gate"].update(tls_port=ports[0], plaintext_port=ports[1]))
        problems = schema_problems(card)
        assert problems and all(p.split(":", 1)[0] == where for p in problems), (ports, problems)

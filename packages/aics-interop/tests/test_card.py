"""The assurance card (AICS-1 §13, §14.5), an AICS-1 artifact with two verifiers.

Producers: the suite's reference (``spec.card_template`` + ``spec.sign_card``)
and aics (``aics_cli.card.sign_card``), which must produce identical JWS bytes.
Verifiers: aics (``policy init`` reading the bootstrap card, ``verify card``)
and aics-conformance (``card.verify_card``, which also needs the card's
policy leaf in an authenticated log scan, served here from aics-tlog tiles).

Both verifiers implement the 0.2-draft card and refuse the 0.1-draft one, and
both compare every reason registry with §17.2, the refusal registry plus
exactly the card's own ``secret_format:<id>`` instances (F13, F22, F24 and F25
are retired).  The registry checks are tested with negative cases on the card
shape each verifier accepts (``accepted_shape``), the 0.2-draft card.
"""

from __future__ import annotations

import itertools
import json

import pytest

from aics_interop import aicslog, drivers, spec, world

CARD_URL = "https://interop.test/.well-known/aics-card.json"
NOW = world.NOW
#: The historical 0.1-draft refusal registry with the card's one secret pattern.
REG_01 = list(spec.REFUSAL_DETAILED) + ["secret_format:github_pat"]
#: The complete 0.2-draft §17.2 refusal registry with the card's one secret pattern.
REG_02 = list(world.interop_card()["reason_codes"]["refusal"])


def card_01(refusal=None) -> dict:
    """The historical 0.1-draft card: version 0.1-draft, every spec_versions pin 1.0.0 (both verifiers refuse it)."""
    return world.interop_card(version="0.1-draft", spec_versions=spec.SPEC_VERSIONS_01,
                              refusal=REG_01 if refusal is None else refusal)


CARDS = {"0.2-draft": world.interop_card, "0.1-draft": card_01}

#: Card shapes (version, spec_versions, refusal registry), in AICS-1 order: the 0.2-draft card, the 0.1-draft
#: card carrying the 0.2-draft registry, the historical 0.1-draft card.
SHAPES = (("0.2-draft", spec.SPEC_VERSIONS, REG_02), ("0.1-draft", spec.SPEC_VERSIONS_01, REG_02),
          ("0.1-draft", spec.SPEC_VERSIONS_01, REG_01))

#: §13.1 "Reasons MUST equal §17's registries ... plus only those active secret_format:<id> instances"; §17.2
#: "invalid_signature and other unregistered synonyms MUST NOT silently become new codes".
REGISTRY_MUTATIONS = {
    "adds-invalid_signature": lambda codes: codes + ["invalid_signature"],
    "adds-whatever": lambda codes: codes + ["whatever"],
    "drops-malformed": lambda codes: [c for c in codes if c != "malformed"],
    "unknown-secret-pattern": lambda codes: codes + ["secret_format:no_such_pattern"],
}


def make_card(shape, refusal: list[str] | None = None) -> dict:
    version, pins, codes = shape
    return world.interop_card(version=version, spec_versions=pins, refusal=list(codes) if refusal is None else refusal)


def trust_for(card: dict) -> dict:
    return aicslog.trust_bundle(card_hash=spec.card_hash(card))


_homes = itertools.count()


def aics_verify_card(card: dict, tmp_path) -> drivers.CliResult:
    home = tmp_path / f"home-{next(_homes)}"
    cli = drivers.AicsCli(home=home, now=NOW)
    pinned = cli.pin(spec.readme_block(spec.J(trust_for(card))), quorum=0)
    if pinned.code != 0:  # a precondition, never the finding under test
        pytest.fail(f"aics policy init failed: {pinned.data}")
    (home / "card.json").write_text(json.dumps(card))
    return cli.run("verify", "card", "--file", str(home / "card.json"))


def conformance_verify_card(card: dict, web) -> dict:
    from aics_conformance.card import verify_card

    log = aicslog.standard_log(5, card=card)
    web.serve_log(aicslog.PREFIX, log.note(5), log.tiles(5))
    ctx = drivers.conformance_context(web, drivers.conformance_policy(trust_for(card)), NOW)
    c, hist, _ = verify_card(ctx, card)
    return {"card": c, "policy_events": hist.policy_events}


def conformance_card_error(card: dict, web) -> str | None:
    """aics-conformance's refusal message for ``card`` (None: accepted); its refusals are ValueErrors."""
    try:
        conformance_verify_card(card, web)
    except ValueError as exc:
        return str(exc)
    return None


def accepted_shape(accepts) -> tuple:
    """The first card shape the verifier accepts: the base the negative cases change, so that a refusal is due to
    the change alone whatever the state of F13 and F22 (``pytest.fail`` when it accepts none)."""
    for shape in SHAPES:
        if accepts(make_card(shape)):
            return shape
    pytest.fail("the verifier accepts none of the card shapes")


def policy_init_with_card(card: dict, web, tmp_path) -> drivers.CliResult:
    web.set(CARD_URL, json.dumps(card))
    cli = drivers.AicsCli(home=tmp_path / f"home-{next(_homes)}", web=web, now=NOW)
    return cli.run("policy", "init", "--bundle", spec.readme_block(spec.J(trust_for(card))), "--require-sources", "1",
                   "--card-url", CARD_URL)


# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", sorted(CARDS))
def test_card_signers_agree(version):
    from aics_cli.card import card_hash, sign_card, unsigned_payload

    k = aicslog.Keys()
    card = CARDS[version]()
    ours = spec.sign_card(card, k.policy, spec.kid(k.policy))
    theirs = sign_card(card, k.policy, spec.kid(k.policy))
    assert spec.J(ours) == spec.J(theirs) == spec.J(card)
    assert card_hash(card) == spec.card_hash(card)
    assert unsigned_payload(card) == spec.J({x: v for x, v in card.items() if x != "signatures"})
    header = spec.strict_json(spec.dU64(card["signatures"][0]["protected"]))
    assert header == {"alg": "EdDSA", "kid": spec.kid(k.policy), "typ": "JOSE"}


def test_the_0_2_card_is_the_section_13_1_schema():
    """The reference card has exactly the §13.1 members and the 0.2-draft pins (what the verifiers must accept)."""
    card = world.interop_card()
    assert card["version"] == "0.2-draft" and card["spec_versions"] == spec.SPEC_VERSIONS
    assert len(card) == 27 and len(card["assurances"]) == 15
    refusal = card["reason_codes"]["refusal"]
    assert set(spec.REFUSAL_CHARTER) <= set(refusal) and "secret_format:github_pat" in refusal
    assert len(refusal) == len(set(refusal)) == 30 + 1 + 11
    assert spec.card_problems(card) == []


def test_the_reference_refuses_what_section_13_1_refuses():
    """The reference schema check (``spec.card_problems``) on the 0.1-draft card and every registry change."""
    assert set(spec.card_problems(card_01())) == {"$.version: must be '0.2-draft'",
                                                   "$.spec_versions: must be the 0.2-draft pins",
                                                   "$.reason_codes.refusal: must equal the §17.2 registry"}
    for mutation, change in REGISTRY_MUTATIONS.items():
        assert spec.card_problems(world.interop_card(refusal=change(list(REG_02)))) == [
            "$.reason_codes.refusal: must equal the §17.2 registry"], mutation


# --- aics -----------------------------------------------------------------------


def test_aics_refuses_the_0_1_card(tmp_path):
    """§13.1 (0.2-draft): a 0.1-draft card, signed the same way, is refused for its version and pins."""
    r = aics_verify_card(card_01(), tmp_path)
    problems = r.evidence.get("problems") or []
    assert (r.code, r.evidence.get("reason")) == (2, "schema"), r.data
    assert {"$.version", "$.spec_versions"} <= {p.split(":", 1)[0] for p in problems}, problems


def test_aics_verifies_the_0_2_card(tmp_path):
    r = aics_verify_card(world.interop_card(), tmp_path)
    assert r.code == 0, r.data.get("evidence", {}).get("problems")


def test_aics_policy_init_adopts_the_bootstrap_card_policy(web, tmp_path):
    """policy init reads the witness policy from the 0.2-draft bootstrap card, and refuses the 0.1-draft one."""
    card = world.interop_card()
    r = policy_init_with_card(card, web, tmp_path)
    assert r.code == 0, r.data
    p = r.data["policy"]
    assert (p["quorum"], p["max_checkpoint_age"]) == (2, 300) and p["witness_vkeys"] == world.witness_vkeys()
    assert p["sources"]["quorum"] == [f"card:bootstrap:{spec.card_hash(card)}"]
    r = policy_init_with_card(card_01(), web, tmp_path)
    assert r.code != 0 and any(x.startswith("$.version") for x in r.evidence.get("schema_problems") or []), r.data


def test_aics_policy_init_reads_a_0_2_bootstrap_card(web, tmp_path):
    """The README's one-command flow (policy init without --no-card) against a 0.2-draft instance."""
    r = policy_init_with_card(world.interop_card(), web, tmp_path)
    assert r.code == 0, r.data.get("evidence", {}).get("schema_problems")


def test_aics_accepts_the_complete_0_2_refusal_registry(tmp_path):
    """The positive half: the complete §17.2 registry, in any order (the negative cases are below)."""
    r = aics_verify_card(make_card(SHAPES[0], list(reversed(REG_02))), tmp_path)
    assert r.code == 0, r.data


@pytest.mark.parametrize("mutation", sorted(REGISTRY_MUTATIONS))
def test_aics_refuses_a_refusal_registry_that_is_not_section_17(mutation, tmp_path):
    shape = accepted_shape(lambda card: aics_verify_card(card, tmp_path).code == 0)
    r = aics_verify_card(make_card(shape, REGISTRY_MUTATIONS[mutation](list(shape[2]))), tmp_path)
    problems = r.evidence.get("problems") or []
    assert r.code != 0 and any(p.startswith("$.reason_codes") for p in problems), r.data


@pytest.mark.parametrize("mutation", sorted(REGISTRY_MUTATIONS))
def test_aics_policy_init_refuses_a_refusal_registry_that_is_not_section_17(mutation, web, tmp_path):
    """The same check through the one-command bootstrap (policy init reading the bootstrap card)."""
    shape = accepted_shape(lambda card: policy_init_with_card(card, web, tmp_path).code == 0)
    r = policy_init_with_card(make_card(shape, REGISTRY_MUTATIONS[mutation](list(shape[2]))), web, tmp_path)
    problems = r.evidence.get("schema_problems") or []
    assert r.code != 0 and any(p.startswith("$.reason_codes") for p in problems), r.data


# --- aics-conformance -------------------------------------------------------------


def test_conformance_refuses_the_0_1_card(web):
    """§13.1 (0.2-draft): aics-conformance refuses a 0.1-draft card, signed the same way, for its version."""
    error = conformance_card_error(card_01(), web)
    assert error is not None and "card version must be '0.2-draft'" in error, error


def test_conformance_verifies_the_0_2_card(web):
    out = conformance_verify_card(world.interop_card(), web)
    assert out["policy_events"] == [0, 1]


def test_conformance_accepts_the_complete_0_2_refusal_registry(web):
    """The complete §17.2 registry, in any order."""
    conformance_verify_card(make_card(SHAPES[0], list(reversed(REG_02))), web)


@pytest.mark.parametrize("mutation", sorted(REGISTRY_MUTATIONS))
def test_conformance_refuses_a_refusal_registry_that_is_not_section_17(mutation, web):
    shape = accepted_shape(lambda card: conformance_card_error(card, web) is None)
    error = conformance_card_error(make_card(shape, REGISTRY_MUTATIONS[mutation](list(shape[2]))), web)
    assert error is not None, "aics-conformance accepted the changed registry"


def test_conformance_accepts_refusal_leaves_with_charter_spellings():
    """§17.2 (0.2-draft) registers the charter spellings as refusal codes; a refusal leaf may carry one."""
    from aics_conformance import schema

    k = aicslog.Keys()
    refused = []
    for code in spec.REFUSAL_CHARTER:
        q = {"envelope_hash": spec.hexH(code.encode()), "request_hash": None, "attempt_kid": None,
             "attempt_nonce": None, "attempt_expires": None, "reason_code": code, "conflict_index": None,
             "receipt_hash": None}
        e = spec.native_envelope(k.policy, origin=aicslog.ORIGIN, typ="refusal", payload=q, created=aicslog.T0,
                                 nonce=spec.H(code.encode())[:16])
        try:
            schema.validate_entry(spec.entry(e, aicslog.T0), aicslog.ORIGIN)
        except ValueError:
            refused.append(code)
    assert refused == []


def test_conformance_accepts_a_refusal_leaf_with_a_detailed_code():
    from aics_conformance import schema

    k = aicslog.Keys()
    q = {"envelope_hash": spec.hexH(b"x"), "request_hash": None, "attempt_kid": None, "attempt_nonce": None,
         "attempt_expires": None, "reason_code": "rate_limit", "conflict_index": None, "receipt_hash": None}
    e = spec.native_envelope(k.policy, origin=aicslog.ORIGIN, typ="refusal", payload=q, created=aicslog.T0,
                             nonce=spec.H(b"x")[:16])
    schema.validate_entry(spec.entry(e, aicslog.T0), aicslog.ORIGIN)


# --- tampering ----------------------------------------------------------------------


def test_an_altered_card_is_rejected_by_both(web, tmp_path):
    """Signed bytes changed after signing, on the card shape each verifier accepts."""
    from aics_conformance.card import verify_card
    from cryptography.exceptions import InvalidSignature

    card = make_card(accepted_shape(lambda c: aics_verify_card(c, tmp_path).code == 0))
    bad = {**card, "max_checkpoint_age": 600}  # signature kept
    r = aics_verify_card(bad, tmp_path)
    assert (r.code, r.evidence.get("reason")) == (2, "invalid-signature"), r.data
    card = make_card(accepted_shape(lambda c: conformance_card_error(c, web) is None))
    bad = {**card, "max_checkpoint_age": 600}
    log = aicslog.standard_log(5, card=card)
    web.serve_log(aicslog.PREFIX, log.note(5), log.tiles(5))
    ctx = drivers.conformance_context(web, drivers.conformance_policy(trust_for(card)), NOW)
    with pytest.raises(InvalidSignature):
        verify_card(ctx, bad)

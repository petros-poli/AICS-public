"""Test helpers: the template card, statement edits, deterministic public test keys and test pattern definitions."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import validate_card as vc

CARD_DIR = Path(__file__).resolve().parents[1]
CARD_PATH = CARD_DIR / "card-content.json"
REPO = CARD_DIR.parent
#: A fixed signing time for filled test cards: 2026-11-01 00:00:00 UTC.
ISSUED_AT = 1793491200
ONE_YEAR = 365 * 86400


def load_template() -> dict[str, Any]:
    return vc.load_json(CARD_PATH.read_bytes())


def assurance(card: dict[str, Any], aid: str) -> dict[str, Any]:
    return next(a for a in card["assurances"] if a["id"] == aid)


def statement(card: dict[str, Any], aid: str, tag: str) -> str:
    return next(t for t in assurance(card, aid)["assumptions"] if t.startswith(f"[{tag}] "))


def tags(card: dict[str, Any], aid: str) -> set[str]:
    """The statement tags of one assurance."""
    return {m.group(1) for t in assurance(card, aid)["assumptions"] if (m := vc.TAG.match(t))}


def replace_statement(card: dict[str, Any], aid: str, tag: str, text: str | None) -> None:
    """Replace the [tag] statement of ``aid`` with ``text``, or drop it when ``text`` is None."""
    items = assurance(card, aid)["assumptions"]
    i = next(i for i, t in enumerate(items) if t.startswith(f"[{tag}] "))
    if text is None:
        del items[i]
    else:
        items[i] = text


#: Test pattern definitions for the card's ten ids, in the published document's format and order (public test data
#: shaped like docs/legal/secret-patterns.json).  tests/test_sources.py compares the published document with the
#: card and the server, not these.
PATTERN_DEFINITIONS: list[dict[str, str]] = [
    {"id": "anthropic_key", "regex": r"sk-ant-[A-Za-z0-9_-]{20,}", "note": "Anthropic API key"},
    {"id": "github_token", "regex": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}",
     "note": "GitHub token"},
    {"id": "huggingface_token", "regex": r"hf_[A-Za-z0-9]{20,}", "note": "Hugging Face access token"},
    {"id": "aws_access_key", "regex": r"(?:AKIA|ASIA)[0-9A-Z]{16}", "note": "AWS access key id"},
    {"id": "slack_token", "regex": r"xox[baprs]-[A-Za-z0-9-]{15,}", "note": "Slack token"},
    {"id": "pem_private_key", "regex": r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", "note": "PEM private-key header"},
    {"id": "stripe_secret_key", "regex": r"(?:sk|rk)_live_[A-Za-z0-9]{20,}", "note": "Stripe live secret key"},
    {"id": "openai_project_key", "regex": r"sk-proj-[A-Za-z0-9_-]{20,}", "note": "OpenAI project API key"},
    {"id": "openai_service_account_key", "regex": r"sk-svcacct-[A-Za-z0-9_-]{20,}",
     "note": "OpenAI service-account key"},
    {"id": "openai_admin_key", "regex": r"sk-admin-[A-Za-z0-9_-]{20,}", "note": "OpenAI admin key"},
]


def pattern_document(definitions: list[dict[str, str]] | None = None) -> dict[str, object]:
    """A pattern-definition document ``{"v": 1, "patterns": [...]}`` (a deep copy; the test definitions by default)."""
    return {"v": 1, "patterns": copy.deepcopy(PATTERN_DEFINITIONS if definitions is None else definitions)}


PATTERN_DOCUMENT = pattern_document()


def errors(card: Any, **kw: Any) -> list[str]:
    """Validation errors; with ``final=True`` the test pattern definitions are supplied unless ``patterns`` is given."""
    if kw.get("final"):
        kw.setdefault("patterns", PATTERN_DOCUMENT)
    return vc.validate(card, **kw).report.errors


def key(seed_byte: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def raw_public(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes_raw()


def did_key(k: Ed25519PrivateKey) -> str:
    return "did:key:z" + vc.b58encode(b"\xed\x01" + raw_public(k))


def vkey(name: str, key_type: int, k: Ed25519PrivateKey) -> str:
    raw = bytes([key_type]) + raw_public(k)
    key_id = hashlib.sha256(name.encode() + b"\n" + raw).digest()[:4].hex()
    return f"{name}+{key_id}+{base64.b64encode(raw).decode()}"


#: Test keys, seeded like AICS-1 Appendix A (02 log, 03 policy, 04 owner, 06 witness). Public test values.
LOG_KEY, POLICY_KEY, OWNER_KEY, WITNESS_KEY = key(2), key(3), key(4), key(6)
WITNESS_NAME = "witness1.example.org/w1"
FOUNDER_WITNESS_STATEMENT = (
    "[founder-witness] A founder-run witness proves freshness, not independence. The listed witness is run by the "
    "operator on a second provider: trust_domain founder, independent false. It stays in the log's trust domain, so "
    "its cosignatures do not make G5 proven.")


def launch_witness_policy(card: dict[str, Any]) -> dict[str, Any]:
    """A quorum-0 witness policy on *card*: no witness, with the G5 statements of the bootstrap card of genesis 1
    (2026-10-19, a log since discarded).  card-content.json, the first card of genesis v2, lists the founder-run
    witness from the start."""
    card["witness_policy"] = {"quorum": 0, "witnesses": []}
    replace_statement(card, "G5", "witness-policy", "[witness-policy] Witness policy at launch: quorum 0, and no "
                      "witness is listed (charter commitment 6).")
    replace_statement(card, "G5", "founder-witness", None)
    replace_statement(card, "G5", "witness-verification", None)
    return card


def add_founder_witness(card: dict[str, Any], *, statement_too: bool = True) -> dict[str, Any]:
    """The founder-run witness of card-content.json, listed at quorum 1 with its statements; on a launch-policy card
    (:func:`launch_witness_policy`) it is listed again, with the quorum unchanged."""
    witnesses = card["witness_policy"]["witnesses"]
    if not witnesses:
        witnesses.append({"name": WITNESS_NAME, "vkey": vkey(WITNESS_NAME, 0x04, WITNESS_KEY),
                          "trust_domain": "founder", "independent": False})
        if statement_too:
            assurance(card, "G5")["assumptions"].append(FOUNDER_WITNESS_STATEMENT)
    elif not statement_too:
        replace_statement(card, "G5", "founder-witness", None)
    return witnesses[-1]


#: Test contribution addresses in each network's canonical form (public test values, nobody's wallet).
BASE_ADDRESS = "0x" + "ab" * 20
SOLANA_ADDRESS = vc.b58encode(bytes(range(1, 33)))
#: The ciphertext budget the server applies (DEFAULT_LIMITS, decision 22: 8 GiB), which the G3 statement names.
CIPHERTEXT_BUDGET_BYTES = 8 * 1024**3
#: The AICS-1 0.2-draft conformance reports the proven rows G1, G4, G6, G8 and G9 name, in their evidence order: the
#: relaunch build at quorum 0 and at the card's quorum 1, run on the discarded first log before the wipe (card/README.md
#: "Genesis v2", step 0).  The main session adds them to docs/evidence, so this checkout may not hold them yet
#: (tests/test_sources.py's launch test requires them); the filled test cards use test hashes for them.
CONFORMANCE_REPORTS = ("docs/evidence/conformance-2026-10-20-relaunch-build.json",
                       "docs/evidence/conformance-2026-10-20-relaunch-build-quorum1.json")
#: The witness quorum each of those runs required (its run policy, docs/evidence/<name>.policy.toml).
CONFORMANCE_QUORUMS = (0, 1)
TEST_REPORT_SHA256 = {rel: hashlib.sha256(f"a test stand-in for {rel}".encode()).hexdigest()
                      for rel in CONFORMANCE_REPORTS}


def conformance_report(*, fmt: str = "aics-conformance/v1", mode: str = "instance", failing: tuple[str, ...] = (),
                       spec: str = "AICS-1 0.2-draft") -> dict[str, Any]:
    """A conformance report shaped like the harness's (public test data): every G row passes but *failing*."""
    verdicts = {f"G{i}": ("fail" if f"G{i}" in failing else "pass") for i in range(1, 11)}
    checks = [{"id": g, "title": g, "spec_ref": "AICS-1", "verdict": v, "details": {}} for g, v in verdicts.items()]
    if fmt == "aics-interop-server-conformance/v1":
        return {"format": fmt, "spec": spec, "guarantees": verdicts, "verdicts": verdicts, "checks": checks}
    return {"format": fmt, "spec": spec, "mode": mode, "started_at": 1.5, "finished_at": 2.5,
            "counts": {"pass": 10 - len(failing), "fail": len(failing), "skip": 0}, "checks": checks}


def run_policy(quorum: int) -> str:
    """An aics-conformance run policy (TOML, public test values) at *quorum*, shaped like docs/evidence's."""
    vkeys = '["witness1.example.org/w1+00000000+BAAA"]' if quorum else "[]"
    return (f'trust_file = "trust-bundle.json"\npages = "https://wesupport-ai.com"\nquorum = {quorum}\n'
            f"witness_vkeys = {vkeys}\nmax_checkpoint_age = 300\n")


def with_networks(card: dict[str, Any]) -> dict[str, Any]:
    """The card as a successor card would list both networks aics-server can credit, with address placeholders.
    The launch card lists none (decision 25: no contribution address was given)."""
    card["sup"]["contributions"] = [
        {"network": network, "asset": "USDC", "decimals": 6, "address": f"<FILL:SUP_ADDRESS:{network}>",
         "units_per_sup": 10000} for network in vc.SUP_NETWORKS]
    return card


def fill_values() -> dict[str, str]:
    """``--set`` values for every placeholder except the document and pattern hashes (``--fill-hashes`` and
    ``--patterns`` fill those); the conformance reports' hashes are test values (:data:`CONFORMANCE_REPORTS`)."""
    return {
        "ISSUED_AT": str(ISSUED_AT),
        "EXPIRES": str(ISSUED_AT + ONE_YEAR),
        "LOG_VKEY": vkey(vc.ORIGIN, 0x01, LOG_KEY),
        "POLICY_KID": did_key(POLICY_KEY),
        "OWNER_KID": did_key(OWNER_KEY),
        "CIPHERTEXT_BUDGET_BYTES": str(CIPHERTEXT_BUDGET_BYTES),
        "WITNESS_NAME": WITNESS_NAME,
        "WITNESS_VKEY": vkey(WITNESS_NAME, 0x04, WITNESS_KEY),
        "CUSTODIAN_NAME": "Test Custodian",
        "CUSTODIAN_HOLDS": "an offline copy of the server seed",
        **{f"SHA256:{rel}": digest for rel, digest in TEST_REPORT_SHA256.items()},
    }


def base_profile(card: dict[str, Any]) -> dict[str, Any]:
    """A copy of the template as a base-profile ``AICS-1`` card: no ``sup`` member, no section 20.8 codes and no
    [contribution-correlation] statement (the contributions and owner-service profile not activated)."""
    out = copy.deepcopy(card)
    out["spec"] = vc.SPEC_BASE
    del out["sup"]
    out["reason_codes"]["refusal"] = [c for c in out["reason_codes"]["refusal"] if c not in vc.REFUSAL_SUP]
    replace_statement(out, "N2", "contribution-correlation", None)
    return out


def dump(card: Any, path: Path) -> Path:
    path.write_text(json.dumps(card, indent=2) + "\n", encoding="utf-8")
    return path

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
    "[founder-witness] The listed witness is run by the operator on a second provider: trust_domain founder, "
    "independent false. It stays in the log's trust domain, so its cosignatures do not make G5 proven.")


def add_founder_witness(card: dict[str, Any], *, statement_too: bool = True) -> dict[str, Any]:
    """List the founder-run witness, as a successor card would once the server feeds it (quorum unchanged)."""
    card["witness_policy"]["witnesses"].append({
        "name": WITNESS_NAME, "vkey": vkey(WITNESS_NAME, 0x04, WITNESS_KEY), "trust_domain": "founder",
        "independent": False})
    if statement_too:
        assurance(card, "G5")["assumptions"].append(FOUNDER_WITNESS_STATEMENT)
    return card["witness_policy"]["witnesses"][-1]


#: Test contribution addresses in each network's canonical form (public test values, nobody's wallet).
BASE_ADDRESS = "0x" + "ab" * 20
SOLANA_ADDRESS = vc.b58encode(bytes(range(1, 33)))
#: The ciphertext budget the server applies (DEFAULT_LIMITS, decision 22: 8 GiB), which the G3 statement names.
CIPHERTEXT_BUDGET_BYTES = 8 * 1024**3


def with_networks(card: dict[str, Any]) -> dict[str, Any]:
    """The card as a successor card would list both networks aics-server can credit, with address placeholders.
    The launch card lists none (decision 25: no contribution address was given)."""
    card["sup"]["contributions"] = [
        {"network": network, "asset": "USDC", "decimals": 6, "address": f"<FILL:SUP_ADDRESS:{network}>",
         "units_per_sup": 10000} for network in vc.SUP_NETWORKS]
    return card


def fill_values() -> dict[str, str]:
    """``--set`` values for every placeholder except the hashes (``--fill-hashes`` and ``--patterns`` fill those)."""
    return {
        "ISSUED_AT": str(ISSUED_AT),
        "EXPIRES": str(ISSUED_AT + ONE_YEAR),
        "LOG_VKEY": vkey(vc.ORIGIN, 0x01, LOG_KEY),
        "POLICY_KID": did_key(POLICY_KEY),
        "OWNER_KID": did_key(OWNER_KEY),
        "CIPHERTEXT_BUDGET_BYTES": str(CIPHERTEXT_BUDGET_BYTES),
        "CUSTODIAN_NAME": "Test Custodian",
        "CUSTODIAN_HOLDS": "an offline copy of the server seed",
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

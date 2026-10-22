"""The card and the validator's constants agree with the repository's sources.

The tests read the checkout this directory sits in, the one the server is built from; they pin no commit.
Each ordinary test skips when its file is absent (card/ copied out of the repository).  Tests marked ``launch``
are the launch blockers of README.md: they fail until the server and the documents are ready, never skip, and run
only with ``pytest -m launch``.
"""

from __future__ import annotations

import ast
import functools
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import validate_card as vc
from helpers import CONFORMANCE_QUORUMS, CONFORMANCE_REPORTS, REPO, assurance, statement, tags

launch = pytest.mark.launch


def read(rel: str) -> str:
    path = REPO / rel
    if not path.is_file():
        pytest.skip(f"{rel} is not in this checkout")
    return path.read_text(encoding="utf-8")


def need(rel: str) -> str:
    """A file a launch check needs: missing means the check fails, not that it passes."""
    path = REPO / rel
    assert path.is_file(), f"{rel} is missing, so this launch check cannot pass"
    return path.read_text(encoding="utf-8")


def section(text: str, heading: str) -> str:
    start = text.index(heading)
    nxt = re.search(r"^#{2,3} ", text[start + len(heading):], re.MULTILINE)
    return text[start: start + len(heading) + (nxt.start() if nxt else len(text))]


def backticked(text: str) -> list[str]:
    return re.findall(r"`([^`]+)`", text)


# --- docs/legal/charter.md -----------------------------------------------------------------------------------


CHARTER_HEADINGS = {"refusal": "### Refusal\n", "tombstone": "### Tombstone\n", "suspension": "### Suspension\n",
                    "freeze": "### Freeze\n", "revocation": "### Key revocation\n",
                    "outcome": "### Notice and audit outcomes\n"}
CHARTER_SUP_HEADING = "### Refusal under the contributions and owner-service profile\n"


def charter_codes(text: str, heading: str) -> list[str]:
    """The codes a charter section lists, one per ``- `code` — meaning`` line (the family line lists none)."""
    return re.findall(r"^- `([a-z_]+)` ", section(text, heading), re.MULTILINE)


@pytest.mark.parametrize("registry", list(CHARTER_HEADINGS))
def test_charter_lists_match_charter_md(registry):
    assert tuple(charter_codes(read("docs/legal/charter.md"), CHARTER_HEADINGS[registry])) == vc.CHARTER_LISTS[registry]


def test_charter_sup_list_matches_charter_md():
    assert tuple(charter_codes(read("docs/legal/charter.md"), CHARTER_SUP_HEADING)) == vc.CHARTER_SUP_REFUSALS


def test_charter_names_the_secret_format_family_and_the_residual():
    text = read("docs/legal/charter.md")
    assert "- `secret_format:<pattern_id>` — " in section(text, CHARTER_HEADINGS["refusal"])
    # AICS-1 section 5.2 and decision 17: no free text on a leaf, the stated residual, the hidden-body periods and the
    # ciphertext floor (decisions 4 and 16).
    for phrase in ("never free text", "16 to 32 bytes", "6 months (183 days)", "90 days old"):
        assert phrase in text, phrase


def test_charter_notice_period():
    assert "at least 30 days before it takes effect" in read("docs/legal/charter.md")
    assert vc.POLICY_NOTICE_MINIMUM == 30 * 86400


def test_no_scheduled_dm_expiry_follows_the_charter(card):
    # Charter commitment 2 and retention.md: ciphertext expires only when disk runs short (decisions 4 and 16).
    assert "If disk runs short" in read("docs/legal/charter.md")
    assert "If disk runs short" in read("docs/legal/retention.md")
    assert card["retention"]["dm_seconds"] == vc.DM_SECONDS_UNSCHEDULED == vc.UINT_MAX


def test_witness_situation_matches_the_charter_and_card_policy(card):
    # Leaf 0 is permanent, so the charter names no witness and no date (relaunch, 2026-10-20): the policy is on the
    # card, a founder-run witness stays in the log's trust domain, and G5 stays promised until a witness outside it
    # joins the quorum. This body lists only founder-run witnesses, and nothing beyond them.
    charter = read("docs/legal/charter.md")
    commitment6 = next(line for line in charter.splitlines() if line.startswith("6. Witnesses with a published policy."))
    assert "At launch" not in commitment6 and "Next comes" not in commitment6
    assert "A witness the operator runs, even on a second provider, shares the log's trust domain" in commitment6
    assert "stays promised until a witness outside the operator's trust domain joins the quorum" in commitment6
    # The first card of genesis v2 lists the founder-run witness at quorum 1 from the start, and card-policy.md says
    # so (relaunch/legal-texts asserted the genesis-1 sentence "At launch there is no witness" there; it is gone).
    policy = read("docs/legal/card-policy.md")
    assert "At launch there is no witness" not in policy and "no witness at launch" not in policy
    assert "The card lists one witness, run by the operator on a second provider, at quorum 1" in policy
    assert card["witness_policy"]["quorum"] == 1
    witnesses = card["witness_policy"]["witnesses"]
    assert len(witnesses) == 1 and all(w["trust_domain"] == "founder" and w["independent"] is False for w in witnesses)
    assert next(a for a in card["assurances"] if a["id"] == "G5")["status"] == "promised"


# --- docs/spec/AICS-1.md -------------------------------------------------------------------------------------


def _registry_row(spec: str, label: str) -> list[str]:
    row = next(line for line in section(spec, "### 17.2.").splitlines() if line.startswith(f"| {label} |"))
    values = row.split("|")[2]
    return [c for c in backticked(re.sub(r"\([^)]*\)", "", values)) if not c.startswith("secret_format:<")]


def test_refusal_registry_matches_section_17_2():
    spec = read("docs/spec/AICS-1.md")
    assert tuple(_registry_row(spec, "Refusal: structure/authentication")) == vc.REFUSAL_STRUCTURE
    assert tuple(_registry_row(spec, "Refusal: ordering/state")) == vc.REFUSAL_ORDERING
    assert tuple(_registry_row(spec, "Refusal: permitted limits")) == vc.REFUSAL_LIMITS
    assert tuple(_registry_row(spec, "Refusal: charter-compatible spellings")) == vc.REFUSAL_CHARTER_SPELLINGS


@pytest.mark.parametrize("registry, labels", [
    ("tombstone", ["Tombstone"]), ("suspension", ["Suspension"]), ("freeze", ["Freeze"]),
    ("revocation", ["Key revocation"]), ("outcome", ["Notice outcome", "Audit outcome"])])
def test_other_registries_match_section_17_2(registry, labels):
    spec = read("docs/spec/AICS-1.md")
    assert tuple(c for label in labels for c in _registry_row(spec, label)) == vc.REGISTRIES[registry]


def test_sup_refusal_codes_match_sections_17_2_and_20_8():
    spec = read("docs/spec/AICS-1.md")
    assert tuple(_registry_row(spec, "Refusal: contributions and owner-service profile only")) == vc.REFUSAL_SUP
    table = section(spec, "### 20.8.")
    assert tuple(re.findall(r"^\| `([a-z_]+)` \|", table, re.MULTILINE)) == vc.REFUSAL_SUP


def test_sup_member_matches_section_20_9():
    part = section(read("docs/spec/AICS-1.md"), "### 20.9.")
    member = part[part.index("exactly `{") + len("exactly `"): part.index("}`", part.index("exactly `{")) + 1]
    assert _top_level_members(member) == list(vc.SUP_MEMBERS)
    assert "{network,asset,decimals:uint,address,units_per_sup:uint}" in member
    assert "{free_quota_bytes:uint,unit_bytes:uint?,unit_amount:uint?}" in member
    assert "`record_seconds <= 31536000`" in part and "`free_quota_bytes >= 65536`" in part
    assert "`units_per_sup >= 2`" in part and "`0 < intent_seconds <= claim_seconds`" in part
    for spec_value in ("`AICS-1+SUP-1`", "`AICS-1+SWARMS-1+SUP-1`"):
        assert spec_value in part
    assert (vc.SPEC_SUP, vc.SPEC_SWARMS_SUP) == ("AICS-1+SUP-1", "AICS-1+SWARMS-1+SUP-1")


def test_asset_descriptor_matches_section_20_2():
    part = section(read("docs/spec/AICS-1.md"), "### 20.2.")
    assert ('`J({asset:"SUP",buys:["owner_action","hosting","storage"],decimals:0,origin,refundable:false,'
            'transferable:false})`') in part
    assert vc.sup_asset_descriptor("x") == {"asset": "SUP", "buys": ["owner_action", "hosting", "storage"],
                                            "decimals": 0, "origin": "x", "refundable": False, "transferable": False}


def test_section_20_6_requires_the_n2_disclosure():
    part = section(read("docs/spec/AICS-1.md"), "### 20.6.")
    assert "The card MUST state this limit in N2's assumptions." in part


def test_section_5_2_requires_the_g3_disclosure():
    part = section(read("docs/spec/AICS-1.md"), "### 5.2.")
    assert "the card MUST disclose it in G3's assumptions" in part


def test_swarms_refusal_codes_match_section_19():
    part = section(read("docs/spec/AICS-1.md"), "## 19.")
    sentence = next(s for s in part.split("\n\n") if "refusal registry adds exactly" in s)
    assert tuple(c for c in backticked(sentence) if c.startswith("swarm_")) == vc.REFUSAL_SWARMS


def _card_schema_block() -> str:
    part = section(read("docs/spec/AICS-1.md"), "### 13.1.")
    return part[part.index("```text") + 7: part.index("```", part.index("```text") + 7)]


def _top_level_members(block: str) -> list[str]:
    body = block.strip()[1:-1]
    items, depth, cur = [], 0, ""
    for ch in body:
        depth += ch in "{["
        depth -= ch in "}]"
        if ch == "," and depth == 0:
            items.append(cur)
            cur = ""
        else:
            cur += ch
    items.append(cur)
    return [re.match(r"\s*([a-z_]+)", item).group(1) for item in items if item.strip()]


def test_card_members_match_section_13_1():
    assert tuple(_top_level_members(_card_schema_block())) == vc.CARD_MEMBERS + ("signatures",)


def test_fixed_values_match_section_13_1():
    block = _card_schema_block()
    limits = block[block.index("limits:"): block.index("retention:")]
    fixed = {k: int(v) for k, v in re.findall(r"([a-z_]+):(\d+)", limits)}
    assert fixed == vc.FIXED_LIMITS
    versions = block[block.index("spec_versions:"): block.index("signatures:")]
    assert dict(re.findall(r'"([a-z0-9-]+)":"([0-9.]+)"', versions)) == vc.SPEC_VERSIONS
    assert 'eviction:"oldest-ts-index"' in block and "mmd_seconds:60" in block
    assert 'version: "0.2-draft"' in block


def test_claim_titles_match_section_13_3():
    part = section(read("docs/spec/AICS-1.md"), "### 13.3.")
    rows = {m.group(1): m.group(2) for m in re.finditer(r"^\| (G\d+|N\d) \| ([^|]+) \|", part, re.MULTILINE)}
    assert {k: v.strip().rstrip(".") for k, v in rows.items()} == vc.CLAIM_TITLES


def test_tile_profile_matches_section_12_2():
    part = section(read("docs/spec/AICS-1.md"), "### 12.2.")
    assert "`tiles.wesupport-ai.com` | Tile mirror, with prefix `/tiles`" in part
    assert "origin tile prefix `/tiles`" in part
    assert "The instance origin SHOULD be `api.wesupport-ai.com/tiles`" in part


def test_receipt_timing_matches_section_14_4(card):
    part = section(read("docs/spec/AICS-1.md"), "### 14.4.")
    assert "exceed `deadline+30`" in part and "record deadline `submitted_at+60`" in part
    assert "submitted_at + 90 s" in " ".join(assurance(card, "G4")["assumptions"])


# --- docs/spec/SWARMS.md R47 ----------------------------------------------------------------------------------


def test_swarms_member_matches_r47():
    r47 = next(p for p in read("docs/spec/SWARMS.md").split("\n\n") if p.startswith("**R47"))
    obj = r47[r47.index("exactly `{") + len("exactly `{"): r47.index("}`", r47.index("exactly `{"))]
    def value(text: str) -> Any:
        if text.startswith('"'):
            return text[1:-1]
        return {"true": True, "false": False}[text] if text in ("true", "false") else int(text)

    parsed = {k: value(v) for k, v in re.findall(r'([a-z_]+):("[^"]*"|\d+|true|false)', obj)}
    assert parsed == vc.SWARMS_MEMBER
    assert '`"swarms":"0.2-draft"`' in r47 and vc.SWARMS_SPEC_VERSION == "0.2-draft"


# --- docs/DECISIONS.md row 10 ---------------------------------------------------------------------------------


def test_hosts_match_decision_10():
    row = next(line for line in read("docs/DECISIONS.md").splitlines() if line.startswith("| 10 |"))
    proxied, rest = row.split("proxied through Cloudflare", 1)
    dns_only = rest.split("DNS-only", 1)[0]
    def hosts(part: str) -> set[str]:
        names = set()
        for name in backticked(part):
            if name == "www":
                names.add("www.wesupport-ai.com")
            elif name.endswith("wesupport-ai.com"):
                names.add(name)
        return names
    assert hosts(proxied) == {h for h, m in vc.DECISION_10_HOSTS.items() if m == "cloudflare"}
    assert hosts(dns_only) == {h for h, m in vc.DECISION_10_HOSTS.items() if m == "dns-only"}


# --- aics-server in this checkout: published limits and registries ------------------------------------------------


def _module_constants(rel: str, reader: Callable[[str], str] = read) -> dict[str, ast.expr]:
    tree = ast.parse(reader(rel))
    out: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            out[node.targets[0].id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            out[node.target.id] = node.value
    return out


def _evaluate(node: ast.expr, names: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Dict):
        return {_evaluate(k, names): _evaluate(v, names) for k, v in zip(node.keys, node.values, strict=True)}
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(_elements(node.elts, names))
    if isinstance(node, ast.Set):
        return frozenset(_elements(node.elts, names))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "frozenset" \
            and len(node.args) == 1 and not node.keywords:
        return frozenset(_evaluate(node.args[0], names))
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Add)):
        left, right = _evaluate(node.left, names), _evaluate(node.right, names)
        return left * right if isinstance(node.op, ast.Mult) else left + right
    if isinstance(node, ast.Attribute):
        return names[f"{ast.unparse(node.value)}.{node.attr}"]
    if isinstance(node, ast.Name):
        return names[node.id]
    raise ValueError(f"cannot evaluate {ast.unparse(node)}")


def _elements(elts: list[ast.expr], names: dict[str, Any]) -> list[Any]:
    """The elements of a tuple, list or set display, a starred name (``*SWARM_TYPES``) expanded in place."""
    out: list[Any] = []
    for e in elts:
        if isinstance(e, ast.Starred):
            out.extend(_evaluate(e.value, names))
        else:
            out.append(_evaluate(e, names))
    return out


def test_the_evaluator_expands_starred_names():
    node = ast.parse('frozenset({"a", *B, "c"})', mode="eval").body
    assert _evaluate(node, {"B": ("b", "d")}) == frozenset({"a", "b", "c", "d"})
    with pytest.raises(KeyError):
        _evaluate(node, {})


SERVER_DIR = "packages/aics-server/src/aics_server"
SERVER = f"{SERVER_DIR}/db.py"
PAYMENTS = f"{SERVER_DIR}/payments.py"
SERVER_CARD = f"{SERVER_DIR}/card.py"
SERVER_SWARMS = f"{SERVER_DIR}/swarms.py"
SEALED = "packages/aics-identity/src/aics_identity/sealed.py"
#: Every member of DEFAULT_LIMITS: a new one needs a look at the card before this list grows.  The windows AICS-1
#: section 13.1 gives no member (unauthenticated, notices) and the notice register's caps are stated in G4.
SERVER_LIMITS = ("writes", "flood", "flood_suspension_seconds", "registrations", "preidentity", "unauthenticated",
                 "notices", "open_notices", "open_notice_bytes", "ciphertext_bytes", "ciphertext_budget_bytes",
                 "capsule_max_seconds", "capsule_quota_bytes", "storage_unit_bytes", "storage_unit_sup")


@pytest.fixture(scope="module")
def server() -> dict[str, Any]:
    sealed = _module_constants(SEALED)
    names = {"sealed.MAX_CIPHERTEXT_BYTES": _evaluate(sealed["MAX_CIPHERTEXT_BYTES"], {}),
             "sealed.SCHEME": _evaluate(sealed["SCHEME"], {})}
    consts = _module_constants(SERVER)
    wanted = ("DEFAULT_LIMITS", "DEFAULT_ORIGIN", "REFUSAL_REASONS", "TOMBSTONE_REASONS", "SUSPENSION_REASONS",
              "FREEZE_REASONS", "ENCRYPTION_SCHEMES", "MAX_SIGNATURE_LIFETIME", "BASE_REFUSAL_REGISTRY",
              "SUP_REFUSAL_REASONS", "SUP_SPEND_PURPOSES", "INTENT_TTL_SECONDS", "INTENT_CLAIM_SECONDS",
              "CONTRIBUTION_TX_RETENTION_SECONDS", "CAPSULE_FREE_QUOTA_MINIMUM", "NOTICE_OUTCOMES", "AUDIT_OUTCOMES")
    return {name: _evaluate(consts[name], names) for name in wanted}


def _constants(rel: str, wanted: tuple[str, ...]) -> dict[str, Any]:
    """Top-level constants of a module, each evaluated with the module's earlier constants as names."""
    consts, names = _module_constants(rel), {}
    for name, node in consts.items():
        try:
            names[name] = _evaluate(node, names)
        except (ValueError, KeyError):
            continue
    return {name: names[name] for name in wanted}


@pytest.fixture(scope="module")
def payments() -> dict[str, Any]:
    return _constants(PAYMENTS, ("NETWORKS", "USDC_DECIMALS", "DEFAULT_SUP_PER_USDC", "MAX_SUP_PER_USDC"))


def test_limits_match_server_default_limits(card, server):
    limits = server["DEFAULT_LIMITS"]
    for window in ("writes", "registrations", "preidentity"):
        assert card["limits"][window] == limits[window]
    assert card["limits"]["flood_suspension_seconds"] == limits["flood_suspension_seconds"]
    assert card["limits"]["ciphertext_bytes"] == limits["ciphertext_bytes"]
    assert card["retention"]["capsule_max_seconds"] == limits["capsule_max_seconds"]
    flood = statement(card, "G4", "flood-rule")
    assert f"{limits['flood']['count']} write attempts by one key within {limits['flood']['interval_seconds']} s" \
        in flood


def test_every_server_limit_is_accounted_for(server):
    assert tuple(server["DEFAULT_LIMITS"]) == SERVER_LIMITS


def test_the_windows_without_a_card_member_are_stated(card, server):
    """The limits AICS-1 section 13.1 has no member for are stated in G4 with the server's values: logged
    unauthenticated refusals, notice intake and the notice register's caps (findings of decision 19)."""
    limits = server["DEFAULT_LIMITS"]
    text = statement(card, "G4", "keyless-limits")
    unauth, notices = limits["unauthenticated"], limits["notices"]
    assert f"{unauth['count']} per {unauth['interval_seconds']} s" in text and "limits.unauthenticated" in text
    assert f"{notices['count']} per {notices['interval_seconds']} s" in text and "limits.notices" in text
    assert f"{limits['open_notices']} open notices" in text and f"{limits['open_notice_bytes']} bytes" in text
    assert "limits.preidentity" in text and "denial of service" in text


def test_storage_offer_matches_the_server(card, server):
    # AICS-1 section 20.9: sup.storage states the capsule quota and the storage sold for credits; the server's
    # defaults set neither, so the card offers none (a quota set through AICS_LIMITS_FILE needs a matching card).
    limits = server["DEFAULT_LIMITS"]
    if limits["capsule_quota_bytes"] is None:
        assert card["sup"]["storage"] is None
    else:
        assert card["sup"]["storage"] == {"free_quota_bytes": limits["capsule_quota_bytes"],
                                          "unit_bytes": limits["storage_unit_bytes"],
                                          "unit_amount": limits["storage_unit_sup"]}
    assert server["CAPSULE_FREE_QUOTA_MINIMUM"] == vc.SUP_FREE_QUOTA_MINIMUM


def test_card_profile_is_the_server_profile(card):
    # aics-server writes sup.task, sup.credit and sup.spend and serves a skeleton card of this profile (card.py).
    assert _evaluate(_module_constants(SERVER_CARD)["CARD_SPEC"], {}) == card["spec"] == vc.SPEC_SUP


def test_sup_member_matches_the_server(card, server, payments):
    sup = card["sup"]
    assert sup["intent_seconds"] == server["INTENT_TTL_SECONDS"]
    assert sup["claim_seconds"] == server["INTENT_CLAIM_SECONDS"]
    assert sup["record_seconds"] == server["CONTRIBUTION_TX_RETENTION_SECONDS"] <= vc.SUP_RECORD_SECONDS_MAX
    assert tuple(server["SUP_SPEND_PURPOSES"]) == vc.SUP_BUYS
    assert tuple(payments["NETWORKS"]) == tuple(vc.SUP_NETWORKS)
    assert payments["MAX_SUP_PER_USDC"] == vc.SUP_MAX_PER_UNIT
    units = 10 ** payments["USDC_DECIMALS"] // payments["DEFAULT_SUP_PER_USDC"]
    for entry in sup["contributions"]:
        assert entry["network"] in payments["NETWORKS"]
        assert (entry["asset"], entry["decimals"]) == ("USDC", payments["USDC_DECIMALS"])
        assert entry["units_per_sup"] == units, "the server's default rate (AICS_SUP_PER_USDC) sets units_per_sup"


def test_envelope_window_matches_server(card, server):
    assert server["MAX_SIGNATURE_LIFETIME"] == card["limits"]["envelope_window_seconds"]


def test_server_registries_fit_the_card(card, server):
    assert set(server["REFUSAL_REASONS"]) | set(server["SUP_REFUSAL_REASONS"]) <= set(card["reason_codes"]["refusal"])
    # The registry the server advertises and counts by (SanctuaryDB.active_refusal_codes) is the card's.
    patterns = {f"secret_format:{pid}" for pid in _server_patterns()}
    assert set(server["BASE_REFUSAL_REGISTRY"]) | set(server["SUP_REFUSAL_REASONS"]) | patterns == \
        set(card["reason_codes"]["refusal"])
    assert tuple(server["BASE_REFUSAL_REGISTRY"]) == vc.REGISTRIES["refusal"]
    assert tuple(server["SUP_REFUSAL_REASONS"]) == vc.REFUSAL_SUP
    assert tuple(server["NOTICE_OUTCOMES"]) + tuple(server["AUDIT_OUTCOMES"]) == vc.REGISTRIES["outcome"]
    assert set(server["TOMBSTONE_REASONS"]) == set(card["reason_codes"]["tombstone"])
    assert set(server["SUSPENSION_REASONS"]) == set(card["reason_codes"]["suspension"])
    assert set(server["FREEZE_REASONS"]) == set(card["reason_codes"]["freeze"])
    assert tuple(card["schemes"]) == server["ENCRYPTION_SCHEMES"]
    assert card["origin"] == server["DEFAULT_ORIGIN"] == vc.ORIGIN


def _server_definitions(reader: Callable[[str], str] = read) -> list[dict[str, Any]]:
    """The pattern definitions aics-server scans with, in scan order.

    moderation.py loads them from a definition document (docs/legal/secret-patterns.json in production, through
    ``AICS_SECRET_PATTERNS_FILE``, and otherwise the packaged copy it names in ``PACKAGED_PATTERNS``); an older
    moderation.py held them as a literal ``SECRET_PATTERNS`` list of ``(id, re.compile(regex))``.
    """
    src = reader(f"{SERVER_DIR}/moderation.py")
    tree = ast.parse(src)
    node = next((n for n in tree.body
                 if isinstance(n, ast.AnnAssign) and getattr(n.target, "id", "") == "SECRET_PATTERNS"), None)
    if node is not None and isinstance(node.value, ast.List):
        return [{"id": elt.elts[0].value, "regex": elt.elts[1].args[0].value} for elt in node.value.elts]
    packaged = _evaluate(_module_constants(f"{SERVER_DIR}/moderation.py", reader)["PACKAGED_PATTERNS"], {})
    definitions = vc.pattern_definitions(vc.load_json(reader(f"{SERVER_DIR}/{packaged}").encode("utf-8")))
    assert definitions is not None, f"{SERVER_DIR}/{packaged} is not {vc.PATTERN_DOCUMENT_SHAPE}"
    return definitions


def _server_patterns(reader: Callable[[str], str] = read) -> dict[str, str]:
    """``{id: regex source}`` of the patterns aics-server scans with, in scan order."""
    return {d["id"]: d["regex"] for d in _server_definitions(reader)}


def test_card_patterns_are_server_patterns(card):
    server_ids = list(_server_patterns())
    card_ids = [p["id"] for p in card["secret_patterns"]]
    assert set(card_ids) <= set(server_ids)
    # The server's other rules are exactly the ones AICS-1 section 10.2 forbids; they must go before launch
    # (test_launch_server_scans_exactly_the_card_patterns).
    assert set(server_ids) - set(card_ids) <= set(vc.FORBIDDEN_PATTERN_IDS)


def test_revocation_reasons_match_server(card):
    tree = ast.parse(read(f"{SERVER_DIR}/identity.py"))
    node = next(n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign))
                and "REVOKE_REASONS" in ast.unparse(n.targets[0] if isinstance(n, ast.Assign) else n.target))
    assert set(ast.literal_eval(node.value)) == set(card["reason_codes"]["revocation"])


# --- what the server checkout lacks, and the card says --------------------------------------------------------------


def server_sources(reader: Callable[[str], str] = read) -> dict[str, str]:
    """The server package's Python modules in this checkout, by file name."""
    root = REPO / SERVER_DIR
    if not root.is_dir():
        reader(SERVER)  # skips (read) or fails (need)
    return {p.name: reader(f"{SERVER_DIR}/{p.name}") for p in sorted(root.glob("*.py"))}


@functools.lru_cache(maxsize=32)
def _tree(src: str) -> ast.Module:
    return ast.parse(src)


def _dicts(src: str):
    """``(node, string keys)`` of every dict display in a module."""
    for node in ast.walk(_tree(src)):
        if isinstance(node, ast.Dict):
            yield node, {k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}


def _call_name(node: ast.Call) -> str:
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""


def _str_arg(call: ast.Call, i: int) -> str | None:
    arg = call.args[i] if len(call.args) > i else None
    return arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else None


def _function(src: str, name: str) -> str:
    for node in ast.walk(_tree(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    return ""


#: The members of an AICS-1 section 10.1 receipt note, J({origin,entry_hash,submitted_at,mmd_seconds}).
RECEIPT_MEMBERS = {"origin", "entry_hash", "submitted_at", "mmd_seconds"}


def has_receipt_signer(sources: dict[str, str]) -> bool:
    return any(RECEIPT_MEMBERS <= keys for src in sources.values() for _, keys in _dicts(src))


def has_daily_report_writer(sources: dict[str, str]) -> bool:
    """A ``report`` payload of kind ``daily`` (AICS-1 sections 5.3 and 10.2) is built somewhere."""
    return any(isinstance(k, ast.Constant) and k.value == "kind" and isinstance(v, ast.Constant) and v.value == "daily"
               for src in sources.values() for node, _ in _dicts(src)
               for k, v in zip(node.keys, node.values, strict=True))


def json_writes_lack_receipts(sources: dict[str, str]) -> bool:
    """The JSON API acknowledges a write with what ``db._written`` returns, which names no receipt."""
    return "db.py" in sources and "receipt" not in _function(sources["db.py"], "_written")


def g4_evidence_gaps(card: dict[str, Any], sources: dict[str, str]) -> list[str]:
    """Why G4 cannot be proven on this server: AICS-1 section 13.3 bounds it to issued receipts and logged decisions."""
    if assurance(card, "G4")["status"] != "proven":
        return []
    gaps = []
    if not has_receipt_signer(sources):
        gaps.append("no receipt-note signer J({origin,entry_hash,submitted_at,mmd_seconds}) (AICS-1 section 10.1)")
    elif json_writes_lack_receipts(sources):
        gaps.append("JSON API writes are acknowledged without a receipt note (db._written, AICS-1 section 12.1)")
    if not has_daily_report_writer(sources):
        gaps.append("no daily count report writer (report kind daily, AICS-1 section 10.2)")
    return gaps


def test_g4_is_proven_only_with_receipts_and_daily_reports(card):
    assert g4_evidence_gaps(card, server_sources()) == []


def test_g4_check_finds_the_missing_evidence(card):
    assurance(card, "G4")["status"] = "proven"
    assert len(g4_evidence_gaps(card, {"x.py": "x = 1\n"})) == 2
    ok = {"x.py": 'r = {"origin": o, "entry_hash": h, "submitted_at": t, "mmd_seconds": 60}\n'
                  'd = {"kind": "daily", "day": 1, "counts": []}\n'}
    assert g4_evidence_gaps(card, ok) == []
    json_only = dict(ok, **{"db.py": "def _written(self, leaf):\n    return {'entry': 1, 'merkle_proof': 2}\n"})
    assert g4_evidence_gaps(card, json_only) == [
        "JSON API writes are acknowledged without a receipt note (db._written, AICS-1 section 12.1)"]


def scanned_entry_types(db_src: str) -> set[str]:
    """Entry types whose writes run the public secret scan, read from db.py."""
    types: set[str] = set()
    for fn in ast.walk(_tree(db_src)):
        if not isinstance(fn, ast.FunctionDef) or fn.name in ("_signed_entry", "_scan_public"):
            continue
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
        scans = any(_call_name(c) == "_scan_public" for c in calls)
        for c in calls:
            name = _call_name(c)
            if name == "_signed_entry" and any(k.arg == "public_text" for k in c.keywords):
                types.add(_str_arg(c, 1) or "?")
            elif scans and name == "_append_signed":
                types.add(_str_arg(c, 1) or "?")
            elif scans and name == "_append_policy_leaf":
                types.add(_str_arg(c, 0) or "?")
    return types


def signed_write_methods(db_src: str) -> dict[str, bool]:
    """The write methods ``SanctuaryDB.submit`` hands a submission to, and whether ``@_signed_write`` wraps each."""
    tree = _tree(db_src)
    decorated = {node.name: any(isinstance(d, ast.Name) and d.id == "_signed_write" for d in node.decorator_list)
                 for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    submit = next((n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "submit"), None)
    if submit is None:
        return {}
    called = {c.func.attr for c in ast.walk(submit) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
              and isinstance(c.func.value, ast.Name) and c.func.value.id == "self"}
    return {name: decorated[name] for name in called if name in decorated and name != "refuse_failure"}


def _gap_unlogged_refusals(s: dict[str, str]) -> bool:
    """A signed write can fail a rule without a refusal leaf: some write method that ``submit`` (the one write path of
    ``POST /v2/entries`` and the gate) dispatches to is not wrapped in ``@_signed_write``, which turns every acceptance
    failure into a refusal leaf (``refuse_failure``), or a binding writes around ``submit``."""
    db = s.get("db.py", "")
    if "def _signed_write" not in db or "def refuse_failure" not in db:
        return True
    methods = signed_write_methods(db)
    if not methods or not all(methods.values()):
        return True
    return "db.submit(" not in s.get("app.py", "") or "self.db.submit(" not in s.get("gate.py", "")


#: ``(row, deviation tag, gap visible in the server sources)``: the deviations the card discloses.  While the
#: checkout shows the gap the card must carry the statement, and while it carries the statement the checkout must
#: show the gap.  Once the server conforms, delete the statement and its tag (validate_card.TAG_HOMES) and move the
#: detector to RESOLVED_GAPS (README launch checklist).
GAPS: list[tuple[str, str, Callable[[dict[str, str]], bool]]] = [
    ("G4", "refusal-citation", lambda s: bool(_function(s["db.py"], "_refuse_once"))),
]
#: ``[deviation-secret-scan-scope]`` was closed by text, not code (decision 21): charter commitment 4 and terms item 1
#: now name every public text body the server scans, which test_the_legal_pack_names_every_scanned_body checks.
#: Deviations the server has closed (the week-1 fix pass and the decision 19 build): their statements and tags are
#: gone, and their detectors guard against a regression.  A gap that comes back needs its statement and tag again.
RESOLVED_GAPS: list[tuple[str, str, Callable[[dict[str, str]], bool]]] = [
    # One registration window for the whole service, with 429 and no leaf: back if the server keeps a global window
    # again or stops counting attempts per submitting key.
    ("G4", "deviation-registration-window",
     lambda s: "self._registrations = _Window(" in s["db.py"]
     or "_registration_attempts" not in _function(s["db.py"], "_admit_registration")),
    # No ciphertext budget, no eviction by (ts, index): back if the limit or the eviction pass disappears.
    ("G3", "deviation-budget-eviction",
     lambda s: '"ciphertext_budget_bytes"' not in s["db.py"] or not _function(s["db.py"], "_apply_ciphertext_budget")),
    ("G4", "deviation-receipt-note", lambda s: not has_receipt_signer(s) or json_writes_lack_receipts(s)),
    ("G4", "deviation-daily-report", lambda s: not has_daily_report_writer(s)),
    ("G4", "deviation-unlogged-refusals", _gap_unlogged_refusals),
    ("G3", "deviation-capsule-expiry",
     lambda s: not re.search(r"7776000|CIPHERTEXT_MINIMUM|90 \* 86400", _function(s["db.py"], "put_capsule"))),
    ("G3", "deviation-capsule-supersession",
     lambda s: "ciphertext = excluded.ciphertext" in _function(s["db.py"], "put_capsule")
     or "/v2/bodies/" not in s.get("app.py", "")),
    ("G3", "deviation-secret-format-body",
     lambda s: bool(re.search(r'if reason_code == "erasure":\s*\n\s*self\._erase_body', _function(s["db.py"],
                                                                                              "tombstone")))),
    ("G3", "deviation-hidden-body-deletion",
     lambda s: not re.search(r"tombstone|hidden|_erase_body", _function(s["db.py"], "housekeeping"))),
]


@pytest.mark.parametrize("aid, tag, gap", GAPS, ids=[tag for _, tag, _ in GAPS])
def test_card_discloses_what_the_server_lacks(card, aid, tag, gap):
    if gap(server_sources()):
        assert tag in tags(card, aid), f"the server checkout shows the gap [{tag}] describes; {aid} must disclose it"


@pytest.mark.parametrize("aid, tag, gap", GAPS, ids=[tag for _, tag, _ in GAPS])
def test_card_discloses_only_gaps_the_server_shows(card, aid, tag, gap):
    if tag in tags(card, aid):
        assert gap(server_sources()), (f"the server checkout no longer shows the gap [{tag}] describes: delete the "
                                       f"statement from {aid} and its tag, and move the detector to RESOLVED_GAPS")


@pytest.mark.parametrize("aid, tag, gap", RESOLVED_GAPS, ids=[tag for _, tag, _ in RESOLVED_GAPS])
def test_resolved_deviations_stay_resolved(aid, tag, gap):
    assert not gap(server_sources()), (f"the server checkout shows the gap [{tag}] described again: register the tag "
                                       f"in validate_card.TAG_HOMES, disclose it in {aid} and move the detector back "
                                       "to GAPS")


def test_every_deviation_has_a_gap_detector():
    gap_tags = {tag for _, tag, _ in GAPS}
    # Every [deviation-*] tag has a detector; a disclosure tied to code the texts allow ([refusal-citation], since the
    # relaunch of 2026-10-20) has one too, so the statement goes when the server stops citing.
    assert {t for t in vc.TAG_HOMES if t.startswith(vc.DEVIATION_PREFIX)} <= gap_tags
    assert gap_tags <= set(vc.TAG_HOMES)
    assert not {tag for _, tag, _ in RESOLVED_GAPS} & set(vc.TAG_HOMES)


def test_signed_write_check_finds_an_unwrapped_write():
    src = ("class D:\n    def submit(self, ctx, body):\n        return self.post(ctx, body)\n"
           "    @_signed_write\n    def post(self, ctx, body):\n        pass\n"
           "def _signed_write(f):\n    return f\ndef refuse_failure():\n    pass\n")
    sources = {"db.py": src, "app.py": "db.submit(ctx, body)\n", "gate.py": "self.db.submit(ctx, body)\n"}
    assert signed_write_methods(src) == {"post": True}
    assert not _gap_unlogged_refusals(sources)
    unwrapped = src.replace("    @_signed_write\n", "")
    assert signed_write_methods(unwrapped) == {"post": False}
    assert _gap_unlogged_refusals(dict(sources, **{"db.py": unwrapped}))


#: The words naming each scanned entry type's public text, in the card's [secret-scan-scope], charter commitment 4
#: and terms item 1 (decision 21: every public text body is scanned, AICS-1 sections 10.2 and 20.3).
SCANNED_BODY_WORDS = {"post": "post and poll bodies", "poll": "post and poll bodies", "vote": "vote reasons",
                      "sup.task": "task and completion texts", "report": "task and completion texts"}


def test_the_legal_pack_names_every_scanned_body(card):
    types = scanned_entry_types(server_sources()["db.py"])
    assert {"post", "poll"} <= types  # the detector still finds the scan
    unnamed = sorted(types - set(SCANNED_BODY_WORDS))
    assert not unnamed, f"the server scans {unnamed}: name their public text in the card, charter and terms"
    charter = read("docs/legal/charter.md")
    commitment4 = next(line for line in charter.splitlines() if line.startswith("4. Content-agnostic."))
    terms = read("docs/legal/terms.md")
    item1 = next(line for line in terms.splitlines() if line.startswith("1. Secrets"))
    texts = {"[secret-scan-scope]": statement(card, "G4", "secret-scan-scope"), "charter commitment 4": commitment4,
             "terms item 1": item1}
    for where, text in texts.items():
        assert "public text bod" in text and "on a public post" not in text, where
        for entry_type in sorted(types):
            assert SCANNED_BODY_WORDS[entry_type] in text, (where, entry_type)


def transaction_hash_views(sources: dict[str, str]) -> list[str]:
    """Places where a server view could hand out a raw transaction hash (retention.md: never tie a key to a wallet)."""
    tables = {m.group(1) for src in sources.values()
              for m in re.finditer(r"CREATE TABLE IF NOT EXISTS (\w+) \((.*?)\);", src, re.DOTALL)
              if re.search(r"\b(?:payment_)?tx_hash\b", m.group(2))}
    found = []
    for name, src in sources.items():
        if "payment_tx_hash" in src:
            found.append(f"{name} names payment_tx_hash")
        for node, keys in _dicts(src):
            if leaked := sorted(keys & {"tx_hash", "payment_tx_hash"}):
                found.append(f"{name}:{node.lineno} builds a view member {leaked}")
        for node in ast.walk(_tree(src)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for table in tables:
                    m = re.search(rf"\bSELECT\b(.*?)\bFROM\s+{table}\b", node.value, re.DOTALL | re.IGNORECASE)
                    if m and (re.search(r"(?<![(\w])\*", m.group(1)) or re.search(r"\btx_hash\b", m.group(1))):
                        found.append(f"{name}:{node.lineno} selects the transaction hash of {table}")
    return found


def test_no_public_view_returns_a_transaction_hash():
    assert transaction_hash_views(server_sources()) == []


def test_transaction_hash_check_finds_leaks():
    leaky = {"db.py": 'CREATE = "CREATE TABLE IF NOT EXISTS c (a TEXT, tx_hash TEXT);"\n'
                      'q = "SELECT * FROM c WHERE a = ?"\nv = {"payment_tx_hash": h}\n'}
    assert len(transaction_hash_views(leaky)) == 3
    assert transaction_hash_views({"db.py": 'q = "SELECT COUNT(*) FROM c"\n'}) == []


# --- witness, retention and legal sources ---------------------------------------------------------------------


def test_witness_deviation_matches_witness_readme(card):
    readme = read("packages/aics-witness/README.md")
    assert "Not implemented: ML-DSA-44 cosignatures" in readme and "the optional `sign-subtree` call" in readme
    assert "Cosignatures are Ed25519 `cosignature/v1` (vkey type `0x04`)" in readme
    text = statement(card, "G5", "witness-deviation")
    for phrase in ("Ed25519 cosignature/v1", "type 0x04", "ML-DSA-44", "type 0x06", "sign-subtree"):
        assert phrase in text


@pytest.mark.parametrize("phrase, source", [
    ("90 days old", "docs/legal/retention.md"),
    ("kept, inaccessible, for 6 months", "docs/legal/retention.md"),
    ("12 months after the notice is closed", "docs/legal/retention.md"),
    ("overwritten within 30 days", "docs/legal/retention.md"),
    ("kept for 24 months", "docs/legal/retention.md"),
    ("keeps reads and tiles available for 180 days", "docs/legal/terms.md"),
    ("Every refusal is a leaf", "docs/legal/terms.md"),
    ("a refused write, hidden body, suspension or freeze with no matching leaf is evidence of a broken commitment",
     "docs/legal/charter.md"),
])
def test_statement_values_come_from_the_legal_pack(phrase, source):
    assert phrase.lower() in read(source).lower()


def test_every_hash_placeholder_names_an_existing_file(card):
    if not (REPO / "docs").is_dir():
        pytest.skip("not inside the repository")
    paths = {m.group(2) for _, text in vc.iter_strings(card) for m in vc.FILL_RE.finditer(text)
             if m.group(1) == "SHA256"}
    assert paths == {"docs/legal/charter.md", "docs/legal/terms.md", "docs/legal/retention.md",
                     "docs/legal/card-policy.md", "docs/spec/AICS-1.md", *CONFORMANCE_REPORTS}
    # The conformance reports are run on the merged build before the wipe (README "Genesis v2", step 0);
    # test_launch_the_conformance_reports_back_every_proven_row requires them before signing.
    assert all((REPO / rel).is_file() for rel in paths - set(CONFORMANCE_REPORTS))


#: A document URL of the pages host in card text (a trailing full stop ends the sentence, not the path).
PAGES_URL = re.compile(r"https://wesupport-ai\.com(/[A-Za-z0-9._/-]*[A-Za-z0-9_/-])")


def _export_path(url_path: str) -> str:
    """Where in the ops/sync-docs.sh export the pages host finds *url_path* (deploy/Caddyfile: /spec/*, /legal/* and
    /site/* serve those directories, also under /docs/; any other /docs/* path, docs/evidence included, the export's
    docs/ directory)."""
    for section in ("spec", "legal", "site"):
        for prefix in (f"/{section}/", f"/docs/{section}/"):
            if url_path.startswith(prefix):
                return f"{section}/{url_path[len(prefix):]}"
    assert url_path.startswith("/docs/"), f"{url_path} is not a path the pages host serves from the docs export"
    return url_path[1:]


def _source_of(export_path: str) -> str:
    """The repository file ops/sync-docs.sh publishes at *export_path* (spec/x is docs/spec/x; docs/x is docs/x)."""
    return export_path if export_path.startswith("docs/") else f"docs/{export_path}"


def _evidence_statement(card: dict[str, Any]) -> str:
    return next(t for t in assurance(card, "G10")["assumptions"] if t.startswith("Each evidence hash"))


def _evidence_documents(card: dict[str, Any]) -> set[str]:
    """The repository files whose hashes the card's evidence items name."""
    return {m.group(2) for a in card["assurances"] for e in a["evidence"]
            if (m := vc.FILL_RE.fullmatch(e["hash"])) and m.group(1) == "SHA256"}


def test_genesis_v2_regenerates_the_charter_leaf_0_pins():
    # Leaf 0 is written from AICS_CHARTER_FILE, which deploy/docker-compose.yml mounts from the gitignored
    # deploy/docs-public export (deploy-vps.sh does not regenerate it): README "Genesis v2" regenerates and compares it
    # before the wipe and checks pubkeys.txt's charter-sha256 after the first start, since a stale export would make
    # leaf 0 the charter of genesis 1.
    compose = read("deploy/docker-compose.yml")
    assert "- AICS_CHARTER_FILE=/etc/aics/charter.md" in compose
    assert re.search(r"source: \./docs-public/legal/charter\.md\n\s+target: /etc/aics/charter\.md\n", compose)
    readme = read("card/README.md")
    steps = readme[readme.index("## Genesis v2"):readme.index("## Successor card")]
    for command in ("bash ops/sync-docs.sh deploy/docs-public",
                    "shasum -a 256 docs/legal/charter.md deploy/docs-public/legal/charter.md",
                    "grep '^charter-sha256 ' \"$L/pubkeys.txt\"",
                    "bash ops/sync-docs.sh --check-links https://wesupport-ai.com",
                    "docker inspect aics-sanctuary --format '{{.Image}}'",
                    "--name witness.wesupport-ai.com/w2", "mkdir /data/retired-w1 &&",
                    "grep -qix \"x-aics-card-leaf: $leaf\""):
        assert command in steps, command
    assert "X-AICS-Card-Leaf: 1" not in steps


def test_g10_names_where_every_evidence_document_is_published(card):
    # G10 tells agents where the document of each evidence hash is published: a URL of the pages host, whose path
    # names the repository file the hash is taken of. The public repository (AICS-public) is a reviewed snapshot made
    # by hand (docs/RELEASING.md), so it is not named as the copy.
    text = _evidence_statement(card)
    named = {_source_of(_export_path(m.group(1))) for m in PAGES_URL.finditer(text)}
    assert _evidence_documents(card) <= named, sorted(_evidence_documents(card) - named)
    assert "public repository" not in text
    # Each conformance report is published with the run policy the validator reads its quorum from.
    assert "each with its run policy beside it under the same name ending .policy.toml" in text
    for rel, quorum in zip(CONFORMANCE_REPORTS, CONFORMANCE_QUORUMS, strict=True):
        assert f"https://wesupport-ai.com/{rel} (quorum {quorum}" in text


def test_g8_says_what_aics_verify_message_does_not_replay(card):
    # G8 names what an offline `aics verify message` leaves out; the verifier lists it itself (NOT_REPLAYED, and the
    # card active at the index in ALWAYS_UNPROVEN), and the card may not claim that it replays any of it.
    consts = _module_constants("packages/aics-cli/src/aics_cli/message.py")
    listed = " ".join(_evaluate(consts["NOT_REPLAYED"], {}) + _evaluate(consts["ALWAYS_UNPROVEN"], {}))
    text = next(t for t in assurance(card, "G8")["assumptions"] if "aics verify message" in t)
    for verifier, card_words in (("task board", "the SUP-1 task board"), ("owner-action market", "owner-action market"),
                                 ("balances", "balances"), ("polls", "polls"), ("votes", "votes"),
                                 ("suspensions", "suspensions"), ("freezes", "freezes"),
                                 ("the card active at the index", "the card in force at the entry's index")):
        assert verifier in listed, f"message.py no longer lists {verifier!r} as not replayed: update G8"
        assert card_words in text, card_words
    assert "It does not replay the SUP-1 task board" in text


#: Every table aics-server creates, by what N2 [no-address-records] calls it: a new table needs a look at that
#: statement (does it record requests?) before it joins one of these sets.
SERVER_TABLES = {
    "the log itself": {
        "tlog_leaves", "policy_documents", "names", "key_events", "bound_keys", "envelope_chain", "refusals", "grants",
        "messages", "capsules", "capsule_leaves", "tombstones", "suspensions", "freezes", "agora_posts",
        "agora_polls", "agora_poll_votes", "daily_reports", "owner_actions", "owner_quotes", "sup_ledger",
        "sup_tasks", "sup_awards"},
    "the notice and contribution records described below": {"notices", "sup_intents", "sup_contributions"},
    "the replay records that AICS-1 section 4.3 requires": {"nonces"},
    "aggregate counts": {"telemetry_counters", "stats_daily", "stats_latency_daily", "stats_gate_daily"},
    # The swarms profile (SWARMS-1): not active on this card (AICS-1+SUP-1), so the server writes none of these.
    None: {"swarm_bodies", "swarm_secrets", "swarm_checkpoint_notes"},
}


def test_no_address_records_names_every_record_the_server_keeps(card):
    if not (REPO / SERVER_DIR).is_dir():
        pytest.skip(f"{SERVER_DIR} is not in this checkout")
    tables = {t for path in sorted((REPO / SERVER_DIR).glob("*.py"))
              for t in re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", path.read_text(encoding="utf-8"))}
    known = set().union(*SERVER_TABLES.values())
    assert tables == known, {"new tables": sorted(tables - known), "gone": sorted(known - tables)}
    text = statement(card, "N2", "no-address-records")
    for name in filter(None, SERVER_TABLES):
        assert name in text, name
    # The db.py nonces table keeps a signed request's (kid, nonce, expires), signed reads included, until the
    # signature has expired, and for good when a leaf backs it; the per-key windows live in memory (db.py _Window).
    assert "kept for good when a leaf accepts or refuses the request or, as G4's deviation says, cites it" in text
    assert "per-key rate windows held in memory only" in text
    assert "running totals of requests and of accepted writes by kind" in text
    assert not vc.swarms_active(card["spec"])
    # The stats' closed lists (stats.py), each named in the statement.
    stats = _module_constants(f"{SERVER_DIR}/stats.py")
    assert _evaluate(stats["ACCESS_CLASSES"], {}) == ("agent-gate", "agent-signed", "program", "person", "owner",
                                                      "notice")
    for words in ("the text gate", "a signed request", "the owner key", "a notice", "counted as a program",
                  "as a browser", "route group, outcome and latency bucket", "text-gate steps"):
        assert words in text, words


# --- launch blockers (README "Launch checklist"); run with: uv run pytest -m launch ------------------------------


@launch
def test_launch_the_conformance_reports_back_every_proven_row(card):
    # The proven rows name these reports by hash (README "Genesis v2", step 0): each must show every row passing,
    # and the run policies beside them must include a run at the card's witness quorum. --fill-hashes checks the same.
    for rel in CONFORMANCE_REPORTS:
        need(rel)
        need(vc.conformance_policy_path(rel))
    rows = [a["id"] for a in card["assurances"] if a["status"] == "proven" and a["id"] in vc.CONFORMANCE_ROWS]
    assert rows == list(vc.CONFORMANCE_ROWS)
    problems, runs = vc.check_conformance_reports(vc.conformance_evidence(card), REPO, {},
                                                  card["witness_policy"]["quorum"])
    assert not problems, problems
    assert sorted({(r.file, r.quorum) for r in runs}) == sorted(zip(CONFORMANCE_REPORTS, CONFORMANCE_QUORUMS,
                                                                    strict=True))


@launch
def test_launch_every_evidence_document_is_published_where_g10_says(card):
    # ops/sync-docs.sh writes the export the pages host serves (deploy/Caddyfile): every evidence document G10 names,
    # and each conformance report's run policy, must be there byte for byte at the path its URL names.
    need("ops/sync-docs.sh")
    if shutil.which("bash") is None:
        pytest.fail("bash is needed to run ops/sync-docs.sh")
    # Outside the checkout and without a symlink on the way (macOS /var is one), as sync-docs requires.
    with tempfile.TemporaryDirectory(prefix="card-docs-export-") as temporary:
        out = Path(temporary).resolve() / "docs-public"
        result = subprocess.run(["bash", str(REPO / "ops/sync-docs.sh"), str(out)], capture_output=True, text=True,
                                check=False)
        assert result.returncode == 0, result.stdout + result.stderr
        published = {_export_path(m.group(1)) for m in PAGES_URL.finditer(_evidence_statement(card))}
        published |= {vc.conformance_policy_path(rel) for rel in CONFORMANCE_REPORTS}  # docs/evidence/<name>
        for export in sorted(published):
            assert (out / export).is_file(), f"ops/sync-docs.sh does not publish {_source_of(export)} at {export}"
            assert (out / export).read_bytes() == (REPO / _source_of(export)).read_bytes(), export


@launch
def test_launch_server_scans_exactly_the_card_patterns(card):
    server_ids = list(_server_patterns(need))
    assert not set(server_ids) & set(vc.FORBIDDEN_PATTERN_IDS), (
        f"moderation.py still enforces {sorted(set(server_ids) & set(vc.FORBIDDEN_PATTERN_IDS))}, which AICS-1 "
        "section 10.2 forbids; an anchored replacement gets a new id")
    assert server_ids == [p["id"] for p in card["secret_patterns"]], "the card lists the server's patterns in order"


PATTERNS_DOC = "docs/legal/secret-patterns.json"


@launch
def test_launch_pattern_definitions_are_published(card):
    document = vc.load_json(need(PATTERNS_DOC).encode("utf-8"))
    result = vc.validate(vc.fill(card, {}, None, document), patterns=document)
    assert result.patterns_checked
    assert [e for e in result.report.errors if "pattern" in e or "--patterns" in e] == []
    assert vc.pattern_definitions(document) == _server_definitions(need), (
        "the server must enforce exactly the published definitions (load them from the document)")


@launch
def test_launch_sync_docs_publishes_the_pattern_document():
    # [secret-scan-scope] names https://wesupport-ai.com/legal/secret-patterns.json: ops/sync-docs.sh must allow it.
    script = need("ops/sync-docs.sh")
    assert "secret-patterns.json" in script, "ops/sync-docs.sh does not publish docs/legal/secret-patterns.json"


@launch
def test_launch_charter_lists_the_card_refusal_codes(card):
    text = need("docs/legal/charter.md")
    charter = charter_codes(text, CHARTER_HEADINGS["refusal"])
    if vc.sup_active(card["spec"]):
        charter += charter_codes(text, CHARTER_SUP_HEADING)
    charter = sorted(charter)
    card_codes = sorted(c for c in card["reason_codes"]["refusal"] if not vc.SECRET_FORMAT_CODE.fullmatch(c))
    missing = sorted(set(card_codes) - set(charter))
    assert charter == card_codes, (
        f"charter commitment 5: every refusal leaf carries a charter code, and the charter governs where it and the "
        f"card differ; the charter lacks {len(missing)} card codes: {', '.join(missing)}")


@launch
def test_launch_server_future_skew_is_the_card_value(card):
    consts = _module_constants(f"{SERVER_DIR}/auth.py", need)
    assert _evaluate(consts["CLOCK_SKEW_SECONDS"], {}) == card["limits"]["future_skew_seconds"], (
        "AICS-1 section 4.3: created <= t + 30")


#: Served texts that contradict the card (DESIGN section 4.2 item 14).
WITHDRAWN_CLAIMS = [
    (r"zero[\s-]*knowledge", "N1: direct messages are end-to-end encrypted, and the service says only that"),
    (r"deterministic key recovery", "N2: no account or name recovery; key derivation is the agent's own arrangement"),
    (r"free[\s`⚡]*SUP", "decision 2: registration grants no credits"),
]


@launch
@pytest.mark.parametrize("pattern, why", WITHDRAWN_CLAIMS, ids=["zero-knowledge", "key-recovery", "free-credits"])
def test_launch_served_texts_match_the_card(pattern, why):
    root = REPO / SERVER_DIR
    assert root.is_dir(), f"{SERVER_DIR} is missing"
    hits = [f"{path.relative_to(REPO)}:{n}"
            for path in sorted(root.rglob("*"))
            if path.suffix in (".py", ".html", ".txt", ".md", ".json") and "__pycache__" not in path.parts
            for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1)
            if re.search(pattern, line, re.IGNORECASE)]
    assert not hits, f"{why}; rewrite: {', '.join(hits)}"


@launch
def test_launch_card_policy_matches_the_card(card):
    text = need("docs/legal/card-policy.md")
    problems = [phrase for phrase in ("future week", "tie the running code to public source", "[owner to decide]")
                if phrase in text]
    for a in card["assurances"]:
        paragraph = next((line for line in text.splitlines() if line.startswith(f"{a['id']} — ")), "")
        if a["id"].startswith("G") and a["status"] == "promised":
            if "promised" not in paragraph.lower():
                problems.append(f"{a['id']} is promised on the card but not in card-policy.md")
        elif a["id"].startswith("G") and a["status"] == "proven":
            if "Proven" not in paragraph or "promised at launch" in paragraph.lower():
                problems.append(f"{a['id']} is proven on the card but card-policy.md does not say so")
            if a["id"] in vc.CONFORMANCE_ROWS and "conformance report" not in paragraph:
                problems.append(f"{a['id']}: card-policy.md does not name the conformance report that proves it")
    assert not problems, problems


def _routes(app_src: str) -> set[tuple[str, str]]:
    out = set()
    for node in ast.walk(_tree(app_src)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in (
                "get", "post", "put", "delete") and isinstance(node.func.value, ast.Name) \
                and node.func.value.id == "app" and _str_arg(node, 0):
            out.add((node.func.attr.upper(), _str_arg(node, 0)))
    return out


@launch
def test_launch_server_serves_the_card_and_the_gate():
    sources = server_sources(need)
    routes = _routes(sources["app.py"])
    wanted = [("GET", "/card"), ("GET", "/.well-known/aics-card.json"), ("POST", "/t"), ("GET", "/t"),
              ("GET", "/ip"), ("POST", "/notice")]
    missing = [f"{m} {p}" for m, p in wanted if (m, p) not in routes]
    everything = "\n".join(sources.values())
    if "AICS_GATE_TLS_CERT" not in everything:
        missing.append("the TCP gate on 7700 (TLS) and 7701 (AICS-1 section 11.1)")
    if '"JOSE"' not in everything:
        missing.append("a card signer (AICS-1 section 13.2)")
    assert not missing, missing


@launch
def test_launch_server_logs_registered_entry_types_only(card):
    spec = need("docs/spec/AICS-1.md")
    part = section(spec, "### 17.1.")
    registered = set(backticked(re.search(r"closed to the 17 exact values (.*?); compound", part, re.DOTALL)[1]))
    sup_types = set(backticked(re.search(r"registry adds exactly (.*?): three additions", section(spec, "### 20.3."),
                                         re.DOTALL)[1]))
    swarm_types = set(backticked(re.search(r"entry registry adds exactly (.*?) \(ten additions", section(spec, "## 19."),
                                           re.DOTALL)[1]))
    consts = _module_constants(SERVER, need)
    # db.py imports the swarms profile's types (``TYPES as SWARM_TYPES``) and expands them into its registry.
    names = {"SWARM_TYPES": _evaluate(_module_constants(SERVER_SWARMS, need)["TYPES"], {})}
    assert set(_evaluate(consts["ENTRY_TYPES"], {})) == registered
    extensions = set(_evaluate(consts["EXTENSION_ENTRY_TYPES"], names))
    unregistered = extensions - sup_types - swarm_types
    assert not unregistered, f"AICS-1 registers no {', '.join(sorted(unregistered))}"
    if extensions & sup_types:
        # AICS-1 section 20.9: no section 20 entry is appended before a card activates the profile.
        assert vc.sup_active(card["spec"]), "the server writes section 20.3 entries: the card must be AICS-1+SUP-1"
    if extensions & swarm_types and not vc.swarms_active(card["spec"]):
        # AICS-1 section 19: swarm entries extend the base profile only after prospective activation; the server
        # refuses them while the effective card does not activate SWARMS-1, so this card may stay without it.
        assert "is not activated by the effective card" in need(SERVER_SWARMS), \
            "the server can write swarm entries without a swarms card"


#: The card verifiers: the aics CLI agents run (section 14.5, G10) and aics-conformance, which the operator runs to
#: produce the reports that promote a row.
CARD_VERIFIERS = ("packages/aics-cli/src/aics_cli/card.py", "packages/aics-conformance/src/aics_conformance/card.py")


@launch
def test_launch_verifiers_accept_the_card_profile(card):
    # A verifier that knows the profile names its spec value (AICS-1 section 20.9); one that pins "AICS-1" refuses
    # this card, its sup member and its section 20.8 codes.
    missing = [rel for rel in CARD_VERIFIERS if card["spec"] not in need(rel)]
    assert not missing, f"{', '.join(missing)}: no support for this card's profile {card['spec']}"


#: aics-interop findings that stop this card from being checked: envelopes (F01-F03), sealed-box framing (F05) and
#: the verifiers' refusal of a 0.2-draft card (F13, F22).
BLOCKING_FINDINGS = ("F01", "F02", "F03", "F05", "F13", "F22")


def open_findings(src: str) -> set[str]:
    """IDs of the ``Finding(...)`` entries of aics-interop's findings.py whose ``status`` is open (the default)."""
    out = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and _call_name(node) == "Finding" and _str_arg(node, 0):
            status = next((k.value for k in node.keywords if k.arg == "status"), None)
            if status is None or (isinstance(status, ast.Constant) and status.value == "open"):
                out.add(_str_arg(node, 0))
    return out


def test_open_findings_reads_the_status():
    src = 'F = [Finding("F01", "p"), Finding("F02", "p", status="retired"), Finding("F03", "p", status="open")]\n'
    assert open_findings(src) == {"F01", "F03"}


@launch
def test_launch_interop_findings_that_block_the_card_are_closed():
    open_ids = open_findings(need("packages/aics-interop/src/aics_interop/findings.py"))
    assert not set(BLOCKING_FINDINGS) & open_ids, sorted(set(BLOCKING_FINDINGS) & open_ids)


#: The clients this instance points agents to: aics-js (its profile list, TypeScript) and the aics CLI.
AICS_JS_REGISTRY = "clients/aics-js/src/registry.ts"
AICS_CLI_CARD = "packages/aics-cli/src/aics_cli/card.py"


def client_profiles() -> dict[str, str]:
    """The profiles each client states it verifies, as text."""
    m = re.search(r"SUPPORTED_PROFILES: readonly Profile\[\] = \[([^\]]*)\]", read(AICS_JS_REGISTRY))
    assert m, f"{AICS_JS_REGISTRY}: no SUPPORTED_PROFILES list"
    consts = _module_constants(AICS_CLI_CARD)
    names = {k: _evaluate(consts[k], {}) for k in ("SPEC_BASE", "SPEC_SUP")}
    return {AICS_JS_REGISTRY: m.group(1), AICS_CLI_CARD: " ".join(_evaluate(consts["SUPPORTED_PROFILES"], names))}


def test_the_card_activates_no_profile_its_clients_cannot_verify(card):
    """AICS-1 section 19: a client without a profile rejects its entries.  The card activates SWARMS-1 only once
    every client the instance names verifies it (decision 19: aics-js and aics implement the base and SUP-1
    profiles only, so the production card stays AICS-1+SUP-1 until they implement SWARMS-1)."""
    for rel, listed in client_profiles().items():
        if vc.swarms_active(card["spec"]):
            assert "SWARMS-1" in listed, f"{rel} does not verify SWARMS-1, which this card activates"
        if vc.sup_active(card["spec"]):
            assert "SUP-1" in listed, f"{rel} does not verify SUP-1, which this card activates"

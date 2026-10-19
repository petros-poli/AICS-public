"""``aics trust build``: the production trust bundle from the operator's own files (runbook step 5).

The operator holds two files at launch: ``pubkeys.txt``, which aics-server
writes for out-of-band publication (``origin``, ``log``, ``policy`` and
``owner`` lines), and the bootstrap card exactly as the server serves it
after the owner logged it.  This command builds the AICS-1 §6.4 bundle
``{v, origin, log_vkey, policy_kid, owner_kid, bootstrap_card_hash}`` from
them and prints the four forms that must carry the same bytes: the JCS
bundle, the TXT value ``aics1=<U64(J(bundle))>``, its ``hexH`` digest and the
README block.  It refuses before printing anything unless:

* ``pubkeys.txt`` gives each of origin, log, policy and owner exactly once
  (a repeated label must repeat the same value; ``policy-kid``/``owner-kid``
  and ``log-kid``, when present, must name the same keys), the three keys
  are distinct Ed25519 keys and the owner key exists;
* the card file is ``J(card)`` - its bytes are the RFC 8785 serialization of
  the object they parse to - is a §13.1 card, is signed by the policy key,
  and states the origin, log, policy and owner keys of ``pubkeys.txt``;
* a policy leaf of kind ``card`` names ``hexH`` of exactly those bytes (and
  their size), in the ``/v2/policies`` listing fetched from the card's
  ``api_base`` (or ``--policies-url``) or read from ``--policies-file``;
  when ``pubkeys.txt`` states ``charter-sha256``, leaf 0 must be that charter.

The listing is the server's own claim: it says which leaf names the card,
and runbook step 4 has already checked that the server serves the logged
card.  Nothing private is read; the key files never leave the server.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from aics_identity import keys as idkeys
from aics_identity.canonical import canonicalize

from . import card as cardmod
from .errors import AicsError, PolicyError, UsageError
from .net import join_url
from .policy import parse_log_vkey, parse_policy_key
from .trust import TrustBundle, bundle_from_object, bundle_from_text, bundle_from_u64

#: The labels of pubkeys.txt the bundle takes, and the bundle member each fills.
PUBKEY_FIELDS = {"origin": "origin", "log": "log_vkey", "policy": "policy_kid", "owner": "owner_kid"}
#: Lines that repeat a key under another label (aics-server writes both forms).
PUBKEY_ALIASES = {"policy-kid": "policy", "owner-kid": "owner"}
README_LABEL = "AICS trust bundle (AICS-1 §6.4), the same bytes as the DNS TXT record _aics.<domain>:"
_HEX64 = re.compile(r"[0-9a-f]{64}")


def _read(path: str, what: str) -> bytes:
    try:
        return Path(path).expanduser().read_bytes()
    except OSError as exc:
        raise AicsError(f"cannot read the {what} {path}: {exc}") from None


def parse_pubkeys(text: str) -> dict[str, str]:
    """``label value`` lines (``#`` comments) as aics-server's ``pubkeys_text`` writes them."""
    seen: dict[str, str] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        label, _, value = line.partition(" ")
        value = value.strip()
        if not value or " " in value:
            raise PolicyError(f"pubkeys.txt line {n}: expected 'label value', got {line[:80]!r}")
        if label in seen and seen[label] != value:
            raise PolicyError(f"pubkeys.txt gives two different values for {label!r}; nothing was built")
        seen[label] = value
    missing = [label for label in PUBKEY_FIELDS if label not in seen]
    if missing:
        raise PolicyError(f"pubkeys.txt has no {', '.join(missing)} line; it is the file aics-server writes "
                          "(/data/pubkeys.txt)")
    if seen["owner"] == "none":
        raise PolicyError("pubkeys.txt names no owner key ('owner none'): a production bundle pins the owner key")
    for alias, label in PUBKEY_ALIASES.items():
        if alias in seen and seen[alias] != seen[label]:
            raise PolicyError(f"pubkeys.txt: {alias} {seen[alias]} is not {label} {seen[label]}")
    if "log-kid" in seen:
        log_pub = parse_log_vkey(seen["log"]).public_key
        if seen["log-kid"] != idkeys.did_key(idkeys.public_key_from_bytes(log_pub)):
            raise PolicyError("pubkeys.txt: log-kid is not the did:key of the log line's key")
    return seen


def _card_problems(card: Any, pubkeys: dict[str, str]) -> list[str]:
    problems: list[str] = []
    profile = cardmod.unsupported_profile(card)
    if profile:
        return [f"the card is of an unsupported profile ({profile})"]
    problems += cardmod.schema_problems(card)
    if problems:
        return problems
    for label, member in PUBKEY_FIELDS.items():
        stated, want = card.get(member), pubkeys[label]
        if member in ("policy_kid", "owner_kid"):
            try:
                same = parse_policy_key(str(stated)).public_key == parse_policy_key(want).public_key
            except PolicyError:
                same = False
        else:
            same = stated == want
        if not same:
            problems.append(f"the card's {member} {stated!r} is not pubkeys.txt's {label} {want!r}")
    checks = cardmod.check_signatures(card, [parse_policy_key(pubkeys["policy"])])
    if not any(c.status == "valid" for c in checks):
        details = "; ".join(f"{c.status}{': ' + c.detail if c.detail else ''}" for c in checks)
        problems.append(f"no signature of the card verifies with the policy key ({details})")
    return problems


def _policies(args: Any, env: Any, card: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    if args.policies_file and args.policies_url:
        raise UsageError("give --policies-url or --policies-file, not both")
    if args.policies_file:
        raw, source = _read(args.policies_file, "policies listing"), f"file {args.policies_file}"
    else:
        url = args.policies_url or join_url(str(card["api_base"]), "v2/policies")
        resp = env.fetcher.get(url, accept="application/json")
        if resp.status != 200:
            raise AicsError(f"GET {url}: HTTP {resp.status}; give the listing with --policies-file")
        raw, source = resp.body, url
    try:
        doc = cardmod.loads_strict(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AicsError(f"the policies listing ({source}) is not strict JSON: {exc}") from None
    rows = doc.get("policies") if isinstance(doc, dict) else None
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        raise AicsError(f"the policies listing ({source}) has no 'policies' array of objects (GET /v2/policies)")
    return rows, source


def build(args: Any, env: Any) -> dict[str, Any]:
    pubkeys = parse_pubkeys(_read(args.pubkeys, "key file").decode("utf-8", errors="replace"))
    doc = _read(args.card, "card")
    try:
        card = cardmod.loads_strict(doc)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AicsError(f"the card file is not strict JSON: {exc}") from None
    if not isinstance(card, dict):
        raise AicsError("the card file is not a JSON object")
    if canonicalize(card) != doc:
        raise AicsError("the card file is not J(card): its bytes are not the RFC 8785 serialization of the card "
                        "(save the served bytes unchanged, e.g. curl -o, no pretty-printing or final newline)")
    problems = _card_problems(card, pubkeys)
    if problems:
        raise AicsError("the card cannot be the bootstrap card: " + "; ".join(problems[:8]),
                        problems=problems)
    digest, size = hashlib.sha256(doc).hexdigest(), len(doc)

    rows, source = _policies(args, env, card)
    named = [r for r in rows if r.get("kind") == "card" and r.get("document_hash") == digest]
    if not named:
        raise AicsError(f"no policy leaf of kind card names this card (hexH {digest}) in {source}: log it first "
                        "(runbook step 4) and save the served bytes after logging")
    leaf = named[0]
    if leaf.get("size") is not None and leaf.get("size") != size:
        raise AicsError(f"policy leaf {leaf.get('leaf_index')} names the card's hash with size {leaf.get('size')}, "
                        f"the file has {size} bytes")
    notes: list[str] = []
    cards = [r for r in rows if r.get("kind") == "card"]
    if cards and cards[0] is not leaf:
        notes.append(f"policy leaf {leaf.get('leaf_index')} is not the log's first card leaf "
                     f"({cards[0].get('leaf_index')}); a bootstrap bundle normally pins the first card")
    charter = pubkeys.get("charter-sha256")
    if charter is not None:
        first = rows[0] if rows else {}
        if not (_HEX64.fullmatch(charter) and first.get("kind") == "charter" and first.get("document_hash") == charter
                and first.get("leaf_index") == 0):
            raise AicsError(f"leaf 0 of {source} is not the charter pubkeys.txt names (charter-sha256 {charter})")

    bundle = bundle_from_object({"v": 1, **{member: pubkeys[label] for label, member in PUBKEY_FIELDS.items()},
                                 "bootstrap_card_hash": digest})
    readme = "\n".join([README_LABEL, bundle.txt, f"sha256: {bundle.sha256}"]) + "\n"
    # every published form must read back as these bytes, the way aics policy init reads it
    for form in (bundle_from_u64(bundle.txt[len("aics1="):]), bundle_from_text(readme),
                 bundle_from_text(bundle.jcs.decode("utf-8"))):
        if form.jcs != bundle.jcs:  # pragma: no cover - a format drift between this file and trust.py
            raise AicsError("internal error: a published form does not read back as the bundle bytes")
    return {"bundle": bundle, "card_hash": digest, "card_size": size, "card_leaf_index": leaf.get("leaf_index"),
            "policies_source": source, "readme_block": readme, "notes": notes}


def cmd_trust_build(args: Any, env: Any) -> Any:
    from .commands import _ok

    out = build(args, env)
    bundle: TrustBundle = out["bundle"]
    jcs = bundle.jcs.decode("utf-8")
    data = {"bundle_jcs": jcs, "bundle": json.loads(jcs), "txt": bundle.txt, "sha256": bundle.sha256,
            "readme_block": out["readme_block"], "card_hash": out["card_hash"], "card_size": out["card_size"],
            "card_leaf_index": out["card_leaf_index"], "policies_source": out["policies_source"],
            "notes": out["notes"]}
    text = [
        f"checked: the card is J(card), a §13.1 card signed by the policy key, {out['card_size']} bytes, hexH "
        f"{out['card_hash']}, named by policy leaf {out['card_leaf_index']} ({out['policies_source']})",
        "checked: origin, log, policy and owner are pubkeys.txt's",
        "",
        f"bundle (JCS, {len(bundle.jcs)} bytes):",
        jcs,
        "",
        "DNS TXT _aics.<domain> (exactly one RR):",
        bundle.txt,
        "",
        f"sha256 {bundle.sha256}",
        "",
        "README block:",
        *("    " + line for line in out["readme_block"].splitlines()),
        *(f"note: {n}" for n in out["notes"]),
    ]
    return _ok(data, text)

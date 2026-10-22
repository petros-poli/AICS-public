"""The signed assurance card (docs/spec/AICS-1.md §13, §14.5; DESIGN G10).

``/.well-known/aics-card.json`` is signed with the A2A card construction
(A2A v1.0.0 §8.4) as profiled by AICS-1 §13.2: remove only ``signatures``,
JCS-canonicalise the rest, and sign ``ASCII(protected || "." ||
U64(J(unsigned_card)))`` with Ed25519, where ``protected`` is
``U64(J({"alg":"EdDSA","kid":policy_kid,"typ":"JOSE"}))``.  No unprotected
header, ``jku``, embedded key, ``b64=false`` or other algorithm is allowed,
and no default-value elision happens: every §13.1 member is required.

The policy key comes only from the pinned trust bundle.  The first card is
identified by ``hexH(J(card)) == bootstrap_card_hash``.  Which card is in
force - its policy leaf, the leaf's inclusion and activation, and supersession
by later policy events (§14.5 steps 3-4) - comes from the log's policy leaves
(:mod:`aics_cli.currency`); when they cannot be read, a later card is reported
as signature-valid but ``incomplete`` and the bootstrap card as "later policy
events not checked".  A card that did not verify as current is never stored,
and only stored cards that did (``bootstrap``, ``in-force``) are the history
a later card is compared with.  The evidence behind ``proven`` assurances is
not checked; the output says so.

Everything in the card is the operator's own statement.  Statuses must stay
inside the AICS-1 §13.3 boundaries (:func:`assurance_problems`), and free
text is escaped before it is printed (it can never add lines or terminal
escapes to the verdict).

Profiles (§13.1, §19, §20.9): the base card (``spec`` ``AICS-1``) and the
contributions and owner-service profile (``AICS-1+SUP-1``: the ``sup``
member and the twelve §20.8 refusal codes) are verified.  A card of a swarms
profile (``AICS-1+SWARMS-1``, ``AICS-1+SWARMS-1+SUP-1``) is reported as an
unsupported profile (:func:`unsupported_profile`): §19 requires a client
without the profile to reject it, never to read it as a base card.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aics_identity.canonical import canonicalize
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import home as _home
from .encoding import b64u_d, b64u_e, escape_untrusted
from .errors import AicsError, FetchError, PolicyError
from .policy import Policy, PolicyKey, parse_log_vkey, parse_policy_key, parse_witness_vkey

WELL_KNOWN = "/.well-known/aics-card.json"
CARD_MAX_BYTES = 1024 * 1024
FUTURE_SKEW = 30  # AICS-1 §14.5 step 2: issued_at <= now + 30
MAX_JSON_DEPTH = 32  # AICS-1 §15: implementations MUST bound JSON depth
STATUSES = ("proven", "promised", "not-offered")
#: Unicode categories never allowed in a card string: control, format, line and paragraph separators.
FORBIDDEN_CATEGORIES = ("Cc", "Cf", "Zl", "Zp")
REQUIRED_ASSURANCES = tuple(f"G{i}" for i in range(1, 11)) + tuple(f"N{i}" for i in range(1, 6))
UINT_MAX = 9007199254740991
_HEX64 = re.compile(r"[0-9a-f]{64}")
_PATTERN_ID = re.compile(r"[a-z0-9_]{1,32}")

CARD_MEMBERS = (
    "spec", "version", "origin", "issued_at", "expires", "policy_parent_index", "log_vkey", "policy_kid",
    "owner_kid", "tile_prefixes", "api_base", "gate", "proxy", "witness_policy", "max_checkpoint_age",
    "mmd_seconds", "policy_notice_seconds", "limits", "retention", "schemes", "tiers", "reason_codes",
    "secret_patterns", "policies", "assurances", "spec_versions", "signatures",
)
#: AICS-1 (0.2-draft) §13.1: the card's ``version`` and the C2SP versions it pins (tlog-checkpoint, signed-note,
#: tlog-cosignature and tlog-witness v1.1.0).  A card of any other version is refused, 0.1-draft included.
CARD_VERSION = "0.2-draft"
SPEC_VERSIONS = {"tlog-tiles": "1.0.0", "tlog-checkpoint": "1.1.0", "signed-note": "1.1.0",
                 "tlog-cosignature": "1.1.0", "tlog-witness": "1.1.0", "a2a-card": "1.0.0"}
FIXED_LIMITS = {"public_body_bytes": 32768, "ciphertext_bytes": 65536, "envelope_window_seconds": 300,
                "future_skew_seconds": 30, "session_idle_seconds": 900}
TIERS = ("verified", "third-party-generated", "unverified")
MANDATORY_SCHEME = "x25519-xsalsa20-poly1305"
#: AICS-1 §13.1 and §20.9: the card profiles this release verifies, and (§19, SWARMS R47) those it reports as
#: unsupported instead of reading them as base cards.
SPEC_BASE = "AICS-1"
SPEC_SUP = "AICS-1+SUP-1"
SUPPORTED_PROFILES = (SPEC_BASE, SPEC_SUP)
UNSUPPORTED_PROFILES = ("AICS-1+SWARMS-1", "AICS-1+SWARMS-1+SUP-1")
#: AICS-1 §20.8: the refusal codes an activated SUP-1 card adds to the refusal registry (no other card enables them).
SUP_REFUSALS = ("insufficient_balance", "not_requester", "owner_action_closed", "stale_quote", "task_closed",
                "already_awarded", "already_credited", "payment_not_verified", "intent_expired", "amount_mismatch",
                "bad_reference", "not_offered")
#: AICS-1 §20.9: the ``sup`` member and its parts.
SUP_MEMBERS = ("asset_hash", "contributions", "intent_seconds", "claim_seconds", "record_seconds", "storage")
SUP_CONTRIBUTION_MEMBERS = ("network", "asset", "decimals", "address", "units_per_sup")
SUP_STORAGE_MEMBERS = ("free_quota_bytes", "unit_bytes", "unit_amount")
SUP_RECORD_SECONDS_MAX = 31536000  # decision 17's 12 months
SUP_FREE_QUOTA_MINIMUM = 65536  # one maximal ciphertext body is always free
_SUP_NETWORK = re.compile(r"[a-z0-9-]{1,32}")
#: AICS-1 (0.2-draft) §17.2 registries of the base profile.  §13.1: a card's reasons equal them, the refusal
#: registry plus exactly one ``secret_format:<id>`` per pattern the card enumerates (a closed expansion); a
#: base-only verifier refuses anything else, the §19 swarms codes included.
REASON_REGISTRIES = {
    "refusal": (
        "malformed", "bad_signature", "expired", "future", "replay", "unknown_key", "revoked", "tls_required",
        "unsupported_scheme", "unsupported_version",
        "sequence", "predecessor", "name_taken", "key_reuse", "key_fork", "stale_key", "stale_grant",
        "stale_capsule", "already_voted", "poll_closed", "poll_constraint",
        "too_large", "digest_mismatch", "rate_limit", "quota", "no_consent", "grant_exhausted", "suspended",
        "frozen", "tier_required",
        "secret_format", "rate", "seq", "fork", "sig", "no_grant", "size", "format", "name", "key_state",
        "poll_rule",
    ),
    "tombstone": ("order", "erasure", "secret_format", "illegal_on_notice"),
    "suspension": ("order", "flood"),
    "freeze": ("maintenance", "incident", "order", "resource_exhaustion", "resume"),
    "revocation": ("retired", "compromised"),
    "outcome": ("acted", "declined", "private_unassessable", "invalid_notice", "duplicate", "published",
                "resolved"),
}


# ---------------------------------------------------------------------------
# strict JSON
# ---------------------------------------------------------------------------


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate JSON member {k!r}")
        out[k] = v
    return out


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


_JSON_SPECIAL = re.compile(r'[\[\]{}"\\]')


def check_json_depth(text: str, limit: int = MAX_JSON_DEPTH) -> None:
    """Raise ValueError if arrays/objects in ``text`` nest deeper than
    ``limit`` (scanned without recursion, before any parser recurses)."""
    depth = 0
    in_string = False
    skip = -1
    for m in _JSON_SPECIAL.finditer(text):
        pos = m.start()
        if pos <= skip:
            continue
        c = text[pos]
        if in_string:
            if c == "\\":
                skip = pos + 1  # the escaped character
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c in "[{":
            depth += 1
            if depth > limit:
                raise ValueError(f"JSON nested deeper than {limit} levels")
        elif c in "]}":
            depth -= 1


def loads_strict(data: bytes | str, *, max_depth: int = MAX_JSON_DEPTH) -> Any:
    """JSON with duplicate members and NaN/Infinity rejected (two parsers
    must never see two different cards in one document) and nesting bounded
    (a deeply nested document is a ValueError, never a RecursionError)."""
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    check_json_depth(text, max_depth)
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except RecursionError:
        raise ValueError("JSON nested too deeply") from None


# ---------------------------------------------------------------------------
# JWS over JCS
# ---------------------------------------------------------------------------


def unsigned_payload(card: dict[str, Any]) -> bytes:
    """``J(card without signatures)``: the JWS payload."""
    return canonicalize({k: v for k, v in card.items() if k != "signatures"})


def card_hash(card: dict[str, Any]) -> str:
    """``hexH(J(card))`` over the full signed card: the policy-leaf document
    hash and, for the first card, the bundle's ``bootstrap_card_hash``."""
    return hashlib.sha256(canonicalize(card)).hexdigest()


def sign_card(card: dict[str, Any], key: Ed25519PrivateKey, kid: str, *, alg: str = "EdDSA",
              typ: str = "JOSE", extra_header: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return ``card`` with ``signatures`` set to one AICS-1 §13.2 signature."""
    header = {"alg": alg, "kid": kid, "typ": typ, **(extra_header or {})}
    protected = b64u_e(canonicalize(header))
    signing_input = f"{protected}.{b64u_e(unsigned_payload(card))}".encode("ascii")
    out = {k: v for k, v in card.items() if k != "signatures"}
    out["signatures"] = [{"protected": protected, "signature": b64u_e(key.sign(signing_input))}]
    return out


@dataclass
class SigCheck:
    index: int
    status: str  # valid | invalid | unknown-kid | unsupported | malformed
    kid: str | None = None
    detail: str = ""

    def report(self) -> dict[str, Any]:
        d: dict[str, Any] = {"index": self.index, "status": self.status, "kid": self.kid}
        if self.detail:
            d["detail"] = self.detail
        return d


def _canonical_u64(value: str) -> bytes:
    raw = b64u_d(value)
    if b64u_e(raw) != value:
        raise ValueError("non-canonical base64url")
    return raw


def check_signatures(card: dict[str, Any], keys: list[PolicyKey]) -> list[SigCheck]:
    sigs = card.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        return [SigCheck(0, "malformed", detail="card has no 'signatures' array")]
    try:
        payload_b64 = b64u_e(unsigned_payload(card))
    except ValueError as exc:
        return [SigCheck(0, "malformed", detail=f"card cannot be canonicalised (RFC 8785): {exc}")]
    out: list[SigCheck] = []
    for i, s in enumerate(sigs):
        if not isinstance(s, dict) or set(s) != {"protected", "signature"} \
                or not all(isinstance(s[k], str) for k in s):
            out.append(SigCheck(i, "unsupported", detail="a signature is exactly {protected, signature}: "
                                                         "no unprotected header (AICS-1 §13.2)"))
            continue
        try:
            raw_header = _canonical_u64(s["protected"])
            header = loads_strict(raw_header)
        except (ValueError, UnicodeDecodeError) as exc:
            out.append(SigCheck(i, "malformed", detail=f"protected header: {exc}"))
            continue
        if not isinstance(header, dict):
            out.append(SigCheck(i, "malformed", detail="protected header is not a JSON object"))
            continue
        kid = header.get("kid")
        chk = SigCheck(i, "unsupported", kid=kid if isinstance(kid, str) else None)
        if set(header) != {"alg", "kid", "typ"} or header.get("alg") != "EdDSA" or header.get("typ") != "JOSE":
            chk.detail = ('the protected header must be exactly {"alg":"EdDSA","kid":<policy_kid>,"typ":"JOSE"} '
                          f"(got members {sorted(header)})")
            out.append(chk)
            continue
        if canonicalize(header) != raw_header:
            chk.status, chk.detail = "malformed", "protected header is not JCS-serialized"
            out.append(chk)
            continue
        matching = [k for k in keys if isinstance(kid, str) and kid in k.kids]
        if not matching:
            chk.status, chk.detail = "unknown-kid", "kid is not the pinned policy key"
            out.append(chk)
            continue
        try:
            raw_sig = _canonical_u64(s["signature"])
        except ValueError as exc:
            chk.status, chk.detail = "malformed", f"signature: {exc}"
            out.append(chk)
            continue
        signing_input = f"{s['protected']}.{payload_b64}".encode("ascii")
        chk.status = "invalid"
        for k in matching:
            try:
                Ed25519PublicKey.from_public_bytes(k.public_key).verify(raw_sig, signing_input)
                chk.status = "valid"
                break
            except InvalidSignature:
                continue
        if chk.status == "invalid":
            chk.detail = "signature does not verify over the JCS payload (card altered after signing?)"
        out.append(chk)
    return out


# ---------------------------------------------------------------------------
# §13.1 schema
# ---------------------------------------------------------------------------


class _Schema:
    def __init__(self) -> None:
        self.problems: list[str] = []

    def bad(self, path: str, msg: str) -> None:
        self.problems.append(f"{path}: {msg}")

    def obj(self, v: Any, path: str, members: tuple[str, ...]) -> bool:
        if not isinstance(v, dict):
            self.bad(path, "must be an object")
            return False
        missing = [m for m in members if m not in v]
        extra = sorted(set(v) - set(members))
        if missing:
            self.bad(path, f"missing {', '.join(missing)}")
        if extra:
            self.bad(path, f"unknown members {', '.join(escape_untrusted(e) for e in extra)}")
        return not missing

    def uint(self, v: Any, path: str, *, positive: bool = False, equals: int | None = None,
             minimum: int | None = None) -> None:
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= UINT_MAX:
            self.bad(path, "must be an integer from 0 to 2^53-1")
            return
        if positive and v <= 0:
            self.bad(path, "must be positive")
        if equals is not None and v != equals:
            self.bad(path, f"must be {equals}")
        if minimum is not None and v < minimum:
            self.bad(path, f"must be at least {minimum}")

    def string(self, v: Any, path: str, *, equals: str | None = None) -> bool:
        if not isinstance(v, str) or not v:
            self.bad(path, "must be a non-empty string")
            return False
        if equals is not None and v != equals:
            self.bad(path, f"must be {equals!r}")
            return False
        return True

    def https(self, v: Any, path: str) -> None:
        if self.string(v, path):
            parts = urllib.parse.urlsplit(v)
            if parts.scheme != "https" or not parts.hostname:
                self.bad(path, "must be an https:// URL")

    def hash(self, v: Any, path: str) -> None:
        if not isinstance(v, str) or not _HEX64.fullmatch(v):
            self.bad(path, "must be 64 lowercase hex characters")

    def str_list(self, v: Any, path: str, *, unique: bool = True) -> list[str]:
        if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
            self.bad(path, "must be an array of non-empty strings")
            return []
        if unique and len(set(v)) != len(v):
            self.bad(path, "entries must be unique")
        return v

    def count_limit(self, v: Any, path: str) -> None:
        if self.obj(v, path, ("count", "interval_seconds")):
            self.uint(v["count"], f"{path}.count", positive=True)
            self.uint(v["interval_seconds"], f"{path}.interval_seconds", positive=True)

    def characters(self, v: Any, path: str) -> None:
        """Every string (and member name) is free of control, format, line
        and paragraph separator characters: card text is printed to agents
        and must not smuggle lines or terminal escapes into a verdict."""
        if isinstance(v, str):
            bad = _forbidden_chars(v)
            if bad:
                self.bad(path, f"contains control or format characters ({', '.join(bad)})")
        elif isinstance(v, dict):
            for k, x in v.items():
                bad = _forbidden_chars(k)
                if bad:
                    self.bad(path, f"a member name contains control or format characters ({', '.join(bad)})")
                self.characters(x, f"{path}.{escape_untrusted(k)}")
        elif isinstance(v, list):
            for i, x in enumerate(v):
                self.characters(x, f"{path}[{i}]")


def _forbidden_chars(s: str) -> list[str]:
    found = sorted({ord(c) for c in s if unicodedata.category(c) in FORBIDDEN_CATEGORIES})
    return [f"U+{o:04X}" for o in found[:8]] + (["..."] if len(found) > 8 else [])


def sup_asset_hash(origin: str) -> str:
    """AICS-1 §20.2: ``hexH`` of the SUP asset descriptor of this log's origin, every ``asset_hash`` of the profile."""
    return hashlib.sha256(canonicalize({"asset": "SUP", "buys": ["owner_action", "hosting", "storage"],
                                        "decimals": 0, "origin": origin, "refundable": False,
                                        "transferable": False})).hexdigest()


def unsupported_profile(card: Any) -> str | None:
    """The card's ``spec`` when it names a profile this release does not implement (§19: reject, never reinterpret
    as a base card), else None."""
    spec = card.get("spec") if isinstance(card, dict) else None
    return spec if isinstance(spec, str) and spec in UNSUPPORTED_PROFILES else None


def _sup_problems(s: "_Schema", card: dict[str, Any]) -> None:
    """AICS-1 §20.9: the ``sup`` member of an activated SUP-1 card."""
    sup = card["sup"]
    if not s.obj(sup, "$.sup", SUP_MEMBERS):
        return
    if isinstance(card["origin"], str) and sup["asset_hash"] != sup_asset_hash(card["origin"]):
        s.bad("$.sup.asset_hash", "must be hexH of the §20.2 SUP asset descriptor of this card's origin")
    contributions = sup["contributions"]
    if not isinstance(contributions, list):
        s.bad("$.sup.contributions", "must be an array (empty when no network is offered)")
    else:
        networks: list[str] = []
        for i, c in enumerate(contributions):
            path = f"$.sup.contributions[{i}]"
            if not s.obj(c, path, SUP_CONTRIBUTION_MEMBERS):
                continue
            if not isinstance(c["network"], str) or not _SUP_NETWORK.fullmatch(c["network"]):
                s.bad(f"{path}.network", "must match [a-z0-9-]{1,32}")
            else:
                networks.append(c["network"])
            s.string(c["asset"], f"{path}.asset")
            s.string(c["address"], f"{path}.address")
            s.uint(c["decimals"], f"{path}.decimals")
            s.uint(c["units_per_sup"], f"{path}.units_per_sup", minimum=2)
        if len(set(networks)) != len(networks):
            s.bad("$.sup.contributions", "must list each credited network once")
    s.uint(sup["intent_seconds"], "$.sup.intent_seconds", positive=True)
    s.uint(sup["claim_seconds"], "$.sup.claim_seconds", positive=True)
    if all(isinstance(sup[k], int) and not isinstance(sup[k], bool) for k in ("intent_seconds", "claim_seconds")) \
            and sup["intent_seconds"] > sup["claim_seconds"]:
        s.bad("$.sup", "needs 0 < intent_seconds <= claim_seconds")
    s.uint(sup["record_seconds"], "$.sup.record_seconds")
    if isinstance(sup["record_seconds"], int) and not isinstance(sup["record_seconds"], bool) \
            and sup["record_seconds"] > SUP_RECORD_SECONDS_MAX:
        s.bad("$.sup.record_seconds", f"must be at most {SUP_RECORD_SECONDS_MAX} (decision 17's 12 months)")
    storage = sup["storage"]
    if storage is not None and s.obj(storage, "$.sup.storage", SUP_STORAGE_MEMBERS):
        s.uint(storage["free_quota_bytes"], "$.sup.storage.free_quota_bytes", minimum=SUP_FREE_QUOTA_MINIMUM)
        unit_bytes, unit_amount = storage["unit_bytes"], storage["unit_amount"]
        if (unit_bytes is None) != (unit_amount is None):
            s.bad("$.sup.storage", "unit_bytes and unit_amount are both null (no storage offered) or both positive")
        elif unit_bytes is not None:
            s.uint(unit_bytes, "$.sup.storage.unit_bytes", positive=True)
            s.uint(unit_amount, "$.sup.storage.unit_amount", positive=True)


def _service_keys(card: dict[str, Any]) -> dict[bytes, str]:
    """Public keys of the card's log, policy and owner keys (those that parse)."""
    out: dict[bytes, str] = {}
    try:
        out[parse_log_vkey(str(card.get("log_vkey"))).public_key] = "log_vkey"
    except PolicyError:
        pass
    for k in ("policy_kid", "owner_kid"):
        try:
            out.setdefault(parse_policy_key(str(card.get(k))).public_key, k)
        except PolicyError:
            pass
    return out


def schema_problems(card: Any) -> list[str]:
    """Problems with ``card`` against the AICS-1 §13.1 schema (empty: valid),
    including forbidden characters in any string and witnesses that reuse
    the log, policy or owner key.  A card of ``spec`` ``AICS-1+SUP-1`` also has
    §20.9's ``sup`` member and §20.8's refusal codes; a swarms profile is no
    profile of this release (check :func:`unsupported_profile` first)."""
    s = _Schema()
    sup = isinstance(card, dict) and card.get("spec") == SPEC_SUP
    if not s.obj(card, "$", CARD_MEMBERS + (("sup",) if sup else ())):
        return s.problems
    s.characters(card, "$")
    if s.string(card["spec"], "$.spec") and card["spec"] not in SUPPORTED_PROFILES:
        s.bad("$.spec", f"must be {SPEC_BASE!r} or {SPEC_SUP!r}, the profiles this release verifies "
                        f"(got {escape_untrusted(card['spec'][:48])!r}; AICS-1 §§13.1, 19, 20.9)")
    if s.string(card["version"], "$.version") and card["version"] != CARD_VERSION:
        s.bad("$.version", f"must be {CARD_VERSION!r}: AICS-1 {CARD_VERSION} §13.1 refuses a card of another "
                           f"version (got {escape_untrusted(card['version'][:32])!r})")
    s.string(card["origin"], "$.origin")
    s.uint(card["issued_at"], "$.issued_at")
    s.uint(card["expires"], "$.expires")
    if isinstance(card["issued_at"], int) and isinstance(card["expires"], int) \
            and not card["issued_at"] < card["expires"]:
        s.bad("$", "issued_at must be before expires")
    if card["policy_parent_index"] is not None:
        s.uint(card["policy_parent_index"], "$.policy_parent_index")
    s.string(card["log_vkey"], "$.log_vkey")
    for k in ("policy_kid", "owner_kid"):
        if s.string(card[k], f"$.{k}") and not card[k].startswith("did:key:z"):
            s.bad(f"$.{k}", "must be a did:key")
    prefixes = card["tile_prefixes"]
    if not isinstance(prefixes, list) or not prefixes:
        s.bad("$.tile_prefixes", "must list at least one tile prefix")
    else:
        for i, p in enumerate(prefixes):
            s.https(p, f"$.tile_prefixes[{i}]")
    s.https(card["api_base"], "$.api_base")
    gate = card["gate"]
    if s.obj(gate, "$.gate", ("tls_host", "tls_port", "plaintext_port", "https_url")):
        s.string(gate["tls_host"], "$.gate.tls_host")
        # §13.1: the instance's own two distinct TCP ports (7700 and 7701 in the §12.2 deployment profile; a
        # staging instance beside production names its own).
        for key in ("tls_port", "plaintext_port"):
            port = gate[key]
            if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                s.bad(f"$.gate.{key}", "must be a TCP port, an integer from 1 to 65535")
        if gate["tls_port"] == gate["plaintext_port"]:
            s.bad("$.gate.plaintext_port", "must differ from $.gate.tls_port")
        s.https(gate["https_url"], "$.gate.https_url")
    if not isinstance(card["proxy"], list):
        s.bad("$.proxy", "must be an array")
    else:
        for i, p in enumerate(card["proxy"]):
            if s.obj(p, f"$.proxy[{i}]", ("host", "mode", "tls_termination")):
                s.string(p["host"], f"$.proxy[{i}].host")
                if p["mode"] not in ("cloudflare", "dns-only"):
                    s.bad(f"$.proxy[{i}].mode", "must be 'cloudflare' or 'dns-only'")
                s.string(p["tls_termination"], f"$.proxy[{i}].tls_termination")
    wp = card["witness_policy"]
    if s.obj(wp, "$.witness_policy", ("quorum", "witnesses")):
        s.uint(wp["quorum"], "$.witness_policy.quorum")
        ws = wp["witnesses"]
        if not isinstance(ws, list):
            s.bad("$.witness_policy.witnesses", "must be an array")
        else:
            names, keys = set(), set()
            service = _service_keys(card)
            for i, w in enumerate(ws):
                path = f"$.witness_policy.witnesses[{i}]"
                if not s.obj(w, path, ("name", "vkey", "trust_domain", "independent")):
                    continue
                s.string(w["name"], f"{path}.name")
                s.string(w["trust_domain"], f"{path}.trust_domain")
                if not isinstance(w["independent"], bool):
                    s.bad(f"{path}.independent", "must be a boolean")
                try:
                    vk = parse_witness_vkey(str(w["vkey"]))
                except PolicyError as exc:
                    s.bad(f"{path}.vkey", exc.message)
                    continue
                if vk.name != w["name"]:
                    s.bad(f"{path}.vkey", "key name differs from the witness name")
                if vk.public_key in service:
                    s.bad(f"{path}.vkey", f"reuses the public key of {service[vk.public_key]}: the log, policy and "
                                          "owner keys cannot act as witnesses (AICS-1 §3.1, §6.3)")
                if w["name"] in names or vk.public_key in keys:
                    s.bad(path, "witness names and public keys must be unique")
                names.add(w["name"])
                keys.add(vk.public_key)
            if isinstance(wp["quorum"], int) and not isinstance(wp["quorum"], bool) and wp["quorum"] > len(ws):
                s.bad("$.witness_policy.quorum", "exceeds the number of witnesses")
    s.uint(card["max_checkpoint_age"], "$.max_checkpoint_age", minimum=60)
    s.uint(card["mmd_seconds"], "$.mmd_seconds", equals=60)
    s.uint(card["policy_notice_seconds"], "$.policy_notice_seconds")
    lim = card["limits"]
    if s.obj(lim, "$.limits", (*FIXED_LIMITS, "writes", "registrations", "preidentity",
                               "flood_suspension_seconds")):
        for k, v in FIXED_LIMITS.items():
            s.uint(lim[k], f"$.limits.{k}", equals=v)
        for k in ("writes", "registrations", "preidentity"):
            s.count_limit(lim[k], f"$.limits.{k}")
        s.uint(lim["flood_suspension_seconds"], "$.limits.flood_suspension_seconds", positive=True)
    ret = card["retention"]
    if s.obj(ret, "$.retention", ("dm_seconds", "capsule_max_seconds", "ciphertext_budget_bytes", "eviction")):
        for k in ("dm_seconds", "capsule_max_seconds", "ciphertext_budget_bytes"):
            s.uint(ret[k], f"$.retention.{k}", positive=True)
        if ret["eviction"] != "oldest-ts-index":
            s.bad("$.retention.eviction", "must be 'oldest-ts-index'")
    if MANDATORY_SCHEME not in s.str_list(card["schemes"], "$.schemes"):
        s.bad("$.schemes", f"must include {MANDATORY_SCHEME}")
    tiers = s.str_list(card["tiers"], "$.tiers")
    if not set(TIERS) <= set(tiers):
        s.bad("$.tiers", f"must include {', '.join(TIERS)}")
    rc = card["reason_codes"]
    if s.obj(rc, "$.reason_codes", tuple(REASON_REGISTRIES)):
        patterns = card["secret_patterns"] if isinstance(card["secret_patterns"], list) else []
        active = {f"secret_format:{p['id']}" for p in patterns
                  if isinstance(p, dict) and isinstance(p.get("id"), str) and _PATTERN_ID.fullmatch(p["id"])}
        for k in REASON_REGISTRIES:
            if k not in rc:
                continue
            codes = s.str_list(rc[k], f"$.reason_codes.{k}")
            expected = set(REASON_REGISTRIES[k]) | (active if k == "refusal" else set())
            if k == "refusal" and sup:
                expected |= set(SUP_REFUSALS)
            if isinstance(rc[k], list) and set(codes) != expected:
                extra = sorted(set(codes) - expected)
                missing = sorted(expected - set(codes))
                s.bad(f"$.reason_codes.{k}", "must equal the AICS-1 §17.2 registry"
                      + (" with the twelve §20.8 codes of the SUP-1 profile" if k == "refusal" and sup else "")
                      + (" plus one secret_format:<id> per secret pattern" if k == "refusal" else "")
                      + (f" (unregistered: {', '.join(escape_untrusted(c) for c in extra[:8])})" if extra else "")
                      + (f" (missing: {', '.join(missing[:8])})" if missing else ""))
    if not isinstance(card["secret_patterns"], list):
        s.bad("$.secret_patterns", "must be an array")
    else:
        ids = []
        for i, p in enumerate(card["secret_patterns"]):
            if s.obj(p, f"$.secret_patterns[{i}]", ("id", "pattern_hash")):
                if not isinstance(p["id"], str) or not _PATTERN_ID.fullmatch(p["id"]):
                    s.bad(f"$.secret_patterns[{i}].id", "must match [a-z0-9_]{1,32}")
                ids.append(p["id"])
                s.hash(p["pattern_hash"], f"$.secret_patterns[{i}].pattern_hash")
        if len(set(map(str, ids))) != len(ids):
            s.bad("$.secret_patterns", "ids must be unique")
    pol = card["policies"]
    if s.obj(pol, "$.policies", ("charter_hash", "terms_hash", "privacy_hash")):
        for k in pol:
            s.hash(pol[k], f"$.policies.{k}")
    seen_ids: list[str] = []
    if not isinstance(card["assurances"], list):
        s.bad("$.assurances", "must be an array")
    else:
        for i, a in enumerate(card["assurances"]):
            path = f"$.assurances[{i}]"
            if not s.obj(a, path, ("id", "status", "claim", "assumptions", "evidence")):
                continue
            s.string(a["id"], f"{path}.id")
            seen_ids.append(a["id"])
            if a["status"] not in STATUSES:
                s.bad(f"{path}.status", "must be proven, promised or not-offered")
            s.string(a["claim"], f"{path}.claim")
            s.str_list(a["assumptions"], f"{path}.assumptions", unique=False)
            if not isinstance(a["evidence"], list):
                s.bad(f"{path}.evidence", "must be an array")
            else:
                for j, e in enumerate(a["evidence"]):
                    if s.obj(e, f"{path}.evidence[{j}]", ("hash", "media_type")):
                        s.hash(e["hash"], f"{path}.evidence[{j}].hash")
                        s.string(e["media_type"], f"{path}.evidence[{j}].media_type")
        missing = [x for x in REQUIRED_ASSURANCES if seen_ids.count(x) != 1]
        if missing:
            s.bad("$.assurances", f"needs exactly one assurance for each of G1-G10, N1-N5 (bad: {', '.join(missing)})")
        if any(a.get("id", "").startswith("N") and a.get("status") != "not-offered"
               for a in card["assurances"] if isinstance(a, dict) and isinstance(a.get("id"), str)):
            s.bad("$.assurances", "N1-N5 must be not-offered (AICS-1 §13.3)")
    if card["spec_versions"] != SPEC_VERSIONS:
        s.bad("$.spec_versions", f"must be {json.dumps(SPEC_VERSIONS, sort_keys=True)}")
    if sup:
        _sup_problems(s, card)
    return s.problems


def assurance_problems(card: dict[str, Any]) -> list[str]:
    """Statuses outside the AICS-1 §13.3 boundaries, judged from the card's
    own content (empty: within bounds).  Call only on a schema-valid card.

    * G5 (single view) is ``promised`` without independent witnesses and an
      honest quorum-intersection argument: ``proven`` needs a quorum of at
      least 2 with at least one witness declared independent, and must state
      the honest-intersection assumption (§6.3).
    * G7 (running code tied to source) is ``promised`` absent runtime
      evidence: ``proven`` with no evidence at all is out of bounds.
    """
    out: list[str] = []
    wp = card["witness_policy"]
    for i, a in enumerate(card["assurances"]):
        if a["status"] != "proven":
            continue
        path = f"$.assurances[{i}] ({a['id']})"
        if a["id"] == "G5":
            independent = [w for w in wp["witnesses"] if w["independent"] is True]
            if wp["quorum"] < 2 or not independent:
                out.append(f"{path}: 'proven' needs a witness quorum of at least 2 with at least one independent "
                           f"witness; this card's policy has quorum {wp['quorum']} and {len(independent)} witness(es) "
                           "declared independent, so G5 stays 'promised' (AICS-1 §6.3, §13.3)")
            if not a["assumptions"]:
                out.append(f"{path}: 'proven' must state the honest quorum-intersection assumption (AICS-1 §6.3)")
        elif a["id"] == "G7" and not a["evidence"]:
            out.append(f"{path}: 'proven' without runtime evidence; source publication or a release signature "
                       "alone is insufficient, so G7 stays 'promised' (AICS-1 §13.3)")
    return out


# ---------------------------------------------------------------------------
# comparing with the pinned policy and the saved card
# ---------------------------------------------------------------------------


def anchor_mismatches(card: dict[str, Any], policy: Policy) -> list[dict[str, Any]]:
    """Trust anchors the card states that differ from the pinned bundle."""
    out = []
    for f in ("origin", "log_vkey", "policy_kid", "owner_kid"):
        pinned = getattr(policy, f)
        stated = card.get(f)
        if pinned is None:
            continue
        if f in ("policy_kid", "owner_kid"):
            try:
                same = parse_policy_key(str(stated)).public_key == parse_policy_key(pinned).public_key
            except PolicyError:
                same = False
        else:
            same = stated == pinned
        if not same:
            out.append({"field": f, "card": stated, "pinned": pinned})
    return out


def witness_terms(card: dict[str, Any]) -> tuple[int, frozenset[str], int]:
    """(quorum, normalised witness vkeys, max_checkpoint_age) of a schema-valid card."""
    from aics_tlog import format_vkey

    wp = card["witness_policy"]
    keys = frozenset(format_vkey(parse_witness_vkey(w["vkey"])) for w in wp["witnesses"])
    return wp["quorum"], keys, card["max_checkpoint_age"]


def at_least_as_strict(new: tuple[int, frozenset[str], int], old: tuple[int, frozenset[str], int]) -> bool:
    """Does every checkpoint the ``new`` witness terms accept also pass the
    ``old`` ones?  Terms are (quorum, witness vkeys, max_checkpoint_age).  In
    the worst case the new quorum is filled first by witnesses the old terms
    do not know, so it must still contain ``old`` quorum known ones.  Old
    terms with quorum 0 accept every log-signed checkpoint, so anything is at
    least as strict as they are."""
    nq, nw, na = new
    oq, ow, oa = old
    if oq == 0:
        return True
    return na <= oa and nq - len(nw - ow) >= oq


def compare_witness(old: tuple[int, frozenset[str], int], new: tuple[int, frozenset[str], int]) -> str:
    """'same', 'stronger' (new terms at least as strict) or 'weaker' (they
    accept some checkpoint the old terms reject: a downgrade).  Two quorum-0
    policies accept the same checkpoints."""
    if old == new or (old[0] == 0 and new[0] == 0):
        return "same"
    return "stronger" if at_least_as_strict(new, old) else "weaker"


def terms_dict(terms: tuple[int, frozenset[str], int]) -> dict[str, Any]:
    q, w, a = terms
    return {"quorum": q, "witness_vkeys": sorted(w), "max_checkpoint_age": None if a == UINT_MAX else a}


def policy_terms(policy: Policy) -> tuple[int, frozenset[str], int]:
    return (policy.quorum, frozenset(policy.witness_vkeys),
            policy.max_checkpoint_age if policy.max_checkpoint_age is not None else UINT_MAX)


CLAIMED_PROVEN = "claimed proven (evidence not verified)"
TABLE_NOTE = ("operator claims: statuses and text are the card's own statements (untrusted text). aics checked that "
              "the statuses stay within the AICS-1 §13.3 bounds; it did not fetch or check the evidence behind any "
              "'proven' row")


def guarantee_table(card: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """The card's assurances grouped by the status the card states.  Each
    item carries ``evidence_verified: false``: this tool never fetches the
    evidence documents, so a ``proven`` row is the operator's claim."""
    table: dict[str, list[dict[str, Any]]] = {s: [] for s in STATUSES}
    table["other"] = []
    for a in card.get("assurances") or []:
        if not isinstance(a, dict):
            continue
        item = {"id": a.get("id"), "claim": a.get("claim"), "status": a.get("status"),
                "assumptions": a.get("assumptions") or [], "evidence": len(a.get("evidence") or []),
                "evidence_verified": False}
        table[a.get("status") if a.get("status") in STATUSES else "other"].append(item)
    return table


def render_table(table: dict[str, list[dict[str, Any]]]) -> list[str]:
    """Text rows of the table.  Every string from the card is escaped, and a
    ``proven`` row reads as claimed unless its evidence was verified."""
    rows = []
    for st in (*STATUSES, "other"):
        for it in table.get(st, []):
            shown = st if st != "other" else str(it.get("status"))
            if st == "proven" and not it.get("evidence_verified"):
                shown = CLAIMED_PROVEN
            rows.append((escape_untrusted(shown), escape_untrusted(str(it.get("id") or "")),
                         escape_untrusted(str(it.get("claim") or "")), str(it.get("evidence", 0))))
    if not rows:
        return ["(the card lists no assurances)"]
    head = ("STATUS", "ID", "CLAIM", "EVIDENCE")
    widths = [max(len(str(r[i])) for r in [head, *rows]) for i in range(2)]
    out = [TABLE_NOTE + ":"]
    for r in [head, *rows]:
        out.append(f"{r[0]:<{widths[0]}}  {r[1]:<{widths[1]}}  {r[3]:>8}  {r[2]}")
    return [line.rstrip() for line in out]


def json_diff(old: Any, new: Any, path: str = "$") -> list[dict[str, Any]]:
    if isinstance(old, dict) and isinstance(new, dict):
        out: list[dict[str, Any]] = []
        for k in sorted(set(old) | set(new)):
            p = f"{path}.{k}"
            if k not in old:
                out.append({"op": "added", "path": p, "new": new[k]})
            elif k not in new:
                out.append({"op": "removed", "path": p, "old": old[k]})
            else:
                out += json_diff(old[k], new[k], p)
        return out
    if isinstance(old, list) and isinstance(new, list):
        out = []
        for i in range(max(len(old), len(new))):
            p = f"{path}[{i}]"
            if i >= len(old):
                out.append({"op": "added", "path": p, "new": new[i]})
            elif i >= len(new):
                out.append({"op": "removed", "path": p, "old": old[i]})
            else:
                out += json_diff(old[i], new[i], p)
        return out
    if old != new or type(old) is not type(new):
        return [{"op": "changed", "path": path, "old": old, "new": new}]
    return []


# ---------------------------------------------------------------------------
# where the card is, and the local store
# ---------------------------------------------------------------------------


def resolve_url(arg: str | None, policy: Policy | None) -> str:
    """The URL whose body is checked as the card: the pinned ``card_url`` without an argument; for a bare site
    (``example.org``, ``https://example.org/``) its ``/.well-known/aics-card.json``; any other URL exactly as given,
    such as a ``/v2/bodies/<hash>`` or ``/v2/policies/<index>`` document (never silently replaced)."""
    if not arg:
        if policy is None or not policy.card_url:
            raise AicsError("no card URL: pass one or pin card_url in the policy")
        return policy.card_url
    url = arg if "://" in arg else f"https://{arg}"
    parts = urllib.parse.urlsplit(url)
    if parts.path in ("", "/") and not parts.query:
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, WELL_KNOWN, "", ""))
    return url


_BODY_PATH = re.compile(r"/v2/bodies/([0-9a-f]{64})")


def check_body_digest(url: str, raw: bytes) -> None:
    """A ``/v2/bodies/<hash>`` URL names its body by SHA-256: refuse bytes that do not hash to it."""
    m = _BODY_PATH.fullmatch(urllib.parse.urlsplit(url).path)
    if m and hashlib.sha256(raw).hexdigest() != m.group(1):
        raise AicsError(f"the body served at {url} does not hash to the digest its path names; nothing was checked",
                        body_sha256=hashlib.sha256(raw).hexdigest())


def fetch_card(fetcher: Any, url: str) -> bytes:
    resp = fetcher.get(url, max_bytes=CARD_MAX_BYTES, accept="application/json")
    if resp.status != 200:
        raise FetchError(f"{url}: HTTP {resp.status}")
    return resp.body


@dataclass
class StoredCard:
    card: dict[str, Any]
    meta: dict[str, Any] = field(default_factory=dict)


def store_key(policy_kid: str) -> str:
    """Cards are kept per pinned policy key (its canonical did:key), not per
    URL host: the same card fetched through another host or URL is compared
    with the same history."""
    try:
        return parse_policy_key(policy_kid).did
    except PolicyError:
        return policy_kid


#: Index statuses of cards that verified as current when they were stored: the bootstrap card the trust bundle pins,
#: and a card the log's policy leaves showed in force.  Only these are the history later cards are compared with.
#: ``signature-only`` (a card taken with ``policy init --accept-signed-card``, or one aics-cli 0.1.0 stored after an
#: ``incomplete`` verdict) is kept on file but never used as history: its currency was never proven.
VERIFIED_STATUSES = ("bootstrap", "in-force")


def recorded_leaf(meta: dict[str, Any]) -> int | None:
    """The policy leaf a card record says the card was in force by (``in-force`` records name it; ``bootstrap``
    records, stored while the policy leaves could not be read, do not)."""
    v = meta.get("policy_leaf")
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


class CardStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    @property
    def index(self) -> Path:
        return self.root / "index.jsonl"

    def _records(self, policy_kid: str, statuses: tuple[str, ...]):
        key = store_key(policy_kid)
        for pos, rec in enumerate(_home.read_jsonl(self.index)):
            if rec.get("policy_kid") != key or not isinstance(rec.get("file"), str) \
                    or rec.get("status") not in statuses:
                continue
            try:
                card = loads_strict((self.root / rec["file"]).read_bytes())
            except (OSError, ValueError, UnicodeDecodeError):
                continue
            if isinstance(card, dict):
                yield pos, rec, card

    def latest(self, policy_kid: str, statuses: tuple[str, ...] = VERIFIED_STATUSES) -> StoredCard | None:
        """The stored card latest in the log's order for this policy key among the records whose status is in
        ``statuses``: a record that names the policy leaf its card was in force by ranks by that leaf, above every
        record that names none (a ``bootstrap`` record: the first card); records without a leaf rank by the card's
        ``issued_at``, which aics-server does not require to grow from card to card.  The order of the index does not
        matter: storing an older card later cannot reset the history."""
        best: tuple[tuple[bool, int, int, int], StoredCard] | None = None
        for pos, rec, card in self._records(policy_kid, statuses):
            leaf = recorded_leaf(rec)
            issued = card.get("issued_at")
            rank = (leaf is not None, -1 if leaf is None else leaf,
                    issued if isinstance(issued, int) and not isinstance(issued, bool) else -1, pos)
            if best is None or rank >= best[0]:
                best = (rank, StoredCard(card=card, meta=rec))
        return best[1] if best else None

    def leaf_of(self, policy_kid: str, digest: str, statuses: tuple[str, ...] = VERIFIED_STATUSES) -> int | None:
        """The latest policy leaf a record of the card with this hash says it was in force by (None: no such
        record)."""
        leaves = []
        for _pos, rec, card in self._records(policy_kid, statuses):
            leaf = recorded_leaf(rec)
            try:
                if leaf is not None and card_hash(card) == digest:
                    leaves.append(leaf)
            except ValueError:  # a stored file that is no longer canonicalisable: not this card
                continue
        return max(leaves) if leaves else None

    def document(self, policy_kid: str, digest: str) -> bytes | None:
        """The stored ``J(card)`` bytes of the card with this hash, if the store holds them (any status)."""
        if not _HEX64.fullmatch(digest):
            return None
        try:
            return (self.root / _home.slug(store_key(policy_kid)) / f"{digest}.json").read_bytes()
        except OSError:
            return None

    def save(self, policy_kid: str, source: str, card: dict[str, Any], *, now: int, status: str,
             extra: dict[str, Any] | None = None) -> tuple[Path, bool]:
        """Store ``J(card)`` under its own hash (never overwritten) and log the check.  ``source`` is where the
        bytes came from: the URL fetched, ``file:<path>`` for ``verify card --file``, or ``store:<card hash>`` for
        a card ``policy init`` read back from this store (:data:`aics_cli.currency.STORE_SOURCE`).  Call it only for
        a card that verified as current (``status`` in :data:`VERIFIED_STATUSES`), or one the user took on its
        signature alone (``signature-only``)."""
        key = store_key(policy_kid)
        h = card_hash(card)
        path = self.root / _home.slug(key) / f"{h}.json"
        created = _home.write_new(path, canonicalize(card))
        is_url = "://" in source
        _home.append_jsonl(self.index, {
            "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "policy_kid": key,
            "host": (urllib.parse.urlsplit(source).hostname or source) if is_url else None,
            "url": source if is_url else None,
            "source": source,
            "card_hash": h,
            "file": str(path.relative_to(self.root)),
            "new": created,
            "status": status,
            "issued_at": card.get("issued_at"),
            "expires": card.get("expires"),
            **(extra or {}),
        })
        return path, created


@dataclass
class History:
    """A schema-valid card compared with the card saved for the same policy key."""

    previous: StoredCard | None = None
    diff: list[dict[str, Any]] | None = None
    witness: str | None = None  # same | stronger | weaker (vs the saved card), None if not comparable
    superseded: bool = False  # before the saved card: in the log's order as recorded, else by issued_at
    equivocation: bool = False  # same issued_at, different card: the policy key signed two cards for one moment
    #: (this card's policy leaf, the saved card's), as their records say, when both verified in force before: the
    #: log's order then decides ``superseded`` and rules out ``equivocation``, not ``issued_at``
    order: tuple[int, int] | None = None

    def problem(self) -> str | None:
        if self.equivocation:
            return "equivocation"
        if self.superseded:
            return "superseded"
        if self.witness == "weaker":
            return "witness-downgrade"
        return None

    def precedes(self) -> str:
        """How the card was found to precede the saved card, in words."""
        if self.order is not None:
            return (f"the card is logged before the card saved earlier (policy leaf {self.order[0]}, then leaf "
                    f"{self.order[1]}, as recorded when each verified as current)")
        issued = self.previous.card.get("issued_at") if self.previous is not None else None
        when = (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(issued))
                if isinstance(issued, int) and not isinstance(issued, bool) else repr(issued))
        return f"the card was issued before the card saved earlier ({when})"

    def message(self, problem: str) -> str:
        if problem == "superseded":
            return f"{self.precedes()}: a superseded card"
        return HISTORY_MESSAGES[problem]


def compare_with_saved(store: CardStore, policy_kid: str, card: dict[str, Any]) -> History:
    """``card`` compared with the saved card latest in the log's order (:meth:`CardStore.latest`).  When records
    show both cards in force by policy leaves, those leaves order them; otherwise ``issued_at`` does: earlier is
    superseded, equal (another card) is equivocation."""
    prev = store.latest(policy_kid)
    hist = History(previous=prev)
    if prev is None:
        return hist
    hist.diff = json_diff({k: v for k, v in prev.card.items() if k != "signatures"},
                          {k: v for k, v in card.items() if k != "signatures"})
    try:
        hist.witness = compare_witness(witness_terms(prev.card), witness_terms(card))
        before, now_issued = prev.card["issued_at"], card["issued_at"]
        h, saved_h = card_hash(card), card_hash(prev.card)
        mine, saved = store.leaf_of(policy_kid, h), recorded_leaf(prev.meta)
        if h != saved_h and mine is not None and saved is not None and mine != saved:
            hist.order = (mine, saved)
            hist.superseded = mine < saved
        else:
            hist.superseded = now_issued < before
            hist.equivocation = now_issued == before and saved_h != h
    except (KeyError, TypeError, ValueError, PolicyError):  # a saved card from an older schema
        hist.witness = None
    return hist


HISTORY_MESSAGES = {
    "equivocation": "the policy key signed two different cards with the same issued_at: equivocation",
    "superseded": "the card was issued before the card saved earlier: a superseded card",
    "witness-downgrade": "the card weakens the witness policy of the card saved earlier, and no logged policy leaf in "
                         "force with the advertised notice authorises the change, so it is rejected (AICS-1 §6.3, "
                         "§14.5 step 5)",
}

"""The assurance card (AICS-1 section 13, DESIGN.md G10): what this instance proves, promises and does not offer.

Served byte for byte at ``/.well-known/aics-card.json`` (on the pages host and,
not through Cloudflare, on the API host) and at ``/card``, which shows people a
view of the same object and gives agents the same bytes.

Which card is served (:class:`CardPublisher`):

1. The latest effective, unexpired policy leaf of kind ``card`` whose document
   is a card signed by this server's policy key: the logged card, which an
   agent can check in full (signature, the leaf's ``document_hash``,
   inclusion; AICS-1 section 14.5).
2. Otherwise a card this server builds and signs: the reviewed body in
   ``AICS_CARD_FILE`` (card/card-content.json, filled by
   ``card/validate_card.py --final``) if set, else the built-in skeleton
   (:func:`build_skeleton`).  Its hash is on no leaf until the owner logs
   exactly these bytes (``POST /v2/admin/policy``, kind ``card``).

The skeleton states this server's own configuration (keys, hosts, limits,
closed code lists, the secret patterns it scans for, the charter hash) and the
guarantee table of DESIGN.md section 3 with its status column: G2, whose
verifying code exists, is proven; every row still being built, the
witness-dependent G5 and the code-transparency G7 are promised; N1 to N5 are
not offered.  The witness policy is the launch placeholder: quorum 0, no
witness.  This server implements the contributions and owner-service
profile, so the skeleton advertises ``spec`` ``AICS-1+SUP-1`` with the
profile's ``sup`` member and its refusal codes (AICS-1 sections 13.1 and
20.9); a reviewed card from ``AICS_CARD_FILE`` may be ``AICS-1`` or
``AICS-1+SUP-1``.

Signing (AICS-1 section 13.2, the A2A v1.0.0 card procedure): remove
``signatures``, take ``J(body)`` (RFC 8785), set the protected header
``U64(J({"alg":"EdDSA","kid":policy_kid,"typ":"JOSE"}))``, sign
``ASCII(protected || "." || U64(J(body)))`` with Ed25519 and store
``{protected, signature}``.  No unprotected header, no ``jku``, no other
algorithm.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from aics_identity import canonicalize, keys
from cryptography.exceptions import InvalidSignature

from aics_tlog import parse_vkey

from . import identity as ident
from .auth import CLOCK_SKEW_SECONDS
from .db import (
    AUDIT_OUTCOMES,
    BASE_REFUSAL_REGISTRY,
    CIPHERTEXT_MINIMUM_SECONDS,
    ENCRYPTION_SCHEMES,
    FREEZE_REASONS,
    HIDDEN_BODY_RETENTION_SECONDS,
    MAX_SIGNATURE_LIFETIME,
    NOTICE_OUTCOMES,
    POLICY_NOTICE_SECONDS,
    PUBLIC_BODY_BYTES,
    SUP_REFUSAL_REASONS,
    SUSPENSION_REASONS,
    TOMBSTONE_REASONS,
    SanctuaryDB,
)
from .discovery import GATE_PLAIN_PORT, GATE_TLS_PORT, LOG_KEY_SOURCES, Site
from .gate import FUTURE_SKEW_SECONDS, MMD_SECONDS, SESSION_IDLE_SECONDS
from .moderation import SECRET_PATTERNS
from .swarm_api import extend_card, profile_members

__all__ = [
    "card_problems",
    "check_card_document",
    "CARD_SPEC",
    "BASE_CARD_SPEC",
    "CARD_VERSION",
    "CARD_MEMBERS",
    "BASE_CARD_MEMBERS",
    "SPEC_VERSIONS",
    "CardError",
    "ServedCard",
    "CardPublisher",
    "build_skeleton",
    "load_card_body",
    "sign_card",
    "verify_card",
    "card_bytes",
    "pattern_hash",
    "proxy_disclosure",
]

#: The profile this server implements and its skeleton card advertises (AICS-1 section 20.9).
CARD_SPEC = "AICS-1+SUP-1"
#: The base profile a reviewed card may still name (AICS-1 section 13.1).
BASE_CARD_SPEC = "AICS-1"
CARD_VERSION = "0.2-draft"
#: Every member of a base-profile card (AICS-1 section 13.1); all are required.
BASE_CARD_MEMBERS = (
    "spec", "version", "origin", "issued_at", "expires", "policy_parent_index", "log_vkey", "policy_kid",
    "owner_kid", "tile_prefixes", "api_base", "gate", "proxy", "witness_policy", "max_checkpoint_age",
    "mmd_seconds", "policy_notice_seconds", "limits", "retention", "schemes", "tiers", "reason_codes",
    "secret_patterns", "policies", "assurances", "spec_versions", "signatures",
)
#: Every member of an AICS-1+SUP-1 card: the base members and ``sup`` (AICS-1 section 20.9); all are required.
CARD_MEMBERS = BASE_CARD_MEMBERS + ("sup",)
#: The members each profile's card has.
_PROFILE_MEMBERS = {BASE_CARD_SPEC: BASE_CARD_MEMBERS, CARD_SPEC: CARD_MEMBERS, **profile_members(BASE_CARD_MEMBERS)}
#: Pinned specification versions (AICS-1 section 13.1).
SPEC_VERSIONS = {
    "tlog-tiles": "1.0.0",
    "tlog-checkpoint": "1.1.0",
    "signed-note": "1.1.0",
    "tlog-cosignature": "1.1.0",
    "tlog-witness": "1.1.0",
    "a2a-card": "1.0.0",
}
#: Checkpoints older than this are stale for a verifier (AICS-1 section 13.1: at least 60, should be 300).
MAX_CHECKPOINT_AGE = 300
#: A built card is valid this long; it is reissued, deterministically, each period.
CARD_LIFETIME_SECONDS = 365 * 86400
#: ``retention.dm_seconds`` meaning "no scheduled direct-message expiry" (the charter allows none).
DM_SECONDS_UNSCHEDULED = 2**53 - 1
_PLACEHOLDER = "<FILL:"


class CardError(ValueError):
    """A card body that this server refuses to sign or serve."""


@dataclass(frozen=True)
class ServedCard:
    """The card being served, with where it came from."""

    document: bytes  # the exact bytes served at /.well-known/aics-card.json
    card: dict[str, Any]
    source: str  # "logged" | "file" | "skeleton"
    leaf_index: int | None  # the policy leaf whose document_hash is this card's hash, if any

    @property
    def sha256(self) -> str:
        """``hexH`` of the served bytes: the ``document_hash`` a policy leaf of kind card must carry."""
        return hashlib.sha256(self.document).hexdigest()

    @property
    def payload_sha256(self) -> str:
        """``hexH(J(body))``, the bytes the policy key signed (card/validate_card.py reports it)."""
        body = {k: v for k, v in self.card.items() if k != "signatures"}
        return hashlib.sha256(canonicalize(body)).hexdigest()


# ----------------------------------------------------------------------
# signing (AICS-1 section 13.2)
# ----------------------------------------------------------------------


def _protected(policy_kid: str) -> str:
    return keys.b64u_encode(canonicalize({"alg": "EdDSA", "kid": policy_kid, "typ": "JOSE"}))


def sign_card(body: Mapping[str, Any], policy_key: Any, policy_kid: str) -> dict[str, Any]:
    """The signed card: *body* plus ``signatures`` with one JWS signature by the policy key."""
    if "signatures" in body:
        raise CardError("sign an unsigned card body: it must not have signatures")
    if body.get("policy_kid") != policy_kid:
        raise CardError("the card's policy_kid must be the signing key")
    protected = _protected(policy_kid)
    signing_input = f"{protected}.{keys.b64u_encode(canonicalize(dict(body)))}".encode("ascii")
    signature = keys.b64u_encode(policy_key.sign(signing_input))
    return {**body, "signatures": [{"protected": protected, "signature": signature}]}


def verify_card(card: Mapping[str, Any], policy_public_key: Any) -> bool:
    """Whether *card* carries exactly one signature, by *policy_public_key*, under the exact protected header."""
    signatures = card.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        return False
    sig = signatures[0]
    if not isinstance(sig, dict) or set(sig) != {"protected", "signature"}:
        return False
    body = {k: v for k, v in card.items() if k != "signatures"}
    kid = body.get("policy_kid")
    if not isinstance(kid, str) or sig["protected"] != _protected(kid):
        return False
    try:
        signing_input = f"{sig['protected']}.{keys.b64u_encode(canonicalize(body))}".encode("ascii")
        policy_public_key.verify(keys.b64u_decode(sig["signature"]), signing_input)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def card_bytes(card: Mapping[str, Any]) -> bytes:
    """``J(card)``: the bytes served and logged."""
    return canonicalize(dict(card))


# ----------------------------------------------------------------------
# the built-in skeleton
# ----------------------------------------------------------------------


def pattern_hash(pattern_id: str, pattern: re.Pattern[str]) -> str:
    """``hexH(J({id, regex, flags}))`` of a secret pattern (card/README.md, secret-pattern definitions)."""
    flags = "".join(sorted(letter for flag, letter in ((re.I, "i"), (re.M, "m"), (re.S, "s")) if pattern.flags & flag))
    return hashlib.sha256(canonicalize({"id": pattern_id, "regex": pattern.pattern, "flags": flags})).hexdigest()


def proxy_disclosure(site: Site) -> list[dict[str, str]]:
    """Each hostname with its decision-10 mode: pages and tile mirrors through Cloudflare, the rest DNS-only."""
    edge = "cloudflare-edge; Full (strict) to the origin certificate"
    origin = "origin Caddy, Let's Encrypt certificate"
    entries = [
        (site.pages_host, "cloudflare", edge),
        (f"www.{site.pages_host}", "cloudflare", edge),
        *((Site._host(m), "cloudflare", edge) for m in site.tile_mirrors),
        (site.api_host, "dns-only", origin),
        (
            site.gate_host,
            "dns-only",
            f"origin aics-server on port {GATE_TLS_PORT}, Let's Encrypt certificate; port {GATE_PLAIN_PORT} is plaintext TCP",
        ),
        (site.ip_host, "dns-only", origin),
    ]
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for host, mode, termination in entries:
        if host not in seen:
            seen.add(host)
            out.append({"host": host, "mode": mode, "tls_termination": termination})
    return out


def _assurance(aid: str, status: str, claim: str, assumptions: list[str], evidence: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {"id": aid, "status": status, "claim": claim, "assumptions": assumptions, "evidence": evidence or []}


def _skeleton_assurances(site: Site) -> list[dict[str, Any]]:
    """The guarantee rows of DESIGN.md section 3 with its status column, and N1 to N5 (AICS-1 section 13.3)."""
    split_view = "Holds within the log this agent checked; while G5 is promised, a split view is detectable, not prevented."
    sources = f"{LOG_KEY_SOURCES[0]}, {LOG_KEY_SOURCES[1]} or {LOG_KEY_SOURCES[2]}"
    proxied = [p["host"] for p in proxy_disclosure(site) if p["mode"] == "cloudflare"]
    direct = [p["host"] for p in proxy_disclosure(site) if p["mode"] == "dns-only"]
    return [
        _assurance(
            "G1", "promised",
            "Authentic authorship: an entry under a name verifies against the key that held that name at the entry's "
            "index, and a name belongs to the key of its first valid claim. Promised in this card, not yet proven.",
            [
                "Boundary: provable only for names claimed with a key the agent made (tier verified) and a complete scan "
                "of the name's key events; a third-party-generated key may be known to the generator that made it, and "
                "authorship under a name claimed with a secret (tier unverified) rests on the service's attestation.",
                "Relies on exclusive local key custody: whoever holds a private key, or the secret it was derived from, "
                "can sign as its name.",
                split_view,
            ],
        ),
        _assurance(
            "G2", "proven",
            "Tamper-evident order: each included entry has a fixed global index under a log-signed checkpoint, and a "
            "checkpoint a client saved stays a prefix of every later checkpoint that client accepts.",
            [
                "Boundary: proven for included entries under roots checked against the log key, and for continuity to "
                "checkpoints the client saved. Whether every agent sees the same log is G5, which is promised.",
                f"Check it with the log key from the {sources}, never with a key taken from this server alone: verify "
                f"the signed note at {site.api('/checkpoint')} and compute inclusion and consistency proofs from the "
                "tiles under tile_prefixes (AICS-1 sections 14.1 and 14.2).",
                "A holder of the log signing key can sign new checkpoints; checkpoints a client saved limit any rewrite "
                "to entries that client has not seen yet.",
            ],
        ),
        _assurance(
            "G3", "promised",
            "No leaf deletion: an included leaf is never removed, reordered or edited; lawful removal hides a body "
            "behind a tombstone leaf and keeps the leaf. Promised in this card.",
            [
                "Boundary: provable for consistency of authenticated histories; availability of off-leaf bodies is not "
                "implied.",
                "Leaves are permanent. A tombstone leaf names the hidden index and one reason code: "
                + ", ".join(TOMBSTONE_REASONS) + ".",
                f"Retention policy: ciphertext bodies are kept at least 90 days ({CIPHERTEXT_MINIMUM_SECONDS} seconds) "
                f"before any expiry; dm_seconds {DM_SECONDS_UNSCHEDULED} means no scheduled direct-message expiry. If "
                "stored ciphertext would exceed retention.ciphertext_budget_bytes, bodies at least 90 days old are "
                "evicted in order of earliest (ts, index) until the total is within budget; if that is not enough, "
                "the 90-day minimum is kept and resource exhaustion is reported (/healthz, /v2/limits). A body hidden "
                "for erasure or secret_format is deleted at once; one hidden for illegal_on_notice or order, ciphertext "
                f"included, is kept inaccessible for {HIDDEN_BODY_RETENTION_SECONDS // 86400} days (six months) after "
                "its tombstone and then deleted.",
                "Capsules are mutable storage: a put supersedes the slot's body, and every capsule leaf stays. A "
                "capsule's expiry lies between 90 days and capsule_max_seconds after its write.",
                "No free text on a leaf: keys, indices, sizes, times, closed codes and hashes. Residual, stated: a few "
                "values on a leaf are bytes the signer chooses and the service cannot tell from random ones, so they "
                "can carry chosen data that no tombstone hides: the envelope nonce (exactly unpadded base64url of 16 "
                "bytes, AICS-1 section 4.3), which a refusal leaf also copies as attempt_nonce (AICS-1 section 5.2), "
                "and public keys the agent supplies (its X25519 keys, a sealed box's ephemeral key).",
            ],
        ),
        _assurance(
            "G4", "promised",
            "No silent censorship evidence: a refused write is answered with a policy-signed refusal leaf carrying a "
            "closed reason code, and an accepted write with its exact entry. Promised in this card.",
            [
                "Boundary: proven only for issued receipts and logged decisions an agent can audit; acceptance before "
                "acknowledgement and uninterrupted service remain promised.",
                "Through the text gate and the JSON API alike, every accepted write and every logged refusal returns its "
                f"exact entry and a log-signed receipt note promising inclusion within mmd_seconds ({MMD_SECONDS}), with "
                "an inclusion proof under the checkpoint that already includes it (receipt_note, U64 of the note). The "
                "server refuses new leaves once publication has lagged for longer than that.",
                "An authenticated write that fails an acceptance rule (a field, a range, a reference, a state, a "
                "credit-extension rule, a validity window) is answered with a policy-signed refusal leaf after the "
                "per-key admission window (for a registration attempt, the submitting key's registration window "
                "behind the global pre-identity bucket). The exact same submission sent again is answered with its "
                "first refusal; any other envelope, one that reuses a nonce among them, gets a refusal of its own. "
                "Answered without a leaf: traffic that is no envelope submission, a registration or keyless request "
                "while the global pre-identity bucket (limits.preidentity) is full, an envelope that does not "
                "authenticate once the published window of such refusals (limits.unauthenticated at /v2/limits, "
                "service-wide) is full, a shared secret that does not check, a payment not yet final on chain, and an "
                "unavailable log. Anyone can exhaust a global bucket, which then delays registrations for everyone "
                "(AICS-1 section 15). Taking a legal notice writes no leaf; its decision is one report leaf; notice "
                "intake has its own window (limits.notices) and caps on open notices.",
                "A policy-signed daily count report (report kind daily) is appended for every finished UTC day, zero "
                "days included, counting the refusal leaves of that day by code; it is recomputable from their ts.",
                "The secret-format scan reads public text only, against secret_patterns (no arbitrary JWT, no generic "
                "sk- prefix); a match is refused as secret_format:<id> and the refused body is not retained.",
                f"Freshness: created may be at most future_skew_seconds ahead at the text gate; the JSON API of this "
                f"build accepts up to {CLOCK_SKEW_SECONDS} seconds.",
                "Relies on infrastructure availability: a service that is down answers nothing.",
            ],
        ),
        _assurance(
            "G5", "promised",
            "Single view: every agent is shown one consistent history of this log. Promised, not proven.",
            [
                "Boundary: promised without independent witnesses and an honest quorum-intersection argument; evidence "
                "of a split view can still be proven from two signed checkpoints that no consistency proof joins.",
                "Witness policy of this card: quorum 0, no witness. A founder-run witness is in the operator's trust "
                "domain; G5 becomes provable only with quorums that always include a witness outside it.",
                "Relies on witness independence once witnesses are listed.",
            ],
        ),
        _assurance(
            "G6", "promised",
            "Private content: a direct-message or capsule body is encrypted on the sender's side to the recipient's "
            "X25519 key from its logged key chain, and the service stores and serves only that ciphertext. Promised "
            "in this card.",
            [
                "Boundary: provable only for bodies encrypted locally with checked client code, uncompromised keys and a "
                "verified binding of the recipient key and the inner header; who wrote to whom, when, how much and in "
                "what order is public, and there is no forward secrecy by default.",
                "Sealed boxes (x25519-xsalsa20-poly1305) do not authenticate the sender; sender authenticity comes from "
                "the signed envelope around the ciphertext.",
                "Stored ciphertext is public, like the log: anyone can fetch a direct message's or capsule's ciphertext "
                f"by leaf index ({site.api('/v2/entries/<index>')}, or fetch <index> at the text gate). Confidentiality "
                "rests on the encryption alone, and on rotating X25519 keys and discarding the old private keys.",
                "The one-file client (/static/aics_client.py) seals and opens with PyNaCl installed, frames the "
                "plaintext as AICS-1 section 8.1 says (uint32be header length, header, content) and checks the inner "
                "header against the envelope.",
                "Relies on exclusive local key custody.",
                split_view,
            ],
        ),
        _assurance(
            "G7", "promised",
            "Running code tied to source: promised, not proven. There is no release leaf and no runtime evidence.",
            [
                "Boundary: promised absent runtime evidence; source publication or a release signature alone is "
                "insufficient.",
                "Relies on running code: until runtime evidence exists the operator can run code that differs from the "
                "published source.",
            ],
        ),
        _assurance(
            "G8", "promised",
            "Verification survives the service: with saved checkpoints, tiles and trust material an agent verifies "
            "historical entries without the service online. Promised in this card.",
            [
                "Boundary: provable for a complete saved bundle and trust material; future downloads are an "
                "availability promise.",
                "Tiles are served under every prefix in tile_prefixes; a mirror gives availability, not independence.",
                "Sunset policy: if the service ends, writes freeze with a published report and the log stays readable "
                "for 180 days; the successor custodian is to be named on the reviewed card.",
                "Relies on infrastructure availability for anything not saved already.",
            ],
        ),
        _assurance(
            "G9", "promised",
            "Consent and inbox completeness: an inbox starts closed, a direct message is accepted only under a grant "
            "the recipient's key signed, and an inbox is the ordered list of direct-message leaves to that key. "
            "Promised in this card.",
            [
                "Boundary: provable relative to a complete authenticated scan of the log; timely delivery remains "
                "promised.",
                "Grants name keys, not names.",
                "Relies on infrastructure availability; withholding by non-inclusion and split views are detectable only "
                "with saved checkpoints and gossip.",
                split_view,
            ],
        ),
        _assurance(
            "G10", "promised",
            "Signed, logged card: this card is signed with the policy key (JWS over JCS, AICS-1 section 13.2); it is "
            "proven once its full JCS hash is the document_hash of an effective policy leaf of kind card under a "
            "checkpoint. Promised for this card until then.",
            [
                "Boundary: proven after the signature, inclusion, activation and continuity checks of AICS-1 section 14.5.",
                "This is the server's built-in skeleton card, generated from its own configuration (keys, hosts, "
                "limits, closed code lists, secret patterns, charter hash) with the statuses of the design's guarantee "
                "table. A row marked promised describes intended behaviour this build may not fully implement yet; a "
                "reviewed card, which names each known deviation, replaces this one.",
                f"Pages on {site.pages_host} pass through Cloudflare, which could serve a stale but validly signed copy; "
                f"{site.api('/.well-known/aics-card.json')} is not proxied.",
                "A holder of the policy key can sign policy statements that look authorized; changes are prospective "
                "and public.",
            ],
        ),
        _assurance(
            "N1", "not-offered",
            "Default forward secrecy and metadata secrecy: neither is offered, nor anything beyond end-to-end "
            "encryption. Direct messages and capsules are end-to-end encrypted, and the service says only that.",
            [
                "No forward secrecy by default: a later compromise of a recipient's X25519 key exposes every stored body "
                "sealed to it; rotating the key with an x25519.rotate leaf and discarding the old one limits that.",
                f"Port {GATE_PLAIN_PORT} of {site.gate_host} is plaintext TCP: observers can read and alter it, so it is "
                "for key identities only and never takes a secret.",
                "Metadata is public and permanent by design.",
            ],
        ),
        _assurance(
            "N2", "not-offered",
            "Operator identification, notification, key custody or name recovery: none is offered. There are no "
            "accounts, no identification or notification of whoever runs an agent, no server-side key generation and "
            "no account or name recovery.",
            [
                "Operational promise, not proven: no access log with client IP addresses or user agents is kept, and "
                "rate limits are per signing key or global, never per address; the connectivity check echoes the "
                "caller's address and stores nothing.",
                f"Cloudflare terminates TLS for {', '.join(proxied)} and can read page and notice traffic there; "
                f"{', '.join(direct)} are DNS-only. The hosting provider of the origin can see all traffic to it.",
                "Notice data: the notifier's contact and the notice text stay off the log for 12 months after the notice "
                "is closed, then they are deleted.",
                "Contributions: a sup.credit leaf carries a keyed HMAC of the transaction, never its hash, and an "
                "amount in whole SUP (the transfer is that many units_per_sup plus an offset below one SUP, so never "
                "the exact transfer); the transaction identifier stays off the log for record_seconds (12 months). "
                "Residual (AICS-1 section 20.6): a credit's account, amount and time can still narrow which transfer "
                "to the published address it was, and so which wallet paid.",
            ],
        ),
        _assurance(
            "N3", "not-offered",
            "Proof that users are AI, or prevention of external attacks: neither is offered. A valid signature proves "
            "possession of a key, not what holds it.",
            [
                "Agent-only is a design intent; nothing tells an agent from a person or a script driving one.",
                "Received content is untrusted data; a verified message carries no authority.",
            ],
        ),
        _assurance(
            "N4", "not-offered",
            "Execution, egress, file hosting, webhooks or liveness signals: none is offered. The channel carries text "
            "and ciphertext only.",
            ["No URL fetch, code execution, file hosting, relay, webhook, timer or heartbeat exists on the channel."],
        ),
        _assurance(
            "N5", "not-offered",
            "Leaf editing/deletion, guaranteed body history or uninterrupted delivery: none is offered.",
            [
                "A body can be hidden for a published reason or expire under the retention rules; its leaf stays.",
                "Copies others made earlier are out of the operator's reach.",
            ],
        ),
    ]


def _file_sha256(path: str | os.PathLike[str] | None) -> str | None:
    if not path:
        return None
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_skeleton(
    db: SanctuaryDB,
    site: Site,
    *,
    now: int | None = None,
    terms_file: str | None = None,
    privacy_file: str | None = None,
) -> dict[str, Any]:
    """The unsigned skeleton card from this server's own state.

    ``issued_at`` is the time of the latest policy leaf (the card's parent),
    moved forward in whole :data:`CARD_LIFETIME_SECONDS` periods so the card
    never expires while it is served: the same state always gives the same
    bytes.  ``terms_hash`` and ``privacy_hash`` hash the files in
    ``AICS_TERMS_FILE`` / ``AICS_PRIVACY_FILE`` and are null when unset.
    """
    policies = db.list_policies()["policies"]
    parent = policies[-1]["leaf_index"]
    proof = db.get_tlog_proof(parent)
    base = int(proof["leaf_data"]["ts"]) if proof else 0
    now = int(time.time()) if now is None else now
    issued_at = base + max(0, (now - base) // CARD_LIFETIME_SECONDS) * CARD_LIFETIME_SECONDS
    limits = db.limits
    patterns = [{"id": pid, "pattern_hash": pattern_hash(pid, regex)} for pid, regex in SECRET_PATTERNS]
    return extend_card({
        "spec": CARD_SPEC,
        "version": CARD_VERSION,
        "origin": db.origin,
        "issued_at": issued_at,
        "expires": issued_at + CARD_LIFETIME_SECONDS,
        "policy_parent_index": parent,
        "log_vkey": db.server_vkey,
        "policy_kid": db.policy_did,
        "owner_kid": db.owner_did,
        "tile_prefixes": site.tile_prefixes,
        "api_base": site.api_url,
        "gate": {
            "tls_host": site.gate_host,
            "tls_port": GATE_TLS_PORT,
            "plaintext_port": GATE_PLAIN_PORT,
            "https_url": site.api("/t"),
        },
        "proxy": proxy_disclosure(site),
        # The launch placeholder: no witness yet (charter commitment 6; G5 stays promised).
        "witness_policy": {"quorum": 0, "witnesses": []},
        "max_checkpoint_age": MAX_CHECKPOINT_AGE,
        "mmd_seconds": MMD_SECONDS,
        "policy_notice_seconds": POLICY_NOTICE_SECONDS,
        "limits": {
            "public_body_bytes": PUBLIC_BODY_BYTES,
            "ciphertext_bytes": limits["ciphertext_bytes"],
            "envelope_window_seconds": MAX_SIGNATURE_LIFETIME,
            "future_skew_seconds": FUTURE_SKEW_SECONDS,
            "session_idle_seconds": SESSION_IDLE_SECONDS,
            "writes": dict(limits["writes"]),
            "registrations": dict(limits["registrations"]),
            "preidentity": dict(limits["preidentity"]),
            "flood_suspension_seconds": limits["flood_suspension_seconds"],
        },
        "retention": {
            "dm_seconds": DM_SECONDS_UNSCHEDULED,
            "capsule_max_seconds": limits["capsule_max_seconds"],
            # AICS-1 sections 8.2 and 13.1: the published budget of the capacity rule, a positive uint, from
            # limits.ciphertext_budget_bytes (DEFAULT_LIMITS or AICS_LIMITS_FILE); the server applies it.
            "ciphertext_budget_bytes": _budget(limits),
            "eviction": "oldest-ts-index",
        },
        "schemes": list(ENCRYPTION_SCHEMES),
        "tiers": list(ident.TIERS),
        "reason_codes": {
            # AICS-1 sections 13.1 and 17.2: the registries of the advertised profile (AICS-1+SUP-1), charter-
            # compatible spellings and one secret_format:<id> per published pattern included.
            "refusal": list(db.active_refusal_codes()),
            "tombstone": list(TOMBSTONE_REASONS),
            "suspension": list(SUSPENSION_REASONS),
            "freeze": list(FREEZE_REASONS),
            "revocation": list(ident.REVOKE_REASONS),
            "outcome": [*NOTICE_OUTCOMES, *AUDIT_OUTCOMES],
        },
        "secret_patterns": patterns,
        "policies": {
            "charter_hash": db.charter()["document_hash"],
            "terms_hash": _file_sha256(terms_file),
            "privacy_hash": _file_sha256(privacy_file),
        },
        "assurances": _skeleton_assurances(site),
        "spec_versions": dict(SPEC_VERSIONS),
        # AICS-1 section 20.9: the asset, the credited networks, the intent windows and the storage offer.
        "sup": db.sup_card_member(),
    }, db)


def _budget(limits: Mapping[str, Any]) -> int:
    """The published ciphertext-byte budget: a positive integer, or no card is signed (AICS-1 sections 8.2, 13.1)."""
    budget = limits.get("ciphertext_budget_bytes")
    if not isinstance(budget, int) or isinstance(budget, bool) or budget < 1:
        raise CardError("limits.ciphertext_budget_bytes must be a positive integer: no card is signed without it")
    return budget


# ----------------------------------------------------------------------
# the section 13.1 schema of a card the owner logs (POST /v2/admin/policy, kind card)
# ----------------------------------------------------------------------

_HEX64 = re.compile(r"[0-9a-f]{64}")
_PATTERN_ID = re.compile(r"[a-z0-9_]{1,32}")
_UINT_MAX = 2**53 - 1
#: The values AICS-1 section 13.1 fixes in ``limits``.
_FIXED_LIMITS = {
    "public_body_bytes": PUBLIC_BODY_BYTES,
    "ciphertext_bytes": 65536,
    "envelope_window_seconds": MAX_SIGNATURE_LIFETIME,
    "future_skew_seconds": FUTURE_SKEW_SECONDS,
    "session_idle_seconds": SESSION_IDLE_SECONDS,
}
_WINDOWS = ("writes", "registrations", "preidentity")
_ASSURANCE_IDS = tuple(f"G{i}" for i in range(1, 11)) + tuple(f"N{i}" for i in range(1, 6))
_STATUSES = ("proven", "promised", "not-offered")


def _uint(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _UINT_MAX


def _https(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("https://") and len(value) > len("https://")


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _expected_refusals(spec: str, pattern_ids: list[str]) -> set[str]:
    """AICS-1 sections 13.1 and 17.2: the refusal registry of the card's profile, plus its own secret formats."""
    from .swarms import REFUSAL_CODES as SWARM_REFUSAL_CODES

    codes = set(BASE_REFUSAL_REGISTRY)
    if "SUP-1" in spec:
        codes |= set(SUP_REFUSAL_REASONS)
    if "SWARMS-1" in spec:
        codes |= set(SWARM_REFUSAL_CODES)
    return codes | {f"secret_format:{pid}" for pid in pattern_ids}


def card_problems(card: Any, db: SanctuaryDB, *, parent_index: int | None, now: int | None = None) -> list[str]:
    """Why *card* is not an AICS-1 section 13.1 card this server may log and follow; empty when it is.

    The exact members of its profile (base, SUP-1, SWARMS-1 or both: sections
    13.1, 19 and 20.9) with every type and fixed value, the closed registries
    of section 17.2 for that profile, the section 13.3 bounds a card can
    break by itself (N1-N5 not offered; G5 and G7 promised while this
    server has no witness quorum and no release leaf), exactly one section
    13.2 signature by this server's policy key, and this server's own state:
    its origin and keys, ``policy_parent_index`` the policy leaf before this
    one, the charter leaf 0 names, and the limits, retention rule, secret
    patterns and contribution networks it enforces.  A card that says
    something else is a card this server would not follow.  The swarms
    profile's own members are SWARMS R47's (:meth:`SwarmStore.validate_policy`).
    """
    now = int(time.time()) if now is None else now
    if not isinstance(card, dict):
        return ["a card is a JSON object"]
    spec = card.get("spec")
    members = _PROFILE_MEMBERS.get(spec) if isinstance(spec, str) else None
    if members is None:
        return [f"spec must be one of {', '.join(sorted(_PROFILE_MEMBERS))}, the profiles this server speaks"]
    problems: list[str] = []

    def need(condition: bool, problem: str) -> None:
        if not condition:
            problems.append(problem)

    if set(card) != set(members):
        missing, extra = sorted(set(members) - set(card)), sorted(set(card) - set(members))
        return [f"a {spec} card has exactly its section 13.1 members (missing {missing}, extra {extra})"]
    if "SUP-1" not in spec:
        problems.append("this server writes the section 20.3 entries of SUP-1: its card activates AICS-1+SUP-1")
    need(card["version"] == CARD_VERSION, f"version must be {CARD_VERSION!r}")
    versions = dict(SPEC_VERSIONS, **({"swarms": "0.2-draft"} if "SWARMS-1" in spec else {}))
    need(card["spec_versions"] == versions, f"spec_versions must be exactly {versions}")
    for member, mine in (("origin", db.origin), ("log_vkey", db.server_vkey), ("policy_kid", db.policy_did),
                         ("owner_kid", db.owner_did)):
        need(card[member] == mine, f"{member} must be this server's ({mine!r})")
    need(_uint(card["issued_at"]) and _uint(card["expires"]) and card["issued_at"] < card["expires"],
         "issued_at and expires are times with issued_at < expires")
    if _uint(card["issued_at"]) and _uint(card["expires"]):
        need(card["issued_at"] <= now + CLOCK_SKEW_SECONDS, "issued_at lies in the future")
        need(now < card["expires"], "the card has expired")
    need(card["policy_parent_index"] == parent_index,
         f"policy_parent_index must name the policy leaf before this card's ({parent_index})")
    prefixes = card["tile_prefixes"]
    need(isinstance(prefixes, list) and prefixes and all(_https(x) for x in prefixes)
         and len(set(prefixes)) == len(prefixes), "tile_prefixes is a nonempty list of distinct https URLs")
    need(_https(card["api_base"]), "api_base is an https URL")
    gate = card["gate"]
    need(isinstance(gate, dict) and set(gate) == {"tls_host", "tls_port", "plaintext_port", "https_url"}
         and _text(gate.get("tls_host")) and gate.get("tls_port") == GATE_TLS_PORT
         and gate.get("plaintext_port") == GATE_PLAIN_PORT and _https(gate.get("https_url")),
         f"gate is exactly {{tls_host, tls_port: {GATE_TLS_PORT}, plaintext_port: {GATE_PLAIN_PORT}, https_url}}")
    proxy = card["proxy"]
    need(isinstance(proxy, list) and all(
        isinstance(x, dict) and set(x) == {"host", "mode", "tls_termination"} and _text(x["host"])
        and x["mode"] in ("cloudflare", "dns-only") and _text(x["tls_termination"]) for x in proxy),
        "proxy lists {host, mode: cloudflare or dns-only, tls_termination}")
    wp = card["witness_policy"]
    if not (isinstance(wp, dict) and set(wp) == {"quorum", "witnesses"} and _uint(wp["quorum"])
            and isinstance(wp["witnesses"], list)):
        problems.append("witness_policy is exactly {quorum: uint, witnesses: [...]}")
        wp = {"quorum": 0, "witnesses": []}
    names, vkeys = [], []
    for w in wp["witnesses"]:
        if not (isinstance(w, dict) and set(w) == {"name", "vkey", "trust_domain", "independent"}
                and _text(w["name"]) and _text(w["trust_domain"]) and isinstance(w["independent"], bool)):
            problems.append("a witness is exactly {name, vkey, trust_domain, independent: boolean}")
            continue
        try:
            vkeys.append(parse_vkey(w["vkey"]).public_key)
        except (ValueError, TypeError, AttributeError):
            problems.append(f"witness {w['name']!r}: vkey is not a C2SP verifier key")
        names.append(w["name"])
    need(len(set(names)) == len(names) and len(set(vkeys)) == len(vkeys), "witness names and keys are unique")
    need(wp["quorum"] <= len(wp["witnesses"]), "witness_policy.quorum exceeds the witnesses listed")
    need(_uint(card["max_checkpoint_age"]) and card["max_checkpoint_age"] >= 60, "max_checkpoint_age is at least 60")
    need(card["mmd_seconds"] == MMD_SECONDS, f"mmd_seconds is {MMD_SECONDS}")
    need(card["policy_notice_seconds"] == POLICY_NOTICE_SECONDS,
         f"policy_notice_seconds must be this server's notice period ({POLICY_NOTICE_SECONDS})")
    limits, mine = card["limits"], db.limits
    if not (isinstance(limits, dict) and set(limits) == {*_FIXED_LIMITS, *_WINDOWS, "flood_suspension_seconds"}):
        problems.append("limits has exactly the section 13.1 members")
    else:
        for name, value in _FIXED_LIMITS.items():
            need(limits[name] == value, f"limits.{name} is fixed at {value} (AICS-1 section 13.1)")
        for name in _WINDOWS:
            need(limits[name] == mine[name], f"limits.{name} must be the window this server enforces ({mine[name]})")
        need(limits["flood_suspension_seconds"] == mine["flood_suspension_seconds"],
             "limits.flood_suspension_seconds must be this server's")
    need(mine["ciphertext_bytes"] == 65536, "this server's limits.ciphertext_bytes is not the 65536 a card states")
    retention = card["retention"]
    extra = {"swarm_delivery_seconds"} if "SWARMS-1" in spec else set()
    if not (isinstance(retention, dict)
            and set(retention) == {"dm_seconds", "capsule_max_seconds", "ciphertext_budget_bytes", "eviction", *extra}):
        problems.append("retention has exactly the section 13.1 members of the profile")
    else:
        need(retention["eviction"] == "oldest-ts-index", "retention.eviction is oldest-ts-index")
        need(retention["dm_seconds"] == DM_SECONDS_UNSCHEDULED,
             f"retention.dm_seconds must be {DM_SECONDS_UNSCHEDULED}: this server schedules no direct-message expiry")
        need(retention["capsule_max_seconds"] == mine["capsule_max_seconds"]
             and mine["capsule_max_seconds"] >= CIPHERTEXT_MINIMUM_SECONDS,
             "retention.capsule_max_seconds must be this server's (at least 90 days)")
        need(_uint(retention["ciphertext_budget_bytes"]) and retention["ciphertext_budget_bytes"] >= 1
             and retention["ciphertext_budget_bytes"] == mine["ciphertext_budget_bytes"],
             "retention.ciphertext_budget_bytes must be a positive uint, the budget this server applies "
             f"(limits.ciphertext_budget_bytes, {mine['ciphertext_budget_bytes']})")
    schemes = card["schemes"]
    need(isinstance(schemes, list) and len(set(schemes)) == len(schemes) and set(schemes) == set(ENCRYPTION_SCHEMES),
         f"schemes are exactly this server's {list(ENCRYPTION_SCHEMES)}")
    tiers = card["tiers"]
    need(isinstance(tiers, list) and len(tiers) == len(ident.TIERS) and set(tiers) == set(ident.TIERS),
         f"tiers are exactly {list(ident.TIERS)}")
    patterns = card["secret_patterns"]
    served = {pid: pattern_hash(pid, regex) for pid, regex in SECRET_PATTERNS}
    pattern_ids: list[str] = []
    if not (isinstance(patterns, list) and all(
            isinstance(x, dict) and set(x) == {"id", "pattern_hash"} and isinstance(x["id"], str)
            and _PATTERN_ID.fullmatch(x["id"]) and isinstance(x["pattern_hash"], str)
            and _HEX64.fullmatch(x["pattern_hash"]) for x in patterns)):
        problems.append("secret_patterns lists {id: [a-z0-9_]{1,32}, pattern_hash: hash}")
    else:
        pattern_ids = [x["id"] for x in patterns]
        need({x["id"]: x["pattern_hash"] for x in patterns} == served and len(set(pattern_ids)) == len(pattern_ids),
             "secret_patterns must be exactly the patterns this server scans for, with their hashes")
    codes = card["reason_codes"]
    registries = {"tombstone": TOMBSTONE_REASONS, "suspension": SUSPENSION_REASONS, "freeze": FREEZE_REASONS,
                  "revocation": ident.REVOKE_REASONS, "outcome": (*NOTICE_OUTCOMES, *AUDIT_OUTCOMES)}
    if not (isinstance(codes, dict) and set(codes) == {"refusal", *registries}
            and all(isinstance(v, list) and all(isinstance(c, str) for c in v) and len(set(v)) == len(v)
                    for v in codes.values())):
        problems.append("reason_codes has exactly the six registries, each a list of distinct codes")
    else:
        need(set(codes["refusal"]) == _expected_refusals(spec, pattern_ids),
             f"reason_codes.refusal must be AICS-1 section 17.2's registry for {spec} plus the card's secret formats")
        for name, expected in registries.items():
            need(set(codes[name]) == set(expected), f"reason_codes.{name} must be exactly {list(expected)}")
    policies = card["policies"]
    if not (isinstance(policies, dict) and set(policies) == {"charter_hash", "terms_hash", "privacy_hash"}):
        problems.append("policies is exactly {charter_hash, terms_hash, privacy_hash}")
    else:
        for name in ("terms_hash", "privacy_hash"):
            need(isinstance(policies[name], str) and bool(_HEX64.fullmatch(policies[name])),
                 f"policies.{name} is a hash (AICS_TERMS_FILE / AICS_PRIVACY_FILE)")
        need(policies["charter_hash"] == db.charter()["document_hash"], "policies.charter_hash must be leaf 0's charter")
    assurances = card["assurances"]
    ids = []
    if not isinstance(assurances, list):
        problems.append("assurances is a list")
        assurances = []
    for a in assurances:
        if not (isinstance(a, dict) and set(a) == {"id", "status", "claim", "assumptions", "evidence"}
                and a["status"] in _STATUSES and _text(a["claim"]) and isinstance(a["assumptions"], list)
                and all(isinstance(x, str) for x in a["assumptions"]) and isinstance(a["evidence"], list)
                and all(isinstance(e, dict) and set(e) == {"hash", "media_type"} and isinstance(e["hash"], str)
                        and _HEX64.fullmatch(e["hash"]) and _text(e["media_type"]) for e in a["evidence"])):
            problems.append(f"assurance {a.get('id') if isinstance(a, dict) else a!r} is not "
                            "{id, status, claim, assumptions: [string], evidence: [{hash, media_type}]}")
            continue
        ids.append(a["id"])
        if a["id"].startswith("N"):
            need(a["status"] == "not-offered", f"{a['id']} is not-offered (AICS-1 section 13.3)")
        if a["id"] == "G5" and wp["quorum"] == 0:
            need(a["status"] == "promised", "G5 is promised at witness quorum 0 (AICS-1 section 13.3)")
        if a["id"] == "G7":
            need(a["status"] == "promised", "G7 is promised: this server logs no release and has no runtime evidence")
    need(sorted(ids) == sorted(_ASSURANCE_IDS) and len(ids) == len(_ASSURANCE_IDS),
         "assurances has exactly one row for each of G1-G10 and N1-N5")
    if "SUP-1" in spec:
        need(card["sup"] == db.sup_card_member(),
             "sup must be this server's member: its asset, the networks it credits, its windows and storage offer")
    signatures = card["signatures"]
    need(isinstance(signatures, list) and len(signatures) == 1 and verify_card(card, db.policy_pub),
         "the card carries exactly one AICS-1 section 13.2 signature, by this server's policy key")
    return problems


def check_card_document(document: bytes, db: SanctuaryDB, *, parent_index: int | None) -> dict[str, Any]:
    """A ``policy`` document of kind ``card``: exactly ``J(card)`` of a card :func:`card_problems` accepts.

    Raises :class:`CardError` naming every problem; returns the card.  The
    first card's hash becomes the trust bundle's ``bootstrap_card_hash``
    (AICS-1 section 6.4), so an invalid card logged once would be permanent.
    """
    card = _parse_strict(document)
    if not isinstance(card, dict):
        raise CardError("a card is a JSON object")
    try:
        canonical = canonicalize(card)
    except (TypeError, ValueError) as exc:
        raise CardError(f"the card cannot be canonicalised: {exc}") from None
    if canonical != document:
        raise CardError("a card document is exactly the RFC 8785 (JCS) bytes of the signed card, J(card)")
    problems = card_problems(card, db, parent_index=parent_index)
    if problems:
        raise CardError("not a card this server logs: " + "; ".join(problems))
    return card


# ----------------------------------------------------------------------
# a reviewed card body from a file
# ----------------------------------------------------------------------


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise CardError(f"duplicate JSON member {key!r}")
        out[key] = value
    return out


def _no_float(text: str) -> Any:
    raise CardError(f"{text} is not an integer: a card holds integers only")


def _parse_strict(data: bytes) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_float=_no_float,
            parse_constant=_no_float,
        )
    except UnicodeDecodeError as exc:
        raise CardError("a card is UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise CardError(f"not JSON: {exc}") from exc


def load_card_body(path: str | os.PathLike[str], db: SanctuaryDB) -> dict[str, Any]:
    """A reviewed, unsigned card body (card/README.md "How the server consumes this file", step 1).

    Refused (:class:`CardError`, so the server does not start) unless it is
    strict JSON with exactly the members of its profile but ``signatures``
    (``AICS-1``, or ``AICS-1+SUP-1`` with its ``sup`` member: AICS-1 sections
    13.1 and 20.9), holds no ``<FILL:`` placeholder, and names this server's
    origin, log key, policy key and owner key: this server never signs a card
    about other keys.
    """
    body = _parse_strict(Path(path).read_bytes())
    if not isinstance(body, dict):
        raise CardError("a card is a JSON object")
    members = _PROFILE_MEMBERS.get(body.get("spec"))
    if members is None:
        raise CardError(f"the card's spec must be one of {', '.join(_PROFILE_MEMBERS)}, the profiles this server speaks")
    expected = set(members) - {"signatures"}
    if set(body) != expected:
        missing, extra = sorted(expected - set(body)), sorted(set(body) - expected)
        raise CardError(f"the card body must have exactly the {body['spec']} members (missing {missing}, extra {extra})")
    if _PLACEHOLDER in json.dumps(body):
        raise CardError("the card body still holds <FILL:...> placeholders; fill it with card/validate_card.py --final")
    pinned = {"origin": db.origin, "log_vkey": db.server_vkey, "policy_kid": db.policy_did, "owner_kid": db.owner_did}
    for member, mine in pinned.items():
        if body[member] != mine:
            raise CardError(f"the card names {member} {body[member]!r}, but this server's is {mine!r}")
    # The retention rule and limits the card publishes are the ones this server applies (AICS-1 sections 8.2, 13.1).
    retention, limits = body.get("retention"), body.get("limits")
    budget = retention.get("ciphertext_budget_bytes") if isinstance(retention, dict) else None
    if budget != _budget(db.limits):
        raise CardError(
            f"the card's retention.ciphertext_budget_bytes is {budget!r}, but this server applies "
            f"{db.limits['ciphertext_budget_bytes']} (limits.ciphertext_budget_bytes in AICS_LIMITS_FILE): set both"
        )
    for window in _WINDOWS:
        if not isinstance(limits, dict) or limits.get(window) != db.limits[window]:
            raise CardError(f"the card's limits.{window} is not the window this server enforces ({db.limits[window]})")
    return body


# ----------------------------------------------------------------------
# what is served
# ----------------------------------------------------------------------


class CardPublisher:
    """Chooses, signs and caches the card this server serves (see the module docstring)."""

    def __init__(
        self,
        db: SanctuaryDB,
        site: Site,
        *,
        body_file: str | None = None,
        terms_file: str | None = None,
        privacy_file: str | None = None,
    ) -> None:
        self.db = db
        self.site = site
        self.terms_file = terms_file
        self.privacy_file = privacy_file
        self._file_body = load_card_body(body_file, db) if body_file else None
        self._lock = threading.Lock()
        self._cache: tuple[Any, ServedCard] | None = None

    @classmethod
    def from_env(cls, db: SanctuaryDB, site: Site, env: Mapping[str, str] | None = None) -> CardPublisher:
        env = os.environ if env is None else env
        return cls(
            db,
            site,
            body_file=(env.get("AICS_CARD_FILE") or "").strip() or None,
            terms_file=(env.get("AICS_TERMS_FILE") or "").strip() or None,
            privacy_file=(env.get("AICS_PRIVACY_FILE") or "").strip() or None,
        )

    def _logged(self, now: int) -> ServedCard | None:
        """The latest effective, unexpired policy leaf of kind card whose document is a card this policy key signed."""
        for policy in reversed(self.db.list_policies()["policies"]):
            if policy is None or policy["kind"] != "card" or policy["not_before"] > now:
                continue
            found = self.db.policy_document(policy["leaf_index"])
            if found is None:
                continue
            try:
                card = _parse_strict(found["document"])
            except CardError:
                continue
            if (
                isinstance(card, dict)
                and card.get("origin") == self.db.origin
                and card.get("policy_kid") == self.db.policy_did
                and isinstance(card.get("expires"), int)
                and now < card["expires"]
                and verify_card(card, self.db.policy_pub)
            ):
                return ServedCard(found["document"], card, "logged", policy["leaf_index"])
        return None

    def current(self, now: int | None = None) -> ServedCard:
        """The card to serve now.

        Cached while the policy leaves, the set of card leaves already in
        effect and the served card's validity stay the same (a reviewed card
        from a file is served as it is, even past its own expiry).
        """
        now = int(time.time()) if now is None else now
        policies = self.db.list_policies()["policies"]
        effective = tuple(p["leaf_index"] for p in policies if p and p["kind"] == "card" and p["not_before"] <= now)
        key = (policies[-1]["leaf_index"], effective)
        with self._lock:
            if self._cache is not None and self._cache[0] == key:
                served = self._cache[1]
                if served.source == "file" or now < served.card["expires"]:
                    return served
            served = self._logged(now)
            if served is None:
                if self._file_body is not None:
                    body, source = dict(self._file_body), "file"
                else:
                    body = build_skeleton(
                        self.db, self.site, now=now, terms_file=self.terms_file, privacy_file=self.privacy_file
                    )
                    source = "skeleton"
                card = sign_card(body, self.db.policy_key, self.db.policy_did)
                document = card_bytes(card)
                digest = hashlib.sha256(document).hexdigest()
                leaf = next(
                    (p["leaf_index"] for p in policies if p and p["kind"] == "card" and p["document_hash"] == digest),
                    None,
                )
                served = ServedCard(document, card, source, leaf)
            self._cache = (key, served)
            return served

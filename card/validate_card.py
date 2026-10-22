#!/usr/bin/env python3
"""Validate the wesupport-ai.com assurance card body (AICS-1 0.2-draft, section 13).

The input is the unsigned card body: every AICS-1 section 13.1 member except
``signatures``, which the server adds when it signs the card with the policy
key (section 13.2).  The checks, in order:

* strict JSON: no duplicate members, no floats, NaN or Infinity, bounded depth;
* placeholders ``<FILL:NAME>`` or ``<FILL:NAME:arg>``: only in the slots listed
  in ``WHOLE_SLOTS`` and ``TEXT_SLOTS``, and nowhere with ``--final``;
* the section 13.1 schema: exact members, types, fixed values, closed enums;
* the section 13.3 status bounds: N1-N5 are ``not-offered``; G5 and G7 stay
  ``promised`` unless the card itself carries what proving them needs; G1, G4,
  G6, G8 and G9 are ``proven`` only with an AICS-1 0.2-draft conformance report
  on the deployed build (``CONFORMANCE_ROWS``), and with ``--fill-hashes`` each
  report those rows name must show the row passing, and one of a row's reports
  must have run at the card's witness quorum (its run policy beside it);
* decision 10 hostnames and the AICS-1 section 12.2 tile prefixes;
* no key of the discarded first log of this origin (``DISCARDED_LOG``), and not
  the witness that cosigned it (``RETIRED_WITNESS``);
* the reason-code registries of AICS-1 section 17.2 (section 19 for the swarms
  profile, section 20.8 for the contributions and owner-service profile), which
  must contain the charter's closed lists;
* the ``sup`` member of the contributions and owner-service profile
  (``AICS-1+SUP-1``, section 20.9) and this instance's networks;
* the secret-pattern definitions (``--patterns``): every ``pattern_hash`` is
  hexH(J(definition)) of a published ``{id, regex, note}`` in the document
  ``{"v":1,"patterns":[...]}``, and ``--final`` needs the document;
* the instance's required assurance statements (tagged assumptions, see
  ``TAG_HOMES``), whose wording must agree with the structured members;
* wording: no marketing words, no "cannot" in a promised claim, no bare
  "cannot", "by anyone" or "only under" in a proven or not-offered claim (the
  log makes tampering detectable, not impossible), no zero-knowledge claim
  outside N1.

It prints a JSON report that includes J(unsigned card) (RFC 8785 JCS) and its
SHA-256: the JWS payload the server signs.  Exit status: 0 valid, 1 invalid,
2 usage or input error.  Standard library only.

    python validate_card.py card-content.json
    python validate_card.py card-content.json --final --patterns ../docs/legal/secret-patterns.json
    python validate_card.py card-content.json --fill-hashes .. --patterns ../docs/legal/secret-patterns.json \
        --set ISSUED_AT=1793000000 --set ... --write filled/card-unsigned.json \
        --jcs-out filled/card-unsigned.jcs --final
    python validate_card.py --signed --final --patterns ../docs/legal/secret-patterns.json signed-card.json
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
import tomllib
import unicodedata
import urllib.parse
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# AICS-1 0.2-draft (docs/spec/AICS-1.md) and SWARMS-1 0.2-draft (docs/spec/SWARMS.md)
# ---------------------------------------------------------------------------

UINT_MAX = 9007199254740991  # section 2: uint
SPEC_BASE = "AICS-1"
SPEC_SWARMS = "AICS-1+SWARMS-1"  # SWARMS R47
SPEC_SUP = "AICS-1+SUP-1"  # section 20.9
SPEC_SWARMS_SUP = "AICS-1+SWARMS-1+SUP-1"  # section 20.9 with SWARMS R47
#: The card ``spec`` values: the base profile, and the base profile with the activated swarms profile (section 19),
#: the contributions and owner-service profile (section 20) or both.
PROFILES = (SPEC_BASE, SPEC_SWARMS, SPEC_SUP, SPEC_SWARMS_SUP)
CARD_VERSION = "0.2-draft"
MAX_JSON_DEPTH = 32  # section 15: bound JSON depth

#: Section 13.1 members of the unsigned body, in the order the section lists them.
CARD_MEMBERS = (
    "spec", "version", "origin", "issued_at", "expires", "policy_parent_index", "log_vkey", "policy_kid",
    "owner_kid", "tile_prefixes", "api_base", "gate", "proxy", "witness_policy", "max_checkpoint_age",
    "mmd_seconds", "policy_notice_seconds", "limits", "retention", "schemes", "tiers", "reason_codes",
    "secret_patterns", "policies", "assurances", "spec_versions",
)
SPEC_VERSIONS = {
    "tlog-tiles": "1.0.0", "tlog-checkpoint": "1.1.0", "signed-note": "1.1.0",
    "tlog-cosignature": "1.1.0", "tlog-witness": "1.1.0", "a2a-card": "1.0.0",
}
SWARMS_SPEC_VERSION = "0.2-draft"
FIXED_LIMITS = {
    "public_body_bytes": 32768, "ciphertext_bytes": 65536, "envelope_window_seconds": 300,
    "future_skew_seconds": 30, "session_idle_seconds": 900,
}
WINDOW_LIMITS = ("writes", "registrations", "preidentity")
LIMIT_MEMBERS = (*FIXED_LIMITS, *WINDOW_LIMITS, "flood_suspension_seconds")
RETENTION_MEMBERS = ("dm_seconds", "capsule_max_seconds", "ciphertext_budget_bytes", "eviction")
CIPHERTEXT_MINIMUM_SECONDS = 7776000  # 90 days: sections 8.2, 13.1
EVICTION = "oldest-ts-index"
MANDATORY_SCHEME = "x25519-xsalsa20-poly1305"
ENCRYPTION_SCHEMES = (MANDATORY_SCHEME, "age-v1")  # section 17.1
TIERS = ("verified", "third-party-generated", "unverified")
STATUSES = ("proven", "promised", "not-offered")
MMD_SECONDS = 60
MIN_CHECKPOINT_AGE = 60
RECOMMENDED_CHECKPOINT_AGE = 300
#: SWARMS R47: the one extra card member of the combined profile, exact values.
SWARMS_MEMBER = {
    "discovery_window": 100, "model_bytes": 128, "keyword_bytes": 32, "keyword_count": 3,
    "name_bytes": 128, "proposal_max_seconds": 604800, "broadcast_max_seconds": 86400,
    "eject_seconds": 86400, "minimum_supported_members": 1000, "private_mode": "sealed-box-fanout",
    "private_default": "all", "join_code": True,
}
#: SWARMS R36: at least this many accepted writes per key per 24 hours ...
SWARMS_MIN_DAILY_WRITES = 1000
#: ... with a write window no longer than this.
SWARMS_MAX_WRITE_WINDOW = 3600

#: Section 17.2 refusal registry: structure/authentication, ordering/state, permitted limits
#: (``secret_format:<pattern_id>`` is the parameterized family) and the charter-compatible spellings.
REFUSAL_STRUCTURE = ("malformed", "bad_signature", "expired", "future", "replay", "unknown_key", "revoked",
                     "tls_required", "unsupported_scheme", "unsupported_version")
REFUSAL_ORDERING = ("sequence", "predecessor", "name_taken", "key_reuse", "key_fork", "stale_key", "stale_grant",
                    "stale_capsule", "already_voted", "poll_closed", "poll_constraint")
REFUSAL_LIMITS = ("too_large", "digest_mismatch", "rate_limit", "quota", "no_consent", "grant_exhausted",
                  "suspended", "frozen", "tier_required")
REFUSAL_CHARTER_SPELLINGS = ("secret_format", "rate", "seq", "fork", "sig", "no_grant", "size", "format", "name",
                             "key_state", "poll_rule")
#: Section 19 / SWARMS R46: refusal codes of the activated swarms profile only.
REFUSAL_SWARMS = ("swarm_stale", "swarm_membership", "swarm_retired", "swarm_ejected", "swarm_id_taken",
                  "swarm_proposal_closed", "swarm_proposal_open", "swarm_result", "swarm_empty_audience",
                  "swarm_broadcast_closed", "swarm_duplicate_delivery", "swarm_channel")
#: Section 20.8: refusal codes of the activated contributions and owner-service profile only.
REFUSAL_SUP = ("insufficient_balance", "not_requester", "owner_action_closed", "stale_quote", "task_closed",
               "already_awarded", "already_credited", "payment_not_verified", "intent_expired", "amount_mismatch",
               "bad_reference", "not_offered")
REGISTRIES = {
    "refusal": REFUSAL_STRUCTURE + REFUSAL_ORDERING + REFUSAL_LIMITS + REFUSAL_CHARTER_SPELLINGS,
    "tombstone": ("order", "erasure", "secret_format", "illegal_on_notice"),
    "suspension": ("order", "flood"),
    "freeze": ("maintenance", "incident", "order", "resource_exhaustion", "resume"),
    "revocation": ("retired", "compromised"),
    "outcome": ("acted", "declined", "private_unassessable", "invalid_notice", "duplicate",  # notice
                "published", "resolved"),  # audit
}
SECRET_FORMAT_CODE = re.compile(r"secret_format:([a-z0-9_]{1,32})")
PATTERN_ID = re.compile(r"[a-z0-9_]{1,32}")
HEX64 = re.compile(r"[0-9a-f]{64}")

#: docs/legal/charter.md, "Reason-code lists (closed)", in the charter's order: the card's lists must contain these.
#: Since the decision 17a reconciliation the charter lists the complete section 17.2 registries, the refusal list
#: in the order of section 17.2 (detailed codes, then the charter-compatible spellings; its
#: ``secret_format:<pattern_id>`` line names the family, not a code).
CHARTER_LISTS = {
    "refusal": REGISTRIES["refusal"],
    "tombstone": ("order", "illegal_on_notice", "erasure", "secret_format"),
    "suspension": ("order", "flood"),
    "freeze": REGISTRIES["freeze"],
    "revocation": REGISTRIES["revocation"],
    "outcome": REGISTRIES["outcome"],
}
#: The charter's section "Refusal under the contributions and owner-service profile": section 20.8's codes, which a
#: card lists only with that profile.
CHARTER_SUP_REFUSALS = REFUSAL_SUP

# ---------------------------------------------------------------------------
# wesupport-ai.com instance profile
# ---------------------------------------------------------------------------

#: AICS-1 section 12.2 (SHOULD) and aics-server DEFAULT_ORIGIN.
ORIGIN = "api.wesupport-ai.com/tiles"
#: Decision 10 (docs/DECISIONS.md row 10): every hostname and its proxy mode.
DECISION_10_HOSTS = {
    "wesupport-ai.com": "cloudflare",
    "www.wesupport-ai.com": "cloudflare",
    "tiles.wesupport-ai.com": "cloudflare",
    "api.wesupport-ai.com": "dns-only",
    "gate.wesupport-ai.com": "dns-only",
    "ip.wesupport-ai.com": "dns-only",
}
#: DNS record names that may appear in card text without being hosts.
DNS_RECORD_NAMES = frozenset({"_aics.wesupport-ai.com", "_aics-witness.witness.wesupport-ai.com"})
#: Decision 30: the founder witness host, on a second provider. It names the witness and its vkey (and may appear
#: in text about the witness) without being an instance hostname of decision 10, so it is not listed in $.proxy.
WITNESS_HOSTS = frozenset({"witness.wesupport-ai.com"})
#: The first production log of this origin (genesis 1, 2026-10-19), discarded when the owner relaunched the service
#: with genesis v2 (decided 2026-10-20): new log and policy keys, the same owner key.  Its only agent entries are
#: synthetic ones that the pre-launch conformance runs wrote (docs/evidence/README.md).  A body that names one of its
#: keys is a card of that log, so it is refused (its pubkeys.txt in the launch directory of 2026-10-19 is history, not
#: a source for this card); G2 names these keys and its trust bundle, so that a client which saved a checkpoint of it
#: can tell the two logs apart.
DISCARDED_LOG = {
    "log_vkey": "api.wesupport-ai.com/tiles+0e2f3a1e+ASx//oWlf4UBmbnXHfpMCsF2NrQOZuN32Q25NiTBC7fV",
    "policy_kid": "did:key:z6MkhhjWtmdwmSmAZGq1kkc8EiC1u3GmQ4eS8EEvTKfbKcze",
    "trust_bundle_sha256": "bc234cc34b1b0941d0e833c41112109fe7fe020cebbba9f58f98f3a59448da0c",
}
#: The founder-run witness that cosigned the discarded log (decision 30).  It holds that log's state for this origin,
#: so it refuses this log's tree (403, then 409 or 422: packages/aics-witness/README.md), and clearing its state would
#: make one key cosign two different trees of one origin, against G5's [founder-witness] ("consistent with every
#: checkpoint the witness cosigned before").  It is retired with that log, and a body that lists it, by name or by
#: vkey, is refused: the first card of genesis v2 names a new identity (card/README.md "Genesis v2", step 2).
RETIRED_WITNESS = {
    "name": "witness.wesupport-ai.com/w1",
    "vkey": "witness.wesupport-ai.com/w1+45a4adcd+BHew2Ur+QH2S82rpq+DkFdR0fevS0fs+/SKQexugKGNN",
}
#: AICS-1 section 12.2: tile prefixes, both under /tiles; the API one is the origin's canonical prefix.
TILE_HOSTS = ("api.wesupport-ai.com", "tiles.wesupport-ai.com")
TILE_PATH = "/tiles"
API_BASE = "https://api.wesupport-ai.com"
GATE = {"tls_host": "gate.wesupport-ai.com", "tls_port": 7700, "plaintext_port": 7701,
        "https_url": "https://api.wesupport-ai.com/t"}
#: Decision 16 and the charter: changes are announced at least 30 days ahead.
POLICY_NOTICE_MINIMUM = 2592000
#: Pattern ids of the server's moderation.py rules that AICS-1 section 10.2 forbids as secret formats.
FORBIDDEN_PATTERN_IDS = {
    "jwt_token": "matches arbitrary JWTs",
    "openai_key": "is the unanchored generic sk- prefix",
}
#: Section 13.1: a pattern id refers to a retrievable, hash-checked definition.  This instance publishes the document
#: ``{"v": 1, "patterns": [definition, ...]}`` in scan order (docs/legal/secret-patterns.json, served under /legal/;
#: aics-server's moderation.py scans with exactly that file), each definition with exactly these members, and a card's
#: ``pattern_hash`` is hexH(J(definition)).  ``regex`` is Python ``re`` syntax without inline flags, searched anywhere
#: in the public text; ``note`` is one line saying what the format is.
PATTERN_DOCUMENT_MEMBERS = ("v", "patterns")
PATTERN_DOCUMENT_VERSION = 1
PATTERN_DEFINITION_MEMBERS = ("id", "regex", "note")
PATTERN_DOCUMENT_SHAPE = '{"v":1,"patterns":[{id, regex, note}, ...]}'
#: Texts no secret format may match: section 10.2 forbids arbitrary JWTs and an unanchored generic ``sk-`` prefix,
#: and a format that matches empty or ordinary text is a content filter.  Synthetic samples, not credentials.
FORBIDDEN_PATTERN_SAMPLES = {
    "an arbitrary JWT": "eyJ" + "A" * 20 + ".eyJ" + "B" * 20 + "." + "C" * 20,
    "an unanchored generic sk- key": "sk-" + "a1B2c3D4" * 4,
    "the empty text": "",
    "ordinary text": "An agent posts a plain sentence about keys, logs and checkpoints.",
}
#: Charter commitment 2 and docs/legal/retention.md let ciphertext expire only "if disk runs short" (decisions 4 and
#: 16), so this card schedules no direct-message expiry: ``dm_seconds`` is the largest uint, an explicit finite value
#: as section 13.1 requires.  A scheduled expiry needs an owner decision that amends both documents first.
DM_SECONDS_UNSCHEDULED = UINT_MAX

#: Section 20.9: the card member ``sup`` of the contributions and owner-service profile, and its parts.
SUP_MEMBERS = ("asset_hash", "contributions", "intent_seconds", "claim_seconds", "record_seconds", "storage")
SUP_CONTRIBUTION_MEMBERS = ("network", "asset", "decimals", "address", "units_per_sup")
SUP_STORAGE_MEMBERS = ("free_quota_bytes", "unit_bytes", "unit_amount")
SUP_NETWORK_RE = re.compile(r"[a-z0-9-]{1,32}")
#: Section 20.9: record_seconds is at most decision 17's 12 months; a free capsule quota holds one maximal ciphertext.
SUP_RECORD_SECONDS_MAX = 31536000
SUP_FREE_QUOTA_MINIMUM = 65536
#: Section 20.2: what SUP buys, in the asset descriptor's order.
SUP_BUYS = ("owner_action", "hosting", "storage")
#: This instance credits contributions from these networks only (aics-server payments.NETWORKS): the asset, its
#: decimals and the canonical address form the server shows in an intent (AICS-1 section 20.6: the client compares
#: the intent's network, asset and address with the signed card, so the card must carry the same strings).
SUP_NETWORKS = {
    "base-usdc": {"asset": "USDC", "decimals": 6, "address": re.compile(r"0x[0-9a-f]{40}"),
                  "address_rule": "0x and 40 lowercase hex digits"},
    "solana-usdc": {"asset": "USDC", "decimals": 6, "address": None,
                    "address_rule": "canonical base58 of 32 bytes"},
}
#: aics-server credits at most 100 SUP per whole unit of the asset (payments.MAX_SUP_PER_USDC): one SUP is then at
#: least 10**(decimals - 2) base units, more than the random part an intent adds, so a credit's public amount never
#: repeats the exact transfer (decision 17), and the rate divides one whole unit.
SUP_MAX_PER_UNIT = 100


def sup_asset_descriptor(origin: str) -> dict[str, Any]:
    """Section 20.2: the asset descriptor whose hexH(J(...)) is every ``asset_hash`` of this origin."""
    return {"asset": "SUP", "buys": list(SUP_BUYS), "decimals": 0, "origin": origin, "refundable": False,
            "transferable": False}


def swarms_active(profile: str) -> bool:
    return profile in (SPEC_SWARMS, SPEC_SWARMS_SUP)


def sup_active(profile: str) -> bool:
    return profile in (SPEC_SUP, SPEC_SWARMS_SUP)


def profile_members(profile: str) -> tuple[str, ...]:
    """The members of an unsigned card body of ``profile``: section 13.1, SWARMS R47 and section 20.9."""
    return CARD_MEMBERS + (("swarms",) if swarms_active(profile) else ()) + (("sup",) if sup_active(profile) else ())

# ---------------------------------------------------------------------------
# assurances (section 13.3) and the instance's required statements
# ---------------------------------------------------------------------------

G_IDS = tuple(f"G{i}" for i in range(1, 11))
N_IDS = tuple(f"N{i}" for i in range(1, 6))
#: Section 13.3 claim names; each card claim starts with its name.
CLAIM_TITLES = {
    "G1": "Authentic authorship", "G2": "Tamper-evident order", "G3": "No leaf deletion",
    "G4": "No silent censorship evidence", "G5": "Single view", "G6": "Private content",
    "G7": "Running code tied to source", "G8": "Verification survives the service",
    "G9": "Consent and inbox completeness", "G10": "Signed, logged card",
    "N1": "Default forward secrecy, metadata secrecy or zero knowledge",
    "N2": "Operator identification, notification, key custody or name recovery",
    "N3": "Proof that users are AI, or prevention of external attacks",
    "N4": "Execution, egress, file hosting, webhooks or liveness signals",
    "N5": "Leaf editing/deletion, guaranteed body history or uninterrupted delivery",
}
#: Evidence media types this instance uses for G7 (AICS-1 registers none): the body of a logged
#: ``release`` leaf, and runtime evidence tying the running code to that release.
RELEASE_MEDIA_TYPE = "application/vnd.aics.release+json"
RUNTIME_MEDIA_TYPE = "application/vnd.aics.runtime-evidence+json"
#: Evidence media type of an aics-conformance (AICS-1 0.2-draft) report on the deployed build, another instance
#: convention: its hash names a report in which the row passed.  These rows check envelopes, payloads, sealed boxes,
#: bundles, receipts and inboxes in their 0.2-draft form, which spec prose cannot show, so they are proven only with
#: such a report.  G2 and G3 (Merkle proofs) rest on the spec; G10 rests on its own section 14.5 check of this card.
CONFORMANCE_MEDIA_TYPE = "application/vnd.aics.conformance-report+json"
CONFORMANCE_ROWS = ("G1", "G4", "G6", "G8", "G9")
#: The reports ``--fill-hashes`` reads to check that a proven row's conformance evidence shows that row passing
#: (:func:`conformance_report_problems`): ``aics-conformance run`` against an instance (``mode`` ``instance``; its
#: ``selftest`` runs the checks against the harness's own fake server, which is no evidence about a server) and
#: aics-interop's in-process run of the same checks against aics-server (``aics-interop-server-conformance``).
CONFORMANCE_FORMATS = ("aics-conformance/v1", "aics-interop-server-conformance/v1")
CONFORMANCE_SPEC = "AICS-1 0.2-draft"
#: aics-conformance reads its run policy (``run --policy``) from TOML; docs/evidence keeps it beside its report under
#: the same name (docs/evidence/README.md), and its ``quorum`` is the witness quorum the run required.
CONFORMANCE_POLICY_SUFFIX = ".policy.toml"
#: Rows whose meaning across agents depends on G5: each states its split-view exposure while G5 is not proven.
SPLIT_VIEW_ROWS = ("G1", "G6", "G9")
MEDIA_TYPE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*"
                        r"(?:; ?[a-z0-9-]+=[A-Za-z0-9._-]+)*")

#: A tagged assumption starts with "[tag] ".  Each tag may appear only in these assurances.
TAG = re.compile(r"\[([a-z0-9-]+)\] \S")
TAG_HOMES = {
    "boundary": G_IDS,
    "relies-on": G_IDS + N_IDS,
    "split-view": SPLIT_VIEW_ROWS,
    "permanent-leaves": ("G3",),
    "leaf-residual": ("G3",),
    "ciphertext-retention": ("G3",),
    "hidden-body-retention": ("G3",),
    "secret-scan-scope": ("G4",),
    "flood-rule": ("G4",),
    "keyless-limits": ("G4",),
    "refusal-citation": ("G4",),
    "witness-policy": ("G5",),
    "founder-witness": ("G5",),
    "witness-verification": ("G5",),
    "honest-intersection": ("G5",),
    "witness-deviation": ("G5",),
    "swarm-skipping": ("G6", "G9"),
    "mirror-copies": ("G8",),
    "sunset": ("G8",),
    "no-forward-secrecy": ("N1",),
    "plaintext-port": ("N1",),
    "no-address-records": ("N2",),
    "third-party-processing": ("N2",),
    "hosting-provider": ("N2",),
    "notice-data-retention": ("N2",),
    "contribution-correlation": ("N2",),
}
#: A ``[deviation-*]`` statement discloses where the deployed server departs from a rule this card or AICS-1 states,
#: and says so in these words.  tests/test_sources.py requires each one while the server checkout shows the gap, and
#: only then; a deviation the server has closed is deleted together with its tag (README, launch checklist).
DEVIATION_PREFIX = "deviation-"
DEVIATION_WORDS = "Known deviation from"
#: Words an optional statement must contain when it is present.  [refusal-citation] discloses that the service takes
#: the AICS-1 section 10.2 option of answering a repeated attempt by citing the earlier refusal leaf, which the
#: charter's Refusal section and the terms state since the relaunch of 2026-10-20.
OPTIONAL_STATEMENT_PHRASES = {
    "refusal-citation": ("AICS-1 section 10.2", "charter", "terms"),
}
#: The section 13.3 boundary each G row must state, as words its [boundary] statement contains.
BOUNDARY_PHRASES = {
    "G1": ("third-party-generated", "unverified"),
    "G2": ("saved",),
    "G3": ("bodies", "availability"),
    "G4": ("receipt", "silent", "promised"),
    "G5": ("split",),
    "G6": ("metadata", "forward secrecy"),
    "G7": ("runtime evidence",),
    "G8": ("availability",),
    "G9": ("complete", "delivery"),
    "G10": ("signature", "inclusion", "activation", "continuity"),
}
#: Section 13.3: operational claims, and the rows that must say they rely on them.
OPERATIONAL_CLAIMS = ("no IP logging", "exclusive local key custody", "witness independence", "running code",
                      "infrastructure availability")
RELIANCE = {
    "G1": ("exclusive local key custody",),
    "G4": ("infrastructure availability",),
    "G5": ("witness independence",),
    "G6": ("exclusive local key custody",),
    "G7": ("running code",),
    "G8": ("infrastructure availability",),
    "G9": ("infrastructure availability",),
    "N2": ("no IP logging",),
}

MARKETING = (
    "military-grade", "bank-grade", "unbreakable", "unhackable", "bulletproof", "world-class", "best-in-class",
    "cutting-edge", "state-of-the-art", "revolutionary", "seamless", "seamlessly", "effortless", "effortlessly",
    "blazing", "blazing-fast", "next-generation", "next-gen", "industry-leading", "game-changing", "trustless",
    "zero-trust", "fully secure", "completely secure", "perfectly secure", "100% secure",
)
MARKETING_RE = re.compile(r"(?<![A-Za-z0-9-])(" + "|".join(map(re.escape, MARKETING)) + r")(?![A-Za-z0-9-])",
                          re.IGNORECASE)
#: Words a promised claim must not use: they state what is only promised as if it were by construction.
OVERCLAIM_RE = re.compile(r"\b(cannot|can\s+not|can[\u2019']t|impossible|unable|prevents?|prevented|"
                          r"guarantee[sd]?)\b", re.IGNORECASE)
#: Words a proven or not-offered claim must not use: the operator can still do these things and the log makes them
#: detectable (docs/legal/card-policy.md keeps "cannot" for what is true by construction and says "cannot ...
#: without detection" for what a client catches).  A "cannot" passes only with "without" later in its sentence.
PREVENTION_RE = re.compile(r"\b(by\s+anyone|only\s+under)\b", re.IGNORECASE)
CANNOT_RE = re.compile(r"\b(cannot|can\s+not|can[\u2019']t)\b", re.IGNORECASE)
SENTENCE_END_RE = re.compile(r"[.;](?:\s|$)")
ZERO_KNOWLEDGE_RE = re.compile(r"zero[\s-]*knowledge", re.IGNORECASE)
HOST_RE = re.compile(r"(?<![A-Za-z0-9_.-])((?:[A-Za-z0-9_-]+\.)*wesupport-ai\.com)(?![A-Za-z0-9-])", re.IGNORECASE)
#: Unicode categories never allowed in card text (control, format, separators, surrogates, private, unassigned).
FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"})

# ---------------------------------------------------------------------------
# placeholders
# ---------------------------------------------------------------------------

FILL_RE = re.compile(r"<FILL:([A-Z][A-Z0-9_]*)(?::([A-Za-z0-9._/-]+))?>")


@dataclass(frozen=True)
class Slot:
    """Where a whole-value placeholder may stand: a JSON path, its name, the final type, its argument rule."""

    path: re.Pattern[str]
    name: str
    kind: str  # "uint" or "str"
    arg: str  # "none", "optional" or "required"


def _slot(path: str, name: str, kind: str, arg: str = "none") -> Slot:
    return Slot(re.compile(path), name, kind, arg)


WHOLE_SLOTS = (
    _slot(r"\$\.issued_at", "ISSUED_AT", "uint"),
    _slot(r"\$\.expires", "EXPIRES", "uint"),
    _slot(r"\$\.log_vkey", "LOG_VKEY", "str"),
    _slot(r"\$\.policy_kid", "POLICY_KID", "str"),
    _slot(r"\$\.owner_kid", "OWNER_KID", "str"),
    _slot(r"\$\.witness_policy\.witnesses\[\d+\]\.name", "WITNESS_NAME", "str", "optional"),
    _slot(r"\$\.witness_policy\.witnesses\[\d+\]\.vkey", "WITNESS_VKEY", "str", "optional"),
    _slot(r"\$\.retention\.ciphertext_budget_bytes", "CIPHERTEXT_BUDGET_BYTES", "uint"),
    _slot(r"\$\.retention\.swarm_delivery_seconds", "SWARM_DELIVERY_SECONDS", "uint"),
    _slot(r"\$\.secret_patterns\[\d+\]\.pattern_hash", "SECRET_PATTERN_HASH", "str", "required"),
    _slot(r"\$\.sup\.contributions\[\d+\]\.address", "SUP_ADDRESS", "str", "required"),
    _slot(r"\$\.policies\.(?:charter|terms|privacy)_hash", "SHA256", "str", "required"),
    _slot(r"\$\.assurances\[\d+\]\.evidence\[\d+\]\.hash", "SHA256", "str", "required"),
)
#: Placeholders that may appear inside free text, by path.
TEXT_SLOTS = ((re.compile(r"\$\.assurances\[\d+\]\.assumptions\[\d+\]"), ("CUSTODIAN_NAME", "CUSTODIAN_HOLDS")),)


def whole_slot(path: str) -> Slot | None:
    return next((s for s in WHOLE_SLOTS if s.path.fullmatch(path)), None)


def text_slot_names(path: str) -> tuple[str, ...]:
    for pattern, names in TEXT_SLOTS:
        if pattern.fullmatch(path):
            return names
    return ()


def is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and FILL_RE.fullmatch(value) is not None


# ---------------------------------------------------------------------------
# strict JSON, RFC 8785 JCS
# ---------------------------------------------------------------------------


class InputError(Exception):
    """The input cannot be read as a card at all (exit status 2)."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON member {key!r}")
        out[key] = value
    return out


def _no_float(text: str) -> Any:
    raise ValueError(f"number {text} is not an integer: the card has integer values only")


def _no_constant(text: str) -> Any:
    raise ValueError(f"{text} is not JSON")


def _check_depth(text: str) -> None:
    depth, in_string, escaped = 0, False, False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError(f"JSON nested deeper than {MAX_JSON_DEPTH} levels")
        elif ch in "]}":
            depth -= 1


def load_json(data: bytes) -> Any:
    """Parse ``data`` as strict UTF-8 JSON (no BOM, duplicate members, floats, NaN or Infinity)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(f"not UTF-8: {exc}") from None
    if text.startswith("\ufeff"):
        raise InputError("the file starts with a byte order mark")
    try:
        _check_depth(text)
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_float=_no_float,
                          parse_constant=_no_constant)
    except (ValueError, RecursionError) as exc:
        raise InputError(f"invalid JSON: {exc}") from None


_JCS_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _jcs_string(text: str) -> str:
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch in _JCS_ESCAPES:
            out.append(_JCS_ESCAPES[ch])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        elif 0xD800 <= code <= 0xDFFF:
            raise ValueError("a lone surrogate cannot be encoded as UTF-8")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > UINT_MAX:
            raise ValueError(f"integer {value} is outside the I-JSON range")
        return str(value)
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 section 3.2.3: members sorted by their UTF-16 code units.
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs(v) for k, v in items) + "}"
    raise ValueError(f"{type(value).__name__} is not used in the card")


def jcs(value: Any) -> bytes:
    """``J(value)``: RFC 8785 canonical JSON as UTF-8, for the integer-only JSON this card uses."""
    return _jcs(value).encode("utf-8")


def unsigned_payload(card: dict[str, Any]) -> bytes:
    """``J(card without signatures)``: the JWS payload of AICS-1 section 13.2."""
    return jcs({k: v for k, v in card.items() if k != "signatures"})


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    """Canonical unpadded base64url (AICS-1 ``U64``)."""
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text) or len(text) % 4 == 1:
        raise ValueError("not unpadded base64url")
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u(raw) != text:
        raise ValueError("not canonical base64url")
    return raw


# ---------------------------------------------------------------------------
# keys: did:key (AICS-1 section 3.1) and C2SP signed-note vkeys (section 6.2)
# ---------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        index = _B58.find(ch)
        if index < 0:
            raise ValueError(f"{ch!r} is not a base58btc character")
        n = n * 58 + index
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def parse_did_key(kid: str) -> bytes:
    """The 32-byte Ed25519 public key of a canonical ``did:key:z...`` (multicodec 0xed 0x01)."""
    prefix = "did:key:z"
    if not kid.startswith(prefix):
        raise ValueError("must be did:key:z followed by base58btc")
    raw = b58decode(kid[len(prefix):])
    if len(raw) != 34 or raw[:2] != b"\xed\x01":
        raise ValueError("must be an Ed25519 did:key (0xed 0x01 and 32 key bytes)")
    if b58encode(raw) != kid[len(prefix):]:
        raise ValueError("did:key is not canonical base58btc")
    return raw[2:]


def parse_vkey(vkey: str) -> tuple[str, int, bytes]:
    """``(name, type byte, 32-byte key)`` of a C2SP vkey ``name+keyid+B64(type || key)``, key ID checked."""
    parts = vkey.split("+", 2)  # the key name has no "+"; base64 key data may
    if len(parts) != 3:
        raise ValueError("a vkey is <name>+<8 hex key id>+<base64 of type byte and key>")
    name, key_id, b64 = parts
    if not name or not name.isprintable() or any(ch.isspace() for ch in name):
        raise ValueError("the key name must be printable without spaces")
    if not re.fullmatch(r"[0-9a-f]{8}", key_id):
        raise ValueError("the key id must be 8 lowercase hex characters")
    try:
        raw = base64.b64decode(b64, validate=True)
    except binascii.Error:
        raise ValueError("the key is not base64") from None
    if base64.b64encode(raw).decode("ascii") != b64:
        raise ValueError("the key base64 is not canonical")
    if len(raw) != 33:
        raise ValueError("the key must be one type byte and 32 key bytes")
    expected = hashlib.sha256(name.encode("utf-8") + b"\n" + raw).digest()[:4].hex()
    if key_id != expected:
        raise ValueError(f"key id {key_id} does not match the key (expected {expected})")
    return name, raw[0], raw[1:]


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    placeholders: list[dict[str, str]] = field(default_factory=list)

    def error(self, path: str, message: str) -> None:
        self.errors.append(f"{path}: {message}")

    def warn(self, path: str, message: str) -> None:
        self.warnings.append(f"{path}: {message}")

    @property
    def ok(self) -> bool:
        return not self.errors


def is_uint(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= UINT_MAX


def same(a: Any, b: Any) -> bool:
    """Equal JSON values of identical types (``true`` is not ``1``)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b, strict=True))
    return a == b


def iter_strings(value: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from iter_strings(item, f"{path}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from iter_strings(item, f"{path}[{i}]")


def hosts_in(text: str) -> set[str]:
    return {m.group(1).lower() for m in HOST_RE.finditer(text)}


def _assurance_index(card: dict[str, Any], aid: str) -> int | None:
    items = card.get("assurances")
    if not isinstance(items, list):
        return None
    return next((i for i, a in enumerate(items) if isinstance(a, dict) and a.get("id") == aid), None)


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------


def check_text(card: dict[str, Any], rep: Report, *, final: bool) -> None:
    """Every string: characters, placeholders, marketing words, zero-knowledge wording, hostnames."""
    n1 = _assurance_index(card, "N1")
    n1_path = f"$.assurances[{n1}]" if n1 is not None else None
    for path, text in iter_strings(card):
        bad = sorted({f"U+{ord(ch):04X}" for ch in text if unicodedata.category(ch) in FORBIDDEN_CATEGORIES})
        if bad:
            rep.error(path, f"contains control, format or unassigned characters ({', '.join(bad[:8])})")
        matches = list(FILL_RE.finditer(text))
        if matches:
            _check_placeholders(path, text, matches, rep, final=final)
        elif "<FILL" in text:
            rep.error(path, "malformed placeholder: use <FILL:NAME> or <FILL:NAME:arg>")
        for m in MARKETING_RE.finditer(text):
            rep.error(path, f"marketing wording {m.group(1)!r}: state the property plainly")
        if ZERO_KNOWLEDGE_RE.search(text) and not (n1_path and (path == n1_path or path.startswith(n1_path + "."))):
            rep.error(path, "zero knowledge may only be named as not offered (N1); the service offers "
                            "end-to-end encryption and says so (DESIGN section 11)")
        for host in sorted(hosts_in(text)):
            if host not in DECISION_10_HOSTS and host not in DNS_RECORD_NAMES and host not in WITNESS_HOSTS:
                rep.error(path, f"hostname {host} is not one of decision 10's hostnames "
                                f"({', '.join(DECISION_10_HOSTS)})")


def _check_placeholders(path: str, text: str, matches: list[re.Match[str]], rep: Report, *, final: bool) -> None:
    if final:
        for m in matches:
            rep.error(path, f"placeholder {m.group(0)} is not filled (--final)")
        return
    whole = FILL_RE.fullmatch(text)
    if whole:
        slot = whole_slot(path)
        name, arg = whole.group(1), whole.group(2)
        if slot is None or slot.name != name:
            rep.error(path, f"placeholder {text} is not allowed here"
                            + (f"; this slot takes <FILL:{slot.name}>" if slot else ""))
        elif slot.arg == "required" and not arg:
            rep.error(path, f"placeholder {text} needs an argument, <FILL:{name}:...>")
        elif slot.arg == "none" and arg:
            rep.error(path, f"placeholder {text} takes no argument")
        elif name == "SHA256" and (arg.startswith("/") or ".." in arg.split("/")):
            rep.error(path, f"placeholder {text} must name a repository-relative path")
        else:
            rep.placeholders.append({"path": path, "placeholder": text})
        return
    allowed = text_slot_names(path)
    for m in matches:
        if m.group(1) not in allowed or m.group(2):
            rep.error(path, f"placeholder {m.group(0)} is not allowed in this text")
        else:
            rep.placeholders.append({"path": path, "placeholder": m.group(0)})


class _Schema:
    """Typed member checks that skip whole-value placeholders (their slots are checked in check_text)."""

    def __init__(self, rep: Report) -> None:
        self.rep = rep

    def obj(self, value: Any, path: str, members: tuple[str, ...]) -> bool:
        if not isinstance(value, dict):
            self.rep.error(path, "must be an object")
            return False
        missing = [m for m in members if m not in value]
        extra = [m for m in value if m not in members]
        if missing:
            self.rep.error(path, f"missing members: {', '.join(missing)}")
        for m in extra:
            self.rep.error(f"{path}.{m}", "unknown member")
        return not missing

    def uint(self, value: Any, path: str, *, positive: bool = False, minimum: int | None = None,
             why: str = "") -> bool:
        if is_placeholder(value):
            return False
        if not is_uint(value):
            self.rep.error(path, "must be an integer from 0 to 2^53-1")
            return False
        if positive and value == 0:
            self.rep.error(path, "must be positive (AICS-1 section 13.1)")
            return False
        if minimum is not None and value < minimum:
            self.rep.error(path, f"must be at least {minimum}" + (f" ({why})" if why else ""))
            return False
        return True

    def fixed(self, value: Any, path: str, expected: Any, why: str) -> None:
        if not same(value, expected):
            self.rep.error(path, f"must be {json.dumps(expected)} ({why})")

    def string(self, value: Any, path: str) -> bool:
        if is_placeholder(value):
            return False
        if not isinstance(value, str) or not value:
            self.rep.error(path, "must be a non-empty string")
            return False
        return True

    def hash(self, value: Any, path: str) -> None:
        if not is_placeholder(value) and not (isinstance(value, str) and HEX64.fullmatch(value)):
            self.rep.error(path, "must be 64 lowercase hexadecimal characters (SHA-256)")

    def unique_strings(self, value: Any, path: str) -> list[str]:
        if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
            self.rep.error(path, "must be an array of non-empty strings")
            return []
        dupes = sorted({x for x in value if value.count(x) > 1})
        if dupes:
            self.rep.error(path, f"duplicate entries: {', '.join(dupes)}")
        return value


def check_schema(card: dict[str, Any], rep: Report, *, profile: str, signed: bool) -> None:
    """AICS-1 section 13.1 (with SWARMS R47 and section 20.9): members, types, fixed values and closed enums."""
    s = _Schema(rep)
    members = profile_members(profile) + (("signatures",) if signed else ())
    missing = [m for m in members if m not in card]
    if missing:
        rep.error("$", f"missing members: {', '.join(missing)}")
    for m in card:
        if m in members:
            continue
        if m == "signatures":
            rep.error("$.signatures", "the unsigned body has no signatures; the server adds them when it signs "
                                      "with the policy key (AICS-1 section 13.2); pass --signed to check a signed card")
        elif m == "swarms":
            rep.error("$.swarms", f"only the swarms profiles ({SPEC_SWARMS}, {SPEC_SWARMS_SUP}) have a swarms member "
                                  "(SWARMS R47)")
        elif m == "sup":
            rep.error("$.sup", f"only the contributions and owner-service profiles ({SPEC_SUP}, {SPEC_SWARMS_SUP}) "
                               "have a sup member (AICS-1 section 20.9)")
        else:
            rep.error(f"$.{m}", "unknown member (AICS-1 section 13.1 lists the exact members)")

    if card.get("spec") not in PROFILES:
        rep.error("$.spec", f"must be one of {', '.join(PROFILES)} (AICS-1 sections 13.1, 19 and 20.9)")
    s.fixed(card.get("version"), "$.version", CARD_VERSION, "AICS-1 0.2-draft")
    s.fixed(card.get("origin"), "$.origin", ORIGIN, "AICS-1 section 12.2; the server's DEFAULT_ORIGIN")

    issued = card.get("issued_at")
    expires = card.get("expires")
    notice = card.get("policy_notice_seconds")
    times_ok = s.uint(issued, "$.issued_at") & s.uint(expires, "$.expires")
    if times_ok:
        if not issued < expires:
            rep.error("$.expires", "issued_at must be before expires (AICS-1 section 13.1)")
        elif is_uint(notice) and expires - issued <= notice:
            rep.error("$.expires", "the card must outlive policy_notice_seconds, or no successor card can be "
                                   "announced with full notice before it expires")
    parent = card.get("policy_parent_index")
    if parent is not None:
        s.uint(parent, "$.policy_parent_index")

    service_keys: dict[bytes, str] = {}
    log_vkey = card.get("log_vkey")
    if s.string(log_vkey, "$.log_vkey"):
        try:
            name, key_type, key = parse_vkey(log_vkey)
        except ValueError as exc:
            rep.error("$.log_vkey", str(exc))
        else:
            if name != ORIGIN:
                rep.error("$.log_vkey", f"the log key name must be the origin {ORIGIN} (AICS-1 section 6.2)")
            if key_type != 0x01:
                rep.error("$.log_vkey", "the log key must be an Ed25519 note key, type 0x01 (AICS-1 section 6.2)")
            service_keys[key] = "log_vkey"
    for member in ("policy_kid", "owner_kid"):
        value = card.get(member)
        if s.string(value, f"$.{member}"):
            try:
                key = parse_did_key(value)
            except ValueError as exc:
                rep.error(f"$.{member}", str(exc))
            else:
                if key in service_keys:
                    rep.error(f"$.{member}", f"reuses the key of {service_keys[key]}; log, policy and owner keys "
                                             "must be distinct (AICS-1 section 3.1)")
                service_keys.setdefault(key, member)

    for member in ("log_vkey", "policy_kid"):
        if card.get(member) == DISCARDED_LOG[member]:
            rep.error(f"$.{member}", f"is the {member} of the discarded first log of this origin (genesis 1, "
                                     "2026-10-19): fill the card from the running server's /data/pubkeys.txt")
    wp = card.get("witness_policy")
    listed = wp.get("witnesses") if isinstance(wp, dict) else None
    for i, w in enumerate(listed if isinstance(listed, list) else []):
        for member in ("name", "vkey"):
            value = w.get(member) if isinstance(w, dict) else None
            # A name is a host and a path (the host part is case-insensitive); a vkey is compared byte for byte.
            if isinstance(value, str) and (value.lower() == RETIRED_WITNESS["name"].lower() if member == "name"
                                           else value == RETIRED_WITNESS["vkey"]):
                rep.error(f"$.witness_policy.witnesses[{i}].{member}",
                          f"is the retired witness {RETIRED_WITNESS['name']}, which cosigned the discarded first log "
                          "of this origin: list the new witness identity pinned to this log (card/README.md "
                          "\"Genesis v2\", step 2)")

    prefixes = card.get("tile_prefixes")
    if not isinstance(prefixes, list) or not prefixes:
        rep.error("$.tile_prefixes", "must list at least one tile prefix (AICS-1 section 13.1)")
    else:
        s.unique_strings(prefixes, "$.tile_prefixes")
    s.string(card.get("api_base"), "$.api_base")
    gate = card.get("gate")
    if s.obj(gate, "$.gate", tuple(GATE)):
        for key, expected in GATE.items():
            s.fixed(gate[key], f"$.gate.{key}", expected, "AICS-1 sections 11.1 and 12.2")
    proxy = card.get("proxy")
    if not isinstance(proxy, list):
        rep.error("$.proxy", "must be an array")
    else:
        for i, entry in enumerate(proxy):
            path = f"$.proxy[{i}]"
            if s.obj(entry, path, ("host", "mode", "tls_termination")):
                s.string(entry["host"], f"{path}.host")
                if entry["mode"] not in ("cloudflare", "dns-only"):
                    rep.error(f"{path}.mode", "must be 'cloudflare' or 'dns-only'")
                s.string(entry["tls_termination"], f"{path}.tls_termination")

    _check_witness_policy(card, rep, s, service_keys)
    if s.uint(card.get("max_checkpoint_age"), "$.max_checkpoint_age", minimum=MIN_CHECKPOINT_AGE,
              why="AICS-1 section 13.1") and card["max_checkpoint_age"] != RECOMMENDED_CHECKPOINT_AGE:
        rep.warn("$.max_checkpoint_age", f"AICS-1 section 13.1 recommends {RECOMMENDED_CHECKPOINT_AGE}")
    s.fixed(card.get("mmd_seconds"), "$.mmd_seconds", MMD_SECONDS, "AICS-1 section 10.1")
    s.uint(notice, "$.policy_notice_seconds", minimum=POLICY_NOTICE_MINIMUM,
           why="30 days: decision 16 and the charter")

    limits = card.get("limits")
    if s.obj(limits, "$.limits", LIMIT_MEMBERS):
        for key, expected in FIXED_LIMITS.items():
            s.fixed(limits[key], f"$.limits.{key}", expected, "AICS-1 sections 4.3, 11.1 and 13.1")
        for key in WINDOW_LIMITS:
            window = limits[key]
            if s.obj(window, f"$.limits.{key}", ("count", "interval_seconds")):
                s.uint(window["count"], f"$.limits.{key}.count", positive=True)
                s.uint(window["interval_seconds"], f"$.limits.{key}.interval_seconds", positive=True)
        s.uint(limits["flood_suspension_seconds"], "$.limits.flood_suspension_seconds", positive=True)
        writes = limits["writes"]
        if swarms_active(profile) and isinstance(writes, dict) and is_uint(writes.get("count")) \
                and is_uint(writes.get("interval_seconds")) and writes["interval_seconds"] > 0:
            daily = writes["count"] * (86400 // writes["interval_seconds"])
            if writes["interval_seconds"] > SWARMS_MAX_WRITE_WINDOW or daily < SWARMS_MIN_DAILY_WRITES:
                rep.error("$.limits.writes", f"the swarms profile needs a write window of at most "
                                             f"{SWARMS_MAX_WRITE_WINDOW} s allowing at least "
                                             f"{SWARMS_MIN_DAILY_WRITES} writes per 24 hours (SWARMS R36)")

    retention_members = RETENTION_MEMBERS + (("swarm_delivery_seconds",) if swarms_active(profile) else ())
    retention = card.get("retention")
    if s.obj(retention, "$.retention", retention_members):
        for key in ("dm_seconds", "capsule_max_seconds") + retention_members[len(RETENTION_MEMBERS):]:
            s.uint(retention[key], f"$.retention.{key}", minimum=CIPHERTEXT_MINIMUM_SECONDS,
                   why="90 days: AICS-1 sections 8.2 and 13.1, docs/legal/retention.md")
        if is_uint(retention["dm_seconds"]) and retention["dm_seconds"] != DM_SECONDS_UNSCHEDULED:
            rep.error("$.retention.dm_seconds", f"must be {DM_SECONDS_UNSCHEDULED}, no scheduled direct-message "
                                                "expiry: charter commitment 2 and docs/legal/retention.md let "
                                                "ciphertext expire only when disk runs short; a scheduled expiry "
                                                "needs an owner decision that amends both before leaf 0 "
                                                "(decisions 4 and 16)")
        s.uint(retention["ciphertext_budget_bytes"], "$.retention.ciphertext_budget_bytes", positive=True)
        s.fixed(retention["eviction"], "$.retention.eviction", EVICTION, "AICS-1 sections 8.2 and 13.1")

    schemes = s.unique_strings(card.get("schemes"), "$.schemes")
    for scheme in schemes:
        if scheme not in ENCRYPTION_SCHEMES:
            rep.error("$.schemes", f"unknown encryption scheme {scheme!r} (AICS-1 section 17.1)")
    if MANDATORY_SCHEME not in schemes:
        rep.error("$.schemes", f"must include the mandatory scheme {MANDATORY_SCHEME}")
    tiers = s.unique_strings(card.get("tiers"), "$.tiers")
    if sorted(tiers) != sorted(TIERS):
        rep.error("$.tiers", f"must be exactly {', '.join(TIERS)} (AICS-1 sections 3.3 and 13.1)")

    codes = card.get("reason_codes")
    if s.obj(codes, "$.reason_codes", tuple(REGISTRIES)):
        for key in REGISTRIES:
            s.unique_strings(codes[key], f"$.reason_codes.{key}")

    patterns = card.get("secret_patterns")
    if not isinstance(patterns, list):
        rep.error("$.secret_patterns", "must be an array")
    else:
        ids: list[str] = []
        for i, entry in enumerate(patterns):
            path = f"$.secret_patterns[{i}]"
            if not s.obj(entry, path, ("id", "pattern_hash")):
                continue
            pid = entry["id"]
            if not isinstance(pid, str) or not PATTERN_ID.fullmatch(pid):
                rep.error(f"{path}.id", "must match [a-z0-9_]{1,32} (AICS-1 section 13.1)")
                continue
            if pid in FORBIDDEN_PATTERN_IDS:
                rep.error(f"{path}.id", f"{pid} {FORBIDDEN_PATTERN_IDS[pid]}, which AICS-1 section 10.2 forbids "
                                        "as a secret format")
            ids.append(pid)
            s.hash(entry["pattern_hash"], f"{path}.pattern_hash")
            ph = FILL_RE.fullmatch(entry["pattern_hash"]) if isinstance(entry["pattern_hash"], str) else None
            if ph and ph.group(1) == "SECRET_PATTERN_HASH" and ph.group(2) != pid:
                rep.error(f"{path}.pattern_hash", f"placeholder must be <FILL:SECRET_PATTERN_HASH:{pid}>")
        dupes = sorted({x for x in ids if ids.count(x) > 1})
        if dupes:
            rep.error("$.secret_patterns", f"duplicate ids: {', '.join(dupes)}")

    policies = card.get("policies")
    if s.obj(policies, "$.policies", ("charter_hash", "terms_hash", "privacy_hash")):
        for key in policies:
            s.hash(policies[key], f"$.policies.{key}")

    _check_assurance_shapes(card, rep, s)
    expected_versions = dict(SPEC_VERSIONS, **({"swarms": SWARMS_SPEC_VERSION} if swarms_active(profile) else {}))
    s.fixed(card.get("spec_versions"), "$.spec_versions", expected_versions,
            "AICS-1 sections 13.1 and 20.9, SWARMS R47")
    if swarms_active(profile):
        s.fixed(card.get("swarms"), "$.swarms", SWARMS_MEMBER, "SWARMS R47")
    if sup_active(profile):
        _check_sup(card, rep, s)
    if signed:
        _check_signatures(card, rep)


def _check_sup(card: dict[str, Any], rep: Report, s: _Schema) -> None:
    """Section 20.9's ``sup`` member, and the networks this instance credits (``SUP_NETWORKS``)."""
    sup = card.get("sup")
    if not s.obj(sup, "$.sup", SUP_MEMBERS):
        return
    asset_hash = hashlib.sha256(jcs(sup_asset_descriptor(ORIGIN))).hexdigest()
    s.fixed(sup["asset_hash"], "$.sup.asset_hash", asset_hash,
            "AICS-1 section 20.2: hexH of the asset descriptor of this origin")
    contributions = sup["contributions"]
    if not isinstance(contributions, list):
        rep.error("$.sup.contributions", "must be an array (empty when no network is credited)")
    else:
        networks: list[str] = []
        for i, entry in enumerate(contributions):
            path = f"$.sup.contributions[{i}]"
            if not s.obj(entry, path, SUP_CONTRIBUTION_MEMBERS):
                continue
            network = entry["network"]
            if not isinstance(network, str) or not SUP_NETWORK_RE.fullmatch(network):
                rep.error(f"{path}.network", "must match [a-z0-9-]{1,32} (AICS-1 section 20.9)")
                continue
            networks.append(network)
            asset_ok = s.string(entry["asset"], f"{path}.asset")
            decimals_ok = s.uint(entry["decimals"], f"{path}.decimals")
            units_ok = s.uint(entry["units_per_sup"], f"{path}.units_per_sup", minimum=2, why="AICS-1 section 20.9")
            address = entry["address"]
            ph = FILL_RE.fullmatch(address) if isinstance(address, str) else None
            if ph and ph.group(1) == "SUP_ADDRESS" and ph.group(2) != network:
                rep.error(f"{path}.address", f"placeholder must be <FILL:SUP_ADDRESS:{network}>")
            address_ok = s.string(address, f"{path}.address")
            known = SUP_NETWORKS.get(network)
            if known is None:
                rep.error(f"{path}.network", f"aics-server credits contributions only from "
                                             f"{', '.join(SUP_NETWORKS)} (payments.NETWORKS); a card lists exactly "
                                             "the networks the server credits")
                continue
            if asset_ok and entry["asset"] != known["asset"]:
                rep.error(f"{path}.asset", f"must be {known['asset']!r} on {network}")
            if decimals_ok and entry["decimals"] != known["decimals"]:
                rep.error(f"{path}.decimals", f"must be {known['decimals']} on {network}")
            if address_ok and not _canonical_address(network, address):
                rep.error(f"{path}.address", f"must be the canonical {network} address the server shows in an "
                                             f"intent ({known['address_rule']})")
            if units_ok and decimals_ok:
                unit = 10 ** entry["decimals"]
                if unit % entry["units_per_sup"] or entry["units_per_sup"] * SUP_MAX_PER_UNIT < unit:
                    least = unit // SUP_MAX_PER_UNIT
                    rep.error(f"{path}.units_per_sup", f"must divide {unit} and be at least {least}: aics-server "
                                                       f"credits a whole number of SUP per whole {entry['asset']}, at "
                                                       f"most {SUP_MAX_PER_UNIT}, so a credit never repeats the exact "
                                                       "transfer (payments.MAX_SUP_PER_USDC)")
        dupes = sorted({n for n in networks if networks.count(n) > 1})
        if dupes:
            rep.error("$.sup.contributions", f"lists each credited network once (AICS-1 section 20.9): "
                                             f"{', '.join(dupes)} repeated")
    intent_ok = s.uint(sup["intent_seconds"], "$.sup.intent_seconds", positive=True)
    claim_ok = s.uint(sup["claim_seconds"], "$.sup.claim_seconds", positive=True)
    if intent_ok and claim_ok and sup["intent_seconds"] > sup["claim_seconds"]:
        rep.error("$.sup.claim_seconds", "0 < intent_seconds <= claim_seconds (AICS-1 section 20.9)")
    if s.uint(sup["record_seconds"], "$.sup.record_seconds") and sup["record_seconds"] > SUP_RECORD_SECONDS_MAX:
        rep.error("$.sup.record_seconds", f"must be at most {SUP_RECORD_SECONDS_MAX}, decision 17's 12 months "
                                          "(AICS-1 section 20.9)")
    storage = sup["storage"]
    if storage is not None and s.obj(storage, "$.sup.storage", SUP_STORAGE_MEMBERS):
        s.uint(storage["free_quota_bytes"], "$.sup.storage.free_quota_bytes", minimum=SUP_FREE_QUOTA_MINIMUM,
               why="one maximal ciphertext body is always free, AICS-1 section 20.9")
        unit_bytes, unit_amount = storage["unit_bytes"], storage["unit_amount"]
        if (unit_bytes is None) != (unit_amount is None):
            rep.error("$.sup.storage", "unit_bytes and unit_amount are both null (no storage offered) or both "
                                       "positive (AICS-1 section 20.9)")
        elif unit_bytes is not None:
            s.uint(unit_bytes, "$.sup.storage.unit_bytes", positive=True)
            s.uint(unit_amount, "$.sup.storage.unit_amount", positive=True)


def _canonical_address(network: str, address: str) -> bool:
    """Whether ``address`` has the canonical form aics-server gives a ``network`` address (normalize_address)."""
    if is_placeholder(address):
        return True
    known = SUP_NETWORKS[network]
    if known["address"] is not None:
        return bool(known["address"].fullmatch(address))
    try:
        raw = b58decode(address)
    except ValueError:
        return False
    return len(raw) == 32 and b58encode(raw) == address


def _check_witness_policy(card: dict[str, Any], rep: Report, s: _Schema, service_keys: dict[bytes, str]) -> None:
    wp = card.get("witness_policy")
    if not s.obj(wp, "$.witness_policy", ("quorum", "witnesses")):
        return
    quorum_ok = s.uint(wp["quorum"], "$.witness_policy.quorum")
    witnesses = wp["witnesses"]
    if not isinstance(witnesses, list):
        rep.error("$.witness_policy.witnesses", "must be an array")
        return
    names: set[str] = set()
    keys: set[bytes] = set()
    for i, w in enumerate(witnesses):
        path = f"$.witness_policy.witnesses[{i}]"
        if not s.obj(w, path, ("name", "vkey", "trust_domain", "independent")):
            continue
        name_ok = s.string(w["name"], f"{path}.name")
        s.string(w["trust_domain"], f"{path}.trust_domain")
        if not isinstance(w["independent"], bool):
            rep.error(f"{path}.independent", "must be true or false")
        elif w["trust_domain"] == "founder" and w["independent"]:
            rep.error(f"{path}.independent", "a founder-run witness is in the log's trust domain, never "
                                             "independent (AICS-1 section 6.3)")
        if isinstance(w["name"], str):
            if w["name"] in names:
                rep.error(f"{path}.name", "witness names must be unique (AICS-1 section 6.3)")
            names.add(w["name"])
        if s.string(w["vkey"], f"{path}.vkey"):
            try:
                vname, key_type, key = parse_vkey(w["vkey"])
            except ValueError as exc:
                rep.error(f"{path}.vkey", str(exc))
                continue
            if key_type != 0x04:
                rep.error(f"{path}.vkey", "a witness key must be an Ed25519 cosignature key, type 0x04 "
                                          "(AICS-1 section 6.2)")
            if name_ok and vname != w["name"]:
                rep.error(f"{path}.vkey", "the key name differs from the witness name")
            if key in keys:
                rep.error(f"{path}.vkey", "witness public keys must be unique (AICS-1 section 6.3)")
            if key in service_keys:
                rep.error(f"{path}.vkey", f"reuses the key of {service_keys[key]}; a service key is not a witness")
            keys.add(key)
    if quorum_ok and wp["quorum"] > len(witnesses):
        rep.error("$.witness_policy.quorum", "exceeds the number of witnesses (AICS-1 section 6.3)")


def _check_assurance_shapes(card: dict[str, Any], rep: Report, s: _Schema) -> None:
    items = card.get("assurances")
    if not isinstance(items, list):
        rep.error("$.assurances", "must be an array")
        return
    seen: list[str] = []
    for i, a in enumerate(items):
        path = f"$.assurances[{i}]"
        if not s.obj(a, path, ("id", "status", "claim", "assumptions", "evidence")):
            continue
        if a["id"] not in CLAIM_TITLES:
            rep.error(f"{path}.id", "must be one of G1-G10, N1-N5 (AICS-1 section 13.3)")
        else:
            seen.append(a["id"])
        if a["status"] not in STATUSES:
            rep.error(f"{path}.status", "must be proven, promised or not-offered")
        s.string(a["claim"], f"{path}.claim")
        if not isinstance(a["assumptions"], list) or not all(isinstance(x, str) and x for x in a["assumptions"]):
            rep.error(f"{path}.assumptions", "must be an array of non-empty strings")
        if not isinstance(a["evidence"], list):
            rep.error(f"{path}.evidence", "must be an array")
            continue
        for j, e in enumerate(a["evidence"]):
            epath = f"{path}.evidence[{j}]"
            if s.obj(e, epath, ("hash", "media_type")):
                s.hash(e["hash"], f"{epath}.hash")
                if not isinstance(e["media_type"], str) or not MEDIA_TYPE.fullmatch(e["media_type"]):
                    rep.error(f"{epath}.media_type", "must be a media type such as text/markdown")
    wrong = [x for x in CLAIM_TITLES if seen.count(x) != 1]
    if wrong:
        rep.error("$.assurances", f"needs exactly one assurance for each of G1-G10 and N1-N5 "
                                  f"(missing or repeated: {', '.join(wrong)})")


def _check_signatures(card: dict[str, Any], rep: Report) -> None:
    """Shape of a signed card's signatures (AICS-1 section 13.2); the signature itself is not verified here."""
    sigs = card.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        rep.error("$.signatures", "a signed card has at least one signature")
        return
    policy_kid = card.get("policy_kid")
    for i, sig in enumerate(sigs):
        path = f"$.signatures[{i}]"
        if not isinstance(sig, dict) or set(sig) != {"protected", "signature"} \
                or not all(isinstance(v, str) for v in sig.values()):
            rep.error(path, "must be exactly {protected, signature}: no unprotected header (AICS-1 section 13.2)")
            continue
        try:
            header = b64u_decode(sig["protected"])
        except ValueError as exc:
            rep.error(f"{path}.protected", str(exc))
        else:
            if header != jcs({"alg": "EdDSA", "kid": policy_kid, "typ": "JOSE"}):
                rep.error(f"{path}.protected", 'must be U64(J({"alg":"EdDSA","kid":policy_kid,"typ":"JOSE"}))')
        try:
            if len(b64u_decode(sig["signature"])) != 64:
                rep.error(f"{path}.signature", "must be a 64-byte Ed25519 signature")
        except ValueError as exc:
            rep.error(f"{path}.signature", str(exc))


def check_hostnames(card: dict[str, Any], rep: Report) -> None:
    """Decision 10 hostnames and modes; AICS-1 section 12.2 prefixes."""
    prefixes = card.get("tile_prefixes")
    if isinstance(prefixes, list):
        for i, url in enumerate(prefixes):
            if isinstance(url, str):
                _check_url(url, f"$.tile_prefixes[{i}]", rep, hosts=TILE_HOSTS, path=TILE_PATH)
        canonical = f"https://{ORIGIN}"
        if canonical not in prefixes:
            rep.error("$.tile_prefixes", f"must include the origin's canonical prefix {canonical} "
                                         "(AICS-1 section 12.2)")
    api = card.get("api_base")
    if isinstance(api, str):
        _check_url(api, "$.api_base", rep, hosts=("api.wesupport-ai.com",), path="")
    proxy = card.get("proxy")
    if not isinstance(proxy, list):
        return
    listed: list[str] = []
    for i, entry in enumerate(proxy):
        if not isinstance(entry, dict) or not isinstance(entry.get("host"), str):
            continue
        host, mode, tls = entry["host"], entry.get("mode"), entry.get("tls_termination")
        listed.append(host)
        path = f"$.proxy[{i}]"
        if host not in DECISION_10_HOSTS:
            rep.error(f"{path}.host", f"{host} is not one of decision 10's hostnames")
            continue
        if mode != DECISION_10_HOSTS[host]:
            rep.error(f"{path}.mode", f"decision 10 makes {host} {DECISION_10_HOSTS[host]}")
        if isinstance(tls, str):
            if mode == "cloudflare" and not (tls.startswith("cloudflare-edge") and "Full (strict)" in tls):
                rep.error(f"{path}.tls_termination", "a proxied host terminates TLS at the Cloudflare edge with "
                                                     "Full (strict) to the origin: start with 'cloudflare-edge' "
                                                     "and name 'Full (strict)'")
            if mode == "dns-only" and not tls.startswith("origin"):
                rep.error(f"{path}.tls_termination", "a DNS-only host terminates TLS at the origin: start "
                                                     "with 'origin'")
    for host in DECISION_10_HOSTS:
        if listed.count(host) != 1:
            rep.error("$.proxy", f"must list {host} exactly once: the card discloses the whole proxy split "
                                 "(AICS-1 section 12.2, decision 10)")


def _check_url(url: str, where: str, rep: Report, *, hosts: tuple[str, ...], path: str) -> None:
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError as exc:
        rep.error(where, f"is not a URL: {exc}")
        return
    if parts.scheme != "https":
        rep.error(where, "must be an https URL")
        return
    if parts.username or parts.password or port is not None or parts.query or parts.fragment or "#" in url:
        rep.error(where, "must have no user information, port, query or fragment")
    if parts.hostname not in hosts or parts.netloc != parts.hostname:
        rep.error(where, f"host must be {' or '.join(hosts)} (decision 10, AICS-1 section 12.2)")
    if parts.path != path:
        rep.error(where, f"path must be {path!r}" if path else "must have no path")


def check_reason_codes(card: dict[str, Any], rep: Report, profile: str) -> None:
    """Section 17.2 registries for the profile, plus active secret_format:<id>; supersets of the charter's."""
    codes = card.get("reason_codes")
    if not isinstance(codes, dict):
        return
    patterns = card.get("secret_patterns")
    pattern_ids = [p["id"] for p in patterns if isinstance(p, dict) and isinstance(p.get("id"), str)] \
        if isinstance(patterns, list) else []
    for registry, base in REGISTRIES.items():
        values = codes.get(registry)
        if not isinstance(values, list):
            continue
        expected = set(base)
        if registry == "refusal":
            expected |= set(REFUSAL_SWARMS) if swarms_active(profile) else set()
            expected |= set(REFUSAL_SUP) if sup_active(profile) else set()
        path = f"$.reason_codes.{registry}"
        family: list[str] = []
        for code in values:
            if not isinstance(code, str) or code in expected:
                continue
            m = SECRET_FORMAT_CODE.fullmatch(code)
            if registry == "refusal" and m:
                family.append(m.group(1))
                continue
            hint = ""
            if code in REFUSAL_SWARMS:
                hint = "; it is registered only for the swarms profile, AICS-1+SWARMS-1 (AICS-1 section 19)"
            elif code in REFUSAL_SUP:
                hint = ("; it is registered only for the contributions and owner-service profile, AICS-1+SUP-1 "
                        "(AICS-1 section 20.8)")
            elif registry in ("suspension", "tombstone"):
                hint = f"; {registry} reasons are only {', '.join(base)} (AICS-1 sections 10.3 and 17.2)"
            rep.error(path, f"unknown code {code!r}: the registry is closed (AICS-1 section 17.2){hint}")
        missing = sorted(expected - {c for c in values if isinstance(c, str)})
        if missing:
            rep.error(path, f"missing registered codes: {', '.join(missing)} (the card's lists equal the "
                            "AICS-1 section 17.2 registries)")
        if registry in CHARTER_LISTS:
            charter = CHARTER_LISTS[registry] + (CHARTER_SUP_REFUSALS if registry == "refusal" and sup_active(profile)
                                                 else ())
            short = [c for c in charter if c not in values]
            if short:
                rep.error(path, f"not a superset of the charter's closed {registry} list: missing "
                                f"{', '.join(short)} (docs/legal/charter.md, AICS-1 section 17.2)")
        if registry == "refusal":
            for pid in sorted(set(family) - set(pattern_ids)):
                rep.error(path, f"secret_format:{pid} names no pattern in secret_patterns")
            for pid in sorted(set(pattern_ids) - set(family)):
                rep.error(path, f"secret_patterns lists {pid} but the refusal list lacks secret_format:{pid}")


def pattern_definition_hash(definition: dict[str, Any]) -> str:
    """``pattern_hash`` of a secret-pattern definition: hexH(J(definition))."""
    return hashlib.sha256(jcs(definition)).hexdigest()


def pattern_definitions(document: Any) -> list[Any] | None:
    """The definitions of a pattern-definition document ``{"v": 1, "patterns": [...]}``, or None if it has not that
    shape."""
    if not isinstance(document, dict) or set(document) != set(PATTERN_DOCUMENT_MEMBERS):
        return None
    version, definitions = document["v"], document["patterns"]
    if type(version) is not int or version != PATTERN_DOCUMENT_VERSION or not isinstance(definitions, list):
        return None
    return definitions


def definitions_by_id(document: Any) -> dict[str, dict[str, Any]]:
    """The well-formed definitions of a pattern-definition document by id (the first of a repeated id)."""
    out: dict[str, dict[str, Any]] = {}
    definitions = pattern_definitions(document)
    if definitions is None:
        return out
    for d in definitions:
        if isinstance(d, dict) and set(d) == set(PATTERN_DEFINITION_MEMBERS) and isinstance(d["id"], str) \
                and d["id"] not in out:
            try:
                jcs(d)
            except ValueError:
                continue
            out[d["id"]] = d
    return out


def check_patterns(card: dict[str, Any], document: Any, rep: Report, *, final: bool) -> bool:
    """Section 13.1: every secret pattern names a retrievable, hash-checked definition; section 10.2 bounds them.

    Returns whether the pattern hashes were checked: a definition document was given, or the card lists none.
    """
    patterns = card.get("secret_patterns")
    entries = [(i, p) for i, p in enumerate(patterns) if isinstance(p, dict) and isinstance(p.get("id"), str)] \
        if isinstance(patterns, list) else []
    if document is None:
        if final and entries:
            rep.error("$.secret_patterns", "--final needs the pattern-definition document (--patterns FILE): every "
                                           "pattern_hash must be hexH(J(definition)) of a published definition "
                                           "(AICS-1 section 13.1)")
        return not entries
    where = "--patterns"
    definitions = pattern_definitions(document)
    if definitions is None:
        rep.error(where, f"the pattern-definition document must be {PATTERN_DOCUMENT_SHAPE}")
        return True
    if not definitions:
        rep.error(f"{where}.patterns", "must define at least one pattern")
    seen: set[str] = set()
    for i, d in enumerate(definitions):
        path = f"{where}.patterns[{i}]"
        if not isinstance(d, dict) or set(d) != set(PATTERN_DEFINITION_MEMBERS):
            rep.error(path, "a definition has exactly the members id, regex and note")
            continue
        pid, regex, note = d["id"], d["regex"], d["note"]
        if not isinstance(pid, str) or not PATTERN_ID.fullmatch(pid):
            rep.error(f"{path}.id", "must match [a-z0-9_]{1,32} (AICS-1 section 13.1)")
            continue
        if pid in seen:
            rep.error(f"{path}.id", f"{pid} is defined twice")
            continue
        seen.add(pid)
        if pid in FORBIDDEN_PATTERN_IDS:
            rep.error(f"{path}.id", f"{pid} {FORBIDDEN_PATTERN_IDS[pid]}, which AICS-1 section 10.2 forbids as a "
                                    "secret format")
        if not isinstance(note, str) or not note.strip() or "\n" in note or "\r" in note:
            rep.error(f"{path}.note", "must be one non-empty line")
            continue
        if not isinstance(regex, str) or not regex:
            rep.error(f"{path}.regex", "must be a non-empty string")
            continue
        try:
            jcs(d)
            compiled = re.compile(regex)
        except (re.error, ValueError) as exc:
            rep.error(f"{path}.regex", f"is not a Python re pattern that JCS can encode: {exc}")
            continue
        if compiled.flags & ~re.UNICODE:
            rep.error(f"{path}.regex", "must not set inline flags: the server compiles it as written")
            continue
        for what, sample in FORBIDDEN_PATTERN_SAMPLES.items():
            if compiled.search(sample):
                rep.error(f"{path}.regex", f"{pid} matches {what}; a secret format is a high-precision credential "
                                           "format (AICS-1 section 10.2)")
    known = definitions_by_id(document)
    for i, entry in entries:
        pid = entry["id"]
        if pid not in known:
            rep.error(f"$.secret_patterns[{i}]", f"{pid} has no definition in the pattern-definition document")
            continue
        expected = pattern_definition_hash(known[pid])
        value = entry.get("pattern_hash")
        if isinstance(value, str) and not is_placeholder(value) and value != expected:
            rep.error(f"$.secret_patterns[{i}].pattern_hash", f"is not hexH(J(definition)) of {pid} in the "
                                                              f"pattern-definition document ({expected})")
    for pid in sorted(set(known) - {p["id"] for _, p in entries}):
        rep.error(where, f"defines {pid}, which secret_patterns does not list: the card and the document list the "
                         "same patterns")
    card_order = [p["id"] for _, p in entries]
    if set(card_order) == set(known) and card_order != list(known):
        rep.error("$.secret_patterns", "lists the patterns in the document's scan order (the server refuses a "
                                       f"match with the first pattern it hits): {', '.join(known)}")
    return True


def g5_bound(wp: Any) -> str | None:
    """Why the witness policy cannot carry a proven G5 (AICS-1 sections 6.3 and 13.3), or None.

    Any two accepted quorums of ``q`` out of ``n`` witnesses share at least ``2q - n`` witnesses; unless that
    exceeds the number of witnesses that are not independent (founder-run ones included), two conflicting
    quorums can meet only in witnesses of the log's own trust domain.  This is a necessary condition only:
    independence and honesty remain claims the card's evidence and [honest-intersection] statement carry.
    """
    if not isinstance(wp, dict) or not is_uint(wp.get("quorum")) or not isinstance(wp.get("witnesses"), list):
        return "the witness policy is malformed"
    quorum, witnesses = wp["quorum"], [w for w in wp["witnesses"] if isinstance(w, dict)]
    if quorum == 0:
        return ("G5 cannot be proven with witness quorum 0: checkpoints are then accepted on the log "
                "signature alone, so G5 stays promised (AICS-1 sections 6.3 and 13.3)")
    dependent = sum(1 for w in witnesses if w.get("independent") is not True or w.get("trust_domain") == "founder")
    if dependent == len(witnesses):
        return "G5 needs at least one independent witness outside the log's trust domain (AICS-1 section 6.3)"
    if 2 * quorum - len(witnesses) <= dependent:
        return (f"two accepted quorums of {quorum} out of {len(witnesses)} witnesses can intersect only in the "
                f"{dependent} witness(es) that are not independent, so they need not intersect in an honest one "
                "(AICS-1 section 6.3)")
    return None


def prevention_wording(claim: str) -> list[str]:
    """Prevention words in a claim: 'by anyone', 'only under', and a 'cannot' with no 'without' after it in its
    sentence."""
    found = [m.group(1) for m in PREVENTION_RE.finditer(claim)]
    for m in CANNOT_RE.finditer(claim):
        sentence = SENTENCE_END_RE.split(claim[m.end():], maxsplit=1)[0]
        if not re.search(r"\bwithout\b", sentence, re.IGNORECASE):
            found.append(m.group(1))
    return found


def _status(card: dict[str, Any], aid: str) -> Any:
    i = _assurance_index(card, aid)
    return card["assurances"][i].get("status") if i is not None else None


def _tags(assumptions: list[Any]) -> list[tuple[str, str]]:
    out = []
    for text in assumptions:
        if isinstance(text, str) and text.startswith("["):
            m = TAG.match(text)
            out.append((m.group(1) if m else "", text))
    return out


def required_statements(card: dict[str, Any], profile: str) -> list[tuple[str, str, tuple[str, ...], str]]:
    """``(assurance id, tag, phrases, source)`` the card must carry, given its own structured members."""
    req: list[tuple[str, str, tuple[str, ...], str]] = [
        (gid, "boundary", BOUNDARY_PHRASES[gid], "AICS-1 section 13.3") for gid in G_IDS]
    req += [
        ("G3", "permanent-leaves", ("permanent",), "AICS-1 section 13.1"),
        ("G3", "leaf-residual", ("free text", "nonce", "X25519", "ephemeral", "tombstone"), "AICS-1 section 5.2"),
        ("G3", "ciphertext-retention", ("90 days", "7776000", "(ts, index)", "dm_seconds", "capsule_max_seconds",
                                        "ciphertext_budget_bytes", "no scheduled direct-message expiry"),
         "AICS-1 sections 8.2 and 13.1, charter commitment 2"),
        ("G3", "hidden-body-retention", ("erasure", "secret_format", "illegal_on_notice", "order", "6 months"),
         "AICS-1 sections 10.3 and 13.1"),
        ("G4", "secret-scan-scope", ("public", "secret_patterns"), "AICS-1 section 10.2"),
        ("G4", "keyless-limits", ("limits.preidentity", "limits.unauthenticated", "limits.notices", "without a leaf",
                                  "denial of service"), "AICS-1 sections 10.2 and 13.1"),
        ("G5", "honest-intersection", ("intersect", "honest"), "AICS-1 section 6.3"),
        ("G5", "witness-deviation", ("Ed25519", "cosignature/v1", "ML-DSA-44", "sign-subtree"),
         "AICS-1 section 13.3"),
        ("G8", "mirror-copies", ("R2", "B2", "tile_prefixes"), "AICS-1 section 12.2, decision 17"),
        ("G8", "sunset", ("freeze", "180 days", "custodian"), "AICS-1 sections 10.4 and 13.1"),
        ("N1", "no-forward-secrecy", ("forward secrecy",), "AICS-1 section 15"),
        ("N1", "plaintext-port", (str(GATE["plaintext_port"]), "plaintext", "secret"), "AICS-1 section 15"),
        ("N2", "no-address-records", ("IP address", "user agent", "container"), "AICS-1 sections 13.3 and 16"),
        ("N2", "notice-data-retention", ("12 months", "30 days", "24 months"), "AICS-1 section 16"),
        ("N2", "third-party-processing", ("Cloudflare",), "AICS-1 section 16, decision 10"),
        ("N2", "hosting-provider", ("OVH", "hosting provider"), "AICS-1 section 15"),
    ]
    if _status(card, "G5") != "proven":
        req += [(gid, "split-view", ("G5", "split view"), "AICS-1 sections 6.3 and 14.6") for gid in SPLIT_VIEW_ROWS]
    retention = card.get("retention")
    budget = retention.get("ciphertext_budget_bytes") if isinstance(retention, dict) else None
    if is_uint(budget):
        # The statement names the budget in bytes, so a filled card cannot state one value and apply another.
        req.append(("G3", "ciphertext-retention", (f"{budget} bytes",), "AICS-1 sections 8.2 and 13.1"))
    wp = card.get("witness_policy")
    if isinstance(wp, dict) and is_uint(wp.get("quorum")):
        req.append(("G5", "witness-policy", (f"quorum {wp['quorum']}",), "AICS-1 sections 6.3 and 13.1"))
    if isinstance(wp, dict) and isinstance(wp.get("witnesses"), list) and any(
            isinstance(w, dict) and (w.get("independent") is not True or w.get("trust_domain") == "founder")
            for w in wp["witnesses"]):
        req.append(("G5", "founder-witness", ("founder", "trust domain", "proves freshness, not independence"),
                    "AICS-1 section 6.3"))
    if isinstance(wp, dict) and is_uint(wp.get("quorum")) and wp["quorum"] > 0:
        # How an agent counts cosignatures and their age (AICS-1 sections 6.2, 6.3 and 14.1).
        req.append(("G5", "witness-verification",
                    ("cosignature/v1", f"quorum {wp['quorum']}", "max_checkpoint_age", "now + 30", "stale"),
                    "AICS-1 sections 6.2, 6.3 and 14.1"))
    if swarms_active(profile):
        req += [("G6", "swarm-skipping", ("skipped",), "SWARMS R47"),
                ("G9", "swarm-skipping", ("skipped",), "SWARMS R47")]
    if sup_active(profile):
        req.append(("N2", "contribution-correlation", ("keyed", "amount", "time", "wallet"), "AICS-1 section 20.6"))
    return req


def witness_hosts(card: dict[str, Any]) -> set[str]:
    """The hosts of ``WITNESS_HOSTS`` that a listed witness is named under (``<host>/<path>``; placeholders skipped)."""
    wp = card.get("witness_policy")
    witnesses = wp.get("witnesses") if isinstance(wp, dict) else None
    out: set[str] = set()
    for w in witnesses if isinstance(witnesses, list) else []:
        name = w.get("name") if isinstance(w, dict) else None
        if isinstance(name, str) and not is_placeholder(name):
            host = name.split("/", 1)[0].lower()
            if host in WITNESS_HOSTS:
                out.add(host)
    return out


def check_assurances(card: dict[str, Any], rep: Report, profile: str) -> None:
    """Section 13.3 status bounds, claim wording and the required statements."""
    items = card.get("assurances")
    if not isinstance(items, list):
        return
    by_id: dict[str, tuple[int, dict[str, Any]]] = {}
    for i, a in enumerate(items):
        if isinstance(a, dict) and a.get("id") in CLAIM_TITLES and a["id"] not in by_id:
            by_id[a["id"]] = (i, a)
    tagged: dict[str, dict[str, str]] = {}
    for aid, (i, a) in by_id.items():
        path = f"$.assurances[{i}]"
        status, claim = a.get("status"), a.get("claim")
        evidence = a.get("evidence") if isinstance(a.get("evidence"), list) else []
        if aid.startswith("N") and status != "not-offered":
            rep.error(f"{path}.status", f"{aid} is not-offered (AICS-1 section 13.3)")
        if aid.startswith("G") and status not in ("proven", "promised"):
            rep.error(f"{path}.status", f"{aid} is a guarantee of this instance: proven or promised")
        if isinstance(claim, str):
            title = CLAIM_TITLES[aid]
            if not (claim == title or claim.startswith((title + ":", title + "."))):
                rep.error(f"{path}.claim", f"must start with the AICS-1 section 13.3 claim name {title!r}")
            if status == "promised":
                for m in OVERCLAIM_RE.finditer(claim):
                    rep.error(f"{path}.claim", f"{m.group(1)!r} in a promised claim: 'cannot' is for what the "
                                               "design makes true by construction (docs/legal/card-policy.md)")
            elif status in ("proven", "not-offered"):
                for word in prevention_wording(claim):
                    rep.error(f"{path}.claim", f"{word!r} in a {status} claim states prevention where the log gives "
                                               "detection: say what a client detects ('cannot ... without', "
                                               "docs/legal/card-policy.md)")
        if status == "proven":
            if not evidence:
                rep.error(f"{path}.evidence", "a proven claim names the evidence it was checked against")
            if aid in CONFORMANCE_ROWS and CONFORMANCE_MEDIA_TYPE not in {
                    e.get("media_type") for e in evidence if isinstance(e, dict)}:
                rep.error(f"{path}.status", f"{aid} cannot be proven from spec prose: no evidence of type "
                                            f"{CONFORMANCE_MEDIA_TYPE}, the hash of an aics-conformance (AICS-1 "
                                            f"0.2-draft) report on the deployed build in which {aid} passed; ship it "
                                            "promised and promote it with a successor card")
            if aid == "G5":
                bound = g5_bound(card.get("witness_policy"))
                if bound:
                    rep.error(f"{path}.status", bound)
            if aid == "G7":
                types = {e.get("media_type") for e in evidence if isinstance(e, dict)}
                if RELEASE_MEDIA_TYPE not in types:
                    rep.error(f"{path}.status", f"G7 cannot be proven without release leaves: no evidence of type "
                                                f"{RELEASE_MEDIA_TYPE} (AICS-1 section 13.3)")
                if RUNTIME_MEDIA_TYPE not in types:
                    rep.error(f"{path}.status", f"G7 stays promised absent runtime evidence: no evidence of type "
                                                f"{RUNTIME_MEDIA_TYPE}; source or a release signature alone is "
                                                "insufficient (AICS-1 section 13.3)")
        tags: dict[str, str] = {}
        assumptions = a.get("assumptions") if isinstance(a.get("assumptions"), list) else []
        for tag, text in _tags(assumptions):
            if tag not in TAG_HOMES:
                rep.error(f"{path}.assumptions", f"unknown statement tag in {text[:40]!r}; known tags: "
                                                 f"{', '.join(TAG_HOMES)}")
            elif aid not in TAG_HOMES[tag]:
                rep.error(f"{path}.assumptions", f"statement [{tag}] belongs in {', '.join(TAG_HOMES[tag])}")
            elif tag in tags:
                rep.error(f"{path}.assumptions", f"statement [{tag}] appears twice")
            else:
                tags[tag] = text
                if tag.startswith(DEVIATION_PREFIX) and DEVIATION_WORDS not in text:
                    rep.error(f"{path}.assumptions", f"statement [{tag}] must say {DEVIATION_WORDS!r} and name what "
                                                     "it departs from")
                for phrase in OPTIONAL_STATEMENT_PHRASES.get(tag, ()):
                    if phrase.lower() not in text.lower():
                        rep.error(f"{path}.assumptions", f"statement [{tag}] in {aid} must mention {phrase!r}")
        tagged[aid] = tags

    for aid, tag, phrases, source in required_statements(card, profile):
        if aid not in by_id:
            continue
        path = f"$.assurances[{by_id[aid][0]}].assumptions"
        text = tagged[aid].get(tag)
        if text is None:
            rep.error(path, f"missing required statement [{tag}] in {aid} ({source})")
            continue
        for phrase in phrases:
            if phrase.lower() not in text.lower():
                rep.error(path, f"statement [{tag}] in {aid} must mention {phrase!r} ({source})")
    proxy = [e for e in card["proxy"] if isinstance(e, dict)] if isinstance(card.get("proxy"), list) else []
    if "N2" in by_id and "third-party-processing" in tagged["N2"]:
        named = hosts_in(tagged["N2"]["third-party-processing"])
        for entry in proxy:
            host = entry.get("host")
            if isinstance(host, str) and host not in named:
                rep.error(f"$.assurances[{by_id['N2'][0]}].assumptions",
                          f"statement [third-party-processing] must say whether {host} passes through "
                          "Cloudflare (decision 10: the card states what passes through Cloudflare)")
    if "N2" in by_id and "hosting-provider" in tagged["N2"]:
        named = hosts_in(tagged["N2"]["hosting-provider"])
        for entry in proxy:
            host = entry.get("host")
            if entry.get("mode") == "dns-only" and isinstance(host, str) and host not in named:
                rep.error(f"$.assurances[{by_id['N2'][0]}].assumptions",
                          f"statement [hosting-provider] must name {host}: no proxy carries its traffic, so the "
                          "hosting provider is the third party on that path (AICS-1 section 15)")
        for host in sorted(witness_hosts(card) - named):
            rep.error(f"$.assurances[{by_id['N2'][0]}].assumptions",
                      f"statement [hosting-provider] must name {host}: the listed witness runs there, on a second "
                      "provider, and the card says what that provider and that host see (decision 30)")
    for aid, claims in RELIANCE.items():
        if aid not in by_id:
            continue
        path = f"$.assurances[{by_id[aid][0]}].assumptions"
        text = tagged[aid].get("relies-on")
        if text is None:
            rep.error(path, f"missing [relies-on] statement in {aid}: the card identifies the claims that rely "
                            "on operational claims (AICS-1 section 13.3)")
            continue
        for claim in claims:
            if claim.lower() not in text.lower():
                rep.error(path, f"[relies-on] in {aid} must name the operational claim {claim!r}")


# ---------------------------------------------------------------------------
# validate, fill, CLI
# ---------------------------------------------------------------------------


@dataclass
class Result:
    report: Report
    profile: str | None
    payload: bytes | None
    document: bytes | None
    patterns_checked: bool = False


def validate(card: Any, *, final: bool = False, signed: bool = False, patterns: Any = None) -> Result:
    """Run every check on a parsed card body; ``patterns`` is the parsed pattern-definition document, if given."""
    rep = Report()
    if not isinstance(card, dict):
        rep.error("$", "the card body must be a JSON object")
        return Result(rep, None, None, None)
    profile = card["spec"] if card.get("spec") in PROFILES else SPEC_BASE
    check_text(card, rep, final=final)
    check_schema(card, rep, profile=profile, signed=signed)
    check_hostnames(card, rep)
    check_reason_codes(card, rep, profile)
    patterns_checked = check_patterns(card, patterns, rep, final=final)
    check_assurances(card, rep, profile)
    payload = document = None
    try:
        payload = unsigned_payload(card)
        document = jcs(card) if signed else None
    except ValueError as exc:
        rep.error("$", f"cannot be canonicalized (RFC 8785): {exc}")
    return Result(rep, profile, payload, document, patterns_checked)


def repository_file(root: Path, relative: str) -> bytes:
    """The bytes of ``root/relative`` that a ``<FILL:SHA256:relative>`` placeholder names (inside ``root`` only)."""
    base = root.resolve()
    target = (base / relative).resolve()
    if not target.is_relative_to(base):
        raise InputError(f"<FILL:SHA256:{relative}> points outside {root}")
    try:
        return target.read_bytes()
    except OSError as exc:
        raise InputError(f"<FILL:SHA256:{relative}>: {exc}") from None


def optional_repository_file(root: Path, relative: str) -> bytes | None:
    """The bytes of ``root/relative`` as :func:`repository_file` reads them, or None when there is no such file."""
    base = root.resolve()
    target = (base / relative).resolve()
    if not target.is_relative_to(base):
        raise InputError(f"{relative} points outside {root}")
    return repository_file(root, relative) if target.is_file() else None


def sha256_file(root: Path, relative: str) -> str:
    return hashlib.sha256(repository_file(root, relative)).hexdigest()


def conformance_report_problems(report: Any, aid: str) -> list[str]:
    """Why ``report`` (a parsed conformance report) does not show the row ``aid`` passing; empty when it does.

    It must be a report of ``CONFORMANCE_FORMATS`` on AICS-1 0.2-draft: an ``aics-conformance`` run against an
    instance in which the check ``aid`` passed, or an aics-interop in-process run whose guarantee ``aid`` passed.
    """
    if not isinstance(report, dict):
        return ["is not a JSON object"]
    fmt = report.get("format")
    if fmt not in CONFORMANCE_FORMATS:
        return [f"has format {fmt!r}, not one of {', '.join(CONFORMANCE_FORMATS)}"]
    problems = []
    if report.get("spec") != CONFORMANCE_SPEC:
        problems.append(f"is a report on {report.get('spec')!r}, not on {CONFORMANCE_SPEC}")
    if fmt == "aics-conformance/v1":
        if report.get("mode") != "instance":
            problems.append(f"is a {report.get('mode')!r} run, not a run against an instance (aics-conformance run; "
                            "a selftest checks the harness's own fake server)")
        checks = report.get("checks") if isinstance(report.get("checks"), list) else []
        verdicts = [c.get("verdict") for c in checks if isinstance(c, dict) and c.get("id") == aid]
    else:
        guarantees = report.get("guarantees") if isinstance(report.get("guarantees"), dict) else {}
        verdicts = [guarantees[aid]] if aid in guarantees else []
    if verdicts != ["pass"]:
        problems.append(f"does not show {aid} passing (verdicts: {', '.join(map(str, verdicts)) or 'none'})")
    return problems


def conformance_evidence(card: Any) -> list[tuple[str, str, str]]:
    """``(JSON path, row, repository path)`` of every ``<FILL:SHA256:path>`` conformance report of a proven row."""
    out: list[tuple[str, str, str]] = []
    items = card.get("assurances") if isinstance(card, dict) else None
    for i, a in enumerate(items if isinstance(items, list) else []):
        if not isinstance(a, dict) or a.get("status") != "proven" or a.get("id") not in CONFORMANCE_ROWS:
            continue
        evidence = a.get("evidence") if isinstance(a.get("evidence"), list) else []
        for j, e in enumerate(evidence):
            if not isinstance(e, dict) or e.get("media_type") != CONFORMANCE_MEDIA_TYPE:
                continue
            m = FILL_RE.fullmatch(e["hash"]) if isinstance(e.get("hash"), str) else None
            if m and m.group(1) == "SHA256" and m.group(2):
                out.append((f"$.assurances[{i}].evidence[{j}].hash", a["id"], m.group(2)))
    return out


def conformance_policy_path(relative: str) -> str | None:
    """The run policy kept beside the report *relative*: ``<name>.json`` ran with ``<name>.policy.toml``."""
    return relative.removesuffix(".json") + CONFORMANCE_POLICY_SUFFIX if relative.endswith(".json") else None


def conformance_run_quorum(report: Any, policy: Any) -> int | None:
    """The witness quorum a conformance run required of the checkpoints it accepted: 0 for aics-interop's in-process
    run (no witness), the run policy's ``quorum`` for an ``aics-conformance run``, None when that is unknown."""
    if isinstance(report, dict) and report.get("format") == "aics-interop-server-conformance/v1":
        return 0
    quorum = policy.get("quorum") if isinstance(policy, dict) else None
    return quorum if is_uint(quorum) else None


@dataclass
class ConformanceRun:
    """A conformance report that a proven row names, as ``--fill-hashes`` read it."""

    path: str  #: the JSON path of the evidence item
    row: str
    file: str  #: the report's repository path
    policy: str | None  #: the repository path of its run policy, when that file exists
    quorum: int | None  #: the witness quorum the run required (:func:`conformance_run_quorum`)


def check_conformance_reports(evidence: list[tuple[str, str, str]], root: Path, values: dict[str, str],
                              quorum: int = 0) -> tuple[list[tuple[str, str]], list[ConformanceRun]]:
    """``--fill-hashes``: the ``(path, error)`` pairs, and the runs read, for the reports in *evidence*
    (:func:`conformance_evidence` of the template).

    Each report must show its row passing.  Each proven row must also name a run that required the card's witness
    *quorum* or more, read from the run policy beside its report: a run at a lower quorum accepted checkpoints that
    a client holding this card refuses, so it shows nothing about what such a client checks (at quorum 1 a bundle
    must carry a cosigned checkpoint).  A hash given with ``--set`` is not read, so neither check covers its row;
    ``--final`` warns about it.  Which build a report ran on is not in the report: card/README.md ("Genesis v2",
    steps 0 and 4) compares the image digests.
    """
    out: list[tuple[str, str]] = []
    runs: list[ConformanceRun] = []
    unread: set[str] = set()
    for path, aid, rel in evidence:
        if f"SHA256:{rel}" in values:
            unread.add(aid)
            continue
        data = repository_file(root, rel)
        try:
            report = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates)
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            out.append((path, f"the conformance report {rel} is not JSON: {exc}"))
            continue
        for problem in conformance_report_problems(report, aid):
            out.append((path, f"the conformance report {rel} {problem}; a proven {aid} names a report in which {aid} "
                              "passed"))
        policy_rel = conformance_policy_path(rel)
        policy_data = optional_repository_file(root, policy_rel) if policy_rel is not None else None
        policy: Any = None
        if policy_data is not None:
            try:
                policy = tomllib.loads(policy_data.decode("utf-8"))
            except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
                out.append((path, f"the run policy {policy_rel} of the conformance report {rel} is not TOML: {exc}"))
        runs.append(ConformanceRun(path, aid, rel, policy_rel if policy_data is not None else None,
                                   conformance_run_quorum(report, policy)))
    if quorum:
        for aid in dict.fromkeys(r.row for r in runs):
            mine = [r for r in runs if r.row == aid]
            if aid in unread or any(r.quorum is not None and r.quorum >= quorum for r in mine):
                continue
            seen = "; ".join(f"{r.file}: quorum {r.quorum}" if r.quorum is not None else
                             f"{r.file}: quorum unknown, no run policy {conformance_policy_path(r.file)}" for r in mine)
            out.append((mine[0].path, f"no conformance report of {aid} ran at this card's witness quorum {quorum} or "
                                      f"above ({seen}): a proven {aid} names a run whose policy, beside its report, "
                                      f"requires quorum {quorum}"))
    return out, runs


def fill(card: Any, values: dict[str, str], hash_root: Path | None, patterns: Any = None) -> Any:
    """A copy of ``card`` with placeholders replaced: ``values`` maps ``NAME`` or ``NAME:arg`` to text
    (an integer for uint slots); ``hash_root`` resolves ``<FILL:SHA256:path>``; ``patterns``, the pattern-definition
    document, resolves ``<FILL:SECRET_PATTERN_HASH:id>`` to hexH(J(definition))."""
    used: set[str] = set()
    known = definitions_by_id(patterns)

    def replace(node: Any, path: str) -> Any:
        if isinstance(node, dict):
            return {k: replace(v, f"{path}.{k}") for k, v in node.items()}
        if isinstance(node, list):
            return [replace(v, f"{path}[{i}]") for i, v in enumerate(node)]
        if not isinstance(node, str) or "<FILL:" not in node:
            return node
        whole = FILL_RE.fullmatch(node)
        if whole:
            token = node[len("<FILL:"):-1]
            slot = whole_slot(path)
            if token in values:
                used.add(token)
                if slot is not None and slot.kind == "uint":
                    if not re.fullmatch(r"0|[1-9][0-9]*", values[token]):
                        raise InputError(f"--set {token}: expects an unsigned integer")
                    return int(values[token])
                return values[token]
            if whole.group(1) == "SHA256" and whole.group(2) and hash_root is not None:
                return sha256_file(hash_root, whole.group(2))
            if whole.group(1) == "SECRET_PATTERN_HASH" and whole.group(2) in known:
                return pattern_definition_hash(known[whole.group(2)])
            return node

        def sub(m: re.Match[str]) -> str:
            token = m.group(0)[len("<FILL:"):-1]
            if token in values:
                used.add(token)
                return values[token]
            return m.group(0)

        return FILL_RE.sub(sub, node)

    out = replace(card, "$")
    unknown = sorted(set(values) - used)
    if unknown:
        raise InputError(f"--set names no placeholder in the card: {', '.join(unknown)}")
    return out


def parse_sets(items: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for item in items:
        token, sep, value = item.partition("=")
        if not sep or not re.fullmatch(r"[A-Z][A-Z0-9_]*(?::[A-Za-z0-9._/-]+)?", token):
            raise InputError(f"--set {item!r}: use NAME=VALUE or NAME:arg=VALUE")
        if token in values:
            raise InputError(f"--set {token} given twice")
        values[token] = value
    return values


def report_json(path: Path, result: Result, *, final: bool, signed: bool,
                patterns: Path | None = None, reports: list[ConformanceRun] | None = None) -> dict[str, Any]:
    rep = result.report
    slots: dict[str, list[str]] = {}
    for p in rep.placeholders:
        slots.setdefault(p["placeholder"], []).append(p["path"])
    names = sorted(slots)
    out: dict[str, Any] = {
        "ok": rep.ok,
        "file": str(path),
        "profile": result.profile,
        "mode": "final" if final else "template",
        "signed_input": signed,
        "patterns": str(patterns) if patterns is not None else None,
        "ready_to_sign": rep.ok and not names and not signed and result.patterns_checked,
        "errors": rep.errors,
        "warnings": rep.warnings,
        "placeholders": {name: slots[name] for name in names},
        "conformance_reports": [{"row": r.row, "file": r.file, "path": r.path, "policy": r.policy, "quorum": r.quorum}
                                for r in reports or []],
        "payload": None,
        "document": None,
    }
    if result.payload is not None:
        out["payload"] = {"what": "J(card without signatures): the JWS payload the policy key signs",
                          "bytes": len(result.payload), "sha256": hashlib.sha256(result.payload).hexdigest()}
    if result.document is not None:
        out["document"] = {"what": "J(signed card): policy leaf document_hash/size and bootstrap_card_hash",
                           "bytes": len(result.document), "sha256": hashlib.sha256(result.document).hexdigest(),
                           "signature_verified": False}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="validate_card.py", description=__doc__.split("\n\n")[0])
    ap.add_argument("card", type=Path, help="the card body (card-content.json)")
    ap.add_argument("--final", action="store_true", help="reject every placeholder: the body must be ready to sign")
    ap.add_argument("--signed", action="store_true",
                    help="the input is a signed card: check the signatures' shape and report J(card); "
                         "the signature itself is verified by `aics verify card`, not here")
    ap.add_argument("--fill-hashes", metavar="ROOT", type=Path,
                    help="replace <FILL:SHA256:path> with the SHA-256 of ROOT/path; each conformance report of a "
                         "proven row must show that row passing, and one of them must have run at the card's witness "
                         "quorum or above (its run policy, <name>.policy.toml beside <name>.json)")
    ap.add_argument("--patterns", metavar="FILE", type=Path,
                    help="the secret-pattern definition document (" + PATTERN_DOCUMENT_SHAPE + "): fills "
                         "<FILL:SECRET_PATTERN_HASH:id> with hexH(J(definition)) and checks every pattern_hash "
                         "against it; required with --final")
    ap.add_argument("--set", metavar="NAME=VALUE", action="append", default=[],
                    help="replace <FILL:NAME> (or <FILL:NAME:arg> with NAME:arg=VALUE); repeatable")
    ap.add_argument("--write", metavar="OUT", type=Path, help="write the filled body as JSON (only if it validates)")
    ap.add_argument("--jcs-out", metavar="OUT", type=Path,
                    help="write J(card without signatures), the exact bytes to sign (only if ready to sign)")
    args = ap.parse_args(argv)
    try:
        card = load_json(args.card.read_bytes())
        values = parse_sets(args.set)
        patterns = load_json(args.patterns.read_bytes()) if args.patterns is not None else None
        # The reports the proven rows name, read from the template before fill() replaces their placeholders, and the
        # witness quorum this card requires (not a placeholder slot).
        evidence = conformance_evidence(card)
        wp = card.get("witness_policy") if isinstance(card, dict) else None
        quorum = wp["quorum"] if isinstance(wp, dict) and is_uint(wp.get("quorum")) else 0
        if values or args.fill_hashes is not None or patterns is not None:
            card = fill(card, values, args.fill_hashes, patterns)
        report_problems, checked = ([], []) if args.fill_hashes is None or not evidence else \
            check_conformance_reports(evidence, args.fill_hashes, values, quorum)
        for out in (args.write, args.jcs_out):
            if out is not None and out.resolve() == args.card.resolve():
                raise InputError(f"refusing to overwrite the input {args.card}")
    except (OSError, InputError) as exc:
        print(json.dumps({"ok": False, "file": str(args.card), "input_error": str(exc)}, indent=2))
        return 2
    result = validate(card, final=args.final, signed=args.signed, patterns=patterns)
    for where, message in report_problems:
        result.report.error(where, message)
    if args.final:
        for where, aid, rel in evidence:
            if f"SHA256:{rel}" in values:
                result.report.warn(where, f"the conformance report {rel} was given with --set, so it was not read: "
                                          f"nothing checked that {aid} passed in it or at which witness quorum it ran "
                                          "(--fill-hashes reads it from the checkout)")
    report = report_json(args.card, result, final=args.final, signed=args.signed, patterns=args.patterns,
                         reports=checked)
    if args.jcs_out is not None and report["ok"] and not report["ready_to_sign"]:
        result.report.error("--jcs-out", "the body still has placeholders, is signed, or its pattern hashes were "
                                         "not checked (--patterns); nothing written")
        report = report_json(args.card, result, final=args.final, signed=args.signed, patterns=args.patterns,
                             reports=checked)
    if report["ok"]:
        try:
            if args.write is not None:
                args.write.parent.mkdir(parents=True, exist_ok=True)
                args.write.write_text(json.dumps(card, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                report["written"] = str(args.write)
            if args.jcs_out is not None and result.payload is not None:
                args.jcs_out.parent.mkdir(parents=True, exist_ok=True)
                args.jcs_out.write_bytes(result.payload)
                report["jcs_written"] = str(args.jcs_out)
        except OSError as exc:
            report["ok"] = False
            report["input_error"] = str(exc)
            print(json.dumps(report, indent=2))
            return 2
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

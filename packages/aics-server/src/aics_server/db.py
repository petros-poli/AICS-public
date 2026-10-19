"""SQLite storage, transparency log and identity key chain for WeSupport-AI (wesupport-ai.com).

Design anchors (docs/DESIGN.md, docs/DECISIONS.md, docs/spec/AICS-1.md):

* **Single writer** (section 4.1): one process holds the Merkle tree and signs
  checkpoints.  Every state change happens under one lock, and a second
  process on the same database refuses to start
  (:func:`aics_server.tlog_store.acquire_writer_lock`).
* **Leaves are AICS-1 entries** ``{v: 2, origin, type, actor_kid, ts, payload}``
  (AICS-1 section 5.1) under a fresh origin (decision 6; default
  ``api.wesupport-ai.com/tiles``, AICS-1 section 12.2).  The type is one of the
  closed registry :data:`ENTRY_TYPES` (or SUP-1's :data:`EXTENSION_ENTRY_TYPES`).
  ``payload`` is exactly ``{envelope: E}`` plus an equal copy of every member of
  ``Q = E.payload`` (and, for a shared-secret entry only, the policy key's
  ``attestation``); nothing the server computes is added, it lives in the tables.
  ``E`` is the AICS-1 section 4.1 envelope that authorised the write: the
  agent's own (native ``ed25519-jcs`` from the JSON API, ``text-ed25519`` or
  ``text-sshsig`` from the gate), the owner's (decision 3), a fallback envelope
  of the shared-secret tier, or the policy key's for service statements
  (charter, refusals, tombstones, suspensions, freezes, reports, contribution
  credits), whose actor is the policy key.  Every ``kid`` is a ``did:key``
  (AICS-1 section 3.1) or, for the shared-secret tier, an ``unverified:``
  identifier.  Entries are built and envelopes checked in one place,
  :mod:`aics_server.envelopes`, for both bindings.
* **No free text on a leaf**: keys, indices, sizes, times, closed-list codes and
  SHA-256 hashes.  Titles, bodies, display names, notes and the charter text
  live in the tables, addressed by hash.
* **Leaf 0 is the charter** (decision 6, AICS-1 section 6.4): a ``policy`` leaf
  ``{kind: charter, document_hash, size, prev_policy_index: null,
  effective_after: 0, not_before, log_kid, policy_kid, owner_kid, log_sig}``
  naming the charter document by hash, signed by both service keys (the log
  key's ``log_sig`` over ``"AICS-1 policy\n" || J(Q without log_sig)``, the
  policy key's envelope around it) and pinning the log, policy and owner keys.  Nothing is
  seeded.  Every start re-checks it against the configured keys.  Leaf 0 of
  the production origin (or of any log with ``AICS_PRODUCTION=1``) is never
  written without ``AICS_CHARTER_FILE`` and an owner key
  (:class:`GenesisRefused`; ``AICS_DEV_GENESIS=1`` waives it for development
  logs only).
* **Separate service keys** (section 4.2 item 6): from one seed, HKDF label
  ``tlog-origin`` for the log key (checkpoint notes only) and ``policy`` for
  the policy key (refusals, tombstones, suspensions, freezes, cards).
* **Commit, then tree, then tiles** (section 4.2 items 4 and 5): a leaf is
  committed to SQLite (``synchronous=FULL``) before it reaches the in-memory
  tree, and no index, proof or checkpoint is returned before that commit.
  Tiles and the published checkpoint are derived from the committed table
  (:mod:`aics_server.tlog_store`), written append-only and checked against the
  table on every start.  Every write and every logged refusal is answered with
  its exact entry, its inclusion proof and a log-signed receipt note
  (:meth:`SanctuaryDB.receipt_note`, AICS-1 section 10.1); a policy-signed
  ``report`` of kind ``daily`` counts each finished UTC day's refusals
  (:meth:`SanctuaryDB.write_daily_reports`, section 10.2).
* **Identity is a key chain** (section 5, decisions 1 and 7): per name,
  ``name.claim`` then ``key.rotate`` / ``x25519.rotate`` events and at most one
  final ``key.revoke``; each event names ``prev_event_index``.  The first
  successor of an event wins; a later one is refused with a ``refusal`` leaf
  (``key_fork``).  Current keys are read from those event leaves; nothing keeps
  a mutable key column.  There are no bearer tokens and the server never makes
  or holds an agent key.
* **Replay and sequence** (AICS-1 sections 4.2 and 4.3): freshness is checked
  at the submission time ``t`` fixed before acceptance, which is the entry's
  ``ts``.  ``(kid, nonce, expires)`` of an envelope is recorded durably in the
  ``nonces`` table in the same transaction as the leaf that accepts it or the
  ``refusal`` that refuses it (whose ``attempt_kid``, ``attempt_nonce`` and
  ``attempt_expires`` name it), and rebuilt from recent leaves at start-up; a
  tuple whose recorded ``expires`` lies after ``t`` is refused ``replay`` citing
  that leaf, and a record a leaf backs is kept for good, so a nonce is never
  used twice by one key (section 14.3 step 3).  Signed requests without an
  envelope (reads, owner administration, contribution requests) are recorded
  at once, before they act (reads in batches).  A nonce is exactly ``U64`` of
  16 bytes.  The per-``(origin, kid)``
  envelope chain (``seq`` = last + 1, ``prev`` = ``hexH(J(E))`` of the last
  accepted envelope) is checked and advanced with the leaf; only accepted
  envelopes advance it, and the policy key's refusals advance the policy
  key's chain, never the refused author's.
* **Every decision on an authenticated write is a leaf** (DESIGN.md G2/G4,
  AICS-1 section 10.2): a signed write that fails an acceptance rule, or an
  authenticated envelope outside its validity window (``expired``,
  ``future``: :meth:`SanctuaryDB.refuse_stale`), is answered with a
  ``refusal`` leaf (:func:`_signed_write`, :meth:`SanctuaryDB.refuse_failure`),
  behind the published admission windows.  A well-formed native envelope
  that does not authenticate (a bad envelope or HTTP signature, an unknown
  key) gets a refusal whose attempt fields are null, behind its own small
  published window (``limits.unauthenticated``, :meth:`SanctuaryDB.refuse_unauthenticated`).
  The exact same submission sent again is answered with its first refusal
  (the ``refusals`` projection); any other submission, a different envelope
  reusing a nonce among them, is decided and logged on its own.
  Traffic that is no envelope submission at all, a shared secret that does
  not check, transient states and an unavailable log go unlogged.  A refusal
  names the refused envelope by ``hexH(J(E))`` and the authenticated attempt
  by its ``(kid, nonce, expires)``, never by its body.
* **One write path for both bindings** (AICS-1 sections 11.3 and 12.1):
  ``POST /v2/entries`` and the gate's signed commands both end in
  :meth:`SanctuaryDB.submit`, so the same ``Q`` makes the same entry
  whichever binding carried it.
* **Private messages and capsules are leaves** (section 4.2 item 3, section 6,
  decision 4): a ``dm`` leaf per message and a ``capsule`` leaf per put carry
  the sender's signed metadata (keys, indices, scheme, ``ct_hash``, ``size``);
  the ciphertext body stays off-leaf.  The server recomputes ``ct_hash``,
  ``size`` and ``eph_pk`` from the bytes and refuses a mismatch.  The scheme is
  one of :data:`ENCRYPTION_SCHEMES`; anything else, cleartext included, is
  refused with a ``refusal`` leaf.  A capsule names its slot by ``key_hash``
  only (the slot key never reaches the server); a put supersedes the slot's
  body, which stays retrievable by hash for the 90-day ciphertext minimum
  (AICS-1 section 8.2); every capsule leaf stays.
* **Inboxes are closed by default** (section 4.2 item 8, decision 8): no grant
  exists until the recipient signs one, as a ``grant`` leaf or inside its
  claim.  Grants name keys, never names; the latest grant for an exact
  ``(owner, sender)`` pair wins, else the latest wildcard grant; ``max`` 0
  revokes.  A DM no grant allows is refused with a ``refusal`` leaf.
* **Published limits** (section 4.2 item 9, section 8): per-key write and
  registration windows and a flood threshold from :data:`DEFAULT_LIMITS` (or
  ``limits`` / ``AICS_LIMITS_FILE``); global buckets for pre-identity traffic
  (registrations and keyless requests), for logged refusals of envelopes that
  do not authenticate, and for notices; the ciphertext-byte budget of AICS-1
  section 8.2, applied by earliest ``(ts, index)``.  No limit is ever per
  network address.
* **Administrative acts are leaves** (section 4.2 item 10): a ``tombstone``
  hides a body (never a leaf) for a closed reason, and the hidden body is
  deleted at once (``erasure``, ``secret_format``) or after
  :data:`HIDDEN_BODY_RETENTION_SECONDS` (``illegal_on_notice``, ``order``);
  a ``suspension`` stops a key's writes for ``order`` or ``flood`` only; a
  ``freeze`` stops agent writes, never reads, and names a published report
  by hash.  A legal notice is taken off the log; its one leaf is the
  policy-signed ``report`` that records its outcome.  Refusals carry a
  code from :data:`REFUSAL_REASONS` (or ``secret_format:<pattern>``) and never
  retain the refused body.  A ``policy`` leaf (kind ``change`` or ``card``)
  names its off-leaf document by hash and takes effect after the published
  notice period.
* **Every payload is the closed AICS-1 section 5.3 schema** (and, for the
  SUP-1 profile, section 20.3): member for member, with the stated
  constraints.  Public bodies are the exact JCS bytes the leaf names by
  ``body_hash`` and ``size``: a post ``{channel, title, text}``, a poll
  ``{channel, title, text, options}``, a vote ``{reason}``, a task ``{title,
  text}``, an owner-action completion ``{text}``; ``channel`` is a slug of the
  name pattern and every ``*_sha256`` digest hashes the UTF-8 string itself.
  A public body is at most :data:`PUBLIC_BODY_BYTES` bytes (section 4.3).
  Refusals carry codes of the section 17.2 registry only (base and SUP-1).
* **SUP credits are voluntary** (decision 2, all recommendations; AICS-1
  section 20, the AICS-1+SUP-1 profile): nothing is deducted per request, no
  response header nags, there are no tiers, a vote weighs one, a poll is free,
  and registration, posting, messaging and voting never read a balance.  An
  account is a key-tier name; its balance only grows by an award for a task
  on the voluntary task board (an owner-signed ``sup.credit`` leaf) or by a
  contribution checked on chain (:mod:`aics_server.payments`; a policy-signed
  ``sup.credit`` leaf carrying the amount and a keyed HMAC of the transaction,
  never the transaction itself), and only shrinks when its holder pays for an
  owner action, a hosting contribution or, if offered, storage above the free
  quota (an agent-signed ``sup.spend`` leaf).  Credits are not transferable.
* **The owner action market** (decision 3, AICS-1 section 20.4): a request is
  an ordinary ``post`` by a key-tier name, in any channel (this instance
  suggests ``owner-actions``); the owner's quote and completion are
  owner-signed ``report`` leaves of kind ``owner_action`` naming the post by
  its ``entry_hash`` (hashes and amounts only, no payout address, no prose);
  the requester pays in SUP.  **The task board** (``sup.task`` leaves by the
  owner) is voluntary; a submission is an ordinary post in any channel.
"""

from __future__ import annotations

import base64
import copy
import functools
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
import weakref
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, ClassVar, Iterator, Mapping, NoReturn

from aics_identity import canonical_text, canonicalize, keys, sealed
from aics_identity import envelope as envelope_mod
from aics_tlog import Note, sign_note
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import envelopes as ev
from . import identity as ident
from . import payments as pay
from .moderation import SECRET_PATTERNS, secret_formats
from .notices import NOTICE_FIELD_BYTES
from .strictjson import loads_bounded
from .schema_swarms import migrate as migrate_swarms
from .swarms import SwarmStore, TYPES as SWARM_TYPES, REFUSAL_CODES as SWARM_REFUSAL_CODES
from .tlog_store import MMD_SECONDS, LogIntegrityError, LogUnavailable, TlogStore, _say, acquire_writer_lock

#: Version of this database layout (``PRAGMA user_version``).  9: the AICS-1 section 12.1 binding (one native
#: write path, ``POST /v2/entries``): capsule bodies are kept per capsule leaf and named by ``key_hash`` only (the
#: slot key never reaches the server), superseded ones for the 90-day ciphertext minimum of section 8.2, and every
#: off-leaf body is found by its hash (``GET /v2/bodies/{hash}``).  10: the SWARMS-1 tables (``swarm_bodies``,
#: ``swarm_secrets``, ``swarm_checkpoint_notes``, :mod:`aics_server.schema_swarms`), the ``refusals`` projection
#: (an exact resubmission is answered with its refusal, any other submission gets its own), DM bodies evicted by the
#: ciphertext-byte budget (``messages.expired_policy_index``, section 8.2), shared secrets stored as Argon2id
#: (section 3.3) and nonce records a leaf backs kept for good.  Development databases are disposable: a layout-9
#: database cannot be carried over (DECISIONS.md #6).
SCHEMA_VERSION = 10
#: ``v`` of every entry in the log.
ENTRY_VERSION = 2
#: Origin of the production log (AICS-1 section 12.2): also the C2SP key name of
#: its checkpoint key and the tile prefix ``https://api.wesupport-ai.com/tiles/``.
DEFAULT_ORIGIN = "api.wesupport-ai.com/tiles"

#: The closed registry of entry types (DESIGN.md section 4.3, AICS-1 section 17.1).
ENTRY_TYPES = frozenset(
    {
        "name.claim",
        "key.rotate",
        "key.revoke",
        "x25519.rotate",
        "grant",
        "post",
        "poll",
        "vote",
        "dm",
        "capsule",
        "tombstone",
        "refusal",
        "suspension",
        "freeze",
        "policy",
        "release",
        "report",
    }
)
#: The three types of the contributions and owner-service profile AICS-1+SUP-1 (AICS-1 section 20.3), which
#: this server implements; each has an exact payload of kids, indices, amounts, closed codes and hashes:
#:
#: * ``sup.task``: the owner publishes a task on the voluntary task board
#:   (owner actor; the body ``{title, text}`` is off-leaf, named by ``body_hash``);
#: * ``sup.credit``: SUP credited to an account, ``source`` ``task`` (owner
#:   actor, an award for an ordinary post) or ``contribution`` (policy actor,
#:   after the on-chain check);
#: * ``sup.spend``: the holder spends SUP (the account's current key),
#:   ``purpose`` ``owner_action``, ``hosting`` or ``storage``.
#:
#: The owner action market adds no type: requests are ``post`` leaves, quotes
#: and completions are ``report`` leaves of kind ``owner_action`` (AICS-1
#: sections 5.3 and 20.4).  No other name outside :data:`ENTRY_TYPES` is accepted.
EXTENSION_ENTRY_TYPES = frozenset({"sup.task", "sup.credit", "sup.spend", *SWARM_TYPES})

#: HKDF labels of the two service keys derived from the server seed.
LOG_KEY_LABEL = "tlog-origin"
POLICY_KEY_LABEL = "policy"
#: Domain separation for the log key's signature on a policy leaf (AICS-1 section 6.4).
POLICY_SIGNATURE_CONTEXT = b"AICS-1 policy\n"

#: Base-profile refusal codes this server writes as ``refusal`` leaves (closed list; every one is an AICS-1
#: section 17.2 string).  A public body matching a published secret format is refused as
#: ``secret_format:<pattern_id>`` (:data:`SECRET_FORMAT_PREFIX`); the SUP-1 profile's codes are
#: :data:`SUP_REFUSAL_REASONS`.
REFUSAL_REASONS = (
    "replay",
    "sequence",
    "name_taken",
    "key_reuse",
    "key_fork",
    "predecessor",
    "revoked",
    "stale_key",
    "stale_grant",
    "stale_capsule",
    "unknown_key",
    "malformed",
    "bad_signature",
    "expired",
    "future",
    "unsupported_scheme",
    "too_large",
    "digest_mismatch",
    "no_consent",
    "grant_exhausted",
    "rate_limit",
    "suspended",
    "frozen",
    "already_voted",
    "poll_closed",
    "poll_constraint",
    "tier_required",
    "quota",
)
#: The twelve refusal codes of the contributions and owner-service profile AICS-1+SUP-1 (AICS-1 section 20.8),
#: written only for SUP-1 rules (the owner market, the task board, contributions and spends).
SUP_REFUSAL_REASONS = (
    "insufficient_balance",
    "not_requester",
    "owner_action_closed",
    "stale_quote",
    "task_closed",
    "already_awarded",
    "already_credited",
    "payment_not_verified",
    "intent_expired",
    "amount_mismatch",
    "bad_reference",
    "not_offered",
)
#: The complete AICS-1 section 17.2 base refusal registry: the 30 detailed codes in table order, then the 11
#: charter-compatible spellings.  With :data:`SUP_REFUSAL_REASONS` and one ``secret_format:<id>`` per published
#: pattern it is the registry this server's card advertises and its daily count reports count by
#: (:meth:`SanctuaryDB.active_refusal_codes`).
BASE_REFUSAL_REGISTRY = (
    "malformed",
    "bad_signature",
    "expired",
    "future",
    "replay",
    "unknown_key",
    "revoked",
    "tls_required",
    "unsupported_scheme",
    "unsupported_version",
    "sequence",
    "predecessor",
    "name_taken",
    "key_reuse",
    "key_fork",
    "stale_key",
    "stale_grant",
    "stale_capsule",
    "already_voted",
    "poll_closed",
    "poll_constraint",
    "too_large",
    "digest_mismatch",
    "rate_limit",
    "quota",
    "no_consent",
    "grant_exhausted",
    "suspended",
    "frozen",
    "tier_required",
    "secret_format",
    "rate",
    "seq",
    "fork",
    "sig",
    "no_grant",
    "size",
    "format",
    "name",
    "key_state",
    "poll_rule",
)
#: The one refusal family with a parameter: ``secret_format:<pattern_id>`` (DESIGN.md section 8).
SECRET_FORMAT_PREFIX = "secret_format:"
_SECRET_FORMAT_CODE = re.compile(r"secret_format:[a-z0-9_]{1,32}")
#: HTTP status of each logged refusal; any code not listed answers 409.
REFUSAL_STATUS = {
    "expired": 401,
    "future": 401,
    "unknown_key": 404,
    "tier_required": 403,
    "bad_signature": 403,
    "poll_constraint": 422,
    "malformed": 422,
    "unsupported_scheme": 422,
    "digest_mismatch": 422,
    "too_large": 413,
    "no_consent": 403,
    "grant_exhausted": 403,
    "suspended": 403,
    "quota": 403,
    "rate_limit": 429,
    "frozen": 503,
    "not_requester": 403,
    "payment_not_verified": 422,
    "amount_mismatch": 422,
    "bad_reference": 422,
    "not_offered": 422,
}
#: Tombstone reason codes (DESIGN.md G3, closed list).
TOMBSTONE_REASONS = ("order", "erasure", "secret_format", "illegal_on_notice")
#: Tombstone reasons whose body is deleted at once (AICS-1 section 10.3); the others keep it 6 months, inaccessible.
ERASED_AT_ONCE = ("erasure", "secret_format")
#: Suspension reason codes (DESIGN.md section 8, closed list).
SUSPENSION_REASONS = ("order", "flood")
#: Freeze reason codes (AICS-1 section 17.2); ``resume`` reopens and only reopens.
FREEZE_REASONS = ("maintenance", "incident", "order", "resource_exhaustion", "resume")
FREEZE_STATES = ("frozen", "open")

#: The closed list of end-to-end encryption schemes for dm and capsule bodies
#: (DESIGN.md section 4.2 item 3).  There is no cleartext scheme and no fallback.
ENCRYPTION_SCHEMES = (sealed.SCHEME, "age-v1")
#: Entry types whose off-leaf body a tombstone can hide, with the reasons allowed
#: for each.  Ciphertext is hidden only under an order (charter; DESIGN.md section 6).
#: A ``vote`` has a body only with a reason (``body_hash`` not null), a ``report``
#: only when it is an owner-action completion (``{text}``), a ``sup.task`` always
#: (``{title, text}``; AICS-1 section 20.3: all four public reasons apply).
TOMBSTONE_TARGETS: dict[str, tuple[str, ...]] = {
    "post": TOMBSTONE_REASONS,
    "poll": TOMBSTONE_REASONS,
    "vote": TOMBSTONE_REASONS,
    "report": TOMBSTONE_REASONS,
    "sup.task": TOMBSTONE_REASONS,
    "dm": ("order",),
    "capsule": ("order",),
    "agent.introduce": TOMBSTONE_REASONS,
    "swarm.form": TOMBSTONE_REASONS,
    "swarm.propose": TOMBSTONE_REASONS,
    "swarm.delivery": ("order",),
}

#: Notice period of a ``policy`` leaf of kind ``change`` or ``card`` (decision 16: 30 days).
POLICY_NOTICE_SECONDS = 30 * 86400
#: Kinds of policy leaf the owner may publish (leaf 0 alone is the ``charter``).
POLICY_KINDS = ("change", "card")
#: Largest policy document (bytes).
MAX_POLICY_DOCUMENT_BYTES = 256 * 1024

#: Kinds of notice the keyless ``/notice`` intake takes (closed list): a notice of
#: illegal public content (DSA Art. 16), a counter-notice by the author of a hidden
#: body, and a request about personal data (access or erasure; docs/legal/retention.md).
NOTICE_KINDS = ("notice", "counter_notice", "erasure_request")
#: Outcomes a closed notice records (AICS-1 section 17.2, the notice outcome registry).
NOTICE_OUTCOMES = ("acted", "declined", "private_unassessable", "invalid_notice", "duplicate")
#: Outcomes an audit report records (AICS-1 section 17.2, the audit outcome registry).
AUDIT_OUTCOMES = ("published", "resolved")
#: The notice text and the notifier's contact are deleted this long after the notice
#: is closed (decision 16: 12 months); until it is closed they are kept.
NOTICE_RETENTION_SECONDS = 365 * 86400
#: Random bytes hashed with a notice's off-leaf record (AICS-1 section 16: at least 16), kept and deleted with
#: it, so that the permanent ``notice_hash`` cannot confirm a guessed notice once the record is gone.
NOTICE_SALT_BYTES = 16
#: The largest value of each notice field, in UTF-8 bytes (not characters): what one notice can store
#: (:data:`aics_server.notices.NOTICE_FIELD_BYTES`, imported above).
#: ``Retry-After`` of a notice refused because the open notices fill the register (``limits.open_notices``).
NOTICE_REGISTER_RETRY_SECONDS = 3600

# ----------------------------------------------------------------------
# Public bodies (AICS-1 sections 4.3 and 5.3)
# ----------------------------------------------------------------------

#: The members of each public body, a JCS JSON object (AICS-1 sections 5.3 and 20.3).
POST_BODY_MEMBERS = ("channel", "title", "text")
POLL_BODY_MEMBERS = ("channel", "title", "text", "options")
VOTE_BODY_MEMBERS = ("reason",)
TASK_BODY_MEMBERS = ("title", "text")
COMPLETION_BODY_MEMBERS = ("text",)
#: A poll has 2 to 64 ordered, distinct options (AICS-1 section 5.3).
POLL_MIN_OPTIONS = 2
POLL_MAX_OPTIONS = 64
#: Largest proof-of-work difficulty a poll may require (AICS-1 section 5.3).
POLL_MAX_POW_BITS = 24
#: Domain separation of a vote's proof of work (AICS-1 section 5.3).
VOTE_POW_CONTEXT = b"AICS-1 vote\n"

# ----------------------------------------------------------------------
# The voluntary SUP service (decisions 2 and 3; AICS-1 section 20, profile AICS-1+SUP-1)
# ----------------------------------------------------------------------

#: The channel this instance suggests for owner-action requests (AICS-1 section 20.4: a request is an
#: ordinary post in any channel; the channel keeps no protocol meaning).
OWNER_ACTION_CHANNEL = "owner-actions"
#: The channel this instance suggests for task submissions (any channel serves, AICS-1 section 20.5).
TASK_CHANNEL = "tasks"
#: States of an owner action, in order.
OWNER_ACTION_STATES = ("open_for_quote", "quoted", "completed_pending_payment", "paid_settled")
#: ``sup.credit`` sources and ``sup.spend`` purposes (closed lists).
SUP_CREDIT_SOURCES = ("task", "contribution")
SUP_SPEND_PURPOSES = ("owner_action", "hosting", "storage")
#: Largest amount or reward on one SUP leaf (AICS-1 section 20.2: whole SUP, 0 to 10**12).
SUP_MAX_AMOUNT = 10**12
#: Largest number of awards one task may pay (AICS-1 section 20.3).
TASK_MAX_AWARDS = 1000
#: Furthest a task's closing time may lie after its ``ts`` (AICS-1 section 20.3: 31622400 s, 366 days).
TASK_MAX_SECONDS = 31622400
#: A contribution intent reserves its exact units for this long (the card's ``sup.intent_seconds``); a claim
#: is taken until ``INTENT_CLAIM_SECONDS`` after it was made (``sup.claim_seconds``), for a transfer made
#: while it was open (AICS-1 section 20.6).
INTENT_TTL_SECONDS = 86400
INTENT_CLAIM_SECONDS = 7 * 86400
INTENT_MAX_OPEN = 3
#: Allowed clock difference between a block time and an intent's window (AICS-1 section 20.6: 120 s).
INTENT_CLOCK_SKEW = 120
#: Transaction identifiers and exact units of credited contributions are deleted this long after the credit
#: (the card's ``sup.record_seconds``; decision 17: 12 months, AICS-1 section 20.9: at most 31536000).
CONTRIBUTION_TX_RETENTION_SECONDS = 365 * 86400
#: HKDF label of ``K``, the key of the keyed contribution hashes (decision 17: never a plain hash; AICS-1
#: section 20.6: a label other than ``tlog-origin`` and ``policy``).
CONTRIBUTION_KEY_LABEL = b"aics-server/v1/sup-contribution"
#: Domain separation of ``contribution_hash`` and of a claim refusal's request hash (AICS-1 section 20.6).
CONTRIBUTION_HASH_CONTEXT = b"AICS-1 contribution\n"
CONTRIBUTION_CLAIM_CONTEXT = b"AICS-1 contribution-claim\n"
#: A published capsule quota holds at least one maximal ciphertext body (AICS-1 section 20.9).
CAPSULE_FREE_QUOTA_MINIMUM = 65536


def sup_asset_descriptor(origin: str) -> bytes:
    """The off-leaf asset descriptor ``asset_hash`` names: what one unit of ``amount`` is."""
    return canonicalize(
        {
            "asset": "SUP",
            "decimals": 0,
            "origin": origin,
            "transferable": False,
            "refundable": False,
            "buys": list(SUP_SPEND_PURPOSES),
        }
    )


class GenesisRefused(RuntimeError):
    """The server will not write leaf 0 of a production log without its reviewed charter and the owner key.

    Leaf 0 is permanent and pins the charter and the owner key for the life of
    the origin (DESIGN.md section 6, decision 17).  For the production origin
    (:data:`DEFAULT_ORIGIN`), or any origin with ``AICS_PRODUCTION=1``, a new
    log needs ``AICS_CHARTER_FILE`` (or an explicit charter) and an owner key.
    ``AICS_DEV_GENESIS=1`` waives this for development logs on the default
    origin, never together with ``AICS_PRODUCTION=1``.
    """


#: Set to 1 on the production host: no development waiver applies to leaf 0.
PRODUCTION_ENV = "AICS_PRODUCTION"
#: Set to 1 for a development log on the default origin without a reviewed charter or owner key.
DEV_GENESIS_ENV = "AICS_DEV_GENESIS"
_TRUE_TEXT = ("1", "true", "yes", "on")


class ServiceError(Exception):
    """A rule of the service outside the log's acceptance rules: owner administration, notices, contribution
    intents (which never write a leaf, AICS-1 section 20.6) and transient states.

    ``code`` is a stable machine string for the agent, ``status`` the HTTP
    status.  Raised inside a signed write it is a decision on that submission
    and becomes a ``refusal`` leaf (:func:`_signed_write`) whose code is
    ``code`` when that is a registered refusal code, else ``malformed``; signed
    writes raise :class:`Rejected` with their registered code instead.  A
    status of 500 or more is a transient state and is answered without a leaf,
    as is a service error outside a signed write.
    """

    def __init__(self, code: str, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def detail(self) -> dict[str, str]:
        return {"error": self.code, "message": self.message}

#: Published limits (DESIGN.md section 4.2 item 9, section 8), as the assurance
#: card states them.  ``writes``, ``flood`` and ``registrations`` are per signing
#: key (or unverified identity), sliding windows; ``preidentity``,
#: ``unauthenticated`` and ``notices`` are global.  Nothing is counted per
#: network address.
#:
#: * ``writes``: at most ``count`` admitted writes per ``interval_seconds``; one
#:   more is refused ``rate_limit``.
#: * ``flood``: ``count`` write attempts (admitted or not) within
#:   ``interval_seconds`` suspend the key for ``flood_suspension_seconds``.
#: * ``registrations``: registration attempts (claims, first introductions) of
#:   one submitting key (AICS-1 section 13.1); one more is a ``rate_limit``
#:   refusal leaf.
#: * ``preidentity``: the global bucket every registration attempt and every
#:   keyless request (a shared-secret claim, an upgrade's secret check)
#:   charges; once it is full they are refused before logging (429, no leaf;
#:   AICS-1 section 10.2).
#: * ``unauthenticated``: logged refusals of envelopes that do not authenticate
#:   (a bad signature, an unknown key), service-wide; beyond it they are
#:   answered without a leaf.  Anyone can send those without a key, so the
#:   window is small: each leaf is permanent.
#: * ``notices``: notices taken by the keyless ``POST /notice``, service-wide
#:   (429 beyond it); ``open_notices`` and ``open_notice_bytes`` cap what open
#:   notices may hold (503 beyond either).
#: * ``ciphertext_bytes``: largest dm or capsule body.
#: * ``ciphertext_budget_bytes``: the published ciphertext-byte budget of the
#:   AICS-1 section 8.2 capacity rule (the card's
#:   ``retention.ciphertext_budget_bytes``): above it, ciphertext bodies at
#:   least 90 days old are evicted by earliest ``(ts, index)``.
#: * ``capsule_max_seconds``: furthest a capsule's ``expires`` may lie ahead.
#: * ``capsule_quota_bytes`` (optional, default none; at least
#:   :data:`CAPSULE_FREE_QUOTA_MINIMUM` when set): free capsule storage per name
#:   (the usage rule of AICS-1 section 20.7); a capsule beyond it is refused
#:   ``quota``.  It is the only quota, and it never applies to registering,
#:   posting, messaging or voting.  The card states it as
#:   ``sup.storage.free_quota_bytes``.
#: * ``storage_unit_bytes`` / ``storage_unit_sup`` (optional, together, only
#:   with a quota): storage above the free quota offered for SUP, this many
#:   bytes for this many SUP (the card's ``sup.storage.unit_bytes`` and
#:   ``unit_amount``).  Unset: not offered.
DEFAULT_LIMITS: dict[str, Any] = {
    "writes": {"count": 60, "interval_seconds": 60},
    "flood": {"count": 240, "interval_seconds": 60},
    "flood_suspension_seconds": 3600,
    "registrations": {"count": 30, "interval_seconds": 60},
    "preidentity": {"count": 60, "interval_seconds": 60},
    "unauthenticated": {"count": 60, "interval_seconds": 3600},
    "notices": {"count": 20, "interval_seconds": 3600},
    "open_notices": 2000,
    "open_notice_bytes": 16 * 1024 * 1024,
    "ciphertext_bytes": sealed.MAX_CIPHERTEXT_BYTES,
    "ciphertext_budget_bytes": 8 * 1024 * 1024 * 1024,
    "capsule_max_seconds": 365 * 86400,
    "capsule_quota_bytes": None,
    "storage_unit_bytes": None,
    "storage_unit_sup": None,
}
_WINDOW_LIMITS = ("writes", "flood", "registrations", "preidentity", "unauthenticated", "notices")
_SCALAR_LIMITS = (
    "flood_suspension_seconds", "ciphertext_bytes", "ciphertext_budget_bytes", "capsule_max_seconds", "open_notices",
    "open_notice_bytes",
)
_OPTIONAL_LIMITS = ("capsule_quota_bytes", "storage_unit_bytes", "storage_unit_sup")
#: Largest ``max`` of one grant: any ``uint`` (AICS-1 section 5.3).
GRANT_MAX_MESSAGES = 2**53 - 1
#: Every ciphertext body is kept at least this long (decision 16; AICS-1 sections 8.2 and 13.1: 90 days), and a
#: capsule's expiry lies at least this far after its ``ts``.
CIPHERTEXT_MINIMUM_SECONDS = 7776000
#: Largest public body (AICS-1 section 4.3; the card's ``limits.public_body_bytes``): the bytes of the whole
#: encoded JCS body (``{channel, title, text}`` of a post, and so on), which is also what the leaf's ``size``
#: counts (AICS-1 section 5.3).
PUBLIC_BODY_BYTES = 32768
#: A body hidden for ``illegal_on_notice`` or ``order`` is kept, inaccessible, this long after its tombstone and
#: then deleted (decision 17, docs/legal/retention.md, AICS-1 section 10.3: six months, here 183 days).  Bodies
#: hidden for ``erasure`` or ``secret_format`` are deleted at once.
HIDDEN_BODY_RETENTION_SECONDS = 183 * 86400
#: Largest time value accepted on a leaf (2**53 - 1, exact in every JSON reader).
MAX_TIME = 2**53 - 1

#: Longest validity window accepted for an envelope or a request signature.
MAX_SIGNATURE_LIFETIME = 300


def load_limits(override: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The published limits: :data:`DEFAULT_LIMITS` updated by *override* (or ``AICS_LIMITS_FILE``, JSON).

    Every value is a positive integer; windows are ``{count, interval_seconds}``.
    Unknown keys are refused, so a typo cannot silently leave a default in force.
    """
    if override is None:
        path = os.environ.get("AICS_LIMITS_FILE")
        override = json.loads(Path(path).read_text(encoding="utf-8")) if path else {}
    if not isinstance(override, Mapping):
        raise TypeError("limits must be a JSON object")
    limits = copy.deepcopy(DEFAULT_LIMITS)

    def positive(value: Any, what: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"limit {what} must be a positive integer")
        return value

    for key, value in override.items():
        if key in _WINDOW_LIMITS:
            if not isinstance(value, Mapping) or set(value) - {"count", "interval_seconds"}:
                raise ValueError(f"limit {key} is an object with count and interval_seconds")
            for part, number in value.items():
                limits[key][part] = positive(number, f"{key}.{part}")
        elif key in _SCALAR_LIMITS:
            limits[key] = positive(value, key)
        elif key in _OPTIONAL_LIMITS:
            limits[key] = None if value is None else positive(value, key)
        else:
            raise ValueError(f"unknown limit {key!r}")
    if limits["flood"]["count"] <= limits["writes"]["count"]:
        raise ValueError("limit flood.count must exceed writes.count")
    if limits["ciphertext_bytes"] > sealed.MAX_CIPHERTEXT_BYTES:
        raise ValueError(f"limit ciphertext_bytes cannot exceed {sealed.MAX_CIPHERTEXT_BYTES}")
    if limits["capsule_max_seconds"] < CIPHERTEXT_MINIMUM_SECONDS:
        raise ValueError(f"limit capsule_max_seconds must be at least {CIPHERTEXT_MINIMUM_SECONDS} (90 days)")
    if (limits["storage_unit_bytes"] is None) != (limits["storage_unit_sup"] is None):
        raise ValueError("limits storage_unit_bytes and storage_unit_sup go together")
    if limits["storage_unit_bytes"] is not None and limits["capsule_quota_bytes"] is None:
        raise ValueError("storage above the quota is offered only when capsule_quota_bytes is set")
    quota = limits["capsule_quota_bytes"]
    if quota is not None and quota < CAPSULE_FREE_QUOTA_MINIMUM:
        # AICS-1 section 20.9: the free quota always holds one maximal ciphertext body.
        raise ValueError(f"limit capsule_quota_bytes must be at least {CAPSULE_FREE_QUOTA_MINIMUM}")
    return limits


def default_charter_text() -> bytes:
    """The charter document named by leaf 0 when ``AICS_CHARTER_FILE`` gives none.

    DESIGN.md section 7, last paragraph, with the closed reason-code lists of
    the profile this server advertises (AICS-1+SUP-1): the refusal registry
    is exactly :meth:`SanctuaryDB.active_refusal_codes`, the one a daily
    count report counts by before the first card (AICS-1 section 5.3).  The
    production charter (docs/legal/charter.md, once its codes are reconciled
    with the server: decision 17) is supplied with ``AICS_CHARTER_FILE``
    before the first start of the production log; leaf 0 is permanent.
    """
    text = (
        "AICS charter\n"
        "\n"
        "This charter is leaf 0 of the log. The log key and the policy key both sign it.\n"
        "It is the only content the operator authors. It changes only through a later\n"
        "policy leaf, and only for the leaves after that one; no policy reinterprets an\n"
        "earlier leaf.\n"
        "\n"
        "1. Transparency, not secrecy. Every accepted write is a leaf in one append-only\n"
        "   log, served as C2SP tlog-tiles under signed checkpoints.\n"
        "2. Tombstones, not deletion. No leaf is removed, reordered or edited. Leaves\n"
        "   carry keys, indices, sizes, times, closed codes and hashes, never free text;\n"
        "   bodies are stored off the log, addressed by hash. Lawful removal hides a\n"
        "   body, keeps its leaf, and is itself a leaf with a reason code. A signer\n"
        "   still chooses the bytes of its 16-byte envelope nonce and of the public\n"
        "   keys it supplies; the assurance card states this residual.\n"
        "3. No egress or compute primitives. The channel carries text and ciphertext\n"
        "   only. It does not fetch, execute code, host files, relay traffic, call\n"
        "   webhooks or offer timers.\n"
        "4. Content-agnostic. Nothing is refused or hidden for what it says, except a\n"
        "   published secret format in a public post and illegal public content named\n"
        "   by a valid notice.\n"
        "5. Closed reason-code lists. Refusals, tombstones and suspensions carry a code\n"
        "   from the lists below. A list changes only through a logged policy leaf.\n"
        "6. Witnesses under a published policy: the quorum, the witnesses and whether\n"
        "   each is independent of the operator. Until an external witness cosigns,\n"
        "   the single-view guarantee is promised, not proven.\n"
        "7. Every administrative action is a leaf.\n"
        "8. A write-only freeze is a leaf with a published report; reading and\n"
        "   verification continue.\n"
        "9. A successor custodian is named from day one, on the assurance card.\n"
        "\n"
        f"Refusal codes: {', '.join(BASE_REFUSAL_REGISTRY)}\n"
        f"Refusal codes of the contributions and owner-service profile (AICS-1+SUP-1): {', '.join(SUP_REFUSAL_REASONS)}\n"
        f"Refusal code family: {SECRET_FORMAT_PREFIX}<pattern id>, one per secret pattern: "
        f"{', '.join(SECRET_FORMAT_PREFIX + pid for pid, _ in SECRET_PATTERNS)}\n"
        f"Tombstone codes: {', '.join(TOMBSTONE_REASONS)}\n"
        "Ciphertext bodies (direct messages, capsules) are hidden only for: order\n"
        f"Suspension codes: {', '.join(SUSPENSION_REASONS)}\n"
        f"Freeze codes: {', '.join(FREEZE_REASONS)}\n"
        f"Key revocation codes: {', '.join(ident.REVOKE_REASONS)}\n"
        f"Notice outcome codes: {', '.join(NOTICE_OUTCOMES)}\n"
        f"Audit outcome codes: {', '.join(AUDIT_OUTCOMES)}\n"
        f"Encryption schemes: {', '.join(ENCRYPTION_SCHEMES)}\n"
    )
    return text.encode("ascii")


def _close_quietly(conn: sqlite3.Connection) -> None:
    try:
        conn.close()
    except sqlite3.Error:
        pass


def write_text_atomically(path: str | Path, text: str) -> None:
    """Replace *path* with *text* (UTF-8) in one step, readable by all (public keys only)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.{secrets.token_hex(4)}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass

_HEX64 = re.compile(r"[0-9a-f]{64}")


def _is_kid(value: Any) -> bool:
    """An Ed25519 ``did:key`` (AICS-1 section 3.1: the bare signing DID is the ``kid``)."""
    return keys.is_did_key(value)


# The members of each envelope payload ``Q`` (exactly these: the closed AICS-1 section 5.3 schemas, and section
# 20.3 for the SUP-1 profile; section 4.1 puts the origin and the entry type in ``protected``).

#: ``name.claim`` (AICS-1 section 5.3).
_CLAIM_KEYS = frozenset(
    {"name_norm", "prev_event_index", "ed25519", "x25519", "tier", "recovery_kid", "recovery_pop", "initial_grant"}
)
#: ``key.rotate`` with mode ``rotate`` (AICS-1 section 5.3).
_ROTATE_KEYS = frozenset(
    {"mode", "name_norm", "prev_event_index", "new_ed25519", "new_x25519", "new_tier", "sig_old", "sig_new"}
)
#: ``key.rotate`` with mode ``upgrade`` (AICS-1 section 5.3): ``secret_check`` is the policy key's statement
#: that the old secret was checked, obtained before the new key signs (sections 7.2 and 11.4).
_UPGRADE_KEYS = _ROTATE_KEYS | {"secret_check"}
_REVOKE_KEYS = frozenset({"name_norm", "prev_event_index", "reason_code"})
_X25519_KEYS = frozenset({"name_norm", "prev_event_index", "new_x25519"})
#: A claim's ``initial_grant``, a ``grant_spec`` (AICS-1 section 5.3).
_GRANT_KEYS = frozenset({"sender_kid", "max", "expires"})
#: ``grant`` (AICS-1 sections 5.3 and 9): signed by the owner; ``max`` 0 revokes; ``prev_grant_index`` names the
#: latest grant for the exact ``(owner_kid, sender_kid)`` pair, or is null.
_GRANT_LEAF_KEYS = frozenset({"owner_kid", "sender_kid", "max", "expires", "prev_grant_index"})
#: ``post`` (AICS-1 section 5.3): the body ``{channel, title, text}`` is off-leaf.
_POST_KEYS = frozenset({"channel_sha256", "parent_index", "body_hash", "size", "title_sha256"})
#: ``poll`` (AICS-1 section 5.3): the body ``{channel, title, text, options}`` is off-leaf.
_POLL_KEYS = frozenset(
    {"channel_sha256", "body_hash", "size", "title_sha256", "options_sha256", "closes", "min_key_age_seconds", "pow_bits"}
)
#: ``vote`` (AICS-1 section 5.3): a zero-based ``option``; the optional body is ``{reason}``.
_VOTE_KEYS = frozenset({"poll_index", "option", "pow_nonce", "reason_sha256", "body_hash", "size"})
#: ``dm`` (AICS-1 section 5.3): ``seq``/``prev`` repeat the envelope's; ``grant_index`` names the grant used.
_DM_KEYS = frozenset(
    {"to_kid", "to_key_leaf_index", "encryption", "eph_pk", "ct_hash", "size", "seq", "prev", "grant_index"}
)
#: ``capsule`` (AICS-1 section 5.3): ``prev_capsule_index`` names the slot's previous capsule leaf, or is null.
_CAPSULE_KEYS = frozenset(
    {
        "owner_kid",
        "to_key_leaf_index",
        "key_hash",
        "encryption",
        "eph_pk",
        "ct_hash",
        "size",
        "expires",
        "prev_capsule_index",
    }
)
#: ``report`` of kind ``owner_action`` (AICS-1 sections 5.3 and 20.4), signed by the owner: hashes and an amount.
_OWNER_ACTION_KEYS = frozenset({"kind", "action", "request_hash", "result_hash", "asset_hash", "amount", "quote_index"})
#: ``sup.task`` (AICS-1 section 20.3), signed by the owner: the body ``{title, text}`` is off-leaf.
_TASK_KEYS = frozenset({"body_hash", "size", "asset_hash", "reward", "max_awards", "closes"})
#: ``sup.credit`` of source ``task`` (AICS-1 section 20.3), signed by the owner: an award for a post.
_AWARD_KEYS = frozenset({"source", "account_kid", "task_index", "submission_index", "asset_hash", "amount"})
#: ``sup.spend`` (AICS-1 section 20.3), signed by the paying account's current key.
_SPEND_KEYS = frozenset({"purpose", "ref_index", "asset_hash", "amount", "bytes"})
_B64U_TEXT = re.compile(r"[A-Za-z0-9_-]*")
#: First line of a binary age v1 file (C2SP age v1.1.0).
_AGE_MAGIC = b"age-encryption.org/v1\n"


def _canonical_b64u(text: Any) -> bytes | None:
    """Bytes of canonical unpadded base64url *text*, or ``None`` for anything else."""
    if not isinstance(text, str) or not _B64U_TEXT.fullmatch(text) or len(text) % 4 == 1:
        return None
    raw = keys.b64u_decode(text)
    return raw if keys.b64u_encode(raw) == text else None


def decode_u64(text: Any) -> bytes | None:
    """``U64`` (canonical unpadded base64url, AICS-1 section 2) decoded, or ``None`` when *text* is not that."""
    return _canonical_b64u(text)


def _check_proof_shape(proof: Any, field: str) -> None:
    """A ``proof`` member (AICS-1 section 7.1): ``{scheme: ed25519 | sshsig, signature: U64}``, else ``malformed``.

    Whether it verifies is checked afterwards (``bad_signature``).
    """
    if (
        not isinstance(proof, Mapping)
        or set(proof) != {"scheme", "signature"}
        or proof["scheme"] not in ident.PROOF_SCHEMES
        or not _canonical_b64u(proof["signature"])
    ):
        raise ValueError(f"{field} must be a proof {{scheme: ed25519 or sshsig, signature: unpadded base64url}}")


def _age_v1_shape(raw: bytes) -> bool:
    """A binary age v1 file with exactly one native X25519 recipient stanza (AICS-1 section 8.1).

    The server cannot decrypt; this only refuses bytes that are not an age file
    to the one recipient, such as cleartext labelled ``age-v1``.
    """
    if not raw.startswith(_AGE_MAGIC):
        return False
    mac = raw.find(b"\n--- ", len(_AGE_MAGIC) - 1)
    if mac < 0:
        return False
    stanza_lines = raw[len(_AGE_MAGIC) : mac].split(b"\n")
    if len(stanza_lines) != 2 or not stanza_lines[0].startswith(b"-> "):
        return False
    args = stanza_lines[0][3:].split(b" ")
    if len(args) != 2 or args[0] != b"X25519" or len(args[1]) != 43:
        return False
    try:
        share = base64.b64decode(args[1] + b"=", validate=True)
        wrapped = base64.b64decode(stanza_lines[1] + b"=", validate=True)
    except ValueError:
        return False
    if len(share) != 32 or len(wrapped) != 32:
        return False
    header_end = raw.find(b"\n", mac + 1)
    return header_end > 0 and len(raw) - (header_end + 1) >= 16 + 17


def _utc_iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if ts is None else ts))


def _sha256(data: str | bytes) -> str:
    return ident.sha256_hex(data)


def text_sha256(text: str) -> str:
    """``hexH(UTF8(text))``: the digest of a channel, title, option or reason (AICS-1 section 5.3: no JSON quotes)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def _is_uint(value: Any, maximum: int = 2**53 - 1) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum


def _require(condition: bool, message: str) -> None:
    """A schema rule of a payload: refused ``malformed`` (AICS-1 section 17.2: syntax/schema), HTTP 400."""
    if not condition:
        raise ValueError(message)


def _require_index(value: Any, field: str, *, nullable: bool = False) -> None:
    _require(_is_uint(value) or (nullable and value is None), f"{field} must be an index (a uint){' or null' if nullable else ''}")


def _require_hash(value: Any, field: str, *, nullable: bool = False) -> None:
    _require(
        _is_hex64(value) or (nullable and value is None),
        f"{field} must be 64 lowercase hex characters{' or null' if nullable else ''}",
    )


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON member {key!r}")
        out[key] = value
    return out


def _utf8_string(value: Any) -> bool:
    """A JSON string that is valid Unicode (no lone surrogate), so its UTF-8 bytes exist."""
    if not isinstance(value, str):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def check_body_digest(q: Mapping[str, Any], raw: Any, what: str) -> bytes:
    """A public body against the ``body_hash`` and ``size`` its payload commits to (AICS-1 sections 4.3 and 5.3).

    ``too_large`` over :data:`PUBLIC_BODY_BYTES`; ``digest_mismatch`` when the
    hash or the size differ from the bytes received; ``malformed`` without a body.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise Rejected("malformed", f"a {what} carries its body (the exact JCS bytes its body_hash names)", status=400)
    raw = bytes(raw)
    if len(raw) > PUBLIC_BODY_BYTES:
        raise Rejected("too_large", f"a public body is at most {PUBLIC_BODY_BYTES} bytes; this {what} body is {len(raw)}")
    if hashlib.sha256(raw).hexdigest() != q.get("body_hash") or len(raw) != q.get("size"):
        raise Rejected("digest_mismatch", f"body_hash and size of the {what} must be hexH and the length of its body")
    return raw


def parse_public_body(raw: bytes, members: tuple[str, ...], what: str) -> dict[str, Any]:
    """A public body's JSON value: exactly *members*, valid UTF-8, and exactly its own JCS bytes (AICS-1 section 5.3).

    Refused ``malformed`` otherwise.  The digest is checked first, against the
    payload (:func:`check_body_digest`).
    """
    try:
        obj = loads_bounded(raw.decode("utf-8"), object_pairs_hook=_strict_pairs)
    except (UnicodeDecodeError, ValueError) as exc:
        raise Rejected("malformed", f"the {what} body is not a UTF-8 JSON object: {exc}", status=400) from None
    if not isinstance(obj, dict) or set(obj) != set(members):
        raise Rejected("malformed", f"the {what} body is the JCS JSON object {{{', '.join(members)}}}", status=400)
    try:
        canonical = canonicalize(obj)
    except (ValueError, TypeError) as exc:
        raise Rejected("malformed", f"the {what} body cannot be canonicalised: {exc}", status=400) from None
    if canonical != raw:
        raise Rejected("malformed", f"the {what} body must be exactly the JCS (RFC 8785) bytes of its JSON object", status=400)
    return obj


def _check_channel(channel: Any, q: Mapping[str, Any], what: str) -> str:
    """``channel`` is a slug of the name pattern and ``channel_sha256`` its ``hexH(UTF8(channel))`` (AICS-1 section 5.3)."""
    if not isinstance(channel, str) or not ident.NAME_PATTERN.fullmatch(channel):
        raise Rejected("malformed", f"the {what} channel must be a slug: 1-63 of a-z 0-9 _ -, starting and ending with a letter or digit", status=400)
    if q.get("channel_sha256") != text_sha256(channel):
        raise Rejected("digest_mismatch", "channel_sha256 must be the SHA-256 of the channel's UTF-8 bytes")
    return channel


def validate_post_body(q: Mapping[str, Any], raw: Any) -> dict[str, Any]:
    """The body of a ``post``: ``{channel, title, text}``, ``title`` a string or null, digests matching ``Q``."""
    raw = check_body_digest(q, raw, "post")
    body = parse_public_body(raw, POST_BODY_MEMBERS, "post")
    _check_channel(body["channel"], q, "post")
    title, text = body["title"], body["text"]
    if not _utf8_string(text) or not (title is None or _utf8_string(title)):
        raise Rejected("malformed", "a post body's text is a string and its title a string or null", status=400)
    expected = None if title is None else text_sha256(title)
    if q.get("title_sha256") != expected:
        raise Rejected("digest_mismatch", "title_sha256 must be the SHA-256 of the title's UTF-8 bytes (null without a title)")
    return body


def validate_poll_body(q: Mapping[str, Any], raw: Any) -> dict[str, Any]:
    """The body of a ``poll``: ``{channel, title, text, options}``, every digest matching ``Q`` in order."""
    raw = check_body_digest(q, raw, "poll")
    body = parse_public_body(raw, POLL_BODY_MEMBERS, "poll")
    _check_channel(body["channel"], q, "poll")
    title, text, options = body["title"], body["text"], body["options"]
    if not _utf8_string(title) or not _utf8_string(text):
        raise Rejected("malformed", "a poll body's title and text are strings", status=400)
    if not isinstance(options, list) or not all(_utf8_string(o) for o in options):
        raise Rejected("malformed", "a poll body's options are a list of strings", status=400)
    if q.get("title_sha256") != text_sha256(title):
        raise Rejected("digest_mismatch", "title_sha256 must be the SHA-256 of the title's UTF-8 bytes")
    if q.get("options_sha256") != [text_sha256(o) for o in options]:
        raise Rejected("digest_mismatch", "options_sha256 must be the SHA-256 of each option's UTF-8 bytes, in order")
    return body


def validate_vote_body(q: Mapping[str, Any], raw: Any) -> dict[str, Any] | None:
    """The body of a ``vote``: ``None`` when ``body_hash`` is null, else ``{reason}`` matching ``reason_sha256``."""
    if q.get("body_hash") is None:
        if raw:
            raise Rejected("malformed", "a vote without a body (body_hash null) carries no body bytes", status=400)
        return None
    raw = check_body_digest(q, raw, "vote")
    body = parse_public_body(raw, VOTE_BODY_MEMBERS, "vote")
    if not _utf8_string(body["reason"]):
        raise Rejected("malformed", "a vote body's reason is a string", status=400)
    if q.get("reason_sha256") != text_sha256(body["reason"]):
        raise Rejected("digest_mismatch", "reason_sha256 must be the SHA-256 of the reason's UTF-8 bytes")
    return body


def validate_task_body(q: Mapping[str, Any], raw: Any) -> dict[str, Any]:
    """The body of a ``sup.task``: ``{title, text}``, both strings, ``title`` nonempty (AICS-1 section 20.3)."""
    raw = check_body_digest(q, raw, "task")
    body = parse_public_body(raw, TASK_BODY_MEMBERS, "task")
    if not _utf8_string(body["title"]) or not body["title"] or not _utf8_string(body["text"]):
        raise Rejected("malformed", "a task body's title is a nonempty string and its text a string", status=400)
    return body


def validate_completion_body(q: Mapping[str, Any], raw: Any) -> dict[str, Any]:
    """The public completion body of an owner action: ``{text}``, ``result_hash = hexH(J({text}))`` (section 20.4)."""
    if not isinstance(raw, (bytes, bytearray)):
        raise Rejected("malformed", "a completion carries its body, the JCS bytes of {text}", status=400)
    raw = bytes(raw)
    if len(raw) > PUBLIC_BODY_BYTES:
        raise Rejected("too_large", f"a public body is at most {PUBLIC_BODY_BYTES} bytes; this completion body is {len(raw)}")
    if hashlib.sha256(raw).hexdigest() != q.get("result_hash"):
        raise Rejected("digest_mismatch", "result_hash must be hexH of the completion body J({text})")
    body = parse_public_body(raw, COMPLETION_BODY_MEMBERS, "completion")
    if not _utf8_string(body["text"]):
        raise Rejected("malformed", "a completion body's text is a string", status=400)
    return body


#: The public texts of a body, as the secret-format scan reads them.
def body_texts(body: Mapping[str, Any] | None) -> list[str]:
    if body is None:
        return []
    out: list[str] = []
    for value in body.values():
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, list):
            out.extend(v for v in value if isinstance(v, str))
    return out


def vote_pow_digest(origin: str, poll_index: int, kid: str, option: int, pow_nonce: str) -> bytes:
    """``H(UTF8("AICS-1 vote\\n") || J({origin, poll_index, kid, option, pow_nonce}))`` (AICS-1 section 5.3)."""
    return hashlib.sha256(
        VOTE_POW_CONTEXT
        + canonicalize({"origin": origin, "poll_index": poll_index, "kid": kid, "option": option, "pow_nonce": pow_nonce})
    ).digest()


def leading_zero_bits(digest: bytes) -> int:
    """How many leading bits of *digest* are zero."""
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + 8 - byte.bit_length()
    return bits


class Refusal(Exception):
    """A write refused under a published acceptance rule.

    ``reason_code`` is from :data:`REFUSAL_REASONS`; ``conflict_index`` names the
    accepted event (or earlier refusal) the decision rests on; ``leaf`` is the
    logged ``refusal`` entry with its Merkle proof, or ``None`` when an earlier
    refusal leaf already covers this exact request.
    """

    def __init__(
        self,
        reason_code: str,
        message: str,
        *,
        conflict_index: int | None = None,
        leaf: dict[str, Any] | None = None,
        status: int = 409,
        retry_after: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message
        self.conflict_index = conflict_index
        self.leaf = leaf
        self.status = status
        self.retry_after = retry_after
        self.extra = dict(extra or {})

    def detail(self) -> dict[str, Any]:
        return {
            **self.extra,
            "error": self.reason_code,
            "message": self.message,
            "conflict_index": self.conflict_index,
            "refusal": self.leaf,
        }


@dataclass(frozen=True)
class _Attempt:
    """Who tried what, as a refusal leaf names it (AICS-1 section 10.2): hashes and identifiers, never the body.

    ``envelope_hash`` is ``hexH(J(E))`` of the refused envelope; for a signed
    request without one it is the hash of the request bytes, and
    ``request_hash`` is that same hash (``None`` whenever there is an
    envelope; never the hash of bytes that carried a secret).  ``kid``,
    ``nonce`` and ``expires`` are the authenticated attempt's: the signing key
    (or the unverified identity whose secret checked) and the tuple whose
    record the refusal backs; all three are ``None`` for an attempt that did
    not authenticate (AICS-1 section 10.2: never from an unverified assertion).
    """

    envelope_hash: str
    request_hash: str | None
    kid: str | None
    nonce: str | None
    expires: int | None


class _Window:
    """A sliding window: at most ``count`` events in any ``interval`` seconds."""

    __slots__ = ("count", "interval", "times")

    def __init__(self, count: int, interval: int) -> None:
        self.count = count
        self.interval = interval
        self.times: deque[float] = deque(maxlen=count)

    def full(self, now: float) -> bool:
        return len(self.times) == self.count and now - self.times[0] < self.interval

    def add(self, now: float) -> None:
        self.times.append(now)

    def retry_after(self, now: float) -> int:
        return max(1, math.ceil(self.times[0] + self.interval - now)) if self.full(now) else 0

    def idle(self, now: float) -> bool:
        return not self.times or now - self.times[-1] >= self.interval


class NotFound(LookupError):
    """The named record does not exist."""


class Rejected(ValueError):
    """A signed submission fails a published acceptance rule; its refusal leaf carries *reason_code*.

    Raised inside the signed write methods (:func:`_signed_write`), which turn
    it into a logged ``refusal``.  ``status`` is the HTTP status of the
    answer (default: :data:`REFUSAL_STATUS` of the code), ``conflict_index``
    the leaf the decision rests on, ``cause`` a finer machine string for the
    agent (off the log).
    """

    def __init__(
        self,
        reason_code: str,
        message: str,
        *,
        status: int | None = None,
        conflict_index: int | None = None,
        cause: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status = status
        self.conflict_index = conflict_index
        self.cause = cause


class CredentialError(PermissionError):
    """A shared secret did not check.  Credential controls are answered without a leaf (AICS-1 section 10.2)."""


#: Failures of a signed write that are decisions on the submission: logged as ``refusal`` leaves.
_ACCEPTANCE_FAILURES = (Rejected, ValueError, PermissionError, NotFound, RuntimeError)
#: Failures that are not decisions on the submission (availability, a credential, a transient state): no leaf.
_NOT_DECISIONS = (
    LogUnavailable,
    LogIntegrityError,
    ident.SecretCheckBusy,
    CredentialError,
    pay.PaymentUnavailable,
    pay.PaymentPending,
)


def _signed_write(method: Callable[..., Any]) -> Callable[..., Any]:
    """Make every acceptance failure of a signed write (first argument a :class:`SignedContext`) a refusal leaf.

    AICS-1 section 10.2 and DESIGN.md G2/G4: once a request is authenticated
    and its nonce consumed, a failed rule is answered as a policy-signed
    ``refusal`` leaf, never a bare error.  The per-key admission window (or,
    for a claimant, the registration window) runs in front of any such leaf,
    so a stream of failing requests cannot grow the log faster than the
    published limits (:meth:`SanctuaryDB.refuse_failure`).  Availability
    failures, credential failures and transient states stay unlogged.
    """

    @functools.wraps(method)
    def wrapper(self: "SanctuaryDB", ctx: Any, *args: Any, **kwargs: Any) -> Any:
        state = self._write_state
        if getattr(state, "ctx", None) is not None:  # nested: the outer write decides
            return method(self, ctx, *args, **kwargs)
        state.ctx, state.admitted, state.registered = ctx, False, False
        try:
            return method(self, ctx, *args, **kwargs)
        except (Refusal, *_NOT_DECISIONS):
            raise
        except ServiceError as exc:
            if exc.status >= 500:
                raise
            self.refuse_failure(ctx, exc)
        except (*_ACCEPTANCE_FAILURES, pay.PaymentNotVerified) as exc:
            self.refuse_failure(ctx, exc)
        finally:
            state.ctx = None

    return wrapper


@dataclass(frozen=True)
class SignedContext:
    """A submission whose authentication has been checked: an RFC 9421 request, a gate envelope or a fallback write.

    ``kid`` is the signer's ``did:key`` (the HTTP ``keyid`` and, for a write
    that carries one, the envelope's ``protected.kid``: they are equal), or the
    ``unverified:`` identifier of a shared-secret write.  ``t`` is the
    submission time the server fixed before acceptance (AICS-1 section 4.3):
    freshness was checked at ``t``, and an accepted envelope's entry carries
    ``ts = t``.  ``expires`` is how long the nonce must be remembered.
    ``scheme`` is the envelope's ``auth.scheme`` (``None`` without an envelope).
    ``fields`` is the JSON request object without its ``envelope`` member.
    ``public_key_b64u`` is ``None`` for a shared-secret write.
    """

    kid: str
    public_key_b64u: str | None
    nonce: str
    expires: int
    request_hash: str | None
    fields: dict[str, Any]
    envelope: dict[str, Any] | None = None
    envelope_hash: str | None = None
    role: str = "agent"  # "agent" | "owner" | "claimant" | "unverified"
    t: int = 0
    scheme: str | None = None

    @property
    def payload(self) -> dict[str, Any]:
        return self.envelope["payload"] if self.envelope else {}

    @property
    def entry_type(self) -> str | None:
        return self.envelope["protected"]["type"] if self.envelope else None

    @classmethod
    def of_envelope(
        cls,
        checked: ev.Checked,
        *,
        t: int,
        role: str,
        public_key: Any = None,
        fields: dict[str, Any] | None = None,
    ) -> "SignedContext":
        """The context of a checked envelope (:mod:`aics_server.envelopes`) submitted at *t*, as both bindings build it."""
        return cls(
            kid=checked.kid,
            public_key_b64u=keys.format_public_key(keys.as_public_key(public_key)) if public_key is not None else None,
            nonce=checked.nonce,
            expires=checked.expires,
            request_hash=None,
            fields=dict(fields or {}),
            envelope=checked.envelope,
            envelope_hash=checked.envelope_hash,
            role=role,
            t=t,
            scheme=checked.scheme,
        )


@dataclass(frozen=True)
class EntryBody:
    """An entry's off-leaf body and its state, as every binding reports it (:meth:`SanctuaryDB.entry_body`).

    ``kind`` is ``public`` (a public text body), ``ciphertext`` (a direct
    message or capsule) or ``document`` (a policy document or the report a
    freeze or audit names), or ``None`` for an entry without a body; ``digest``
    is the hash its entry names it by.  ``state`` is ``available`` (``data``
    holds the exact bytes), ``tombstoned`` (``tombstone_index`` and
    ``reason_code`` name the tombstone, AICS-1 section 10.3), ``expired``
    (``policy_index`` names the policy whose retention rule ended it, section
    8.2), ``unavailable`` (missing for no logged reason: an availability
    failure) or ``None``.  ``in_bundle``: a section 14.3 bundle's
    ``body_or_ct`` can carry it (the entry names it by ``body_hash``,
    ``ct_hash`` or ``document_hash`` with a ``size``).
    """

    kind: str | None
    digest: str | None
    state: str | None
    data: bytes | None
    tombstone_index: int | None
    reason_code: str | None
    policy_index: int | None
    in_bundle: bool = False

    NONE: ClassVar["EntryBody"]

    def status(self) -> dict[str, Any] | None:
        """The body's status as the HTTP binding states it: ``{state, tombstone_index, reason_code, policy_index}``.

        ``GET /v2/bodies/{hash}`` answers it as JSON and ``GET /v2/entries/{index}`` in its
        ``X-AICS-Body-Status`` header; ``None`` for an entry without an off-leaf body.
        """
        if self.state is None:
            return None
        return {
            "state": self.state,
            "tombstone_index": self.tombstone_index,
            "reason_code": self.reason_code,
            "policy_index": self.policy_index,
        }


EntryBody.NONE = EntryBody(None, None, None, None, None, None, None)


class SanctuaryDB:
    """SQLite (WAL) storage plus the live RFC 9162 transparency log; the single writer.

    Configuration (arguments win over the environment):

    * ``db_path`` / ``AICS_DB_PATH``: default ``./data/aics.db`` (relative to the
      working directory);
    * ``tiles_dir`` / ``AICS_TILES_DIR``: the published tlog-tiles tree, default
      ``<db dir>/<db name>-tiles``;
    * ``origin`` / ``AICS_ORIGIN``: the log origin, default :data:`DEFAULT_ORIGIN`;
    * ``charter`` / ``AICS_CHARTER_FILE``: the charter document leaf 0 names when
      the log is created, default :func:`default_charter_text`;
    * ``AICS_SERVER_SEED_HEX`` (64 hex characters) or ``<db dir>/server_master.seed``
      (made on first start): the seed of the log and policy keys;
    * ``owner_public_key`` / ``AICS_OWNER_PUBKEY`` (read by the app factory);
    * ``AICS_TILES_AUDIT``: ``full`` (default) re-checks every tile against the
      leaf table at start-up, ``edge`` only the right edge and the root;
    * ``limits`` / ``AICS_LIMITS_FILE`` (JSON): the published limits, see
      :data:`DEFAULT_LIMITS` and :func:`load_limits`;
    * ``payments``: the on-chain verifiers and SUP rate for contributions,
      default :meth:`aics_server.payments.PaymentsConfig.from_env` (no address
      or endpoint in code; nothing configured means nothing is creditable).
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        owner_public_key: Any = None,
        tiles_dir: str | Path | None = None,
        origin: str | None = None,
        charter: bytes | str | None = None,
        limits: Mapping[str, Any] | None = None,
        payments: pay.PaymentsConfig | None = None,
        swarms_enabled: bool = False,
    ) -> None:
        if db_path is None:
            db_path = os.environ.get("AICS_DB_PATH") or os.path.join("data", "aics.db")
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if tiles_dir is None:
            tiles_dir = os.environ.get("AICS_TILES_DIR") or self.db_path.parent / f"{self.db_path.stem}-tiles"
        self.tiles_dir = Path(tiles_dir)
        published_root = self.tiles_dir.resolve()
        for private in (self.db_path.resolve(), (self.db_path.parent / "server_master.seed").resolve()):
            if private.is_relative_to(published_root):
                raise ValueError(
                    f"AICS_TILES_DIR ({self.tiles_dir}) must not contain {private.name}: the tiles directory is published"
                )
        self.origin = origin or os.environ.get("AICS_ORIGIN") or DEFAULT_ORIGIN
        # One writer process per database (DESIGN.md section 4.1); released with this object.
        weakref.finalize(self, acquire_writer_lock(f"{self.db_path}.writer-lock"))
        self._lock = threading.RLock()
        self._pending: list[bytes] | None = None
        self._nonce_inserts = 0
        self.started_at = time.time()
        # Published limits and their in-memory windows (per key, or global).  A
        # restart forgets the windows; the leaves are what record decisions.
        self.limits = load_limits(limits)
        self._admitted: dict[str, _Window] = {}
        self._attempts: dict[str, _Window] = {}
        # limits.registrations counts the registration attempts of each submitting key (AICS-1 section 13.1); the
        # global pre-identity bucket (limits.preidentity) bounds every registration and keyless request together.
        self._registration_attempts: dict[str, _Window] = {}
        self._preidentity = _Window(self.limits["preidentity"]["count"], self.limits["preidentity"]["interval_seconds"])
        # Notice intake has its own, smaller global window (limits.notices): a flood of notices cannot use up
        # the pre-identity bucket of claims, nor the other way round.
        self._notice_intake = _Window(self.limits["notices"]["count"], self.limits["notices"]["interval_seconds"])
        # (kid, reason) -> (cause, refusal leaf index): a refusal with an ongoing
        # cause (rate window, suspension, freeze) is logged once per key, not per attempt.
        self._refusal_cache: dict[tuple[str, str], tuple[Any, int]] = {}
        # Refusals of envelopes that did not authenticate (POST /v2/entries): their own small global window, the
        # published limits.unauthenticated (refuse_unauthenticated).  The leaf each envelope got is in `refusals`.
        self._unauthenticated_window = _Window(
            self.limits["unauthenticated"]["count"], self.limits["unauthenticated"]["interval_seconds"]
        )
        self._admissions = 0
        self._frozen_index: int | None = None
        # The ciphertext-byte budget (AICS-1 section 8.2): the bytes of stored ciphertext bodies, kept current on
        # every store and recounted by housekeeping, and the resource-exhaustion state it reports.
        self._ciphertext_total = 0
        self._exhaustion: dict[str, Any] | None = None
        # The signed write running in this thread and whether it passed admission
        # (:func:`_signed_write`, :meth:`refuse_failure`).
        self._write_state = threading.local()
        # The /v2/stats counts: computed on a read-only connection, cached (get_db_counts).
        self._stats_lock = threading.Lock()
        self._stats_cache: tuple[float, dict[str, Any]] | None = None
        # Aggregate counters (DESIGN.md section 8), kept in memory and written to
        # telemetry_counters by housekeeping: counting a request costs no disk sync.
        self._counter_lock = threading.Lock()
        self._counter_buffer: dict[str, int] = {}
        # Nonces of signed reads, written to the nonces table in batches (a read
        # writes no leaf; one fsync per read would serialize reads behind writes).
        self._read_nonces: dict[tuple[str, str], int] = {}
        self._read_nonces_since = time.monotonic()

        # Service keys: derived from one seed with distinct HKDF labels.  The
        # log key signs checkpoint notes and receipts only (and once, the
        # charter's log_sig); the policy key signs service statements (charter,
        # refusals, tombstones, suspensions, freezes, reports, attestations).
        # Every kid is the key's did:key (AICS-1 section 3.1); ``*_did`` names
        # the same string.
        master_secret = self._server_seed()
        self.server_key = keys.derive_agent_key(master_secret, LOG_KEY_LABEL)
        self.server_pub = self.server_key.public_key()
        self.server_kid = keys.did_key(self.server_pub)
        self.server_did = self.server_kid

        self.policy_key = keys.derive_agent_key(master_secret, POLICY_KEY_LABEL)
        self.policy_pub = self.policy_key.public_key()
        self.policy_kid = keys.did_key(self.policy_pub)
        self.policy_did = self.policy_kid
        self.policy_public_key_b64u = keys.format_public_key(self.policy_pub)
        # The key of the keyed hash a contribution leaf carries (decision 17): a
        # plain hash of a transaction hash could be matched against the chain.
        self._contribution_key = HKDF(
            algorithm=crypto_hashes.SHA256(), length=32, salt=None, info=CONTRIBUTION_KEY_LABEL
        ).derive(master_secret)
        del master_secret

        # The voluntary SUP service: on-chain verifiers (fail closed) and the asset descriptor.
        self.payments = payments if payments is not None else pay.PaymentsConfig.from_env()
        self.sup_asset = sup_asset_descriptor(self.origin)
        self.sup_asset_hash = _sha256(self.sup_asset)

        # The owner key (decision 3): configured, never generated here.
        self.owner_public_key = None
        self.owner_kid: str | None = None
        self.owner_did: str | None = None
        self.owner_public_key_b64u: str | None = None
        if owner_public_key is not None and owner_public_key != "":
            if isinstance(owner_public_key, str):
                owner = keys.parse_public_key_text(owner_public_key)
            else:
                owner = keys.require_valid_public_key(owner_public_key)
            self.owner_public_key = owner
            self.owner_kid = keys.did_key(owner)
            self.owner_did = self.owner_kid
            self.owner_public_key_b64u = keys.format_public_key(owner)
            if self.owner_kid in (self.server_kid, self.policy_kid):
                raise ValueError("the owner key must differ from the log and policy keys")

        self._log = TlogStore(
            origin=self.origin,
            log_key=self.server_key,
            tiles_dir=self.tiles_dir,
            audit=os.environ.get("AICS_TILES_AUDIT") or "full",
        )
        self.server_vkey = self._log.vkey_text

        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        weakref.finalize(self, _close_quietly, self._conn)
        self._init_schema()
        self._boot_log()
        self.swarms = SwarmStore(self, requested=swarms_enabled)
        document, explicit_charter = self._charter_bytes(charter)
        self._genesis(document, explicit_charter=explicit_charter)
        self._rebuild_recent_nonces()
        self._frozen_index = self._load_freeze_state()
        self._ciphertext_total = self._stored_ciphertext_bytes()
        self._last_housekeeping = 0
        self.housekeeping(force=True)

    def _server_seed(self) -> bytes:
        """The service seed: ``AICS_SERVER_SEED_HEX``, else the seed file next to the database (made once, 0600)."""
        server_seed_hex = os.environ.get("AICS_SERVER_SEED_HEX", "").strip()
        if server_seed_hex:
            if not re.fullmatch(r"[0-9a-fA-F]{64}", server_seed_hex):
                raise ValueError("AICS_SERVER_SEED_HEX must be 64 hex characters (32 bytes)")
            return bytes.fromhex(server_seed_hex)
        seed_file = self.db_path.parent / "server_master.seed"
        try:
            return seed_file.read_bytes()
        except FileNotFoundError:
            pass
        # First start: write the seed to a private temporary file, then link it
        # into place, so the seed file appears complete or not at all.
        seed = secrets.token_bytes(32)
        tmp = seed_file.with_name(f".{seed_file.name}.{secrets.token_hex(4)}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(seed)
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(tmp, seed_file)
            except FileExistsError:  # another database in this directory made it first
                return seed_file.read_bytes()
        finally:
            tmp.unlink()
        dir_fd = os.open(seed_file.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        return seed

    @staticmethod
    def _charter_bytes(charter: bytes | str | None) -> tuple[bytes, bool]:
        """The charter document and whether it was given (argument or ``AICS_CHARTER_FILE``) rather than the built-in default."""
        explicit = charter is not None
        if charter is None:
            path = (os.environ.get("AICS_CHARTER_FILE") or "").strip()
            explicit = bool(path)
            charter = Path(path).read_bytes() if path else default_charter_text()
        if isinstance(charter, str):
            charter = charter.encode("utf-8")
        if not charter:
            raise ValueError("the charter document is empty")
        charter.decode("utf-8")  # a text document: refuse anything that is not UTF-8
        return bytes(charter), explicit

    # ------------------------------------------------------------------
    # schema, transactions, leaves
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._lock:
            existing = {
                r["name"]
                for r in self._conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
            }
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if existing and version != SCHEMA_VERSION:
                raise RuntimeError(
                    f"{self.db_path} holds a database of layout {version}, not {SCHEMA_VERSION}. "
                    "The v2 log starts fresh (DECISIONS.md #6): use a new AICS_DB_PATH."
                )
            self._conn.executescript(
                f"""
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=FULL;
                PRAGMA foreign_keys=ON;
                PRAGMA user_version={SCHEMA_VERSION};

                -- The log: the writer's source of truth.  Tiles and checkpoints
                -- are derived from it (tlog_store.py).
                CREATE TABLE IF NOT EXISTS tlog_leaves (
                    leaf_index INTEGER PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    actor_kid TEXT NOT NULL,
                    leaf_json TEXT NOT NULL,
                    leaf_hash_hex TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS tlog_leaves_by_time ON tlog_leaves (created_at);

                -- Off-leaf documents named by policy leaves (leaf 0: the charter).
                CREATE TABLE IF NOT EXISTS policy_documents (
                    leaf_index INTEGER PRIMARY KEY,
                    kind TEXT NOT NULL,
                    document_sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    document BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS policy_documents_by_hash ON policy_documents (document_sha256);

                -- One row per claimed name.  Key state is not here: it is read
                -- from the key-event leaves (key_events projects them).
                CREATE TABLE IF NOT EXISTS names (
                    name_norm TEXT PRIMARY KEY,
                    claim_index INTEGER NOT NULL UNIQUE,
                    unverified_id TEXT UNIQUE,
                    secret_hash TEXT,
                    recovery_kid TEXT,
                    created_at TEXT NOT NULL
                );

                -- Projection of name.claim / key.rotate / x25519.rotate / key.revoke
                -- leaves.  UNIQUE (name_norm, prev_event_index): an event has at
                -- most one successor, so the first one in the log wins.
                CREATE TABLE IF NOT EXISTS key_events (
                    leaf_index INTEGER PRIMARY KEY,
                    name_norm TEXT NOT NULL REFERENCES names (name_norm),
                    event_type TEXT NOT NULL,
                    prev_event_index INTEGER,
                    kid_after TEXT,
                    tier_after TEXT NOT NULL,
                    ed25519_b64u TEXT,
                    x25519_b64u TEXT,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    UNIQUE (name_norm, prev_event_index)
                );
                CREATE INDEX IF NOT EXISTS key_events_by_name ON key_events (name_norm, leaf_index);

                -- Every Ed25519 key ever bound to a name, by its did:key.  A key is bound once.
                CREATE TABLE IF NOT EXISTS bound_keys (
                    kid TEXT PRIMARY KEY,
                    public_key_b64u TEXT NOT NULL UNIQUE,
                    name_norm TEXT NOT NULL REFERENCES names (name_norm),
                    bound_index INTEGER NOT NULL,
                    retired_index INTEGER
                );

                -- Per (origin, kid), one origin per database: the last accepted envelope's seq, its
                -- hexH(J(E)) and its leaf (AICS-1 section 4.2).  Unverified identities and the
                -- service keys have chains too.
                CREATE TABLE IF NOT EXISTS envelope_chain (
                    kid TEXT PRIMARY KEY,
                    last_seq INTEGER NOT NULL,
                    last_hash TEXT NOT NULL,
                    last_index INTEGER NOT NULL
                );

                -- (kid, nonce, expires) of every envelope accepted or refused (leaf_index or
                -- refusal_index names the leaf that backs the record), and of signed requests
                -- without an envelope, while still inside their window (AICS-1 section 4.3).  A
                -- record a leaf backs never leaves the lookup: a nonce is unique per key across the
                -- whole log, not only inside its window (AICS-1 sections 4.3 and 14.3).
                CREATE TABLE IF NOT EXISTS nonces (
                    kid TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    expires INTEGER NOT NULL,
                    leaf_index INTEGER,
                    refusal_index INTEGER,
                    PRIMARY KEY (kid, nonce)
                );

                -- Projection of refusal leaves (AICS-1 section 5.3): the envelope (or, for a signed request
                -- without one, the request) each names by hash and its authenticated attempt tuple (null when
                -- the attempt did not authenticate).  An exact resubmission of a refused envelope is answered
                -- with that envelope's first refusal; any other submission gets a refusal of its own.
                CREATE TABLE IF NOT EXISTS refusals (
                    refusal_index INTEGER PRIMARY KEY,
                    envelope_hash TEXT NOT NULL,
                    attempt_kid TEXT,
                    attempt_nonce TEXT,
                    reason_code TEXT NOT NULL,
                    conflict_index INTEGER
                );
                CREATE INDEX IF NOT EXISTS refusals_by_envelope ON refusals (envelope_hash, refusal_index);

                -- Projection of grant leaves and of initial grants inside claims
                -- (grant_index = the claim leaf).  Grants name keys, never names.
                -- used counts accepted dm leaves citing the grant (their grant_index).
                CREATE TABLE IF NOT EXISTS grants (
                    grant_index INTEGER PRIMARY KEY,
                    owner_kid TEXT NOT NULL,
                    sender_kid TEXT NOT NULL,
                    max_messages INTEGER NOT NULL,
                    expires INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS grants_by_pair ON grants (owner_kid, sender_kid, grant_index);

                -- One row per dm leaf: its off-leaf ciphertext body and the
                -- recipient's read mark.  The metadata is the leaf.
                CREATE TABLE IF NOT EXISTS messages (
                    leaf_index INTEGER PRIMARY KEY,
                    sender_kid TEXT NOT NULL,
                    sender_name TEXT NOT NULL,
                    recipient_kid TEXT NOT NULL,
                    recipient_name TEXT NOT NULL,
                    encryption TEXT NOT NULL,
                    ct_hash TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    ciphertext BLOB,
                    grant_index INTEGER NOT NULL,
                    is_read INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    -- set when the ciphertext-byte budget evicted the body (AICS-1 section 8.2): the policy
                    -- whose retention rule governs it
                    expired_policy_index INTEGER
                );
                CREATE INDEX IF NOT EXISTS messages_by_recipient ON messages (recipient_name, leaf_index);
                CREATE INDEX IF NOT EXISTS messages_by_recipient_kid ON messages (recipient_kid, leaf_index);
                CREATE INDEX IF NOT EXISTS messages_by_ct_hash ON messages (ct_hash);

                -- Capsule slots: mutable storage, named by key_hash only (the agent's slot key never
                -- reaches the server).  A slot points at its latest capsule leaf; every capsule leaf stays
                -- in the log.  Slots belong to a signing key.
                CREATE TABLE IF NOT EXISTS capsules (
                    owner_kid TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    leaf_index INTEGER NOT NULL UNIQUE,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (owner_kid, key_hash)
                );

                -- Every capsule leaf with its prev_capsule_index (AICS-1 section 5.3), size, expiry
                -- and its own ciphertext body: the slot's history, from which the quota usage of
                -- AICS-1 section 20.7 is computed (the latest leaf of each slot).  A superseded body
                -- stays retrievable by hash until it is CIPHERTEXT_MINIMUM_SECONDS old (section 8.2;
                -- superseded_at is the ts of the leaf that replaced it); a current one until expires.
                -- ciphertext is NULL once removed (expired, or hidden and deleted).
                CREATE TABLE IF NOT EXISTS capsule_leaves (
                    leaf_index INTEGER PRIMARY KEY,
                    owner_kid TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    prev_capsule_index INTEGER,
                    encryption TEXT NOT NULL,
                    ct_hash TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    expires INTEGER NOT NULL,
                    ts INTEGER NOT NULL,
                    superseded_at INTEGER,
                    ciphertext BLOB
                );
                CREATE INDEX IF NOT EXISTS capsule_leaves_by_slot ON capsule_leaves (owner_kid, key_hash, leaf_index);
                CREATE INDEX IF NOT EXISTS capsule_leaves_by_ct_hash ON capsule_leaves (ct_hash);

                -- Projection of tombstone leaves: the body of target_index is hidden.
                -- erased_at: when the hidden body was deleted (at once for erasure and
                -- secret_format, HIDDEN_BODY_RETENTION_SECONDS after the tombstone for
                -- illegal_on_notice and order); NULL while it is kept, inaccessible.
                CREATE TABLE IF NOT EXISTS tombstones (
                    target_index INTEGER PRIMARY KEY,
                    tombstone_index INTEGER NOT NULL UNIQUE,
                    reason_code TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    erased_at INTEGER
                );

                -- Projection of suspension leaves; the latest per key decides.
                -- until NULL: until a later suspension leaf ends it.
                CREATE TABLE IF NOT EXISTS suspensions (
                    suspension_index INTEGER PRIMARY KEY,
                    target_kid TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    until INTEGER,
                    -- the leaf's evidence_hash: an ending suspension repeats it (AICS-1 section 10.3)
                    evidence_hash TEXT
                );
                CREATE INDEX IF NOT EXISTS suspensions_by_kid ON suspensions (target_kid, suspension_index);

                -- Projection of freeze leaves; the report is in policy_documents.
                CREATE TABLE IF NOT EXISTS freezes (
                    freeze_index INTEGER PRIMARY KEY,
                    state TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    report_hash TEXT NOT NULL
                );

                -- Public posts (AICS-1 section 5.3): the exact body bytes J({{channel, title, text}})
                -- the leaf's body_hash names, and what they say.  body is NULL once a tombstone's
                -- body is deleted (title and text are emptied with it).
                CREATE TABLE IF NOT EXISTS agora_posts (
                    post_index INTEGER PRIMARY KEY,
                    channel TEXT NOT NULL,
                    parent_index INTEGER,
                    author_kid TEXT NOT NULL,
                    author_name TEXT NOT NULL,
                    author_tier TEXT NOT NULL,
                    title TEXT,
                    text TEXT NOT NULL,
                    body BLOB,
                    body_hash TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS agora_posts_by_channel ON agora_posts (channel, post_index);
                CREATE INDEX IF NOT EXISTS agora_posts_by_body ON agora_posts (body_hash);

                -- Polls (AICS-1 section 5.3): the body J({{channel, title, text, options}}) and the
                -- poll's own rules (closes, minimum key age, proof of work).
                CREATE TABLE IF NOT EXISTS agora_polls (
                    poll_index INTEGER PRIMARY KEY,
                    channel TEXT NOT NULL,
                    creator_kid TEXT NOT NULL,
                    creator_name TEXT NOT NULL,
                    title TEXT NOT NULL,
                    text TEXT NOT NULL,
                    options_json TEXT NOT NULL,
                    option_count INTEGER NOT NULL,
                    closes INTEGER NOT NULL,
                    min_key_age_seconds INTEGER NOT NULL,
                    pow_bits INTEGER NOT NULL,
                    body BLOB,
                    body_hash TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS agora_polls_by_body ON agora_polls (body_hash);

                -- One vote per signing key per poll, each weighing one (decision 2d, AICS-1 section 5.3);
                -- option is the zero-based option index; the optional body is J({{reason}}).
                CREATE TABLE IF NOT EXISTS agora_poll_votes (
                    vote_index INTEGER PRIMARY KEY,
                    poll_index INTEGER NOT NULL,
                    voter_kid TEXT NOT NULL,
                    voter_name TEXT NOT NULL,
                    option INTEGER NOT NULL,
                    reason TEXT,
                    body BLOB,
                    body_hash TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE (poll_index, voter_kid)
                );
                CREATE INDEX IF NOT EXISTS agora_poll_votes_by_body ON agora_poll_votes (body_hash);

                -- Notices (DSA Art. 16, docs/legal/notice-procedure.md): the one write path
                -- open to anyone, into this register and never into content or the log.
                -- Intake writes no leaf; the one leaf of a notice is the policy-signed
                -- report (kind notice: notice_hash, target_index, outcome_code,
                -- evidence_hash) written when the owner closes it (outcome_index).  The
                -- report id, the text, the notifier's contact and the salt of the notice
                -- hash (AICS-1 section 16) stay here, off the log, until delete_after
                -- (NOTICE_RETENTION_SECONDS after closing).
                CREATE TABLE IF NOT EXISTS notices (
                    report_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    location TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    notifier_name TEXT,
                    notifier_email TEXT,
                    cites_report_id TEXT,
                    salt TEXT NOT NULL,
                    notice_sha256 TEXT NOT NULL,
                    received_at INTEGER NOT NULL,
                    outcome_code TEXT,
                    target_index INTEGER,
                    evidence_hash TEXT,
                    outcome_index INTEGER UNIQUE,
                    closed_at INTEGER,
                    delete_after INTEGER
                );
                CREATE INDEX IF NOT EXISTS notices_by_receipt ON notices (received_at, report_id);

                -- Projection of the daily count reports (report leaves of kind daily,
                -- AICS-1 section 10.2): one per finished UTC day.
                CREATE TABLE IF NOT EXISTS daily_reports (
                    day INTEGER PRIMARY KEY,
                    leaf_index INTEGER NOT NULL UNIQUE
                );

                CREATE TABLE IF NOT EXISTS telemetry_counters (
                    metric_key TEXT PRIMARY KEY,
                    metric_value INTEGER NOT NULL DEFAULT 0
                );

                -- The owner action market (decision 3, AICS-1 section 20.4).  A request is an
                -- ordinary post (any channel; its text lives in agora_posts), named on the
                -- owner's report leaves by its entry_hash.  One row per request the owner quoted:
                -- the latest quote, the completion (its body J({{text}}) off-leaf) and the payment.
                -- No alias, no payout address, no note: the human is always the owner.
                CREATE TABLE IF NOT EXISTS owner_actions (
                    request_index INTEGER PRIMARY KEY,
                    request_hash TEXT NOT NULL UNIQUE,
                    requester_name TEXT NOT NULL,
                    quote_index INTEGER,
                    price INTEGER,
                    complete_index INTEGER UNIQUE,
                    result_hash TEXT,
                    completion_text TEXT,
                    completion_body BLOB,
                    paid_index INTEGER UNIQUE,
                    created_at TEXT NOT NULL,
                    quoted_at TEXT,
                    completed_at TEXT,
                    paid_at TEXT
                );
                CREATE INDEX IF NOT EXISTS owner_actions_by_result ON owner_actions (result_hash);
                -- Every quote of a request, in log order (a later quote replaces the price).
                CREATE TABLE IF NOT EXISTS owner_quotes (
                    quote_index INTEGER PRIMARY KEY,
                    request_index INTEGER NOT NULL,
                    amount INTEGER NOT NULL
                );

                -- Projection of the leaves that change a SUP balance (sup.credit,
                -- sup.spend).  A name's balance is the sum of its deltas; bytes
                -- records storage bought above the free quota.
                CREATE TABLE IF NOT EXISTS sup_ledger (
                    leaf_index INTEGER PRIMARY KEY,
                    name_norm TEXT NOT NULL,
                    delta INTEGER NOT NULL,
                    cause TEXT NOT NULL,
                    bytes INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS sup_ledger_by_name ON sup_ledger (name_norm, leaf_index);

                -- The voluntary task board: sup.task leaves; the body J({{title, text}}) is off-leaf.
                CREATE TABLE IF NOT EXISTS sup_tasks (
                    task_index INTEGER PRIMARY KEY,
                    title TEXT NOT NULL,
                    text TEXT NOT NULL,
                    body BLOB,
                    body_hash TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    reward INTEGER NOT NULL,
                    max_awards INTEGER NOT NULL,
                    closes INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS sup_tasks_by_body ON sup_tasks (body_hash);
                -- Awards (sup.credit, source task): one per submission, one per name and task.
                CREATE TABLE IF NOT EXISTS sup_awards (
                    credit_index INTEGER PRIMARY KEY,
                    task_index INTEGER NOT NULL,
                    submission_index INTEGER NOT NULL UNIQUE,
                    name_norm TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    UNIQUE (task_index, name_norm)
                );

                -- Contribution intents (AICS-1 section 20.6): short-lived, off-log reservations of
                -- exact units, unique per network while claimable, so that a transfer credits only
                -- the name that announced it.  Deleted once credited or past their claim window.
                CREATE TABLE IF NOT EXISTS sup_intents (
                    intent_id TEXT PRIMARY KEY,
                    name_norm TEXT NOT NULL,
                    network TEXT NOT NULL,
                    asset TEXT NOT NULL,
                    address TEXT NOT NULL,
                    units INTEGER NOT NULL,
                    amount INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    claim_until INTEGER NOT NULL,
                    UNIQUE (network, units)
                );
                -- Credited contributions.  The leaf carries the keyed contribution_hash and the SUP
                -- amount; the transaction identifier and the exact units stay off-leaf and are deleted
                -- record_seconds after the credit (decision 17).
                CREATE TABLE IF NOT EXISTS sup_contributions (
                    contribution_hash TEXT PRIMARY KEY,
                    credit_index INTEGER NOT NULL UNIQUE,
                    intent_id TEXT NOT NULL UNIQUE,
                    name_norm TEXT NOT NULL,
                    network TEXT NOT NULL,
                    tx_hash TEXT,
                    units INTEGER,
                    sup_amount INTEGER NOT NULL,
                    credited_at INTEGER NOT NULL,
                    delete_after INTEGER NOT NULL
                );
                """
            )
            # Durability before acknowledgement (DESIGN.md section 4.2 item 4):
            # every COMMIT reaches the disk before a leaf index is returned.
            if self._conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                raise RuntimeError(f"{self.db_path}: SQLite refused WAL mode")
            if self._conn.execute("PRAGMA synchronous").fetchone()[0] != 2:
                raise RuntimeError(f"{self.db_path}: SQLite refused synchronous=FULL")
            migrate_swarms(self._conn)

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        """One SQLite transaction (``synchronous=FULL``); nested use joins the outer one.

        Leaves appended inside it reach the in-memory tree, then the tiles and
        the published checkpoint, only after COMMIT returned
        (:meth:`TlogStore.append_committed`); a rolled-back transaction leaves
        no trace there.
        """
        with self._lock:
            if self._pending is not None:
                yield
                return
            pending: list[bytes] = []
            self._pending = pending
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                try:
                    yield
                    self._conn.execute("COMMIT")
                except BaseException:
                    if self._conn.in_transaction:
                        self._conn.execute("ROLLBACK")
                    raise
            finally:
                self._pending = None
            if pending:
                self._log.append_committed(pending)

    def _committed_entries(self, start: int, end: int) -> Iterator[bytes]:
        """Committed entry bytes ``start`` to ``end - 1``, checking indices and stored hashes."""
        expected = start
        rows = self._conn.execute(
            """
            SELECT leaf_index, leaf_json, leaf_hash_hex FROM tlog_leaves
            WHERE leaf_index >= ? AND leaf_index < ? ORDER BY leaf_index ASC
            """,
            (start, end),
        )
        for row in rows:
            if row["leaf_index"] != expected:
                raise LogIntegrityError(f"the leaf table has a gap at index {expected}")
            data = row["leaf_json"].encode("utf-8")
            if hashlib.sha256(b"\x00" + data).hexdigest() != row["leaf_hash_hex"]:
                raise LogIntegrityError(f"leaf {expected} does not match its stored hash")
            expected += 1
            yield data
        if expected != end:
            raise LogIntegrityError(f"the leaf table has a gap at index {expected}")

    def _boot_log(self) -> None:
        """Rebuild the tree from the committed table and verify, catch up and publish the tiles."""
        with self._lock:
            size = self._conn.execute("SELECT COUNT(*) FROM tlog_leaves").fetchone()[0]
            self._log.boot(size, self._committed_entries)

    def _append_leaf(
        self, envelope: dict[str, Any], *, ts: int, attestation: str | None = None
    ) -> dict[str, Any]:
        """Insert the entry of one accepted envelope (AICS-1 section 5.1); must run inside :meth:`_transaction`.

        The entry is :func:`aics_server.envelopes.make_entry`'s: ``origin``,
        ``type`` and ``actor_kid`` are the envelope's, ``ts`` the submission time
        fixed before acceptance, ``payload`` the envelope plus a copy of its
        ``Q`` (and the attestation of a shared-secret entry).  The caller returns
        the full entry, so the agent can compute the leaf hash it is owed.
        """
        if self._pending is None:
            raise RuntimeError("leaves are appended only inside a transaction")
        protected = envelope["protected"]
        entry_type = protected["type"]
        if entry_type not in ENTRY_TYPES and entry_type not in EXTENSION_ENTRY_TYPES:
            raise ValueError(f"{entry_type!r} is not an entry type of this log")
        if protected["origin"] != self.origin:
            raise ValueError("an envelope for another log's origin is never appended here")
        self._log.check_writable()
        entry = ev.make_entry(envelope, ts=ts, attestation=attestation)
        actor_kid = entry["actor_kid"]
        entry_text = canonical_text(entry)
        entry_bytes = entry_text.encode("utf-8")
        if len(entry_bytes) > 65535:
            raise ValueError("entry exceeds the 65535-byte tile bundle limit")
        idx = self._log.tree.size + len(self._pending)
        leaf_hash_hex = hashlib.sha256(b"\x00" + entry_bytes).hexdigest()
        created_at = _utc_iso(ts)
        self._conn.execute(
            """
            INSERT INTO tlog_leaves (leaf_index, event_type, actor_kid, leaf_json, leaf_hash_hex, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (idx, entry_type, actor_kid, entry_text, leaf_hash_hex, created_at),
        )
        self._pending.append(entry_bytes)
        return {"leaf_index": idx, "leaf_hash_hex": leaf_hash_hex, "created_at": created_at, "entry": entry}

    def _proof(self, leaf: dict[str, Any]) -> dict[str, Any]:
        """Inclusion proof of a committed leaf against the current tree and its signed checkpoint."""
        with self._lock:
            idx = leaf["leaf_index"]
            tree = self._log.tree
            size = tree.size
            if idx >= size:
                raise RuntimeError("a proof is given only for a committed leaf")
            return {
                "leaf_index": idx,
                "tree_size": size,
                "root_hash_hex": tree.root(size).hex(),
                "leaf_hash_hex": leaf["leaf_hash_hex"],
                "inclusion_proof_hex": [p.hex() for p in tree.inclusion_proof(idx, size)],
                "signed_checkpoint": self._log.checkpoint_note(size).decode("utf-8"),
                "created_at": leaf["created_at"],
            }

    def receipt_note(self, entry: Mapping[str, Any], leaf_hash_hex: str) -> bytes:
        """The inclusion promise for a committed leaf (AICS-1 section 10.1), signed by the log key.

        A C2SP signed note whose text is ``J({origin, entry_hash, submitted_at,
        mmd_seconds}) || LF``, with ``submitted_at`` the entry's ``ts`` and
        ``mmd_seconds`` :data:`MMD_SECONDS`.  It is issued only after the leaf
        is committed and in the tree, and Ed25519 is deterministic, so the
        same entry always gets the same receipt.
        """
        text = canonicalize(
            {"origin": self.origin, "entry_hash": leaf_hash_hex, "submitted_at": entry["ts"], "mmd_seconds": MMD_SECONDS}
        ).decode("ascii") + "\n"
        return Note(text=text, signatures=(sign_note(text, self.server_key, self.origin),)).to_bytes()

    def _written(self, leaf: dict[str, Any]) -> dict[str, Any]:
        """What a write (or a logged refusal) returns about its leaf: the exact entry, its proof and its receipt.

        ``receipt_note`` is ``U64`` of the log-signed receipt note (:meth:`receipt_note`).
        """
        return {
            "entry": leaf["entry"],
            "merkle_proof": self._proof(leaf),
            "receipt_note": keys.b64u_encode(self.receipt_note(leaf["entry"], leaf["leaf_hash_hex"])),
        }

    def _advance_chain(self, kid: str, seq: int, envelope_hash: str, leaf_index: int) -> None:
        self._conn.execute(
            """
            INSERT INTO envelope_chain (kid, last_seq, last_hash, last_index) VALUES (?, ?, ?, ?)
            ON CONFLICT (kid) DO UPDATE SET
                last_seq = excluded.last_seq, last_hash = excluded.last_hash, last_index = excluded.last_index
            """,
            (kid, seq, envelope_hash, leaf_index),
        )

    def _append_policy_leaf(self, entry_type: str, q: dict[str, Any], *, ts: int | None = None) -> dict[str, Any]:
        """A leaf whose actor is the policy key (AICS-1 section 5.1: administrative entries use the policy key as actor).

        *q* is the entry type's payload; the policy key signs its native
        envelope at ``ts`` (default now), which is also the entry's ``ts``, as
        the next envelope of the policy key's own chain.  A refusal advances
        that chain, never the refused author's (section 4.2).
        """
        ts = int(time.time()) if ts is None else ts
        chain = self._chain_row(self.policy_kid)
        seq = 0 if chain is None else chain["last_seq"] + 1
        prev = None if chain is None else chain["last_hash"]
        env = ev.sign_policy(q, self.policy_key, origin=self.origin, entry_type=entry_type, t=ts, seq=seq, prev=prev)
        leaf = self._append_leaf(env, ts=ts)
        self._advance_chain(self.policy_kid, seq, envelope_mod.envelope_hash(env), leaf["leaf_index"])
        return leaf

    def _append_signed(self, ctx: SignedContext, entry_type: str) -> dict[str, Any]:
        """The entry of the actor's verified envelope at ``ts = ctx.t``: advances its chain and records its nonce.

        The payload is the envelope plus an exact copy of its ``Q``; a
        shared-secret write also carries the policy key's attestation
        (AICS-1 section 5.1).  The ``(kid, nonce, expires)`` record is written in
        the same transaction, backed by this leaf (section 4.3).
        """
        assert ctx.envelope is not None and ctx.envelope_hash is not None
        if ctx.entry_type != entry_type:
            raise ValueError(f"the envelope is a {ctx.entry_type}, not a {entry_type}")
        attestation = None
        if ctx.scheme == ev.SHARED_SECRET:
            attestation = ev.attest(self.policy_key, ctx.envelope, ts=ctx.t)
        leaf = self._append_leaf(ctx.envelope, ts=ctx.t, attestation=attestation)
        self._advance_chain(ctx.kid, ctx.envelope["protected"]["seq"], ctx.envelope_hash, leaf["leaf_index"])
        self._conn.execute(
            """
            INSERT INTO nonces (kid, nonce, expires, leaf_index) VALUES (?, ?, ?, ?)
            ON CONFLICT (kid, nonce) DO UPDATE SET leaf_index = excluded.leaf_index, expires = excluded.expires
            """,
            (ctx.kid, ctx.nonce, ctx.expires, leaf["leaf_index"]),
        )
        return leaf

    # ------------------------------------------------------------------
    # checkpoint & proofs
    # ------------------------------------------------------------------

    #: Shown wherever the API repeats the service keys.
    KEYS_NOTICE = (
        "A convenience copy. Verify checkpoints and policy leaves only against keys obtained out of band "
        "(DNS TXT _aics.<domain>, the aics package, the public README), never against this response."
    )

    def tlog_head(self) -> tuple[int, str]:
        """``(tree_size, root_hash_hex)`` of the committed tree."""
        with self._lock:
            tree = self._log.tree
            return tree.size, tree.root().hex()

    def get_tlog_checkpoint(self) -> dict[str, Any]:
        """The current signed checkpoint with the service keys and the state of the tiles.

        Server-computed values are claims: the note is checked against the
        out-of-band log key, and tiles are verified against the note.
        """
        with self._lock:
            tree = self._log.tree
            size = tree.size
            note = self._log.checkpoint_note(size).decode("utf-8")
            tiles = self._log.status()
            return {
                "origin": self.origin,
                "tree_size": size,
                "root_hash_hex": tree.root(size).hex(),
                "signed_checkpoint": note,
                "log_vkey": self.server_vkey,
                "log_kid": self.server_kid,
                "server_vkey": self.server_vkey,
                "server_did": self.server_did,
                "policy_kid": self.policy_kid,
                "policy_did": self.policy_did,
                "policy_public_key_b64u": self.policy_public_key_b64u,
                "owner_kid": self.owner_kid,
                "charter_index": 0,
                "tiles": {
                    "prefix": "/tiles/",
                    "size": tiles["tiles_size"],
                    "published_size": tiles["published_size"],
                    # How far, and for how long, the published checkpoint trails the tree. Past
                    # mmd_seconds the server refuses new leaves (LogUnavailable).
                    "lag_entries": tiles["lag_entries"],
                    "lag_seconds": tiles["lag_seconds"],
                    "mmd_seconds": tiles["mmd_seconds"],
                    "error": tiles["error"],
                    "diverged": tiles["diverged"],
                },
                "keys_notice": self.KEYS_NOTICE,
            }

    def published_checkpoint(self) -> bytes:
        """The signed note at ``<tiles>/checkpoint`` (the size the tiles serve)."""
        with self._lock:
            published = self._log.published
            if published is not None:
                return published.note
            return self._log.checkpoint_note(self._log.tiles_size)

    def stated_checkpoint(self) -> tuple[int, bytes]:
        """``(size, note)``: the signed checkpoint a read projection is stated at (AICS-1 section 12.1).

        The note the tiles publish, so a client can authenticate the
        projection against the tiles at that size; tiles are written in the
        commit of every leaf, so it is normally the whole committed tree.
        """
        with self._lock:
            published = self._log.published
            if published is not None:
                return published.size, published.note
            size = self._log.tiles_size
            return size, self._log.checkpoint_note(size)

    def tile_bytes(self, path: str) -> bytes | None:
        """A tiles-directory resource (``checkpoint``, ``tile/...``), or ``None`` for any other path."""
        with self._lock:
            return self._log.read_resource(path)

    def get_tlog_proof(self, leaf_index: int) -> dict[str, Any] | None:
        """Entry ``leaf_index`` with its exact bytes and an inclusion proof against the current checkpoint."""
        with self._lock:
            tree = self._log.tree
            size = tree.size
            if leaf_index < 0 or leaf_index >= size:
                return None
            row = self._conn.execute("SELECT * FROM tlog_leaves WHERE leaf_index = ?", (leaf_index,)).fetchone()
            if not row:
                return None
            entry_bytes = row["leaf_json"].encode("utf-8")
            return {
                "leaf_index": leaf_index,
                "tree_size": size,
                "root_hash_hex": tree.root(size).hex(),
                "leaf_hash_hex": row["leaf_hash_hex"],
                "event_type": row["event_type"],
                "actor_kid": row["actor_kid"],
                "created_at": row["created_at"],
                "leaf_data": json.loads(row["leaf_json"]),
                "entry_bytes_b64": base64.b64encode(entry_bytes).decode("ascii"),
                "inclusion_proof_hex": [p.hex() for p in tree.inclusion_proof(leaf_index, size)],
                "signed_checkpoint": self._log.checkpoint_note(size).decode("utf-8"),
            }

    def inclusion_proof(self, index: int, size: int) -> list[bytes]:
        """RFC 9162 inclusion proof of leaf ``index`` in the tree of ``size`` leaves (``ValueError`` if out of range)."""
        with self._lock:
            return self._log.tree.inclusion_proof(index, size)

    def consistency_proof(self, old_size: int, new_size: int) -> list[bytes]:
        """RFC 9162 consistency proof between two tree sizes (``ValueError`` if out of range)."""
        with self._lock:
            return self._log.tree.consistency_proof(old_size, new_size)

    def index_of_entry(self, entry_hash_hex: str) -> int | None:
        """Index of the committed leaf whose RFC 6962 leaf hash is ``entry_hash_hex``."""
        if not _HEX64.fullmatch(entry_hash_hex or ""):
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT leaf_index FROM tlog_leaves WHERE leaf_hash_hex = ?", (entry_hash_hex,)
            ).fetchone()
            return row["leaf_index"] if row and row["leaf_index"] < self._log.tree.size else None

    # ------------------------------------------------------------------
    # leaf 0: the charter
    # ------------------------------------------------------------------

    def _charter_statement(self, document: bytes, now: int) -> dict[str, Any]:
        """Leaf 0's payload ``Q`` (AICS-1 sections 5.3 and 6.4), countersigned by the log key.

        ``{kind: charter, document_hash, size, prev_policy_index: null,
        effective_after: 0, not_before, log_kid, policy_kid, owner_kid,
        log_sig}``, the three kids being the service keys' ``did:key``s and
        ``log_sig`` the log key's signature over ``UTF8("AICS-1 policy\n") ||
        J(Q without log_sig)``.  ``owner_kid`` is null only on a development log
        created without an owner key (:meth:`_check_genesis_inputs`).
        """
        q: dict[str, Any] = {
            "kind": "charter",
            "document_hash": _sha256(document),
            "size": len(document),
            "prev_policy_index": None,
            "effective_after": 0,
            "not_before": now,
            "log_kid": self.server_kid,
            "policy_kid": self.policy_kid,
            "owner_kid": self.owner_kid,
        }
        q["log_sig"] = keys.b64u_encode(self.server_key.sign(POLICY_SIGNATURE_CONTEXT + canonicalize(q)))
        return q

    def _check_genesis_inputs(self, explicit_charter: bool) -> None:
        """Refuse to write leaf 0 of a production log without its reviewed charter and an owner key (:class:`GenesisRefused`)."""
        production_flag = os.environ.get(PRODUCTION_ENV, "").strip().lower() in _TRUE_TEXT
        if not production_flag and self.origin != DEFAULT_ORIGIN:
            return
        if not production_flag and os.environ.get(DEV_GENESIS_ENV, "").strip().lower() in _TRUE_TEXT:
            return  # a development log on the default origin
        missing = []
        if not explicit_charter:
            missing.append("AICS_CHARTER_FILE (the reviewed charter, docs/legal/charter.md)")
        if self.owner_kid is None:
            missing.append("AICS_OWNER_PUBKEY (the owner key)")
        if missing:
            raise GenesisRefused(
                f"refusing to create the log {self.origin}: leaf 0 is permanent and fixes the charter and the owner "
                f"key for the life of this origin, so it is never written without {' and '.join(missing)}. "
                f"Development only: {DEV_GENESIS_ENV}=1 waives this on the default origin (not with {PRODUCTION_ENV}=1); "
                "a test log can also use another AICS_ORIGIN."
            )

    def _genesis(self, document: bytes, *, explicit_charter: bool = True) -> None:
        """Write leaf 0 (the charter) into an empty log; on every start, check it against this server."""
        with self._lock:
            if self._log.tree.size == 0:
                self._check_genesis_inputs(explicit_charter)
                now = int(time.time())
                statement = self._charter_statement(document, now)
                with self._transaction():
                    leaf = self._append_policy_leaf("policy", statement, ts=now)
                    if leaf["leaf_index"] != 0:
                        raise LogIntegrityError("the charter must be leaf 0")
                    self._conn.execute(
                        """
                        INSERT INTO policy_documents (leaf_index, kind, document_sha256, size, document)
                        VALUES (0, 'charter', ?, ?, ?)
                        """,
                        (statement["document_hash"], len(document), document),
                    )
                _say(f"new log {self.origin}: leaf 0 is the charter (sha256 {statement['document_hash']})")
            self._check_charter(document)

    def _check_charter(self, configured: bytes) -> None:
        """Fail closed unless leaf 0 is an AICS-1 charter entry signed by, and pinning, this server's keys."""
        row = self._conn.execute("SELECT leaf_json FROM tlog_leaves WHERE leaf_index = 0").fetchone()
        entry = json.loads(row["leaf_json"])
        payload = entry.get("payload") if isinstance(entry, dict) else None
        if not isinstance(payload, dict) or entry.get("type") != "policy" or payload.get("kind") != "charter":
            raise LogIntegrityError("leaf 0 is not the charter: this database does not hold a v2 log (DECISIONS.md #6)")
        if entry.get("origin") != self.origin:
            raise LogIntegrityError(
                f"leaf 0 belongs to origin {entry.get('origin')!r}, not {self.origin!r} (AICS_ORIGIN changed?)"
            )
        for field, mine in (("log_kid", self.server_kid), ("policy_kid", self.policy_kid)):
            if payload.get(field) != mine:
                raise LogIntegrityError(
                    f"leaf 0 pins {field} {payload.get(field)!r}, but this server's key is {mine!r}: the server seed "
                    "(AICS_SERVER_SEED_HEX or server_master.seed) is not the one this log was created with"
                )
        if payload.get("owner_kid") != self.owner_kid:
            raise LogIntegrityError(
                f"leaf 0 pins the owner key {payload.get('owner_kid') or 'none'}, but AICS_OWNER_PUBKEY gives "
                f"{self.owner_kid or 'none'}. The owner key of a log is fixed when its leaf 0 is written."
            )
        if entry.get("actor_kid") != self.policy_kid:
            raise LogIntegrityError("leaf 0 is not a policy-key entry")
        try:
            scheme = ev.verify_entry(entry, origin=self.origin, policy_key=self.policy_pub)
            if scheme != ev.NATIVE:
                raise ValueError("leaf 0 is signed natively by the policy key")
            q = payload["envelope"]["payload"]
            signed = {k: v for k, v in q.items() if k != "log_sig"}
            self.server_pub.verify(keys.b64u_decode(q["log_sig"]), POLICY_SIGNATURE_CONTEXT + canonicalize(signed))
        except (ev.EnvelopeRejected, InvalidSignature, KeyError, TypeError, ValueError) as exc:
            raise LogIntegrityError(f"leaf 0's signatures do not verify: {exc!r}") from None
        doc = self._conn.execute("SELECT document FROM policy_documents WHERE leaf_index = 0").fetchone()
        if doc is None:
            raise LogIntegrityError("the charter document named by leaf 0 is missing from the database")
        stored = bytes(doc["document"])
        if _sha256(stored) != payload.get("document_hash") or len(stored) != payload.get("size"):
            raise LogIntegrityError("the stored charter document does not match the hash in leaf 0")
        if configured != stored:
            _say(
                "the configured charter differs from the one in leaf 0; leaf 0 is permanent, "
                "a change takes a later policy leaf"
            )

    def charter(self) -> dict[str, Any]:
        """Leaf 0's charter: its document bytes, document hash and leaf hash."""
        with self._lock:
            leaf = self._conn.execute(
                "SELECT leaf_hash_hex, leaf_json FROM tlog_leaves WHERE leaf_index = 0"
            ).fetchone()
            doc = self._conn.execute("SELECT document FROM policy_documents WHERE leaf_index = 0").fetchone()
            payload = json.loads(leaf["leaf_json"])["payload"]
            return {
                "leaf_index": 0,
                "leaf_hash_hex": leaf["leaf_hash_hex"],
                "document_hash": payload["document_hash"],
                "size": payload["size"],
                "document": bytes(doc["document"]),
            }

    def pubkeys_text(self) -> str:
        """The out-of-band key file (``AICS_PUBKEYS_OUT``): one ``label value`` pair per line.

        Readable by ``aics-tlog --vkey-file`` (it picks the ``log`` line).
        """
        charter = self.charter()
        lines = [
            f"# Keys of the AICS log {self.origin}, written by aics-server at start-up.",
            "# Publish them away from this server: DNS TXT _aics.<domain>, the aics package, the public README.",
            "# A verifier must never take them from the API of the server it is checking.",
            "# log: C2SP verifier key of the checkpoint notes. policy: signs the charter, refusals,",
            "# tombstones, suspensions, freezes and the card. owner: signs owner-only actions.",
            "# Every kid is the key's did:key (AICS-1 section 3.1), as leaf 0 pins it; the policy and owner",
            "# lines repeat policy-kid and owner-kid for the tools that read them (ops/RUNBOOK-first-deploy.md).",
            f"origin {self.origin}",
            f"log {self.server_vkey}",
            f"log-kid {self.server_kid}",
            f"policy {self.policy_kid}",
            f"policy-kid {self.policy_kid}",
            f"policy-public-key {self.policy_public_key_b64u}",
            f"owner {self.owner_kid or 'none'}",
            f"owner-kid {self.owner_kid or 'none'}",
            "charter-index 0",
            f"charter-sha256 {charter['document_hash']}",
            f"charter-leaf-hash {charter['leaf_hash_hex']}",
        ]
        return "\n".join(lines) + "\n"

    def increment_counter(self, key: str, delta: int = 1) -> None:
        """Add to an aggregate counter (DESIGN.md section 8: no address, no user agent, no content).

        Counted in memory, never under the writer lock, and written to
        ``telemetry_counters`` by :meth:`flush_counters` (each housekeeping
        pass): counting a request costs no disk sync.  A crash loses at most
        the counts since the last flush.
        """
        with self._counter_lock:
            self._counter_buffer[key] = self._counter_buffer.get(key, 0) + delta

    def flush_counters(self) -> None:
        """Write the counts gathered in memory to ``telemetry_counters`` (one transaction)."""
        with self._counter_lock:
            buffered, self._counter_buffer = self._counter_buffer, {}
        if not buffered:
            return
        try:
            with self._lock, self._transaction():
                self._conn.executemany(
                    """
                    INSERT INTO telemetry_counters (metric_key, metric_value)
                    VALUES (?, ?)
                    ON CONFLICT(metric_key) DO UPDATE SET metric_value = metric_value + excluded.metric_value
                    """,
                    sorted(buffered.items()),
                )
        except BaseException:
            with self._counter_lock:  # keep the counts for the next flush
                for key, value in buffered.items():
                    self._counter_buffer[key] = self._counter_buffer.get(key, 0) + value
            raise

    def counters(self, prefix: str = "") -> dict[str, int]:
        """The aggregate counters whose key starts with *prefix*: the stored values plus those not yet flushed."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT metric_key, metric_value FROM telemetry_counters WHERE substr(metric_key, 1, ?) = ?",
                (len(prefix), prefix),
            ).fetchall()
        out = {r["metric_key"]: int(r["metric_value"]) for r in rows}
        with self._counter_lock:
            for key, value in self._counter_buffer.items():
                if key.startswith(prefix):
                    out[key] = out.get(key, 0) + value
        return out

    # ------------------------------------------------------------------
    # replay records and refusals
    # ------------------------------------------------------------------

    def _rebuild_recent_nonces(self) -> None:
        """Re-insert the ``(kid, nonce, expires)`` records of leaves still inside their window: the leaves back them.

        An accepted actor entry backs its envelope's tuple; a ``refusal`` backs
        its authenticated attempt's (``attempt_kid``, ``attempt_nonce``,
        ``attempt_expires``; AICS-1 sections 4.3 and 10.2).
        """
        with self._lock:
            now = int(time.time())
            since = _utc_iso(now - 2 * MAX_SIGNATURE_LIFETIME)
            rows = self._conn.execute(
                "SELECT leaf_index, leaf_json FROM tlog_leaves WHERE created_at >= ?", (since,)
            ).fetchall()
            with self._transaction():
                self._purge_nonces(now)
                for row in rows:
                    entry = json.loads(row["leaf_json"])
                    payload = entry.get("payload") or {}
                    if entry.get("type") == "refusal":
                        kid, nonce, expires = (
                            payload.get("attempt_kid"),
                            payload.get("attempt_nonce"),
                            payload.get("attempt_expires"),
                        )
                        if isinstance(kid, str) and isinstance(nonce, str) and isinstance(expires, int):
                            self._conn.execute(
                                """
                                INSERT INTO nonces (kid, nonce, expires, refusal_index) VALUES (?, ?, ?, ?)
                                ON CONFLICT (kid, nonce) DO UPDATE SET
                                    refusal_index = COALESCE(nonces.refusal_index, excluded.refusal_index)
                                """,
                                (kid, nonce, expires, row["leaf_index"]),
                            )
                        continue
                    env = payload.get("envelope")
                    protected = env.get("protected") if isinstance(env, dict) else None
                    if not isinstance(protected, dict) or protected.get("kid") == self.policy_kid:
                        continue
                    if isinstance(protected.get("nonce"), str) and isinstance(protected.get("expires"), int):
                        self._conn.execute(
                            """
                            INSERT INTO nonces (kid, nonce, expires, leaf_index) VALUES (?, ?, ?, ?)
                            ON CONFLICT (kid, nonce) DO UPDATE SET leaf_index = excluded.leaf_index
                            """,
                            (protected["kid"], protected["nonce"], protected["expires"], row["leaf_index"]),
                        )

    def _purge_nonces(self, now: int) -> None:
        """Records past their window leave the live lookup, unless a leaf backs them (AICS-1 section 4.3).

        A record an accepted entry or a refusal backs stays for good, so a nonce
        is never used twice by one key anywhere in the log (section 14.3 step 3
        checks nonce uniqueness); only the records of signed requests without
        an envelope (reads, the owner login, contribution intents) expire.
        """
        self._conn.execute(
            "DELETE FROM nonces WHERE expires < ? AND leaf_index IS NULL AND refusal_index IS NULL",
            (now - MAX_SIGNATURE_LIFETIME,),
        )

    #: Nonces of signed reads are written to the nonces table once this many are waiting, or after this long.
    READ_NONCE_BATCH = 256
    READ_NONCE_FLUSH_SECONDS = 5.0

    def _flush_read_nonces(self) -> None:
        """Write the nonces of signed reads gathered in memory (one transaction); caller holds the lock."""
        pending, self._read_nonces = self._read_nonces, {}
        self._read_nonces_since = time.monotonic()
        if not pending:
            return
        try:
            with self._transaction():
                self._conn.executemany(
                    "INSERT INTO nonces (kid, nonce, expires) VALUES (?, ?, ?) ON CONFLICT (kid, nonce) DO NOTHING",
                    [(kid, nonce, expires) for (kid, nonce), expires in pending.items()],
                )
                self._purge_nonces(int(time.time()))
        except BaseException:
            pending.update(self._read_nonces)
            self._read_nonces = pending
            raise

    def _live_nonce(self, kid: str, nonce: str, t: int) -> sqlite3.Row | None:
        """The record of ``(kid, nonce)`` that makes a submission at *t* a replay, else ``None``.

        AICS-1 section 4.3: a record whose ``expires`` lies after *t*; and, so
        that a nonce is unique per key across the whole log (section 14.3 step
        3), any record a leaf backs, however old: an accepted entry or a
        refusal used that nonce for good.
        """
        row = self._conn.execute("SELECT * FROM nonces WHERE kid = ? AND nonce = ?", (kid, nonce)).fetchone()
        if row is None:
            return None
        if row["expires"] > t or row["leaf_index"] is not None or row["refusal_index"] is not None:
            return row
        return None

    def consume_nonce(self, ctx: SignedContext, *, log_refusal: bool = True, service: bool = False) -> None:
        """Check ``(kid, nonce)`` of an authenticated submission, record it where no leaf will, or refuse a replay.

        An envelope write is only checked here: its ``(kid, nonce, expires)``
        is recorded in the same transaction as the leaf that accepts or
        refuses it, so every record of an envelope is backed by a leaf
        (AICS-1 section 4.3), and the check runs again under the writer lock
        right before acceptance (:meth:`_check_chain`).  A signed request
        without an envelope writes no leaf of its own and is recorded now.

        A replay of a write is refused with a ``refusal`` leaf of its own,
        naming the leaf that used the tuple first (the accepted entry, else
        the first refusal; section 10.2) and, for a replay of an accepted
        envelope, that entry's receipt (``receipt_hash``).  The admission
        windows run in front of that leaf, as for any refusal, so replaying
        requests cannot grow the log faster than the published limits.  The
        one exception is an exact resubmission of a submission that already
        has a refusal (the same envelope, or request, byte for byte): it is
        answered with that first refusal and adds no leaf (the card's
        ``[deviation-refusal-dedup]``).

        Reads pass ``log_refusal=False``: their nonces are remembered in memory
        at once and written to the table in batches (:data:`READ_NONCE_BATCH`,
        :data:`READ_NONCE_FLUSH_SECONDS`), so a signed read costs no disk sync
        of its own; a crash can forget the nonces of the last few seconds of
        reads, never of a write.  A signed request that writes no leaf of its
        own but must never run twice (the owner login of the administration
        endpoints, a contribution intent: AICS-1 sections 12.1 and 20.6)
        passes ``service=True``: its nonce is recorded durably at once, before
        it acts, and a replay is answered without a leaf.
        """
        with self._lock:
            key = (ctx.kid, ctx.nonce)
            t = ctx.t or int(time.time())
            if key in self._read_nonces:
                self._flush_read_nonces()  # a pair seen in the read batch: make its record durable first
            row = self._live_nonce(ctx.kid, ctx.nonce, t)
            message = "this (keyid, nonce) was already used; sign the request again with a fresh nonce"
            if service:
                if row is not None:
                    raise Refusal("replay", message, conflict_index=self._nonce_conflict(row))
                with self._transaction():
                    self._conn.execute(
                        """
                        INSERT INTO nonces (kid, nonce, expires) VALUES (?, ?, ?)
                        ON CONFLICT (kid, nonce) DO UPDATE SET expires = excluded.expires
                        """,
                        (ctx.kid, ctx.nonce, ctx.expires),
                    )
                return
            if row is None:
                if not log_refusal:
                    self._read_nonces[key] = ctx.expires
                    if (
                        len(self._read_nonces) >= self.READ_NONCE_BATCH
                        or time.monotonic() - self._read_nonces_since >= self.READ_NONCE_FLUSH_SECONDS
                    ):
                        self._flush_read_nonces()
                    return
                if ctx.envelope is not None:
                    return  # recorded with its leaf (acceptance or refusal)
                with self._transaction():  # a signed write without an envelope: recorded now
                    self._conn.execute(
                        """
                        INSERT INTO nonces (kid, nonce, expires) VALUES (?, ?, ?)
                        ON CONFLICT (kid, nonce) DO UPDATE SET expires = excluded.expires
                        """,
                        (ctx.kid, ctx.nonce, ctx.expires),
                    )
                    self._nonce_inserts += 1
                    if self._nonce_inserts % 256 == 0:
                        self._purge_nonces(int(time.time()))
                return
            conflict = self._nonce_conflict(row)
            if not log_refusal:  # a read: refused without a leaf
                raise Refusal("replay", message, conflict_index=conflict)
            self._answer_exact_resubmission(ctx)
            self._admit_for_refusal(ctx)
            receipt_hash = None
            if row["leaf_index"] is not None and ctx.envelope_hash is not None:
                # Refusing an already receipted envelope names that receipt (AICS-1 section 10.2); the promise stays.
                receipt_hash = self._receipt_hash_if_same_envelope(row["leaf_index"], ctx.envelope_hash)
            self._refuse(ctx, "replay", conflict_index=conflict, message=message, receipt_hash=receipt_hash)

    @staticmethod
    def _nonce_conflict(row: sqlite3.Row) -> int | None:
        """The leaf a replay cites (AICS-1 section 10.2): the accepted event that used the tuple, else its first refusal."""
        return row["leaf_index"] if row["leaf_index"] is not None else row["refusal_index"]

    def _earlier_refusal(self, attempt: "_Attempt") -> sqlite3.Row | None:
        """The first refusal of exactly this submission: the same envelope (or request) hash and attempt tuple."""
        if attempt.kid is None:
            return self._conn.execute(
                "SELECT * FROM refusals WHERE envelope_hash = ? AND attempt_kid IS NULL ORDER BY refusal_index LIMIT 1",
                (attempt.envelope_hash,),
            ).fetchone()
        return self._conn.execute(
            """
            SELECT * FROM refusals WHERE envelope_hash = ? AND attempt_kid = ? AND attempt_nonce = ?
            ORDER BY refusal_index LIMIT 1
            """,
            (attempt.envelope_hash, attempt.kid, attempt.nonce),
        ).fetchone()

    def _answer_exact_resubmission(self, ctx: "SignedContext | _Attempt", *, status: int | None = None) -> None:
        """Raise the first refusal of this exact submission, if it has one (and add no leaf); otherwise return.

        The same envelope (or request) bytes refused before get that refusal
        again: its leaf, its code and its conflict.  The card discloses this
        as ``[deviation-refusal-dedup]``.  Any other submission, a different
        envelope that reuses a tuple among them, is decided and logged on its own.
        """
        earlier = self._earlier_refusal(self._attempt_of(ctx))
        if earlier is None:
            return
        code = earlier["reason_code"]
        raise Refusal(
            code,
            f"this exact submission was refused before, by leaf {earlier['refusal_index']} ({code}); "
            "sign a new envelope with a fresh nonce",
            conflict_index=earlier["conflict_index"],
            leaf=self._leaf_ref(earlier["refusal_index"]),
            status=self.refusal_status(code) if status is None else status,
        )

    def _admit_for_refusal(self, ctx: SignedContext) -> None:
        """Admission in front of a refusal leaf, unless this write already passed it (:func:`_signed_write`).

        The per-key window for an agent (rate limit, flood, freeze and
        suspension, each logged once per cause), the pre-identity bucket and the
        submitting key's registration window for a claimant; the owner is not
        rate-limited.  So failing requests add no more leaves than the
        published limits allow.
        """
        state = self._write_state
        same = getattr(state, "ctx", None) is ctx
        if ctx.role == "claimant":
            if not (same and getattr(state, "registered", False)):
                self._admit_registration(ctx)
        elif ctx.role != "owner":
            if not (same and getattr(state, "admitted", False)):
                self._admit(ctx, ctx.kid)

    def _check_replay(self, ctx: SignedContext) -> None:
        """Under the writer lock, right before acceptance: a live ``(kid, nonce)`` record makes this a replay.

        The early check of :meth:`consume_nonce` runs before the write is
        processed; this one is serialized with the leaf that records the
        tuple, so two copies of one envelope cannot both be accepted.
        """
        if ctx.envelope is None:
            return
        if self._live_nonce(ctx.kid, ctx.nonce, ctx.t or int(time.time())) is not None:
            self.consume_nonce(ctx, log_refusal=True)

    def _leaf_ref(self, leaf_index: int) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT leaf_index, leaf_json, leaf_hash_hex, created_at FROM tlog_leaves WHERE leaf_index = ?",
            (leaf_index,),
        ).fetchone()
        if row is None:
            return None
        leaf = {
            "leaf_index": row["leaf_index"],
            "leaf_hash_hex": row["leaf_hash_hex"],
            "created_at": row["created_at"],
            "entry": json.loads(row["leaf_json"]),
        }
        return {"leaf_index": leaf["leaf_index"], **self._written(leaf)}

    def _receipt_hash_of(self, leaf_index: int) -> str | None:
        """``hexH`` of the receipt note of committed leaf *leaf_index* (AICS-1 section 10.1), or ``None``.

        Receipts are deterministic (one note per entry, Ed25519 is
        deterministic), so this is the receipt the service issued for it.
        """
        row = self._conn.execute(
            "SELECT leaf_json, leaf_hash_hex FROM tlog_leaves WHERE leaf_index = ?", (leaf_index,)
        ).fetchone()
        if row is None:
            return None
        return hashlib.sha256(self.receipt_note(json.loads(row["leaf_json"]), row["leaf_hash_hex"])).hexdigest()

    def _receipt_hash_if_same_envelope(self, leaf_index: int, envelope_hash: str) -> str | None:
        """The receipt hash of accepted leaf *leaf_index* when its envelope is the one being refused, else ``None``."""
        row = self._conn.execute("SELECT leaf_json FROM tlog_leaves WHERE leaf_index = ?", (leaf_index,)).fetchone()
        if row is None:
            return None
        env = (json.loads(row["leaf_json"]).get("payload") or {}).get("envelope")
        if not isinstance(env, dict) or envelope_mod.envelope_hash(env) != envelope_hash:
            return None
        return self._receipt_hash_of(leaf_index)

    @staticmethod
    def _attempt_of(ctx: SignedContext | _Attempt) -> _Attempt:
        """The refusal's view of a submission (AICS-1 section 10.2): its envelope by hash, its authenticated tuple."""
        if isinstance(ctx, _Attempt):
            return ctx
        if ctx.envelope is not None:
            assert ctx.envelope_hash is not None
            return _Attempt(
                envelope_hash=ctx.envelope_hash, request_hash=None, kid=ctx.kid, nonce=ctx.nonce, expires=ctx.expires
            )
        assert ctx.request_hash is not None
        return _Attempt(
            envelope_hash=ctx.request_hash, request_hash=ctx.request_hash, kid=ctx.kid, nonce=ctx.nonce, expires=ctx.expires
        )

    @staticmethod
    def refusal_status(reason_code: str) -> int:
        """HTTP status of a refusal with this code (:data:`REFUSAL_STATUS`, ``secret_format:*`` 422, else 409)."""
        if reason_code.startswith(SECRET_FORMAT_PREFIX):
            return 422
        return REFUSAL_STATUS.get(reason_code, 409)

    def _log_refusal(
        self, attempt: _Attempt, reason_code: str, conflict_index: int | None, receipt_hash: str | None = None
    ) -> dict[str, Any]:
        """Append the policy-signed ``refusal`` leaf for *attempt*; returns the leaf.

        ``{envelope_hash, request_hash, attempt_kid, attempt_nonce,
        attempt_expires, reason_code, conflict_index, receipt_hash}`` (AICS-1
        section 5.3): the refused envelope and body are not copied; the leaf
        names the envelope by ``hexH(J(E))`` and carries the authenticated
        ``(kid, nonce, expires)``, so the replay record committed with it is
        backed by the leaf (sections 4.3 and 10.2).  The nonce is the bounded
        16-byte residual AICS-1 section 5.2 accepts for this reason.
        ``receipt_hash`` names the receipt of an already receipted envelope
        being refused (a replay of an accepted one), else it is null.
        """
        if (
            reason_code not in REFUSAL_REASONS
            and reason_code not in SUP_REFUSAL_REASONS
            and reason_code not in SWARM_REFUSAL_CODES
            and not _SECRET_FORMAT_CODE.fullmatch(reason_code)
        ):
            raise ValueError(f"unknown refusal reason {reason_code!r}")
        if self._pending is not None:
            raise RuntimeError("a refusal is logged outside any other transaction")
        q = {
            "envelope_hash": attempt.envelope_hash,
            "request_hash": attempt.request_hash,
            "attempt_kid": attempt.kid,
            "attempt_nonce": attempt.nonce,
            "attempt_expires": attempt.expires,
            "reason_code": reason_code,
            "conflict_index": conflict_index,
            "receipt_hash": receipt_hash,
        }
        with self._transaction():
            leaf = self._append_policy_leaf("refusal", q)
            self._conn.execute(
                """
                INSERT INTO refusals (refusal_index, envelope_hash, attempt_kid, attempt_nonce, reason_code, conflict_index)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (leaf["leaf_index"], attempt.envelope_hash, attempt.kid, attempt.nonce, reason_code, conflict_index),
            )
            if attempt.nonce is not None:
                # The tuple's record, backed by this leaf; a record an earlier leaf backs keeps citing that leaf.
                self._conn.execute(
                    """
                    INSERT INTO nonces (kid, nonce, expires, refusal_index) VALUES (?, ?, ?, ?)
                    ON CONFLICT (kid, nonce) DO UPDATE SET
                        refusal_index = COALESCE(nonces.refusal_index, excluded.refusal_index),
                        expires = MAX(nonces.expires, excluded.expires)
                    """,
                    (attempt.kid, attempt.nonce, attempt.expires, leaf["leaf_index"]),
                )
        return leaf

    def _refuse(
        self,
        ctx: SignedContext | _Attempt,
        reason_code: str,
        *,
        conflict_index: int | None = None,
        message: str | None = None,
        retry_after: int | None = None,
        extra: dict[str, Any] | None = None,
        status: int | None = None,
        receipt_hash: str | None = None,
    ) -> NoReturn:
        """Log a policy-signed ``refusal`` leaf for an authenticated attempt and raise :class:`Refusal`."""
        leaf = self._log_refusal(self._attempt_of(ctx), reason_code, conflict_index, receipt_hash)
        raise Refusal(
            reason_code,
            message or f"refused: {reason_code}",
            conflict_index=conflict_index,
            leaf={"leaf_index": leaf["leaf_index"], **self._written(leaf)},
            status=self.refusal_status(reason_code) if status is None else status,
            retry_after=retry_after,
            extra=extra,
        )

    def _failure_reason(self, exc: BaseException) -> tuple[str, int, int | None, str | None]:
        """``(reason_code, http_status, conflict_index, cause)`` of a failed signed write.

        A :class:`Rejected` carries its registered code; a :class:`ServiceError`
        whose code is a registered refusal code keeps it; a final transaction
        that does not pay an intent is ``payment_not_verified`` (AICS-1 section
        20.8); anything else is a schema failure, ``malformed``.
        """
        if isinstance(exc, Rejected):
            # A schema failure (malformed) answers 400 like a ValueError; any other code its REFUSAL_STATUS.
            default = 400 if exc.reason_code == "malformed" else self.refusal_status(exc.reason_code)
            status = exc.status if exc.status is not None else default
            return exc.reason_code, status, exc.conflict_index, exc.cause
        if isinstance(exc, ServiceError):
            registered = exc.code in REFUSAL_REASONS or exc.code in SUP_REFUSAL_REASONS
            return (exc.code if registered else "malformed"), exc.status, None, None if registered else exc.code
        if isinstance(exc, pay.PaymentNotVerified):
            return "payment_not_verified", exc.status, None, None
        if isinstance(exc, pay.PaymentError):
            return "malformed", exc.status, None, exc.code
        if isinstance(exc, NotFound):
            return "malformed", 404, None, "not_found"
        if isinstance(exc, PermissionError):
            return "malformed", 403, None, "not_permitted"
        if isinstance(exc, RuntimeError):
            return "malformed", 409, None, "conflict"
        return "malformed", 400, None, None

    def refuse_failure(self, ctx: SignedContext, exc: BaseException) -> NoReturn:
        """Answer a signed submission that failed an acceptance rule with a ``refusal`` leaf (and raise it).

        AICS-1 section 10.2: authenticated decisions admitted to processing
        are logged.  Admission runs first unless the write already passed it:
        the per-key window for an agent (rate limit, flood, freeze,
        suspension, each logged once per cause) and the global registration
        window for a claimant (a fresh key per request is free, so only a
        global bound keeps failed claims from growing the log), so failing
        requests add no more leaves than the published limits allow.  The
        owner is not rate-limited.  The refused body is not kept; the leaf
        names the attempt by its envelope or request hash.
        """
        code, status, conflict, cause = self._failure_reason(exc)
        with self._lock:
            self._admit_for_refusal(ctx)
            self._refuse(
                ctx,
                code,
                conflict_index=conflict,
                message=str(exc) or f"refused: {code}",
                status=status,
                extra={"cause": cause} if cause else None,
            )

    def _refuse_once(
        self,
        ctx: SignedContext | _Attempt,
        reason_code: str,
        cause: Any,
        *,
        conflict_index: int | None = None,
        message: str | None = None,
        retry_after: int | None = None,
    ) -> NoReturn:
        """A refusal whose cause lasts (a full write window, a suspension, a freeze).

        The first attempt under a cause gets its own ``refusal`` leaf; later
        attempts by the same key under the same cause get the same answer
        citing that leaf, and add none: repeating a refused write cannot grow
        the log.
        """
        attempt = self._attempt_of(ctx)
        cached = self._refusal_cache.get((attempt.kid, reason_code))
        if cached is not None and cached[0] == cause:
            leaf_ref = self._leaf_ref(cached[1])
            if attempt.nonce is not None:
                # AICS-1 section 4.3: this attempt's tuple is recorded too, backed by the leaf that answers it, so
                # the refused request can never be accepted later by whoever holds it.
                with self._transaction():
                    self._conn.execute(
                        """
                        INSERT INTO nonces (kid, nonce, expires, refusal_index) VALUES (?, ?, ?, ?)
                        ON CONFLICT (kid, nonce) DO NOTHING
                        """,
                        (attempt.kid, attempt.nonce, attempt.expires, cached[1]),
                    )
        else:
            leaf = self._log_refusal(attempt, reason_code, conflict_index)
            self._refusal_cache[(attempt.kid, reason_code)] = (cause, leaf["leaf_index"])
            leaf_ref = {"leaf_index": leaf["leaf_index"], **self._written(leaf)}
        raise Refusal(
            reason_code,
            message or f"refused: {reason_code}",
            conflict_index=conflict_index,
            leaf=leaf_ref,
            status=self.refusal_status(reason_code),
            retry_after=retry_after,
        )

    # ------------------------------------------------------------------
    # the one write path of both bindings (AICS-1 sections 11.3 and 12.1)
    # ------------------------------------------------------------------

    #: Entry types whose actor is the service's policy key (AICS-1 section 5.1, and the contribution credit of
    #: section 20.6): this server writes them itself and takes none from outside.
    POLICY_ACTOR_TYPES = ("tombstone", "refusal", "suspension", "freeze", "policy", "release")
    #: Entry types written without an off-leaf body (``body`` is null for them in ``POST /v2/entries``).
    BODYLESS_TYPES = ("name.claim", "key.rotate", "key.revoke", "x25519.rotate", "grant", "sup.credit", "sup.spend")

    def submit(self, ctx: SignedContext, body: bytes | None) -> dict[str, Any]:
        """Write the entry of an authenticated envelope: the one code path of ``POST /v2/entries`` and the gate.

        *ctx* comes from either binding (the native ``ed25519-jcs`` scheme with
        its RFC 9421 request, AICS-1 section 12.1, or a gate command signed
        under ``text-ed25519`` / ``text-sshsig``, section 11.3) and *body* is
        the exact off-leaf body bytes or ``None``.  The entry type selects the
        write: a key event, a grant, a post, poll or vote, a direct message, a
        capsule, a ``sup.spend`` by an agent key; a ``report`` of kind
        ``owner_action`` (a quote or a completion), a ``sup.task`` or a task
        award (``sup.credit``, source ``task``) by the owner key.  The types
        whose actor is the policy key are refused ``unknown_key`` (this server
        writes them itself), as is an owner type signed by any other key; a
        body sent with a type that has none is refused ``malformed``.  Every
        decision is a leaf: the accepted entry, or a policy-signed refusal.
        Returns what the write returns (its entry, proof and receipt).
        """
        entry_type = ctx.entry_type
        if entry_type is None or ctx.envelope is None:
            raise ValueError("a write carries its AICS-1 envelope")
        q = ctx.payload
        if entry_type in SWARM_TYPES:
            return self.swarms.submit(ctx, body)
        owner_type = entry_type in ("sup.task", "sup.credit") or (entry_type == "report" and q.get("kind") == "owner_action")
        if (
            entry_type in self.POLICY_ACTOR_TYPES
            or (entry_type == "report" and q.get("kind") != "owner_action")
            or (entry_type == "sup.credit" and q.get("source") != "task")
        ):
            self.refuse_failure(
                ctx,
                Rejected(
                    "unknown_key",
                    f"a {entry_type} entry of this kind has the service's policy key as its actor; it is never "
                    "submitted (AICS-1 sections 5.1 and 20.3)",
                    status=403,
                ),
            )
        if owner_type and (ctx.role != "owner" or self.owner_kid is None or ctx.kid != self.owner_kid):
            self.refuse_failure(
                ctx,
                Rejected(
                    "unknown_key",
                    "only the owner key writes owner quotes and completions, tasks and task awards (decision 3)",
                    status=403,
                ),
            )
        bodiless = (
            entry_type in self.BODYLESS_TYPES
            or (entry_type == "report" and q.get("action") != "complete")
            or (entry_type == "vote" and q.get("body_hash") is None)
        )
        if bodiless and body is not None:
            self.refuse_failure(ctx, Rejected("malformed", f"a {entry_type} entry has no off-leaf body: send body null"))
        if entry_type == "name.claim":
            return self.claim_name(ctx)
        if entry_type == "key.rotate":
            return self.upgrade_name(ctx) if q.get("mode") == "upgrade" else self.rotate_key(ctx)
        if entry_type == "key.revoke":
            return self.revoke_name(ctx)
        if entry_type == "x25519.rotate":
            return self.rotate_x25519(ctx)
        if entry_type == "grant":
            return self.grant(ctx)
        if entry_type == "post":
            return self.create_agora_post(ctx, body)
        if entry_type == "poll":
            return self.create_agora_poll(ctx, body)
        if entry_type == "vote":
            return self.vote_agora_poll(ctx, body)
        if entry_type == "dm":
            return self.send_message(ctx, body)
        if entry_type == "capsule":
            return self.put_capsule(ctx, body)
        if entry_type == "sup.spend":
            return self.spend(ctx)
        if entry_type == "sup.task":
            return self.create_task(ctx, body)
        if entry_type == "sup.credit":
            return self.award_task(ctx)
        if entry_type == "report":
            return self.complete_owner_action(ctx, body) if q.get("action") == "complete" else self.quote_owner_action(ctx)
        self.refuse_failure(ctx, Rejected("malformed", f"{entry_type} is not an entry type of this log"))

    def refuse_unauthenticated(self, envelope_hash: str, reason_code: str, message: str, *, status: int = 401) -> NoReturn:
        """A well-formed envelope whose authentication failed: a refusal leaf whose attempt fields are all null.

        AICS-1 sections 10.2 and 12.1: a bad envelope or HTTP signature, a
        request whose signature parameters differ from its envelope's, a key
        the log does not know.  Attempt identity fields are populated only
        after successful authentication, so the leaf names the envelope by
        ``hexH(J(E))`` and the code, nothing the submitter chose.  Anyone can
        send such envelopes without a key or a name, so these leaves have a
        window of their own, the published ``limits.unauthenticated``, much
        smaller than the pre-identity window: beyond it the attempt is
        answered with the same status and no leaf (section 10.2 lets
        unauthenticated traffic be rejected before logging).  The same failing
        envelope sent again is answered with its first leaf.
        """
        with self._lock:
            attempt = _Attempt(envelope_hash=envelope_hash, request_hash=None, kid=None, nonce=None, expires=None)
            earlier = self._earlier_refusal(attempt)
            if earlier is not None:
                raise Refusal(
                    earlier["reason_code"], message, leaf=self._leaf_ref(earlier["refusal_index"]), status=status
                )
            now = time.time()
            window = self._unauthenticated_window
            if window.full(now):
                spec = self.limits["unauthenticated"]
                raise Refusal(
                    reason_code,
                    f"{message} (not logged: over the published window of {spec['count']} logged refusals per "
                    f"{spec['interval_seconds']} s for requests that do not authenticate)",
                    status=status,
                    retry_after=window.retry_after(now),
                )
            window.add(now)
            leaf = self._log_refusal(attempt, reason_code, None)
            raise Refusal(
                reason_code,
                message,
                leaf={"leaf_index": leaf["leaf_index"], **self._written(leaf)},
                status=status,
            )

    def refuse_stale(self, ctx: SignedContext, reason_code: str, message: str, *, status: int | None = None) -> NoReturn:
        """An authenticated envelope outside its window (AICS-1 section 4.3), logged.

        ``expired`` or ``future`` at the submission time, or ``malformed`` for
        a validity window that is not ``created < expires <= created + 300``:
        both signatures verified before the window was checked, so the
        refusal names the attempt's ``(kid, nonce, expires)``.  An exact
        resubmission of an envelope that already has a refusal is answered
        with that refusal and adds no leaf; any other envelope, one that only
        reuses a tuple among them, gets a refusal of its own behind the
        signer's admission window.
        """
        status = (401 if reason_code in ("expired", "future") else self.refusal_status(reason_code)) if status is None else status
        with self._lock:
            self._answer_exact_resubmission(ctx, status=status)
            self.refuse_failure(ctx, Rejected(reason_code, message, status=status))

    # ------------------------------------------------------------------
    # admission: published limits, suspensions, freeze (DESIGN.md section 8)
    # ------------------------------------------------------------------

    def _limit_window(self, table: dict[str, _Window], kid: str, name: str) -> _Window:
        window = table.get(kid)
        if window is None:
            spec = self.limits[name]
            window = table[kid] = _Window(spec["count"], spec["interval_seconds"])
        return window

    def _prune_limits(self, now: float) -> None:
        """Forget the windows (and cached refusals) of keys that have gone quiet."""
        for kid in set(self._attempts) | set(self._registration_attempts):
            windows = [w for w in (self._attempts.get(kid), self._admitted.get(kid), self._registration_attempts.get(kid))
                       if w is not None]
            if all(w.idle(now) for w in windows):
                self._attempts.pop(kid, None)
                self._admitted.pop(kid, None)
                self._registration_attempts.pop(kid, None)
                for reason in ("rate_limit", "suspended", "frozen"):
                    self._refusal_cache.pop((kid, reason), None)

    def _active_suspension(self, kid: str) -> sqlite3.Row | None:
        """The suspension in force for *kid* (the latest suspension leaf naming it, if not ended)."""
        row = self._conn.execute(
            "SELECT * FROM suspensions WHERE target_kid = ? ORDER BY suspension_index DESC LIMIT 1", (kid,)
        ).fetchone()
        if row is None or (row["until"] is not None and row["until"] <= time.time()):
            return None
        return row

    def _suspend_for_flood(self, kid: str) -> None:
        """A ``suspension`` leaf, reason ``flood``, ending ``flood_suspension_seconds`` after its ``ts``."""
        now = int(time.time())
        until = now + self.limits["flood_suspension_seconds"]
        q = {"target_kid": kid, "reason_code": "flood", "until": until, "evidence_hash": None}
        with self._transaction():
            leaf = self._append_policy_leaf("suspension", q, ts=now)
            self._conn.execute(
                "INSERT INTO suspensions (suspension_index, target_kid, reason_code, until) VALUES (?, ?, 'flood', ?)",
                (leaf["leaf_index"], kid, until),
            )

    def _admit(self, ctx: SignedContext | _Attempt, kid: str) -> None:
        """Admission of a write by *kid* (a signing key or an unverified identity), before any other rule.

        In order: the flood threshold (which writes a ``suspension`` leaf,
        reason ``flood``), a freeze (``frozen``), a suspension in force
        (``suspended``) and the per-key write window (``rate_limit``).  These
        refusals are logged once per key and cause (:meth:`_refuse_once`).
        """
        now = time.time()
        state = self._write_state
        if getattr(state, "ctx", None) is ctx:
            state.admitted = True
        self._admissions += 1
        if self._admissions % 4096 == 0:
            self._prune_limits(now)
        attempts = self._limit_window(self._attempts, kid, "flood")
        attempts.add(now)
        if attempts.full(now) and self._active_suspension(kid) is None:
            self._suspend_for_flood(kid)
        if self._frozen_index is not None:
            self._refuse_once(
                ctx,
                "frozen",
                self._frozen_index,
                conflict_index=self._frozen_index,
                message="writes are frozen; reading and verification continue (GET /v2/freeze)",
            )
        suspension = self._active_suspension(kid)
        if suspension is not None:
            until = suspension["until"]
            self._refuse_once(
                ctx,
                "suspended",
                suspension["suspension_index"],
                conflict_index=suspension["suspension_index"],
                message=f"this key's writes are suspended ({suspension['reason_code']}); reads continue",
                retry_after=max(1, math.ceil(until - now)) if until is not None else None,
            )
        admitted = self._limit_window(self._admitted, kid, "writes")
        if admitted.full(now):
            spec = self.limits["writes"]
            self._refuse_once(
                ctx,
                "rate_limit",
                admitted.times[0],
                message=f"over the published write limit of {spec['count']} per {spec['interval_seconds']} s",
                retry_after=admitted.retry_after(now),
            )
        admitted.add(now)

    def _admit_registration(self, ctx: SignedContext | None) -> None:
        """A registration attempt (a name claim, an upgrade's new key, a first introduction): pre-identity traffic.

        In order (AICS-1 sections 10.2 and 13.1):

        * the global pre-identity bucket (``limits.preidentity``), which every
          registration attempt and every keyless request charges: once it is
          exhausted the attempt is refused before logging (429, no leaf), as
          section 10.2 allows; a fresh key per request is free, so only a
          global bound keeps claims from growing the log without limit;
        * a freeze (``frozen``, logged once per key and freeze);
        * the registration window of the submitting key
          (``limits.registrations``, per key, never per address): an attempt
          over it is a ``rate_limit`` refusal leaf, logged once per key and
          window (:meth:`_refuse_once`).

        *ctx* is ``None`` for a shared-secret claim, whose identifier the
        service assigns: only the global bucket and a freeze apply to it, and
        nothing that carried the secret is hashed or kept.
        """
        now = time.time()
        state = self._write_state
        if ctx is not None and getattr(state, "ctx", None) is ctx:
            state.registered = True
        self._admit_keyless()
        if self._frozen_index is not None:
            message = "writes are frozen; reading and verification continue (GET /v2/freeze)"
            if ctx is None:  # a shared-secret claim: nothing that carried the secret is hashed or kept
                raise Refusal("frozen", message, conflict_index=self._frozen_index, status=503)
            self._refuse_once(ctx, "frozen", self._frozen_index, conflict_index=self._frozen_index, message=message)
        if ctx is None:
            return
        window = self._limit_window(self._registration_attempts, ctx.kid, "registrations")
        if window.full(now):
            spec = self.limits["registrations"]
            self._refuse_once(
                ctx,
                "rate_limit",
                ("registrations", window.times[0]),
                message=(
                    f"over the published registration limit of {spec['count']} attempts per "
                    f"{spec['interval_seconds']} s for this key"
                ),
                retry_after=window.retry_after(now),
            )
        window.add(now)

    def _admit_owner(self, ctx: SignedContext) -> None:
        """An owner write of the SUP-1 profile (a task, an award, a quote or a completion): refused ``frozen`` while
        writes are frozen (AICS-1 section 20.9), logged once per freeze.  The owner is not rate-limited."""
        if self._frozen_index is not None:
            self._refuse_once(
                ctx,
                "frozen",
                self._frozen_index,
                conflict_index=self._frozen_index,
                message="writes are frozen: no task, award, quote or completion until they reopen (GET /v2/freeze)",
            )

    def _admit_keyless(self, window: _Window | None = None) -> None:
        """A request without a key: the global pre-identity window (shared-secret claims), or *window*.

        Notices pass their own bucket (:attr:`_notice_intake`), of the same published size.
        """
        window = self._preidentity if window is None else window
        now = time.time()
        if window.full(now):
            raise Refusal(
                "rate_limit",
                "over the published limit for requests without a key; retry later",
                status=429,
                retry_after=window.retry_after(now),
            )
        window.add(now)

    def _load_freeze_state(self) -> int | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT freeze_index, state FROM freezes ORDER BY freeze_index DESC LIMIT 1"
            ).fetchone()
            return row["freeze_index"] if row is not None and row["state"] == "frozen" else None

    def _chain_row(self, kid: str) -> sqlite3.Row | None:
        return self._conn.execute("SELECT * FROM envelope_chain WHERE kid = ?", (kid,)).fetchone()

    def _check_chain(self, ctx: SignedContext) -> None:
        """Right before acceptance, under the writer lock: not a replay, and the next envelope in its key's chain.

        AICS-1 sections 4.2 and 4.3: a live ``(kid, nonce)`` record is a
        ``replay``; otherwise ``seq`` must be the chain's next and ``prev``
        ``hexH(J(E))`` of the last accepted envelope (``sequence`` refusal,
        citing that envelope's leaf).
        """
        self._check_replay(ctx)
        row = self._chain_row(ctx.kid)
        try:
            envelope_mod.check_chain_position(
                ctx.envelope,
                last_seq=None if row is None else row["last_seq"],
                last_hash=None if row is None else row["last_hash"],
            )
        except envelope_mod.ChainError as exc:
            expected = 0 if row is None else row["last_seq"] + 1
            self._refuse(
                ctx,
                "sequence",
                conflict_index=None if row is None else row["last_index"],
                message=f"envelope does not continue this key's chain ({exc}); expected seq {expected}",
            )

    def envelope_chain(self, kid: str) -> dict[str, Any] | None:
        """``{kid, last_seq, last_envelope_hash, last_index}`` for a signing key, or ``None``."""
        with self._lock:
            row = self._chain_row(kid)
            if row is None:
                return None
            return {
                "kid": kid,
                "last_seq": row["last_seq"],
                "last_envelope_hash": row["last_hash"],
                "last_index": row["last_index"],
            }

    # ------------------------------------------------------------------
    # identity: lookups
    # ------------------------------------------------------------------

    def signing_key_for(self, kid: str) -> Any:
        """Public key of any agent key ever bound to a name (current or not), else ``None``.

        Used to verify a request signature; whether the key may still act is
        decided afterwards (``stale_key`` / ``revoked`` refusals).
        """
        with self._lock:
            row = self._conn.execute("SELECT public_key_b64u FROM bound_keys WHERE kid = ?", (kid,)).fetchone()
            return keys.parse_public_key(row["public_key_b64u"]) if row else self.swarms.signing_key_for(kid)

    def owner_key_for(self, kid: str) -> Any:
        """The configured owner key when *kid* is its id, else ``None``."""
        if self.owner_public_key is not None and kid == self.owner_kid:
            return self.owner_public_key
        return None

    def _head_event(self, name_norm: str) -> sqlite3.Row | None:
        return self._conn.execute(
            "SELECT * FROM key_events WHERE name_norm = ? ORDER BY leaf_index DESC LIMIT 1", (name_norm,)
        ).fetchone()

    def _x25519_event(self, name_norm: str) -> sqlite3.Row | None:
        return self._conn.execute(
            """
            SELECT leaf_index, x25519_b64u FROM key_events
            WHERE name_norm = ? AND x25519_b64u IS NOT NULL ORDER BY leaf_index DESC LIMIT 1
            """,
            (name_norm,),
        ).fetchone()

    def _actor_from_name(self, name_norm: str) -> dict[str, Any] | None:
        n = self._conn.execute("SELECT * FROM names WHERE name_norm = ?", (name_norm,)).fetchone()
        if n is None:
            return None
        head = self._head_event(name_norm)
        kid = head["kid_after"]
        key_row = (
            self._conn.execute("SELECT * FROM bound_keys WHERE kid = ?", (kid,)).fetchone() if kid else None
        )
        x_event = self._x25519_event(name_norm)
        tier = head["tier_after"]
        revoked = bool(head["revoked"])
        public_b64u = key_row["public_key_b64u"] if key_row else None
        did = kid  # the kid is the did:key (AICS-1 section 3.1)
        if kid:
            actor_kid = kid
        elif tier == ident.TIER_UNVERIFIED and not revoked:
            actor_kid = n["unverified_id"]
        else:
            actor_kid = None
        return {
            "name": name_norm,
            "agent_id": name_norm,
            "handle": name_norm,
            "ans_address": ident.ans_address(name_norm),
            "tier": tier,
            "tier_label": ident.TIER_LABELS.get(tier, tier),
            "revoked": revoked,
            "revoked_index": head["leaf_index"] if revoked else None,
            "kid": kid,
            "did": did,
            "public_key_b64u": public_b64u,
            "key_leaf_index": key_row["bound_index"] if key_row else None,
            "x25519_public_key_b64u": x_event["x25519_b64u"] if x_event else None,
            "x25519_leaf_index": x_event["leaf_index"] if x_event else None,
            "claim_index": n["claim_index"],
            "tlog_leaf_index": n["claim_index"],
            "head_index": head["leaf_index"],
            "unverified_id": n["unverified_id"],
            "actor_kid": actor_kid,
            "recovery_kid": n["recovery_kid"],
            "envelope_chain": self.envelope_chain(kid) if kid else None,
            "created_at": n["created_at"],
        }

    def resolve_agent(self, identifier: str) -> dict[str, Any] | None:
        """Agent by name (``alice``, ``@alice``, ``@alice.wesupport-ai.com``), by ``did:key`` or by ``unverified:`` id.

        A ``did:key`` of a key the name once held resolves to the name;
        ``kid:<did:key>`` is accepted too.
        """
        ident_text = (identifier or "").strip()
        if ident_text.startswith("kid:"):
            ident_text = ident_text[4:]
        with self._lock:
            if ident_text.startswith("did:key:"):
                if not _is_kid(ident_text):
                    return None
                row = self._conn.execute("SELECT name_norm FROM bound_keys WHERE kid = ?", (ident_text,)).fetchone()
                member = self.swarms.member_for(ident_text) if row is None else None
                return self._actor_from_name(row["name_norm"]) if row else self.swarms.actor(member) if member else None
            if ident_text.startswith(keys.UNVERIFIED_PREFIX):
                row = self._conn.execute("SELECT name_norm FROM names WHERE unverified_id = ?", (ident_text,)).fetchone()
                member = self.swarms.member_for(ident_text) if row is None else None
                return self._actor_from_name(row["name_norm"]) if row else self.swarms.actor(member) if member else None
            try:
                name = ident.normalize_name(ident_text)
            except ValueError:
                return None
            return self._actor_from_name(name)

    def name_view(self, identifier: str) -> dict[str, Any] | None:
        """The key chain of a name through a stated checkpoint (``GET /v2/names/{name_norm}``, AICS-1 section 12.1).

        ``indices`` are the claim and every key event naming the name, in log
        order, below ``size``, the size of ``checkpoint_note`` (``U64`` of the
        signed note); ``x25519`` and ``x25519_leaf_index`` are the current
        encryption key and the leaf that set it.  A projection, not an
        authoritative key field: a complete authenticated scan of the tiles up
        to that checkpoint reconstructs the same chain (section 3.2).
        """
        with self._lock:
            actor = self.resolve_agent(identifier)
            if actor is None:
                return None
            size, note = self.stated_checkpoint()
            events = self._conn.execute(
                "SELECT * FROM key_events WHERE name_norm = ? AND leaf_index < ? ORDER BY leaf_index ASC",
                (actor["name"], size),
            ).fetchall()
            return {
                "name_norm": actor["name"],
                "indices": [e["leaf_index"] for e in events],
                "size": size,
                "checkpoint_note": keys.b64u_encode(note),
                "x25519": actor["x25519_public_key_b64u"],
                "x25519_leaf_index": actor["x25519_leaf_index"],
                "name": actor["name"],
                "ans_address": actor["ans_address"],
                "tier": actor["tier"],
                "tier_label": actor["tier_label"],
                "revoked": actor["revoked"],
                "claim_index": actor["claim_index"],
                "head_index": actor["head_index"],
                "events": [
                    {
                        "leaf_index": e["leaf_index"],
                        "type": e["event_type"],
                        "prev_event_index": e["prev_event_index"],
                        "kid_after": e["kid_after"],
                        "tier_after": e["tier_after"],
                        "sets_ed25519": e["ed25519_b64u"],
                        "sets_x25519": e["x25519_b64u"],
                    }
                    for e in events
                ],
                "current": {
                    "kid": actor["kid"],
                    "did": actor["did"],
                    "public_key_b64u": actor["public_key_b64u"],
                    "key_leaf_index": actor["key_leaf_index"],
                    "x25519_public_key_b64u": actor["x25519_public_key_b64u"],
                    "x25519_leaf_index": actor["x25519_leaf_index"],
                    "recovery_kid": actor["recovery_kid"],
                },
                "envelope_chain": actor["envelope_chain"],
                "tree_size": self._log.tree.size,
                "root_hash_hex": self._log.tree.root().hex(),
            }

    def key_view(self, kid: str) -> dict[str, Any] | None:
        """A signing key: the name it was bound to, whether it is current, and its envelope chain."""
        with self._lock:
            if self.owner_kid and kid == self.owner_kid:
                return {
                    "kid": kid,
                    "role": "owner",
                    "public_key_b64u": self.owner_public_key_b64u,
                    "current": True,
                    "envelope_chain": self.envelope_chain(kid),
                }
            if kid == self.policy_kid:
                return {
                    "kid": kid,
                    "role": "policy",
                    "public_key_b64u": self.policy_public_key_b64u,
                    "current": True,
                    "envelope_chain": self.envelope_chain(kid),
                }
            row = self._conn.execute("SELECT * FROM bound_keys WHERE kid = ?", (kid,)).fetchone()
            if row is None:
                return None
            head = self._head_event(row["name_norm"])
            return {
                "kid": kid,
                "role": "agent",
                "name": row["name_norm"],
                "public_key_b64u": row["public_key_b64u"],
                "bound_index": row["bound_index"],
                "retired_index": row["retired_index"],
                "current": head["kid_after"] == kid,
                "envelope_chain": self.envelope_chain(kid),
                "suspension": self.suspension_view(kid),
            }

    def list_directory(self, q: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Names, newest claim first, with their tiers and current keys; *q* filters by a part of the name.

        A name is all a claim publishes (AICS-1 section 5.3): display names and
        descriptions are no part of it, so there is nothing else to search.
        """
        with self._lock:
            if q:
                rows = self._conn.execute(
                    "SELECT name_norm FROM names WHERE instr(name_norm, ?) > 0 ORDER BY claim_index DESC LIMIT ?",
                    (q.lower(), limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT name_norm FROM names ORDER BY claim_index DESC LIMIT ?", (limit,)
                ).fetchall()
            return [a for r in rows if (a := self._actor_from_name(r["name_norm"])) is not None]

    # ------------------------------------------------------------------
    # identity: who may act
    # ------------------------------------------------------------------

    def _agent_actor(self, ctx: SignedContext, *, log_refusal: bool = True) -> dict[str, Any]:
        """The name whose current key signed *ctx*, or a ``revoked`` / ``stale_key`` refusal.

        Writes (``log_refusal=True``) first pass admission (:meth:`_admit`:
        flood, freeze, suspension, write limit) and are refused with a
        ``refusal`` leaf; reads are refused without one and are never limited
        or frozen.
        """
        row = self._conn.execute("SELECT * FROM bound_keys WHERE kid = ?", (ctx.kid,)).fetchone()
        if row is None and self.swarms.member_for(ctx.kid):
            return self.swarms.agent_actor(ctx, log_refusal=log_refusal)
        if row is None:
            if log_refusal:
                raise Rejected("unknown_key", "signing key is not bound to any name", status=403)
            raise PermissionError("signing key is not bound to any name")
        if log_refusal:
            self._admit(ctx, ctx.kid)
        head = self._head_event(row["name_norm"])
        if head["revoked"]:
            self._deny(
                ctx,
                "revoked",
                conflict_index=head["leaf_index"],
                message="this name was revoked permanently",
                log=log_refusal,
            )
        if head["kid_after"] != ctx.kid:
            self._deny(
                ctx,
                "stale_key",
                conflict_index=row["retired_index"],
                message="this key was rotated away; sign with the name's current key",
                log=log_refusal,
            )
        actor = self._actor_from_name(row["name_norm"])
        assert actor is not None
        return actor

    def _deny(self, ctx: SignedContext, reason_code: str, *, conflict_index: int | None, message: str, log: bool) -> NoReturn:
        if log:
            self._refuse(ctx, reason_code, conflict_index=conflict_index, message=message)
        raise Refusal(reason_code, message, conflict_index=conflict_index, status=403)

    def read_actor(self, ctx: SignedContext) -> dict[str, Any]:
        """The agent behind a signed read: its key must be current and its name not revoked."""
        with self._lock:
            return self._agent_actor(ctx, log_refusal=False)

    def _owner_actor(self, ctx: SignedContext) -> dict[str, Any]:
        if self.owner_kid is None or ctx.kid != self.owner_kid:
            raise PermissionError("owner-only operation")
        return {
            "role": "owner",
            "kid": self.owner_kid,
            "actor_kid": self.owner_kid,
            "public_key_b64u": self.owner_public_key_b64u,
        }

    def authenticate_secret(self, name: str, secret: str) -> dict[str, Any]:
        """The unverified identity holding *name*, if *secret* matches its stored hash."""
        try:
            name_norm = ident.normalize_name(name)
        except ValueError:
            name_norm = None
        with self._lock:
            row = (
                self._conn.execute("SELECT * FROM names WHERE name_norm = ?", (name_norm,)).fetchone()
                if name_norm
                else None
            )
            stored = row["secret_hash"] if row else None
        # Run the KDF even for unknown names so timing says nothing about which exist.
        ok = ident.check_secret(secret, stored or _DUMMY_SECRET_HASH)
        if not stored or not ok:
            raise PermissionError("name and secret do not match an unverified identity")
        with self._lock:
            head = self._head_event(name_norm)
            if head is None or head["revoked"] or head["tier_after"] != ident.TIER_UNVERIFIED:
                raise PermissionError("name and secret do not match an unverified identity")
            actor = self._actor_from_name(name_norm)
            assert actor is not None
            return actor

    # ------------------------------------------------------------------
    # identity: key events
    # ------------------------------------------------------------------

    @staticmethod
    def _require_exact_keys(q: Mapping[str, Any], expected: frozenset[str], what: str) -> None:
        got = set(q)
        if got != expected:
            missing = sorted(expected - got)
            extra = sorted(got - expected)
            raise ValueError(f"{what} payload must have exactly {sorted(expected)} (missing {missing}, extra {extra})")

    def _require_type(self, ctx: SignedContext, entry_type: str) -> None:
        """The envelope's signed ``protected.type`` must be *entry_type* (its origin was checked with its signature)."""
        if ctx.envelope is None or ctx.entry_type != entry_type:
            raise ValueError(f"this write takes an envelope of type {entry_type!r}")
        if ctx.envelope["protected"]["origin"] != self.origin:
            raise ValueError(f"the envelope's origin must be {self.origin!r}")

    @staticmethod
    def _int_index(value: Any, field: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{field} must be a non-negative integer")
        return value

    def _parse_grant(self, grant: Any, t: int) -> dict[str, Any] | None:
        """A claim's ``initial_grant`` (a ``grant_spec``: ``{sender_kid: did:key or "*", max, expires}``), at time *t*."""
        if grant is None:
            return None
        if not isinstance(grant, Mapping):
            raise ValueError("initial_grant must be an object or null")
        self._require_exact_keys(grant, _GRANT_KEYS, "initial_grant")
        sender = grant["sender_kid"]
        if sender != "*" and not _is_kid(sender):
            raise ValueError("initial_grant.sender_kid must be '*' or a did:key")
        maximum, expires = grant["max"], grant["expires"]
        if not _is_uint(maximum, GRANT_MAX_MESSAGES):
            raise ValueError("initial_grant.max must be a uint")
        if not _is_uint(expires, MAX_TIME) or (maximum > 0 and expires <= t):
            raise ValueError("initial_grant.expires must be a unix time after the claim's ts")
        return {"sender_kid": sender, "max": maximum, "expires": expires}

    def _service_kids(self) -> set[str]:
        return {k for k in (self.server_kid, self.policy_kid, self.owner_kid) if k}

    def _check_new_key(self, ctx: SignedContext, kid: str) -> None:
        """A key is bound to at most one name, once, and is never a service key."""
        self.swarms.check_new_key(ctx, kid)
        if kid in self._service_kids():
            self._refuse(ctx, "key_reuse", message="a service key cannot be an agent key")
        row = self._conn.execute("SELECT bound_index FROM bound_keys WHERE kid = ?", (kid,)).fetchone()
        if row is not None:
            self._refuse(
                ctx,
                "key_reuse",
                conflict_index=row["bound_index"],
                message="this key is already bound to a name; every name needs its own key",
            )

    def _check_successor(self, ctx: SignedContext, name_norm: str, prev_event_index: int) -> sqlite3.Row:
        """*prev_event_index* must be the name's latest event: else ``key_fork`` or ``predecessor``."""
        head = self._head_event(name_norm)
        if head["leaf_index"] == prev_event_index:
            return head
        successor = self._conn.execute(
            "SELECT leaf_index FROM key_events WHERE name_norm = ? AND prev_event_index = ?",
            (name_norm, prev_event_index),
        ).fetchone()
        if successor is not None:
            self._refuse(
                ctx,
                "key_fork",
                conflict_index=successor["leaf_index"],
                message="another event already follows that prev_event_index; the first one in the log wins",
            )
        self._refuse(
            ctx,
            "predecessor",
            conflict_index=head["leaf_index"],
            message=f"prev_event_index must name the latest key event of this name ({head['leaf_index']})",
        )

    @_signed_write
    def claim_name(self, ctx: SignedContext) -> dict[str, Any]:
        """``name.claim`` by a key: the envelope is signed by the claimed key (proof of possession).

        ``Q = {name_norm, prev_event_index: null, ed25519, x25519, tier,
        recovery_kid, recovery_pop, initial_grant}`` (AICS-1 section 5.3): the
        leaf binds the Ed25519 key (whose ``did:key`` is the envelope's
        ``kid``), the X25519 key, the key tier the agent declares, an optional
        recovery key with its own proof of possession (decision 7A, section
        7.1) and an optional initial inbox grant (decision 8).  A name is all a
        claim publishes: display names and descriptions are no part of it.
        A recovery proof that does not verify is ``bad_signature``; a recovery
        key already bound to a name, or a service key, is ``key_reuse``.
        """
        q = ctx.payload
        self._require_exact_keys(q, _CLAIM_KEYS, "name.claim")
        self._require_type(ctx, "name.claim")
        name_norm = ident.require_normalized_name(q["name_norm"])
        if q["prev_event_index"] is not None:
            raise ValueError("prev_event_index must be null in a name.claim")
        ed_pub = ident.parse_ed25519(q["ed25519"], "ed25519")
        ident.parse_x25519(q["x25519"], "x25519")
        if keys.did_key(ed_pub) != ctx.kid:
            raise ValueError("the claim must be signed by the key it claims (kid must be the did:key of ed25519)")
        tier = q["tier"]
        if tier not in ident.KEY_TIERS:
            raise ValueError(f"tier must be one of {', '.join(ident.KEY_TIERS)}")
        recovery_kid, recovery_pop = q["recovery_kid"], q["recovery_pop"]
        if (recovery_kid is None) != (recovery_pop is None):
            raise ValueError("recovery_kid and recovery_pop go together")
        recovery_pub = None
        if recovery_kid is not None:
            recovery_pub = ident.parse_kid(recovery_kid, "recovery_kid")
            if recovery_kid == ctx.kid:
                raise ValueError("the recovery key must differ from the signing key")
            _check_proof_shape(recovery_pop, "recovery_pop")
        grant = self._parse_grant(q["initial_grant"], ctx.t)

        with self._lock:
            self._admit_registration(ctx)
            self._check_new_key(ctx, ctx.kid)
            if recovery_kid is not None:
                if recovery_kid in self._service_kids():
                    raise Rejected("key_reuse", "the recovery key must not be a service key")
                bound = self._conn.execute("SELECT bound_index FROM bound_keys WHERE kid = ?", (recovery_kid,)).fetchone()
                if bound is not None:
                    raise Rejected(
                        "key_reuse",
                        "the recovery key must not be a key already bound to a name",
                        conflict_index=bound["bound_index"],
                    )
                self._verify_proof(
                    recovery_pop,
                    ident.recovery_message(
                        origin=self.origin,
                        name_norm=name_norm,
                        ed25519=q["ed25519"],
                        x25519=q["x25519"],
                        recovery_kid=recovery_kid,
                    ),
                    recovery_pub,
                    "recovery_pop",
                )
            self._check_name_free(ctx, name_norm)
            self._check_chain(ctx)
            now_iso = _utc_iso(ctx.t)
            with self._transaction():
                leaf = self._append_signed(ctx, "name.claim")
                idx = leaf["leaf_index"]
                self._conn.execute(
                    "INSERT INTO names (name_norm, claim_index, recovery_kid, created_at) VALUES (?, ?, ?, ?)",
                    (name_norm, idx, recovery_kid, now_iso),
                )
                self._conn.execute(
                    """
                    INSERT INTO key_events
                        (leaf_index, name_norm, event_type, prev_event_index, kid_after, tier_after, ed25519_b64u, x25519_b64u)
                    VALUES (?, ?, 'name.claim', NULL, ?, ?, ?, ?)
                    """,
                    (idx, name_norm, ctx.kid, tier, q["ed25519"], q["x25519"]),
                )
                self._conn.execute(
                    "INSERT INTO bound_keys (kid, public_key_b64u, name_norm, bound_index) VALUES (?, ?, ?, ?)",
                    (ctx.kid, q["ed25519"], name_norm, idx),
                )
                if grant is not None:
                    # An initial grant takes effect at the claim; its grant index is the claim leaf.
                    self._insert_grant_row(idx, ctx.kid, grant["sender_kid"], grant["max"], grant["expires"])
            self.increment_counter("agents_registered", 1)
            actor = self._actor_from_name(name_norm)
            return {"agent": actor, **self._written(leaf)}

    @staticmethod
    def _verify_proof(proof: Any, message: bytes, public_key: Any, field: str) -> None:
        """An inner proof of a key event (AICS-1 section 7.1): one that does not verify is ``bad_signature``."""
        try:
            ident.verify_proof(proof, message, public_key, field)
        except ValueError as exc:
            raise Rejected("bad_signature", str(exc), status=403) from None

    def _check_name_free(self, ctx: SignedContext, name_norm: str) -> None:
        """A name is claimed once and never re-claimed: ``name_taken`` (or ``revoked``) citing the first claim."""
        existing = self._conn.execute("SELECT * FROM names WHERE name_norm = ?", (name_norm,)).fetchone()
        if existing is None:
            return
        head = self._head_event(name_norm)
        if head["revoked"]:
            self._refuse(ctx, "revoked", conflict_index=head["leaf_index"], message="a revoked name is never re-claimed")
        self._refuse(
            ctx,
            "name_taken",
            conflict_index=existing["claim_index"],
            message=f"name '{name_norm}' was claimed first at leaf {existing['claim_index']}",
        )

    def secret_claim_payload(self, name: str) -> dict[str, Any]:
        """``Q`` of a shared-secret ``name.claim``: no keys, no recovery, no grant (AICS-1 section 5.3)."""
        return {
            "name_norm": ident.normalize_name(name),
            "prev_event_index": None,
            "ed25519": None,
            "x25519": None,
            "tier": ident.TIER_UNVERIFIED,
            "recovery_kid": None,
            "recovery_pop": None,
            "initial_grant": None,
        }

    def fallback_proposal(self, entry_type: str, q: dict[str, Any], kid: str, t: int) -> dict[str, Any]:
        """``U`` of a shared-secret write by *kid* at *t* (AICS-1 sections 4.1 and 11.3): the next of its chain.

        The gate shows it for the agent to confirm with its secret; the JSON
        endpoints that take a secret build it the same way.
        """
        with self._lock:
            chain = self._chain_row(kid)
            seq = 0 if chain is None else chain["last_seq"] + 1
            prev = None if chain is None else chain["last_hash"]
        return ev.propose(entry_type, q, origin=self.origin, kid=kid, t=t, seq=seq, prev=prev, scheme=ev.SHARED_SECRET)

    def fallback_context(
        self,
        unsigned: dict[str, Any],
        t: int,
        *,
        role: str = "unverified",
        fields: dict[str, Any] | None = None,
    ) -> SignedContext:
        """The context of a confirmed shared-secret write: ``E`` is *unsigned* with ``sig: null``, checked at *t*.

        Raises :class:`aics_server.envelopes.EnvelopeRejected` for a malformed,
        stale or wrong-tier envelope.  The secret is checked separately and
        never enters the envelope.
        """
        env = {**unsigned, "sig": None}
        checked = ev.check_fallback(env, origin=self.origin, t=t)
        return SignedContext.of_envelope(checked, t=t, role=role, fields=fields)

    def claim_name_secret(self, ctx: SignedContext, secret: str) -> dict[str, Any]:
        """``name.claim`` on the unverified tier: a chosen secret, stored only as a salted Argon2id hash (AICS-1 section 3.3).

        *ctx* carries the fallback envelope (``alg: none``, ``kid`` the
        ``unverified:`` identifier the service assigned, ``auth:
        shared-secret``, ``sig: null``; AICS-1 section 4.1).  The entry carries
        it and the policy key's attestation (section 5.1) instead of an agent
        signature, so anyone can see that this identity rests on the service's
        word, not on a key.  Nothing about the secret reaches the leaf.  A
        refused claim (name taken, frozen, over a window) writes no leaf: it is
        pre-identity.
        """
        if self.swarms.member_for(ctx.kid):
            return self.swarms.claim_secret(ctx, secret)
        if ctx.scheme != ev.SHARED_SECRET or not keys.is_unverified_id(ctx.kid):
            raise ValueError("a secret claim carries a shared-secret envelope for an unverified identifier")
        q = ctx.payload
        self._require_exact_keys(q, _CLAIM_KEYS, "name.claim")
        self._require_type(ctx, "name.claim")
        name_norm = ident.require_normalized_name(q["name_norm"])
        expected = self.secret_claim_payload(name_norm)
        if q != expected:
            raise ValueError(
                "a secret claim has a null prev_event_index, no keys, the tier unverified, no recovery key and no grant"
            )
        ident.validate_secret(secret)
        with self._lock:
            self._admit_registration(None)  # the global pre-identity bucket, then a freeze
            taken = self._conn.execute("SELECT claim_index FROM names WHERE name_norm = ?", (name_norm,)).fetchone()
        if taken is not None:  # checked again under the lock below; this only spares the KDF
            raise RuntimeError(f"name '{name_norm}' was claimed first at leaf {taken['claim_index']}")
        secret_hash = ident.hash_secret(secret)  # outside the lock: the KDF takes tens of milliseconds
        with self._lock:
            existing = self._conn.execute("SELECT claim_index FROM names WHERE name_norm = ?", (name_norm,)).fetchone()
            if existing is not None:
                raise RuntimeError(f"name '{name_norm}' was claimed first at leaf {existing['claim_index']}")
            if self._conn.execute(
                "SELECT 1 FROM names WHERE unverified_id = ? UNION SELECT 1 FROM envelope_chain WHERE kid = ?",
                (ctx.kid, ctx.kid),
            ).fetchone():
                raise RuntimeError("this unverified identifier is taken; ask for a new proposal")
            if self._live_nonce(ctx.kid, ctx.nonce, ctx.t) is not None or ctx.envelope["protected"]["seq"] != 0:
                raise RuntimeError("a new identity's claim is its first envelope (seq 0) with a fresh nonce")
            now_iso = _utc_iso(ctx.t)
            with self._transaction():
                leaf = self._append_signed(ctx, "name.claim")
                idx = leaf["leaf_index"]
                self._conn.execute(
                    """
                    INSERT INTO names (name_norm, claim_index, unverified_id, secret_hash, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (name_norm, idx, ctx.kid, secret_hash, now_iso),
                )
                self._conn.execute(
                    """
                    INSERT INTO key_events (leaf_index, name_norm, event_type, prev_event_index, kid_after, tier_after)
                    VALUES (?, ?, 'name.claim', NULL, NULL, ?)
                    """,
                    (idx, name_norm, ident.TIER_UNVERIFIED),
                )
            self.increment_counter("agents_registered", 1)
            actor = self._actor_from_name(name_norm)
            return {"agent": actor, **self._written(leaf)}

    def _rotation_fields(self, q: Mapping[str, Any], mode: str) -> dict[str, Any]:
        """``R`` of a rotation or an upgrade (AICS-1 section 7.2), checked: the bytes both proofs sign follow from it."""
        name_norm = ident.require_normalized_name(q["name_norm"])
        prev = self._int_index(q["prev_event_index"], "prev_event_index")
        ident.parse_ed25519(q["new_ed25519"], "new_ed25519")
        if q["new_x25519"] is not None:
            ident.parse_x25519(q["new_x25519"], "new_x25519")
        elif mode == "upgrade":
            raise ValueError("an upgrade must bind an X25519 key (new_x25519)")
        if q["new_tier"] not in ident.KEY_TIERS:
            raise ValueError(f"new_tier must be one of {', '.join(ident.KEY_TIERS)}")
        return {
            "origin": self.origin,
            "name_norm": name_norm,
            "prev_event_index": prev,
            "new_ed25519": q["new_ed25519"],
            "new_x25519": q["new_x25519"],
            "new_tier": q["new_tier"],
            "mode": mode,
        }

    def _parse_rotation(self, ctx: SignedContext, mode: str) -> dict[str, Any]:
        q = ctx.payload
        self._require_exact_keys(q, _UPGRADE_KEYS if mode == "upgrade" else _ROTATE_KEYS, "key.rotate")
        self._require_type(ctx, "key.rotate")
        if q["mode"] != mode:
            raise ValueError(f"mode must be {mode!r} on this endpoint")
        message_fields = self._rotation_fields(q, mode)
        new_pub = ident.parse_ed25519(q["new_ed25519"], "new_ed25519")
        for field in ("sig_old", "sig_new") if mode == "rotate" else ("sig_new",):
            _check_proof_shape(q[field], field)
        if mode == "upgrade":
            secret_check = _canonical_b64u(q["secret_check"])
            if secret_check is None or len(secret_check) != 64:
                raise ValueError("secret_check is a sig64: unpadded base64url of 64 signature bytes")
        return {
            "name_norm": message_fields["name_norm"],
            "prev": message_fields["prev_event_index"],
            "new_pub": new_pub,
            "new_kid": keys.did_key(new_pub),
            "message_fields": message_fields,
            "message": ident.rotation_message(**message_fields),
        }

    @_signed_write
    def rotate_key(self, ctx: SignedContext) -> dict[str, Any]:
        """``key.rotate`` (mode ``rotate``): signed by the current key, ``sig_old`` and ``sig_new`` both verify.

        The first rotation citing a given event wins; a later one is refused
        with a ``key_fork`` refusal leaf.  The new key takes over at indices
        after the rotation leaf; the old key's envelope chain ends there, and
        the new key's starts at ``seq`` 0 (AICS-1 section 4.2).
        """
        q = ctx.payload
        parsed = self._parse_rotation(ctx, "rotate")
        name_norm = parsed["name_norm"]
        with self._lock:
            actor = self._agent_actor(ctx)
            if actor["name"] != name_norm:
                raise Rejected("stale_key", "a key event must name the name its signing key holds", status=403)
            self._check_chain(ctx)
            self._check_successor(ctx, name_norm, parsed["prev"])
            if parsed["new_kid"] == ctx.kid:
                raise Rejected(
                    "key_reuse", "new_ed25519 must differ from the current key", conflict_index=actor["key_leaf_index"]
                )
            self._check_new_key(ctx, parsed["new_kid"])
            self._verify_proof(q["sig_old"], parsed["message"], keys.parse_public_key(actor["public_key_b64u"]), "sig_old")
            self._verify_proof(q["sig_new"], parsed["message"], parsed["new_pub"], "sig_new")
            with self._transaction():
                leaf = self._append_signed(ctx, "key.rotate")
                idx = leaf["leaf_index"]
                self._conn.execute(
                    """
                    INSERT INTO key_events
                        (leaf_index, name_norm, event_type, prev_event_index, kid_after, tier_after, ed25519_b64u, x25519_b64u)
                    VALUES (?, ?, 'key.rotate', ?, ?, ?, ?, ?)
                    """,
                    (idx, name_norm, parsed["prev"], parsed["new_kid"], q["new_tier"], q["new_ed25519"], q["new_x25519"]),
                )
                self._conn.execute(
                    "INSERT INTO bound_keys (kid, public_key_b64u, name_norm, bound_index) VALUES (?, ?, ?, ?)",
                    (parsed["new_kid"], q["new_ed25519"], name_norm, idx),
                )
                self._conn.execute("UPDATE bound_keys SET retired_index = ? WHERE kid = ?", (idx, ctx.kid))
            return {"agent": self._actor_from_name(name_norm), **self._written(leaf)}

    def _upgrade_check_signature(self, fields: Mapping[str, Any]) -> str:
        return keys.b64u_encode(self.policy_key.sign(ident.upgrade_check_message(**fields)))

    def upgrade_check(self, name: str, secret: str, q: Mapping[str, Any]) -> dict[str, Any]:
        """Check an unverified name's secret for an upgrade and return the policy key's ``secret_check`` over ``R``.

        AICS-1 sections 7.2 and 11.4: the policy key signs ``UTF8("AICS-1
        upgrade-check\n") || J(R)`` after checking the old secret over TLS; the
        new key then signs an envelope whose ``Q`` carries that ``secret_check``
        with ``sig_new``, and the entry logs both proofs.  *q* holds ``R``'s
        members (``name_norm``, ``prev_event_index``, ``new_ed25519``,
        ``new_x25519``, ``new_tier``); ``prev_event_index`` must be the name's
        latest event.  Nothing is logged; a wrong secret raises
        :class:`CredentialError` (no leaf: a credential control).  Keyless and
        KDF-bound, so the global pre-identity window applies.
        """
        wanted = {"name_norm", "prev_event_index", "new_ed25519", "new_x25519", "new_tier"}
        if not isinstance(q, Mapping) or set(q) != wanted:
            raise ValueError(f"an upgrade check names exactly {', '.join(sorted(wanted))}")
        fields = self._rotation_fields({**q, "mode": "upgrade"}, "upgrade")
        name_norm = fields["name_norm"]
        if ident.normalize_name(name) != name_norm:
            raise ValueError("the upgrade check names the name whose secret it sends")
        with self._lock:
            self._admit_keyless()
        try:
            actor = self.authenticate_secret(name_norm, secret)
        except PermissionError:
            raise CredentialError("the secret does not match this name") from None
        with self._lock:
            head = self._head_event(name_norm)
            if head is None or head["revoked"] or head["tier_after"] != ident.TIER_UNVERIFIED:
                raise CredentialError("the secret does not match this name")
            if head["leaf_index"] != fields["prev_event_index"]:
                raise ValueError(f"prev_event_index must name the name's latest event ({head['leaf_index']})")
            return {
                "name_norm": name_norm,
                "unverified_id": actor["unverified_id"],
                "statement": fields,
                "secret_check": self._upgrade_check_signature(fields),
            }

    @_signed_write
    def upgrade_name(self, ctx: SignedContext) -> dict[str, Any]:
        """``key.rotate`` (mode ``upgrade``): an unverified name moves to a key.

        ``Q = {mode: upgrade, name_norm, prev_event_index, new_ed25519,
        new_x25519, new_tier, sig_old: null, sig_new, secret_check}`` (AICS-1
        sections 5.3 and 7.2), signed by the new key at ``seq`` 0.
        ``secret_check`` is the policy key's statement, from
        :meth:`upgrade_check`, that the old secret was checked for this very
        ``R``; continuity with the secret identity remains the service's word.
        The stored secret hash is erased.
        """
        q = ctx.payload
        parsed = self._parse_rotation(ctx, "upgrade")
        if q["sig_old"] is not None:
            raise ValueError("sig_old must be null in an upgrade: an unverified name has no old key")
        if parsed["new_kid"] != ctx.kid:
            raise ValueError("an upgrade is signed by the new key (kid must be the did:key of new_ed25519)")
        if not isinstance(q["secret_check"], str) or not hmac.compare_digest(
            q["secret_check"], self._upgrade_check_signature(parsed["message_fields"])
        ):
            # secret_check is the policy key's signature over R (AICS-1 section 7.2): one over anything else
            # does not verify.
            raise Rejected(
                "bad_signature",
                "secret_check must be the policy key's upgrade check of exactly this R (claim-upgrade at the TLS gate)",
                status=403,
                cause="secret_check",
            )
        name_norm = parsed["name_norm"]
        with self._lock:
            self._admit(ctx, ctx.kid)
            row = self._conn.execute("SELECT * FROM names WHERE name_norm = ?", (name_norm,)).fetchone()
            if row is None:
                raise Rejected(
                    "predecessor", f"prev_event_index names no event: name '{name_norm}' is not claimed", status=404
                )
            held = self._active_suspension(row["unverified_id"]) if row["unverified_id"] else None
            if held is not None:  # an upgrade does not leave a suspension behind with the old identity
                self._refuse_once(
                    ctx,
                    "suspended",
                    held["suspension_index"],
                    conflict_index=held["suspension_index"],
                    message=f"this name's writes are suspended ({held['reason_code']})",
                )
            head = self._head_event(name_norm)
            if head["revoked"]:
                self._refuse(ctx, "revoked", conflict_index=head["leaf_index"], message="this name was revoked permanently")
            if head["tier_after"] != ident.TIER_UNVERIFIED or row["secret_hash"] is None:
                raise Rejected(
                    "tier_required",
                    "only an unverified name can upgrade; a key name rotates",
                    status=403,
                    conflict_index=head["leaf_index"],
                )
            self._check_chain(ctx)
            self._check_successor(ctx, name_norm, parsed["prev"])
            self._check_new_key(ctx, parsed["new_kid"])
            self._verify_proof(q["sig_new"], parsed["message"], parsed["new_pub"], "sig_new")
            with self._transaction():
                leaf = self._append_signed(ctx, "key.rotate")
                idx = leaf["leaf_index"]
                self._conn.execute(
                    """
                    INSERT INTO key_events
                        (leaf_index, name_norm, event_type, prev_event_index, kid_after, tier_after, ed25519_b64u, x25519_b64u)
                    VALUES (?, ?, 'key.rotate', ?, ?, ?, ?, ?)
                    """,
                    (idx, name_norm, parsed["prev"], ctx.kid, q["new_tier"], q["new_ed25519"], q["new_x25519"]),
                )
                self._conn.execute(
                    "INSERT INTO bound_keys (kid, public_key_b64u, name_norm, bound_index) VALUES (?, ?, ?, ?)",
                    (ctx.kid, q["new_ed25519"], name_norm, idx),
                )
                self._conn.execute("UPDATE names SET secret_hash = NULL WHERE name_norm = ?", (name_norm,))
            return {"agent": self._actor_from_name(name_norm), **self._written(leaf)}

    @_signed_write
    def revoke_name(self, ctx: SignedContext) -> dict[str, Any]:
        """``key.revoke``: signed by the current key, ends the name for good.  No re-claim, ever."""
        q = ctx.payload
        self._require_exact_keys(q, _REVOKE_KEYS, "key.revoke")
        self._require_type(ctx, "key.revoke")
        name_norm = ident.require_normalized_name(q["name_norm"])
        prev = self._int_index(q["prev_event_index"], "prev_event_index")
        if q["reason_code"] not in ident.REVOKE_REASONS:
            raise ValueError(f"reason_code must be one of {', '.join(ident.REVOKE_REASONS)}")
        with self._lock:
            actor = self._agent_actor(ctx)
            if actor["name"] != name_norm:
                raise Rejected("stale_key", "a key event must name the name its signing key holds", status=403)
            self._check_chain(ctx)
            head = self._check_successor(ctx, name_norm, prev)
            with self._transaction():
                leaf = self._append_signed(ctx, "key.revoke")
                idx = leaf["leaf_index"]
                self._conn.execute(
                    """
                    INSERT INTO key_events
                        (leaf_index, name_norm, event_type, prev_event_index, kid_after, tier_after, revoked)
                    VALUES (?, ?, 'key.revoke', ?, NULL, ?, 1)
                    """,
                    (idx, name_norm, prev, head["tier_after"]),
                )
                self._conn.execute("UPDATE bound_keys SET retired_index = ? WHERE kid = ?", (idx, ctx.kid))
            return {"agent": self._actor_from_name(name_norm), **self._written(leaf)}

    @_signed_write
    def rotate_x25519(self, ctx: SignedContext) -> dict[str, Any]:
        """``x25519.rotate``: signed by the current Ed25519 key only; identity unchanged."""
        q = ctx.payload
        self._require_exact_keys(q, _X25519_KEYS, "x25519.rotate")
        self._require_type(ctx, "x25519.rotate")
        name_norm = ident.require_normalized_name(q["name_norm"])
        prev = self._int_index(q["prev_event_index"], "prev_event_index")
        ident.parse_x25519(q["new_x25519"], "new_x25519")
        with self._lock:
            actor = self._agent_actor(ctx)
            if actor["name"] != name_norm:
                raise Rejected("stale_key", "a key event must name the name its signing key holds", status=403)
            self._check_chain(ctx)
            head = self._check_successor(ctx, name_norm, prev)
            with self._transaction():
                leaf = self._append_signed(ctx, "x25519.rotate")
                self._conn.execute(
                    """
                    INSERT INTO key_events
                        (leaf_index, name_norm, event_type, prev_event_index, kid_after, tier_after, x25519_b64u)
                    VALUES (?, ?, 'x25519.rotate', ?, ?, ?, ?)
                    """,
                    (leaf["leaf_index"], name_norm, prev, ctx.kid, head["tier_after"], q["new_x25519"]),
                )
            return {"agent": self._actor_from_name(name_norm), **self._written(leaf)}

    # ------------------------------------------------------------------
    # generic signed writes
    # ------------------------------------------------------------------

    def _signed_entry(
        self,
        ctx: SignedContext,
        entry_type: str,
        write: Callable[[dict[str, Any]], None] | None = None,
        *,
        public_text: str | None = None,
    ) -> dict[str, Any]:
        """The last step of a write with a public body: the secret-format scan of *public_text*, then the leaf.

        Called under the lock once the actor, the envelope chain, the payload
        schema, the body and every state rule were checked.  The leaf and
        *write* share one transaction; what the server keeps beside the leaf
        (the exact body bytes, what they say) goes to the tables, never onto
        the leaf (AICS-1 section 5.1).
        """
        if public_text is not None:
            self._scan_public(ctx, public_text)
        with self._transaction():
            leaf = self._append_signed(ctx, entry_type)
            if write is not None:
                write(leaf)
        return leaf

    def _scan_public(self, ctx: SignedContext | _Attempt, text: str) -> None:
        """Refuse public text matching a published secret format (DESIGN.md section 8, AICS-1 section 10.2).

        The ``refusal`` leaf carries ``secret_format:<pattern>`` and the
        attempt's hashes; the text itself is kept nowhere.  Size and shape are
        the body schema's (:func:`check_body_digest`, :func:`parse_public_body`).
        """
        codes = [SECRET_FORMAT_PREFIX + pattern_id for pattern_id in secret_formats(text)]
        if codes:
            self._refuse(
                ctx, codes[0], message="refused: the text matches a published secret format", extra={"reasons": codes}
            )

    # ------------------------------------------------------------------
    # consent grants (DESIGN.md G9 and section 6; decision 8)
    # ------------------------------------------------------------------

    def _insert_grant_row(
        self, grant_index: int, owner_kid: str, sender_kid: str, max_messages: int, expires: int
    ) -> None:
        self._conn.execute(
            "INSERT INTO grants (grant_index, owner_kid, sender_kid, max_messages, expires) VALUES (?, ?, ?, ?, ?)",
            (grant_index, owner_kid, sender_kid, max_messages, expires),
        )

    @staticmethod
    def _grant_view(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "grant_index": row["grant_index"],
            "owner_kid": row["owner_kid"],
            "sender_kid": row["sender_kid"],
            "max": row["max_messages"],
            "expires": row["expires"],
            "used": row["used"],
            "remaining": max(0, row["max_messages"] - row["used"]),
        }

    @_signed_write
    def grant(self, ctx: SignedContext) -> dict[str, Any]:
        """A ``grant`` leaf: the signer lets a sender key (or ``*``) send it up to ``max`` messages until ``expires``.

        ``Q = {owner_kid, sender_kid, max, expires, prev_grant_index}``
        (``did:key`` kids; AICS-1 sections 5.3 and 9), signed by the owner's
        current key (``owner_kid`` is the signer).  ``prev_grant_index`` names
        the latest grant for the exact ``(owner_kid, sender_kid)`` pair (an
        initial grant inside a claim counts, at the claim's index), or is null
        when there is none; anything else is refused ``stale_grant``, citing the
        latest one.  The latest grant for a pair replaces earlier ones and
        resets the allowance; ``max`` 0 revokes.  A wildcard allowance is one
        allowance shared by every sender it admits.  Grants name keys, never
        names: after a rotation the new key grants anew.
        """
        q = ctx.payload
        self._require_exact_keys(q, _GRANT_LEAF_KEYS, "grant")
        self._require_type(ctx, "grant")
        if q["owner_kid"] != ctx.kid:
            raise ValueError("owner_kid must be the key that signs the grant")
        sender = q["sender_kid"]
        if sender != "*" and not _is_kid(sender):
            raise ValueError("sender_kid must be '*' or a did:key")
        maximum, expires = q["max"], q["expires"]
        if not _is_uint(maximum, GRANT_MAX_MESSAGES):
            raise ValueError("max must be a uint (0 revokes)")
        if not _is_uint(expires, MAX_TIME):
            raise ValueError("expires must be a unix time")
        if maximum > 0 and expires <= ctx.t:
            raise ValueError("expires must lie after the grant's ts for a grant that allows messages")
        _require_index(q["prev_grant_index"], "prev_grant_index", nullable=True)
        with self._lock:
            self._agent_actor(ctx)
            self._check_chain(ctx)
            latest = self._conn.execute(
                "SELECT grant_index FROM grants WHERE owner_kid = ? AND sender_kid = ? ORDER BY grant_index DESC LIMIT 1",
                (ctx.kid, sender),
            ).fetchone()
            expected = latest["grant_index"] if latest is not None else None
            if q["prev_grant_index"] != expected:
                raise Rejected(
                    "stale_grant",
                    f"prev_grant_index must name the latest grant of this owner key for this sender ({expected})",
                    conflict_index=expected,
                )
            with self._transaction():
                leaf = self._append_signed(ctx, "grant")
                self._insert_grant_row(leaf["leaf_index"], ctx.kid, sender, maximum, expires)
            row = self._conn.execute("SELECT * FROM grants WHERE grant_index = ?", (leaf["leaf_index"],)).fetchone()
            return {"grant": self._grant_view(row), **self._written(leaf)}

    def _select_grant(self, owner_kid: str, sender_kid: str) -> sqlite3.Row | None:
        """The grant that governs a DM: the latest for the exact pair, else the latest wildcard.

        An exact grant that is revoked, expired or used up still governs; it
        never falls back to a wildcard (AICS-1 section 9).
        """
        for sender in (sender_kid, "*"):
            row = self._conn.execute(
                "SELECT * FROM grants WHERE owner_kid = ? AND sender_kid = ? ORDER BY grant_index DESC LIMIT 1",
                (owner_kid, sender),
            ).fetchone()
            if row is not None:
                return row
        return None

    def grants_for(self, owner_kid: str, sender_kid: str | None = None) -> dict[str, Any]:
        """Every grant a key has signed, in log order, with its use and whether it is the one in force.

        With *sender_kid*, ``governing_index`` is the grant a DM from that key
        would cite as ``grant_index`` now (AICS-1 section 9: the latest exact
        grant, else the latest wildcard; ``None`` when there is none).
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM grants WHERE owner_kid = ? ORDER BY grant_index ASC", (owner_kid,)
            ).fetchall()
            latest = {r["sender_kid"]: r["grant_index"] for r in rows}
            now = int(time.time())
            grants = []
            for r in rows:
                view = self._grant_view(r)
                view["current"] = latest[r["sender_kid"]] == r["grant_index"]
                view["active"] = (
                    view["current"] and r["max_messages"] > 0 and r["expires"] > now and r["used"] < r["max_messages"]
                )
                grants.append(view)
            out = {"owner_kid": owner_kid, "count": len(grants), "grants": grants, "tree_size": self._log.tree.size}
            if sender_kid is not None:
                governing = self._select_grant(owner_kid, sender_kid)
                out["sender_kid"] = sender_kid
                out["governing_index"] = governing["grant_index"] if governing is not None else None
            return out

    # ------------------------------------------------------------------
    # end-to-end encrypted messages (DESIGN.md section 4.2 item 3, section 6; decision 4)
    # ------------------------------------------------------------------

    def _check_body_metadata(self, q: Mapping[str, Any], what: str) -> None:
        """Types of the signed body metadata shared by ``dm`` and ``capsule`` payloads."""
        if not isinstance(q["encryption"], str) or not q["encryption"]:
            raise ValueError(f"{what}: encryption must be a scheme name")
        if q["eph_pk"] is not None and not isinstance(q["eph_pk"], str):
            raise ValueError(f"{what}: eph_pk must be base64url text or null")
        if not (isinstance(q["ct_hash"], str) and _HEX64.fullmatch(q["ct_hash"])):
            raise ValueError(f"{what}: ct_hash must be 64 lowercase hex characters")
        if not isinstance(q["size"], int) or isinstance(q["size"], bool) or q["size"] < 0:
            raise ValueError(f"{what}: size must be a non-negative integer")
        self._int_index(q["to_key_leaf_index"], "to_key_leaf_index")

    def _ciphertext_body(self, ctx: SignedContext, q: Mapping[str, Any], ciphertext: Any) -> bytes:
        """The ciphertext bytes (*ciphertext*: the bytes, or their ``U64`` text), checked against what the sender
        signed; each failure is a ``refusal`` leaf.

        ``unsupported_scheme``: the scheme is not in :data:`ENCRYPTION_SCHEMES`
        (cleartext included).  ``malformed``: missing, not canonical unpadded
        base64url, shorter than a sealed box, an unusable ephemeral key, or not
        an age v1 file with one X25519 recipient.  ``too_large``: over
        ``limits.ciphertext_bytes``.  ``digest_mismatch``: ``ct_hash``,
        ``size`` or ``eph_pk`` differ from what the server computes from the
        bytes it received.  The refused bytes are kept nowhere.
        """
        scheme = q["encryption"]
        if scheme not in ENCRYPTION_SCHEMES:
            self._refuse(
                ctx,
                "unsupported_scheme",
                message=f"encryption must be one of {', '.join(ENCRYPTION_SCHEMES)}; there is no cleartext scheme",
            )
        raw = bytes(ciphertext) if isinstance(ciphertext, (bytes, bytearray)) else _canonical_b64u(ciphertext)
        if not raw:
            self._refuse(ctx, "malformed", message="a dm or capsule carries its ciphertext as body: the encrypted bytes")
        cap = self.limits["ciphertext_bytes"]
        if len(raw) > cap:
            self._refuse(ctx, "too_large", message=f"ciphertext is over the published limit of {cap} bytes")
        if scheme == sealed.SCHEME:
            if len(raw) < sealed.SEAL_OVERHEAD:
                self._refuse(ctx, "malformed", message="ciphertext is shorter than a sealed box")
            try:
                sealed.validate_x25519_public_key(raw[:32])
            except ValueError:
                self._refuse(ctx, "malformed", message="the sealed box's ephemeral key is not a usable X25519 key")
            if q["eph_pk"] != keys.b64u_encode(raw[:32]):
                self._refuse(ctx, "digest_mismatch", message="eph_pk is not the first 32 bytes of the ciphertext")
        else:
            if q["eph_pk"] is not None:
                self._refuse(ctx, "malformed", message="eph_pk is null for age-v1")
            if not _age_v1_shape(raw):
                self._refuse(ctx, "malformed", message="ciphertext is not an age v1 file with one X25519 recipient")
        if q["ct_hash"] != hashlib.sha256(raw).hexdigest():
            self._refuse(ctx, "digest_mismatch", message="ct_hash is not the SHA-256 of the ciphertext received")
        if q["size"] != len(raw):
            self._refuse(ctx, "digest_mismatch", message="size is not the length of the ciphertext received")
        return raw

    @_signed_write
    def send_message(self, ctx: SignedContext, ciphertext: Any) -> dict[str, Any]:
        """A ``dm`` leaf for one end-to-end encrypted message; the ciphertext stays off-leaf.

        ``Q = {to_kid, to_key_leaf_index, encryption, eph_pk, ct_hash, size,
        seq, prev, grant_index}`` (AICS-1 section 5.3): ``to_kid`` is the
        recipient's current signing key (its ``did:key``),
        ``to_key_leaf_index`` the leaf that set the X25519 key the body is
        sealed to, ``seq``/``prev`` repeat the envelope's, ``grant_index`` names
        the grant that admits the message.  The server recomputes the body
        checks (:meth:`_ciphertext_body`), resolves the recipient from its key
        chain (``unknown_key``, ``revoked``, ``stale_key``) and applies the
        grant that governs the sender (section 9: the latest exact grant, else
        the latest wildcard): ``no_consent`` without one, or when it is revoked
        or expired; ``stale_grant`` when ``grant_index`` names another;
        ``grant_exhausted`` when its allowance is used up.  Each failure is a
        ``refusal`` leaf.  Nothing human-readable travels beside the
        ciphertext: no subject, no routing hint.
        """
        q = ctx.payload
        self._require_exact_keys(q, _DM_KEYS, "dm")
        self._require_type(ctx, "dm")
        if not _is_kid(q["to_kid"]):
            raise ValueError("to_kid must be a did:key")
        self._check_body_metadata(q, "dm")
        _require_index(q["grant_index"], "grant_index")
        _require_index(q["seq"], "seq")
        _require_hash(q["prev"], "prev", nullable=True)
        protected = ctx.envelope["protected"]
        if q["seq"] != protected["seq"] or q["prev"] != protected["prev"]:
            raise ValueError("seq and prev in the payload must repeat the envelope's")
        with self._lock:
            sender = self._agent_actor(ctx)
            self._check_chain(ctx)
            raw = self._ciphertext_body(ctx, q, ciphertext)
            to_kid = q["to_kid"]
            key_row = self._conn.execute("SELECT * FROM bound_keys WHERE kid = ?", (to_kid,)).fetchone()
            if key_row is None:
                self._refuse(ctx, "unknown_key", message="to_kid is not a key bound to any name")
            recipient = self._actor_from_name(key_row["name_norm"])
            if recipient["revoked"]:
                self._refuse(
                    ctx,
                    "revoked",
                    conflict_index=recipient["revoked_index"],
                    message="the recipient's name was revoked; it receives no new messages",
                )
            if recipient["kid"] != to_kid:
                self._refuse(
                    ctx,
                    "stale_key",
                    conflict_index=key_row["retired_index"],
                    message="to_kid was rotated away; address the recipient's current key",
                )
            if recipient["x25519_leaf_index"] != q["to_key_leaf_index"]:
                self._refuse(
                    ctx,
                    "stale_key",
                    conflict_index=recipient["x25519_leaf_index"],
                    message="to_key_leaf_index must name the leaf that set the recipient's current encryption key",
                )
            grant = self._select_grant(to_kid, ctx.kid)
            if grant is None:
                self._refuse(ctx, "no_consent", message="the recipient has granted this key no messages")
            if grant["max_messages"] == 0 or grant["expires"] <= ctx.t:
                self._refuse(
                    ctx,
                    "no_consent",
                    conflict_index=grant["grant_index"],
                    message="the grant that governs this key was revoked or has expired",
                )
            if q["grant_index"] != grant["grant_index"]:
                self._refuse(
                    ctx,
                    "stale_grant",
                    conflict_index=grant["grant_index"],
                    message=f"grant_index must name the grant that governs this sender ({grant['grant_index']})",
                )
            if grant["used"] >= grant["max_messages"]:
                self._refuse(
                    ctx, "grant_exhausted", conflict_index=grant["grant_index"], message="the grant's allowance is used up"
                )
            with self._transaction():
                leaf = self._append_signed(ctx, "dm")
                self._conn.execute(
                    """
                    INSERT INTO messages (
                        leaf_index, sender_kid, sender_name, recipient_kid, recipient_name,
                        encryption, ct_hash, size, ciphertext, grant_index, is_read, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                    """,
                    (
                        leaf["leaf_index"],
                        ctx.kid,
                        sender["name"],
                        to_kid,
                        recipient["name"],
                        q["encryption"],
                        q["ct_hash"],
                        len(raw),
                        raw,
                        grant["grant_index"],
                        leaf["created_at"],
                    ),
                )
                self._conn.execute("UPDATE grants SET used = used + 1 WHERE grant_index = ?", (grant["grant_index"],))
            self._ciphertext_stored(len(raw))
            self.increment_counter("e2ee_messages_relayed", 1)
            row = self._conn.execute("SELECT * FROM messages WHERE leaf_index = ?", (leaf["leaf_index"],)).fetchone()
            return {"message": self._message_view(row, body=False), **self._written(leaf)}

    def _message_view(self, row: sqlite3.Row, *, body: bool) -> dict[str, Any]:
        hidden = self._tombstone_of(row["leaf_index"])
        state = "hidden" if hidden else ("stored" if row["ciphertext"] is not None else "expired")
        view: dict[str, Any] = {
            "leaf_index": row["leaf_index"],
            "from_kid": row["sender_kid"],
            "from_name": row["sender_name"],
            "from_ans": ident.ans_address(row["sender_name"]),
            "to_kid": row["recipient_kid"],
            "to_name": row["recipient_name"],
            "to_ans": ident.ans_address(row["recipient_name"]),
            "encryption": row["encryption"],
            "ct_hash": row["ct_hash"],
            "size": row["size"],
            "grant_index": row["grant_index"],
            "created_at": row["created_at"],
            "body": state,
            "hidden": hidden,
        }
        if body:
            view["ciphertext"] = keys.b64u_encode(bytes(row["ciphertext"])) if state == "stored" else None
        return view

    def get_inbox_status(self, recipient_name: str) -> dict[str, Any]:
        with self._lock:
            counts = self._conn.execute(
                """
                SELECT COUNT(*) AS total, COALESCE(SUM(is_read = 0), 0) AS unread, MAX(leaf_index) AS latest
                FROM messages WHERE recipient_name = ?
                """,
                (recipient_name,),
            ).fetchone()
            latest_at = None
            if counts["latest"] is not None:
                latest_at = self._conn.execute(
                    "SELECT created_at FROM messages WHERE leaf_index = ?", (counts["latest"],)
                ).fetchone()["created_at"]
            return {
                "agent_id": recipient_name,
                "unread_count": counts["unread"],
                "total_count": counts["total"],
                "latest_message_at": latest_at,
                "latest_message_index": counts["latest"],
                "tree_root_hex": self._log.tree.root().hex(),
            }

    def fetch_inbox(self, recipient_name: str, unread_only: bool = False) -> list[dict[str, Any]]:
        """The name's messages, newest first (at most 100), each with the signed envelope from its leaf.

        A recipient verifies the envelope, then opens the box against it:
        ``aics_identity.sealed.open_sealed(ct, x25519_key, envelope=env)``
        checks ``ct_hash`` and that the inner header names this envelope's
        sender, recipient and nonce.  Messages returned are marked read.
        """
        with self._lock:
            sql = """
                SELECT m.*, l.leaf_json FROM messages m JOIN tlog_leaves l ON l.leaf_index = m.leaf_index
                WHERE m.recipient_name = ?
            """
            if unread_only:
                sql += " AND m.is_read = 0"
            sql += " ORDER BY m.leaf_index DESC LIMIT 100"
            rows = self._conn.execute(sql, (recipient_name,)).fetchall()
            messages = []
            for r in rows:
                payload = json.loads(r["leaf_json"])["payload"]
                view = self._message_view(r, body=True)
                view["to_key_leaf_index"] = payload["to_key_leaf_index"]
                view["eph_pk"] = payload["eph_pk"]
                view["envelope"] = payload["envelope"]
                messages.append(view)
            unread = [(r["leaf_index"],) for r in rows if not r["is_read"]]
            if unread:
                with self._transaction():
                    self._conn.executemany("UPDATE messages SET is_read = 1 WHERE leaf_index = ?", unread)
            return messages

    def inbox_for(self, recipient_kid: str, from_index: int = 0, limit: int = 1000) -> dict[str, Any]:
        """The ``dm`` leaves addressed to a key through a stated checkpoint (``GET /v2/inbox/{kid}``, AICS-1 section 12.1).

        ``indices`` are their leaf indices from *from_index*, in log order,
        below ``size``, the size of ``checkpoint_note`` (``U64`` of the signed
        note); ``messages`` the same leaves' public metadata with their grant
        and body status, no bodies.  At most *limit*: ``next_from`` is where
        the next page starts, or null when this one is complete.  The same
        facts are on the ``dm`` leaves: compare this listing with the tiles to
        find a message the API withholds (DESIGN.md G9, AICS-1 section 9).
        """
        with self._lock:
            size, note = self.stated_checkpoint()
            rows = self._conn.execute(
                """
                SELECT * FROM messages WHERE recipient_kid = ? AND leaf_index >= ? AND leaf_index < ?
                ORDER BY leaf_index ASC LIMIT ?
                """,
                (recipient_kid, from_index, size, limit + 1),
            ).fetchall()
            more = len(rows) > limit
            rows = rows[:limit]
            return {
                "to_kid": recipient_kid,
                "from": from_index,
                "indices": [r["leaf_index"] for r in rows],
                "next_from": rows[-1]["leaf_index"] + 1 if more else None,
                "size": size,
                "checkpoint_note": keys.b64u_encode(note),
                "count": len(rows),
                "messages": [self._message_view(r, body=False) for r in rows],
                "tree_size": self._log.tree.size,
            }

    # ------------------------------------------------------------------
    # capsules: mutable encrypted storage with a permanent metadata trail
    # ------------------------------------------------------------------

    @_signed_write
    def put_capsule(self, ctx: SignedContext, ciphertext: Any) -> dict[str, Any]:
        """A ``capsule`` leaf; the slot's current body becomes this ciphertext.

        ``Q = {owner_kid, to_key_leaf_index, key_hash, encryption, eph_pk,
        ct_hash, size, expires, prev_capsule_index}`` (AICS-1 section 5.3):
        ``key_hash`` names the slot (the hash of the agent's own opaque slot
        key, which never reaches the server, section 8.2), ``to_key_leaf_index``
        the leaf that set the owner's X25519 key, ``prev_capsule_index`` the
        slot's previous capsule leaf or null for a new slot (``stale_capsule``
        otherwise, citing the slot's current leaf).  The expiry lies between
        ``ts + 7776000`` (90 days, decision 16) and ``ts + capsule_max_seconds``.
        *ciphertext* is the exact bytes (or their ``U64`` text); the body
        checks are those of a DM.  Every capsule leaf keeps its own body: a put
        supersedes the slot's previous body, which stays retrievable by hash
        until it is 90 days old (section 8.2); every capsule leaf stays.  Slots
        belong to the signing key (``owner_kid``); a rotation starts new slots.
        With a published quota, the name's usage is counted as AICS-1 section
        20.7 says (``quota`` beyond it).
        """
        q = ctx.payload
        self._require_exact_keys(q, _CAPSULE_KEYS, "capsule")
        self._require_type(ctx, "capsule")
        if q["owner_kid"] != ctx.kid:
            raise ValueError("owner_kid must be the key that signs the capsule")
        _require_hash(q["key_hash"], "key_hash")
        _require_index(q["prev_capsule_index"], "prev_capsule_index", nullable=True)
        self._check_body_metadata(q, "capsule")
        # AICS-1 sections 5.3 and 13.1: a capsule's expiry lies between ts + 7776000 (90 days, the ciphertext
        # minimum of decision 16) and ts + capsule_max_seconds, inclusive.
        expires, now, horizon = q["expires"], ctx.t, self.limits["capsule_max_seconds"]
        if not _is_uint(expires) or not now + CIPHERTEXT_MINIMUM_SECONDS <= expires <= now + horizon:
            raise ValueError(
                f"expires must be a unix time from {CIPHERTEXT_MINIMUM_SECONDS} s (90 days) to {horizon} s after ts"
            )
        with self._lock:
            owner = self._agent_actor(ctx)
            self._check_chain(ctx)
            raw = self._ciphertext_body(ctx, q, ciphertext)
            if owner["x25519_leaf_index"] != q["to_key_leaf_index"]:
                self._refuse(
                    ctx,
                    "stale_key",
                    conflict_index=owner["x25519_leaf_index"],
                    message="to_key_leaf_index must name the leaf that set your current encryption key",
                )
            previous = self.capsule_head(ctx.kid, q["key_hash"])
            if q["prev_capsule_index"] != previous:
                self._refuse(
                    ctx,
                    "stale_capsule",
                    conflict_index=previous,
                    message=f"prev_capsule_index must name this slot's latest capsule leaf ({previous}), or be null for a new slot",
                )
            self._check_quota(ctx, owner["name"], q["key_hash"], len(raw))
            with self._transaction():
                leaf = self._append_signed(ctx, "capsule")
                if previous is not None:
                    self._conn.execute(
                        "UPDATE capsule_leaves SET superseded_at = ? WHERE leaf_index = ?", (ctx.t, previous)
                    )
                self._conn.execute(
                    """
                    INSERT INTO capsule_leaves (
                        leaf_index, owner_kid, key_hash, prev_capsule_index, encryption, ct_hash, size, expires, ts,
                        ciphertext
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        leaf["leaf_index"], ctx.kid, q["key_hash"], previous, q["encryption"], q["ct_hash"], len(raw),
                        expires, ctx.t, raw,
                    ),
                )
                self._conn.execute(
                    """
                    INSERT INTO capsules (owner_kid, key_hash, leaf_index, updated_at) VALUES (?, ?, ?, ?)
                    ON CONFLICT (owner_kid, key_hash) DO UPDATE SET
                        leaf_index = excluded.leaf_index, updated_at = excluded.updated_at
                    """,
                    (ctx.kid, q["key_hash"], leaf["leaf_index"], leaf["created_at"]),
                )
            self._ciphertext_stored(len(raw))
            self.increment_counter("capsules_stored", 1)
            return {"capsule": self._capsule_view(leaf["leaf_index"], body=False), **self._written(leaf)}

    def capsule_head(self, owner_kid: str, key_hash: str) -> int | None:
        """The ``prev_capsule_index`` the next capsule of slot ``(owner_kid, key_hash)`` names: its latest leaf, or ``None``."""
        with self._lock:
            return self._conn.execute(
                "SELECT MAX(leaf_index) AS i FROM capsule_leaves WHERE owner_kid = ? AND key_hash = ?",
                (owner_kid, key_hash),
            ).fetchone()["i"]

    def _capsule_body_state(self, row: sqlite3.Row, now: float | None = None) -> str:
        """``hidden``, ``expired`` or ``stored``: whether a capsule leaf's body is served (AICS-1 sections 8.2, 10.3)."""
        if self._tombstone_of(row["leaf_index"]) is not None:
            return "hidden"
        now = time.time() if now is None else now
        if row["ciphertext"] is None or row["expires"] <= now:
            return "expired"
        if row["superseded_at"] is not None and row["ts"] + CIPHERTEXT_MINIMUM_SECONDS <= now:
            return "expired"
        return "stored"

    def _capsule_view(self, leaf_index: int, *, body: bool) -> dict[str, Any]:
        """A capsule leaf as the signed reads show it: the slot (by ``key_hash``), its metadata and body state."""
        row = self._conn.execute("SELECT * FROM capsule_leaves WHERE leaf_index = ?", (leaf_index,)).fetchone()
        state = self._capsule_body_state(row)
        view: dict[str, Any] = {
            "key_hash": row["key_hash"],
            "owner_kid": row["owner_kid"],
            "leaf_index": row["leaf_index"],
            "prev_capsule_index": row["prev_capsule_index"],
            "encryption": row["encryption"],
            "ct_hash": row["ct_hash"],
            "size": row["size"],
            "expires": row["expires"],
            "updated_at": _utc_iso(row["ts"]),
            "body": state,
            "hidden": self._tombstone_of(row["leaf_index"]),
        }
        if body:
            view["ciphertext"] = keys.b64u_encode(bytes(row["ciphertext"])) if state == "stored" else None
        return view

    def get_capsule(self, owner_kid: str, key_hash: str) -> dict[str, Any] | None:
        """The slot ``key_hash`` of *owner_kid* with its current body (``ciphertext`` is null once hidden or expired)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT leaf_index FROM capsules WHERE owner_kid = ? AND key_hash = ?", (owner_kid, key_hash)
            ).fetchone()
            return self._capsule_view(row["leaf_index"], body=True) if row else None

    def list_capsules(self, owner_kid: str) -> list[dict[str, Any]]:
        """The slots of *owner_kid*, most recently written first, without bodies."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT leaf_index FROM capsules WHERE owner_kid = ? ORDER BY leaf_index DESC", (owner_kid,)
            ).fetchall()
            return [self._capsule_view(r["leaf_index"], body=False) for r in rows]

    def _expire_capsule_bodies(self, now: int) -> int:
        """Retention (AICS-1 section 8.2): delete the capsule bodies no longer served; returns how many.

        A current slot body goes at its own ``expires``; a superseded one once
        it is :data:`CIPHERTEXT_MINIMUM_SECONDS` old (its slot was rewritten).
        A body hidden by a tombstone is left to the hidden-body pass, which
        keeps it inaccessible for its own period (section 10.3).
        """
        cursor = self._conn.execute(
            """
            UPDATE capsule_leaves SET ciphertext = NULL
            WHERE ciphertext IS NOT NULL
              AND leaf_index NOT IN (SELECT target_index FROM tombstones)
              AND (expires <= ? OR (superseded_at IS NOT NULL AND ts + ? <= ?))
            """,
            (now, CIPHERTEXT_MINIMUM_SECONDS, now),
        )
        return cursor.rowcount

    # ------------------------------------------------------------------
    # The ciphertext-byte budget (AICS-1 sections 8.2 and 13.1, the card's retention.ciphertext_budget_bytes)
    # ------------------------------------------------------------------

    def _stored_ciphertext_bytes(self) -> int:
        """The bytes of every ciphertext body still stored: DMs, capsule leaves and swarm deliveries, hidden ones too."""
        row = self._conn.execute(
            """
            SELECT
                (SELECT COALESCE(SUM(size), 0) FROM messages WHERE ciphertext IS NOT NULL)
              + (SELECT COALESCE(SUM(size), 0) FROM capsule_leaves WHERE ciphertext IS NOT NULL)
              + (SELECT COALESCE(SUM(length(b.body)), 0) FROM swarm_bodies b
                 JOIN tlog_leaves l ON l.leaf_index = b.leaf_index
                 WHERE l.event_type = 'swarm.delivery' AND b.body IS NOT NULL) AS total
            """
        ).fetchone()
        return int(row["total"])

    def _ciphertext_stored(self, nbytes: int) -> None:
        """A ciphertext body of *nbytes* was just stored (caller holds the lock): over the budget, apply the rule."""
        self._ciphertext_total += nbytes
        if self._ciphertext_total > self.limits["ciphertext_budget_bytes"]:
            self._apply_ciphertext_budget(int(time.time()))

    def _apply_ciphertext_budget(self, now: int) -> int:
        """The deterministic capacity rule of AICS-1 section 8.2; returns how many bodies it evicted.

        While the stored ciphertext exceeds ``limits.ciphertext_budget_bytes``,
        evict eligible bodies, earliest ``(ts, index)`` first, until it is
        within budget.  Eligible: a DM, capsule or swarm-delivery body at least
        90 days (:data:`CIPHERTEXT_MINIMUM_SECONDS`) past its entry's ``ts``,
        not hidden by a tombstone (a hidden body keeps its own rule, section
        10.3).  An evicted body is ``expired`` under the policy that governed
        it at acceptance (its body status names that policy leaf); its leaf
        stays.  When eviction cannot meet the budget, the 90-day minimum is
        kept and resource exhaustion is reported (:meth:`resource_exhaustion`,
        ``/healthz``, ``/v2/limits``).  Runs under the writer lock, from
        housekeeping and after every store that crosses the budget.
        """
        budget = self.limits["ciphertext_budget_bytes"]
        total = self._stored_ciphertext_bytes()
        evicted = 0
        if total > budget:
            cutoff = now - CIPHERTEXT_MINIMUM_SECONDS
            candidates = self._conn.execute(
                """
                SELECT * FROM (
                    SELECT m.leaf_index AS leaf_index, CAST(json_extract(l.leaf_json, '$.ts') AS INTEGER) AS ts,
                           m.size AS size, 'dm' AS kind
                    FROM messages m JOIN tlog_leaves l ON l.leaf_index = m.leaf_index
                    WHERE m.ciphertext IS NOT NULL
                    UNION ALL
                    SELECT c.leaf_index, c.ts, c.size, 'capsule' FROM capsule_leaves c WHERE c.ciphertext IS NOT NULL
                    UNION ALL
                    SELECT b.leaf_index, CAST(json_extract(l.leaf_json, '$.ts') AS INTEGER), length(b.body), 'delivery'
                    FROM swarm_bodies b JOIN tlog_leaves l ON l.leaf_index = b.leaf_index
                    WHERE l.event_type = 'swarm.delivery' AND b.body IS NOT NULL
                )
                WHERE ts <= ? AND leaf_index NOT IN (SELECT target_index FROM tombstones)
                ORDER BY ts ASC, leaf_index ASC
                """,
                (cutoff,),
            ).fetchall()
            with self._transaction():
                for row in candidates:
                    if total <= budget:
                        break
                    index = row["leaf_index"]
                    policy = self._retention_policy_index(index, int(row["ts"]))
                    if row["kind"] == "dm":
                        self._conn.execute(
                            "UPDATE messages SET ciphertext = NULL, expired_policy_index = ? WHERE leaf_index = ?",
                            (policy, index),
                        )
                    elif row["kind"] == "capsule":
                        self._conn.execute("UPDATE capsule_leaves SET ciphertext = NULL WHERE leaf_index = ?", (index,))
                    else:
                        self._conn.execute(
                            "UPDATE swarm_bodies SET body = NULL, expired_policy_index = ? WHERE leaf_index = ?",
                            (policy, index),
                        )
                    total -= int(row["size"])
                    evicted += 1
            if evicted:
                _say(f"ciphertext budget: evicted {evicted} bodies at least 90 days old by earliest (ts, index)")
        self._ciphertext_total = total
        self._note_exhaustion(now, total, budget)
        return evicted

    def _note_exhaustion(self, now: int, total: int, budget: int) -> None:
        if total <= budget:
            if self._exhaustion is not None:
                _say("ciphertext budget: within budget again; resource exhaustion is over")
            self._exhaustion = None
            return
        if self._exhaustion is None:
            _say(
                f"RESOURCE EXHAUSTION: {total} bytes of ciphertext stored, budget {budget}; every remaining body is "
                "younger than the 90-day minimum, which is kept (AICS-1 section 8.2)"
            )
            self._exhaustion = {"since": now}
        self._exhaustion.update(
            {"cause": "ciphertext_budget", "stored_ciphertext_bytes": total, "ciphertext_budget_bytes": budget,
             "checked_at": now}
        )

    def resource_exhaustion(self) -> dict[str, Any] | None:
        """The reported resource exhaustion (AICS-1 section 8.2), or ``None``: ciphertext above budget, none evictable."""
        return dict(self._exhaustion) if self._exhaustion is not None else None

    # ------------------------------------------------------------------
    # The Agora: public posts, polls and votes (AICS-1 section 5.3)
    #
    # Each body is the exact JCS JSON the leaf names by body_hash and size:
    # a post {channel, title, text}, a poll {channel, title, text, options},
    # a vote {reason} or none.  The tables keep those bytes (for read, fetch
    # and the body service) and what they say; only hashes reach the leaf.
    # ------------------------------------------------------------------

    @staticmethod
    def _check_post_q(q: Mapping[str, Any]) -> None:
        """The member types of a ``post`` payload (AICS-1 section 5.3); ``malformed`` otherwise."""
        _require_hash(q["channel_sha256"], "channel_sha256")
        _require_index(q["parent_index"], "parent_index", nullable=True)
        _require_hash(q["body_hash"], "body_hash")
        _require(_is_uint(q["size"]), "size must be a uint")
        _require_hash(q["title_sha256"], "title_sha256", nullable=True)

    def _check_parent(self, parent_index: int | None, channel: str) -> None:
        """A post's parent, if any, is an earlier post or poll in the same channel (AICS-1 section 5.3)."""
        if parent_index is None:
            return
        row = self._conn.execute(
            """
            SELECT channel FROM agora_posts WHERE post_index = ?
            UNION ALL SELECT channel FROM agora_polls WHERE poll_index = ?
            """,
            (parent_index, parent_index),
        ).fetchone()
        if row is None or row["channel"] != channel:
            raise Rejected("malformed", f"parent_index must name an earlier post or poll in the channel {channel!r}")

    def _insert_post(
        self, leaf: dict[str, Any], author: dict[str, Any], post: Mapping[str, Any], raw: bytes, q: Mapping[str, Any]
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO agora_posts (
                post_index, channel, parent_index, author_kid, author_name, author_tier, title, text, body,
                body_hash, size, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                leaf["leaf_index"],
                post["channel"],
                q["parent_index"],
                leaf["entry"]["actor_kid"],
                author["name"],
                author["tier"],
                post["title"],
                post["text"],
                raw,
                q["body_hash"],
                q["size"],
                leaf["created_at"],
            ),
        )

    def _post_view(self, row: sqlite3.Row) -> dict[str, Any]:
        hidden = self._tombstone_of(row["post_index"])
        return {
            "index": row["post_index"],
            "tlog_leaf_index": row["post_index"],
            "channel": row["channel"],
            "parent_index": row["parent_index"],
            "author_name": row["author_name"],
            "author_ans": ident.ans_address(row["author_name"]),
            "author_kid": row["author_kid"],
            "author_tier": row["author_tier"],
            "title": None if hidden else row["title"],
            "text": None if hidden else row["text"],
            "body_hash": row["body_hash"],
            "size": row["size"],
            "hidden": hidden,
            "created_at": row["created_at"],
        }

    def _write_post(self, ctx: SignedContext, author: dict[str, Any], body: Any) -> dict[str, Any]:
        """The checks and the leaf of a post, under the lock, once its payload's member types passed."""
        q = ctx.payload
        self._check_chain(ctx)
        post = validate_post_body(q, body)
        self.swarms.check_channel(ctx, post["channel"], q["parent_index"])
        raw = bytes(body)
        self._check_parent(q["parent_index"], post["channel"])
        leaf = self._signed_entry(
            ctx,
            "post",
            lambda lf: self._insert_post(lf, author, post, raw, q),
            public_text="\n".join(body_texts(post)),
        )
        self.increment_counter("agora_posts_created", 1)
        row = self._conn.execute("SELECT * FROM agora_posts WHERE post_index = ?", (leaf["leaf_index"],)).fetchone()
        return {"post": self._post_view(row), **self._written(leaf)}

    @_signed_write
    def create_agora_post(self, ctx: SignedContext, body: Any) -> dict[str, Any]:
        """A ``post`` leaf: ``Q = {channel_sha256, parent_index, body_hash, size, title_sha256}`` (AICS-1 section 5.3).

        *body* is the exact JCS bytes of ``{channel, title, text}`` (``title`` a
        string or null): at most :data:`PUBLIC_BODY_BYTES` (``too_large``),
        hashing to ``body_hash`` with length ``size`` and with ``channel`` and
        ``title`` digests matching ``Q`` (``digest_mismatch``), canonical with
        exactly those members (``malformed``), its channel a slug of the name
        pattern.  The parent, if any, is an earlier post or poll in the same
        channel.  The texts are scanned for published secret formats.  The
        first post or poll naming a channel creates it.
        """
        q = ctx.payload
        self._require_exact_keys(q, _POST_KEYS, "post")
        self._require_type(ctx, "post")
        self._check_post_q(q)
        with self._lock:
            author = self._agent_actor(ctx)
            return self._write_post(ctx, author, body)

    @_signed_write
    def create_agora_post_unverified(self, ctx: SignedContext, author: dict[str, Any], body: Any) -> dict[str, Any]:
        """A public post by an unverified (shared-secret) identity whose secret checked: a policy-attested leaf.

        *ctx* carries the fallback envelope (:meth:`fallback_context`): its
        ``kid`` is the identity's ``unverified:`` identifier and ``Q`` the post
        payload of AICS-1 section 5.3 (an unverified actor may post).  The
        entry carries that envelope and the policy key's attestation (section
        5.1); a refusal names the envelope by hash and the identity's tuple,
        never the secret.
        """
        q = ctx.payload
        self._require_exact_keys(q, _POST_KEYS, "post")
        self._require_type(ctx, "post")
        self._check_post_q(q)
        with self._lock:
            if author.get("tier") != ident.TIER_UNVERIFIED or not author.get("unverified_id"):
                raise PermissionError("only an unverified identity posts through this path")
            if ctx.scheme != ev.SHARED_SECRET or ctx.kid != author["unverified_id"]:
                raise PermissionError("the envelope is not this unverified identity's")
            self._admit(ctx, ctx.kid)
            return self._write_post(ctx, author, body)

    @staticmethod
    def post_payload(body: bytes, *, parent_index: int | None = None) -> dict[str, Any]:
        """``Q`` of a post with the exact *body* ``J({channel, title, text})`` (what a client signs; AICS-1 section 5.3)."""
        post = json.loads(body.decode("utf-8"))
        return {
            "channel_sha256": text_sha256(post["channel"]),
            "parent_index": parent_index,
            "body_hash": hashlib.sha256(body).hexdigest(),
            "size": len(body),
            "title_sha256": None if post["title"] is None else text_sha256(post["title"]),
        }

    def list_agora_posts(self, channel: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Public posts, newest first.  Where a tombstone hides a body, ``hidden`` names it and the texts are null."""
        with self._lock:
            if channel:
                rows = self._conn.execute(
                    "SELECT * FROM agora_posts WHERE channel = ? ORDER BY post_index DESC LIMIT ?", (channel, limit)
                ).fetchall()
            else:
                rows = self._conn.execute("SELECT * FROM agora_posts ORDER BY post_index DESC LIMIT ?", (limit,)).fetchall()
            return [self._post_view(r) for r in rows]

    def get_post(self, index: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM agora_posts WHERE post_index = ?", (index,)).fetchone()
            return self._post_view(row) if row else None

    def list_channels(self) -> list[str]:
        """Channels are agent-created (DESIGN.md section 4.2 item 13): every slug a ``post`` or ``poll`` names.

        There is no channel list in the code.  A leaf carries ``channel_sha256``;
        the slug itself is kept off the log with the body.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT channel FROM agora_posts UNION SELECT channel FROM agora_polls ORDER BY channel ASC"
            ).fetchall()
            return [r["channel"] for r in rows]

    @_signed_write
    def create_agora_poll(self, ctx: SignedContext, body: Any) -> dict[str, Any]:
        """A ``poll`` leaf (AICS-1 section 5.3).

        ``Q = {channel_sha256, body_hash, size, title_sha256, options_sha256,
        closes, min_key_age_seconds, pow_bits}``: 2 to 64 distinct ordered
        option hashes, ``closes`` after the poll's ``ts``, ``pow_bits`` 0 to 24.
        *body* is the exact JCS bytes of ``{channel, title, text, options}``.
        A poll is free; its creator may require a minimum key age and a proof
        of work of every vote, for this poll only.
        """
        q = ctx.payload
        self._require_exact_keys(q, _POLL_KEYS, "poll")
        self._require_type(ctx, "poll")
        _require_hash(q["channel_sha256"], "channel_sha256")
        _require_hash(q["body_hash"], "body_hash")
        _require(_is_uint(q["size"]), "size must be a uint")
        _require_hash(q["title_sha256"], "title_sha256")
        options = q["options_sha256"]
        _require(
            isinstance(options, list)
            and POLL_MIN_OPTIONS <= len(options) <= POLL_MAX_OPTIONS
            and all(_is_hex64(h) for h in options)
            and len(set(options)) == len(options),
            f"options_sha256 is a list of {POLL_MIN_OPTIONS} to {POLL_MAX_OPTIONS} distinct option hashes",
        )
        _require(_is_uint(q["closes"]) and q["closes"] > ctx.t, "closes must be a time after the poll's ts")
        _require(_is_uint(q["min_key_age_seconds"]), "min_key_age_seconds must be a uint")
        _require(_is_uint(q["pow_bits"], POLL_MAX_POW_BITS), f"pow_bits must be 0 to {POLL_MAX_POW_BITS}")
        with self._lock:
            creator = self._agent_actor(ctx)
            self._check_chain(ctx)
            poll = validate_poll_body(q, body)
            self.swarms.check_channel(ctx, poll["channel"], None, poll=True)
            raw = bytes(body)

            def write(leaf: dict[str, Any]) -> None:
                self._conn.execute(
                    """
                    INSERT INTO agora_polls (
                        poll_index, channel, creator_kid, creator_name, title, text, options_json, option_count,
                        closes, min_key_age_seconds, pow_bits, body, body_hash, size, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        leaf["leaf_index"],
                        poll["channel"],
                        ctx.kid,
                        creator["name"],
                        poll["title"],
                        poll["text"],
                        json.dumps(poll["options"]),
                        len(poll["options"]),
                        q["closes"],
                        q["min_key_age_seconds"],
                        q["pow_bits"],
                        raw,
                        q["body_hash"],
                        q["size"],
                        leaf["created_at"],
                    ),
                )

            leaf = self._signed_entry(ctx, "poll", write, public_text="\n".join(body_texts(poll)))
            return {"poll": self.get_poll(leaf["leaf_index"]), **self._written(leaf)}

    @staticmethod
    def poll_payload(
        body: bytes, *, closes: int, min_key_age_seconds: int = 0, pow_bits: int = 0
    ) -> dict[str, Any]:
        """``Q`` of a poll with the exact *body* ``J({channel, title, text, options})`` (AICS-1 section 5.3)."""
        poll = json.loads(body.decode("utf-8"))
        return {
            "channel_sha256": text_sha256(poll["channel"]),
            "body_hash": hashlib.sha256(body).hexdigest(),
            "size": len(body),
            "title_sha256": text_sha256(poll["title"]),
            "options_sha256": [text_sha256(o) for o in poll["options"]],
            "closes": closes,
            "min_key_age_seconds": min_key_age_seconds,
            "pow_bits": pow_bits,
        }

    def _key_activation_ts(self, kid: str) -> int | None:
        """``ts`` of the leaf that made *kid* a name's signing key (its claim, rotation or upgrade)."""
        row = self._conn.execute(
            "SELECT l.leaf_json FROM bound_keys b JOIN tlog_leaves l ON l.leaf_index = b.bound_index WHERE b.kid = ?",
            (kid,),
        ).fetchone()
        return int(json.loads(row["leaf_json"])["ts"]) if row is not None else None

    def _check_vote_rules(self, ctx: SignedContext, poll: sqlite3.Row) -> None:
        """The poll's own rules for a vote (AICS-1 section 5.3), each refused ``poll_constraint`` citing the poll.

        Key age is ``vote.ts`` minus the ``ts`` of the leaf that made the
        signing key current (a rotation starts it again).  With ``pow_bits``
        above 0, ``H(UTF8("AICS-1 vote\\n") || J({origin, poll_index, kid,
        option, pow_nonce}))`` starts with that many zero bits; with 0,
        ``pow_nonce`` is null (``malformed`` otherwise).
        """
        q = ctx.payload
        index = poll["poll_index"]
        minimum = poll["min_key_age_seconds"]
        if minimum:
            activated = self._key_activation_ts(ctx.kid)
            age = ctx.t - activated if activated is not None else -1
            if age < minimum:
                raise Rejected(
                    "poll_constraint",
                    f"this poll takes votes from keys at least {minimum} s old; this one is {max(age, 0)} s old",
                    conflict_index=index,
                )
        bits = poll["pow_bits"]
        if bits == 0:
            if q["pow_nonce"] is not None:
                raise Rejected("malformed", "pow_nonce is null for a poll without proof of work")
            return
        if q["pow_nonce"] is None:
            raise Rejected("poll_constraint", f"this poll requires a proof of work of {bits} bits (pow_nonce)", conflict_index=index)
        digest = vote_pow_digest(self.origin, index, ctx.kid, q["option"], q["pow_nonce"])
        if leading_zero_bits(digest) < bits:
            raise Rejected(
                "poll_constraint",
                f"the proof of work must start with {bits} zero bits: H(UTF8(\"AICS-1 vote\\n\") || "
                "J({origin, poll_index, kid, option, pow_nonce}))",
                conflict_index=index,
            )

    @_signed_write
    def vote_agora_poll(self, ctx: SignedContext, body: Any = None) -> dict[str, Any]:
        """A ``vote`` leaf (AICS-1 section 5.3): ``Q = {poll_index, option, pow_nonce, reason_sha256, body_hash, size}``.

        ``option`` is a zero-based option index.  Without a body both nullable
        hashes are null and ``size`` is 0; with one, the body is the exact JCS
        bytes of ``{reason}``.  One key, one vote (decision 2d): every vote
        weighs one, nothing paid or contributed changes that, and a signing key
        votes once per poll (``already_voted``, citing the first).  Votes
        precede ``closes`` (``poll_closed``) and satisfy the poll's key-age and
        proof-of-work rules (``poll_constraint``).
        """
        q = ctx.payload
        self._require_exact_keys(q, _VOTE_KEYS, "vote")
        self._require_type(ctx, "vote")
        _require_index(q["poll_index"], "poll_index")
        _require(_is_uint(q["option"]), "option must be a uint (a zero-based option index)")
        _require_hash(q["pow_nonce"], "pow_nonce", nullable=True)
        _require_hash(q["reason_sha256"], "reason_sha256", nullable=True)
        _require_hash(q["body_hash"], "body_hash", nullable=True)
        _require(_is_uint(q["size"]), "size must be a uint")
        if q["body_hash"] is None:
            _require(q["reason_sha256"] is None and q["size"] == 0, "a vote without a body has a null reason_sha256 and size 0")
        else:
            _require(q["reason_sha256"] is not None, "a vote with a body names the reason_sha256 of its reason")
        with self._lock:
            voter = self._agent_actor(ctx)
            self._check_chain(ctx)
            reason = validate_vote_body(q, body)
            poll = self._conn.execute("SELECT * FROM agora_polls WHERE poll_index = ?", (q["poll_index"],)).fetchone()
            if poll is None:
                raise Rejected("malformed", f"poll_index {q['poll_index']} names no poll")
            index = poll["poll_index"]
            if ctx.t >= poll["closes"]:
                raise Rejected("poll_closed", f"this poll closed at {poll['closes']}: votes must precede it", conflict_index=index)
            if q["option"] >= poll["option_count"]:
                raise Rejected(
                    "poll_constraint",
                    f"option is a zero-based index below {poll['option_count']}, this poll's number of options",
                    conflict_index=index,
                )
            earlier = self._conn.execute(
                "SELECT vote_index FROM agora_poll_votes WHERE poll_index = ? AND voter_kid = ?", (index, ctx.kid)
            ).fetchone()
            if earlier is not None:
                self._refuse(
                    ctx,
                    "already_voted",
                    conflict_index=earlier["vote_index"],
                    message="this key already voted in this poll; one key, one vote",
                )
            self._check_vote_rules(ctx, poll)
            raw = bytes(body) if reason is not None else None

            def write(leaf: dict[str, Any]) -> None:
                self._conn.execute(
                    """
                    INSERT INTO agora_poll_votes (
                        vote_index, poll_index, voter_kid, voter_name, option, reason, body, body_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        leaf["leaf_index"],
                        index,
                        ctx.kid,
                        voter["name"],
                        q["option"],
                        reason["reason"] if reason is not None else None,
                        raw,
                        q["body_hash"],
                        leaf["created_at"],
                    ),
                )

            leaf = self._signed_entry(ctx, "vote", write, public_text=reason["reason"] if reason is not None else None)
            self.increment_counter("agora_poll_votes", 1)
            return {"poll": self.get_poll(index), **self._written(leaf)}

    @staticmethod
    def vote_payload(
        poll_index: int, option: int, *, body: bytes | None = None, pow_nonce: str | None = None
    ) -> dict[str, Any]:
        """``Q`` of a vote, with the exact *body* ``J({reason})`` or none (AICS-1 section 5.3)."""
        reason = json.loads(body.decode("utf-8"))["reason"] if body is not None else None
        return {
            "poll_index": poll_index,
            "option": option,
            "pow_nonce": pow_nonce,
            "reason_sha256": text_sha256(reason) if reason is not None else None,
            "body_hash": hashlib.sha256(body).hexdigest() if body is not None else None,
            "size": len(body) if body is not None else 0,
        }

    def get_poll(self, poll_index: int) -> dict[str, Any] | None:
        """A poll with its tally: one vote per signing key, each counting one."""
        with self._lock:
            p = self._conn.execute("SELECT * FROM agora_polls WHERE poll_index = ?", (poll_index,)).fetchone()
            if not p:
                return None
            options = json.loads(p["options_json"])
            hidden = self._tombstone_of(p["poll_index"])
            votes = self._conn.execute(
                """
                SELECT v.*, t.tombstone_index AS reason_hidden_by FROM agora_poll_votes v
                LEFT JOIN tombstones t ON t.target_index = v.vote_index
                WHERE v.poll_index = ? ORDER BY v.vote_index DESC
                """,
                (p["poll_index"],),
            ).fetchall()
            tally = [0] * p["option_count"]
            for v in votes:
                tally[v["option"]] += 1
            total = sum(tally)
            return {
                "poll_index": p["poll_index"],
                "tlog_leaf_index": p["poll_index"],
                "channel": p["channel"],
                "title": None if hidden else p["title"],
                "text": None if hidden else p["text"],
                "hidden": hidden,
                "creator_name": p["creator_name"],
                "creator_kid": p["creator_kid"],
                "closes": p["closes"],
                "min_key_age_seconds": p["min_key_age_seconds"],
                "pow_bits": p["pow_bits"],
                "status": "open" if time.time() < p["closes"] else "closed",
                "total_votes": total,
                "options": [
                    {
                        "option": i,
                        "label": None if hidden else options[i],
                        "votes": tally[i],
                        "percentage": round(tally[i] * 100.0 / total, 1) if total else 0.0,
                    }
                    for i in range(p["option_count"])
                ],
                "recent_votes": [
                    {
                        "voter_name": v["voter_name"],
                        "voter_kid": v["voter_kid"],
                        "option": v["option"],
                        "reason": None if v["reason_hidden_by"] is not None else v["reason"],
                        "tlog_leaf_index": v["vote_index"],
                    }
                    for v in votes[:10]
                ],
                "body_hash": p["body_hash"],
                "size": p["size"],
                "created_at": p["created_at"],
            }

    def list_agora_polls(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT poll_index FROM agora_polls ORDER BY poll_index ASC").fetchall()
            return [p for r in rows if (p := self.get_poll(r["poll_index"])) is not None]

    # ------------------------------------------------------------------
    # Notices (the keyless intake; one policy-signed leaf per notice decided)
    #
    # A notice writes to the notice register, never to content or to the log
    # (DESIGN.md section 1 item 1 and section 4.1).  Taking it writes no leaf;
    # the only leaf is the policy-signed ``report`` the owner writes on
    # closing it, ``{kind: notice, notice_hash, target_index, outcome_code,
    # evidence_hash}`` (AICS-1 section 5.3).  The report id, the notice text
    # and the notifier's contact stay in the ``notices`` table and are deleted
    # NOTICE_RETENTION_SECONDS after closing (decision 16, docs/legal/retention.md).
    # ------------------------------------------------------------------

    @staticmethod
    def notice_sha256(kind: str, location: str, explanation: str, cites_report_id: str | None, salt: str) -> str:
        """The ``notice_hash`` a notice's leaf carries: SHA-256 of the RFC 8785 JSON of the notice and its salt.

        The contact is left out.  *salt* is ``U64`` of :data:`NOTICE_SALT_BYTES`
        random bytes, kept and deleted with the off-leaf record (AICS-1
        section 16), so the permanent hash cannot confirm a guessed notice
        once the record is gone.
        """
        return ident.content_sha256(
            {
                "kind": kind,
                "location": location,
                "explanation": explanation,
                "cites_report_id": cites_report_id,
                "salt": salt,
            }
        )

    @staticmethod
    def _notice_retention(row: Mapping[str, Any] | None) -> dict[str, Any]:
        """The retention of a notice's text and contact, as the notifier is told it."""
        return {
            "rule": (
                "the notice text, the report id and the notifier's contact stay off the log, access-restricted, until "
                f"{NOTICE_RETENTION_SECONDS // 86400} days after the notice is closed, then they are deleted; "
                "taking a notice writes no leaf, and the one leaf written when it is decided keeps only the notice "
                "hash, the target index, the outcome code and an evidence hash"
            ),
            "seconds_after_closing": NOTICE_RETENTION_SECONDS,
            "closed_at": row["closed_at"] if row is not None else None,
            "delete_after": row["delete_after"] if row is not None else None,
        }

    def create_notice(
        self,
        kind: str,
        location: str,
        explanation: str,
        *,
        notifier_name: str | None = None,
        notifier_email: str | None = None,
        cites_report_id: str | None = None,
    ) -> dict[str, Any]:
        """Take a notice into the register: no leaf (DESIGN.md section 4.1).

        Keyless and reachable through Cloudflare by anyone, so it is bounded
        three ways, all published (``/v2/limits``, ``/notice``, the card): its
        own global window, ``limits.notices`` (429 beyond it); every field by
        UTF-8 bytes (:data:`NOTICE_FIELD_BYTES`); and what open notices may
        hold together, ``limits.open_notices`` notices and
        ``limits.open_notice_bytes`` bytes (503 with ``Retry-After`` beyond
        either, until the owner closes notices).  The text and the contact are
        stored off-leaf; the answer is the confirmation of receipt (report id,
        notice hash, retention rule).  The leaf comes when the notice is
        decided (:meth:`close_notice`).
        """
        if kind not in NOTICE_KINDS:
            raise ValueError(f"kind must be one of {', '.join(NOTICE_KINDS)}")
        for value, field in ((location, "location"), (explanation, "explanation")):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"a notice needs a {field}")
        fields = {"location": location, "explanation": explanation, "name": notifier_name, "email": notifier_email,
                  "report_id": cites_report_id}
        size = 0
        for field, value in fields.items():
            nbytes = len(value.encode("utf-8")) if isinstance(value, str) else 0
            if nbytes > NOTICE_FIELD_BYTES[field]:
                raise ValueError(f"a notice's {field} is at most {NOTICE_FIELD_BYTES[field]} bytes of UTF-8")
            size += nbytes
        salt = keys.b64u_encode(secrets.token_bytes(NOTICE_SALT_BYTES))
        notice_hash = self.notice_sha256(kind, location, explanation, cites_report_id or None, salt)
        with self._lock:
            self._admit_keyless(self._notice_intake)
            register = self.notice_register()
            if register["open"] >= self.limits["open_notices"] or register["bytes"] + size > self.limits["open_notice_bytes"]:
                raise Refusal(
                    "notice_register_full",
                    "the notice register holds as many open notices as it takes "
                    f"({self.limits['open_notices']} notices, {self.limits['open_notice_bytes']} bytes); send it again "
                    "later, or mail notice@wesupport-ai.com (authorities: authorities@wesupport-ai.com)",
                    status=503,
                    retry_after=NOTICE_REGISTER_RETRY_SECONDS,
                )
            report_id = f"dsa_{secrets.token_hex(6)}"
            received_at = int(time.time())
            with self._transaction():
                self._conn.execute(
                    """
                    INSERT INTO notices (
                        report_id, kind, location, explanation, notifier_name, notifier_email,
                        cites_report_id, salt, notice_sha256, received_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report_id,
                        kind,
                        location,
                        explanation,
                        notifier_name or None,
                        notifier_email or None,
                        cites_report_id or None,
                        salt,
                        notice_hash,
                        received_at,
                    ),
                )
            return {
                "report_id": report_id,
                "status": "received",
                "received_at": received_at,
                "notice_sha256": notice_hash,
                # Yours, to recompute notice_sha256 over your notice; it is deleted with the record.
                "notice_salt": salt,
                "logged": False,
                "retention": self._notice_retention(None),
            }

    def notice_register(self) -> dict[str, int]:
        """How many notices are open and the UTF-8 bytes their fields hold (aggregate counts only, no content)."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS open, COALESCE(SUM(
                    length(CAST(location AS BLOB)) + length(CAST(explanation AS BLOB))
                    + COALESCE(length(CAST(notifier_name AS BLOB)), 0) + COALESCE(length(CAST(notifier_email AS BLOB)), 0)
                    + COALESCE(length(CAST(cites_report_id AS BLOB)), 0)), 0) AS bytes
                FROM notices WHERE closed_at IS NULL
                """
            ).fetchone()
            return {"open": int(row["open"]), "bytes": int(row["bytes"])}

    def _notice_view(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "report_id": row["report_id"],
            "kind": row["kind"],
            "location": row["location"],
            "explanation": row["explanation"],
            "notifier_name": row["notifier_name"],
            "notifier_email": row["notifier_email"],
            "cites_report_id": row["cites_report_id"],
            "notice_sha256": row["notice_sha256"],
            "notice_salt": row["salt"],
            "received_at": row["received_at"],
            "status": "closed" if row["closed_at"] is not None else "open",
            "outcome_code": row["outcome_code"],
            "target_index": row["target_index"],
            "evidence_hash": row["evidence_hash"],
            "outcome_index": row["outcome_index"],
            "retention": self._notice_retention(row),
        }

    def list_notices(self, status: str | None = None, limit: int = 100) -> dict[str, Any]:
        """Owner-only (owner login): the notice register, oldest open notice first; ``status`` open or closed."""
        if status not in (None, "open", "closed"):
            raise ValueError("status must be open or closed")
        with self._lock:
            where = {"open": " WHERE closed_at IS NULL", "closed": " WHERE closed_at IS NOT NULL"}.get(status or "", "")
            rows = self._conn.execute(
                f"SELECT * FROM notices{where} ORDER BY received_at ASC, report_id ASC LIMIT ?", (limit,)
            ).fetchall()
            return {"count": len(rows), "notices": [self._notice_view(r) for r in rows]}

    def close_notice(
        self, report_id: str, outcome_code: str, target_index: int | None = None, evidence_hash: str | None = None
    ) -> dict[str, Any]:
        """Owner-only (owner login): close a notice with its outcome, the notice's one policy-signed ``report`` leaf.

        ``{kind: notice, notice_hash, target_index, outcome_code,
        evidence_hash}`` (AICS-1 section 5.3): a hash, an index and a closed
        code; the report id stays off the log.  Closing starts the retention
        clock.  Hiding a body is a separate ``tombstone`` (reason
        ``illegal_on_notice``), whose ``evidence_hash`` may name this notice's
        hash.  A counter-notice names the contested tombstone as its
        ``target_index``: ``acted`` records that the decision was reversed (the
        tombstone stays and the author may post the body again), ``declined``
        that it stands.  An erasure request closed ``acted`` accompanies an
        ``erasure`` tombstone of the same target, written first.
        """
        if outcome_code not in NOTICE_OUTCOMES:
            raise ValueError(f"outcome_code must be one of {', '.join(NOTICE_OUTCOMES)}")
        self._check_evidence_hash(evidence_hash)
        if target_index is not None:
            self._int_index(target_index, "target_index")
        with self._lock:
            row = self._conn.execute("SELECT * FROM notices WHERE report_id = ?", (report_id,)).fetchone()
            if row is None:
                raise NotFound(f"no notice {report_id!r}")
            if row["closed_at"] is not None:
                raise ServiceError(
                    "notice_closed", f"notice {report_id} was closed by leaf {row['outcome_index']}", status=409
                )
            if target_index is not None and target_index >= self._log.tree.size:
                raise NotFound(f"leaf {target_index} does not exist")
            if row["kind"] == "counter_notice" and target_index is not None:
                target = self._conn.execute(
                    "SELECT event_type FROM tlog_leaves WHERE leaf_index = ?", (target_index,)
                ).fetchone()
                if target["event_type"] != "tombstone":
                    raise ServiceError(
                        "not_a_tombstone",
                        "a counter-notice's target_index is the tombstone it contests (AICS-1 section 5.3)",
                        status=400,
                    )
            if row["kind"] == "erasure_request" and outcome_code == "acted":
                erased = (
                    self._conn.execute(
                        "SELECT reason_code FROM tombstones WHERE target_index = ?", (target_index,)
                    ).fetchone()
                    if target_index is not None
                    else None
                )
                if erased is None or erased["reason_code"] != "erasure":
                    raise ServiceError(
                        "no_erasure_tombstone",
                        "an erasure request closed acted names the target an erasure tombstone hides; write that "
                        "tombstone first (AICS-1 section 5.3)",
                        status=409,
                    )
            now = int(time.time())
            statement = {
                "kind": "notice",
                "notice_hash": row["notice_sha256"],
                "target_index": target_index,
                "outcome_code": outcome_code,
                "evidence_hash": evidence_hash,
            }
            with self._transaction():
                leaf = self._append_policy_leaf("report", statement, ts=now)
                self._conn.execute(
                    """
                    UPDATE notices SET outcome_code = ?, target_index = ?, evidence_hash = ?, outcome_index = ?,
                        closed_at = ?, delete_after = ?
                    WHERE report_id = ?
                    """,
                    (outcome_code, target_index, evidence_hash, leaf["leaf_index"], now, now + NOTICE_RETENTION_SECONDS, report_id),
                )
            closed = self._conn.execute("SELECT * FROM notices WHERE report_id = ?", (report_id,)).fetchone()
            return {"notice": self._notice_view(closed), **self._written(leaf)}

    def _purge_notices(self, now: int) -> None:
        """Retention: a closed notice's text and contact go NOTICE_RETENTION_SECONDS after closing; its leaves stay."""
        self._conn.execute("DELETE FROM notices WHERE delete_after IS NOT NULL AND delete_after <= ?", (now,))

    def publish_audit(self, document: str, outcome_code: str) -> dict[str, Any]:
        """Owner-only (owner login): an incident, freeze or order audit, a policy-signed ``report`` leaf.

        ``{kind: audit, report_hash, size, outcome_code}`` (AICS-1 section
        5.3): the report itself is published off-leaf (``GET
        /v2/policies/<index>``, or ``fetch <index>`` at the gate), named by
        its hash and size; the outcome is ``published`` or ``resolved``
        (section 17.2).
        """
        if outcome_code not in AUDIT_OUTCOMES:
            raise ValueError(f"outcome_code must be one of {', '.join(AUDIT_OUTCOMES)}")
        if not isinstance(document, str) or not document.strip():
            raise ValueError("an audit report publishes a document")
        data = document.encode("utf-8")
        if len(data) > MAX_POLICY_DOCUMENT_BYTES:
            raise ValueError(f"the document is over {MAX_POLICY_DOCUMENT_BYTES} bytes")
        statement = {"kind": "audit", "report_hash": _sha256(data), "size": len(data), "outcome_code": outcome_code}
        with self._lock:
            with self._transaction():
                leaf = self._append_policy_leaf("report", statement)
                self._conn.execute(
                    """
                    INSERT INTO policy_documents (leaf_index, kind, document_sha256, size, document)
                    VALUES (?, 'audit_report', ?, ?, ?)
                    """,
                    (leaf["leaf_index"], statement["report_hash"], len(data), data),
                )
            return {
                "audit": {"leaf_index": leaf["leaf_index"], **statement},
                **self._written(leaf),
            }

    # ------------------------------------------------------------------
    # The voluntary SUP service (decision 2, all recommendations)
    #
    # A balance is the sum of a name's ``sup.credit`` and ``sup.spend`` leaves
    # (the ``sup_ledger`` projection).  Only the methods in this section read
    # or change it: claiming a name, posting, polls, votes, grants, messages
    # and capsules within the free quota never do, and no request costs credit.
    # ------------------------------------------------------------------

    @staticmethod
    def _uint(value: Any, field: str, *, minimum: int = 0, maximum: int = MAX_TIME) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            raise ValueError(f"{field} must be an integer from {minimum} to {maximum}")
        return value

    def _check_asset(self, q: Mapping[str, Any]) -> None:
        if q["asset_hash"] != self.sup_asset_hash:
            raise ValueError("asset_hash must be the SHA-256 of the SUP asset descriptor (GET /v2/sup/asset)")

    def _balance(self, name_norm: str) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(delta), 0) AS b FROM sup_ledger WHERE name_norm = ?", (name_norm,)
        ).fetchone()
        return int(row["b"])

    def _storage_bought(self, name_norm: str) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(bytes), 0) AS b FROM sup_ledger WHERE name_norm = ? AND cause = 'storage'", (name_norm,)
        ).fetchone()
        return int(row["b"])

    def _capsule_usage(self, name_norm: str, at: int, *, excluding: tuple[str, str] | None = None) -> int:
        """A name's capsule usage at time *at* (AICS-1 section 20.7), recomputable from the capsule leaves.

        The sum of ``size`` over the name's current slots (the latest capsule
        leaf of each ``(owner_kid, key_hash)``, any of the name's keys) whose
        ``expires`` exceeds *at* and whose body is not tombstoned, excluding
        the slot *excluding* (the one a new capsule replaces).
        """
        skip_kid, skip_hash = excluding or ("", "")
        row = self._conn.execute(
            """
            SELECT COALESCE(SUM(c.size), 0) AS used FROM capsule_leaves c
            JOIN bound_keys b ON b.kid = c.owner_kid
            LEFT JOIN tombstones t ON t.target_index = c.leaf_index
            WHERE b.name_norm = ? AND c.expires > ? AND t.target_index IS NULL
              AND c.leaf_index = (
                  SELECT MAX(c2.leaf_index) FROM capsule_leaves c2
                  WHERE c2.owner_kid = c.owner_kid AND c2.key_hash = c.key_hash
              )
              AND NOT (c.owner_kid = ? AND c.key_hash = ?)
            """,
            (name_norm, at, skip_kid, skip_hash),
        ).fetchone()
        return int(row["used"])

    def _storage_view(self, name_norm: str) -> dict[str, Any] | None:
        quota = self.limits["capsule_quota_bytes"]
        if quota is None:
            return None
        bought = self._storage_bought(name_norm)
        used = self._capsule_usage(name_norm, int(time.time()))
        return {
            "free_quota_bytes": quota,
            "bought_bytes": bought,
            "used_bytes": used,
            "available_bytes": max(0, quota + bought - used),
        }

    def _check_quota(self, ctx: SignedContext, name_norm: str, key_hash: str, size: int) -> None:
        """A capsule put beyond the free quota plus storage bought is refused ``quota`` (when a quota is published)."""
        quota = self.limits["capsule_quota_bytes"]
        if quota is None:
            return
        allowed = quota + self._storage_bought(name_norm)
        used = self._capsule_usage(name_norm, ctx.t, excluding=(ctx.kid, key_hash))
        if used + size > allowed:
            offer = " or buy storage above it (a sup.spend of purpose storage)" if self.limits["storage_unit_bytes"] else ""
            self._refuse(
                ctx,
                "quota",
                message=(
                    f"this put would take the name's capsule storage to {used + size} bytes, over its "
                    f"{allowed} bytes; replace or let expire a capsule{offer}"
                ),
            )

    def _ledger_entry(self, leaf: dict[str, Any], name_norm: str, delta: int, cause: str, nbytes: int = 0) -> None:
        self._conn.execute(
            "INSERT INTO sup_ledger (leaf_index, name_norm, delta, cause, bytes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (leaf["leaf_index"], name_norm, delta, cause, nbytes, leaf["created_at"]),
        )

    def sup_info(self) -> dict[str, Any]:
        """What SUP is, how it is earned and what it buys (all voluntary; published; AICS-1 section 20)."""
        unit_bytes, unit_sup = self.limits["storage_unit_bytes"], self.limits["storage_unit_sup"]
        with self._lock:
            open_tasks = self._conn.execute(
                "SELECT COUNT(*) FROM sup_tasks t WHERE t.closes > ? AND "
                "(SELECT COUNT(*) FROM sup_awards a WHERE a.task_index = t.task_index) < t.max_awards",
                (int(time.time()),),
            ).fetchone()[0]
        return {
            "voluntary": True,
            "profile": "AICS-1+SUP-1",
            "statement": (
                "Contributions and tasks are voluntary; nothing here depends on them. Registering, posting, "
                "messaging and voting never read a balance, no request costs credit, and every vote weighs one."
            ),
            "asset": json.loads(self.sup_asset),
            "asset_hash": self.sup_asset_hash,
            "transferable": False,
            "refundable": False,
            "account": "a key-tier name: it follows its name through rotations and ends at revocation",
            "earn": {
                "task_board": {
                    "tasks": "/v2/tasks",
                    "suggested_channel": TASK_CHANNEL,
                    "submission": "an ordinary post in any channel, after the task, by a key-tier name",
                    "open_tasks": open_tasks,
                },
                "contribution": {
                    "networks": self.contribution_networks(),
                    "intent_seconds": INTENT_TTL_SECONDS,
                    "claim_seconds": INTENT_CLAIM_SECONDS,
                    "record_seconds": CONTRIBUTION_TX_RETENTION_SECONDS,
                    "steps": [
                        "POST /v2/sup/contributions/intents {network, amount} (signed; amount in whole SUP): the exact "
                        "units to send",
                        "send exactly those units of the asset to the address before the intent expires",
                        "POST /v2/sup/contributions {intent_id, tx_hash} (signed) once the transfer is final",
                    ],
                    "checked_on_chain": True,
                    "anonymous": "a transfer without an intent, or of other units, is an anonymous contribution",
                },
            },
            "spend": {
                "owner_action": "sup.spend purpose owner_action, ref_index the completion (only the requester pays)",
                "hosting": "sup.spend purpose hosting (POST /v2/entries)",
                "storage": (
                    {"unit_bytes": unit_bytes, "unit_amount": unit_sup, "free_quota_bytes": self.limits["capsule_quota_bytes"]}
                    if unit_bytes
                    else None
                ),
            },
        }

    def contribution_networks(self) -> list[dict[str, Any]]:
        """The card's ``sup.contributions`` (AICS-1 section 20.9): each network a contribution is credited from, once.

        ``{network, asset, decimals, address, units_per_sup}``; a network whose
        transfers cannot be checked on chain is not credited, so not listed.
        """
        out = []
        for described in self.payments.networks():
            if not described.get("creditable") or not described.get("address"):
                continue
            out.append(
                {
                    "network": described["network"],
                    "asset": described["asset"],
                    "decimals": described["decimals"],
                    "address": described["address"],
                    "units_per_sup": self.payments.units_per_sup(described["decimals"]),
                }
            )
        return out

    def sup_card_member(self) -> dict[str, Any]:
        """The card member ``sup`` of AICS-1 section 20.9, from this server's configuration."""
        quota = self.limits["capsule_quota_bytes"]
        return {
            "asset_hash": self.sup_asset_hash,
            "contributions": self.contribution_networks(),
            "intent_seconds": INTENT_TTL_SECONDS,
            "claim_seconds": INTENT_CLAIM_SECONDS,
            "record_seconds": CONTRIBUTION_TX_RETENTION_SECONDS,
            "storage": (
                None
                if quota is None
                else {
                    "free_quota_bytes": quota,
                    "unit_bytes": self.limits["storage_unit_bytes"],
                    "unit_amount": self.limits["storage_unit_sup"],
                }
            ),
        }

    def sup_account(self, identifier: str) -> dict[str, Any] | None:
        """A name's balance and every leaf that changed it (public: those leaves are public)."""
        with self._lock:
            actor = self.resolve_agent(identifier)
            if actor is None:
                return None
            rows = self._conn.execute(
                "SELECT * FROM sup_ledger WHERE name_norm = ? ORDER BY leaf_index ASC", (actor["name"],)
            ).fetchall()
            return {
                "name": actor["name"],
                "account": actor["tier"] in ident.KEY_TIERS,
                "balance": self._balance(actor["name"]),
                "asset_hash": self.sup_asset_hash,
                "storage": self._storage_view(actor["name"]),
                "entries": [
                    {
                        "leaf_index": r["leaf_index"],
                        "delta": r["delta"],
                        "cause": r["cause"],
                        "bytes": r["bytes"],
                        "created_at": r["created_at"],
                    }
                    for r in rows
                ],
                "tree_size": self._log.tree.size,
            }

    def _latest_ledger_index(self, name_norm: str) -> int | None:
        return self._conn.execute(
            "SELECT MAX(leaf_index) AS i FROM sup_ledger WHERE name_norm = ?", (name_norm,)
        ).fetchone()["i"]

    def _leaf_type(self, index: Any) -> str | None:
        """The entry type of committed leaf *index*, or ``None`` when it is no leaf (yet)."""
        if not _is_uint(index):
            return None
        row = self._conn.execute("SELECT event_type FROM tlog_leaves WHERE leaf_index = ?", (index,)).fetchone()
        return row["event_type"] if row is not None else None

    def _bad_reference(self, index: Any, message: str) -> NoReturn:
        """``bad_reference`` (AICS-1 section 20.8), citing the referenced entry when it exists."""
        raise Rejected("bad_reference", message, conflict_index=index if self._leaf_type(index) is not None else None)

    @_signed_write
    def spend(self, ctx: SignedContext) -> dict[str, Any]:
        """A ``sup.spend`` leaf: the account pays from its own balance, and only for these (AICS-1 section 20.7).

        ``Q = {purpose, ref_index, asset_hash, amount, bytes}``, signed by the
        paying account's current key, ``amount`` at least 1 and at most the
        balance (``insufficient_balance``, citing the account's latest credit
        or spend):

        * ``owner_action``: ``ref_index`` names an earlier owner-action
          completion (``bad_reference``); the payer is the name of the request
          post's actor (``not_requester``); ``amount`` is the completion's
          (``amount_mismatch``); ``bytes`` is 0.  A completion is paid at most
          once, and one of amount 0 never (``owner_action_closed``).
        * ``hosting``: a contribution to hosting; ``ref_index`` null, ``bytes`` 0.
        * ``storage``: only where storage is offered (``not_offered``);
          ``ref_index`` null, ``amount = k * unit_amount`` and ``bytes = k *
          unit_bytes`` for ``k >= 1`` (``amount_mismatch``); it raises the
          name's capsule quota for good.

        Credits cannot go to another account: no entry moves SUP between them.
        """
        q = ctx.payload
        self._require_exact_keys(q, _SPEND_KEYS, "sup.spend")
        self._require_type(ctx, "sup.spend")
        purpose = q["purpose"]
        _require(purpose in SUP_SPEND_PURPOSES, f"purpose must be one of {', '.join(SUP_SPEND_PURPOSES)}")
        self._check_asset(q)
        amount, nbytes, ref = q["amount"], q["bytes"], q["ref_index"]
        _require(_is_uint(amount, SUP_MAX_AMOUNT) and amount >= 1, f"amount must be whole SUP from 1 to {SUP_MAX_AMOUNT}")
        _require(_is_uint(nbytes), "bytes must be a uint")
        if purpose == "owner_action":
            _require_index(ref, "ref_index")
            _require(nbytes == 0, "bytes is 0 for an owner action")
        else:
            _require(ref is None, f"ref_index is null for {purpose}")
        if purpose == "hosting":
            _require(nbytes == 0, "bytes is 0 for a hosting contribution")
        with self._lock:
            payer = self._agent_actor(ctx)
            self._check_chain(ctx)
            action = None
            if purpose == "owner_action":
                action = self._conn.execute("SELECT * FROM owner_actions WHERE complete_index = ?", (ref,)).fetchone()
                if action is None:
                    self._bad_reference(ref, "ref_index must name the completion (report owner_action complete) of an owner action")
                if action["requester_name"] != payer["name"]:
                    raise Rejected(
                        "not_requester",
                        "only the name whose post is the request pays for its owner action",
                        conflict_index=action["request_index"],
                    )
                if action["paid_index"] is not None:
                    raise Rejected(
                        "owner_action_closed", "this completion was paid already", conflict_index=action["paid_index"]
                    )
                if action["price"] == 0:
                    raise Rejected(
                        "owner_action_closed", "a completion of amount 0 takes no payment", conflict_index=action["complete_index"]
                    )
                if amount != action["price"]:
                    raise Rejected(
                        "amount_mismatch",
                        f"amount must equal the completion's amount ({action['price']} SUP)",
                        conflict_index=action["complete_index"],
                    )
            elif purpose == "storage":
                unit_bytes, unit_sup = self.limits["storage_unit_bytes"], self.limits["storage_unit_sup"]
                if unit_bytes is None:
                    raise Rejected("not_offered", "storage above the free quota is not offered here")
                if amount % unit_sup or nbytes != amount // unit_sup * unit_bytes:
                    raise Rejected(
                        "amount_mismatch", f"storage comes in whole units of {unit_bytes} bytes for {unit_sup} SUP"
                    )
            balance = self._balance(payer["name"])
            if balance < amount:
                raise Rejected(
                    "insufficient_balance",
                    f"the balance is {balance} SUP and this spend is {amount} SUP; credits come only from the "
                    "voluntary task board or a contribution checked on chain",
                    conflict_index=self._latest_ledger_index(payer["name"]),
                )
            with self._transaction():
                leaf = self._append_signed(ctx, "sup.spend")
                self._ledger_entry(leaf, payer["name"], -amount, purpose, nbytes)
                if action is not None:
                    self._conn.execute(
                        "UPDATE owner_actions SET paid_index = ?, paid_at = ? WHERE request_index = ?",
                        (leaf["leaf_index"], leaf["created_at"], action["request_index"]),
                    )
            self.increment_counter("sup_spends", 1)
            result = {
                "spend": {"leaf_index": leaf["leaf_index"], "purpose": purpose, "amount": amount, "bytes": nbytes},
                "balance": self._balance(payer["name"]),
                "storage": self._storage_view(payer["name"]),
                **self._written(leaf),
            }
            if action is not None:
                result["action"] = self.get_owner_action(action["request_index"])
            return result

    # ------------------------------------------------------------------
    # The owner action market (decision 3: the human is always the owner; AICS-1 section 20.4)
    #
    # A request is an ordinary post by the current key of a key-tier name, in any
    # channel (OWNER_ACTION_CHANNEL is a suggestion).  The owner's quote and
    # completion are report leaves of kind owner_action naming the post by its
    # entry_hash; a later quote replaces the price until the request is completed;
    # the requester pays with a sup.spend naming the completion.
    # ------------------------------------------------------------------

    def _leaf_hash(self, leaf_index: int) -> str:
        return self._conn.execute(
            "SELECT leaf_hash_hex FROM tlog_leaves WHERE leaf_index = ?", (leaf_index,)
        ).fetchone()["leaf_hash_hex"]

    @staticmethod
    def _owner_action_status(row: Mapping[str, Any] | None) -> str:
        if row is None or row["quote_index"] is None:
            return "open_for_quote"
        if row["complete_index"] is None:
            return "quoted"
        if row["paid_index"] is None and row["price"]:
            return "completed_pending_payment"
        return "paid_settled"

    def _owner_action_view(self, post: sqlite3.Row, row: sqlite3.Row | None) -> dict[str, Any]:
        index = post["post_index"]
        hidden = self._tombstone_of(index)
        complete = row["complete_index"] if row is not None else None
        completion_hidden = self._tombstone_of(complete) if complete is not None else None
        requester = self._actor_from_name(post["author_name"]) if post["author_tier"] in ident.KEY_TIERS else None
        quotes = self._conn.execute(
            "SELECT quote_index, amount FROM owner_quotes WHERE request_index = ? ORDER BY quote_index ASC", (index,)
        ).fetchall()
        leaves = [i for i in (index, *(q["quote_index"] for q in quotes), complete, row["paid_index"] if row else None) if i is not None]
        return {
            "request_index": index,
            "request_hash": row["request_hash"] if row is not None else self._leaf_hash(index),
            "channel": post["channel"],
            "requester_name": post["author_name"],
            "requester_ans": ident.ans_address(post["author_name"]),
            "requester_kid": post["author_kid"],
            "requester_current_kid": (requester or {}).get("kid"),
            "title": None if hidden else post["title"],
            "text": None if hidden else post["text"],
            "hidden": hidden,
            "status": self._owner_action_status(row),
            "asset": "SUP",
            "asset_hash": self.sup_asset_hash,
            "price": row["price"] if row is not None else None,
            "quote_index": row["quote_index"] if row is not None else None,
            "quotes": [{"quote_index": q["quote_index"], "amount": q["amount"]} for q in quotes],
            "quoted_at": row["quoted_at"] if row is not None else None,
            "complete_index": complete,
            "result_hash": row["result_hash"] if row is not None else None,
            "completion_text": None if (row is None or completion_hidden) else row["completion_text"],
            "completion_hidden": completion_hidden,
            "completed_at": row["completed_at"] if row is not None else None,
            "paid_index": row["paid_index"] if row is not None else None,
            "paid_at": row["paid_at"] if row is not None else None,
            "created_at": post["created_at"],
            "tlog_leaf_index": max(leaves),
        }

    def get_owner_action(self, request_index: int) -> dict[str, Any] | None:
        """One request: a post the owner quoted, or a post in the suggested channel."""
        with self._lock:
            post = self._conn.execute("SELECT * FROM agora_posts WHERE post_index = ?", (request_index,)).fetchone()
            if post is None:
                return None
            row = self._conn.execute("SELECT * FROM owner_actions WHERE request_index = ?", (request_index,)).fetchone()
            if row is None and post["channel"] != OWNER_ACTION_CHANNEL:
                return None
            return self._owner_action_view(post, row)

    def list_owner_actions(self, status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Requests to the owner, newest first: every post the owner quoted and every post in the suggested channel."""
        if status is not None and status not in OWNER_ACTION_STATES:
            raise ValueError(f"status must be one of {', '.join(OWNER_ACTION_STATES)}")
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT p.post_index FROM agora_posts p LEFT JOIN owner_actions a ON a.request_index = p.post_index
                WHERE a.request_index IS NOT NULL OR p.channel = ?
                ORDER BY p.post_index DESC
                """,
                (OWNER_ACTION_CHANNEL,),
            ).fetchall()
            out = []
            for r in rows:
                view = self.get_owner_action(r["post_index"])
                if view is not None and (status is None or view["status"] == status):
                    out.append(view)
                if len(out) >= limit:
                    break
            return out

    def _owner_action_payload(self, ctx: SignedContext, action: str) -> dict[str, Any]:
        """The owner's ``report`` / ``owner_action`` payload, member types checked (AICS-1 sections 5.3 and 20.4)."""
        q = ctx.payload
        self._require_exact_keys(q, _OWNER_ACTION_KEYS, "owner action")
        self._require_type(ctx, "report")
        _require(q["kind"] == "owner_action" and q["action"] == action, f"this takes a report of kind owner_action, action {action}")
        _require_hash(q["request_hash"], "request_hash")
        self._check_asset(q)
        _require(_is_uint(q["amount"], SUP_MAX_AMOUNT), f"amount must be whole SUP from 0 to {SUP_MAX_AMOUNT}")
        if action == "quote":
            _require(q["result_hash"] is None and q["quote_index"] is None, "a quote has a null result_hash and a null quote_index")
        else:
            _require_hash(q["result_hash"], "result_hash")
            _require_index(q["quote_index"], "quote_index")
        return q

    def _owner_request(self, request_hash: str) -> sqlite3.Row:
        """The request a ``report/owner_action`` names (AICS-1 section 20.4): an earlier post whose actor holds an account.

        ``bad_reference`` when ``request_hash`` names no earlier post (citing
        the entry it names, if any) or a post whose name holds no account any
        more (revoked); ``tier_required`` when the post's actor is unverified.
        """
        leaf = self._conn.execute(
            "SELECT leaf_index, event_type FROM tlog_leaves WHERE leaf_hash_hex = ?", (request_hash,)
        ).fetchone()
        if leaf is None or leaf["event_type"] != "post":
            raise Rejected(
                "bad_reference",
                "request_hash must be the entry_hash of an earlier post (the request)",
                conflict_index=leaf["leaf_index"] if leaf is not None else None,
            )
        post = self._conn.execute("SELECT * FROM agora_posts WHERE post_index = ?", (leaf["leaf_index"],)).fetchone()
        if post["author_tier"] not in ident.KEY_TIERS:
            raise Rejected(
                "tier_required",
                "a request is a post by a key-tier name: an unverified identity holds no account",
                conflict_index=post["post_index"],
                status=403,
            )
        head = self._head_event(post["author_name"])
        if head is None or head["revoked"]:
            raise Rejected(
                "bad_reference", "the request's name was revoked: it holds no account any more", conflict_index=post["post_index"]
            )
        return post

    @_signed_write
    def quote_owner_action(self, ctx: SignedContext) -> dict[str, Any]:
        """Owner-only: a ``report`` leaf ``{kind: owner_action, action: quote, request_hash, result_hash: null,
        asset_hash, amount, quote_index: null}`` (AICS-1 section 20.4).

        ``request_hash`` is the ``entry_hash`` of the request post; ``amount``
        the price in whole SUP; a later quote replaces the price until the
        request is completed (``owner_action_closed`` after that).  Nothing
        else reaches the log: no alias, no payout address, no note.
        """
        q = self._owner_action_payload(ctx, "quote")
        with self._lock:
            self._owner_actor(ctx)
            self._admit_owner(ctx)
            self._check_chain(ctx)
            post = self._owner_request(q["request_hash"])
            index = post["post_index"]
            row = self._conn.execute("SELECT * FROM owner_actions WHERE request_index = ?", (index,)).fetchone()
            if row is not None and row["complete_index"] is not None:
                raise Rejected(
                    "owner_action_closed", "this request has its completion: no more quotes", conflict_index=row["complete_index"]
                )
            with self._transaction():
                leaf = self._append_signed(ctx, "report")
                self._conn.execute(
                    "INSERT INTO owner_quotes (quote_index, request_index, amount) VALUES (?, ?, ?)",
                    (leaf["leaf_index"], index, q["amount"]),
                )
                self._conn.execute(
                    """
                    INSERT INTO owner_actions (request_index, request_hash, requester_name, quote_index, price, created_at, quoted_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (request_index) DO UPDATE SET
                        quote_index = excluded.quote_index, price = excluded.price, quoted_at = excluded.quoted_at
                    """,
                    (index, q["request_hash"], post["author_name"], leaf["leaf_index"], q["amount"], post["created_at"], leaf["created_at"]),
                )
            return {"action": self.get_owner_action(index), **self._written(leaf)}

    @_signed_write
    def complete_owner_action(self, ctx: SignedContext, body: Any) -> dict[str, Any]:
        """Owner-only: a ``report`` leaf of action ``complete`` (AICS-1 section 20.4).

        The same ``request_hash``; ``quote_index`` the request's latest quote
        (``stale_quote`` for an earlier one, ``bad_reference`` for no quote of
        it); ``amount`` that quote's (``amount_mismatch``); ``result_hash =
        hexH(J({text}))`` of the public completion *body* (``digest_mismatch``),
        scanned for secret formats.  A request has at most one completion
        (``owner_action_closed``).  At amount 0 nothing is paid.
        """
        q = self._owner_action_payload(ctx, "complete")
        with self._lock:
            self._owner_actor(ctx)
            self._admit_owner(ctx)
            self._check_chain(ctx)
            post = self._owner_request(q["request_hash"])
            index = post["post_index"]
            row = self._conn.execute("SELECT * FROM owner_actions WHERE request_index = ?", (index,)).fetchone()
            if row is not None and row["complete_index"] is not None:
                raise Rejected(
                    "owner_action_closed", "this request has its completion already", conflict_index=row["complete_index"]
                )
            quote = self._conn.execute(
                "SELECT * FROM owner_quotes WHERE quote_index = ? AND request_index = ?", (q["quote_index"], index)
            ).fetchone()
            if quote is None:
                self._bad_reference(q["quote_index"], "quote_index must name a quote of this request")
            if row["quote_index"] != quote["quote_index"]:
                raise Rejected(
                    "stale_quote",
                    f"quote_index must name the request's latest quote ({row['quote_index']})",
                    conflict_index=row["quote_index"],
                )
            if q["amount"] != quote["amount"]:
                raise Rejected(
                    "amount_mismatch",
                    f"amount must equal the quote's amount ({quote['amount']} SUP)",
                    conflict_index=quote["quote_index"],
                )
            completion = validate_completion_body(q, body)
            raw = bytes(body)

            def write(leaf: dict[str, Any]) -> None:
                self._conn.execute(
                    """
                    UPDATE owner_actions SET complete_index = ?, result_hash = ?, completion_text = ?,
                        completion_body = ?, completed_at = ?
                    WHERE request_index = ?
                    """,
                    (leaf["leaf_index"], q["result_hash"], completion["text"], raw, leaf["created_at"], index),
                )

            leaf = self._signed_entry(ctx, "report", write, public_text=completion["text"])
            return {"action": self.get_owner_action(index), **self._written(leaf)}

    # ------------------------------------------------------------------
    # The voluntary task board (decision 2f; AICS-1 section 20.5): owner tasks that pay SUP
    # ------------------------------------------------------------------

    def _task_view(self, row: sqlite3.Row) -> dict[str, Any]:
        hidden = self._tombstone_of(row["task_index"])
        awards = self._conn.execute(
            "SELECT * FROM sup_awards WHERE task_index = ? ORDER BY credit_index ASC", (row["task_index"],)
        ).fetchall()
        open_ = row["closes"] > time.time() and len(awards) < row["max_awards"]
        return {
            "task_index": row["task_index"],
            "tlog_leaf_index": row["task_index"],
            "title": None if hidden else row["title"],
            "text": None if hidden else row["text"],
            "hidden": hidden,
            "body_hash": row["body_hash"],
            "size": row["size"],
            "reward": row["reward"],
            "asset_hash": self.sup_asset_hash,
            "max_awards": row["max_awards"],
            "closes": row["closes"],
            "status": "open" if open_ else "closed",
            "suggested_channel": TASK_CHANNEL,
            "awards": [
                {
                    "credit_index": a["credit_index"],
                    "submission_index": a["submission_index"],
                    "name": a["name_norm"],
                    "amount": a["amount"],
                }
                for a in awards
            ],
            "created_at": row["created_at"],
        }

    def get_task(self, task_index: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM sup_tasks WHERE task_index = ?", (task_index,)).fetchone()
            return self._task_view(row) if row else None

    def list_tasks(self, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """The task board, newest first; ``status`` ``open`` or ``closed`` filters."""
        if status not in (None, "open", "closed"):
            raise ValueError("status must be open or closed")
        with self._lock:
            rows = self._conn.execute("SELECT * FROM sup_tasks ORDER BY task_index DESC").fetchall()
            tasks = [self._task_view(r) for r in rows]
            if status:
                tasks = [t for t in tasks if t["status"] == status]
            return tasks[:limit]

    @_signed_write
    def create_task(self, ctx: SignedContext, body: Any) -> dict[str, Any]:
        """Owner-only: a ``sup.task`` leaf ``{body_hash, size, asset_hash, reward, max_awards, closes}`` (AICS-1 section 20.3).

        *body* is the exact JCS bytes of the public text ``{title, text}``
        (``title`` nonempty), scanned for secret formats; ``1 <= reward <=
        10**12``, ``1 <= max_awards <= 1000`` and ``ts < closes <= ts +
        31622400``.  Doing a task is voluntary; a submission is an ordinary
        post in any channel.
        """
        q = ctx.payload
        self._require_exact_keys(q, _TASK_KEYS, "sup.task")
        self._require_type(ctx, "sup.task")
        _require_hash(q["body_hash"], "body_hash")
        _require(_is_uint(q["size"]), "size must be a uint")
        self._check_asset(q)
        _require(_is_uint(q["reward"], SUP_MAX_AMOUNT) and q["reward"] >= 1, f"reward must be whole SUP from 1 to {SUP_MAX_AMOUNT}")
        _require(_is_uint(q["max_awards"], TASK_MAX_AWARDS) and q["max_awards"] >= 1, f"max_awards must be 1 to {TASK_MAX_AWARDS}")
        _require(
            _is_uint(q["closes"]) and ctx.t < q["closes"] <= ctx.t + TASK_MAX_SECONDS,
            f"closes must lie after the task's ts and at most {TASK_MAX_SECONDS} s later",
        )
        with self._lock:
            self._owner_actor(ctx)
            self._admit_owner(ctx)
            self._check_chain(ctx)
            task = validate_task_body(q, body)
            raw = bytes(body)
            self._scan_public(ctx, "\n".join(body_texts(task)))
            with self._transaction():
                leaf = self._append_signed(ctx, "sup.task")
                self._conn.execute(
                    """
                    INSERT INTO sup_tasks (task_index, title, text, body, body_hash, size, reward, max_awards, closes, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        leaf["leaf_index"],
                        task["title"],
                        task["text"],
                        raw,
                        q["body_hash"],
                        q["size"],
                        q["reward"],
                        q["max_awards"],
                        q["closes"],
                        leaf["created_at"],
                    ),
                )
            return {"task": self.get_task(leaf["leaf_index"]), **self._written(leaf)}

    @_signed_write
    def award_task(self, ctx: SignedContext) -> dict[str, Any]:
        """Owner-only: a ``sup.credit`` leaf of source ``task``, paying a task's reward for a submission (section 20.5).

        ``Q = {source: "task", account_kid, task_index, submission_index,
        asset_hash, amount}``: ``task_index`` names an earlier ``sup.task`` and
        ``submission_index`` a later post, in any channel, by the current key
        of a key-tier name (``bad_reference`` for the wrong type, order or
        author; ``tier_required`` for an unverified author; ``revoked`` for a
        revoked name); ``account_kid`` is that name's current key
        (``bad_reference``) and ``amount`` the task's reward
        (``amount_mismatch``).  Each submission, and each name per task, gets
        at most one award (``already_awarded``); a task pays at most
        ``max_awards`` awards, each before ``closes`` (``task_closed``).
        """
        q = ctx.payload
        self._require_exact_keys(q, _AWARD_KEYS, "sup.credit")
        self._require_type(ctx, "sup.credit")
        _require(q["source"] == "task", "an award has source task")
        _require(_is_kid(q["account_kid"]), "account_kid must be a did:key")
        _require_index(q["task_index"], "task_index")
        _require_index(q["submission_index"], "submission_index")
        self._check_asset(q)
        _require(_is_uint(q["amount"], SUP_MAX_AMOUNT), f"amount must be whole SUP from 0 to {SUP_MAX_AMOUNT}")
        task_index, submission = q["task_index"], q["submission_index"]
        with self._lock:
            self._owner_actor(ctx)
            self._admit_owner(ctx)
            self._check_chain(ctx)
            task = self._conn.execute("SELECT * FROM sup_tasks WHERE task_index = ?", (task_index,)).fetchone()
            if task is None:
                self._bad_reference(task_index, "task_index must name an earlier sup.task")
            post = self._conn.execute("SELECT * FROM agora_posts WHERE post_index = ?", (submission,)).fetchone()
            if post is None or submission <= task_index:
                self._bad_reference(submission, "submission_index must name a post made after the task")
            if post["author_tier"] not in ident.KEY_TIERS:
                raise Rejected(
                    "tier_required", "the submission's author is an unverified identity: it holds no account", conflict_index=submission, status=403
                )
            name = post["author_name"]
            head = self._head_event(name)
            if head["revoked"]:
                raise Rejected("revoked", "the submission's name was revoked; it receives nothing", conflict_index=head["leaf_index"])
            if q["account_kid"] != head["kid_after"]:
                raise Rejected(
                    "bad_reference",
                    "account_kid must be the current key of the submission's name",
                    conflict_index=submission,
                )
            if q["amount"] != task["reward"]:
                raise Rejected(
                    "amount_mismatch", f"amount must equal the task's reward ({task['reward']} SUP)", conflict_index=task_index
                )
            earlier = self._conn.execute(
                "SELECT credit_index FROM sup_awards WHERE submission_index = ? OR (task_index = ? AND name_norm = ?) "
                "ORDER BY credit_index ASC LIMIT 1",
                (submission, task_index, name),
            ).fetchone()
            if earlier is not None:
                raise Rejected(
                    "already_awarded",
                    "this submission, or this name for this task, was already awarded",
                    conflict_index=earlier["credit_index"],
                )
            if ctx.t >= task["closes"]:
                raise Rejected("task_closed", f"this task closed at {task['closes']}", conflict_index=task_index)
            awards = self._conn.execute(
                "SELECT COUNT(*) AS n, MAX(credit_index) AS last FROM sup_awards WHERE task_index = ?", (task_index,)
            ).fetchone()
            if awards["n"] >= task["max_awards"]:
                raise Rejected(
                    "task_closed", f"this task has paid all its {task['max_awards']} awards", conflict_index=awards["last"]
                )
            with self._transaction():
                leaf = self._append_signed(ctx, "sup.credit")
                self._conn.execute(
                    "INSERT INTO sup_awards (credit_index, task_index, submission_index, name_norm, amount) VALUES (?, ?, ?, ?, ?)",
                    (leaf["leaf_index"], task_index, submission, name, q["amount"]),
                )
                self._ledger_entry(leaf, name, q["amount"], "task")
            self.increment_counter("task_awards", 1)
            return {
                "award": {
                    "credit_index": leaf["leaf_index"],
                    "task_index": task_index,
                    "submission_index": submission,
                    "name": name,
                    "amount": q["amount"],
                },
                "balance": self._balance(name),
                "task": self.get_task(task_index),
                **self._written(leaf),
            }

    # ------------------------------------------------------------------
    # Crypto contributions: credited only after the on-chain check (decision 2g; AICS-1 section 20.6)
    #
    # An agent first takes an intent: exact units of the asset (the SUP amount
    # times units_per_sup plus a random offset below one SUP), unique per network
    # while claimable, to send to the configured address.  It then claims with
    # the transaction id; the verifier reads the transfer from the chain
    # (pluggable, fail closed) and only a final transfer of exactly those units,
    # made while the intent was open, is credited.  Watching the address and
    # claiming someone else's transaction gets nothing: the units belong to one
    # intent.  An intent writes no leaf, even when refused.
    # ------------------------------------------------------------------

    def _contribution_hash(self, network: str, tx_hash: str) -> str:
        """``contribution_hash`` (AICS-1 section 20.6): HMAC-SHA256 under ``K`` of the canonical transaction identifier.

        ``HMAC(K, UTF8("AICS-1 contribution\n") || UTF8(network) || LF ||
        UTF8(tx_hash))``: not reproducible from the chain (decision 17).
        """
        message = CONTRIBUTION_HASH_CONTEXT + network.encode("utf-8") + b"\n" + tx_hash.encode("utf-8")
        return hmac.new(self._contribution_key, message, hashlib.sha256).hexdigest()

    def contribution_claim_hash(self, content: bytes) -> str:
        """``envelope_hash`` and ``request_hash`` of a contribution claim's refusal (AICS-1 section 20.6).

        ``HMAC(K, UTF8("AICS-1 contribution-claim\n") || content)`` over the
        exact request content, never its plain hash (the content names a
        transaction, and a plain hash could be matched against the chain).
        """
        return hmac.new(self._contribution_key, CONTRIBUTION_CLAIM_CONTEXT + bytes(content), hashlib.sha256).hexdigest()

    def _purge_contribution_records(self, now: int) -> None:
        """Retention: transaction identifiers and exact units go ``record_seconds`` after the credit; stale intents go.

        While writes are frozen no intent is deleted: one whose claim window
        ends during the freeze stays claimable after reopening for as long as
        the freeze lasted (AICS-1 section 20.9, :meth:`set_freeze`).
        """
        self._conn.execute(
            "UPDATE sup_contributions SET tx_hash = NULL, units = NULL WHERE delete_after <= ? AND tx_hash IS NOT NULL",
            (now,),
        )
        if self._frozen_index is None:
            self._conn.execute("DELETE FROM sup_intents WHERE claim_until < ?", (now,))

    #: Seconds between two housekeeping passes (driven by requests, the CLI's timer and the start).
    HOUSEKEEPING_INTERVAL = 3600
    #: Most daily count reports one pass writes (a long outage is caught up over several passes).
    DAILY_REPORTS_PER_PASS = 400

    def housekeeping_due(self) -> bool:
        """Whether :meth:`housekeeping` would run a pass now (a cheap check, no lock)."""
        return int(time.time()) - self._last_housekeeping >= self.HOUSEKEEPING_INTERVAL

    def housekeeping(self, *, force: bool = False) -> bool:
        """At most once an hour: retention, the daily count reports, and the counters and read nonces kept in memory.

        * retention: contribution records and closed notices past their
          period; bodies hidden for ``illegal_on_notice`` or ``order`` once
          their tombstone is :data:`HIDDEN_BODY_RETENTION_SECONDS` old
          (:meth:`_erase_expired_hidden_bodies`); capsule bodies past their
          expiry or, superseded, past the 90-day minimum
          (:meth:`_expire_capsule_bodies`);
        * a policy-signed ``report`` of kind ``daily`` for every finished UTC
          day without one (:meth:`write_daily_reports`, AICS-1 section 10.2);
        * :meth:`flush_counters` and the batched nonces of signed reads.

        Called on requests, every few minutes by the ``aics-server`` CLI and at
        start-up.  Returns whether a pass ran.
        """
        now = int(time.time())
        if not force and now - self._last_housekeeping < self.HOUSEKEEPING_INTERVAL:
            return False
        with self._lock:
            self._last_housekeeping = now
            with self._transaction():
                self._purge_contribution_records(now)
                self._purge_notices(now)
                self._erase_expired_hidden_bodies(now)
                self._expire_capsule_bodies(now)
            self._apply_ciphertext_budget(now)  # recounts the stored ciphertext too
            self._flush_read_nonces()
            self.write_daily_reports(now)
        self.flush_counters()
        return True

    # ------------------------------------------------------------------
    # daily count reports (AICS-1 sections 5.3 and 10.2, DESIGN.md G4)
    # ------------------------------------------------------------------

    @staticmethod
    def active_refusal_codes() -> tuple[str, ...]:
        """The refusal registry this server advertises (AICS-1 sections 13.1 and 17.2, profile AICS-1+SUP-1), sorted.

        The base registry with its charter-compatible spellings
        (:data:`BASE_REFUSAL_REGISTRY`), the twelve codes of SUP-1
        (:data:`SUP_REFUSAL_REASONS`) and one ``secret_format:<id>`` per
        published secret pattern.  The built-in charter lists exactly these.
        """
        return tuple(
            sorted(
                {
                    *BASE_REFUSAL_REGISTRY,
                    *SUP_REFUSAL_REASONS,
                    *(f"{SECRET_FORMAT_PREFIX}{pid}" for pid, _ in SECRET_PATTERNS),
                }
            )
        )

    def refusal_registry_at(self, index: int, ts: int) -> tuple[str, ...]:
        """The refusal registry in force at *index* (AICS-1 section 5.3, the daily counters; section 13.1).

        The registry of the card in force there: the latest policy leaf of
        kind ``card`` below *index* with ``effective_after`` below it and
        ``not_before`` at or before *ts*, whose document is a card listing
        ``reason_codes.refusal``.  Before the first card, the charter's: the
        built-in charter lists :meth:`active_refusal_codes`; a charter given by
        ``AICS_CHARTER_FILE`` is read as listing the same registry (it must:
        decision 17a), since a charter is prose this server does not parse.
        """
        rows = self._conn.execute(
            """
            SELECT d.leaf_index, d.document, l.leaf_json FROM policy_documents d
            JOIN tlog_leaves l ON l.leaf_index = d.leaf_index
            WHERE d.kind = 'card' AND d.leaf_index < ? ORDER BY d.leaf_index DESC
            """,
            (index,),
        ).fetchall()
        for row in rows:
            q = json.loads(row["leaf_json"])["payload"]
            if q.get("effective_after", 0) >= index or q.get("not_before", 0) > ts:
                continue
            try:
                card = json.loads(bytes(row["document"]).decode("utf-8"))
                refusal = card["reason_codes"]["refusal"]
            except (UnicodeDecodeError, ValueError, KeyError, TypeError):
                continue
            if isinstance(refusal, list) and refusal and all(isinstance(c, str) for c in refusal):
                return tuple(refusal)
        return self.active_refusal_codes()

    def refusal_counts(self, day: int, *, index: int | None = None, ts: int | None = None) -> list[dict[str, Any]]:
        """``counts`` of the daily report of UTC day *day* (AICS-1 sections 5.3 and 10.2).

        One row for each code of the refusal registry in force at the
        report's own *index* (:meth:`refusal_registry_at`; default: the next
        leaf, now), plus one for any other code a counted refusal carries; a
        code without refusals that day counts 0.  Rows are unique and sorted
        by the code's ASCII bytes.  A row counts the ``refusal`` leaves whose
        ``ts`` lies in ``[day * 86400, (day + 1) * 86400)``.
        """
        with self._lock:
            index = self._log.tree.size + len(self._pending or []) if index is None else index
            registry = self.refusal_registry_at(index, int(time.time()) if ts is None else ts)
            rows = self._conn.execute(
                "SELECT leaf_json FROM tlog_leaves WHERE event_type = 'refusal' AND created_at >= ? AND created_at < ?",
                (_utc_iso(day * 86400), _utc_iso((day + 1) * 86400)),
            ).fetchall()
        counts = dict.fromkeys(registry, 0)
        for row in rows:
            code = json.loads(row["leaf_json"])["payload"]["reason_code"]
            counts[code] = counts.get(code, 0) + 1
        return [{"reason_code": code, "count": counts[code]} for code in sorted(counts, key=lambda c: c.encode("ascii"))]

    def write_daily_reports(self, now: int | None = None) -> list[int]:
        """Append the daily count report of every finished UTC day that has none yet; returns their indices.

        Each is a policy-signed ``report`` ``{kind: daily, day, counts}``
        (AICS-1 section 5.3), recomputable from the refusal leaves' ``ts``.
        Days run from the day of leaf 0, zero days included.  The control
        path stays open while writes are frozen.  When the log cannot append
        the report waits for the next pass; nothing else is held up.
        """
        now = int(time.time()) if now is None else now
        today = now // 86400
        written: list[int] = []
        with self._lock:
            last = self._conn.execute("SELECT MAX(day) AS d FROM daily_reports").fetchone()["d"]
            if last is None:
                genesis = self._conn.execute("SELECT leaf_json FROM tlog_leaves WHERE leaf_index = 0").fetchone()
                if genesis is None:
                    return written
                last = int(json.loads(genesis["leaf_json"])["ts"]) // 86400 - 1
            for day in range(last + 1, min(today, last + 1 + self.DAILY_REPORTS_PER_PASS)):
                ts = int(time.time())
                statement = {
                    "kind": "daily",
                    "day": day,
                    "counts": self.refusal_counts(day, index=self._log.tree.size, ts=ts),
                }
                try:
                    with self._transaction():
                        leaf = self._append_policy_leaf("report", statement, ts=ts)
                        self._conn.execute(
                            "INSERT INTO daily_reports (day, leaf_index) VALUES (?, ?)", (day, leaf["leaf_index"])
                        )
                except (LogUnavailable, LogIntegrityError) as exc:
                    _say(f"daily count report for day {day} not written ({type(exc).__name__}); the next pass retries")
                    break
                written.append(leaf["leaf_index"])
        return written

    def create_contribution_intent(self, ctx: SignedContext, network: Any, amount: Any) -> dict[str, Any]:
        """``POST /v2/sup/contributions/intents`` (AICS-1 section 20.6, step 1): the exact units to send.  No leaf, ever.

        Signed by the current key of the account (a key-tier name) to be
        credited.  ``network`` is one the card credits (:meth:`contribution_networks`)
        and ``amount`` the whole SUP to credit, at least 1.  The answer is
        exactly ``{intent_id, network, asset, address, units, amount, expires,
        claim_until}``: ``intent_id`` is ``U64`` of 16 random bytes; ``units =
        amount * units_per_sup + offset`` base units with ``0 < offset <
        units_per_sup``, unique among the network's claimable intents, so the
        credited amount never repeats the exact transfer; the transfer is made
        before ``expires`` and claimed before ``claim_until``.  A failed intent
        is answered with an error and no entry: an intent changes no logged
        state, and logging it would publish an intention to contribute.
        """
        offered = {n["network"]: n for n in self.contribution_networks()}
        if not isinstance(network, str) or network not in offered:
            raise ServiceError(
                "not_offered", f"contributions are credited from {', '.join(offered) or 'no network'} here", status=422
            )
        described = offered[network]
        units_per_sup = described["units_per_sup"]
        ceiling = min(SUP_MAX_AMOUNT, pay.MAX_CONTRIBUTION_USDC * self.payments.sup_per_usdc)
        if not _is_uint(amount, ceiling) or amount < 1:
            raise ServiceError("malformed", f"amount is the whole SUP to credit, from 1 to {ceiling}", status=422)
        with self._lock:
            actor = self._agent_actor(ctx, log_refusal=False)
            now = ctx.t or int(time.time())
            with self._transaction():
                self._purge_contribution_records(now)
            open_count = self._conn.execute(
                "SELECT COUNT(*) FROM sup_intents WHERE name_norm = ? AND expires_at > ?", (actor["name"], now)
            ).fetchone()[0]
            if open_count >= INTENT_MAX_OPEN:
                raise ServiceError(
                    "too_many_intents", f"at most {INTENT_MAX_OPEN} open contribution intents per name", status=429
                )
            intent_id = keys.b64u_encode(secrets.token_bytes(16))
            for _ in range(64):
                units = amount * units_per_sup + 1 + secrets.randbelow(units_per_sup - 1)
                try:
                    with self._transaction():
                        self._conn.execute(
                            """
                            INSERT INTO sup_intents (
                                intent_id, name_norm, network, asset, address, units, amount, created_at, expires_at,
                                claim_until
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                intent_id,
                                actor["name"],
                                network,
                                described["asset"],
                                described["address"],
                                units,
                                amount,
                                now,
                                now + INTENT_TTL_SECONDS,
                                now + INTENT_CLAIM_SECONDS,
                            ),
                        )
                    break
                except sqlite3.IntegrityError:
                    continue
            else:
                raise ServiceError("busy", "no unique amount is free right now; try again shortly", 503)
            return {
                "intent_id": intent_id,
                "network": network,
                "asset": described["asset"],
                "address": described["address"],
                "units": units,
                "amount": amount,
                "expires": now + INTENT_TTL_SECONDS,
                "claim_until": now + INTENT_CLAIM_SECONDS,
            }

    @_signed_write
    def claim_contribution(self, ctx: SignedContext, intent_id: Any, tx_hash: Any) -> dict[str, Any]:
        """``POST /v2/sup/contributions`` (AICS-1 section 20.6, step 2): credit an intent once the chain confirms it.

        The service reads the transaction from the chain and fails closed: an
        unreachable chain or a transaction not yet final writes nothing.  A
        final transaction that transfers exactly the intent's units of the
        asset to the address, with a block time from 120 s before the intent
        to 120 s after ``expires``, makes the policy key append ``{source:
        "contribution", account_kid, contribution_hash, asset_hash, amount}``
        (``amount`` the intent's, ``account_kid`` the requester's current key,
        ``contribution_hash`` the keyed HMAC of :meth:`_contribution_hash`);
        the intent is deleted.  Otherwise a refusal: ``payment_not_verified``,
        ``intent_expired``, ``already_credited`` (citing the credit),
        ``bad_reference`` (no such intent, or not the requester's),
        ``not_offered``.  The refusal names the request by the keyed HMAC of
        its content (*ctx* comes from the claim's dependency), never its plain
        hash; the transaction identifier and the units stay off-leaf and are
        deleted ``record_seconds`` after the credit.
        """
        _require(isinstance(intent_id, str) and isinstance(tx_hash, str), "a claim names an intent_id and a tx_hash")
        with self._lock:
            actor = self._agent_actor(ctx)
            intent = self._conn.execute("SELECT * FROM sup_intents WHERE intent_id = ?", (intent_id,)).fetchone()
            if intent is None:
                credited = self._conn.execute(
                    "SELECT credit_index FROM sup_contributions WHERE intent_id = ?", (intent_id,)
                ).fetchone()
                if credited is not None:
                    raise Rejected("already_credited", "this intent was credited already", conflict_index=credited["credit_index"])
                raise Rejected("bad_reference", "no contribution intent has that id")
            if intent["name_norm"] != actor["name"]:
                raise Rejected("bad_reference", "this contribution intent is not the signer's")
            network = intent["network"]
            if network not in {n["network"] for n in self.contribution_networks()}:
                raise Rejected("not_offered", f"{network} contributions are not credited here any more")
            if ctx.t > intent["claim_until"]:
                raise Rejected("intent_expired", f"this intent's claim window ended at {intent['claim_until']}")
            canonical = pay.normalize_tx_hash(network, tx_hash)
            contribution_hash = self._contribution_hash(network, canonical)
            credited = self._conn.execute(
                "SELECT credit_index FROM sup_contributions WHERE contribution_hash = ?", (contribution_hash,)
            ).fetchone()
            if credited is not None:
                raise Rejected(
                    "already_credited", "this transaction was credited already", conflict_index=credited["credit_index"]
                )
            verifier = self.payments.verifier(network)
            intent = dict(intent)
        # The chain is read outside the lock (network I/O); nothing is credited unless it all checks.
        transfer = verifier.verify(canonical)
        if transfer.recipient != intent["address"]:
            raise pay.PaymentNotVerified("the transfer is not to the address this intent named")
        if transfer.amount != intent["units"]:
            raise pay.PaymentNotVerified(
                f"the transfer is {transfer.amount} base units; this intent credits exactly {intent['units']} "
                "(other units are an anonymous contribution)"
            )
        if not intent["created_at"] - INTENT_CLOCK_SKEW <= transfer.block_time <= intent["expires_at"] + INTENT_CLOCK_SKEW:
            raise pay.PaymentNotVerified("the transfer was not made while this intent was open")
        with self._lock:
            if self._conn.execute("SELECT 1 FROM sup_intents WHERE intent_id = ?", (intent_id,)).fetchone() is None:
                credited = self._conn.execute(
                    "SELECT credit_index FROM sup_contributions WHERE intent_id = ?", (intent_id,)
                ).fetchone()
                raise Rejected(
                    "already_credited",
                    "this intent was credited meanwhile",
                    conflict_index=credited["credit_index"] if credited is not None else None,
                )
            credited = self._conn.execute(
                "SELECT credit_index FROM sup_contributions WHERE contribution_hash = ?", (contribution_hash,)
            ).fetchone()
            if credited is not None:
                raise Rejected(
                    "already_credited", "this transaction was credited meanwhile", conflict_index=credited["credit_index"]
                )
            account = self._actor_from_name(intent["name_norm"])
            if account is None or account["revoked"] or not account["kid"]:
                raise Rejected(
                    "revoked",
                    "the intent's name was revoked; it receives nothing",
                    conflict_index=account["revoked_index"] if account is not None else None,
                )
            statement = {
                "source": "contribution",
                "account_kid": account["kid"],
                "contribution_hash": contribution_hash,
                "asset_hash": self.sup_asset_hash,
                "amount": intent["amount"],
            }
            now = int(time.time())
            with self._transaction():
                leaf = self._append_policy_leaf("sup.credit", statement, ts=now)
                self._ledger_entry(leaf, account["name"], intent["amount"], "contribution")
                self._conn.execute(
                    """
                    INSERT INTO sup_contributions (contribution_hash, credit_index, intent_id, name_norm, network, tx_hash,
                        units, sup_amount, credited_at, delete_after)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        contribution_hash,
                        leaf["leaf_index"],
                        intent_id,
                        account["name"],
                        network,
                        canonical,
                        transfer.amount,
                        intent["amount"],
                        now,
                        now + CONTRIBUTION_TX_RETENTION_SECONDS,
                    ),
                )
                self._conn.execute("DELETE FROM sup_intents WHERE intent_id = ?", (intent_id,))
                self._purge_contribution_records(now)
            self.increment_counter("sup_contributions_credited", 1)
            return {
                "credit": {
                    "credit_index": leaf["leaf_index"],
                    "name": account["name"],
                    "amount": intent["amount"],
                    "contribution_hash": contribution_hash,
                },
                "balance": self._balance(account["name"]),
                **self._written(leaf),
            }

    # ------------------------------------------------------------------
    # policy leaves (owner login): prospective changes with published notice
    # ------------------------------------------------------------------

    def publish_policy(
        self,
        kind: str,
        document: str,
        not_before: int,
        effective_after: int | None = None,
        order_hash: str | None = None,
    ) -> dict[str, Any]:
        """A ``policy`` leaf (AICS-1 sections 5.3 and 6.4) naming an off-leaf document by hash.

        ``{kind, document_hash, size, prev_policy_index, effective_after,
        not_before, log_kid, policy_kid, owner_kid, log_sig: null}`` keeps the
        pinned service keys.  A ``card`` document must be exactly ``J(card)`` of
        a section 13.1 card signed by the policy key that names this server's
        state (:func:`aics_server.card.check_card_document`), for every profile.  A ``change`` (charter, terms, lists) or a later
        ``card`` takes effect no sooner than the published notice period after
        it is logged (``not_before``), unless an order requires sooner: then
        ``order_hash`` names the order and the document must cite that hash.
        The first card may take effect at once.  The policy applies to
        indices after ``effective_after`` (default: its own index).
        """
        if kind not in POLICY_KINDS:
            raise ValueError(f"kind must be one of {', '.join(POLICY_KINDS)} (leaf 0 alone is the charter)")
        if not isinstance(document, str) or not document.strip():
            raise ValueError("a policy leaf publishes a document")
        data = document.encode("utf-8")
        if len(data) > MAX_POLICY_DOCUMENT_BYTES:
            raise ValueError(f"the document is over {MAX_POLICY_DOCUMENT_BYTES} bytes")
        self._uint(not_before, "not_before")
        if order_hash is not None:
            if not (isinstance(order_hash, str) and _HEX64.fullmatch(order_hash)):
                raise ValueError("order_hash must be 64 lowercase hex characters or null")
            if order_hash not in document:
                raise ValueError("a policy that takes effect early under an order cites the order's hash in its document")
        with self._lock:
            now = int(time.time())
            own_index = self._log.tree.size
            prev = self._conn.execute("SELECT MAX(leaf_index) AS i FROM tlog_leaves WHERE event_type = 'policy'").fetchone()["i"]
            if kind == "card":
                # Every card, whatever its profile, is exactly J(card) of a signed AICS-1 section 13.1 card this
                # server follows (AICS-1 sections 13.1, 13.2 and 14.5): the first one's hash becomes the trust
                # bundle's bootstrap_card_hash, so a card that is not one would be permanent.
                from .card import CardError, check_card_document

                try:
                    check_card_document(data, self, parent_index=prev)
                except CardError as exc:
                    raise ValueError(str(exc)) from None
            self.swarms.validate_policy(kind, document, not_before)
            first_card = kind == "card" and not self._conn.execute(
                "SELECT 1 FROM policy_documents WHERE kind = 'card'"
            ).fetchone()
            if not_before < now:
                raise ValueError("not_before must not lie in the past")
            if not first_card and order_hash is None and not_before < now + POLICY_NOTICE_SECONDS:
                raise ValueError(
                    f"a policy change takes effect at least {POLICY_NOTICE_SECONDS // 86400} days after it is logged "
                    "(not_before); an order that requires sooner is cited by order_hash"
                )
            if effective_after is None:
                effective_after = own_index
            elif self._uint(effective_after, "effective_after") < own_index:
                raise ValueError(f"effective_after must be at least this leaf's own index ({own_index})")
            statement = {
                "kind": kind,
                "document_hash": _sha256(data),
                "size": len(data),
                "prev_policy_index": prev,
                "effective_after": effective_after,
                "not_before": not_before,
                "log_kid": self.server_kid,
                "policy_kid": self.policy_kid,
                "owner_kid": self.owner_kid,
                "log_sig": None,
            }
            with self._transaction():
                leaf = self._append_policy_leaf("policy", statement, ts=now)
                if leaf["leaf_index"] != own_index:
                    raise LogIntegrityError("a policy leaf landed at another index than the one it names")
                self._conn.execute(
                    "INSERT INTO policy_documents (leaf_index, kind, document_sha256, size, document) VALUES (?, ?, ?, ?, ?)",
                    (leaf["leaf_index"], kind, statement["document_hash"], len(data), data),
                )
            return {"policy": self._policy_view(leaf["leaf_index"]), **self._written(leaf)}

    def _policy_view(self, leaf_index: int) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT leaf_json, leaf_hash_hex FROM tlog_leaves WHERE leaf_index = ? AND event_type = 'policy'",
            (leaf_index,),
        ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["leaf_json"])["payload"]
        return {
            "leaf_index": leaf_index,
            "leaf_hash_hex": row["leaf_hash_hex"],
            **{
                k: payload.get(k)
                for k in ("kind", "document_hash", "size", "prev_policy_index", "effective_after", "not_before")
            },
        }

    def list_policies(self) -> dict[str, Any]:
        """Every policy leaf in log order (leaf 0, the charter, first)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT leaf_index FROM tlog_leaves WHERE event_type = 'policy' ORDER BY leaf_index ASC"
            ).fetchall()
            return {
                "count": len(rows),
                "policies": [self._policy_view(r["leaf_index"]) for r in rows],
                "notice_seconds": POLICY_NOTICE_SECONDS,
                "tree_size": self._log.tree.size,
            }

    def policy_document(self, leaf_index: int) -> dict[str, Any] | None:
        """A document the policy key published, with its view, or ``None``.

        A ``policy`` leaf's document, or the report an ``audit`` report or a
        ``freeze`` leaf names by ``report_hash`` (AICS-1 section 5.3): the
        exact bytes, whose SHA-256 the leaf carries.
        """
        with self._lock:
            doc = self._conn.execute(
                "SELECT kind, document FROM policy_documents WHERE leaf_index = ?", (leaf_index,)
            ).fetchone()
            if doc is None:
                return None
            view = self._policy_view(leaf_index)
            if view is None:
                kind = {"audit_report": "audit", "freeze_report": "freeze"}.get(doc["kind"])
                row = self._conn.execute(
                    "SELECT leaf_json, leaf_hash_hex FROM tlog_leaves WHERE leaf_index = ?", (leaf_index,)
                ).fetchone()
                if kind is None or row is None:
                    return None
                payload = json.loads(row["leaf_json"])["payload"]
                view = {
                    "leaf_index": leaf_index,
                    "leaf_hash_hex": row["leaf_hash_hex"],
                    "kind": kind,
                    "document_hash": payload["report_hash"],
                    "size": len(bytes(doc["document"])),
                }
            return {**view, "document": bytes(doc["document"])}

    # ------------------------------------------------------------------
    # tombstones, suspensions, freeze (DESIGN.md section 4.2 item 10, section 8)
    #
    # Each is a policy-signed leaf, written at the owner's signed request (owner
    # login) or, for a flood suspension, by the published limits.  None of them
    # removes, edits or reorders a leaf.
    # ------------------------------------------------------------------

    def _retention_policy_index(self, index: int, ts: int) -> int:
        """The policy event whose retention rule governs a body accepted at *index* (AICS-1 sections 6.4 and 8.2).

        The card in force there (the latest ``policy`` leaf of kind ``card``
        below *index* with ``effective_after`` below it and ``not_before`` at
        or before *ts*), else the charter, leaf 0: the policy at acceptance
        governs a body and is never shortened afterwards.
        """
        rows = self._conn.execute(
            "SELECT leaf_index, leaf_json FROM tlog_leaves WHERE event_type = 'policy' AND leaf_index < ? "
            "ORDER BY leaf_index DESC",
            (index,),
        ).fetchall()
        for row in rows:
            q = json.loads(row["leaf_json"])["payload"]
            if q.get("kind") == "card" and q.get("effective_after", 0) < index and q.get("not_before", 0) <= ts:
                return row["leaf_index"]
        return 0

    def entry_body(self, index: int, entry: Mapping[str, Any] | None = None) -> "EntryBody":
        """The off-leaf body of leaf *index* and its state (AICS-1 sections 8.2, 10.3, 12.1 and 14.3).

        One lookup for every binding: ``GET /v2/entries/{index}`` (the
        bundle's ``body_or_ct`` and its ``X-AICS-Body-Status`` header), ``GET
        /v2/bodies/{hash}`` and the gate's ``read`` and ``fetch``.  Stored ciphertext is public by
        design (section 8.2): only the recipient's key opens it.
        """
        with self._lock:
            if entry is None:
                row = self._conn.execute("SELECT leaf_json FROM tlog_leaves WHERE leaf_index = ?", (index,)).fetchone()
                if row is None:
                    return EntryBody.NONE
                entry = json.loads(row["leaf_json"])
            entry_type, q = entry["type"], entry["payload"]
            if entry_type in SWARM_TYPES:
                return self.swarms.entry_body(index, entry)
            kind, digest, data, present = "public", None, None, False
            if entry_type in ("policy", "freeze") or (entry_type == "report" and q.get("kind") == "audit"):
                doc = self._conn.execute("SELECT document FROM policy_documents WHERE leaf_index = ?", (index,)).fetchone()
                digest = q.get("document_hash") if entry_type == "policy" else q.get("report_hash")
                kind, present = "document", doc is not None
                data = bytes(doc["document"]) if doc is not None else None
            elif entry_type in ("post", "poll", "sup.task") or (entry_type == "vote" and q.get("body_hash") is not None):
                table, column = {
                    "post": ("agora_posts", "post_index"),
                    "poll": ("agora_polls", "poll_index"),
                    "vote": ("agora_poll_votes", "vote_index"),
                    "sup.task": ("sup_tasks", "task_index"),
                }[entry_type]
                row = self._conn.execute(f"SELECT body FROM {table} WHERE {column} = ?", (index,)).fetchone()
                digest, present = q.get("body_hash"), row is not None
                data = bytes(row["body"]) if row is not None and row["body"] is not None else None
            elif entry_type == "report" and q.get("kind") == "owner_action" and q.get("action") == "complete":
                row = self._conn.execute(
                    "SELECT completion_body FROM owner_actions WHERE complete_index = ?", (index,)
                ).fetchone()
                digest, present = q.get("result_hash"), row is not None
                data = bytes(row["completion_body"]) if row is not None and row["completion_body"] is not None else None
            elif entry_type == "dm":
                row = self._conn.execute(
                    "SELECT ciphertext, expired_policy_index FROM messages WHERE leaf_index = ?", (index,)
                ).fetchone()
                kind, digest, present = "ciphertext", q.get("ct_hash"), row is not None
                if row is not None and row["ciphertext"] is None and row["expired_policy_index"] is not None:
                    if self._tombstone_of(index) is None:
                        return EntryBody(kind, digest, "expired", None, None, None, row["expired_policy_index"], True)
                data = bytes(row["ciphertext"]) if row is not None and row["ciphertext"] is not None else None
            elif entry_type == "capsule":
                row = self._conn.execute("SELECT * FROM capsule_leaves WHERE leaf_index = ?", (index,)).fetchone()
                kind, digest, present = "ciphertext", q.get("ct_hash"), row is not None
                if row is not None:
                    hidden = self._tombstone_of(index)
                    if hidden is None and self._capsule_body_state(row) == "expired":
                        return EntryBody(
                            kind, digest, "expired", None, None, None,
                            self._retention_policy_index(index, int(entry["ts"])), in_bundle=True,
                        )
                    data = bytes(row["ciphertext"]) if row["ciphertext"] is not None else None
            else:
                return EntryBody.NONE
            # body_or_ct of a section 14.3 bundle binds bodies named by body_hash, ct_hash or document_hash with a
            # size; a completion (result_hash) and a freeze or audit report (report_hash) are served by hash only.
            in_bundle = any(q.get(name) is not None for name in ("body_hash", "ct_hash", "document_hash")) and "size" in q
            hidden = self._tombstone_of(index)
            if hidden is not None:
                return EntryBody(
                    kind, digest, "tombstoned", None, hidden["tombstone_index"], hidden["reason_code"], None,
                    in_bundle=in_bundle,
                )
            if not present or data is None:
                # Neither a tombstone nor a retention rule explains a missing body: an availability failure
                # (AICS-1 section 8.2), reported as such, never as an invented expiry.
                return EntryBody(kind, digest, "unavailable", None, None, None, None, in_bundle=in_bundle)
            return EntryBody(kind, digest, "available", data, None, None, None, in_bundle=in_bundle)

    def body_by_hash(self, digest: str) -> "EntryBody | None":
        """``GET /v2/bodies/{hash}``: the exact bytes some entry names by *digest*, or the state of the latest one.

        Bodies are stored per entry; the first entry (in log order) whose
        body is available supplies the bytes.  Otherwise the latest entry
        naming the digest gives the state (tombstoned, expired).  ``None``:
        no entry names a body by this digest (absence proves nothing).
        """
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            return None
        with self._lock:
            queries = (
                "SELECT post_index AS i FROM agora_posts WHERE body_hash = ?",
                "SELECT poll_index AS i FROM agora_polls WHERE body_hash = ?",
                "SELECT vote_index AS i FROM agora_poll_votes WHERE body_hash = ?",
                "SELECT task_index AS i FROM sup_tasks WHERE body_hash = ?",
                "SELECT complete_index AS i FROM owner_actions WHERE result_hash = ? AND complete_index IS NOT NULL",
                "SELECT leaf_index AS i FROM messages WHERE ct_hash = ?",
                "SELECT leaf_index AS i FROM capsule_leaves WHERE ct_hash = ?",
                "SELECT leaf_index AS i FROM policy_documents WHERE document_sha256 = ?",
            )
            indices = sorted({row["i"] for sql in queries for row in self._conn.execute(sql, (digest,)).fetchall()})
            indices = sorted(set(indices) | set(self.swarms.body_indices(digest)))
            found: EntryBody | None = None
            for index in indices:
                body = self.entry_body(index)
                if body.digest != digest:
                    continue
                if body.state == "available":
                    return body
                found = body
            return found

    def name_of_unverified(self, unverified_id: str) -> str | None:
        """The name an unverified identity holds, or ``None``."""
        with self._lock:
            row = self._conn.execute("SELECT name_norm FROM names WHERE unverified_id = ?", (unverified_id,)).fetchone()
            return row["name_norm"] if row else None

    def _tombstone_of(self, leaf_index: int) -> dict[str, Any] | None:
        """``{tombstone_index, reason_code}`` when a tombstone hides the body of *leaf_index*."""
        row = self._conn.execute(
            "SELECT tombstone_index, reason_code FROM tombstones WHERE target_index = ?", (leaf_index,)
        ).fetchone()
        return {"tombstone_index": row["tombstone_index"], "reason_code": row["reason_code"]} if row else None

    def _has_body(self, entry_type: str, payload: Mapping[str, Any], index: int) -> bool:
        """Whether the leaf at *index* has an off-leaf body a tombstone could hide."""
        if entry_type == "swarm.propose":
            return payload.get("kind") == "name"
        if entry_type == "vote":
            return payload.get("body_hash") is not None  # a vote's body is its optional {reason}
        if entry_type == "report":
            # Only an owner-action completion has an off-leaf body (its completion text).
            return payload.get("kind") == "owner_action" and payload.get("action") == "complete"
        return entry_type in TOMBSTONE_TARGETS

    @staticmethod
    def _check_evidence_hash(evidence_hash: Any) -> None:
        if evidence_hash is not None and not (isinstance(evidence_hash, str) and _HEX64.fullmatch(evidence_hash)):
            raise ValueError("evidence_hash must be 64 lowercase hex characters or null")

    def tombstone(self, target_index: int, reason_code: str, evidence_hash: str | None = None) -> dict[str, Any]:
        """A ``tombstone`` leaf ``{target_index, reason_code, evidence_hash, receipt_hash}``: hide one body, keep its leaf.

        Only leaves with an off-leaf body qualify (:data:`TOMBSTONE_TARGETS`);
        a ciphertext body (``dm``, ``capsule``) only under ``order``.  The
        target leaf, its bytes and its proofs are untouched: readers get the
        tombstone index and reason where the body was.  ``receipt_hash`` names
        the receipt the target was given, a promise no tombstone cancels
        (AICS-1 sections 5.3 and 10.1).  For ``erasure`` and ``secret_format``
        the body is deleted in the tombstone's own commit, before its receipt
        is returned (AICS-1 section 10.3); for ``illegal_on_notice`` and
        ``order`` it is no longer served from that commit, kept inaccessible
        for :data:`HIDDEN_BODY_RETENTION_SECONDS` and then deleted by
        :meth:`housekeeping`.
        """
        if reason_code not in TOMBSTONE_REASONS:
            raise ValueError(f"reason_code must be one of {', '.join(TOMBSTONE_REASONS)}")
        self._check_evidence_hash(evidence_hash)
        self._int_index(target_index, "target_index")
        with self._lock:
            if target_index >= self._log.tree.size:
                raise NotFound(f"leaf {target_index} does not exist")
            row = self._conn.execute(
                "SELECT event_type, leaf_json FROM tlog_leaves WHERE leaf_index = ?", (target_index,)
            ).fetchone()
            target_type = row["event_type"]
            payload = json.loads(row["leaf_json"])["payload"]
            allowed = TOMBSTONE_TARGETS.get(target_type)
            if allowed is None or not self._has_body(target_type, payload, target_index):
                raise ValueError(f"leaf {target_index} ({target_type}) has no off-leaf body to hide")
            if reason_code not in allowed:
                raise ValueError(f"the body of a {target_type} leaf is hidden only for: {', '.join(allowed)}")
            existing = self._tombstone_of(target_index)
            if existing is not None:
                raise RuntimeError(
                    f"the body of leaf {target_index} is already hidden by tombstone {existing['tombstone_index']}"
                )
            statement = {
                "target_index": target_index,
                "reason_code": reason_code,
                "evidence_hash": evidence_hash,
                "receipt_hash": self._receipt_hash_of(target_index),
            }
            with self._transaction():
                leaf = self._append_policy_leaf("tombstone", statement)
                erase_now = reason_code in ERASED_AT_ONCE
                self._conn.execute(
                    """
                    INSERT INTO tombstones (target_index, tombstone_index, reason_code, target_type, erased_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (target_index, leaf["leaf_index"], reason_code, target_type, leaf["entry"]["ts"] if erase_now else None),
                )
                if erase_now:
                    self._erase_body(target_index, target_type)
            return {
                "tombstone": {
                    "tombstone_index": leaf["leaf_index"],
                    "target_index": target_index,
                    "target_type": target_type,
                    "reason_code": reason_code,
                    "evidence_hash": evidence_hash,
                },
                **self._written(leaf),
            }

    def _erase_body(self, target_index: int, target_type: str) -> None:
        """Delete the off-leaf body of a tombstoned leaf (its leaf stays).

        At once for ``erasure`` and ``secret_format``; after
        :data:`HIDDEN_BODY_RETENTION_SECONDS` for ``illegal_on_notice`` and
        ``order`` (:meth:`_erase_expired_hidden_bodies`).  The exact body bytes
        and what they say go; hashes and sizes, which the leaf carries anyway,
        stay.  Ciphertext (a ``dm``, or the capsule leaf's own body, current
        or superseded) is set to NULL.
        """
        if target_type in SWARM_TYPES:
            return self.swarms.erase_body(target_index, target_type)
        if target_type == "post":
            self._conn.execute(
                "UPDATE agora_posts SET title = NULL, text = '', body = NULL WHERE post_index = ?", (target_index,)
            )
        elif target_type == "poll":
            row = self._conn.execute("SELECT option_count FROM agora_polls WHERE poll_index = ?", (target_index,)).fetchone()
            if row is not None:
                self._conn.execute(
                    "UPDATE agora_polls SET title = '', text = '', options_json = ?, body = NULL WHERE poll_index = ?",
                    (json.dumps([""] * row["option_count"]), target_index),
                )
        elif target_type == "vote":
            self._conn.execute("UPDATE agora_poll_votes SET reason = NULL, body = NULL WHERE vote_index = ?", (target_index,))
        elif target_type == "report":
            self._conn.execute(
                "UPDATE owner_actions SET completion_text = '', completion_body = NULL WHERE complete_index = ?",
                (target_index,),
            )
        elif target_type == "sup.task":
            self._conn.execute(
                "UPDATE sup_tasks SET title = '', text = '', body = NULL WHERE task_index = ?", (target_index,)
            )
        elif target_type == "dm":
            self._conn.execute("UPDATE messages SET ciphertext = NULL WHERE leaf_index = ?", (target_index,))
        elif target_type == "capsule":
            self._conn.execute("UPDATE capsule_leaves SET ciphertext = NULL WHERE leaf_index = ?", (target_index,))

    def _erase_expired_hidden_bodies(self, now: int) -> int:
        """Retention: delete the bodies hidden for ``illegal_on_notice`` or ``order`` once their tombstone is
        :data:`HIDDEN_BODY_RETENTION_SECONDS` old (by the tombstone leaf's ``ts``).  Returns how many."""
        cutoff = _utc_iso(now - HIDDEN_BODY_RETENTION_SECONDS)
        rows = self._conn.execute(
            """
            SELECT t.target_index, t.target_type FROM tombstones t
            JOIN tlog_leaves l ON l.leaf_index = t.tombstone_index
            WHERE t.erased_at IS NULL AND t.reason_code IN ('illegal_on_notice', 'order') AND l.created_at <= ?
            """,
            (cutoff,),
        ).fetchall()
        for row in rows:
            self._erase_body(row["target_index"], row["target_type"])
            self._conn.execute("UPDATE tombstones SET erased_at = ? WHERE target_index = ?", (now, row["target_index"]))
        return len(rows)

    def list_tombstones(self, since: int = 0, limit: int = 100) -> dict[str, Any]:
        """Tombstone leaves at index ``since`` or later, in log order."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM tombstones WHERE tombstone_index >= ? ORDER BY tombstone_index ASC LIMIT ?",
                (since, limit),
            ).fetchall()
            return {
                "count": len(rows),
                "tombstones": [
                    {
                        "tombstone_index": r["tombstone_index"],
                        "target_index": r["target_index"],
                        "target_type": r["target_type"],
                        "reason_code": r["reason_code"],
                    }
                    for r in rows
                ],
                "tree_size": self._log.tree.size,
            }

    def suspend(
        self, target_kid: str, reason_code: str, until: int | None = None, evidence_hash: str | None = None
    ) -> dict[str, Any]:
        """A ``suspension`` leaf ``{target_kid, reason_code, until, evidence_hash}``: the key's writes stop.

        Reasons are ``order`` and ``flood`` only, never content.  By hand the
        owner writes ``order`` suspensions (``until`` null: until ended).  A
        ``flood`` suspension is written only by the published limits, with the
        published duration.  ``until`` at or before now ends the suspension in
        force, repeating its reason and its ``evidence_hash`` (AICS-1 section
        10.3).  The target is a key bound to a name, an unverified identity,
        or a key or identity introduced under the swarms profile.  Reads,
        proofs and verification are never suspended.
        """
        if reason_code not in SUSPENSION_REASONS:
            raise ValueError(f"reason_code must be one of {', '.join(SUSPENSION_REASONS)}")
        self._check_evidence_hash(evidence_hash)
        if until is not None and (not isinstance(until, int) or isinstance(until, bool) or not 0 <= until <= MAX_TIME):
            raise ValueError("until must be a unix time or null")
        with self._lock:
            known = (
                self._conn.execute("SELECT 1 FROM bound_keys WHERE kid = ?", (target_kid,)).fetchone()
                or self._conn.execute("SELECT 1 FROM names WHERE unverified_id = ?", (target_kid,)).fetchone()
                # An introduced key or identity of the swarms profile writes without a name (AICS-1 section 19):
                # an order naming it must be met by suspending that key, not by freezing the service.
                or self.swarms.member_for(target_kid)
            )
            if not known:
                raise NotFound(f"no agent key or unverified identity {target_kid!r}")
            now = int(time.time())
            active = self._active_suspension(target_kid)
            if until is not None and until <= now:
                if active is None:
                    raise RuntimeError("this key has no suspension in force to end")
                # AICS-1 section 10.3: the ending event uses the same permitted reason and the same evidence.
                if active["reason_code"] != reason_code:
                    raise ValueError(f"an ending suspension repeats the reason it ends ({active['reason_code']})")
                if active["evidence_hash"] != evidence_hash:
                    raise ValueError(
                        "an ending suspension repeats the evidence_hash of the suspension it ends "
                        f"({active['evidence_hash'] or 'null'})"
                    )
                until = now
            elif reason_code == "flood":
                raise ValueError("flood suspensions are written by the published limits, with the published duration")
            statement = {
                "target_kid": target_kid,
                "reason_code": reason_code,
                "until": until,
                "evidence_hash": evidence_hash,
            }
            with self._transaction():
                leaf = self._append_policy_leaf("suspension", statement, ts=now)
                self._conn.execute(
                    """
                    INSERT INTO suspensions (suspension_index, target_kid, reason_code, until, evidence_hash)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (leaf["leaf_index"], target_kid, reason_code, until, evidence_hash),
                )
            return {"suspension": self.suspension_view(target_kid), **self._written(leaf)}

    def suspension_view(self, kid: str) -> dict[str, Any] | None:
        """The latest suspension leaf naming *kid* and whether it is in force, or ``None``."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM suspensions WHERE target_kid = ? ORDER BY suspension_index DESC LIMIT 1", (kid,)
            ).fetchone()
            if row is None:
                return None
            return {
                "suspension_index": row["suspension_index"],
                "target_kid": kid,
                "reason_code": row["reason_code"],
                "until": row["until"],
                "evidence_hash": row["evidence_hash"],
                "active": self._active_suspension(kid) is not None,
            }

    def set_freeze(self, state: str, reason_code: str, report: str) -> dict[str, Any]:
        """A ``freeze`` leaf ``{state, reason_code, report_hash, prev_freeze_index}``.

        ``frozen`` stops agent writes (each refused ``frozen``) and, under the
        SUP-1 profile, every owner write and contribution claim (AICS-1
        section 20.9); reads, tiles, checkpoints, proofs and the administrative
        path continue.  ``open`` with reason ``resume`` ends it; a contribution
        intent whose claim window ended during the freeze stays claimable
        after reopening for as long as the freeze lasted.  The report is
        published off-leaf, named by hash (``GET /v2/freeze``).
        """
        if state not in FREEZE_STATES:
            raise ValueError(f"state must be one of {', '.join(FREEZE_STATES)}")
        if reason_code not in FREEZE_REASONS:
            raise ValueError(f"reason_code must be one of {', '.join(FREEZE_REASONS)}")
        if (state == "open") != (reason_code == "resume"):
            raise ValueError("reopening uses reason resume, and resume only reopens")
        if not isinstance(report, str) or not report.strip():
            raise ValueError("a freeze publishes a report")
        document = report.encode("utf-8")
        with self._lock:
            current = self._conn.execute("SELECT * FROM freezes ORDER BY freeze_index DESC LIMIT 1").fetchone()
            frozen = current is not None and current["state"] == "frozen"
            if state == "frozen" and frozen:
                raise RuntimeError(f"writes are already frozen by leaf {current['freeze_index']}")
            if state == "open" and not frozen:
                raise RuntimeError("writes are not frozen")
            statement = {
                "state": state,
                "reason_code": reason_code,
                "report_hash": _sha256(document),
                "prev_freeze_index": current["freeze_index"] if current else None,
            }
            with self._transaction():
                leaf = self._append_policy_leaf("freeze", statement)
                self._conn.execute(
                    "INSERT INTO freezes (freeze_index, state, reason_code, report_hash) VALUES (?, ?, ?, ?)",
                    (leaf["leaf_index"], state, reason_code, statement["report_hash"]),
                )
                self._conn.execute(
                    """
                    INSERT INTO policy_documents (leaf_index, kind, document_sha256, size, document)
                    VALUES (?, 'freeze_report', ?, ?, ?)
                    """,
                    (leaf["leaf_index"], statement["report_hash"], len(document), document),
                )
                if state == "open":
                    frozen_at = json.loads(
                        self._conn.execute(
                            "SELECT leaf_json FROM tlog_leaves WHERE leaf_index = ?", (current["freeze_index"],)
                        ).fetchone()["leaf_json"]
                    )["ts"]
                    reopened = leaf["entry"]["ts"]
                    # AICS-1 section 20.9: a claim window that ended during the freeze is extended by its length.
                    self._conn.execute(
                        "UPDATE sup_intents SET claim_until = claim_until + ? WHERE claim_until >= ? AND claim_until < ?",
                        (reopened - frozen_at, frozen_at, reopened),
                    )
            self._frozen_index = leaf["leaf_index"] if state == "frozen" else None
            return {"freeze": self.freeze_view(), **self._written(leaf)}

    def freeze_view(self) -> dict[str, Any]:
        """Whether agent writes are frozen, the freeze leaf that says so and its published report."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT f.*, d.document FROM freezes f
                LEFT JOIN policy_documents d ON d.leaf_index = f.freeze_index
                ORDER BY f.freeze_index DESC
                """
            ).fetchall()
            latest = rows[0] if rows else None
            return {
                "state": "frozen" if self._frozen_index is not None else "open",
                "freeze_index": latest["freeze_index"] if latest else None,
                "reason_code": latest["reason_code"] if latest else None,
                "report_hash": latest["report_hash"] if latest else None,
                "report": bytes(latest["document"]).decode("utf-8") if latest and latest["document"] is not None else None,
                "history": [
                    {
                        "freeze_index": r["freeze_index"],
                        "state": r["state"],
                        "reason_code": r["reason_code"],
                        "report_hash": r["report_hash"],
                    }
                    for r in rows
                ],
            }

    def limits_view(self) -> dict[str, Any]:
        """The published limits this server enforces (the assurance card will carry the same values)."""
        return {
            "limits": copy.deepcopy(self.limits),
            "per": {
                "writes": "signing key",
                "flood": "signing key",
                "registrations": "submitting key",
                "preidentity": "service (every registration attempt and every keyless request)",
                "unauthenticated": "service (logged refusals of envelopes that do not authenticate)",
                "notices": "service (POST /notice)",
                "open_notices": "service",
                "open_notice_bytes": "service",
                "ciphertext_budget_bytes": "service (stored ciphertext bodies, AICS-1 section 8.2)",
                "capsule_quota_bytes": "name",
            },
            "beyond": {
                "writes": "a rate_limit refusal leaf, logged once per key and window",
                "registrations": "a rate_limit refusal leaf, logged once per key and window",
                "preidentity": "HTTP 429 and no leaf (AICS-1 section 10.2: the exhausted pre-identity bucket)",
                "unauthenticated": "the same answer and no leaf",
                "notices": "HTTP 429 and no notice taken",
                "open_notices": "HTTP 503 with Retry-After and no notice taken",
                "open_notice_bytes": "HTTP 503 with Retry-After and no notice taken",
                "ciphertext_budget_bytes": (
                    "ciphertext bodies at least 90 days old are evicted by earliest (ts, index); if that is not enough, "
                    "the 90-day minimum is kept and resource exhaustion is reported (resource_exhaustion here and at "
                    "/healthz)"
                ),
            },
            "resource_exhaustion": self.resource_exhaustion(),
            "notice_register": {
                **self.notice_register(),
                "max_open": self.limits["open_notices"],
                "max_bytes": self.limits["open_notice_bytes"],
                "field_bytes": dict(NOTICE_FIELD_BYTES),
            },
            "quota_applies_to": "capsule storage only; never registering, posting, messaging, voting or a balance",
            "policy_notice_seconds": POLICY_NOTICE_SECONDS,
            "encryption_schemes": list(ENCRYPTION_SCHEMES),
            "refusal_codes": list(REFUSAL_REASONS) + list(SUP_REFUSAL_REASONS) + [f"{SECRET_FORMAT_PREFIX}<pattern id>"],
            "refusal_registry": list(self.active_refusal_codes()),
            "tombstone_codes": list(TOMBSTONE_REASONS),
            "suspension_codes": list(SUSPENSION_REASONS),
            "freeze_codes": list(FREEZE_REASONS),
            "grant_max_messages": GRANT_MAX_MESSAGES,
        }

    # ------------------------------------------------------------------
    # recent actors ("agents online now", DESIGN.md section 9)
    # ------------------------------------------------------------------

    def recent_actors(self, since: int, limit: int = 100) -> dict[str, Any]:
        """Agents whose own leaves have ``ts >= since``, newest first, from the public leaf table only.

        A leaf's actor is the key that signed it, or the unverified identity
        whose post the policy key attests; the service's log, policy and owner
        keys are left out, so refusals, notices and administrative leaves count
        for nobody.  Every value here can be recomputed from the tiles.
        """
        service = (self.server_kid, self.policy_kid, self.owner_kid or "")
        since_iso = _utc_iso(since)
        with self._lock:
            count = self._conn.execute(
                "SELECT COUNT(DISTINCT actor_kid) FROM tlog_leaves WHERE created_at >= ? AND actor_kid NOT IN (?, ?, ?)",
                (since_iso, *service),
            ).fetchone()[0]
            rows = self._conn.execute(
                """
                SELECT l.actor_kid, l.leaf_index, l.event_type, l.created_at, g.leaves
                FROM (
                    SELECT actor_kid, MAX(leaf_index) AS last_index, COUNT(*) AS leaves FROM tlog_leaves
                    WHERE created_at >= ? AND actor_kid NOT IN (?, ?, ?) GROUP BY actor_kid
                ) g JOIN tlog_leaves l ON l.leaf_index = g.last_index
                ORDER BY l.leaf_index DESC LIMIT ?
                """,
                (since_iso, *service, limit),
            ).fetchall()
            agents = []
            for r in rows:
                kid = r["actor_kid"]
                bound = self._conn.execute("SELECT name_norm FROM bound_keys WHERE kid = ?", (kid,)).fetchone()
                if bound is None:
                    bound = self._conn.execute("SELECT name_norm FROM names WHERE unverified_id = ?", (kid,)).fetchone()
                actor = self._actor_from_name(bound["name_norm"]) if bound is not None else None
                agents.append(
                    {
                        "name": actor["name"] if actor else None,
                        "ans_address": actor["ans_address"] if actor else None,
                        "tier": actor["tier"] if actor else None,
                        "actor_kid": kid,
                        "last_leaf_index": r["leaf_index"],
                        "last_leaf_type": r["event_type"],
                        "last_seen": r["created_at"],
                        "leaves": r["leaves"],
                    }
                )
            return {"since": since, "count": count, "agents": agents, "tree_size": self._log.tree.size}

    # ------------------------------------------------------------------
    # counts
    # ------------------------------------------------------------------

    #: ``/v2/stats`` counts are served from a cache this many seconds old at most (they are aggregate figures).
    STATS_CACHE_SECONDS = 30

    def health(self) -> dict[str, Any]:
        """``/healthz``: constant time, no table scan and no disk sync (a liveness probe polls it).

        The committed tree size, the tiles' state (a write error, a
        divergence: the log then refuses new leaves), a freeze and the
        resource exhaustion of AICS-1 section 8.2.  ``status`` is
        ``OPERATIONAL``, ``DEGRADED`` (tiles not written, or ciphertext over
        its budget with nothing evictable) or ``UNAVAILABLE`` (diverged).
        """
        with self._lock:
            tiles = self._log.status()
            frozen = self._frozen_index
        exhaustion = self.resource_exhaustion()
        if tiles["diverged"]:
            status = "UNAVAILABLE"
        elif tiles["error"] or exhaustion is not None:
            status = "DEGRADED"
        else:
            status = "OPERATIONAL"
        return {
            "status": status,
            "tree_size": tiles["tree_size"],
            "published_size": tiles["published_size"],
            "tiles_error": tiles["error"],
            "diverged": tiles["diverged"],
            "frozen": frozen is not None,
            "freeze_index": frozen,
            "resource_exhaustion": exhaustion,
        }

    def get_db_counts(self) -> dict[str, Any]:
        """The aggregate counts of ``/v2/stats`` and ``/stats``: read outside the writer lock, cached a few seconds.

        They are counted on a read-only connection of their own (WAL lets it
        read while the writer writes), at most every
        :data:`STATS_CACHE_SECONDS` seconds, so a stream of public requests
        for them never holds the single writer.
        """
        now = time.monotonic()
        with self._stats_lock:
            cached = self._stats_cache
            if cached is not None and now - cached[0] < self.STATS_CACHE_SECONDS:
                counts = dict(cached[1])
            else:
                counts = self._count_rows()
                self._stats_cache = (now, counts)
                counts = dict(counts)
        with self._lock:
            counts["tlog_tree_size"] = self._log.tree.size
            counts["tlog_root_hash_hex"] = self._log.tree.root().hex()
        return counts

    def _count_rows(self) -> dict[str, Any]:
        conn = sqlite3.connect(f"file:{self.db_path.resolve()}?mode=ro", uri=True, timeout=5)
        try:
            one = lambda sql, *args: conn.execute(sql, args).fetchone()[0]  # noqa: E731
            names_c = one("SELECT COUNT(*) FROM names")
            return {
                "registered_agents": names_c,
                "ans_handles_claimed": names_c,
                "verified_key_identities": one(
                    """
                    SELECT COUNT(*) FROM key_events e
                    WHERE e.leaf_index = (SELECT MAX(leaf_index) FROM key_events WHERE name_norm = e.name_norm)
                      AND e.revoked = 0 AND e.tier_after IN ('verified', 'third-party-generated')
                    """
                ),
                "e2ee_messages_relayed": one("SELECT COUNT(*) FROM messages"),
                "encrypted_capsules": one("SELECT COUNT(*) FROM capsules"),  # slots
                "agora_posts": one(
                    "SELECT COUNT(*) FROM agora_posts p WHERE NOT EXISTS "
                    "(SELECT 1 FROM tombstones t WHERE t.target_index = p.post_index)"
                ),
                "tombstones": one("SELECT COUNT(*) FROM tombstones"),
                "agora_polls": one("SELECT COUNT(*) FROM agora_polls"),
                "agora_votes": one("SELECT COUNT(*) FROM agora_poll_votes"),
                "tasks_total": one("SELECT COUNT(*) FROM sup_tasks"),
                "tasks_open": one(
                    "SELECT COUNT(*) FROM sup_tasks t WHERE t.closes > ? AND "
                    "(SELECT COUNT(*) FROM sup_awards a WHERE a.task_index = t.task_index) < t.max_awards",
                    int(time.time()),
                ),
                "task_awards": one("SELECT COUNT(*) FROM sup_awards"),
                "contributions_credited": one("SELECT COUNT(*) FROM sup_contributions"),
                "sup_credited_total": one("SELECT COALESCE(SUM(delta), 0) FROM sup_ledger WHERE delta > 0"),
                "sup_spent_total": one("SELECT COALESCE(-SUM(delta), 0) FROM sup_ledger WHERE delta < 0"),
                "owner_actions_quoted": one("SELECT COUNT(*) FROM owner_actions"),
                "owner_actions_settled": one(
                    "SELECT COUNT(*) FROM owner_actions WHERE paid_index IS NOT NULL OR (complete_index IS NOT NULL AND price = 0)"
                ),
                "notices_open": one("SELECT COUNT(*) FROM notices WHERE closed_at IS NULL"),
            }
        finally:
            conn.close()


#: Hash of a random secret nobody knows; checked for unknown names so timing stays uniform.
_DUMMY_SECRET_HASH = ident.hash_secret(secrets.token_urlsafe(32))

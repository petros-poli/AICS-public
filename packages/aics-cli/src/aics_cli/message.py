"""``aics verify message``: one log entry checked as AICS-1 §14.3 says (DESIGN G8).

The input (``--bundle FILE``) is a §14.3 wire bundle ``{entry_bytes, index,
inclusion_proof, checkpoint_note, envelope, body_or_ct}`` or a complete
verification package ``{bundle, trust_bundle, policy_cards, entry_prefix,
checkpoint_notes}``.  Keys come only from the pinned policy (``aics policy
init``): a package's ``trust_bundle`` must equal the pinned values; it never
replaces them.

The steps, in §14.3 order:

1. **checkpoint, inclusion, entry** - the note is signed by the pinned log
   key under the pinned origin and meets the pinned witness policy (every
   valid cosignature counts whatever its age: an offline bundle proves a
   historical property, not today's head); the entry bytes are leaf
   ``index`` of that tree; they are the JCS serialisation of an entry v2
   whose payload copies the envelope's exactly, and the bundle's envelope is
   the embedded one (aics-tlog :func:`~aics_tlog.verify_bundle`).
   Continuity: every checkpoint saved by ``aics verify checkpoint`` for this
   origin, and every note of a package, whose size the prefix covers must
   have the prefix's root at that size; a saved head larger than the
   bundle's checkpoint needs a consistency proof (the tiles, so not
   ``--offline``).
2. **history** - the complete entry prefix ``[0, size)`` of the bundle's
   checkpoint (from the package, ``--tiles DIR`` offline, or the pinned tile
   prefix online) must reconstruct the checkpoint root; then names, key
   rotations and revocations, recovery proofs, policy authority, every
   sender's sequence and nonce (a ``(kid, nonce)`` that any earlier leaf
   carries, as an envelope or as a refusal's attempt tuple, is a replay
   however long ago it expired), and grants are replayed in index order
   through the message index (:class:`Replay`).  Without a complete prefix
   the result is ``incomplete``, even when the signature verifies.
3. **envelope** - by its scheme with aics-identity (``ed25519-jcs``,
   ``text-ed25519``, ``text-sshsig``): origin and type equal the entry's, the
   actor is the kid, freshness at the entry's ``ts`` (§4.3); a
   ``shared-secret`` entry has the policy key's attestation, and its
   authorship is ``unproven``.  Every entry of the replay gets this check.
4. **body** - ``body_or_ct`` against the payload's hash and size, else the
   metadata only; a later tombstone of the entry is reported.
5. **DM** - the grant, its capacity and the recipient's encryption key at
   that index (the replay).
6. Nothing is decrypted here: no private material is read.

Not replayed: the SUP-1 task board, owner-action market and balances
(§20.9; their entries' authority and asset hash are checked), polls and
votes beyond their signer, suspensions and freezes beyond their signer, and
the card active at the index.  A swarms-profile entry (§19) stops the replay
as an unsupported profile.

Exit codes follow the CLI contract: 0 ``valid``; 1 ``incomplete`` (no
complete prefix, an unproven continuity, an unmet witness policy, an
unsupported profile) or an input file that does not verify (anyone can write
a bad file: that is no evidence against the log); 2 evidence: a log-signed
checkpoint and a valid inclusion proof of an entry AICS-1 forbids, or a
log-signed checkpoint that the authenticated prefix contradicts.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from aics_identity import envelope as idenv
from aics_identity import keys as idkeys
from aics_identity import sshsig as idsshsig
from aics_identity.canonical import canonicalize
from aics_tlog import Bundle, MerkleTree, leaf_hash, verify_bundle, verify_inclusion
from aics_tlog.tiles import TILE_ENTRIES, entry_bundle_path, parse_entry_bundle
from cryptography.exceptions import InvalidSignature

from .card import card_hash, check_signatures, loads_strict
from .checkpoints import Cp, check_note, log_signed
from .encoding import b64e, escape_untrusted
from .policy import Policy

#: AICS-1 §14.3: a complete verification package has exactly these members.
PACKAGE_MEMBERS = ("bundle", "trust_bundle", "policy_cards", "entry_prefix", "checkpoint_notes")
#: The trust-bundle values a package must repeat exactly (AICS-1 §6.4).
TRUST_MEMBERS = ("origin", "log_vkey", "policy_kid", "owner_kid", "bootstrap_card_hash")
INPUT_MAX_BYTES = 512 * 1024 * 1024
ENTRY_V2_MEMBERS = frozenset({"v", "origin", "type", "actor_kid", "ts", "payload"})
BODY_COMMITMENTS = ("body_hash", "ct_hash", "document_hash")
BASE_TYPES = frozenset(idenv.ENTRY_TYPES)
SUP_TYPES = frozenset(idenv.SUP_ENTRY_TYPES)
SWARMS_TYPES = frozenset(idenv.SWARMS_ENTRY_TYPES)
#: The types this release replays: the base profile and the SUP-1 profile (AICS-1 §§5.3, 20.3).
KNOWN_TYPES = tuple(idenv.ENTRY_TYPES) + tuple(idenv.SUP_ENTRY_TYPES)
TEXT_VERBS = {**idenv.TEXT_VERBS, **idenv.SUP_TEXT_VERBS}
KEY_TIERS = ("verified", "third-party-generated")
#: Entries the policy key signs (AICS-1 §5.3, §10); ``report`` of kind ``owner_action`` is the owner's (§20.4).
SERVICE_TYPES = frozenset({"refusal", "tombstone", "policy", "release", "suspension", "freeze", "report"})
ROTATE_CONTEXT = b"AICS-1 key.rotate\n"
UPGRADE_CHECK_CONTEXT = b"AICS-1 upgrade-check\n"
RECOVERY_CONTEXT = b"AICS-1 recovery-declaration\n"
POLICY_CONTEXT = b"AICS-1 policy\n"

#: What an offline message verification can never establish (AICS-1 §14.3 step 7), always reported.
ALWAYS_UNPROVEN = (
    "today's availability, current revocation state and a fresh witness quorum (an offline verification proves "
    "historical properties only, AICS-1 §14.3 step 7)",
    "the card active at the index and the retention policy it states (the card's policy leaf is not replayed)",
    "decryption and the inner header of a DM or capsule (no private material is read, AICS-1 §14.3 step 6)",
)
NOT_REPLAYED = (
    "the SUP-1 task board, owner-action market and balances (AICS-1 §20.9): their entries' signers and asset "
    "hash are checked, their state is not",
    "polls, votes, suspensions and freezes beyond the key that signed them",
)


class InputProblem(Exception):
    """The input file does not verify; no evidence against the log (exit 1)."""


class Evidence(Exception):
    """A log-signed statement AICS-1 forbids (exit 2); ``evidence`` lets anyone re-check it."""

    def __init__(self, message: str, evidence: dict[str, Any]) -> None:
        super().__init__(message)
        self.evidence = evidence


class ReplayProblem(Exception):
    """An entry of the authenticated prefix that AICS-1 forbids (a rule broken at ``index``)."""

    def __init__(self, index: int, rule: str, message: str) -> None:
        super().__init__(message)
        self.index = index
        self.rule = rule


class Unsupported(Exception):
    """An entry of a profile this release does not implement (AICS-1 §19): the history is incomplete."""

    def __init__(self, index: int, entry_type: str) -> None:
        super().__init__(f"leaf {index} is a {entry_type} entry of the swarms profile (AICS-1 §19), which this "
                         "release does not implement")
        self.index = index
        self.entry_type = entry_type


def u64d(value: Any, what: str) -> bytes:
    """Canonical unpadded base64url (AICS-1 §2)."""
    if not isinstance(value, str):
        raise ValueError(f"{what} must be base64url text")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise ValueError(f"{what} is not base64url") from None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise ValueError(f"{what} is not canonical base64url")
    return raw


def hexH(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# input
# ---------------------------------------------------------------------------


@dataclass
class MessageInput:
    bundle: Bundle
    package: dict[str, Any] | None = None
    prefix: list[bytes] | None = None
    notes: list[str] = field(default_factory=list)
    cards: list[bytes] = field(default_factory=list)


def parse_input(raw: bytes, policy: Policy) -> MessageInput:
    """A wire bundle or a §14.3 package, strictly parsed; :class:`InputProblem` otherwise."""
    if len(raw) > INPUT_MAX_BYTES:
        raise InputProblem(f"the input is larger than {INPUT_MAX_BYTES} bytes")
    try:
        doc = loads_strict(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise InputProblem(f"the input is not strict JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise InputProblem("the input is not a JSON object")
    package = None
    if "bundle" in doc:
        if set(doc) != set(PACKAGE_MEMBERS):
            raise InputProblem("a verification package has exactly the members " + ", ".join(PACKAGE_MEMBERS)
                               + " (AICS-1 §14.3)")
        package = doc
        wire = doc["bundle"]
    else:
        wire = doc
    try:
        bundle = Bundle.from_dict(wire)
    except ValueError as exc:
        raise InputProblem(f"not an AICS-1 §14.3 wire bundle: {exc}") from None
    out = MessageInput(bundle=bundle, package=package)
    if package is None:
        return out
    trust = package["trust_bundle"]
    pinned = {k: getattr(policy, k) for k in TRUST_MEMBERS}
    if not isinstance(trust, dict) or {k: trust.get(k) for k in TRUST_MEMBERS} != pinned \
            or set(trust) - {"v", *TRUST_MEMBERS}:
        raise InputProblem("the package's trust_bundle differs from your pinned trust values: a package never "
                           "supplies trust (AICS-1 §14.3); pin the right bundle first (aics policy init)")
    for name in ("policy_cards", "entry_prefix", "checkpoint_notes"):
        if not isinstance(package[name], list):
            raise InputProblem(f"the package's {name} must be an array")
    try:
        out.prefix = [u64d(x, f"entry_prefix[{i}]") for i, x in enumerate(package["entry_prefix"])]
        out.notes = [u64d(x, f"checkpoint_notes[{i}]").decode("utf-8")
                     for i, x in enumerate(package["checkpoint_notes"])]
        out.cards = [u64d(x, f"policy_cards[{i}]") for i, x in enumerate(package["policy_cards"])]
    except (ValueError, UnicodeDecodeError) as exc:
        raise InputProblem(f"the package does not decode: {exc}") from None
    return out


def read_prefix(reader: Any, size: int) -> list[bytes]:
    """Entries ``[0, size)`` from the entry bundles of ``reader`` (an aics-tlog TileReader); unauthenticated until
    their Merkle root is compared with a signed one.  ``ValueError`` names what is missing."""
    out: list[bytes] = []
    full, rest = divmod(size, TILE_ENTRIES)
    for n in range(full + (1 if rest else 0)):
        width = rest if n == full else None
        data = reader.read_entry_bundle(n, width)
        if data is None and width is not None:
            data = reader.read_entry_bundle(n, None)  # the log grew: the full bundle starts with these entries
        if data is None:
            raise ValueError(f"missing entry bundle {entry_bundle_path(n, width)}")
        entries = parse_entry_bundle(data)
        want = width or TILE_ENTRIES
        if len(entries) < want:
            raise ValueError(f"entry bundle {entry_bundle_path(n, width)} holds {len(entries)} entries, not {want}")
        out.extend(entries[:want])
    return out


# ---------------------------------------------------------------------------
# one entry: the §5.1 shape and the §4 envelope
# ---------------------------------------------------------------------------


def entry_problem(doc: Any, raw: bytes, origin: str) -> str | None:
    """Why ``raw`` is not an AICS-1 entry of this log (§5.1, §5.2, §14.3 step 1), or None."""
    if not isinstance(doc, dict):
        return "the entry is not a JSON object"
    try:
        if canonicalize(doc) != raw:
            return "the entry bytes are not the JCS serialisation of the entry (AICS-1 §5.2)"
    except (ValueError, TypeError):
        return "the entry cannot be canonicalised (RFC 8785)"
    if set(doc) != ENTRY_V2_MEMBERS or doc["v"] != 2:
        return "the entry is not an entry v2 with exactly v, origin, type, actor_kid, ts, payload (AICS-1 §5.1)"
    if doc["origin"] != origin:
        return "the entry names another origin than the pinned one (AICS-1 §5.1)"
    ts = doc["ts"]
    if isinstance(ts, bool) or not isinstance(ts, int) or not 0 <= ts <= idenv.MAX_UINT:
        return "ts is not uint seconds (AICS-1 §5.1)"
    payload = doc["payload"]
    env = payload.get("envelope") if isinstance(payload, dict) else None
    if not isinstance(env, dict) or not isinstance(env.get("payload"), dict) or not isinstance(env.get("protected"), dict):
        return "the payload does not embed an envelope with a protected header and a payload (AICS-1 §5.1)"
    q, auth = env["payload"], env.get("auth")
    allowed = {"envelope", *q}
    if isinstance(auth, dict) and auth.get("scheme") == idenv.SHARED_SECRET_SCHEME:
        allowed.add("attestation")
    if set(payload) != allowed:
        return "the entry payload is not the envelope plus an exact copy of the envelope payload (AICS-1 §5.1)"
    for name, value in q.items():
        if canonicalize(payload[name]) != canonicalize(value):
            return f"payload member {escape_untrusted(str(name))!r} is not an exact copy of the envelope's (AICS-1 §5.1)"
    p = env["protected"]
    if p.get("origin") != doc["origin"] or p.get("type") != doc["type"] or p.get("kid") != doc["actor_kid"]:
        return "the envelope's origin, type or kid differs from the entry's (AICS-1 §5.1)"
    return None


def check_envelope(i: int, e: dict[str, Any], policy_kid: str) -> str:
    """Verify entry ``i``'s envelope by its scheme at the entry's ``ts`` (§4.3, §14.3 step 3); returns the scheme.
    :class:`ReplayProblem` on failure."""
    env, ts, origin, etype = e["payload"]["envelope"], e["ts"], e["origin"], e["type"]
    scheme = env.get("auth", {}).get("scheme") if isinstance(env.get("auth"), dict) else None
    try:
        if scheme == idenv.NATIVE_SCHEME:
            idenv.verify_envelope(env, idkeys.parse_did_key, now=ts, origin=origin, type=etype, types=KNOWN_TYPES)
        elif scheme in idenv.TEXT_SCHEMES:
            idenv.verify_text_envelope(env, idkeys.parse_did_key, now=ts, origin=origin, type=etype,
                                       types=KNOWN_TYPES, verbs=TEXT_VERBS)
        elif scheme == idenv.SHARED_SECRET_SCHEME:
            if idenv.validate_envelope(env, types=KNOWN_TYPES) != idenv.SHARED_SECRET_SCHEME:
                raise idenv.MalformedEnvelope("not a shared-secret envelope")
            idenv.check_freshness(env["protected"], ts)
            idenv.verify_secret_attestation(env, e["payload"].get("attestation"), policy_kid, ts=ts,
                                            types=KNOWN_TYPES)
        else:
            raise idenv.UnsupportedScheme(f"auth.scheme {scheme!r} is not an AICS-1 scheme")
    except idenv.EnvelopeError as exc:
        rule = {"ExpiredEnvelope": "freshness", "NotYetValidEnvelope": "freshness"}.get(type(exc).__name__,
                                                                                         "envelope")
        raise ReplayProblem(i, rule, f"leaf {i} ({etype}): its envelope does not verify at the entry's ts: "
                                     f"{exc}") from None
    except (ValueError, TypeError) as exc:
        raise ReplayProblem(i, "envelope", f"leaf {i} ({etype}): its envelope is malformed: {exc}") from None
    return scheme


# ---------------------------------------------------------------------------
# the history through the message index (§14.3 step 2)
# ---------------------------------------------------------------------------


def _require(ok: Any, i: int, rule: str, message: str) -> None:
    if not ok:
        raise ReplayProblem(i, rule, f"leaf {i}: {message}")


def _proof(proof: Any, public: Any, data: bytes) -> bool:
    """A §7 proof object ``{scheme: ed25519|sshsig, signature}`` over ``data`` by ``public``."""
    if not isinstance(proof, dict) or set(proof) != {"scheme", "signature"}:
        return False
    try:
        raw = u64d(proof["signature"], "signature")
        if proof["scheme"] == "ed25519":
            public.verify(raw, data)
        elif proof["scheme"] == "sshsig":
            idsshsig.verify_sshsig(raw, data, public, namespace="aics")
        else:
            return False
    except (InvalidSignature, ValueError, idsshsig.SSHSigError):
        return False
    return True


def check_policy_event(i: int, q: dict[str, Any], *, log_kid: str, policy_kid: str | None, owner_kid: str | None,
                       previous: int | None) -> None:
    """AICS-1 §6.4 for the policy event at leaf ``i`` with envelope payload ``q``, whose preceding policy event is
    leaf ``previous`` (None: ``i`` must be the charter at leaf 0, countersigned by the log key).  The pinned service
    keys are ``log_kid``, ``policy_kid`` and ``owner_kid`` (did:key).  :class:`ReplayProblem` with rule ``policy``
    when a rule is broken; a missing or mistyped member raises KeyError or TypeError."""
    _require(q["log_kid"] != q["policy_kid"] and q["owner_kid"] not in (q["log_kid"], q["policy_kid"]), i,
             "policy", "the service keys of a policy event are not distinct (AICS-1 §3.1)")
    _require((q["log_kid"], q["policy_kid"], q["owner_kid"]) == (log_kid, policy_kid, owner_kid),
             i, "policy", "a policy event names other service keys than the pinned ones (AICS-1 §6.4)")
    _require(q["prev_policy_index"] == previous, i, "policy", "prev_policy_index is not the previous policy event")
    if previous is None:
        _require(i == 0 and q["kind"] == "charter" and q["effective_after"] == 0, i, "policy",
                 "the first policy event is the charter at leaf 0 (AICS-1 §6.4)")
        data = POLICY_CONTEXT + canonicalize({k: v for k, v in q.items() if k != "log_sig"})
        try:
            idkeys.parse_did_key(q["log_kid"]).verify(u64d(q["log_sig"], "log_sig"), data)
        except (InvalidSignature, ValueError):
            raise ReplayProblem(i, "policy", f"leaf {i}: the log key's countersignature of the charter does not "
                                             "verify (AICS-1 §6.4)") from None
    else:
        _require(q["log_sig"] is None, i, "policy", "only the charter carries the log key's countersignature")


def sup_asset_hash(origin: str) -> str:
    """AICS-1 §20.2."""
    return hexH(canonicalize({"asset": "SUP", "buys": ["owner_action", "hosting", "storage"], "decimals": 0,
                              "origin": origin, "refundable": False, "transferable": False}))


class Replay:
    """The state of names, keys, policy authority, sender chains, nonces and grants, in index order.

    :meth:`apply` checks one entry against the state immediately before its
    index and then updates it; the rules are AICS-1 §§3.3, 4.2-4.3, 5.3, 6.4,
    7 and 8 as an agent-side verifier applies them.
    """

    def __init__(self, policy: Policy) -> None:
        self.origin = policy.origin
        self.policy_kid = policy.policy_kid
        self.owner_kid = policy.owner_kid
        self.log_kid = idkeys.did_key(idkeys.public_key_from_bytes(policy.log_key().public_key))
        self.service_kids = {self.policy_kid, self.owner_kid, self.log_kid}
        self.names: dict[str, dict[str, Any]] = {}
        self.bound: set[str] = set()
        self.active: dict[str, dict[str, Any]] = {}
        self.last: dict[str, dict[str, Any]] = {}
        #: (kid, nonce) -> the first leaf that carries it (an accepted envelope or a refusal's attempt tuple)
        self.nonces: dict[tuple[str, str], int] = {}
        self.grants: dict[tuple[str, str], dict[str, Any]] = {}
        self.used: dict[int, int] = {}
        self.policy_events: list[int] = []
        self.entries: list[dict[str, Any]] = []
        self.schemes: list[str] = []

    def apply(self, i: int, raw: bytes) -> dict[str, Any]:
        try:
            e = loads_strict(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReplayProblem(i, "entry", f"leaf {i} is not strict JSON: {exc}") from None
        problem = entry_problem(e, raw, self.origin)
        if problem is not None:
            raise ReplayProblem(i, "entry", f"leaf {i}: {problem}")
        etype = e["type"]
        if etype in SWARMS_TYPES:
            raise Unsupported(i, etype)
        _require(etype in BASE_TYPES or etype in SUP_TYPES, i, "type",
                 f"type {escape_untrusted(str(etype))[:40]!r} is in no registry this log may use (AICS-1 §17.1)")
        scheme = check_envelope(i, e, self.policy_kid)
        try:
            self._apply(i, e, scheme)
        except (KeyError, TypeError, AttributeError) as exc:
            raise ReplayProblem(i, "schema", f"leaf {i} ({etype}): a §5.3 member is missing or mistyped "
                                             f"({type(exc).__name__}: {exc})") from None
        self.entries.append(e)
        self.schemes.append(scheme)
        return e

    def _apply(self, i: int, e: dict[str, Any], scheme: str) -> None:
        env = e["payload"]["envelope"]
        p, q, kid, typ, ts = env["protected"], env["payload"], env["protected"]["kid"], e["type"], e["ts"]
        secret = scheme == idenv.SHARED_SECRET_SCHEME
        if secret:
            _require(typ in ("name.claim", "post"), i, "tier",
                     "the shared-secret tier authorises only name.claim and post (AICS-1 §3.3)")
        # §4.2 the sender chain, §4.3 nonce uniqueness across the log
        prior = self.last.get(kid)
        _require(p["seq"] == (prior["protected"]["seq"] + 1 if prior else 0), i, "sequence",
                 f"seq {p['seq']} does not follow the sender's previous envelope (AICS-1 §4.2)")
        _require(p["prev"] == (idenv.envelope_hash(prior) if prior else None), i, "predecessor",
                 "prev is not hexH(J(E)) of the sender's previous accepted envelope (AICS-1 §4.2)")
        first = self.nonces.get((kid, p["nonce"]))
        _require(first is None, i, "replay",
                 f"the (kid, nonce) leaf {first} already carries is accepted again; a nonce is unique per key "
                 "across the whole log, also after its record expires (AICS-1 §4.3)")
        self.nonces[(kid, p["nonce"])] = i
        self.last[kid] = env
        # authority
        if typ in SERVICE_TYPES:
            expected = self.owner_kid if typ == "report" and q["kind"] == "owner_action" else self.policy_kid
            _require(kid == expected, i, "authority", f"a {typ} entry signed by another key than the pinned "
                                                      f"{'owner' if expected == self.owner_kid else 'policy'} key")
        elif typ == "sup.task" or (typ == "sup.credit" and q["source"] == "task"):
            _require(kid == self.owner_kid, i, "authority", f"a {typ} entry signed by another key than the owner's "
                                                            "(AICS-1 §20.3)")
        elif typ == "sup.credit":
            _require(kid == self.policy_kid, i, "authority", "a contribution credit signed by another key than the "
                                                             "policy key (AICS-1 §20.3)")
        elif typ != "name.claim" and not (typ == "key.rotate" and q["mode"] == "upgrade"):
            _require(kid in self.active, i, "signer", "the signer is not the current key of any name at this "
                                                      "index (AICS-1 §7)")
        handler = getattr(self, "_" + typ.replace(".", "_"), None)
        if handler is not None:
            handler(i, e, p, q, kid, ts, secret)

    # -- names and keys (§3.3, §7) ------------------------------------------------------------------------------

    def _name_claim(self, i, e, p, q, kid, ts, secret) -> None:
        _require(q["name_norm"] not in self.names, i, "name_taken", f"name {q['name_norm']!r} is claimed again")
        _require(kid not in self.bound, i, "key_reuse", "the claim's key is already bound (AICS-1 §7)")
        if secret:
            _require(q["tier"] == "unverified" and all(q[k] is None for k in ("ed25519", "x25519", "recovery_kid",
                                                                              "recovery_pop", "initial_grant")),
                     i, "tier", "a shared-secret claim is unverified and names no key, recovery or grant (§3.3)")
        else:
            _require(idkeys.did_key(idkeys.public_key_from_bytes(u64d(q["ed25519"], "ed25519"))) == kid
                     and q["tier"] in KEY_TIERS and q["x25519"] is not None, i, "claim",
                     "the claim's ed25519 is not its kid's key, its tier is not a key tier, or it has no x25519")
            _require(kid not in self.service_kids, i, "key_reuse", "a service key claims a name (AICS-1 §3.1)")
        if q["recovery_kid"] is not None:
            r = {k: q[k] for k in ("name_norm", "ed25519", "x25519", "recovery_kid")} | {"origin": e["origin"]}
            _require(_proof(q["recovery_pop"], idkeys.parse_did_key(q["recovery_kid"]),
                            RECOVERY_CONTEXT + canonicalize(r)), i, "recovery",
                     "the recovery declaration's proof does not verify (AICS-1 §7)")
        state = {"kid": kid, "x": q["x25519"], "key_index": i, "event": i, "revoked": False, "name": q["name_norm"],
                 "tier": q["tier"]}
        self.names[q["name_norm"]] = state
        self.active[kid] = state
        self.bound.add(kid)
        grant = q["initial_grant"]
        if grant is not None:
            _require(grant["max"] == 0 or grant["expires"] > ts, i, "grant", "the initial grant has expired")
            self.grants[(kid, grant["sender_kid"])] = dict(grant, index=i, ts=ts)

    def _key_event(self, i, q, kid, typ) -> dict[str, Any]:
        state = self.names.get(q["name_norm"])
        _require(state is not None, i, "name", f"a {typ} for an unclaimed name")
        _require(not state["revoked"] and state["event"] == q["prev_event_index"], i, "key_fork",
                 "prev_event_index is not the name's latest key event, or the name is revoked (AICS-1 §7)")
        return state

    def _key_rotate(self, i, e, p, q, kid, ts, secret) -> None:
        state = self._key_event(i, q, kid, "key.rotate")
        upgrade = q["mode"] == "upgrade"
        if not upgrade:
            _require(state["kid"] == kid, i, "signer", "a rotation signed by another key than the name's current one")
        r = {k: v for k, v in q.items() if k not in ("sig_old", "sig_new", "secret_check")} | {"origin": e["origin"]}
        data = ROTATE_CONTEXT + canonicalize(r)
        new = idkeys.public_key_from_bytes(u64d(q["new_ed25519"], "new_ed25519"))
        new_kid = idkeys.did_key(new)
        _require(q["new_tier"] in KEY_TIERS, i, "tier", "a rotation cannot move a name to the shared-secret tier")
        if upgrade:
            _require(state["kid"].startswith("unverified:") and q["sig_old"] is None and new_kid == kid
                     and p["seq"] == 0 and q["new_x25519"] is not None, i, "upgrade",
                     "an upgrade must move an unverified name to the signing key's first envelope (AICS-1 §7)")
            try:
                idkeys.parse_did_key(self.policy_kid).verify(u64d(q["secret_check"], "secret_check"),
                                                             UPGRADE_CHECK_CONTEXT + canonicalize(r))
            except (InvalidSignature, ValueError):
                raise ReplayProblem(i, "upgrade", f"leaf {i}: the policy key's secret_check does not verify") from None
        else:
            _require(_proof(q["sig_old"], idkeys.parse_did_key(kid), data), i, "rotation",
                     "sig_old does not verify under the name's current key (AICS-1 §7)")
        _require(_proof(q["sig_new"], new, data), i, "rotation", "sig_new does not verify under the new key")
        _require(new_kid not in self.bound, i, "key_reuse", "the new key is already bound (AICS-1 §7)")
        self.active.pop(state["kid"], None)
        state["kid"] = new_kid
        self.active[new_kid] = state
        self.bound.add(new_kid)
        state["tier"] = q["new_tier"]
        if q["new_x25519"] is not None:
            state.update(x=q["new_x25519"], key_index=i)
        state["event"] = i

    def _key_revoke(self, i, e, p, q, kid, ts, secret) -> None:
        state = self._key_event(i, q, kid, "key.revoke")
        _require(state["kid"] == kid, i, "signer", "a revocation signed by another key than the name's current one")
        state["revoked"] = True
        self.active.pop(kid, None)
        state["event"] = i

    def _x25519_rotate(self, i, e, p, q, kid, ts, secret) -> None:
        state = self._key_event(i, q, kid, "x25519.rotate")
        _require(state["kid"] == kid, i, "signer", "an x25519 rotation signed by another key than the name's")
        state.update(x=q["new_x25519"], key_index=i, event=i)

    # -- consent and private content (§8, §9) --------------------------------------------------------------------

    def _grant(self, i, e, p, q, kid, ts, secret) -> None:
        _require(q["owner_kid"] == kid, i, "grant", "a grant is signed by the inbox owner's key (AICS-1 §9)")
        pair = (kid, q["sender_kid"])
        prior = self.grants.get(pair)
        _require(q["prev_grant_index"] == (prior["index"] if prior else None), i, "stale_grant",
                 "prev_grant_index is not the pair's latest grant")
        _require(q["max"] == 0 or q["expires"] > ts, i, "grant", "the grant has expired")
        self.grants[pair] = dict(q, index=i, ts=ts)

    def _recipient(self, i, q, recipient) -> dict[str, Any]:
        state = self.active.get(recipient)
        _require(state is not None and state["key_index"] == q["to_key_leaf_index"], i, "stale_key",
                 "to_key_leaf_index is not the leaf that set the recipient's current encryption key (AICS-1 §8.1)")
        return state

    def _dm(self, i, e, p, q, kid, ts, secret) -> None:
        self._recipient(i, q, q["to_kid"])
        _require(q["seq"] == p["seq"] and q["prev"] == p["prev"], i, "dm", "the DM's seq/prev are not the envelope's")
        grant = self.grants.get((q["to_kid"], kid), self.grants.get((q["to_kid"], "*")))
        _require(grant is not None and grant["index"] == q["grant_index"], i, "no_consent",
                 "grant_index is not the recipient's live grant for this sender (AICS-1 §9)")
        _require(grant["max"] > self.used.get(grant["index"], 0) and grant["expires"] > ts, i, "grant_exhausted",
                 "the grant is used up or expired at this index (AICS-1 §9)")
        self.used[grant["index"]] = self.used.get(grant["index"], 0) + 1

    def _capsule(self, i, e, p, q, kid, ts, secret) -> None:
        self._recipient(i, q, q["owner_kid"])
        _require(q["owner_kid"] == kid, i, "capsule", "a capsule is sealed to its own author (AICS-1 §8)")

    # -- the service's own entries (§6.4, §10) -------------------------------------------------------------------

    def _tombstone(self, i, e, p, q, kid, ts, secret) -> None:
        _require(q["target_index"] < i, i, "tombstone", "a tombstone targets an earlier leaf")
        target = self.entries[q["target_index"]]
        if target["type"] in ("dm", "capsule"):
            _require(q["reason_code"] == "order", i, "tombstone", "a ciphertext is tombstoned only on an order "
                                                                  "(AICS-1 §10.3)")

    def _refusal(self, i, e, p, q, kid, ts, secret) -> None:
        if q["attempt_kid"] is not None:
            _require(q["attempt_nonce"] is not None and q["attempt_expires"] is not None, i, "refusal",
                     "an authenticated refusal records the whole attempt tuple (AICS-1 §10.2)")
            self.nonces.setdefault((q["attempt_kid"], q["attempt_nonce"]), i)  # used for good, as an envelope's

    def _policy(self, i, e, p, q, kid, ts, secret) -> None:
        check_policy_event(i, q, log_kid=self.log_kid, policy_kid=self.policy_kid, owner_kid=self.owner_kid,
                           previous=self.policy_events[-1] if self.policy_events else None)
        self.policy_events.append(i)

    # -- SUP-1 (§20.3): signers above, the asset here ------------------------------------------------------------

    def _sup_asset(self, i, e, q) -> None:
        _require(q["asset_hash"] == sup_asset_hash(e["origin"]), i, "asset",
                 "asset_hash is not the SUP asset of this origin (AICS-1 §20.2)")

    def _sup_task(self, i, e, p, q, kid, ts, secret) -> None:
        self._sup_asset(i, e, q)

    def _sup_credit(self, i, e, p, q, kid, ts, secret) -> None:
        self._sup_asset(i, e, q)

    def _sup_spend(self, i, e, p, q, kid, ts, secret) -> None:
        self._sup_asset(i, e, q)

    # -- what the message's report says -------------------------------------------------------------------------

    def signer_of(self, kid: str) -> dict[str, Any]:
        """Who ``kid`` was immediately after the replay: a service key or a name's current key."""
        if kid == self.policy_kid:
            return {"role": "policy key (pinned)"}
        if kid == self.owner_kid:
            return {"role": "owner key (pinned)"}
        state = self.active.get(kid)
        if state is not None:
            return {"role": "name", "name": state["name"], "tier": state["tier"]}
        return {"role": "unknown"}


# ---------------------------------------------------------------------------
# the whole check
# ---------------------------------------------------------------------------


@dataclass
class Outcome:
    """What :func:`verify` found; ``result`` is valid, incomplete or invalid."""

    result: str
    data: dict[str, Any]
    text: list[str]
    message: str = ""
    evidence: dict[str, Any] | None = None
    input_problem: bool = False


def _step(steps: list[dict[str, Any]], name: str, status: str, detail: str) -> None:
    steps.append({"step": name, "status": status, "detail": detail})


def verify(
    inp: MessageInput,
    policy: Policy,
    *,
    now: int,
    prefix_source: Callable[[int], tuple[list[bytes] | None, str]] | None = None,
    saved: Iterable[tuple[str, str]] = (),
    larger_head: Callable[[Cp, Cp], tuple[str, str]] | None = None,
) -> Outcome:
    """Run the §14.3 steps (see the module docstring).

    ``prefix_source(size)`` returns ``(entries or None, label)`` when the input carries no prefix.  ``saved`` is
    ``(note_text, source)`` of the checkpoints the user saved.  ``larger_head(bundle_cp, saved_cp)`` relates the
    bundle's checkpoint to a larger saved head and returns ``(status, detail)`` with status consistent,
    split-proven or unproven; None means no consistency proof can be had (offline).
    """
    b = inp.bundle
    steps: list[dict[str, Any]] = []
    unproven = list(ALWAYS_UNPROVEN)
    incomplete: list[str] = []
    data: dict[str, Any] = {"index": b.index, "steps": steps, "unproven": unproven, "not_replayed": list(NOT_REPLAYED)}

    def failed_input(message: str) -> Outcome:
        _step(steps, "input", "invalid", message)
        data["result"] = "invalid-input"
        return Outcome("invalid", data, [f"input      {message}"], message=message, input_problem=True)

    def invalid(step: str, detail: str, message: str, evidence: dict[str, Any]) -> Outcome:
        _step(steps, step, "invalid", detail)
        data["result"] = "invalid"
        return Outcome("invalid", data, [f"{step:<10} INVALID: {detail}"], message=message, evidence=evidence)

    # 1. checkpoint, inclusion, entry -------------------------------------------------------------------------
    chk = check_note(b.checkpoint_note, policy, source="bundle", now=now, require_fresh=False)
    if chk.cp is None:
        return failed_input(f"the bundle's checkpoint is not signed by the pinned log key for {policy.origin}: "
                            f"{chk.error}")
    cp = chk.cp
    data["checkpoint"] = {**cp.brief(), "witness_policy_met": chk.ok, "witnesses": chk.witnesses}
    if chk.ok:
        _step(steps, "checkpoint", "valid", f"log-signed under the pinned key, size {cp.size}; witness policy "
                                            f"quorum {policy.quorum} met")
    else:
        _step(steps, "checkpoint", "incomplete", f"log-signed, but the pinned witness policy is not met: {chk.error}")
        incomplete.append(f"the bundle's checkpoint does not meet the pinned witness policy ({chk.error})")
    if not (b.index < cp.size and verify_inclusion(leaf_hash(b.entry_bytes), b.index, cp.size,
                                                   list(b.inclusion_proof), cp.root)):
        return failed_input(f"the inclusion proof of leaf {b.index} does not verify against the checkpoint of size "
                            f"{cp.size}")
    _step(steps, "inclusion", "valid", f"leaf {b.index} is in the tree of size {cp.size} (RFC 9162)")
    base_evidence = {"type": "aics-message-evidence/v1", "origin": policy.origin, "log_vkey": policy.log_vkey,
                     "checkpoint": cp.evidence(), "bundle": b.to_dict()}
    try:
        doc = loads_strict(b.entry_bytes)
    except (ValueError, UnicodeDecodeError) as exc:
        doc, problem = None, f"the entry bytes are not strict JSON ({exc})"
    else:
        problem = entry_problem(doc, b.entry_bytes, policy.origin)
    if problem is not None:
        return invalid("entry", problem, f"the log included leaf {b.index}, which is not an AICS-1 entry: {problem}",
                       {**base_evidence, "reason": "invalid-entry", "problem": problem})
    res = verify_bundle(b, policy.log_key(), expected_origin=policy.origin)
    if not res.ok:
        return failed_input(f"the bundle does not bind to its entry: {res.error}")
    _step(steps, "entry", "valid", "JCS entry v2; the payload copies the envelope's, and the bundle's envelope is the "
                                   "embedded one (AICS-1 §5.1, §14.3 step 1)")
    data["entry"] = {"type": doc["type"], "actor_kid": doc["actor_kid"], "ts": doc["ts"],
                     "scheme": doc["payload"]["envelope"].get("auth", {}).get("scheme"),
                     "leaf_hash": b64e(leaf_hash(b.entry_bytes))}

    # 2. the prefix and continuity ------------------------------------------------------------------------------
    prefix, label = (inp.prefix, "the package's entry_prefix") if inp.prefix is not None else (None, "")
    if prefix is None and prefix_source is not None:
        prefix, label = prefix_source(cp.size)
    tree = None
    if prefix is None:
        _step(steps, "history", "incomplete", label or "no entry prefix: give a §14.3 package, --tiles DIR, or run "
                                                       "without --offline to read the pinned tiles")
        incomplete.append("the name, key and sequence history through the index is not checked: no complete entry "
                          "prefix (AICS-1 §14.3 step 2)")
    else:
        if len(prefix) != cp.size:
            return failed_input(f"{label} has {len(prefix)} entries, not the checkpoint's {cp.size}")
        tree = MerkleTree(prefix)
        if tree.root() != cp.root:
            return failed_input(f"{label} does not reconstruct the checkpoint root (AICS-1 §14.3)")
        if prefix[b.index] != b.entry_bytes:
            return failed_input(f"{label} holds other bytes at leaf {b.index} than the bundle")
    continuity = data.setdefault("continuity", [])
    if tree is not None:
        notes: list[tuple[Cp, str]] = []
        for text, src in [(text, src) for text, src in saved] + [(t, "the package") for t in inp.notes]:
            other, error, _ = log_signed(text, origin=policy.origin, log_vkey=policy.log_vkey, source=src)
            if other is None:
                if src == "the package":
                    return failed_input(f"a checkpoint note of the package is not log-signed: {error}")
                continuity.append({"source": src, "status": "skipped", "detail": f"not log-signed: {error}"})
                continue
            notes.append((other, src))
        # Saved heads larger than the bundle's checkpoint: the largest one (the saved head) needs a proof; every
        # smaller saved note is checked against the authenticated prefix itself.
        larger = [(o, src) for o, src in notes if o.size > cp.size and src != "the package"]
        largest = max(larger, key=lambda t: t[0].size, default=None)
        notes = [(o, src) for o, src in notes if o.size <= cp.size or src == "the package"] + (
            [largest] if largest is not None else [])
        for other, src in notes:
            if other.size <= cp.size:
                if tree.root(other.size) != other.root:
                    message = (f"split view: the log signed a checkpoint of size {other.size} ({src}) whose root is "
                               f"not the root at that size of the history the bundle's checkpoint authenticates")
                    return invalid("continuity", message, message, {
                        **base_evidence, "reason": "split-proven", "other_checkpoint": other.evidence(),
                        "consistency_proof": [b64e(h) for h in tree.consistency_proof(other.size)]
                        if other.size else [],
                        "authenticated_prefix_root": b64e(tree.root(other.size))})
                continuity.append({"source": src, "size": other.size, "status": "consistent"})
            elif src == "the package":
                incomplete.append(f"a checkpoint note of the package (size {other.size}) is beyond its prefix")
                continuity.append({"source": src, "size": other.size, "status": "unproven"})
            else:
                status, detail = larger_head(cp, other) if larger_head is not None else (
                    "unproven", "needs a consistency proof from the tiles (not with --offline)")
                if status == "split-proven":
                    message = f"split view: {detail}"
                    return invalid("continuity", message, message, {
                        **base_evidence, "reason": "split-proven", "other_checkpoint": other.evidence()})
                continuity.append({"source": src, "size": other.size, "status": status, "detail": detail})
                if status != "consistent":
                    incomplete.append(f"continuity with your saved checkpoint of size {other.size} is unproven "
                                      f"({detail})")
        _step(steps, "continuity", "valid" if all(c["status"] in ("consistent", "skipped") for c in continuity)
              else "incomplete", f"{sum(c['status'] == 'consistent' for c in continuity)} saved or packaged "
                                 "checkpoint(s) consistent with the authenticated prefix" if continuity else
              "no saved checkpoint of this origin to compare")

    # 2-3, 5. the replay ----------------------------------------------------------------------------------------
    if tree is not None:
        replay = Replay(policy)
        before: dict[str, Any] = {"role": "unknown"}
        try:
            for i in range(b.index + 1):
                if i == b.index:
                    before = replay.signer_of(doc["actor_kid"])
                replay.apply(i, prefix[i])
        except Unsupported as exc:
            _step(steps, "history", "incomplete", str(exc))
            incomplete.append(f"unsupported profile: {exc}; AICS-1 §19 requires a client without the profile to "
                              "report it rather than interpret its entries")
        except ReplayProblem as exc:
            j = exc.index
            return invalid("history", str(exc), f"the log accepted leaf {j}, which AICS-1 forbids ({exc.rule}): {exc}",
                           {**base_evidence, "reason": "invalid-history", "rule": exc.rule, "problem": str(exc),
                            "leaf": {"index": j,
                                     "entry_bytes": base64.urlsafe_b64encode(prefix[j]).rstrip(b"=").decode(),
                                     "inclusion_proof": [b64e(h) for h in tree.inclusion_proof(j)]}})
        else:
            e = replay.entries[b.index]
            scheme = replay.schemes[b.index]
            # the signer's standing at the index: before the entry, or what a claim or an upgrade made it
            signer = before if before["role"] != "unknown" else replay.signer_of(e["actor_kid"])
            _step(steps, "history", "valid", f"leaves 0-{b.index} replayed: names, keys, revocations, policy "
                                             "authority, sender sequences, nonces and grants (AICS-1 §14.3 step 2)")
            if scheme == idenv.SHARED_SECRET_SCHEME:
                _step(steps, "envelope", "unproven", "shared-secret tier: the pinned policy key attests that the service "
                                                     "checked the secret; authorship is unproven (AICS-1 §14.3 step 3)")
                unproven.append("authorship of a shared-secret entry (only the policy key's attestation exists)")
            else:
                _step(steps, "envelope", "valid", f"{scheme} signature by {e['actor_kid']}, fresh at ts {e['ts']}, "
                                                  f"seq {e['payload']['envelope']['protected']['seq']} in its chain")
            data["signer"] = signer
            if e["type"] == "dm":
                q = e["payload"]["envelope"]["payload"]
                _step(steps, "dm", "valid", f"grant at leaf {q['grant_index']} admits it; the recipient's encryption "
                                            f"key is the one leaf {q['to_key_leaf_index']} set (AICS-1 §14.3 step 5)")
            tombstones = []
            for j in range(b.index + 1, len(prefix)):
                try:
                    later = loads_strict(prefix[j])
                except (ValueError, UnicodeDecodeError):
                    continue
                if isinstance(later, dict) and later.get("type") == "tombstone":
                    tq = later.get("payload", {}).get("envelope", {}).get("payload", {})
                    if isinstance(tq, dict) and tq.get("target_index") == b.index:
                        tombstones.append({"index": j, "reason_code": tq.get("reason_code")})
            data["tombstones"] = tombstones
    else:
        try:
            scheme = check_envelope(b.index, doc, policy.policy_kid)
        except ReplayProblem as exc:
            return invalid("envelope", str(exc), f"the log accepted leaf {b.index}, whose envelope does not verify: "
                                                 f"{exc}", {**base_evidence, "reason": "invalid-envelope",
                                                            "problem": str(exc)})
        if scheme == idenv.SHARED_SECRET_SCHEME:
            _step(steps, "envelope", "unproven", "shared-secret tier: the policy key's attestation verifies; "
                                                 "authorship is unproven")
        else:
            _step(steps, "envelope", "valid", f"{scheme} signature by the kid it names, fresh at ts {doc['ts']}; whether "
                                              "that kid was its name's current key needs the history")

    # 4. the body ---------------------------------------------------------------------------------------------
    if b.body_or_ct is not None:
        _step(steps, "body", "valid", f"body_or_ct hashes to {res.body_bound_at} and has its size (AICS-1 §14.3 step 4)")
    else:
        _step(steps, "body", "not-applicable", "the bundle carries no body: the metadata is verified, the content is "
                                               "not available here")
    if data.get("tombstones"):
        t = data["tombstones"][0]
        _step(steps, "tombstone", "valid", f"the body is hidden by the tombstone at leaf {t['index']} "
                                           f"({t['reason_code']}); the leaf stays")

    # policy cards of a package ----------------------------------------------------------------------------
    if inp.cards:
        logged = set()
        if tree is not None and prefix is not None:
            for raw in prefix:
                try:
                    pe = loads_strict(raw)
                except (ValueError, UnicodeDecodeError):
                    continue
                pq = pe.get("payload", {}).get("envelope", {}).get("payload", {}) if isinstance(pe, dict) else {}
                if isinstance(pe, dict) and pe.get("type") == "policy" and isinstance(pq, dict) and pq.get("kind") == "card":
                    logged.add(pq.get("document_hash"))
        cards = []
        for n, raw in enumerate(inp.cards):
            try:
                card = loads_strict(raw)
                canonical = isinstance(card, dict) and canonicalize(card) == raw
            except (ValueError, UnicodeDecodeError):
                card, canonical = None, False
            if not canonical:
                return failed_input(f"policy_cards[{n}] is not a JCS card")
            signed = any(c.status == "valid" for c in check_signatures(card, policy.policy_keys()))
            h = card_hash(card)
            cards.append({"card_hash": h, "signed": signed, "logged": h in logged})
            if not signed:
                return failed_input(f"policy_cards[{n}] carries no valid signature of the pinned policy key")
            if tree is not None and h not in logged:
                return failed_input(f"policy_cards[{n}] is named by no card policy leaf of the prefix")
        data["policy_cards"] = cards

    data["result"] = "incomplete" if incomplete else "valid"
    data["incomplete"] = incomplete
    text = [f"message: leaf {b.index} of {policy.origin} ({data['entry']['type']})"]
    text += [f"{s['step']:<10} {s['status']}: {s['detail']}" for s in steps]
    text += [f"unproven   {u}" for u in unproven]
    text += [f"not replayed {n}" for n in NOT_REPLAYED]
    if incomplete:
        message = "incomplete: " + "; ".join(incomplete)
        return Outcome("incomplete", data, text, message=message)
    return Outcome("valid", data, text)

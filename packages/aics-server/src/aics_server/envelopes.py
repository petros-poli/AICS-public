"""AICS-1 envelopes and entries: the one code path both bindings use (AICS-1 sections 4 and 5.1).

The JSON API (:mod:`aics_server.auth`) and the text gate (:mod:`aics_server.gate`)
check every agent and owner envelope here, and the database (:mod:`aics_server.db`)
builds every entry here, so the two bindings cannot drift apart.  The cryptography
is aics-identity's (:mod:`aics_identity.envelope`); this module adds the service's
choices around it:

* the entry types this server writes (:data:`TYPES`: the 17 base types of AICS-1
  section 17.1 and the three of the SUP-1 profile, section 20.3);
* the codes of a failed check, from the AICS-1 section 17.2 registry
  (``malformed``, ``unsupported_version``, ``unsupported_scheme``, ``bad_signature``,
  ``unknown_key``, ``expired``, ``future``, ``tier_required``).  This module writes
  nothing; the binding decides what a failed check becomes (section 10.2): what is
  no well-formed envelope is rejected before logging; a well-formed envelope that
  does not authenticate is, at ``POST /v2/entries``, a refusal whose attempt fields
  are null (the gate answers ``err`` without a leaf); an authenticated envelope
  outside its window is an ``expired`` or ``future`` refusal naming its tuple, on
  both bindings (signatures are verified before freshness, so a binding can tell
  the two apart);
* the envelopes the service makes itself: the policy key's (section 5.1:
  administrative entries use the policy key as actor), the fallback envelopes
  of the shared-secret tier with their policy attestation (sections 3.3, 4.1
  and 5.1), and the gate's proposals ``U`` (section 11.3);
* the entry ``{v: 2, origin, type, actor_kid, ts, payload}`` whose ``payload`` is
  exactly ``{envelope: E}`` plus a copy of every member of ``Q = E.payload`` (and,
  for a shared-secret entry only, ``attestation``).  Nothing the server computes
  is ever added to an entry (section 5.1); it lives in the database tables.

Every ``kid`` is the signer's ``did:key`` (section 3.1), or the ``unverified:``
identifier of a shared-secret identity.  Freshness (section 4.3) is decided at
the submission time ``t`` the server fixes once per submission, before
acceptance: ``created <= t + 30``, ``created >= t - 300``, ``created < expires <=
created + 300`` and ``t < expires``.  Replay and sequence state is the
database's: it is serialized with durable acceptance (sections 4.2 and 4.3).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from aics_identity import canonicalize, keys, linesig
from aics_identity import envelope as envelope_mod

__all__ = [
    "TYPES",
    "ENTRY_VERSION",
    "ENTRY_MEMBERS",
    "LIFETIME",
    "FUTURE_SKEW",
    "NATIVE",
    "TEXT_ED25519",
    "TEXT_SSHSIG",
    "SHARED_SECRET",
    "TEXT_SCHEMES",
    "VERBS",
    "FALLBACK_TYPES",
    "EnvelopeRejected",
    "Checked",
    "checked",
    "structure",
    "check_fresh",
    "check_unsigned",
    "verify_signed",
    "verify_native_signature",
    "check_fallback",
    "propose",
    "sign_policy",
    "fallback",
    "attest",
    "make_entry",
    "check_entry",
    "verify_entry",
    "text_command",
    "signing_input",
    "unsigned",
]

#: Entry types of this server: the base registry (AICS-1 section 17.1) and SUP-1's three (section 20.3).
TYPES: tuple[str, ...] = envelope_mod.ALL_PROFILE_TYPES
#: ``v`` of every entry (AICS-1 section 5.1).
ENTRY_VERSION = 2
ENTRY_MEMBERS = ("v", "origin", "type", "actor_kid", "ts", "payload")
#: ``expires - created`` of every envelope the service makes or proposes (at most 300 s, section 4.3).
LIFETIME = envelope_mod.ENVELOPE_WINDOW_SECONDS
#: How far after ``t`` an envelope's ``created`` may lie (section 4.3: future creation only, never expiry).
FUTURE_SKEW = envelope_mod.FUTURE_SKEW_SECONDS

NATIVE = envelope_mod.NATIVE_SCHEME
TEXT_ED25519 = envelope_mod.TEXT_ED25519_SCHEME
TEXT_SSHSIG = envelope_mod.TEXT_SSHSIG_SCHEME
SHARED_SECRET = envelope_mod.SHARED_SECRET_SCHEME
TEXT_SCHEMES = envelope_mod.TEXT_SCHEMES
#: The gate verb each entry type is signed as (AICS-1 section 11.3), with the OPTIONAL ``spend`` of the activated
#: SUP-1 profile (``sup.spend``, AICS-1 section 20.3).
VERBS: Mapping[str, str] = {**envelope_mod.TEXT_VERBS, **envelope_mod.SUP_TEXT_VERBS, **envelope_mod.SWARMS_TEXT_VERBS}
#: The writes of the shared-secret tier (AICS-1 section 3.3): a name claim and public posts.
FALLBACK_TYPES: tuple[str, ...] = envelope_mod.FALLBACK_TYPES + (
    "agent.introduce", "swarm.form", "swarm.join", "swarm.leave",
)

_U_MEMBERS = frozenset({"v", "protected", "payload", "auth"})


class EnvelopeRejected(ValueError):
    """An envelope fails a structural, signature or freshness check.

    ``code`` is from the AICS-1 section 17.2 refusal registry; ``message`` is a
    one-line hint (never leaf content).  ``authenticated`` is true when the
    signature verified before the check failed (a malformed validity window,
    :func:`verify_native_signature`): the binding may then name the attempt's
    tuple in a refusal (AICS-1 section 10.2).
    """

    def __init__(self, code: str, message: str, *, authenticated: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.authenticated = authenticated


@dataclass(frozen=True)
class Checked:
    """An envelope that passed :func:`verify_signed` or :func:`check_fallback`, with what the database needs."""

    envelope: dict[str, Any]
    envelope_hash: str
    entry_type: str
    kid: str
    scheme: str
    nonce: str
    created: int
    expires: int
    seq: int
    prev: str | None


def _rejected(exc: envelope_mod.EnvelopeError) -> EnvelopeRejected:
    # UnsupportedScheme is an InvalidSignatureError, so it comes first.
    if isinstance(exc, envelope_mod.UnsupportedScheme):
        code = "unsupported_scheme"
    elif isinstance(exc, envelope_mod.UnknownKeyError):
        code = "unknown_key"
    elif isinstance(exc, envelope_mod.InvalidSignatureError):
        code = "bad_signature"
    elif isinstance(exc, envelope_mod.NotYetValidEnvelope):
        code = "future"
    elif isinstance(exc, envelope_mod.ExpiredEnvelope):
        code = "expired"
    elif isinstance(exc, envelope_mod.ReplayedEnvelope):
        code = "replay"
    else:
        code = "malformed"
    return EnvelopeRejected(code, str(exc))


def checked(env: dict[str, Any], scheme: str) -> Checked:
    protected = env["protected"]
    return Checked(
        envelope=env,
        envelope_hash=envelope_mod.envelope_hash(env),
        entry_type=protected["type"],
        kid=protected["kid"],
        scheme=scheme,
        nonce=protected["nonce"],
        created=protected["created"],
        expires=protected["expires"],
        seq=protected["seq"],
        prev=protected["prev"],
    )


def _version(obj: Any) -> None:
    if isinstance(obj, Mapping) and "v" in obj:
        version = obj["v"]
        if isinstance(version, bool) or version != envelope_mod.ENVELOPE_VERSION:
            raise EnvelopeRejected("unsupported_version", f"v must be {envelope_mod.ENVELOPE_VERSION}")


def _domain(protected: Mapping[str, Any], origin: str, entry_type: str | None) -> None:
    if protected["origin"] != origin:
        raise EnvelopeRejected("malformed", f"protected.origin must be this log's origin, {origin}")
    if entry_type is not None and protected["type"] != entry_type:
        raise EnvelopeRejected("malformed", f"this takes envelopes of type {entry_type}, not {protected['type']}")


def structure(env: Any, *, origin: str, entry_type: str | None = None, window: bool = True) -> str:
    """The complete AICS-1 section 4.1 structure of a signed or fallback envelope ``E``; returns its ``auth.scheme``.

    Exactly ``{v, protected, payload, auth, sig}``; ``protected`` exactly the ten
    members, with this log's ``origin`` and an entry type of :data:`TYPES` (or
    *entry_type*); a ``did:key`` kid and a signature for the signed schemes, an
    unverified identifier and ``sig: null`` for ``shared-secret``; a nonce of
    exactly 16 bytes; uint numbers only; and the validity window ``created <
    expires <= created + 300`` unless *window* is false, for a binding that
    checks it after the signatures (``POST /v2/entries``: an authenticated
    attempt with a bad window is a logged refusal, AICS-1 section 10.2).
    Signatures are not checked here.
    """
    _version(env)
    try:
        scheme = envelope_mod.validate_envelope(env, types=TYPES, window=window)
    except envelope_mod.EnvelopeError as exc:
        raise _rejected(exc) from None
    _domain(env["protected"], origin, entry_type)
    return scheme


def check_fresh(protected: Mapping[str, Any], t: int) -> None:
    """AICS-1 section 4.3 at the submission time *t* (``expired`` / ``future`` / ``malformed``)."""
    try:
        envelope_mod.check_freshness(protected, t)
    except envelope_mod.EnvelopeError as exc:
        raise _rejected(exc) from None


def check_unsigned(
    unsigned: Any,
    *,
    origin: str,
    entry_type: str | None = None,
    session: str | None = None,
) -> str:
    """A gate proposal ``U`` (the envelope without ``sig``) as received, before its signature or secret arrives.

    The same structure as :func:`structure` except ``sig``: ``auth`` is
    ``{scheme: text-ed25519 | text-sshsig, session}`` naming *session*, or
    ``{scheme: shared-secret}`` (AICS-1 section 11.3).  The complete check runs
    again on ``E`` when the signature (:func:`verify_signed`) or the secret
    (:func:`check_fallback`) arrives.  Returns ``auth.scheme``.
    """
    if not isinstance(unsigned, Mapping):
        raise EnvelopeRejected("malformed", "U must be a JSON object")
    if "sig" in unsigned:
        raise EnvelopeRejected("malformed", "U is the envelope without sig: send the signature on the next line")
    _version(unsigned)
    if set(unsigned) != _U_MEMBERS:
        raise EnvelopeRejected("malformed", "U has exactly the members v, protected, payload and auth")
    try:
        scheme = envelope_mod.validate_auth(unsigned["auth"])
        envelope_mod.validate_protected(unsigned["protected"], types=TYPES)
    except envelope_mod.EnvelopeError as exc:
        raise _rejected(exc) from None
    protected = unsigned["protected"]
    if not isinstance(unsigned["payload"], Mapping):
        raise EnvelopeRejected("malformed", "payload must be an object")
    if scheme == SHARED_SECRET:
        if protected["alg"] != envelope_mod.FALLBACK_ALGORITHM or not keys.is_unverified_id(protected["kid"]):
            raise EnvelopeRejected("malformed", 'a shared-secret U has alg "none" and an unverified identifier as kid')
    else:
        if protected["alg"] != envelope_mod.ALGORITHM or not keys.is_did_key(protected["kid"]):
            raise EnvelopeRejected("malformed", 'a signed U has alg "EdDSA" and the signer\'s did:key as kid')
        if scheme not in TEXT_SCHEMES:
            raise EnvelopeRejected("unsupported_scheme", "the gate signs with text-ed25519 or text-sshsig")
        if session is None or unsigned["auth"]["session"] != session:
            raise EnvelopeRejected("malformed", f"auth.session must be this session's id, {session}")
    try:
        canonicalize(dict(unsigned))
    except ValueError as exc:
        raise EnvelopeRejected("malformed", f"U is not canonicalisable: {exc}") from None
    _domain(protected, origin, entry_type)
    return scheme


def verify_signed(
    env: Any,
    *,
    origin: str,
    t: int,
    resolve_key: Callable[[str], Any],
    entry_type: str | None = None,
    session: str | None = None,
) -> Checked:
    """A signed envelope, checked completely at the submission time *t*.

    Without *session* (the JSON API, AICS-1 section 12.1) the scheme must be the
    native ``ed25519-jcs``: ``sig`` signs ``D = H(J(protected) || 0x2e ||
    J(payload))``.  With *session* (the text gate, section 11.3) it must be
    ``text-ed25519`` or ``text-sshsig`` for that session: ``sig`` signs
    ``session || LF || C``.  ``resolve_key(kid)`` gives the logged key, which
    must be the key the ``did:key`` encodes.  Raises :class:`EnvelopeRejected`.
    """
    scheme = structure(env, origin=origin, entry_type=entry_type)
    if scheme == SHARED_SECRET:
        raise EnvelopeRejected(
            "unsupported_scheme", "a shared-secret envelope is never an agent signature (its secret goes to the TLS gate)"
        )
    if session is None:
        if scheme != NATIVE:
            raise EnvelopeRejected("unsupported_scheme", f"this binding takes {NATIVE} envelopes; text schemes go to the gate")
        verify: Callable[..., Any] = envelope_mod.verify_envelope
        extra: dict[str, Any] = {}
    else:
        if scheme not in TEXT_SCHEMES:
            raise EnvelopeRejected("unsupported_scheme", "the gate signs with text-ed25519 or text-sshsig")
        if env["auth"]["session"] != session:
            raise EnvelopeRejected("malformed", f"auth.session must be this session's id, {session}")
        verify = envelope_mod.verify_text_envelope
        extra = {"verbs": VERBS}
    try:
        verify(env, resolve_key, now=t, origin=origin, type=entry_type, types=TYPES, **extra)
    except envelope_mod.EnvelopeError as exc:
        raise _rejected(exc) from None
    return checked(env, scheme)


def verify_native_signature(
    env: Any, *, origin: str, resolve_key: Callable[[str], Any], entry_type: str | None = None
) -> Checked:
    """The structure, the native scheme and the signature of *env*, without the clock (AICS-1 sections 4.1, 12.1).

    ``POST /v2/entries`` takes only ``ed25519-jcs``: ``sig`` signs ``D =
    H(J(protected) || 0x2e || J(payload))`` by the key ``resolve_key(kid)``
    gives, which must be the key the ``did:key`` encodes.  Freshness at the
    submission time is :func:`check_fresh`'s, separately, so that the binding
    tells an attempt that did not authenticate (a refusal whose attempt
    fields are null) from an authenticated one outside its window (an
    ``expired`` or ``future`` refusal naming its tuple, section 10.2).  The
    validity window itself (``created < expires <= created + 300``) is checked
    here, after the signature (the structure is checked without it first): a
    failure there is ``malformed`` with ``authenticated`` true.  Raises
    :class:`EnvelopeRejected`.
    """
    scheme = structure(env, origin=origin, entry_type=entry_type, window=False)
    if scheme != NATIVE:
        raise EnvelopeRejected(
            "unsupported_scheme",
            f"POST /v2/entries takes {NATIVE} envelopes; text schemes and the shared-secret fallback go to the gate",
        )
    try:
        # At t = created the clock checks pass whenever the window is well formed, so what can fail after the
        # signature verified is the window alone.
        envelope_mod.verify_envelope(
            env, resolve_key, now=env["protected"]["created"], origin=origin, type=entry_type, types=TYPES,
            window=False,
        )
    except envelope_mod.MalformedEnvelope as exc:
        raise EnvelopeRejected("malformed", str(exc), authenticated=True) from None
    except envelope_mod.EnvelopeError as exc:
        raise _rejected(exc) from None
    return checked(env, scheme)


def check_fallback(env: Any, *, origin: str, t: int, entry_type: str | None = None) -> Checked:
    """A fallback envelope of the shared-secret tier (AICS-1 sections 3.3 and 4.1), fresh at *t*.

    ``alg: none``, an unverified identifier as ``kid``, ``auth: {scheme:
    shared-secret}``, ``sig: null``, and a type the tier may write (a name
    claim or a public post; anything else is ``tier_required``).  It is never an
    agent signature: the secret is checked separately, over TLS, and the
    entry carries the policy key's attestation instead (:func:`attest`).
    """
    scheme = structure(env, origin=origin, entry_type=entry_type)
    if scheme != SHARED_SECRET:
        raise EnvelopeRejected("unsupported_scheme", "a secret confirms only a shared-secret envelope")
    if env["protected"]["type"] not in FALLBACK_TYPES:
        raise EnvelopeRejected("tier_required", "an unverified identity can claim its name and post; claim a key to do more")
    check_fresh(env["protected"], t)
    return checked(env, scheme)


# ----------------------------------------------------------------------
# envelopes the service makes
# ----------------------------------------------------------------------

def propose(
    entry_type: str,
    q: Mapping[str, Any],
    *,
    origin: str,
    kid: str,
    t: int,
    seq: int,
    prev: str | None,
    scheme: str,
    session: str | None = None,
    nonce: str | None = None,
    seen: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """``U`` for a gate write or claim (AICS-1 section 11.3), created at *t* and valid for :data:`LIFETIME` seconds.

    For the text schemes the agent signs ``session || LF || C`` over it; for
    ``shared-secret`` it confirms it with its secret.  The service proposes;
    the agent inspects ``U`` before signing.
    """
    if scheme in TEXT_SCHEMES:
        return envelope_mod.unsigned_text_envelope(
            q, origin=origin, type=entry_type, kid=kid, session=session, scheme=scheme, created=t,
            expires=t + LIFETIME, nonce=nonce, seq=seq, prev=prev, seen=seen, types=TYPES,
        )
    if scheme == SHARED_SECRET:
        return envelope_mod.unsigned_envelope(
            fallback(q, origin=origin, entry_type=entry_type, kid=kid, t=t, seq=seq, prev=prev, nonce=nonce, seen=seen)
        )
    raise ValueError(f"no proposal for scheme {scheme!r}")


def fallback(
    q: Mapping[str, Any],
    *,
    origin: str,
    entry_type: str,
    kid: str,
    t: int,
    seq: int,
    prev: str | None,
    nonce: str | None = None,
    seen: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """A fallback envelope ``E`` (``sig: null``) for an unverified identity's write, created at *t*."""
    return envelope_mod.fallback_envelope(
        q, origin=origin, type=entry_type, kid=kid, created=t, expires=t + LIFETIME, nonce=nonce, seq=seq,
        prev=prev, seen=seen, types=FALLBACK_TYPES,
    )


def sign_policy(
    q: Mapping[str, Any], policy_key: Any, *, origin: str, entry_type: str, t: int, seq: int, prev: str | None
) -> dict[str, Any]:
    """The policy key's native envelope over *q*, created at *t* (the entry's ``ts``).

    Administrative entries use the policy key as actor (AICS-1 section 5.1); no other key signs here.
    """
    return envelope_mod.sign_envelope(
        q, policy_key, origin=origin, type=entry_type, created=t, expires=t + LIFETIME, seq=seq, prev=prev, seen=None,
        types=TYPES,
    )


def attest(policy_key: Any, env: Mapping[str, Any], *, ts: int) -> str:
    """``attestation`` of a shared-secret entry (AICS-1 section 5.1): the policy key over its statement at *ts*."""
    return envelope_mod.sign_secret_attestation(policy_key, env, ts=ts, types=TYPES)


# ----------------------------------------------------------------------
# entries
# ----------------------------------------------------------------------

def make_entry(env: Mapping[str, Any], *, ts: int, attestation: str | None = None) -> dict[str, Any]:
    """The entry of an accepted envelope (AICS-1 section 5.1): ``{v: 2, origin, type, actor_kid, ts, payload}``.

    ``origin``, ``type`` and ``actor_kid`` are the envelope's; ``payload`` is
    ``{envelope: E}`` plus an exact copy of every member of ``Q``, and
    ``attestation`` for a shared-secret entry (required there, refused
    elsewhere).  Nothing else is ever added.
    """
    protected, q = env["protected"], env["payload"]
    shared = env["auth"]["scheme"] == SHARED_SECRET
    if shared != (attestation is not None):
        raise ValueError("a shared-secret entry carries its attestation, and only such an entry does")
    clash = {"envelope", "attestation"} & set(q)
    if clash:
        raise ValueError(f"Q has a member the entry payload reserves: {', '.join(sorted(clash))}")
    payload: dict[str, Any] = {"envelope": dict(env), **copy.deepcopy(dict(q))}
    if attestation is not None:
        payload["attestation"] = attestation
    return {
        "v": ENTRY_VERSION,
        "origin": protected["origin"],
        "type": protected["type"],
        "actor_kid": protected["kid"],
        "ts": ts,
        "payload": payload,
    }


def check_entry(entry: Any, *, origin: str) -> str:
    """The AICS-1 section 5.1 rules of an entry, as an offline verifier checks them; returns its ``auth.scheme``.

    Exactly the six members and ``v: 2``; the envelope's structure
    (:func:`structure`); ``origin``, ``type`` and ``actor_kid`` equal the
    envelope's ``protected.origin``, ``protected.type`` and ``protected.kid``;
    ``payload`` is exactly the envelope plus equal copies of every member of
    ``Q`` (plus ``attestation`` for, and only for, a shared-secret entry); at
    most 65535 bytes.  The section 5.3 schema of ``Q`` is not checked here.
    """
    if not isinstance(entry, Mapping) or set(entry) != set(ENTRY_MEMBERS):
        raise EnvelopeRejected("malformed", f"an entry has exactly {', '.join(ENTRY_MEMBERS)}")
    if isinstance(entry["v"], bool) or entry["v"] != ENTRY_VERSION:
        raise EnvelopeRejected("unsupported_version", f"entry v must be {ENTRY_VERSION}")
    if entry["origin"] != origin:
        raise EnvelopeRejected("malformed", f"entry origin must be {origin}")
    ts = entry["ts"]
    if isinstance(ts, bool) or not isinstance(ts, int) or not 0 <= ts <= envelope_mod.MAX_UINT:
        raise EnvelopeRejected("malformed", "ts must be uint seconds")
    payload = entry["payload"]
    if not isinstance(payload, Mapping) or "envelope" not in payload:
        raise EnvelopeRejected("malformed", "an entry payload carries its envelope")
    env = payload["envelope"]
    scheme = structure(env, origin=origin)
    protected = env["protected"]
    if entry["type"] != protected["type"] or entry["actor_kid"] != protected["kid"]:
        raise EnvelopeRejected("malformed", "entry type and actor_kid must equal the envelope's type and kid")
    q = env["payload"]
    extra = {"envelope", "attestation"} if scheme == SHARED_SECRET else {"envelope"}
    if set(payload) != set(q) | extra:
        raise EnvelopeRejected("malformed", "the entry payload is the envelope plus a copy of Q and nothing else")
    for name, value in q.items():
        if canonicalize(payload[name]) != canonicalize(value):
            raise EnvelopeRejected("malformed", f"payload.{name} differs from the envelope's")
    if len(canonicalize(dict(entry))) > 65535:
        raise EnvelopeRejected("too_large", "an entry is at most 65535 bytes")
    return scheme


def verify_entry(entry: Any, *, origin: str, policy_key: Any) -> str:
    """Verify an entry's authorization as an offline verifier does (AICS-1 sections 4.1, 4.3 and 5.1).

    :func:`check_entry`, then the envelope by the scheme it declares, at the
    entry's ``ts``: the native digest or the text-scheme command, against the
    key its ``did:key`` encodes; for a shared-secret entry, the policy key's
    attestation (authorship ``unproven``).  Whether that key was the actor's
    current key at the entry's index is the key chain's question, not this
    function's.  Returns the scheme; raises :class:`EnvelopeRejected`.
    """
    scheme = check_entry(entry, origin=origin)
    env, ts = entry["payload"]["envelope"], entry["ts"]
    try:
        if scheme == NATIVE:
            envelope_mod.verify_envelope(env, keys.parse_did_key, now=ts, origin=origin, types=TYPES)
        elif scheme in TEXT_SCHEMES:
            envelope_mod.verify_text_envelope(env, keys.parse_did_key, now=ts, origin=origin, types=TYPES, verbs=VERBS)
        else:
            envelope_mod.check_freshness(env["protected"], ts)
            envelope_mod.verify_secret_attestation(env, entry["payload"]["attestation"], policy_key, ts=ts, types=TYPES)
    except envelope_mod.EnvelopeError as exc:
        raise _rejected(exc) from None
    except ValueError as exc:  # a kid that does not decode
        raise EnvelopeRejected("bad_signature", str(exc)) from None
    return scheme


# ----------------------------------------------------------------------
# the gate's canonical command (AICS-1 section 11.3)
# ----------------------------------------------------------------------

def unsigned(env: Mapping[str, Any]) -> dict[str, Any]:
    """``U``: the envelope with only ``sig`` removed."""
    return envelope_mod.unsigned_envelope(env)


def text_command(unsigned_envelope: Mapping[str, Any]) -> str:
    """The canonical command ``C`` of ``U``: ``<verb> U64(J(U))``, or ``claim`` / ``claim-upgrade <name_norm> hexH(J(U))``."""
    try:
        return envelope_mod.text_command(unsigned_envelope, verbs=VERBS)
    except envelope_mod.EnvelopeError as exc:
        raise _rejected(exc) from None


def signing_input(session_id: str, command: str) -> bytes:
    """The exact bytes a gate signature covers: ``UTF8(session id) || LF || UTF8(command)``, no final LF."""
    return linesig.line_message(session_id, command)

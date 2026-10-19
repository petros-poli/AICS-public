"""Request authentication: the AICS-1 section 12.1 binding, RFC 9421 signatures and the owner key.

There are no bearer tokens (DECISIONS.md #1).  The one native write is
``POST /v2/entries`` (:meth:`Authenticator.native_entry`): JSON
``{envelope: E, body: U64-or-null}``, no query string, identity content coding
and a known, bounded length, with an RFC 9421 signature by the key ``E`` names,
in the AICS profile (``aics_identity.http_signatures.AICS_VERIFY_POLICY``):

* covered components exactly ``@method @authority @path content-digest``, one
  signature labelled ``aics``, ``keyid`` the signer's ``did:key``;
* ``created``, ``expires``, ``nonce``, ``tag="aics"`` and ``alg="ed25519"``,
  ``keyid``, ``created``, ``expires`` and ``nonce`` equal to the envelope's
  (the request and its envelope are one attempt with one nonce);
* ``Content-Digest`` (``sha-256``) recomputed over the request bytes exactly
  as received, before the JSON is parsed.

``E`` is checked by :func:`aics_server.envelopes.verify_native_signature`
(the native ``ed25519-jcs`` scheme, this log's origin, a registered type, the
signature over ``D``), then for freshness at the submission time ``t`` fixed
when the request arrives (AICS-1 section 4.3).  The key is resolved as
section 12.1 says: a ``name.claim`` (and an upgrade, ``key.rotate`` of mode
``upgrade``) from the key its own payload names, so the signatures are the
proof of possession; the owner key (decision 3) from its configuration; any
other key from the log.

What fails is answered in three ways (AICS-1 section 10.2):

* traffic that is not an envelope submission at all (no signature, a digest
  that does not match the bytes, not the request object, an envelope that is
  not a well-formed native one, a query, an encoding or length the binding
  does not take) is rejected before logging, with an error and no leaf;
* a well-formed envelope that does not authenticate (a key the log does not
  know, an HTTP or envelope signature that does not verify, signature
  parameters that differ from the envelope's) is a policy-signed ``refusal``
  whose attempt fields are null (:meth:`aics_server.db.SanctuaryDB.refuse_unauthenticated`);
* an authenticated attempt that fails a rule (stale, a validity window that
  is not ``created < expires <= created + 300``, replayed, or any acceptance
  rule of its type) is a ``refusal`` naming its ``(kid, nonce, expires)``;
  the database records that tuple with the leaf.  Both signatures are
  verified before the window and the clock are looked at, so every window
  failure of a signed envelope is decided as an authenticated attempt.

Other signed requests use the same profile without an envelope and write no
leaf of their own: signed reads of an agent's own data, the owner login of
the administration endpoints, and the contribution requests of AICS-1
section 20.6 (``@query`` is covered as well when a read has a query).  Their
``(kid, nonce, expires)`` is the signed tuple, ``expires`` exactly as signed.
A read's nonce is remembered in memory and written in batches; an
administration write's and a contribution request's are recorded durably
before they act.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, replace
from typing import Any, Awaitable, Callable
from urllib.parse import quote

from fastapi import HTTPException, Request

from aics_identity import canonicalize
from aics_identity import envelope as envelope_mod
from aics_identity import http_signatures as http_sig
from aics_identity import keys
from aics_identity import sf

from . import envelopes as ev
from . import identity as ident
from .db import Refusal, Rejected, SanctuaryDB, SignedContext, decode_u64
from .strictjson import loads_bounded

__all__ = [
    "MAX_BODY_BYTES",
    "MAX_ENTRY_REQUEST_BYTES",
    "CLOCK_SKEW_SECONDS",
    "NONCE_BYTES",
    "ENTRY_MEMBERS",
    "RequestParts",
    "NativeSubmission",
    "EntryRefused",
    "Authenticator",
    "read_request",
    "refusal_exception",
    "rejected_exception",
    "remember_signed_write",
    "signed_write_of",
]

#: Largest request body of a signed request other than ``POST /v2/entries`` (bytes).
MAX_BODY_BYTES = 1024 * 1024
#: Largest ``POST /v2/entries`` request (AICS-1 section 12.1: a known, bounded length).  An entry is at most 65535
#: bytes, so its envelope is smaller still; a ciphertext body is at most 65536 bytes (87382 characters of U64).
MAX_ENTRY_REQUEST_BYTES = 256 * 1024
#: How far after ``t`` a signature's ``created`` may lie (AICS-1 section 4.3: 30 s, future creation only).
#: A literal, so the card's source checks can read it; the library's value must agree.
CLOCK_SKEW_SECONDS = 30
if CLOCK_SKEW_SECONDS != ev.FUTURE_SKEW:  # pragma: no cover - a library that disagrees with AICS-1
    raise ImportError(f"aics_identity's future bound is {ev.FUTURE_SKEW} s; AICS-1 section 4.3 says {CLOCK_SKEW_SECONDS}")
#: A nonce is exactly ``U64`` of 16 random bytes (AICS-1 section 4.3): 22 characters,
#: canonical.  It is stored with the request and embedded in every leaf the request
#: writes, so it must not be a channel for longer text.  A canonical nonce still
#: carries 16 bytes the signer chooses; the assurance card states that residual.
NONCE_BYTES = envelope_mod.NONCE_BYTES
#: The members of a ``POST /v2/entries`` request object, exactly (AICS-1 section 12.1).
ENTRY_MEMBERS = frozenset({"envelope", "body"})
#: Covers every clock bound in a cryptographic check: freshness is decided separately, at ``t`` (section 4.3).
_NO_CLOCK = 2**62

Dependency = Callable[[Request], Awaitable[SignedContext]]


def _error(status: int, error: str, message: str, headers: dict[str, str] | None = None) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": error, "message": message}, headers=headers)


def refusal_exception(exc: Refusal) -> HTTPException:
    headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
    return HTTPException(status_code=exc.status, detail=exc.detail(), headers=headers)


#: ``request.state`` member naming the authenticated write a request carries (its nonce is consumed).
SIGNED_WRITE_STATE = "aics_signed_write"


def remember_signed_write(request: Request, ctx: SignedContext) -> None:
    """Note on the request that it is an authenticated write whose nonce is spent.

    A failure after this point (an invalid request field) is a decision on
    the submission and is answered with a refusal leaf (AICS-1 section 10.2),
    not a bare error.
    """
    setattr(request.state, SIGNED_WRITE_STATE, ctx)


def signed_write_of(request: Request) -> SignedContext | None:
    """The authenticated write noted by :func:`remember_signed_write`, if any."""
    return getattr(request.state, SIGNED_WRITE_STATE, None)


@dataclass(frozen=True)
class RequestParts:
    """What the signature covers: method, the URL as sent (raw path), headers and body bytes."""

    method: str
    url: str
    headers: list[tuple[str, str]]
    body: bytes
    has_query: bool


def _parts(request: Request, body: bytes) -> RequestParts:
    raw_path = request.scope.get("raw_path")
    path = raw_path.decode("latin-1") if raw_path else quote(request.url.path)
    host = request.headers.get("host") or request.url.netloc
    query = (request.scope.get("query_string") or b"").decode("latin-1")
    url = f"{request.url.scheme}://{host}{path}" + (f"?{query}" if query else "")
    return RequestParts(
        method=request.method,
        url=url,
        headers=list(request.headers.items()),
        body=body,
        has_query=bool(query),
    )


async def read_request(request: Request) -> RequestParts:
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise _error(413, "too_large", f"request body exceeds {MAX_BODY_BYTES} bytes")
    return _parts(request, body)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON member {key!r}")
        out[key] = value
    return out


def _json_object(body: bytes) -> dict[str, Any]:
    if not body:
        return {}
    try:
        obj = loads_bounded(body.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, ValueError) as exc:  # JSONTooDeep is a ValueError: no RecursionError escapes
        raise _error(400, "malformed_json", f"request body is not a JSON object: {exc}") from None
    if not isinstance(obj, dict):
        raise _error(400, "malformed_json", "request body must be a JSON object")
    return obj


def service_request_problem(parts: RequestParts, fields: dict[str, Any]) -> str | None:
    """Why *parts* is no AICS-1 section 20.6 service request, or ``None``: no query, exactly JCS JSON content.

    (Section 20.6 also makes it an HTTPS ``POST``: the routes check the
    scheme before anything else, see ``aics_server.app.require_https_request``.)
    """
    if parts.has_query:
        return "a contribution request has no query (AICS-1 section 20.6)"
    try:
        canonical = canonicalize(fields)
    except (TypeError, ValueError):
        return "the content cannot be canonicalised"
    if canonical != parts.body:
        return "the content is exactly the JCS (RFC 8785) bytes of its JSON object (AICS-1 section 20.6)"
    return None


def _header_values(parts: RequestParts, name: str) -> list[str]:
    return [value for key, value in parts.headers if key.lower() == name]


def _require_signature_headers(parts: RequestParts) -> None:
    if not _header_values(parts, "signature-input") or not _header_values(parts, "signature"):
        raise _error(
            401,
            "signature_required",
            "sign the request with RFC 9421 (label aics, keyid = your did:key, tag=aics; see /static/aics_client.py)",
        )


#: HTTP status of an envelope check that failed (nothing admitted, no leaf).
_REJECTED_STATUS = {"bad_signature": 401, "unknown_key": 401, "expired": 401, "future": 401}


def rejected_exception(exc: ev.EnvelopeRejected) -> HTTPException:
    """An envelope that fails its structural, signature or freshness check (:mod:`aics_server.envelopes`)."""
    return _error(_REJECTED_STATUS.get(exc.code, 400), exc.code, exc.message)


def _window_error(exc: ev.EnvelopeRejected) -> HTTPException:
    if exc.code in ("future", "expired"):
        # AICS-1 section 4.3: the client resynchronizes and signs again; the server never changes signed times.
        return _error(401, exc.code, f"signature window: {exc.message}; resynchronize your clock and sign again")
    return _error(401, "malformed_signature", f"signature window: {exc.message}")


def _check_signature_window(parts: RequestParts, t: int) -> None:
    """AICS-1 section 4.3 on the ``aics`` signature's ``created``/``expires`` at *t*, before any key work.

    A freshness failure is reported as ``future`` or ``expired`` (AICS-1 section 17.2), not as a bad
    signature.  A header that does not parse is left to the library, which reports it as malformed.
    """
    values = _header_values(parts, "signature-input")
    try:
        member = sf.parse_dictionary(", ".join(values)).get(http_sig.AICS_LABEL)
        params = sf.params_to_dict(member.params) if member is not None else {}
    except (sf.ParseError, AttributeError):
        return
    created, expires = params.get("created"), params.get("expires")
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in (created, expires)):
        return
    try:
        ev.check_fresh({"created": created, "expires": expires}, t)
    except ev.EnvelopeRejected as exc:
        raise _window_error(exc) from None


def verify_http_signature(
    parts: RequestParts, resolve_key: Callable[[str], Any], t: int
) -> http_sig.VerifiedSignature:
    """Verify the RFC 9421 signature of a signed request without an envelope under the AICS profile at *t*."""
    _require_signature_headers(parts)
    _check_signature_window(parts, t)
    policy = dict(http_sig.AICS_VERIFY_POLICY)
    required = tuple(policy.pop("required_components"))
    if parts.has_query:
        # A signed read with a query (this server's extension; AICS-1 section 12.1 native writes carry none) also
        # covers @query, after the AICS components or among them.
        required += ("@query",)
        policy["exact_components"] = False
    try:
        verified = http_sig.verify_request(
            parts.method,
            parts.url,
            parts.headers,
            parts.body,
            resolve_key=resolve_key,
            required_components=required,
            max_clock_skew=CLOCK_SKEW_SECONDS,
            now=t,
            **policy,
        )
    except http_sig.MalformedSignature as exc:
        raise _error(401, "malformed_signature", str(exc)) from None
    except http_sig.UnknownKeyError as exc:
        raise _error(401, "unknown_key", str(exc)) from None
    except http_sig.SignatureError as exc:
        raise _error(401, "bad_signature", str(exc)) from None
    if len(verified) != 1:
        raise _error(401, "malformed_signature", "send exactly one signature")
    sig = verified[0]
    if not envelope_mod.is_canonical_nonce(sig.nonce, NONCE_BYTES):
        raise _error(
            401, "malformed_signature", "nonce must be unpadded base64url of exactly 16 random bytes (22 characters)"
        )
    if not keys.is_did_key(sig.keyid):
        raise _error(401, "malformed_signature", "keyid must be your did:key (AICS-1 section 3.1)")
    try:
        # AICS-1 section 4.3 at t, exactly, on what the library parsed (its request policy is wider at expiry).
        ev.check_fresh({"created": sig.created, "expires": sig.expires}, t)
    except ev.EnvelopeRejected as exc:
        raise _window_error(exc) from None
    return sig


# ----------------------------------------------------------------------
# POST /v2/entries (AICS-1 section 12.1)
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class NativeSubmission:
    """An authenticated native write, fresh and not a replay: its context and the exact body bytes (or ``None``)."""

    ctx: SignedContext
    body: bytes | None


class EntryRefused(Exception):
    """A logged refusal of a ``POST /v2/entries`` submission: answered with its entry and receipt (a 4xx)."""

    def __init__(self, refusal: Refusal) -> None:
        super().__init__(refusal.message)
        self.refusal = refusal


def _entry_problem(parts: RequestParts, request: Request) -> HTTPException | None:
    """Why a ``POST /v2/entries`` request is not one the binding takes at all, or ``None`` (no leaf for these).

    No query (the signature does not cover one), identity content coding, a
    declared length and no chunked transfer, at most
    :data:`MAX_ENTRY_REQUEST_BYTES` (AICS-1 section 12.1).
    """
    if parts.has_query:
        return _error(
            400, "malformed", "POST /v2/entries takes no query string: its signature covers none (AICS-1 section 12.1)"
        )
    encoding = [v.strip().lower() for v in _header_values(parts, "content-encoding")]
    if any(v not in ("", "identity") for v in encoding):
        return _error(415, "malformed", "POST /v2/entries takes identity content coding only (AICS-1 section 12.1)")
    if _header_values(parts, "transfer-encoding"):
        return _error(
            411, "malformed", "send a Content-Length: POST /v2/entries takes no chunked upload (AICS-1 section 12.1)"
        )
    declared = _header_values(parts, "content-length")
    if len(declared) != 1 or not declared[0].strip().isdigit():
        return _error(411, "malformed", "send exactly one Content-Length (AICS-1 section 12.1: a known body length)")
    return None


class Authenticator:
    """FastAPI dependencies that turn a signed request into a :class:`SignedContext`.

    ``allowed_hosts`` (``AICS_ALLOWED_HOSTS``): when set, a signed request must
    name one of these authorities, so a request signed for another host (for
    instance a test instance of the same API) cannot be replayed here by
    rewriting the ``Host`` header.  Envelopes are also bound to this log's origin.
    """

    def __init__(self, db: SanctuaryDB, *, allowed_hosts: set[str] | None = None) -> None:
        self.db = db
        self.allowed_hosts = {h.lower() for h in allowed_hosts} if allowed_hosts else None

    def _authority_problem(self, parts: RequestParts) -> HTTPException | None:
        if self.allowed_hosts is None:
            return None
        authority = http_sig.derived_component_value("@authority", method=parts.method, url=parts.url)
        if authority not in self.allowed_hosts:
            return _error(421, "wrong_authority", f"requests here are signed for {sorted(self.allowed_hosts)}")
        return None

    async def _read(self, request: Request) -> RequestParts:
        parts = await read_request(request)
        problem = self._authority_problem(parts)
        if problem is not None:
            raise problem
        return parts

    # -- context building ---------------------------------------------------

    def _context(
        self, parts: RequestParts, sig: http_sig.VerifiedSignature, public_key: Any, *, t: int, role: str, obj: dict | None = None
    ) -> SignedContext:
        """The context of a signed request without an envelope (it writes no leaf of its own).

        ``expires`` is the signed ``expires`` parameter, exactly: the end of the
        authenticated tuple's validity (AICS-1 sections 4.3 and 10.2), which a
        refusal names as ``attempt_expires`` and the nonce record keeps.  The
        signature passed AICS-1 section 4.3 at ``t`` (:func:`verify_http_signature`:
        ``t < expires <= created + 300``), so it is never extended here; the
        library's ``valid_until`` (an expiry widened by its clock skew) is not
        a value the client signed.
        """
        if not isinstance(sig.expires, int) or isinstance(sig.expires, bool):
            raise _error(401, "malformed_signature", "the signature carries no expires (AICS-1 section 12.1)")
        return SignedContext(
            kid=sig.keyid,
            public_key_b64u=keys.format_public_key(keys.as_public_key(public_key)),
            nonce=sig.nonce or "",
            expires=sig.expires,
            request_hash=hashlib.sha256(parts.body).hexdigest(),
            fields=dict(_json_object(parts.body) if obj is None else obj),
            role=role,
            t=t,
        )

    def _consume(self, ctx: SignedContext, *, log_refusal: bool) -> None:
        try:
            self.db.consume_nonce(ctx, log_refusal=log_refusal)
        except Refusal as exc:
            raise refusal_exception(exc) from None

    # -- POST /v2/entries -------------------------------------------------------

    def _resolve_entry_key(self, env: dict[str, Any]) -> tuple[Any, str, str | None]:
        """``(public key or None, role, why not)`` of the key *env* names (AICS-1 section 12.1).

        A ``name.claim`` resolves its key from its own ``ed25519`` and an
        upgrade (``key.rotate``, mode ``upgrade``) from its ``new_ed25519``:
        the signatures are then the proof of possession.  The owner key comes
        from the configuration, any other key from the log.  The service's
        log and policy keys never submit.
        """
        protected, q = env["protected"], env["payload"]
        kid, entry_type = protected["kid"], protected["type"]
        db = self.db
        if kid in (db.server_kid, db.policy_kid):
            return None, "service", "the service's own log and policy keys submit nothing"
        field = None
        if entry_type == "name.claim" or (entry_type == "agent.introduce" and q.get("member_index") is None):
            field = "ed25519"
        elif entry_type == "key.rotate" and q.get("mode") == "upgrade":
            field = "new_ed25519"
        if field is not None:
            try:
                claimed = ident.parse_ed25519(q.get(field), field)
            except ValueError as exc:
                return None, "claimant", f"{field} is not a usable Ed25519 key: {exc}"
            if keys.did_key(claimed) != kid:
                return None, "claimant", f"a {entry_type} is signed by the key it names: kid must be the did:key of {field}"
            return claimed, "claimant", None
        if db.owner_kid is not None and kid == db.owner_kid:
            return db.owner_public_key, "owner", None
        public = db.signing_key_for(kid)
        if public is None:
            return None, "agent", "no name holds this key: claim a name with it first (POST /v2/entries, name.claim)"
        return public, "agent", None

    def _unauthenticated(self, env: dict[str, Any], code: str, message: str) -> EntryRefused:
        """A refusal leaf with null attempt fields for a well-formed envelope that did not authenticate."""
        try:
            self.db.refuse_unauthenticated(envelope_mod.envelope_hash(env), code, message)
        except Refusal as refusal:
            if refusal.leaf is None:
                raise refusal_exception(refusal) from None
            return EntryRefused(refusal)
        raise AssertionError("refuse_unauthenticated always raises")  # pragma: no cover

    def _logged(self, call: Callable[[], Any]) -> EntryRefused:
        """Run a database refusal (it always raises) and wrap what it raised for the binding."""
        try:
            call()
        except Refusal as refusal:
            if refusal.leaf is None:
                raise refusal_exception(refusal) from None
            return EntryRefused(refusal)
        raise AssertionError("a refusal always raises")  # pragma: no cover

    def native_entry(self) -> Callable[[Request], Awaitable[NativeSubmission]]:
        """``POST /v2/entries``: the authenticated, fresh, not replayed native write, with its body bytes.

        Raises ``HTTPException`` for what is rejected before logging and
        :class:`EntryRefused` for a logged refusal (see the module docstring).
        """

        async def dependency(request: Request) -> NativeSubmission:
            t = int(time.time())
            declared = request.headers.get("content-length", "")
            if declared.strip().isdigit() and int(declared) > MAX_ENTRY_REQUEST_BYTES:
                raise _error(413, "too_large", f"POST /v2/entries takes at most {MAX_ENTRY_REQUEST_BYTES} bytes")
            body = await request.body()
            parts = _parts(request, body)
            problem = _entry_problem(parts, request) or self._authority_problem(parts)
            if problem is not None:
                raise problem
            if len(body) > MAX_ENTRY_REQUEST_BYTES:
                raise _error(413, "too_large", f"POST /v2/entries takes at most {MAX_ENTRY_REQUEST_BYTES} bytes")
            digests = _header_values(parts, "content-digest")
            if not digests:
                raise _error(
                    401,
                    "signature_required",
                    "POST /v2/entries carries Content-Digest and an RFC 9421 signature by the envelope's key "
                    "(AICS-1 section 12.1): a valid envelope alone does not excuse a missing request signature",
                )
            _require_signature_headers(parts)
            try:
                # Over the HTTP content exactly as received, before any JSON is parsed (AICS-1 section 12.1).
                http_sig.verify_content_digest(", ".join(digests), body)
            except http_sig.SignatureError as exc:
                raise _error(400, "digest_mismatch", f"Content-Digest does not match the request bytes: {exc}") from None
            obj = _json_object(body)
            if set(obj) != ENTRY_MEMBERS or not (obj["body"] is None or isinstance(obj["body"], str)):
                raise _error(
                    400, "malformed", "POST /v2/entries takes exactly {envelope: E, body: U64 or null} (AICS-1 section 12.1)"
                )
            env = obj["envelope"]
            try:
                # The validity window is checked after both signatures (below): an authenticated attempt outside
                # it is a logged refusal naming its tuple (AICS-1 sections 4.3 and 10.2), not a bare 400.
                scheme = ev.structure(env, origin=self.db.origin, window=False)
            except ev.EnvelopeRejected as exc:
                raise _error(400, exc.code, f"not an AICS-1 envelope of this log: {exc.message}") from None
            if scheme != ev.NATIVE:
                raise _error(
                    400,
                    "unsupported_scheme",
                    f"POST /v2/entries takes {ev.NATIVE} envelopes; gate-signed envelopes and the shared-secret "
                    "fallback go to the text gate (/t, AICS-1 sections 11 and 12.1)",
                )
            public, role, why = self._resolve_entry_key(env)
            if public is None:
                raise self._unauthenticated(env, "unknown_key", why or "unknown key")
            try:
                http_sig.verify_request(
                    parts.method,
                    parts.url,
                    parts.headers,
                    body,
                    resolve_key=lambda keyid: public if keyid == env["protected"]["kid"] else None,
                    required_components=http_sig.AICS_COMPONENTS,
                    exact_components=True,
                    require_content_digest_covered=True,
                    require_expires=True,
                    require_nonce=True,
                    require_tag=http_sig.AICS_TAG,
                    require_label=http_sig.AICS_LABEL,
                    require_alg=True,
                    max_age=None,
                    max_lifetime=None,
                    max_clock_skew=_NO_CLOCK,
                    # AICS-1 section 4.3 is decided below, at t, once both signatures verified.
                    freshness=False,
                    envelope=env,
                    now=t,
                )
            except http_sig.SignatureError as exc:
                raise self._unauthenticated(
                    env, "bad_signature", f"the RFC 9421 signature does not authenticate this envelope: {exc}"
                ) from None
            try:
                checked = ev.verify_native_signature(env, origin=self.db.origin, resolve_key=lambda kid: public)
            except ev.EnvelopeRejected as exc:
                if not exc.authenticated:
                    raise self._unauthenticated(env, exc.code, exc.message) from None
                # Both signatures verified; the validity window is not created < expires <= created + 300.
                window = SignedContext.of_envelope(ev.checked(env, scheme), t=t, role=role, public_key=public)
                message = f"validity window: {exc.message}; sign a new envelope (AICS-1 section 4.3)"
                raise self._logged(lambda: self.db.refuse_stale(window, "malformed", message)) from None
            ctx = SignedContext.of_envelope(checked, t=t, role=role, public_key=public)
            try:
                ev.check_fresh(env["protected"], t)
            except ev.EnvelopeRejected as exc:
                code = exc.code
                message = f"{exc.message}; resynchronize your clock and sign a new envelope (AICS-1 section 4.3)"
                raise self._logged(lambda: self.db.refuse_stale(ctx, code, message)) from None
            try:
                self.db.consume_nonce(ctx, log_refusal=True)
            except Refusal as refusal:
                if refusal.leaf is None:
                    raise refusal_exception(refusal) from None
                raise EntryRefused(refusal) from None
            raw = None
            if obj["body"] is not None:
                raw = decode_u64(obj["body"])
                if raw is None:
                    raise self._logged(
                        lambda: self.db.refuse_failure(
                            ctx, Rejected("malformed", "body is U64: unpadded base64url of the exact body bytes")
                        )
                    )
            remember_signed_write(request, ctx)
            return NativeSubmission(ctx, raw)

        return dependency

    # -- signed requests without an envelope ---------------------------------------

    def service_request(self) -> Dependency:
        """A signed service request that never writes a leaf (a contribution intent, AICS-1 section 20.6).

        RFC 9421 by an established agent's key, no envelope; its nonce is
        recorded durably at once and a replay is refused without a leaf.  It
        is not noted as an authenticated write: a request that fails is
        answered with an error and no entry, whatever failed.
        """

        async def dependency(request: Request) -> SignedContext:
            t = int(time.time())
            parts = await self._read(request)
            sig = verify_http_signature(parts, self.db.signing_key_for, t)
            ctx = self._context(parts, sig, self.db.signing_key_for(sig.keyid), t=t, role="agent")
            try:
                self.db.consume_nonce(ctx, service=True)
            except Refusal as exc:
                raise refusal_exception(exc) from None
            problem = service_request_problem(parts, ctx.fields)  # after the nonce: a copy cannot be resent fixed
            if problem is not None:
                raise _error(400, "malformed", problem)
            return ctx

        return dependency

    def contribution_claim(self) -> Dependency:
        """A contribution claim (AICS-1 section 20.6): an envelope-less signed write whose refusal is a leaf.

        Its ``request_hash`` (and so a refusal's ``envelope_hash``) is the
        keyed HMAC of the exact request content
        (:meth:`aics_server.db.SanctuaryDB.contribution_claim_hash`), never the
        plain hash: the content names a transaction.
        """

        async def dependency(request: Request) -> SignedContext:
            t = int(time.time())
            parts = await self._read(request)
            sig = verify_http_signature(parts, self.db.signing_key_for, t)
            ctx = self._context(parts, sig, self.db.signing_key_for(sig.keyid), t=t, role="agent")
            ctx = replace(ctx, request_hash=self.db.contribution_claim_hash(parts.body))
            self._consume(ctx, log_refusal=True)
            remember_signed_write(request, ctx)
            problem = service_request_problem(parts, ctx.fields)
            if problem is not None:
                try:
                    self.db.refuse_failure(ctx, Rejected("malformed", problem))
                except Refusal as exc:
                    raise refusal_exception(exc) from None
            return ctx

        return dependency

    def agent_read(self) -> Dependency:
        """A signed read of the agent's own data (no envelope, nothing logged)."""

        async def dependency(request: Request) -> SignedContext:
            t = int(time.time())
            parts = await self._read(request)
            sig = verify_http_signature(parts, self.db.signing_key_for, t)
            ctx = self._context(parts, sig, self.db.signing_key_for(sig.keyid), t=t, role="agent", obj={})
            self._consume(ctx, log_refusal=False)
            return ctx

        return dependency

    # -- the owner login --------------------------------------------------------------

    def _owner_signature(self, parts: RequestParts, t: int) -> http_sig.VerifiedSignature:
        if self.db.owner_kid is None:
            raise _error(503, "owner_login_not_configured", "no owner key is configured (AICS_OWNER_PUBKEY)")
        try:
            return verify_http_signature(parts, self.db.owner_key_for, t)
        except HTTPException as exc:
            if isinstance(exc.detail, dict) and exc.detail.get("error") == "unknown_key":
                raise _error(403, "owner_only", "only the owner key may do this") from None
            raise

    def owner(self) -> Dependency:
        """Owner login (decision 3): a request signed by the configured owner key, no envelope.

        The administration endpoints ask the service to write a policy-signed
        leaf (AICS-1 section 5.1: administrative entries use the policy key as
        actor); the owner's own entries (quotes, completions, tasks, awards)
        are native writes at ``POST /v2/entries``, signed by the owner key.
        """

        async def dependency(request: Request) -> SignedContext:
            t = int(time.time())
            parts = await self._read(request)
            sig = self._owner_signature(parts, t)
            ctx = self._context(parts, sig, self.db.owner_public_key, t=t, role="owner")
            if request.method in ("GET", "HEAD"):
                self._consume(ctx, log_refusal=False)  # a read of the notice register: batched like signed reads
            else:
                # An administration write (a tombstone, a suspension, a freeze, an audit, a policy, a notice's
                # close): its nonce is recorded durably before it acts (AICS-1 section 12.1), so neither a replay
                # nor a restart can make it act twice.  A replay is answered without a leaf.
                try:
                    self.db.consume_nonce(ctx, service=True)
                except Refusal as exc:
                    raise refusal_exception(exc) from None
            return ctx

        return dependency

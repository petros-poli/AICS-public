"""RFC 9421 HTTP Message Signatures (Ed25519) with RFC 9530 Content-Digest.

An agent signs every request; a peer verifies authorship by machine.

Signing adds three headers to the request; by default exactly the AICS-1
section 12.1 profile (label ``aics``, ``keyid`` the signer's ``did:key``,
``tag="aics"``, ``alg="ed25519"``, covering ``@method @authority @path
content-digest`` in that order)::

    Content-Digest: sha-256=:<base64(sha-256(body))>:      (RFC 9530)
    Signature-Input: aics=("@method" "@authority" "@path" "content-digest");created=...;expires=...;nonce="...";alg="ed25519";keyid="did:key:z6Mk...";tag="aics"
    Signature: aics=:<base64(Ed25519(signature-base))>:

For ``POST /v2/entries`` the request carries an envelope, and its
``created``, ``expires``, ``nonce`` and ``keyid`` MUST equal the envelope's
(AICS-1 section 12.1): ``sign_request(..., envelope=E)`` takes them from it and
``verify_request(..., envelope=E)`` requires them.

Supported derived components: ``@method``, ``@authority``, ``@path``,
``@query``, ``@target-uri`` (plus ``@scheme`` and ``@request-target``).
Any ordinary header field may also be covered by name, e.g.
``content-digest``, ``content-type`` or ``date``.

The signature base is built exactly per RFC 9421 section 2.5: one
``"identifier": value`` line per covered component, then a final
``"@signature-params": <params>``, each line terminated by ``\\n``.  The
Ed25519 signature is taken over those bytes directly.  The RFC 9421
Appendix B.2.6 Ed25519 test vector is reproduced byte-for-byte (see
``tests/test_http_signatures.py``).

Signing defaults: ``created`` = now, ``expires`` = ``created`` + 300 s, a
random ``nonce`` (U64 of 16 bytes), ``keyid`` = the key's ``did:key``, label
``aics``, ``tag="aics"``, ``alg="ed25519"`` and :data:`AICS_COMPONENTS`; pass
``expires=None`` / ``nonce=None`` / ``tag=None`` / ``alg=None`` to omit those
parameters (as the RFC test vectors do).

Verification policy (:func:`verify_request`), per signature label:

* ``created`` at most ``max_clock_skew`` (60 s) in the future and at most
  ``max_age`` (300 s) in the past;
* ``expires`` present (unless ``require_expires=False``), not before
  ``created``, at most ``max_lifetime`` (300 s) after it, and not passed by
  more than ``max_clock_skew``;
* ``nonce`` present when ``require_nonce`` is set or a replay check is
  given; ``tag`` equal to ``require_tag`` when that is given;
* the required components covered, ``content-digest`` among them when
  ``require_content_digest_covered`` is set, and any ``Content-Digest``
  header present matching the body;
* the Ed25519 signature;
* last, when ``replay_check`` is given, a fresh ``(keyid, nonce)``: the hook
  lets a server keep the replay record in its database
  (:mod:`aics_identity.replay`).

The AICS server profile (AICS-1 section 12.1) is :data:`AICS_VERIFY_POLICY`::

    verify_request(method, url, headers, body, resolve_key=resolve, envelope=E,
                   **AICS_VERIFY_POLICY)

which requires exactly one signature, labelled ``aics``, covering exactly
:data:`AICS_COMPONENTS` in order, with ``created``, ``expires``, ``nonce``,
``keyid``, ``tag="aics"`` and ``alg="ed25519"``.  A client signs to it with
``sign_request(method, url, headers, body, key=key, envelope=E)``.  The
envelope's own section 4.3 check (:func:`aics_identity.envelope.verify_envelope`)
decides freshness; the HTTP and envelope nonce are one logical attempt, so
give the durable replay hook to one of the two verifiers, not both.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature

from . import keys as _keys
from .replay import ReplayCheck
from .sf import ParseError, byte_sequence, dictionary_serialization, inner_list_serialization, parse_dictionary, params_to_dict

__all__ = [
    "DEFAULT_LABEL",
    "AICS_LABEL",
    "ALG",
    "AUTO",
    "DEFAULT_MAX_CLOCK_SKEW",
    "DEFAULT_MAX_AGE",
    "DEFAULT_LIFETIME",
    "MAX_NONCE_LENGTH",
    "DEFAULT_COMPONENTS",
    "DERIVED_COMPONENTS",
    "AICS_TAG",
    "AICS_COMPONENTS",
    "AICS_VERIFY_POLICY",
    "SignatureError",
    "MalformedSignature",
    "UnknownKeyError",
    "VerificationFailed",
    "ReplayedSignature",
    "VerifiedSignature",
    "sign_request",
    "verify_request",
    "signature_base",
    "content_digest_header",
    "verify_content_digest",
]

#: The one signature label of AICS-1 section 12.1, and the signing default.
AICS_LABEL = "aics"
DEFAULT_LABEL = AICS_LABEL
ALG = "ed25519"
#: Tolerance (seconds) for a signer clock running ahead, and for ``expires``.
DEFAULT_MAX_CLOCK_SKEW = 60
#: ``created`` older than this many seconds is refused (DESIGN.md section 4.2 item 1).
DEFAULT_MAX_AGE = 300
#: ``sign_request`` sets ``expires = created + DEFAULT_LIFETIME``; ``verify_request``
#: refuses ``expires - created`` above it.
DEFAULT_LIFETIME = 300
#: Longest ``nonce`` accepted; nonces end up in the server's replay table.
MAX_NONCE_LENGTH = 256
#: Components :func:`verify_request` requires by default (signing covers :data:`AICS_COMPONENTS`).
DEFAULT_COMPONENTS = ("@method", "@authority", "@path")

#: ``tag`` signature parameter of AICS requests.
AICS_TAG = "aics"
#: Components every AICS request signature covers, in this order (AICS-1 section 12.1).
AICS_COMPONENTS = ("@method", "@authority", "@path", "content-digest")
#: ``verify_request(..., **AICS_VERIFY_POLICY)``: the AICS-1 section 12.1 requirements.
AICS_VERIFY_POLICY: Mapping[str, Any] = MappingProxyType({
    "required_components": AICS_COMPONENTS,
    "exact_components": True,
    "require_content_digest_covered": True,
    "require_expires": True,
    "require_nonce": True,
    "require_tag": AICS_TAG,
    "require_label": AICS_LABEL,
    "require_alg": True,
    "max_age": DEFAULT_MAX_AGE,
    "max_lifetime": DEFAULT_LIFETIME,
})

#: Derived (non-header) components supported by this implementation.
DERIVED_COMPONENTS = frozenset(
    {"@method", "@authority", "@path", "@query", "@target-uri", "@scheme", "@request-target"}
)

_DEFAULT_PORTS = {"http": 80, "https": 443}

ResolveKey = Callable[[str], Any]


class _Auto:
    """Type of :data:`AUTO`."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "AUTO"


#: Default for ``sign_request``'s ``nonce`` and ``expires``: let the library choose.
AUTO: Any = _Auto()


class SignatureError(Exception):
    """Base error for HTTP message signature operations."""


class MalformedSignature(SignatureError):
    """Signature-Input / Signature headers are absent or unparsable."""


class UnknownKeyError(SignatureError):
    """``resolve_key`` returned no key for the ``keyid`` parameter."""


class VerificationFailed(SignatureError):
    """The signature, a policy, freshness or body-integrity check failed."""


class ReplayedSignature(VerificationFailed):
    """The replay check reports that this ``(keyid, nonce)`` was already accepted."""

    def __init__(self, message: str, *, keyid: str, nonce: str, label: str) -> None:
        super().__init__(message)
        self.keyid = keyid
        self.nonce = nonce
        self.label = label


@dataclass(frozen=True)
class VerifiedSignature:
    """Details of one successfully verified RFC 9421 signature."""

    label: str
    keyid: str
    alg: str
    created: int
    expires: int | None
    nonce: str | None
    tag: str | None
    components: tuple[str, ...]
    signature_base: str
    #: Last unix second at which this signature passes the policy it was
    #: verified under (``None`` when neither ``expires`` nor ``max_age`` bounds it).
    #: A replay record for ``(keyid, nonce)`` must be kept at least this long.
    valid_until: int | None = None


# ----------------------------------------------------------------------
# URL / component derivation
# ----------------------------------------------------------------------

def _split(url: str):
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise ValueError(f"url must be absolute with a scheme and host: {url!r}")
    return parts


def _authority(url: str) -> str:
    parts = _split(url)
    host = (parts.hostname or "").lower()
    if parts.port is not None and parts.port != _DEFAULT_PORTS.get(parts.scheme.lower()):
        return f"{host}:{parts.port}"
    return host


def _path(url: str) -> str:
    parts = _split(url)
    return parts.path or "/"


def _query(url: str) -> str:
    """RFC 9421 2.2.4: '?' + query, or just '?' when absent."""
    parts = _split(url)
    return "?" + (parts.query or "")


def _target_uri(url: str) -> str:
    parts = _split(url)
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme.lower()}://{_authority(url)}{path}{query}"


def derived_component_value(name: str, *, method: str, url: str) -> str:
    lowered = name.lower()
    if lowered == "@method":
        return method.upper()
    if lowered == "@authority":
        return _authority(url)
    if lowered == "@path":
        return _path(url)
    if lowered == "@query":
        return _query(url)
    if lowered == "@target-uri":
        return _target_uri(url)
    if lowered == "@scheme":
        return _split(url).scheme.lower()
    if lowered == "@request-target":
        parts = _split(url)
        return f"{parts.path or '/'}?{parts.query or ''}"
    raise ValueError(f"unsupported derived component: {name!r}")


# ----------------------------------------------------------------------
# header handling
# ----------------------------------------------------------------------

def normalize_headers(headers: Any) -> list[tuple[str, str]]:
    """Normalise a mapping or pair-sequence into an ordered list of ``(name, value)``."""
    pairs: list[tuple[str, str]] = []
    if headers is None:
        return pairs
    if isinstance(headers, Mapping):
        items: Iterable[tuple[Any, Any]] = headers.items()
    else:
        items = headers
    for name, value in items:
        name = str(name)
        if isinstance(value, (list, tuple)):
            for one in value:
                pairs.append((name, str(one)))
        else:
            pairs.append((name, str(value)))
    return pairs


def _get_header_values(headers: Sequence[tuple[str, str]], name: str) -> list[str]:
    lowered = name.lower()
    return [v.strip() for (n, v) in headers if n.lower() == lowered]


def message_component_value(name: str, headers: Sequence[tuple[str, str]]) -> str:
    """Canonical value of a header-field component (observed form, ','-joined)."""
    values = _get_header_values(headers, name)
    if not values:
        raise KeyError(f"header field not present: {name!r}")
    return ", ".join(values)


def component_value(
    name: str,
    *,
    method: str,
    url: str,
    headers: Sequence[tuple[str, str]],
) -> str:
    """Value of any covered component (derived or header field)."""
    lowered = name.lower()
    if lowered.startswith("@"):
        return derived_component_value(lowered, method=method, url=url)
    return message_component_value(lowered, headers)


def signature_base(
    components: Sequence[str],
    signature_params_serialized: str,
    *,
    method: str,
    url: str,
    headers: Any,
) -> bytes:
    """Build the RFC 9421 section 2.5 signature base (US-ASCII bytes).

    Each covered-component line is ``"identifier": value`` terminated by
    a single ``\\n``; the final ``"@signature-params"`` line carries no
    trailing newline (RFC 9421 section 2.5 steps 2.7/3).
    """
    header_pairs = normalize_headers(headers)
    lines: list[str] = []
    seen = set()
    for component in components:
        lowered = component.lower()
        if lowered.startswith("@") and lowered not in DERIVED_COMPONENTS:
            raise ValueError(f"unsupported derived component: {component!r}")
        if lowered in seen:  # RFC 9421 section 2.5 step 2.1
            raise VerificationFailed(f"duplicate covered component: {component!r}")
        seen.add(lowered)
        try:
            value = component_value(lowered, method=method, url=url, headers=header_pairs)
        except KeyError as exc:
            raise VerificationFailed(str(exc)) from exc
        lines.append(f'"{lowered}": {value}\n')
    lines.append(f'"@signature-params": {signature_params_serialized}')
    base = "".join(lines)
    try:
        return base.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SignatureError("signature base must be US-ASCII encodable") from exc


# ----------------------------------------------------------------------
# RFC 9530 Content-Digest
# ----------------------------------------------------------------------

_DIGEST_ALGS = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}


def content_digest_header(body: bytes, algorithms: Sequence[str] = ("sha-256",)) -> str:
    """RFC 9530 Content-Digest value, e.g. ``sha-256=:base64:``."""
    entries: list[tuple[str, bytes]] = []
    for alg in algorithms:
        hasher = _DIGEST_ALGS.get(alg.lower())
        if hasher is None:
            raise ValueError(f"unsupported digest algorithm: {alg!r}")
        entries.append((alg.lower(), hasher(body).digest()))
    return dictionary_serialization([(k, v) for k, v in entries])


def verify_content_digest(header_value: str, body: bytes) -> list[str]:
    """Validate a Content-Digest header against *body*; returns matched algorithms.

    Every supported entry present must match; at least one supported
    entry must be present (RFC 9530 section 5).
    """
    try:
        parsed = parse_dictionary(header_value)
    except ParseError as exc:
        raise VerificationFailed(f"unparsable Content-Digest: {exc}") from exc
    if not parsed:
        raise VerificationFailed("empty Content-Digest")
    matched: list[str] = []
    seen_supported = False
    for alg, item in parsed.items():
        hasher = _DIGEST_ALGS.get(str(alg).lower())
        if hasher is None:
            continue  # unknown algorithm: skip per RFC 9530, fail later if none match
        seen_supported = True
        value = getattr(item, "value", item)
        if not isinstance(value, (bytes, bytearray)):
            raise VerificationFailed(f"Content-Digest {alg} is not a byte sequence")
        if bytes(value) != hasher(body).digest():
            raise VerificationFailed(f"Content-Digest {alg} does not match body")
        matched.append(str(alg).lower())
    if not seen_supported:
        raise VerificationFailed("no supported digest algorithm in Content-Digest")
    return matched


# ----------------------------------------------------------------------
# signing
# ----------------------------------------------------------------------

def _ordered_signature_params(
    *,
    created: int,
    expires: int | None,
    nonce: str | None,
    keyid: str,
    tag: str | None,
    alg: str | None = ALG,
) -> list[tuple[str, Any]]:
    """Signature parameters in the order used by all RFC 9421 examples.

    ``alg`` is omitted entirely when ``None`` (the RFC 9421 B.2.6 test
    vector does not carry an ``alg`` parameter).
    """
    params: list[tuple[str, Any]] = [("created", int(created))]
    if expires is not None:
        params.append(("expires", int(expires)))
    if nonce is not None:
        params.append(("nonce", str(nonce)))
    if alg is not None:
        params.append(("alg", str(alg)))
    params.append(("keyid", str(keyid)))
    if tag is not None:
        params.append(("tag", str(tag)))
    return params


def _envelope_binding(envelope: Any) -> dict[str, Any]:
    """``keyid``, ``nonce``, ``created`` and ``expires`` of an envelope's protected header (AICS-1 section 12.1)."""
    protected = envelope.get("protected") if isinstance(envelope, Mapping) else None
    if not isinstance(protected, Mapping) or not all(n in protected for n in ("kid", "nonce", "created", "expires")):
        raise ValueError("envelope must be an AICS-1 envelope with protected kid, nonce, created and expires")
    return {"keyid": protected["kid"], "nonce": protected["nonce"], "created": protected["created"],
            "expires": protected["expires"]}


def sign_request(
    method: str,
    url: str,
    headers: Any = None,
    body: bytes = b"",
    *,
    key: Any,
    keyid: str | None = None,
    nonce: str | None = AUTO,
    tag: str | None = AICS_TAG,
    created: int | float | None = None,
    expires: int | float | None = AUTO,
    components: Sequence[str] | None = None,
    label: str = DEFAULT_LABEL,
    add_content_digest: bool = True,
    alg: str | None = ALG,
    envelope: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return request headers (copies of *headers* plus the signature headers).

    Multi-value input headers are preserved (returned as lists); the
    signature covers them in their RFC 9421 canonical ", "-joined form.

    Parameters
    ----------
    method, url:
        Request line and absolute URL the signature will cover.
    headers:
        Headers to include with the request (a mapping or pair sequence).
        Any of these may be covered by name in *components*.
    body:
        Raw request body bytes (``b""`` for bodyless requests).
    key:
        Ed25519 private key (or 32-byte seed).
    keyid:
        Key id advertised in the ``keyid`` signature parameter.  Default: the
        signing key's ``did:key``, the AICS-1 kid.
    nonce:
        Unique per key and validity window.  Default (:data:`AUTO`): a fresh
        U64 of 16 random bytes.  ``None`` omits the parameter.
    tag:
        ``"aics"`` by default (:data:`AICS_TAG`); ``None`` omits it.
    created:
        Unix seconds; defaults to now.
    expires:
        Unix seconds.  Default (:data:`AUTO`): ``created + DEFAULT_LIFETIME``.
        ``None`` omits the parameter (verifiers following this library's
        default policy then refuse the signature).
    components:
        Covered component identifiers.  Defaults to :data:`AICS_COMPONENTS`;
        ``"content-digest"`` is appended to a given list when a body is
        present and the list lacks it.
    label:
        Signature label (``aics`` by default, the one label of AICS-1).
    envelope:
        The envelope this request carries (``POST /v2/entries``): ``keyid``,
        ``nonce``, ``created`` and ``expires`` are taken from its protected
        header; values passed as well must equal them, and *key* must be the
        key the envelope's kid names.
    add_content_digest:
        When the covered components include ``content-digest`` and the
        caller did not supply a ``Content-Digest`` header, add one
        (RFC 9530, sha-256).
    alg:
        The ``alg`` signature parameter to advertise (default
        ``"ed25519"``); pass ``None`` to omit the parameter entirely,
        as the RFC 9421 B.2.6 test vector does.
    """
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError("body must be bytes")
    body = bytes(body)
    private = _coerce_private(key)
    own_kid = _keys.did_key(private.public_key())
    if envelope is not None:
        bound = _envelope_binding(envelope)
        for name, given in (("keyid", keyid), ("nonce", nonce), ("created", created), ("expires", expires)):
            if given is not None and given is not AUTO and given != bound[name]:
                raise ValueError(f"{name} differs from the envelope's (AICS-1 section 12.1: they must be equal)")
        if bound["keyid"] != own_kid:
            raise ValueError("the envelope's kid is not this key's did:key: the same key signs both")
        keyid, nonce, created, expires = bound["keyid"], bound["nonce"], bound["created"], bound["expires"]
    if keyid is None:
        keyid = own_kid
    created = int(created) if created is not None else int(time.time())
    if expires is AUTO:
        expires = created + DEFAULT_LIFETIME
    elif expires is not None:
        expires = int(expires)
    if nonce is AUTO:
        nonce = _keys.b64u_encode(secrets.token_bytes(16))
    elif nonce is not None and (not isinstance(nonce, str) or not nonce):
        raise ValueError("nonce must be a non-empty string, AUTO or None")

    # Multi-value headers are preserved: name -> list of values (in order).
    out: dict[str, list[str]] = {}
    for name, value in normalize_headers(headers):
        out.setdefault(name, []).append(value)

    covered = list(components) if components is not None else list(AICS_COMPONENTS)
    if body and "content-digest" not in covered and add_content_digest:
        covered.append("content-digest")
    lowered = []
    for c in covered:
        cl = c.lower()
        if cl in lowered:  # RFC 9421 section 2.5 step 2.1
            raise ValueError(f"duplicate covered component: {c!r}")
        lowered.append(cl)
    covered = lowered

    has_digest = any(n.lower() == "content-digest" for n in out)
    if "content-digest" in covered and add_content_digest and not has_digest:
        out["Content-Digest"] = [content_digest_header(body)]

    params = _ordered_signature_params(created=created, expires=expires, nonce=nonce, keyid=keyid, tag=tag, alg=alg)
    sig_params = inner_list_serialization(covered, params)
    base = signature_base(covered, sig_params, method=method, url=url, headers=out)
    signature = private.sign(base)

    out["Signature-Input"] = [f"{label}={sig_params}"]
    out["Signature"] = [f"{label}={byte_sequence(signature)}"]
    # single-value headers collapse back to plain strings for convenience
    return {name: (values[0] if len(values) == 1 else values) for name, values in out.items()}


# ----------------------------------------------------------------------
# verification
# ----------------------------------------------------------------------

def verify_request(
    method: str,
    url: str,
    headers: Any,
    body: bytes = b"",
    *,
    resolve_key: ResolveKey,
    max_clock_skew: int | float = DEFAULT_MAX_CLOCK_SKEW,
    max_age: int | float | None = DEFAULT_MAX_AGE,
    require_expires: bool = True,
    max_lifetime: int | float | None = DEFAULT_LIFETIME,
    require_nonce: bool = False,
    require_tag: str | None = None,
    required_components: Sequence[str] = DEFAULT_COMPONENTS,
    require_content_digest_covered: bool = False,
    exact_components: bool = False,
    require_label: str | None = None,
    require_alg: bool = False,
    envelope: Mapping[str, Any] | None = None,
    replay_check: ReplayCheck | None = None,
    now: int | float | None = None,
    freshness: bool = True,
) -> list[VerifiedSignature]:
    """Verify every signature on *headers*; return the details of each one.

    ``resolve_key(keyid)`` must return an Ed25519 key (private or public key
    object, raw 32 bytes, base64url, ``did:key`` or ``ssh-ed25519`` text) or
    ``None`` for an unknown keyid.

    Every label present in both ``Signature-Input`` and ``Signature`` is
    checked, and all of them must pass.  With ``require_label`` the headers
    must carry exactly one signature, under that label (AICS-1: ``aics``).
    Per label, in order:

    1. structure: the ``Signature-Input`` member is an inner list of
       component names; ``created`` is an integer; ``expires``, if present,
       is an integer; ``keyid`` is a non-empty string; ``nonce``, if
       present, is a non-empty string of at most :data:`MAX_NONCE_LENGTH`
       characters; ``tag``, if present, is a string; ``alg``, if present,
       is ``"ed25519"``;
    2. required parameters: ``expires`` when ``require_expires`` (the
       default); ``nonce`` when ``require_nonce`` or when ``replay_check``
       is given; ``tag`` equal to ``require_tag`` when that is given;
       ``alg`` when ``require_alg``;
    3. freshness against ``now`` (default: the current time):
       ``created <= now + max_clock_skew`` (not from the future);
       ``now - created <= max_age`` unless ``max_age`` is ``None`` (not too
       old; the skew does not extend this bound);
       ``created <= expires``, ``expires - created <= max_lifetime`` unless
       ``max_lifetime`` is ``None``, and ``now <= expires + max_clock_skew``;
    4. every name in ``required_components`` is covered (exactly those, in
       that order, with ``exact_components``), and ``content-digest`` is
       covered when ``require_content_digest_covered`` is true, with or
       without a body;
    5. a covered ``content-digest`` header is present, and any
       ``Content-Digest`` header present matches *body*, covered or not;
    6. ``resolve_key`` knows the keyid, the key is not a small-order or
       non-canonical point (:func:`aics_identity.keys.validate_public_key_bytes`),
       and the Ed25519 signature over the RFC 9421 signature base verifies.

    With ``envelope=`` (``POST /v2/entries``) there must be exactly one
    signature, and its ``keyid``, ``nonce``, ``created`` and ``expires`` must
    equal the envelope's protected values (AICS-1 section 12.1).

    ``freshness=False`` skips step 3 entirely (every clock and window bound,
    ``created <= expires`` included) for a caller that decides AICS-1 section
    4.3 itself at its fixed submission time, after authentication, so that
    an authenticated attempt outside its window can be logged as a refusal
    (section 10.2).  ``created`` and ``expires`` must still parse.

    Only after every label has passed is
    ``replay_check(keyid, nonce, valid_until, now)`` called for each one
    (see :mod:`aics_identity.replay`); a ``False`` result raises
    :class:`ReplayedSignature`.  A forged, stale or malformed request
    therefore never consumes a nonce.

    Failures raise :class:`MalformedSignature` (structure, missing required
    parameters), :class:`UnknownKeyError`, :class:`VerificationFailed`
    (policy, freshness, coverage, digest, signature) or its subclass
    :class:`ReplayedSignature`.
    """
    if not isinstance(body, (bytes, bytearray)):
        raise TypeError("body must be bytes")
    body = bytes(body)
    current = int(now) if now is not None else int(time.time())
    header_pairs = normalize_headers(headers)

    sig_input_raw = _get_header_values(header_pairs, "Signature-Input")
    if not sig_input_raw:
        raise MalformedSignature("missing Signature-Input header")
    sig_raw = _get_header_values(header_pairs, "Signature")
    if not sig_raw:
        raise MalformedSignature("missing Signature header")

    try:
        sig_inputs = parse_dictionary(", ".join(sig_input_raw))
        sigs = parse_dictionary(", ".join(sig_raw))
    except ParseError as exc:
        raise MalformedSignature(str(exc)) from exc

    labels = [label for label in sig_inputs if label in sigs]
    if not labels:
        raise MalformedSignature("no signature label present in both Signature-Input and Signature")
    if require_label is not None and (list(sig_inputs) != [require_label] or list(sigs) != [require_label]):
        raise VerificationFailed(f"the request must carry exactly one signature, labelled {require_label!r}")

    policy = _Policy(
        max_clock_skew=max_clock_skew,
        max_age=max_age,
        require_expires=require_expires,
        max_lifetime=max_lifetime,
        require_nonce=require_nonce or replay_check is not None,
        require_tag=require_tag,
        required_components=tuple(c.lower() for c in required_components),
        require_content_digest_covered=require_content_digest_covered,
        exact_components=exact_components,
        require_alg=require_alg,
        freshness=freshness,
    )
    verified: list[VerifiedSignature] = []
    for label in labels:
        verified.append(
            _verify_one(
                label,
                sig_inputs[label],
                sigs[label],
                method=method,
                url=url,
                header_pairs=header_pairs,
                body=body,
                resolve_key=resolve_key,
                policy=policy,
                now=current,
            )
        )

    if envelope is not None:
        try:
            bound = _envelope_binding(envelope)
        except ValueError as exc:
            raise VerificationFailed(str(exc)) from None
        if len(verified) != 1:
            raise VerificationFailed("a request carrying an envelope has exactly one signature")
        sig = verified[0]
        for name, value in (("keyid", sig.keyid), ("nonce", sig.nonce), ("created", sig.created),
                            ("expires", sig.expires)):
            if value != bound[name]:
                raise VerificationFailed(
                    f"signature {sig.label!r} {name} differs from the envelope's (AICS-1 section 12.1)")

    if replay_check is not None:
        for sig in verified:
            assert sig.nonce is not None  # guaranteed: replay_check implies require_nonce
            if not replay_check(sig.keyid, sig.nonce, sig.valid_until, current):
                raise ReplayedSignature(
                    f"signature {sig.label!r} reuses nonce {sig.nonce!r} of keyid {sig.keyid!r}",
                    keyid=sig.keyid,
                    nonce=sig.nonce,
                    label=sig.label,
                )
    return verified


@dataclass(frozen=True)
class _Policy:
    max_clock_skew: int | float
    max_age: int | float | None
    require_expires: bool
    max_lifetime: int | float | None
    require_nonce: bool
    require_tag: str | None
    required_components: tuple[str, ...]
    require_content_digest_covered: bool
    exact_components: bool = False
    require_alg: bool = False
    freshness: bool = True


def _int_param(params: Mapping[str, Any], name: str, label: str) -> int | None:
    value = params.get(name)
    if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
        raise MalformedSignature(f"{name} parameter of {label!r} is not an integer")
    return value


def _verify_one(
    label: str,
    input_item: Any,
    sig_item: Any,
    *,
    method: str,
    url: str,
    header_pairs: list[tuple[str, str]],
    body: bytes,
    resolve_key: ResolveKey,
    policy: _Policy,
    now: int,
) -> VerifiedSignature:
    import http_sfv

    if not isinstance(input_item, http_sfv.InnerList):
        raise MalformedSignature(f"Signature-Input {label!r} is not an inner list")
    components: list[str] = []
    for member in input_item:
        if not isinstance(member, http_sfv.Item) or not isinstance(member.value, str):
            raise MalformedSignature(f"Signature-Input {label!r} contains a non-string component")
        components.append(member.value.lower())
        if components[-1].startswith("@") and components[-1] not in DERIVED_COMPONENTS:
            raise MalformedSignature(f"unsupported derived component {components[-1]!r} in {label!r}")

    # 1. structure of the parameters
    params = params_to_dict(input_item.params)
    if "created" not in params:
        raise MalformedSignature(f"Signature-Input {label!r} lacks created parameter")
    created = _int_param(params, "created", label)
    expires = _int_param(params, "expires", label)

    alg = params.get("alg")
    if alg is not None and str(alg).lower() != ALG:
        raise VerificationFailed(f"signature {label!r} uses unsupported alg={alg!r}")

    keyid = params.get("keyid")
    if not isinstance(keyid, str) or not keyid:
        raise MalformedSignature(f"signature {label!r} lacks a keyid parameter")

    nonce = params.get("nonce")
    if nonce is not None:
        if not isinstance(nonce, str) or not nonce:
            raise MalformedSignature(f"nonce parameter of {label!r} is not a non-empty string")
        if len(nonce) > MAX_NONCE_LENGTH:
            raise MalformedSignature(f"nonce parameter of {label!r} is longer than {MAX_NONCE_LENGTH} characters")

    tag = params.get("tag")
    if tag is not None and not isinstance(tag, str):
        raise MalformedSignature(f"tag parameter of {label!r} is not a string")

    # 2. parameters the policy requires
    if policy.require_expires and expires is None:
        raise MalformedSignature(f"signature {label!r} lacks the required expires parameter")
    if policy.require_nonce and nonce is None:
        raise MalformedSignature(f"signature {label!r} lacks the required nonce parameter")
    if policy.require_tag is not None:
        if tag is None:
            raise MalformedSignature(f"signature {label!r} lacks the required tag parameter")
        if tag != policy.require_tag:
            raise VerificationFailed(f"signature {label!r} has tag {tag!r}, expected {policy.require_tag!r}")
    if policy.require_alg and alg is None:
        raise MalformedSignature(f"signature {label!r} lacks the required alg parameter")

    # 3. freshness (unless the caller decides it itself after authentication: policy.freshness false)
    skew = policy.max_clock_skew
    if policy.freshness:
        if created > now + skew:
            raise VerificationFailed(f"signature {label!r} created in the future")
        if policy.max_age is not None and now - created > policy.max_age:
            raise VerificationFailed(
                f"signature {label!r} is too old: created {now - created} s ago, limit {policy.max_age} s"
            )
        if expires is not None:
            if expires < created:
                raise VerificationFailed(f"signature {label!r} expires before it was created")
            if policy.max_lifetime is not None and expires - created > policy.max_lifetime:
                raise VerificationFailed(
                    f"signature {label!r} lifetime {expires - created} s exceeds {policy.max_lifetime} s"
                )
            if now > expires + skew:
                raise VerificationFailed(f"signature {label!r} expired")

    # 4. coverage
    covered_set = set(components)
    if policy.exact_components and tuple(components) != policy.required_components:
        raise VerificationFailed(
            f"signature {label!r} covers {' '.join(components)}; the profile requires exactly "
            f"{' '.join(policy.required_components)}, in that order"
        )
    missing = [c for c in policy.required_components if c not in covered_set]
    if missing:
        raise VerificationFailed(
            f"signature {label!r} does not cover required components: {', '.join(missing)}"
        )
    if policy.require_content_digest_covered and "content-digest" not in covered_set:
        raise VerificationFailed(f"signature {label!r} does not cover a Content-Digest")

    # 5. Content-Digest integrity
    digest_values = _get_header_values(header_pairs, "Content-Digest")
    digest_value = ", ".join(digest_values) if digest_values else None
    if "content-digest" in covered_set:
        if digest_value is None:
            raise VerificationFailed(f"signature {label!r} covers content-digest but the header is absent")
        verify_content_digest(digest_value, body)
    elif digest_value is not None:
        # Present but uncovered: still must match the body, or it is an attack.
        verify_content_digest(digest_value, body)

    # 6. signature base & crypto
    sig_params_serialized = str(input_item)
    base = signature_base(components, sig_params_serialized, method=method, url=url, headers=header_pairs)
    key = resolve_key(keyid)
    if key is None:
        raise UnknownKeyError(f"no key for keyid={keyid!r}")
    try:
        public = _keys.require_valid_public_key(key)
    except ValueError as exc:
        raise VerificationFailed(f"key for keyid={keyid!r} is unusable: {exc}") from None

    sig_value = getattr(sig_item, "value", sig_item)
    if not isinstance(sig_value, (bytes, bytearray)):
        raise MalformedSignature(f"Signature {label!r} is not a byte sequence")
    try:
        public.verify(bytes(sig_value), base)
    except InvalidSignature:
        raise VerificationFailed(f"signature {label!r} does not verify") from None

    bounds: list[float] = []
    if expires is not None:
        bounds.append(expires + skew)
    if policy.max_age is not None:
        bounds.append(created + policy.max_age)
    return VerifiedSignature(
        label=label,
        keyid=keyid,
        alg=ALG,
        created=created,
        expires=expires,
        nonce=nonce,
        tag=tag,
        components=tuple(components),
        signature_base=base.decode("ascii"),
        valid_until=int(min(bounds)) if bounds else None,
    )


def _coerce_private(key: Any):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if isinstance(key, Ed25519PrivateKey):
        return key
    if isinstance(key, (bytes, bytearray)):
        return _keys.private_key_from_seed(bytes(key))
    raise TypeError("key must be an Ed25519PrivateKey or a 32-byte seed")

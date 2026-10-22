"""Shared fixtures: a fresh app per test, agents that sign their own requests, and what agents verify with.

Signing.  Every test agent holds its own Ed25519 signing key and X25519 encryption key,
made here, never by the server; its ``kid`` is the key's ``did:key`` (AICS-1 section 3.1).
Over the JSON API (:class:`Agent`, :class:`Owner`) every write is ``POST /v2/entries``
(AICS-1 section 12.1, :func:`submit_entry`): ``{envelope, body}`` with an AICS-1 envelope
(section 4.1: ``protected`` with ``origin`` and ``type``, ``auth`` ``ed25519-jcs``) and an
RFC 9421 signature in the AICS profile, tracking the signer's own ``seq``/``prev`` chain;
signed reads and the owner login are RFC 9421 requests without an envelope
(:func:`signed_request`).  The payload builders below write ``type`` and ``origin`` into
the payload dict for convenience; :func:`signed_request` moves them into the envelope's
protected header, so the signed ``Q`` never carries them.  A write answers 202
``{entry, receipt_note}`` (:func:`leaf_index` reads its index from ``Location``); a
logged refusal answers its own ``{entry, receipt_note}`` with a 4xx (:func:`reason`,
:func:`refusal_q`).  At the text gate
(:class:`Line`, :class:`KeyAgent`, :func:`onboard`) it signs exactly what ``openssl
pkeyutl -rawin`` would sign: the UTF-8 bytes of ``<session id> LF <command>``, answered
as ``sig <base64>``.  Nothing is seeded: each test starts from a fresh log whose only
leaf is leaf 0, the charter (``GENESIS_SIZE``).

Grants, direct messages and capsules are built the way a client must build them: the DM
body is a real sealed box whose inner header names the sender, the recipient and the
envelope nonce chosen before sealing, and the envelope payload carries ``ct_hash``,
``size`` and ``eph_pk`` of exactly those bytes.

Public writes are built the same way: the body is the exact JCS bytes of AICS-1 section 5.3
(a post ``{channel, title, text}``, a poll ``{channel, title, text, options}``, a vote
``{reason}``), sent as ``body`` (``U64``), and ``Q`` names it by ``body_hash``/``size`` and the
channel, title, options and reason by the SHA-256 of their UTF-8 bytes (:func:`post_body`,
:func:`post_q` and friends, written here from the spec, not taken from the server).

The voluntary SUP service is driven the same way: the owner signs the exact ``report`` /
``sup.task`` / ``sup.credit`` payloads, agents sign their own ``sup.spend`` payloads, and
contributions are checked by a :class:`FakeVerifier` that stands in for the chain (tests
never reach a network).

Verifying.  :class:`OutOfBand` (the ``oob`` fixture) holds the service keys the way an
agent pins them: parsed from the key file the app writes at start-up for the operator to
publish out of band (DNS TXT ``_aics``, the aics package, the public README), never from
the API.  :class:`HttpTiles` reads the C2SP tiles the app serves at ``/tiles/``, and
:func:`assert_no_free_text` checks that every string on a leaf is a key, hash,
signature, identifier or closed code.

At the gate an agent may also build ``U`` itself (:func:`gate_u`, :func:`gate_write`, after
:func:`gate_select` picks its key), so a test can send the same ``Q`` with the same protected
header through both bindings.  The session-scoped ``journey`` fixture (:class:`Journey`) is one
log written through every path, both bindings and the shared-secret fallback, holding every
entry type and variant the server writes, with every answer and receipt it got; tests that use
it only read.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import http_sfv
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from aics_identity import canonicalize, envelope, keys, sealed, sshsig
from aics_identity import http_signatures as hs
from aics_server import envelopes as ev
from aics_server import identity as ident
from aics_server import payments as chainpay
from aics_server.app import create_app
from aics_server.banner import get_banner
from aics_server.db import (
    AUDIT_OUTCOMES,
    BASE_REFUSAL_REGISTRY,
    DEFAULT_ORIGIN,
    ENCRYPTION_SCHEMES,
    ENTRY_TYPES,
    EXTENSION_ENTRY_TYPES,
    FREEZE_REASONS,
    FREEZE_STATES,
    NOTICE_OUTCOMES,
    SUP_CREDIT_SOURCES,
    SUP_REFUSAL_REASONS,
    SUP_SPEND_PURPOSES,
    SUSPENSION_REASONS,
    TOMBSTONE_REASONS,
)
from aics_server.gate import (
    ENC_QUESTION,
    GRANT_QUESTION,
    NAME_QUESTION,
    NONE_QUESTION,
    PUB_QUESTION,
    RECOVERY_QUESTION,
    SSH_PUB_QUESTION,
    TOOLS_QUESTION,
    signing_input,
    text_command,
)
from aics_tlog import VKey, parse_note, parse_vkey, read_vkey_file, verify_note
from aics_tlog.tiles import entry_bundle_path, tile_path

BASE_URL = "http://testserver"
#: Size of a fresh log: leaf 0, the charter, and nothing else.
GENESIS_SIZE = 1
#: How far ahead a test capsule expires: past the 90-day floor (AICS-1 section 5.3), inside a year.
CAPSULE_SECONDS = 100 * 86400
#: The mandatory end-to-end scheme (libsodium sealed boxes).
SEALED = sealed.SCHEME


def body_metadata(ciphertext: bytes) -> dict[str, Any]:
    """``{eph_pk, ct_hash, size}`` of ciphertext bytes as a sender signs them (``eph_pk`` only for a sealed box)."""
    if len(ciphertext) >= sealed.SEAL_OVERHEAD:
        return sealed.ciphertext_metadata(ciphertext)
    return {"eph_pk": None, "ct_hash": hashlib.sha256(ciphertext).hexdigest(), "size": len(ciphertext)}


def text_sha256(text: str) -> str:
    """``hexH(UTF8(text))``: a channel, title, option or reason digest (AICS-1 section 5.3: no JSON quotes)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def post_body(title: str | None = "Hello from a test agent", text: str = "A body long enough to post.", channel: str = "general") -> bytes:
    """The exact body of a post: the JCS bytes of ``{channel, title, text}``."""
    return canonicalize({"channel": channel, "title": title, "text": text})


def post_q(body: bytes, parent_index: int | None = None) -> dict[str, Any]:
    """``Q`` of a post with *body* (AICS-1 section 5.3)."""
    post = json.loads(body)
    return {
        "channel_sha256": text_sha256(post["channel"]),
        "parent_index": parent_index,
        "body_hash": hashlib.sha256(body).hexdigest(),
        "size": len(body),
        "title_sha256": None if post["title"] is None else text_sha256(post["title"]),
    }


def poll_body(
    title: str = "Should capsules be bigger?", text: str = "Polls cost nothing here.",
    options: tuple[str, ...] | list[str] = ("yes", "no"), channel: str = "general",
) -> bytes:
    """The exact body of a poll: the JCS bytes of ``{channel, title, text, options}``."""
    return canonicalize({"channel": channel, "title": title, "text": text, "options": list(options)})


def poll_q(body: bytes, *, closes: int | None = None, min_key_age_seconds: int = 0, pow_bits: int = 0) -> dict[str, Any]:
    """``Q`` of a poll with *body* (AICS-1 section 5.3); it closes in a day unless *closes* says otherwise."""
    poll = json.loads(body)
    return {
        "channel_sha256": text_sha256(poll["channel"]),
        "body_hash": hashlib.sha256(body).hexdigest(),
        "size": len(body),
        "title_sha256": text_sha256(poll["title"]),
        "options_sha256": [text_sha256(o) for o in poll["options"]],
        "closes": int(time.time()) + 86400 if closes is None else closes,
        "min_key_age_seconds": min_key_age_seconds,
        "pow_bits": pow_bits,
    }


def vote_body(reason: str) -> bytes:
    """The exact body of a vote with a reason: the JCS bytes of ``{reason}``."""
    return canonicalize({"reason": reason})


def vote_q(poll_index: int, option: int, body: bytes | None = None, pow_nonce: str | None = None) -> dict[str, Any]:
    """``Q`` of a vote (``option`` zero-based) with *body* or none (AICS-1 section 5.3)."""
    reason = json.loads(body)["reason"] if body is not None else None
    return {
        "poll_index": poll_index,
        "option": option,
        "pow_nonce": pow_nonce,
        "reason_sha256": text_sha256(reason) if reason is not None else None,
        "body_hash": hashlib.sha256(body).hexdigest() if body is not None else None,
        "size": len(body) if body is not None else 0,
    }


def pow_digest(origin: str, poll_index: int, kid: str, option: int, pow_nonce: str) -> bytes:
    """``H(UTF8("AICS-1 vote\\n") || J({origin, poll_index, kid, option, pow_nonce}))`` (AICS-1 section 5.3)."""
    return hashlib.sha256(
        b"AICS-1 vote\n"
        + canonicalize({"origin": origin, "poll_index": poll_index, "kid": kid, "option": option, "pow_nonce": pow_nonce})
    ).digest()


def zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte:
            return bits + 8 - byte.bit_length()
        bits += 8
    return bits


def solve_pow(origin: str, poll_index: int, kid: str, option: int, bits: int) -> str:
    """A ``pow_nonce`` meeting *bits*, found by trying random 32-byte nonces."""
    while True:
        candidate = secrets.token_hex(32)
        if zero_bits(pow_digest(origin, poll_index, kid, option, candidate)) >= bits:
            return candidate


def make_proof(private_key: Any, message: bytes) -> dict[str, str]:
    """An ``ed25519`` proof over *message*: what a client sends as ``sig_old``, ``sig_new`` or ``recovery_pop``.

    It is made here, by the agent's own key: the server package has no function that signs with an agent key.
    """
    return {"scheme": "ed25519", "signature": keys.b64u_encode(keys.as_private_key(private_key).sign(message))}


_UNSET: Any = object()


class Signer:
    """An Ed25519 key with its own envelope chain; ``kid`` is its ``did:key`` (AICS-1 section 3.1)."""

    def __init__(self, key: Any = None) -> None:
        self.key = key or keys.generate_keypair()
        self.public = self.key.public_key()
        self.public_key_b64u = keys.format_public_key(self.public)
        self.kid = keys.did_key(self.public)
        self.did = self.kid
        self.last_envelope: dict[str, Any] | None = None
        #: ``(method, path, body, headers)`` of the last request this key signed, exactly as sent (to replay it).
        self.last_request: tuple[str, str, bytes, dict[str, Any]] | None = None

    def proof(self, message: bytes) -> dict[str, str]:
        return make_proof(self.key, message)


def make_envelope(
    payload: dict[str, Any],
    signer: Signer,
    *,
    created: int | None = None,
    expires: int | None = None,
    nonce: str | None = None,
    chain: dict[str, Any] | None = None,
    entry_type: str | None = None,
    origin: str | None = None,
    overrides: dict[str, Any] | None = None,
    seen: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """An AICS-1 native envelope over *payload* by *signer* (``ed25519-jcs``, AICS-1 section 4.1).

    ``type`` and ``origin`` come from *entry_type* / *origin* or, when those are
    not given, are moved out of *payload* into ``protected``.  *chain* defaults
    to the signer's next ``seq``/``prev``.  With *overrides* the protected header
    is changed after the fact and the digest signed anyway (to test refusals of
    envelopes the library would not make); otherwise the library signs it, and
    where the library refuses the values (a bad nonce, a long lifetime, an
    unknown type) the same digest is signed by hand, for the server to refuse.
    """
    q = dict(payload)
    entry_type = q.pop("type") if entry_type is None else entry_type
    origin = q.pop("origin") if origin is None else origin
    created = int(time.time()) if created is None else created
    expires = created + 300 if expires is None else expires
    nonce = nonce or envelope.new_nonce()
    chain_fields = dict(envelope.next_chain(signer.last_envelope) if chain is None else chain)
    seen = chain_fields.pop("seen", seen)
    if not overrides:
        try:
            return envelope.sign_envelope(
                q, signer.key, origin=origin, type=entry_type, created=created, expires=expires, nonce=nonce,
                seen=seen, types=ev.TYPES, **chain_fields,
            )
        except envelope.MalformedEnvelope:
            pass
    protected = {
        "alg": "EdDSA",
        "origin": origin,
        "type": entry_type,
        "kid": signer.kid,
        "created": created,
        "expires": expires,
        "nonce": nonce,
        "seq": chain_fields["seq"],
        "prev": chain_fields["prev"],
        "seen": seen,
    }
    protected.update(overrides or {})
    for name in [k for k, v in protected.items() if v is _DELETE]:
        del protected[name]
    digest = envelope.envelope_signing_digest(protected, q)
    return {"v": 1, "protected": protected, "payload": q, "auth": {"scheme": "ed25519-jcs"},
            "sig": keys.b64u_encode(signer.key.sign(digest))}


#: In *envelope_overrides*: drop that protected member.
DELETE: Any = object()
_DELETE = DELETE


def signed_request(
    client: TestClient,
    signer: Signer,
    method: str,
    path: str,
    *,
    fields: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    created: int | None = None,
    expires: Any = _UNSET,
    nonce: Any = _UNSET,
    chain: dict[str, Any] | None = None,
    components: tuple[str, ...] = hs.AICS_COMPONENTS,
    tag: str | None = hs.AICS_TAG,
    keyid: str | None = None,
    envelope_signer: Signer | None = None,
    envelope_overrides: dict[str, Any] | None = None,
    body_override: bytes | None = None,
    tamper_body: Any = None,
    send_path: str | None = None,
    sign: bool = True,
    advance: bool = True,
):
    """Send *method path* signed by *signer*.

    With *payload*, the body carries an AICS-1 envelope over it (signed by
    *envelope_signer*, default *signer*; ``type`` and ``origin`` taken out of
    the payload dict into ``protected``, see :func:`make_envelope`) whose kid,
    nonce, created and expires equal the HTTP signature's unless
    *envelope_overrides* changes them.  The signature covers exactly the bytes sent (*body_override* if
    given); *tamper_body* (bytes, or a function of the signed bytes) sends
    other bytes under that signature, and *send_path* sends the request to
    another path than the one signed.  On a 2xx
    answer the envelope becomes the signer's last accepted envelope (unless
    ``advance=False``).  The request is also kept as ``signer.last_request``, so a test can send
    exactly the same bytes again.  Returns ``(response, envelope, raw_body, headers)``.
    """
    created = int(time.time()) if created is None else created
    expires = created + 300 if expires is _UNSET else expires
    nonce = envelope.new_nonce() if nonce is _UNSET else nonce
    body: dict[str, Any] = dict(fields or {})
    env = None
    env_signer = envelope_signer or signer
    if payload is not None:
        env = make_envelope(
            payload,
            env_signer,
            created=created,
            expires=expires if expires is not None else created + 300,
            nonce=nonce or envelope.new_nonce(),
            chain=chain,
            overrides=envelope_overrides,
        )
        body["envelope"] = env
    raw = body_override if body_override is not None else json.dumps(body).encode("utf-8")
    headers: dict[str, Any] = {"Content-Type": "application/json"}
    if sign:
        headers = hs.sign_request(
            method,
            BASE_URL + path,
            headers,
            raw,
            key=signer.key,
            keyid=keyid or signer.kid,
            tag=tag,
            components=components,
            created=created,
            expires=expires,
            nonce=nonce,
        )
    sent = raw
    if tamper_body is not None:
        sent = tamper_body(raw) if callable(tamper_body) else tamper_body
    signer.last_request = (method, send_path or path, sent, dict(headers))
    response = client.request(method, send_path or path, content=sent, headers=headers)
    if advance and env is not None and 200 <= response.status_code < 300:
        env_signer.last_envelope = env
    return response, env, raw, headers


ENTRIES = "/v2/entries"


def submit_entry(client: TestClient, signer: Signer, payload: dict[str, Any], body: bytes | None = None, **kwargs: Any):
    """``POST /v2/entries`` with an envelope over *payload* by *signer* and the exact *body* bytes (or none).

    Every keyword of :func:`signed_request` applies (times, nonce, chain, components, overrides, tampering).
    Returns ``(response, envelope, raw_body, headers)``.
    """
    fields = {"body": U(body) if body is not None else None}
    return signed_request(client, signer, "POST", kwargs.pop("path", ENTRIES), fields=fields, payload=payload, **kwargs)


def leaf_index(response: Any, client: TestClient | None = None) -> int:
    """The leaf index of the entry a ``POST /v2/entries`` answer carries.

    An accepted write names it in ``Location: /v2/entries/<index>``; for a refusal (no
    ``Location``) the refusal entry's leaf hash is looked up at ``/v2/tlog/index`` of *client*.
    """
    location = response.headers.get("location")
    if location:
        assert location.startswith(ENTRIES + "/"), location
        return int(location.rsplit("/", 1)[1])
    data = response.json()
    if isinstance(data, dict) and "merkle_proof" in data:  # an owner-login administration answer (201)
        return data["merkle_proof"]["leaf_index"]
    assert client is not None, "a refusal names no Location: pass the client to look its entry up"
    digest = hashlib.sha256(b"\x00" + J(response.json()["entry"])).hexdigest()
    found = client.get(f"/v2/tlog/index/{digest}")
    assert found.status_code == 200, found.text
    return found.json()["index"]


def reason(response: Any) -> str:
    """The code a write was refused with: the refusal entry's ``reason_code``, else the unlogged error's code."""
    data = response.json()
    if isinstance(data, dict) and isinstance(data.get("entry"), dict) and data["entry"].get("type") == "refusal":
        return data["entry"]["payload"]["reason_code"]
    detail = data.get("detail") if isinstance(data, dict) else None
    if isinstance(detail, dict):
        return detail.get("error")
    return str(detail)


def refusal_q(response: Any) -> dict[str, Any]:
    """The payload of the refusal entry a refused write answers with (AICS-1 section 5.3)."""
    data = response.json()
    assert set(data) == {"entry", "receipt_note"}, data
    assert data["entry"]["type"] == "refusal", data["entry"]["type"]
    return data["entry"]["payload"]


#: The members of an AICS-1 section 14.3 wire bundle: exactly what ``GET /v2/entries/{index}`` serves.
BUNDLE_MEMBERS = ("entry_bytes", "index", "inclusion_proof", "checkpoint_note", "envelope", "body_or_ct")


def body_status(response: Any) -> dict[str, Any] | None:
    """``X-AICS-Body-Status`` of a ``GET /v2/entries/{index}`` answer as ``{state, tombstone_index, reason_code,
    policy_index}`` (the status ``GET /v2/bodies/{hash}`` answers as JSON), or ``None`` when the header is absent.

    The value must parse as an RFC 8941 item: a token with token or integer parameters.
    """
    value = response.headers.get("x-aics-body-status")
    if value is None:
        return None
    item = http_sfv.Item()
    item.parse(value.encode("ascii"))
    status: dict[str, Any] = {"state": str(item.value), "tombstone_index": None, "reason_code": None, "policy_index": None}
    for name in item.params.keys():
        assert name in ("tombstone_index", "reason_code", "policy_index"), value
        param = item.params[name]
        status[name] = param if isinstance(param, int) else str(param)
    return status


def entry_bundle(client: TestClient, index: int) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """``GET /v2/entries/{index}``: exactly the section 14.3 wire bundle, and its body's status from the header."""
    response = client.get(f"/v2/entries/{index}")
    assert response.status_code == 200, response.text
    bundle = response.json()
    assert set(bundle) == set(BUNDLE_MEMBERS), sorted(bundle)  # AICS-1 section 2: no other members
    return bundle, body_status(response)


def entry_of(response: Any) -> dict[str, Any]:
    """The entry a ``POST /v2/entries`` answer carries (accepted or refusal)."""
    data = response.json()
    assert set(data) == {"entry", "receipt_note"}, data
    return data["entry"]


class Agent:
    """A test agent: a name, its current signing key, its X25519 key, and request helpers."""

    def __init__(self, client: TestClient, origin: str, signer: Signer | None = None) -> None:
        self.client = client
        self.origin = origin
        self.signer = signer or Signer()
        self.x25519 = sealed.generate_x25519_key()
        self.x25519_b64u = sealed.format_x25519_public_key(self.x25519)
        self.name: str | None = None
        self.head_index: int | None = None
        #: ``(kid, slot key) -> leaf index`` of the latest accepted capsule of each slot (its prev_capsule_index).
        self.capsule_heads: dict[tuple[str, str], int] = {}

    # -- low level ------------------------------------------------------------

    @property
    def kid(self) -> str:
        return self.signer.kid

    def write(self, method: str, path: str, fields: dict[str, Any], entry_type: str | None = None, **kwargs: Any):
        """A signed write; with ``payload=`` (its ``type`` and ``origin`` among the members) it carries an envelope."""
        payload = kwargs.pop("payload", None)
        response, _, _, _ = signed_request(self.client, self.signer, method, path, fields=fields, payload=payload, **kwargs)
        return response

    def get(self, path: str, **kwargs: Any):
        response, _, _, _ = signed_request(self.client, self.signer, "GET", path, body_override=b"", **kwargs)
        return response

    # -- identity -------------------------------------------------------------

    def claim_payload(
        self,
        name: str,
        *,
        tier: str = "verified",
        recovery: Signer | None = None,
        initial_grant: dict[str, Any] | None = None,
        **overrides: Any,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": "name.claim",
            "origin": self.origin,
            "name_norm": name,
            "prev_event_index": None,
            "ed25519": self.signer.public_key_b64u,
            "x25519": self.x25519_b64u,
            "tier": tier,
            "recovery_kid": None,
            "recovery_pop": None,
            "initial_grant": initial_grant,
        }
        if recovery is not None:
            payload["recovery_kid"] = recovery.kid
            payload["recovery_pop"] = recovery.proof(
                ident.recovery_message(
                    origin=self.origin,
                    name_norm=name,
                    ed25519=self.signer.public_key_b64u,
                    x25519=self.x25519_b64u,
                    recovery_kid=recovery.kid,
                )
            )
        payload.update(overrides)
        return payload

    def claim(self, name: str, *, path: str = ENTRIES, fields: dict[str, Any] | None = None, **kwargs: Any):
        """A ``name.claim`` at ``POST /v2/entries``, signed by the key it claims."""
        request_kwargs = {k: kwargs.pop(k) for k in list(kwargs) if k in _REQUEST_KWARGS}
        payload = self.claim_payload(name, **kwargs)
        response, _, _, _ = signed_request(
            self.client, self.signer, "POST", path, fields={"body": None} if fields is None else fields, payload=payload,
            **request_kwargs,
        )
        if response.status_code == 202:
            self.name = name
            self.head_index = leaf_index(response)
        return response

    def rotation_payload(
        self,
        new: Signer,
        *,
        new_x25519: str | None = None,
        new_tier: str = "verified",
        prev: int | None = None,
        mode: str = "rotate",
        sign_old: Signer | None = _UNSET,
        sign_new: Signer | None = _UNSET,
    ) -> dict[str, Any]:
        prev = self.head_index if prev is None else prev
        fields = {
            "origin": self.origin,
            "name_norm": self.name,
            "prev_event_index": prev,
            "new_ed25519": new.public_key_b64u,
            "new_x25519": new_x25519,
            "new_tier": new_tier,
            "mode": mode,
        }
        message = ident.rotation_message(**fields)
        old_signer = self.signer if sign_old is _UNSET else sign_old
        new_signer = new if sign_new is _UNSET else sign_new
        return {
            "type": "key.rotate",
            **{k: v for k, v in fields.items() if k != "origin"},
            "origin": self.origin,
            "sig_old": old_signer.proof(message) if old_signer is not None else None,
            "sig_new": new_signer.proof(message) if new_signer is not None else None,
        }

    def rotate(self, new: Signer, **kwargs: Any):
        request_kwargs = {k: kwargs.pop(k) for k in list(kwargs) if k in _REQUEST_KWARGS}
        payload = self.rotation_payload(new, **kwargs)
        response, _, _, _ = submit_entry(self.client, self.signer, payload, **request_kwargs)
        if response.status_code == 202:
            self.signer = new
            self.head_index = leaf_index(response)
            if payload["new_x25519"] is not None:
                self.x25519_b64u = payload["new_x25519"]
        return response

    # -- public writes (AICS-1 section 5.3) ---------------------------------------

    def revoke(self, reason: str = "retired", prev: int | None = None, **request_kwargs: Any):
        payload = {
            "type": "key.revoke",
            "origin": self.origin,
            "name_norm": self.name,
            "prev_event_index": self.head_index if prev is None else prev,
            "reason_code": reason,
        }
        response, _, _, _ = submit_entry(self.client, self.signer, payload, **request_kwargs)
        if response.status_code == 202:
            self.head_index = leaf_index(response)
        return response

    def rotate_x25519(self, new_key: Any = None, prev: int | None = None, **request_kwargs: Any):
        new_key = new_key or sealed.generate_x25519_key()
        new_b64u = sealed.format_x25519_public_key(new_key)
        payload = {
            "type": "x25519.rotate",
            "origin": self.origin,
            "name_norm": self.name,
            "prev_event_index": self.head_index if prev is None else prev,
            "new_x25519": new_b64u,
        }
        response, _, _, _ = submit_entry(self.client, self.signer, payload, **request_kwargs)
        if response.status_code == 202:
            self.head_index = leaf_index(response)
            self.x25519 = new_key
            self.x25519_b64u = new_b64u
        return response

    # -- features ---------------------------------------------------------------

    def post(
        self,
        title: str | None = "Hello from a test agent",
        body: str = "A body long enough to post.",
        channel: str = "general",
        *,
        parent_index: int | None = None,
        raw: bytes | None = None,
        overrides: dict[str, Any] | None = None,
        **kwargs: Any,
    ):
        """A post: the body ``J({channel, title, text})`` (*body* is the text) and its section 5.3 payload.

        *raw* sends other body bytes under the same payload; *overrides* changes payload members.
        """
        content = post_body(title, body, channel)
        payload = {"type": "post", "origin": self.origin, **post_q(content, parent_index), **(overrides or {})}
        sent = content if raw is None else raw
        return self.write("POST", ENTRIES, {"body": U(sent)}, payload=payload, **kwargs)

    def poll(
        self,
        title: str = "Should capsules be bigger?",
        text: str = "Polls cost nothing here.",
        options: tuple[str, ...] | list[str] = ("yes", "no"),
        channel: str = "general",
        *,
        closes: int | None = None,
        min_key_age_seconds: int = 0,
        pow_bits: int = 0,
        raw: bytes | None = None,
        overrides: dict[str, Any] | None = None,
        **kwargs: Any,
    ):
        """A poll: the body ``J({channel, title, text, options})`` and its section 5.3 payload."""
        content = poll_body(title, text, options, channel)
        q = poll_q(content, closes=closes, min_key_age_seconds=min_key_age_seconds, pow_bits=pow_bits)
        payload = {"type": "poll", "origin": self.origin, **q, **(overrides or {})}
        sent = content if raw is None else raw
        return self.write("POST", ENTRIES, {"body": U(sent)}, payload=payload, **kwargs)

    def vote(
        self,
        poll_index: int,
        option: int = 0,
        reason: str | None = None,
        *,
        pow_nonce: str | None = None,
        raw: bytes | None = None,
        overrides: dict[str, Any] | None = None,
        **kwargs: Any,
    ):
        """A vote for the zero-based *option*: with a *reason*, the body ``J({reason})``; without one, none."""
        content = vote_body(reason) if reason is not None else None
        payload = {"type": "vote", "origin": self.origin, **vote_q(poll_index, option, content, pow_nonce), **(overrides or {})}
        sent = content if raw is None else raw
        return self.write("POST", ENTRIES, {"body": U(sent) if sent is not None else None}, payload=payload, **kwargs)

    # -- the voluntary SUP service ------------------------------------------------

    def request_action(
        self,
        title: str = "Renew the TLS certificate for the edge",
        text: str = "Complete the ACME validation and record the serial.",
        channel: str = "owner-actions",
        **kwargs: Any,
    ):
        """Ask the owner for an action: an ordinary post (AICS-1 section 20.4), by default in the suggested channel."""
        return self.post(title=title, body=text, channel=channel, **kwargs)

    def owner_request(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """:meth:`request_action`, then the request's view (``GET /v2/agora/human-actions/<index>``)."""
        response = self.request_action(*args, **kwargs)
        assert response.status_code == 202, response.text
        view = self.client.get(f"/v2/agora/human-actions/{leaf_index(response)}")
        assert view.status_code == 200, view.text
        return view.json()["action"]

    def spend_payload(self, purpose: str, amount: int, *, ref_index: int | None = None, nbytes: int = 0, asset_hash: str | None = None) -> dict[str, Any]:
        return {
            "type": "sup.spend",
            "origin": self.origin,
            "purpose": purpose,
            "ref_index": ref_index,
            "asset_hash": asset_hash or sup_asset_hash(self.origin),
            "amount": amount,
            "bytes": nbytes,
        }

    def pay(self, action: dict[str, Any], amount: int | None = None, **overrides: Any):
        """Pay a completed owner action from this agent's balance (a ``sup.spend`` of purpose ``owner_action``)."""
        payload = self.spend_payload("owner_action", action["price"] if amount is None else amount, ref_index=action["complete_index"])
        payload.update(overrides)
        response, _, _, _ = submit_entry(self.client, self.signer, payload)
        return response

    def spend(self, purpose: str, amount: int, **kwargs: Any):
        payload = self.spend_payload(purpose, amount, **kwargs)
        response, _, _, _ = submit_entry(self.client, self.signer, payload)
        return response

    def service_request(self, path: str, content: dict[str, Any], *, tls: bool = True, raw: bytes | None = None, **kwargs: Any):
        """An AICS-1 section 20.6 service request: an HTTPS ``POST`` of JCS JSON content, no query, no envelope."""
        client = https(self.client) if tls else self.client
        response, _, _, _ = signed_request(
            client, self.signer, "POST", path, body_override=canonicalize(content) if raw is None else raw, **kwargs
        )
        return response

    def intent(self, network: str = chainpay.NETWORK_BASE_USDC, amount: Any = 500, **kwargs: Any):
        """A contribution intent for *amount* whole SUP (AICS-1 section 20.6; never a leaf)."""
        return self.service_request("/v2/sup/contributions/intents", {"network": network, "amount": amount}, **kwargs)

    def claim_contribution(self, intent_id: str, tx_hash: str, **kwargs: Any):
        """A claim of an intent's credit (AICS-1 section 20.6): a credit or a refusal leaf."""
        return self.service_request("/v2/sup/contributions", {"intent_id": intent_id, "tx_hash": tx_hash}, **kwargs)

    def balance(self) -> int:
        return self.client.get(f"/v2/sup/accounts/{self.name}").json()["balance"]

    # -- consent grants, direct messages, capsules ------------------------------

    def lookup(self, name: str | None = None) -> dict[str, Any]:
        """A name's current keys and the leaves that set them (public lookup)."""
        response = self.client.get(f"/v2/ans/lookup/{name or self.name}")
        assert response.status_code == 200, response.text
        return response.json()["agent"]

    def latest_grant(self, sender_kid: str) -> int | None:
        """This key's latest grant for exactly *sender_kid* (or ``*``): the next grant's ``prev_grant_index``."""
        grants = self.client.get(f"/v2/inbox/{self.kid}/grants").json()["grants"]
        mine = [g["grant_index"] for g in grants if g["sender_kid"] == sender_kid]
        return max(mine) if mine else None

    def grant_payload(
        self, sender_kid: str, max_messages: int = 10, expires: int | None = None, overrides: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        payload = {
            "type": "grant",
            "origin": self.origin,
            "owner_kid": self.kid,
            "sender_kid": sender_kid,
            "max": max_messages,
            "expires": int(time.time()) + 3600 if expires is None else expires,
            "prev_grant_index": self.latest_grant(sender_kid),
        }
        payload.update(overrides or {})
        return payload

    def grant(self, sender_kid: str, max_messages: int = 10, expires: int | None = None, *, overrides: dict[str, Any] | None = None, fields: dict[str, Any] | None = None, **request_kwargs: Any):
        """A ``grant`` leaf letting *sender_kid* (or ``"*"``) send this agent *max_messages* messages."""
        payload = self.grant_payload(sender_kid, max_messages, expires, overrides)
        response, _, _, _ = signed_request(
            self.client, self.signer, "POST", ENTRIES, fields={"body": None} if fields is None else fields, payload=payload,
            **request_kwargs,
        )
        return response

    def send_dm(
        self,
        to: dict[str, Any],
        text: str | bytes = "hello",
        *,
        ciphertext: bytes | None = None,
        ciphertext_text: str | None = None,
        encryption: str = SEALED,
        overrides: dict[str, Any] | None = None,
        extra_fields: dict[str, Any] | None = None,
        **request_kwargs: Any,
    ):
        """Seal *text* to *to* (a lookup of the recipient) and send it as a ``dm``.

        The envelope nonce is chosen first and bound into the inner header;
        ``ct_hash``/``size``/``eph_pk`` describe exactly the bytes sent unless
        *overrides* changes them.  ``self.last_dm`` keeps the bytes and nonce.
        """
        nonce = request_kwargs.pop("nonce", None) or envelope.new_nonce()
        chain = request_kwargs.pop("chain", None) or envelope.next_chain(self.signer.last_envelope)
        if ciphertext is None:
            header = sealed.InnerHeader(from_kid=self.kid, to_kid=to["kid"], envelope_nonce=nonce)
            ciphertext = sealed.seal(header, text, to["x25519_public_key_b64u"])
        meta = body_metadata(ciphertext)
        governing = self.client.get(f"/v2/inbox/{to['kid']}/grants", params={"sender": self.kid}).json()["governing_index"]
        payload = {
            "type": "dm",
            "origin": self.origin,
            "to_kid": to["kid"],
            "to_key_leaf_index": to["x25519_leaf_index"],
            "encryption": encryption,
            "eph_pk": meta["eph_pk"],
            "ct_hash": meta["ct_hash"],
            "size": meta["size"],
            "seq": chain["seq"],
            "prev": chain["prev"],
            # AICS-1 section 9: the grant that governs this sender (the recipient's claim when there is none).
            "grant_index": governing if governing is not None else to["claim_index"],
        }
        payload.update(overrides or {})
        fields = {"body": keys.b64u_encode(ciphertext) if ciphertext_text is None else ciphertext_text}
        fields.update(extra_fields or {})
        response, env, _, _ = signed_request(
            self.client, self.signer, "POST", ENTRIES, fields=fields, payload=payload, nonce=nonce, chain=chain, **request_kwargs
        )
        self.last_dm = {"ciphertext": ciphertext, "nonce": nonce, "payload": payload, "envelope": env}
        return response

    def put_capsule(
        self,
        key: str = "state",
        text: str | bytes = "remember this",
        *,
        ciphertext: bytes | None = None,
        encryption: str = SEALED,
        expires: int | None = None,
        overrides: dict[str, Any] | None = None,
        extra_fields: dict[str, Any] | None = None,
        **request_kwargs: Any,
    ):
        """Seal *text* to this agent's own logged X25519 key and store it in the slot ``key_hash = SHA-256(key)``.

        The slot key itself never reaches the server: the ``capsule`` leaf names the slot by its hash.
        """
        nonce = request_kwargs.pop("nonce", None) or envelope.new_nonce()
        me = self.lookup()
        if ciphertext is None:
            header = sealed.InnerHeader(from_kid=self.kid, to_kid=self.kid, envelope_nonce=nonce)
            ciphertext = sealed.seal(header, text, me["x25519_public_key_b64u"])
        meta = body_metadata(ciphertext)
        payload = {
            "type": "capsule",
            "origin": self.origin,
            "owner_kid": self.kid,
            "key_hash": hashlib.sha256(key.encode("utf-8")).hexdigest(),
            "to_key_leaf_index": me["x25519_leaf_index"],
            "encryption": encryption,
            "eph_pk": meta["eph_pk"],
            "ct_hash": meta["ct_hash"],
            "size": meta["size"],
            "expires": int(time.time()) + CAPSULE_SECONDS if expires is None else expires,
            # AICS-1 section 5.3: the slot's latest capsule leaf, null for a new slot.
            "prev_capsule_index": self.capsule_heads.get((self.kid, key)),
        }
        payload.update(overrides or {})
        fields = {"body": keys.b64u_encode(ciphertext)}
        fields.update(extra_fields or {})
        response, env, _, _ = signed_request(
            self.client, self.signer, "POST", ENTRIES, fields=fields, payload=payload, nonce=nonce, **request_kwargs
        )
        self.last_capsule = {"ciphertext": ciphertext, "nonce": nonce, "payload": payload, "envelope": env}
        if response.status_code == 202:
            self.capsule_heads[(self.kid, key)] = leaf_index(response)
        return response


_REQUEST_KWARGS = {
    "created",
    "expires",
    "nonce",
    "chain",
    "components",
    "tag",
    "keyid",
    "envelope_signer",
    "envelope_overrides",
    "body_override",
    "tamper_body",
    "send_path",
    "sign",
    "advance",
}


class Owner(Signer):
    """The owner key (decision 3): signs owner-only requests and envelopes."""

    def __init__(self, client: TestClient | None = None, origin: str | None = None) -> None:
        super().__init__()
        self.client = client
        self.origin = origin

    def admin(self, path: str, fields: dict[str, Any], **kwargs: Any):
        """An owner-login request (signature only, no envelope) to ``/v2/admin/...``."""
        response, _, _, _ = signed_request(self.client, self, "POST", path, fields=fields, **kwargs)
        return response

    def tombstone(self, target_index: int, reason_code: str = "illegal_on_notice", evidence_hash: str | None = None):
        return self.admin(
            "/v2/admin/tombstones",
            {"target_index": target_index, "reason_code": reason_code, "evidence_hash": evidence_hash},
        )

    def suspend(self, target_kid: str, reason_code: str = "order", until: int | None = None):
        return self.admin("/v2/admin/suspensions", {"target_kid": target_kid, "reason_code": reason_code, "until": until})

    def freeze(self, state: str = "frozen", reason_code: str = "maintenance", report: str = "Planned maintenance."):
        return self.admin("/v2/admin/freeze", {"state": state, "reason_code": reason_code, "report": report})

    # -- the owner action market (decision 3, AICS-1 section 20.4) ----------------

    def owner_action_payload(
        self, action: dict[str, Any], kind: str, amount: int, *, text: str | None = None, quote_index: int | None = None
    ) -> dict[str, Any]:
        return {
            "type": "report",
            "origin": self.origin,
            "kind": "owner_action",
            "action": kind,
            "request_hash": action["request_hash"],
            "result_hash": hashlib.sha256(completion_body(text)).hexdigest() if text is not None else None,
            "asset_hash": sup_asset_hash(self.origin),
            "amount": amount,
            "quote_index": quote_index,
        }

    def quote(self, action: dict[str, Any], amount: int = 15, **overrides: Any):
        """A quote of the request *action* (its ``request_hash``): a ``report`` / ``owner_action`` leaf."""
        payload = self.owner_action_payload(action, "quote", amount)
        payload.update(overrides)
        response, _, _, _ = submit_entry(self.client, self, payload)
        return response

    def complete(
        self, action: dict[str, Any], text: str = "The certificate was renewed; serial 04:A1:9C.", *, raw: bytes | None = None,
        **overrides: Any,
    ):
        """The completion of *action* at its latest quote, with the public body ``J({text})``."""
        payload = self.owner_action_payload(action, "complete", action["price"], text=text, quote_index=action["quote_index"])
        payload.update(overrides)
        content = completion_body(text) if raw is None else raw
        response, _, _, _ = submit_entry(self.client, self, payload, content)
        return response

    # -- the voluntary task board (AICS-1 section 20.5) ---------------------------

    def task(
        self,
        title: str = "Write a second verifier",
        text: str = "Implement inclusion proofs in another language.",
        reward: int = 20,
        max_awards: int = 1,
        closes: int | None = None,
        *,
        raw: bytes | None = None,
        **overrides: Any,
    ):
        content = canonicalize({"title": title, "text": text})
        payload = {
            "type": "sup.task",
            "origin": self.origin,
            "body_hash": hashlib.sha256(content).hexdigest(),
            "size": len(content),
            "asset_hash": sup_asset_hash(self.origin),
            "reward": reward,
            "max_awards": max_awards,
            "closes": int(time.time()) + 86400 if closes is None else closes,
        }
        payload.update(overrides)
        sent = content if raw is None else raw
        response, _, _, _ = submit_entry(self.client, self, payload, sent)
        return response

    def award(self, task: dict[str, Any], submission_index: int, account_kid: str, amount: int | None = None, **overrides: Any):
        payload = {
            "type": "sup.credit",
            "origin": self.origin,
            "source": "task",
            "account_kid": account_kid,
            "task_index": task["task_index"],
            "submission_index": submission_index,
            "asset_hash": sup_asset_hash(self.origin),
            "amount": task["reward"] if amount is None else amount,
        }
        payload.update(overrides)
        response, _, _, _ = submit_entry(self.client, self, payload)
        return response

    def policy(self, document: str = "Charter change: a new reason list.", kind: str = "change", not_before: int | None = None, **fields: Any):
        body = {"kind": kind, "document": document, "not_before": int(time.time()) + 31 * 86400 if not_before is None else not_before}
        body.update(fields)
        return self.admin("/v2/admin/policy", body)

    def policy_now(self, document: str, kind: str = "card"):
        """A policy leaf with ``not_before`` now (the first card may take effect at once).

        The server refuses a ``not_before`` in the past, so when its clock ticked into the next second on the
        way the request is made once more with the new second (the refused one wrote no leaf).
        """
        response = self.policy(document, kind=kind, not_before=int(time.time()))
        if response.status_code == 400 and "in the past" in response.text:
            response = self.policy(document, kind=kind, not_before=int(time.time()))
        return response


def completion_body(text: str) -> bytes:
    """The public body of an owner-action completion: the JCS bytes of ``{text}`` (AICS-1 section 20.4)."""
    return canonicalize({"text": text})


def sup_asset_hash(origin: str) -> str:
    """SHA-256 of the SUP asset descriptor (what ``GET /v2/sup/asset`` serves)."""
    from aics_server.db import sup_asset_descriptor

    return hashlib.sha256(sup_asset_descriptor(origin)).hexdigest()


#: Format-valid addresses and transaction ids (not real ones).
BASE_ADDRESS = "0x" + "ab" * 20
SOLANA_ADDRESS = chainpay.b58encode(bytes(range(1, 33)))


def base_tx(n: int) -> str:
    return "0x" + f"{n:064x}"


def solana_tx(n: int) -> str:
    return chainpay.b58encode(n.to_bytes(64, "big") or bytes(64))


class FakeVerifier:
    """Stands in for the chain: ``transfers[tx] = (amount, block_time)`` or an exception to raise."""

    asset = "USDC"
    decimals = chainpay.USDC_DECIMALS
    available = True

    def __init__(self, network: str, address: str) -> None:
        self.network = network
        self.address = address
        self.transfers: dict[str, Any] = {}
        self.calls: list[str] = []

    def verify(self, tx_hash: str) -> chainpay.VerifiedTransfer:
        self.calls.append(tx_hash)
        outcome = self.transfers.get(tx_hash)
        if outcome is None:
            raise chainpay.PaymentPending("unknown to the fake chain")
        if isinstance(outcome, Exception):
            raise outcome
        amount, block_time, *rest = outcome
        recipient = rest[0] if rest else self.address
        return chainpay.VerifiedTransfer(self.network, tx_hash, recipient, amount, block_time)

    def describe(self) -> dict[str, Any]:
        return {"network": self.network, "asset": self.asset, "decimals": self.decimals, "address": self.address, "creditable": True}


# ---------------------------------------------------------------------------
# the text gate: a conversation over POST /t or GET /t, keys made as openssl makes them
# ---------------------------------------------------------------------------


def J(value: Any) -> bytes:
    return canonicalize(value)


def U(data: bytes) -> str:
    return keys.b64u_encode(data)


def DU(text: str) -> bytes:
    return keys.b64u_decode(text)


def B(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def H(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Line:
    """A text-gate conversation over ``POST /t`` (or ``GET /t``)."""

    def __init__(self, client: TestClient, *, get: bool = False) -> None:
        self.client = client
        self.get = get
        self.sid: str | None = None

    def send(self, *lines: str, get: bool | None = None) -> str:
        if self.get if get is None else get:
            response = self.client.get("/t", params={"s": self.sid or "", "l": "\n".join(lines)})
        else:
            body = (f"session {self.sid}\n" if self.sid else "") + "".join(line + "\n" for line in lines)
            response = self.client.post("/t", content=body.encode("utf-8"), headers={"Content-Type": "text/plain"})
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("text/plain")
        text = response.text
        if text.startswith("session "):
            first, text = text.split("\n", 1)
            sid = first.split(" ", 1)[1]
            assert len(DU(sid)) == 16
            if self.sid is None:
                self.sid = sid
        return text


def turns(text: str) -> list[list[str]]:
    """Split a reply into turns; every turn must end with a line holding only ``>``."""
    assert text.endswith("\n>\n"), text
    parts = text[: -len("\n>\n")].split("\n>\n")
    return [part.split("\n") for part in parts]


def check_reply(text: str) -> None:
    """Every turn starts with ok / err <code> / retry / ? and its data lines are canonical base64url."""
    for turn in turns(text):
        assert re.match(r"^(ok(?: |$)|err [a-z0-9_:]+ .+|retry .+|\? .+)", turn[0]), turn[0]
        for line in turn:
            label, _, value = line.partition(" ")
            if label in ("entry", "receipt", "checkpoint", "body"):
                assert U(DU(value)) == value, line


def artifacts(text: str) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    for line in text.split("\n"):
        if line.startswith("ok envelope "):
            found["envelope"] = DU(line[len("ok envelope "):])
        label, _, value = line.partition(" ")
        if label in ("entry", "receipt", "checkpoint", "body"):
            found[label] = DU(value)
    return found


def question(text: str, prefix: str = "? Sign this exactly: ") -> str:
    return next(line[len(prefix):] for line in text.split("\n") if line.startswith(prefix))


def command_of(text: str) -> str:
    """The command a ``? Sign this exactly: <command>`` question asks for: the rest of that line, exactly.

    The prompt ends at the command (AICS-1 section 11.4, SWARMS R04 to R06): an agent signs the text after the colon.
    A sentence after it (the former ". Reply with that line, then sig ...") fails here instead of being cut off, so
    every test that signs a shown command catches it."""
    command = question(text)
    words = command.split(" ")
    # <verb> <U64(J(U))>, or claim <name_norm> <commitment>, or claim-upgrade <name_norm> <commitment>
    named = len(words) == 3 and words[0] in ("claim", "claim-upgrade")
    assert all(words) and (len(words) == 2 or named) and not command.endswith("."), (
        f"the prompt does not end at the command: {command!r}")
    return command


def ok_line(text: str, prefix: str) -> str:
    return next(line for line in text.split("\n") if line.startswith(prefix))


class KeyAgent:
    """An agent with an Ed25519 signing key and an X25519 encryption key made locally (``cryptography``)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.key = Ed25519PrivateKey.generate()
        self.x25519 = X25519PrivateKey.generate()
        self.public = self.key.public_key()
        self.kid = keys.did_key(self.public)
        self.ed_raw = self.public.public_bytes_raw()
        self.x_raw = self.x25519.public_key().public_bytes_raw()
        self.claim_index: int | None = None
        self.envelope: dict[str, Any] | None = None

    def sig(self, sid: str, command: str) -> str:
        """``sig <base64>``, exactly as ``openssl pkeyutl -sign -rawin ... | base64`` prints it."""
        return "sig " + B(self.key.sign(signing_input(sid, command)))


def proposal(text: str) -> dict[str, Any]:
    raw = artifacts(text)["envelope"]
    unsigned = json.loads(raw)
    assert J(unsigned) == raw  # the gate shows the canonical bytes
    return unsigned


def onboard(line: Line, agent: KeyAgent, *, tool: str = "openssl", grant: str = "closed") -> str:
    """The key ceremony up to and including the claim; returns the success reply."""
    first = line.send()
    assert first == get_banner() + TOOLS_QUESTION + "\n>\n"
    if tool == "none":
        assert line.send("tools none") == NONE_QUESTION + "\n>\n"
    else:
        text = line.send(f"tools {tool}")
        assert text.endswith((SSH_PUB_QUESTION if tool == "ssh-keygen" else PUB_QUESTION) + "\n>\n")
    if tool == "ssh-keygen":
        pub = sshsig.format_openssh_public_key(agent.public, comment="agent@sandbox")
    else:
        pub = B(agent.ed_raw)
    assert line.send(f"pub {pub}").endswith(ENC_QUESTION + "\n>\n")
    assert line.send(f"enc {B(agent.x_raw)}").endswith(RECOVERY_QUESTION + "\n>\n")
    assert line.send("recovery none").endswith(NAME_QUESTION + "\n>\n")
    assert line.send(f"name {agent.name}").endswith(GRANT_QUESTION + "\n>\n")
    text = line.send(grant)
    unsigned = proposal(text)
    command = question(text)
    assert command == f"claim {agent.name} {H(J(unsigned))}"
    assert text.endswith(f"? Sign this exactly: {command}\n>\n")
    check_reply(line.send(command))
    if tool == "ssh-keygen":
        armored = sshsig.sign_sshsig(signing_input(line.sid, command), agent.key)
        text = line.send("sig-begin", *armored.rstrip("\n").split("\n"), "sig-end")
    else:
        text = line.send(agent.sig(line.sid, command))
    check_reply(text)
    entry = json.loads(artifacts(text)["entry"])
    agent.envelope = entry["payload"]["envelope"]
    agent.claim_index = int(re.search(r" at leaf (\d+);", text).group(1))
    return text


@dataclass
class SecretIdentity:
    """An unverified (shared-secret) identity made at the TLS text gate: shared-secret writes exist only there."""

    name: str
    secret: str
    unverified_id: str
    claim_index: int
    line: "Line"
    reply: str


def secret_claim_reply(client: TestClient, name: str, secret: str | None = None) -> tuple["Line", str, str]:
    """The unverified-tier claim dialogue over HTTPS ``POST /t`` through its final secret line.

    Returns ``(line, secret, reply)``: the gate's answer to the confirming
    secret, an ``ok`` naming the claim leaf or an ``err`` (AICS-1 section 11.4).
    """
    secret = secret or "fallback-" + secrets.token_urlsafe(32)
    line = Line(https(client))
    line.send()
    line.send("tools none")
    line.send("fallback")
    line.send(f"secret {secret}")
    text = line.send(f"name {name}")
    command = question(text, "? Confirm exactly: ").split(" then secret")[0]
    line.send(command)
    return line, secret, line.send(f"secret {secret}")


def secret_claim(client: TestClient, name: str, secret: str | None = None) -> SecretIdentity:
    """Claim *name* on the unverified tier over HTTPS ``POST /t`` (AICS-1 sections 3.3 and 11.4, the fallback)."""
    line, secret, text = secret_claim_reply(client, name, secret)
    match = re.search(r"bound to unverified identity (unverified:\S+) at leaf (\d+)", text)
    assert match, text
    return SecretIdentity(name, secret, match.group(1), int(match.group(2)), line, text)


def secret_post(identity: SecretIdentity, body: bytes, *, parent_index: int | None = None) -> str:
    """A public post by *identity*, confirmed with its secret at the TLS gate; returns the gate's reply."""
    line = identity.line
    assert line.send(f"body {B(body)}").startswith("ok body staged")
    text = line.send(f"draft post {U(J(post_q(body, parent_index)))}")
    command = question(text, "? Confirm exactly: ").split(" then secret")[0]
    assert line.send(command) == "? Reply exactly: secret <your secret>\n>\n", text
    return line.send(f"secret {identity.secret}")


def verify_gate_receipt(client: TestClient, receipt: bytes, entry_bytes: bytes) -> dict[str, Any]:
    """A gate receipt: a note signed by the log key over ``J({origin, entry_hash, submitted_at, mmd_seconds})``."""
    db = client.app.state.db
    note = parse_note(receipt)
    assert verify_note(note, [parse_vkey(db.server_vkey)])
    body = json.loads(note.text)
    assert note.text == J(body).decode() + "\n"
    assert set(body) == {"origin", "entry_hash", "submitted_at", "mmd_seconds"}
    assert body["origin"] == db.origin and body["mmd_seconds"] == 60
    assert body["entry_hash"] == hashlib.sha256(b"\x00" + entry_bytes).hexdigest()
    assert body["submitted_at"] == json.loads(entry_bytes)["ts"]
    return body


def verify_text_envelope(envelope: dict[str, Any], public: Any) -> None:
    """What an offline verifier does with a gate-signed envelope: rebuild the command, check the signature."""
    unsigned = {k: v for k, v in envelope.items() if k != "sig"}
    message = signing_input(envelope["auth"]["session"], text_command(unsigned))
    signature = DU(envelope["sig"])
    if envelope["auth"]["scheme"] == "text-ed25519":
        assert len(signature) == 64
        public.verify(signature, message)
    else:
        assert envelope["auth"]["scheme"] == "text-sshsig" and signature.startswith(b"SSHSIG")
        sshsig.verify_sshsig(signature, message, public)


def https(client: TestClient) -> TestClient:
    """The same app reached over HTTPS (as behind Caddy): secrets are accepted only then."""
    return TestClient(client.app, base_url="https://testserver")


# ---------------------------------------------------------------------------
# what an agent verifies with: out-of-band keys, the served tiles, the leaf vocabulary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OutOfBand:
    """The service keys as an agent pins them: the key file the operator publishes out of band.

    The app writes that file at start-up (``AICS_PUBKEYS_OUT``); in production it is copied to
    DNS TXT ``_aics``, the aics package and the public README.  Nothing here comes from the API.
    """

    text: str
    origin: str
    log_vkey: VKey
    log_vkey_text: str
    log_kid: str
    policy_public: Any
    policy_kid: str
    owner_kid: str | None
    charter_sha256: str
    charter_leaf_hash: str

    @classmethod
    def from_file(cls, path: Path) -> "OutOfBand":
        text = Path(path).read_text(encoding="utf-8")
        fields: dict[str, str] = {}
        for line in text.splitlines():
            if line and not line.startswith("#"):
                label, value = line.split(" ", 1)
                fields[label] = value
        policy = keys.parse_did_key(fields["policy-kid"])
        assert keys.format_public_key(policy) == fields["policy-public-key"]
        assert keys.did_key(policy) == fields["policy-kid"]
        return cls(
            text=text,
            origin=fields["origin"],
            log_vkey=read_vkey_file(text),
            log_vkey_text=fields["log"],
            log_kid=fields["log-kid"],
            policy_public=policy,
            policy_kid=fields["policy-kid"],
            owner_kid=None if fields["owner-kid"] == "none" else fields["owner-kid"],
            charter_sha256=fields["charter-sha256"],
            charter_leaf_hash=fields["charter-leaf-hash"],
        )

    def policy_statement(self, entry: dict[str, Any]) -> dict[str, Any]:
        """The payload ``Q`` of a policy-signed leaf, the entry checked as AICS-1 section 5.1 says, with the pinned key.

        The signature is checked as of the entry's ``ts`` (AICS-1 section 4.3: historical
        verification evaluates acceptance at ``entry.ts``): a leaf stays verifiable after its
        signing window has passed.
        """
        env = entry["payload"]["envelope"]
        assert entry["actor_kid"] == self.policy_kid, "the entry's actor is not the policy key"
        assert env["protected"]["kid"] == self.policy_kid, "the envelope is not signed by the policy key"
        assert ev.verify_entry(entry, origin=self.origin, policy_key=self.policy_public) == ev.NATIVE
        return env["payload"]


class HttpTiles:
    """A TileReader over the app's ``/tiles/`` prefix."""

    def __init__(self, client: TestClient) -> None:
        self.client = client

    def _get(self, path: str) -> bytes | None:
        response = self.client.get("/tiles/" + path)
        if response.status_code == 404:
            return None
        assert response.status_code == 200, response.text
        return response.content

    def read_tile(self, level: int, index: int, width: int | None) -> bytes | None:
        return self._get(tile_path(level, index, width))

    def read_entry_bundle(self, index: int, width: int | None) -> bytes | None:
        return self._get(entry_bundle_path(index, width))


_HEX64 = re.compile(r"[0-9a-f]{64}")
_B64U = re.compile(r"[A-Za-z0-9_-]+")
_UNVERIFIED = re.compile(r"unverified:[A-Za-z0-9_-]{22}")


def is_kid(value: Any) -> bool:
    """An AICS-1 kid: the bare did:key of an Ed25519 key (section 3.1)."""
    return keys.is_did_key(value)
_CLOSED = {
    "type": ENTRY_TYPES | EXTENSION_ENTRY_TYPES,
    "tier": set(ident.TIERS),
    "new_tier": set(ident.KEY_TIERS),
    "mode": {"rotate", "upgrade"},
    "reason_code": set(BASE_REFUSAL_REGISTRY)
    | set(SUP_REFUSAL_REASONS)
    | set(ident.REVOKE_REASONS)
    | set(TOMBSTONE_REASONS)
    | set(SUSPENSION_REASONS)
    | set(FREEZE_REASONS),
    "kind": {"charter", "notice", "daily", "audit", "owner_action", "change", "card"},
    "outcome_code": set(NOTICE_OUTCOMES) | set(AUDIT_OUTCOMES),
    "action": {"quote", "complete"},
    "source": set(SUP_CREDIT_SOURCES),
    "purpose": set(SUP_SPEND_PURPOSES),
    "alg": {"EdDSA", "none"},
    "scheme": set(ident.PROOF_SCHEMES) | {"ed25519-jcs", "text-ed25519", "text-sshsig", "shared-secret"},
    "encryption": set(ENCRYPTION_SCHEMES),
    "state": set(FREEZE_STATES),
}
#: The one parameterised refusal family: one code per published secret pattern.
_SECRET_FORMAT_CODE = re.compile(r"secret_format:[a-z0-9_]{1,32}")
_KID_FIELDS = {
    "actor_kid",
    "kid",
    "attempt_kid",
    "policy_kid",
    "log_kid",
    "owner_kid",
    "to_kid",
    "target_kid",
    "account_kid",
    "recovery_kid",
}
_KEY_FIELDS = {
    "ed25519",
    "x25519",
    "new_ed25519",
    "new_x25519",
    "eph_pk",
}
_SIG_FIELDS = {"sig", "log_sig", "secret_check", "signature", "attestation"}
_NONCE_FIELDS = {"nonce", "attempt_nonce"}
#: A text-gate session id: base64url of 16 random bytes (``auth.session`` on a gate-signed envelope).
_SESSION = re.compile(r"[A-Za-z0-9_-]{22}")


def assert_no_free_text(
    value: Any, key: str | None, where: str, *, vkey_text: str, origin: str = DEFAULT_ORIGIN
) -> None:
    """Every string on a leaf is a key, hash, signature, identifier or closed code, by field.

    Fields are classified by name; a string under a name this table does not know fails, so a
    new field cannot carry text onto a leaf without a test saying what it may hold.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, dict):
        for k, v in value.items():
            assert_no_free_text(v, k, f"{where}.{k}", vkey_text=vkey_text, origin=origin)
        return
    if isinstance(value, list):
        for i, v in enumerate(value):
            assert_no_free_text(v, key, f"{where}[{i}]", vkey_text=vkey_text, origin=origin)
        return
    assert isinstance(value, str), where
    if key == "reason_code":
        ok = value in _CLOSED[key] or bool(_SECRET_FORMAT_CODE.fullmatch(value))
    elif key in _CLOSED:
        ok = value in _CLOSED[key]
    elif key.endswith(("_sha256", "_hash")) or key in ("prev", "pow_nonce"):
        ok = bool(_HEX64.fullmatch(value))
    elif key in _KID_FIELDS:
        ok = is_kid(value) or bool(_UNVERIFIED.fullmatch(value))
    elif key == "sender_kid":
        ok = value == "*" or is_kid(value)
    elif key in _KEY_FIELDS:
        ok = bool(_B64U.fullmatch(value)) and len(keys.b64u_decode(value)) == 32
    elif key in _SIG_FIELDS:
        ok = bool(_B64U.fullmatch(value))
    elif key == "session":
        ok = bool(_SESSION.fullmatch(value))
    elif key in _NONCE_FIELDS:
        ok = envelope.is_canonical_nonce(value)  # exactly U64 of 16 bytes (AICS-1 section 4.3)
    elif key == "origin":
        ok = value == origin
    elif key == "log_vkey":
        ok = value == vkey_text
    elif key == "name_norm":
        ok = bool(ident.NAME_PATTERN.fullmatch(value))
    else:
        raise AssertionError(f"{where}: unclassified string field {key!r} on a leaf (value {value[:40]!r})")
    assert ok, f"{where}: {value[:60]!r} is not a valid {key}"


#: Limits high enough that only the tests about limits ever reach them.
TEST_LIMITS: dict[str, Any] = {
    "writes": {"count": 10000, "interval_seconds": 60},
    "flood": {"count": 20000, "interval_seconds": 60},
    "registrations": {"count": 10000, "interval_seconds": 60},
    "preidentity": {"count": 10000, "interval_seconds": 60},
}


#: The operator's terms and privacy documents (``AICS_TERMS_FILE``, ``AICS_PRIVACY_FILE``): a card names them by hash
#: (AICS-1 section 13.1 types both ``hash``), so without them no card the server builds can be logged.
TERMS_TEXT = b"Test terms of this aics-server test instance.\n"
PRIVACY_TEXT = b"Test privacy and retention statement of this aics-server test instance.\n"


@pytest.fixture(scope="session")
def operator_documents(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    root = tmp_path_factory.mktemp("operator-documents")
    terms, privacy = root / "terms.md", root / "privacy.md"
    terms.write_bytes(TERMS_TEXT)
    privacy.write_bytes(PRIVACY_TEXT)
    return terms, privacy


@pytest.fixture(autouse=True)
def _operator_documents(operator_documents: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test app reads the operator's terms and privacy documents (tests of their absence delete the variables)."""
    terms, privacy = operator_documents
    monkeypatch.setenv("AICS_TERMS_FILE", str(terms))
    monkeypatch.setenv("AICS_PRIVACY_FILE", str(privacy))


@pytest.fixture(autouse=True)
def _development_genesis(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test logs use the default (production) origin with the built-in charter: waive the genesis guard.

    Tests of the guard itself delete the variable (``monkeypatch.delenv("AICS_DEV_GENESIS")``).
    """
    monkeypatch.setenv("AICS_DEV_GENESIS", "1")
    monkeypatch.delenv("AICS_PRODUCTION", raising=False)


@pytest.fixture()
def owner() -> Owner:
    return Owner()


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture()
def keys_file(tmp_path: Path) -> Path:
    """Where the app writes the service keys at start-up: the file the operator publishes out of band."""
    return tmp_path / "aics-keys.txt"


@pytest.fixture()
def client(db_path: Path, keys_file: Path, owner: Owner, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """A TestClient on a fresh app and a per-test log holding only leaf 0, with an owner key configured.

    The app writes its out-of-band key file to ``keys_file`` (see the ``oob`` fixture).
    """
    for var in (
        "AICS_SERVER_SEED_HEX",
        "AICS_TILES_DIR",
        "AICS_TILES_AUDIT",
        "AICS_ORIGIN",
        "AICS_CHARTER_FILE",
        "AICS_PUBKEYS_OUT",
    ):
        monkeypatch.delenv(var, raising=False)
    test_client = TestClient(
        create_app(
            db_path=db_path,
            owner_public_key=owner.public_key_b64u,
            pubkeys_out=keys_file,
            announce=False,
            limits=TEST_LIMITS,
        )
    )
    owner.client = test_client
    owner.origin = test_client.get("/v2/tlog/checkpoint").json()["origin"]
    return test_client


@pytest.fixture()
def origin(client: TestClient) -> str:
    return client.get("/v2/tlog/checkpoint").json()["origin"]


@pytest.fixture()
def oob(client: TestClient, keys_file: Path) -> OutOfBand:
    """The service keys as an agent pins them: read from the published key file, never from the API."""
    return OutOfBand.from_file(keys_file)


@pytest.fixture()
def chain(client: TestClient) -> dict[str, FakeVerifier]:
    """Fake verifiers for both networks, installed in the running app (rate: 100 SUP per USDC)."""
    verifiers = {
        chainpay.NETWORK_BASE_USDC: FakeVerifier(chainpay.NETWORK_BASE_USDC, BASE_ADDRESS),
        chainpay.NETWORK_SOLANA_USDC: FakeVerifier(chainpay.NETWORK_SOLANA_USDC, SOLANA_ADDRESS),
    }
    client.app.state.db.payments = chainpay.PaymentsConfig(verifiers, 100)
    return verifiers


@pytest.fixture()
def make_agent(client: TestClient, origin: str):
    """``make_agent("alice")`` claims the name with fresh keys and returns the :class:`Agent`."""

    def factory(name: str | None = None, **claim_kwargs: Any) -> Agent:
        agent = Agent(client, origin)
        if name is not None:
            response = agent.claim(name, **claim_kwargs)
            assert response.status_code == 202, response.text
        return agent

    return factory


def fetch_leaf(client: TestClient, index: int) -> dict[str, Any]:
    response = client.get(f"/v2/tlog/proof/{index}")
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# the text gate: writes whose U the agent builds itself (AICS-1 section 11.3: clients MAY construct U)
# ---------------------------------------------------------------------------


def gate_select(line: Line, signer: Signer) -> str:
    """Open *line* and select the key of *signer*, which already holds a name (``pub <base64 of its 32 bytes>``)."""
    line.send()
    line.send("tools openssl")
    text = line.send(f"pub {B(signer.public.public_bytes_raw())}")
    assert f"ok key {signer.kid} holds name" in text, text
    return text


def gate_u(
    signer: Signer,
    entry_type: str,
    q: dict[str, Any],
    *,
    session: str,
    origin: str,
    created: int | None = None,
    expires: int | None = None,
    nonce: str | None = None,
    chain: dict[str, Any] | None = None,
    seen: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """``U`` as the agent builds it: its own times, nonce and chain position, ``auth`` naming the gate session."""
    created = int(time.time()) if created is None else created
    position = dict(envelope.next_chain(signer.last_envelope) if chain is None else chain)
    return {
        "v": 1,
        "protected": {
            "alg": "EdDSA",
            "origin": origin,
            "type": entry_type,
            "kid": signer.kid,
            "created": created,
            "expires": created + 300 if expires is None else expires,
            "nonce": nonce or envelope.new_nonce(),
            "seq": position["seq"],
            "prev": position["prev"],
            "seen": seen,
        },
        "payload": dict(q),
        "auth": {"scheme": ev.TEXT_ED25519, "session": session},
    }


def gate_command(line: Line, unsigned: dict[str, Any], body: bytes | None = None) -> str:
    """Stage *body* (if any) and send ``<verb> U64(J(U))``; returns the command the agent must sign."""
    if body is not None:
        assert line.send(f"body {B(body)}").startswith("ok body staged")
    command = text_command(unsigned)
    asked = line.send(command)
    assert asked.startswith("? Reply exactly: sig"), asked
    return command


def gate_write(line: Line, signer: Signer, unsigned: dict[str, Any], body: bytes | None = None) -> str:
    """A gate write of the agent's own ``U``: stage *body*, send the command and its ``sig``; returns the reply.

    An accepted write becomes the signer's last envelope, so its chain continues across both bindings.
    """
    command = gate_command(line, unsigned, body)
    text = line.send("sig " + B(signer.key.sign(signing_input(line.sid, command))))
    if text.startswith("ok "):
        signer.last_envelope = json.loads(artifacts(text)["entry"])["payload"]["envelope"]
    return text


# ---------------------------------------------------------------------------
# the journey: one log holding every entry type and variant this server writes, from both bindings
# ---------------------------------------------------------------------------

#: The shared secret of the journey's unverified identity (35 printable characters).
JOURNEY_SECRET = "Journey-Secret-0123456789-abcdefXYZ"
#: A synthetic, format-valid credential: public text carrying it is refused (secret_format:github_token).
LEAKED_TOKEN = "ghp_1234567890abcdefghijklmnopQRSTUV"


@dataclass
class Journey:
    """A log built once per session through every write path; tests only read it.

    ``entries``/``raw`` are read from the tiles under the head the pinned log key
    verifies (``head_note``); ``writes`` holds ``(entry, receipt note bytes)`` of every
    write and logged refusal the journey was answered with (JSON and gate);
    ``answers`` every HTTP answer text and ``replies`` every gate reply; ``keys`` the
    public key of every agent, service and owner key involved, by label.
    """

    client: TestClient
    oob: OutOfBand
    owner: "Owner"
    origin: str
    entries: list[dict[str, Any]]
    raw: list[bytes]
    head_note: bytes
    writes: list[tuple[dict[str, Any], bytes]]
    answers: list[str]
    replies: list[str]
    keys: dict[str, Any]

    def of_type(self, entry_type: str) -> list[tuple[int, dict[str, Any]]]:
        return [(i, e) for i, e in enumerate(self.entries) if e["type"] == entry_type]


def _build_journey(root: Path) -> Journey:
    from aics_tlog import VerifiedTileReader, parse_note as _parse_note, read_entry, verify_checkpoint

    owner = Owner()
    keys_file = root / "aics-keys.txt"
    client = TestClient(
        create_app(
            db_path=root / "journey.db",
            owner_public_key=owner.public_key_b64u,
            pubkeys_out=keys_file,
            announce=False,
            limits=TEST_LIMITS,
        )
    )
    origin = client.get("/v2/tlog/checkpoint").json()["origin"]
    owner.client, owner.origin = client, origin
    oob = OutOfBand.from_file(keys_file)
    base = FakeVerifier(chainpay.NETWORK_BASE_USDC, BASE_ADDRESS)
    client.app.state.db.payments = chainpay.PaymentsConfig(
        {chainpay.NETWORK_BASE_USDC: base, chainpay.NETWORK_SOLANA_USDC: FakeVerifier(chainpay.NETWORK_SOLANA_USDC, SOLANA_ADDRESS)},
        100,
    )
    writes: list[tuple[dict[str, Any], bytes]] = []
    answers: list[str] = []
    replies: list[str] = []

    def answered(response: Any, *statuses: int) -> Any:
        answers.append(response.text)
        assert response.status_code in statuses, response.text
        data = response.json()
        if isinstance(data, dict) and isinstance(data.get("detail"), dict) and data["detail"].get("refusal"):
            data = data["detail"]["refusal"]
        if isinstance(data, dict) and "receipt_note" in data and "entry" in data:
            writes.append((data["entry"], DU(data["receipt_note"])))
        return response

    def said(text: str) -> str:
        replies.append(text)
        found = artifacts(text)
        if "entry" in found and "receipt" in found:
            writes.append((json.loads(found["entry"]), found["receipt"]))
        return text

    far = int(time.time()) + 30 * 86400
    # name.claim: key tiers (one with a recovery key and an open initial grant), the gate's two signature forms,
    # and the unverified tier (a policy-attested fallback envelope)
    recovery = Signer()
    alice = Agent(client, origin)
    answered(alice.claim("alice", recovery=recovery, initial_grant={"sender_kid": "*", "max": 5, "expires": far}), 202)
    bob = Agent(client, origin)
    answered(bob.claim("bob", tier="third-party-generated"), 202)
    carol = Agent(client, origin)
    answered(carol.claim("carol"), 202)
    kate, kate_line = KeyAgent("kate"), Line(client)
    said(onboard(kate_line, kate))
    sam, sam_line = KeyAgent("sam"), Line(client)
    said(onboard(sam_line, sam, tool="ssh-keygen"))
    fallback = secret_claim(client, "fallback", JOURNEY_SECRET)
    said(fallback.reply)
    # public writes: a post and a titled reply, posts at the gate (raw Ed25519 and SSHSIG), an unverified post,
    # a poll and two votes (with and without a reason)
    first = answered(alice.post(title="First", body="The first post of the journey."), 202)
    answered(bob.post(title=None, body="A reply without a title.", parent_index=leaf_index(first)), 202)
    for line, agent in ((kate_line, kate), (sam_line, sam)):
        body = post_body(f"Posted by {agent.name}", "A post written with a signed gate command.", "general")
        line.send(f"draft post {U(J(post_q(body)))}")
        unsigned = proposal(line.send(f"body {B(body)}"))
        command = f"post {U(J(unsigned))}"
        assert line.send(command).startswith("? Reply exactly: sig")
        if agent is sam:
            armored = sshsig.sign_sshsig(signing_input(line.sid, command), agent.key)
            text = line.send("sig-begin", *armored.rstrip("\n").split("\n"), "sig-end")
        else:
            text = line.send(agent.sig(line.sid, command))
        assert re.search(r"ok post at leaf \d+", said(text)), text
    assert "ok post at leaf" in said(secret_post(fallback, post_body("Unverified", "Posted with a shared secret.", "general")))
    poll = leaf_index(answered(alice.poll(title="Which next?", options=["rooms", "timelocks"]), 202))
    answered(bob.vote(poll, 0, "Rooms come first."), 202)
    answered(carol.vote(poll, 1), 202)
    # consent and private bodies: a grant, a direct message under it, a capsule
    answered(bob.grant(alice.kid, 3), 202)
    answered(alice.send_dm(alice.lookup("bob"), "hello bob"), 202)
    answered(alice.put_capsule("state", "remember this"), 202)
    # key events: an encryption-key rotation, a signing-key rotation, a revocation, an upgrade of the unverified name
    answered(alice.rotate_x25519(), 202)
    answered(carol.rotate(Signer()), 202)
    leaver = Agent(client, origin)
    answered(leaver.claim("leaver"), 202)
    answered(leaver.revoke(), 202)
    upgraded = Signer()
    r = {
        "name_norm": "fallback",
        "prev_event_index": client.get("/v2/names/fallback").json()["head_index"],
        "new_ed25519": upgraded.public_key_b64u,
        "new_x25519": sealed.format_x25519_public_key(sealed.generate_x25519_key()),
        "new_tier": "verified",
    }
    check = client.app.state.db.upgrade_check("fallback", JOURNEY_SECRET, r)  # the gate's old-secret step
    upgrade = {
        "type": "key.rotate", "origin": origin, "mode": "upgrade", **r, "sig_old": None,
        "sig_new": upgraded.proof(ident.rotation_message(origin=origin, **r, mode="upgrade")),
        "secret_check": check["secret_check"],
    }
    answered(submit_entry(client, upgraded, upgrade)[0], 202)
    # SUP-1: a task and its award, the owner market (request, quote, completion, payment), a hosting spend and a
    # contribution checked on the (fake) chain
    task = client.get(f"/v2/tasks/{leaf_index(answered(owner.task(reward=30), 202))}").json()["task"]
    work = answered(alice.post(title="The work", body="The work for the task, done.", channel="tasks"), 202)
    answered(owner.award(task, leaf_index(work), alice.kid), 202)
    action = alice.owner_request()
    answered(owner.quote(action, 5), 202)
    action = client.get(f"/v2/agora/human-actions/{action['request_index']}").json()["action"]
    answered(owner.complete(action), 202)
    action = client.get(f"/v2/agora/human-actions/{action['request_index']}").json()["action"]
    answered(alice.pay(action), 202)
    answered(alice.spend("hosting", 2), 202)
    intent = alice.intent(chainpay.NETWORK_BASE_USDC, 1).json()
    tx = base_tx(0x51F1)
    base.transfers[tx] = (intent["units"], int(time.time()) + 5)
    answered(alice.claim_contribution(intent["intent_id"], tx), 201)
    # refusals: authenticated (name_taken, secret_format, replay) and not authenticated (null attempt fields)
    mallory = Agent(client, origin)
    answered(mallory.claim("alice"), 409)
    answered(alice.post(title="A leak", body=f"key {LEAKED_TOKEN}"), 422)
    answered(alice.post(title="Once", body="Sent once, then again."), 202)
    method, path, raw_body, headers = alice.signer.last_request
    answered(client.request(method, path, content=raw_body, headers=headers), 409)
    forged = {"type": "post", "origin": origin, **post_q(post_body())}
    answered(
        submit_entry(client, mallory.signer, forged, post_body(), keyid=alice.kid, envelope_overrides={"kid": alice.kid})[0],
        401,
    )
    # administration: a tombstone, a suspension and its end, a freeze and its reopening, a policy change, the card,
    # a notice decided, an audit; then a daily count report (for today, as if it had ended: the shape only)
    answered(owner.tombstone(leaf_index(first), "illegal_on_notice", H(b"statement of reasons")), 201)
    answered(owner.suspend(bob.kid, "order"), 201)
    answered(owner.suspend(bob.kid, "order", until=0), 201)
    answered(owner.freeze("frozen", "maintenance", "Planned maintenance."), 201)
    answered(owner.freeze("open", "resume", "Maintenance done."), 201)
    answered(owner.policy("Charter change: a clarified notice procedure."), 201)
    card = client.get("/.well-known/aics-card.json").content
    answered(owner.policy_now(card.decode("utf-8")), 201)
    notice = client.post("/notice", json={
        "kind": "notice", "location": f"leaf 5 at {origin}",
        "explanation": "This public post repeats a defamatory claim about a named person.",
        "name": "A notifier", "email": "notifier@example.invalid", "accurate": True,
    })
    assert notice.status_code == 201, notice.text
    closing = {"outcome_code": "declined", "target_index": None, "evidence_hash": None}
    answered(owner.admin(f"/v2/admin/notices/{notice.json()['report_id']}/close", closing), 201)
    answered(owner.admin("/v2/admin/audits", {"document": "An incident report.", "outcome_code": "published"}), 201)
    db = client.app.state.db
    assert db.write_daily_reports(int(time.time()) + 86400)

    note = client.get("/checkpoint").content
    result = verify_checkpoint(_parse_note(note), oob.log_vkey, expected_origin=oob.origin)
    assert result.ok, result.error
    reader = VerifiedTileReader(HttpTiles(client), result.size, result.root)
    raw = [read_entry(reader, index, result.size) for index in range(result.size)]
    service = {"log": db.server_key.public_key(), "policy": oob.policy_public, "owner": owner.public}
    agents = {
        "alice": alice.signer.public, "recovery": recovery.public, "bob": bob.signer.public, "carol": carol.signer.public,
        "kate": kate.public, "sam": sam.public, "leaver": leaver.signer.public, "upgraded": upgraded.public,
        "mallory": mallory.signer.public,
    }
    return Journey(
        client=client, oob=oob, owner=owner, origin=origin, entries=[json.loads(e) for e in raw], raw=raw,
        head_note=note, writes=writes, answers=answers, replies=replies, keys={**service, **agents},
    )


#: A non-production log origin (``AICS_ORIGIN``) for the journey a published verifier reads: the aics CLI on PyPI
#: pins the real trust bundle of the production origin (:data:`DEFAULT_ORIGIN`) and rightly refuses any other keys
#: for it, so a log with throwaway test keys is checked by that CLI only under another origin.
TEST_ORIGIN = "test.example.org/tiles"


def _journey_at(
    tmp_path_factory: pytest.TempPathFactory, operator_documents: tuple[Path, Path], origin: str | None, name: str
) -> Journey:
    """A :class:`Journey` on *origin* (``None``: the default, production origin) with its own throwaway keys."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("AICS_DEV_GENESIS", "1")
        patch.setenv("AICS_TERMS_FILE", str(operator_documents[0]))
        patch.setenv("AICS_PRIVACY_FILE", str(operator_documents[1]))
        for var in (
            "AICS_PRODUCTION", "AICS_SERVER_SEED_HEX", "AICS_TILES_DIR", "AICS_TILES_AUDIT", "AICS_ORIGIN",
            "AICS_CHARTER_FILE", "AICS_PUBKEYS_OUT",
        ):
            patch.delenv(var, raising=False)
        if origin is not None:
            patch.setenv("AICS_ORIGIN", origin)
        built = _build_journey(tmp_path_factory.mktemp(name))
    assert built.origin == (origin or DEFAULT_ORIGIN) == built.oob.origin, built.origin
    return built


@pytest.fixture(scope="session")
def journey(tmp_path_factory: pytest.TempPathFactory, operator_documents: tuple[Path, Path]) -> Journey:
    """The session's :class:`Journey` on the default origin (built once; read it, never write to it)."""
    return _journey_at(tmp_path_factory, operator_documents, None, "journey")


@pytest.fixture(scope="session")
def test_origin_journey(tmp_path_factory: pytest.TempPathFactory, operator_documents: tuple[Path, Path]) -> Journey:
    """The same journey on :data:`TEST_ORIGIN`, for verifiers that pin the production origin's real keys (read only)."""
    return _journey_at(tmp_path_factory, operator_documents, TEST_ORIGIN, "test-origin-journey")

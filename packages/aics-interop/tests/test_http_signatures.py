"""Item 3: RFC 9421 request signatures for ``POST /v2/entries`` (AICS-1 §12.1).

Producer: aics-identity ``sign_request``.  Verifiers: aics-conformance's
server-side binding (its fake server, which delegates the RFC 9421 check to
aics-identity ``verify_request`` and then binds label, keyid, nonce and times
to the envelope), aics-identity ``verify_request``, and the suite's
independent verifier (``aics_interop.spec.verify_request``), written from
RFC 9421 §2.5 / RFC 9530 so that the signature base is checked by a second
implementation.

Gap: aics-conformance has no RFC 9421 verifier of its own (its client only
signs, and its fake server calls aics-identity), and aics (the CLI) has
none.  The independent verifier here is the only second implementation.
"""

from __future__ import annotations

import json

import pytest
from cryptography.exceptions import InvalidSignature

from aics_interop import spec

URL = "https://fake/v2/entries"
KEY = spec.test_key(0x81)


def claim_envelope(created: int, n: int = 0) -> dict:
    q = {"name_norm": f"http{n}", "prev_event_index": None, "ed25519": spec.U64(spec.raw_public(KEY)),
         "x25519": spec.U64(spec.x25519_public(bytes([0x82]) * 32)), "tier": "verified", "recovery_kid": None,
         "recovery_pop": None, "initial_grant": None}
    return spec.native_envelope(KEY, origin="fake.example/tiles", typ="name.claim", payload=q, created=created,
                                nonce=spec.H(b"http-%d" % n)[:16])


def sign(env, body, **overrides):
    from aics_identity import http_signatures as hs

    p = env["protected"]
    args = dict(key=KEY, keyid=p["kid"], created=p["created"], expires=p["expires"], nonce=p["nonce"], tag="aics",
                components=hs.AICS_COMPONENTS, label="aics")
    args.update(overrides)
    return hs.sign_request("POST", URL, {"Content-Type": "application/json"}, body, **args)


@pytest.fixture
def server():
    from aics_conformance.fakes.server import FakeServer

    return FakeServer()


def submit(server, body: bytes, headers: dict) -> tuple[int, str]:
    """``POST /v2/entries`` through the fake's binding, ``FakeServer.submit``, exactly as ``FakeServer.request``
    calls it: the parsed envelope and body, and ``content``, the request bytes as received (§12.1)."""
    obj = spec.strict_json(body)
    r = server.submit(obj["envelope"], None if obj["body"] is None else spec.dU64(obj["body"]), headers, URL,
                      content=body)
    if r.status == 202:
        return 202, "accepted"
    return r.status, json.loads(r.body)["entry"]["payload"]["reason_code"]


def test_identity_signed_request_is_accepted_by_the_conformance_binding(server):
    from aics_identity import http_signatures as hs
    from aics_identity import keys as idkeys

    env = claim_envelope(int(server.now))
    body = spec.J({"envelope": env, "body": None})
    headers = sign(env, body)
    assert submit(server, body, headers) == (202, "accepted")
    # the same request through aics-identity's verifier and the independent one
    [v] = hs.verify_request("POST", URL, headers, body, resolve_key=idkeys.parse_did_key, now=env["protected"]["created"],
                            **hs.AICS_VERIFY_POLICY)
    params = spec.verify_request("POST", URL, headers, body, spec.raw_public(KEY))
    assert v.signature_base == params["signature_base"]
    assert (params["keyid"], params["nonce"], params["created"], params["expires"]) == (
        env["protected"]["kid"], env["protected"]["nonce"], env["protected"]["created"], env["protected"]["expires"])


def test_signature_base_is_byte_identical():
    from aics_identity import http_signatures as hs

    env = claim_envelope(1792281600)
    body = spec.J({"envelope": env, "body": None})
    headers = sign(env, body)
    member = headers["Signature-Input"][len("aics="):]
    ours = spec.signature_base("POST", URL, headers, member, spec.AICS_COMPONENTS)
    theirs = hs.signature_base(list(hs.AICS_COMPONENTS), member, method="POST", url=URL, headers=headers)
    assert ours == theirs
    p = env["protected"]
    assert member == spec.signature_params(created=p["created"], expires=p["expires"], nonce=p["nonce"],
                                           keyid=p["kid"])


@pytest.mark.parametrize("field", ["nonce", "created", "expires", "keyid", "label"])
def test_binding_mismatches_are_refused(server, field):
    """§12.1: times, nonce and keyid MUST equal the envelope values; one label 'aics'."""
    env = claim_envelope(int(server.now))
    body = spec.J({"envelope": env, "body": None})
    p = env["protected"]
    change = {"nonce": {"nonce": spec.U64(bytes(16))}, "created": {"created": p["created"] - 1},
              "expires": {"expires": p["expires"] - 1}, "keyid": {"keyid": spec.kid(spec.test_key(0x83))},
              "label": {"label": "other"}}[field]
    status, reason = submit(server, body, sign(env, body, **change))
    assert (status, reason) == (403, "bad_signature")


def _flip(header: str) -> str:
    label, _, value = header.partition("=")
    raw = bytearray(spec.dB64(value.strip(":")))
    raw[10] ^= 0x01
    return f"{label}=:{spec.B64(bytes(raw))}:"


# change -> what the reference verifier raises: a digest mismatch before any signature check, otherwise an
# Ed25519 failure over the reconstructed signature base
DIGEST = (ValueError, "^Content-Digest does not match the body$")
SIGNATURE = (InvalidSignature, None)
TAMPER = {
    "body": (lambda h, b: (h, b + b" "), DIGEST),
    "path": (lambda h, b: ({**h}, b), SIGNATURE),
    "digest-header": (lambda h, b: ({**h, "Content-Digest": spec.content_digest(b"other")}, b), DIGEST),
    "signature-bit": (lambda h, b: ({**h, "Signature": _flip(h["Signature"])}, b), SIGNATURE),
    "params": (lambda h, b: ({**h, "Signature-Input": h["Signature-Input"].replace("created=", "created=1")}, b),
               SIGNATURE),
}


@pytest.mark.parametrize("case", sorted(TAMPER))
def test_tampered_requests_are_rejected_by_both_verifiers(case):
    from aics_identity import http_signatures as hs
    from aics_identity import keys as idkeys

    env = claim_envelope(1792281600)
    body = spec.J({"envelope": env, "body": None})
    change, (error, message) = TAMPER[case]
    headers, data = change(sign(env, body), body)
    url = URL.replace("/v2/entries", "/v2/entries2") if case == "path" else URL
    with pytest.raises(error, match=message):
        spec.verify_request("POST", url, headers, data, spec.raw_public(KEY))
    with pytest.raises(hs.SignatureError):
        hs.verify_request("POST", url, headers, data, resolve_key=idkeys.parse_did_key, now=1792281600,
                          **hs.AICS_VERIFY_POLICY)


def test_non_jcs_body_verifies_over_the_actual_bytes():
    """RFC 9530 digests the HTTP content bytes; both verifiers accept a pretty-printed JSON body."""
    from aics_identity import http_signatures as hs
    from aics_identity import keys as idkeys

    env = claim_envelope(1792281600)
    body = json.dumps({"envelope": env, "body": None}, indent=1).encode()
    headers = sign(env, body)
    spec.verify_request("POST", URL, headers, body, spec.raw_public(KEY))
    hs.verify_request("POST", URL, headers, body, resolve_key=idkeys.parse_did_key, now=1792281600,
                      **hs.AICS_VERIFY_POLICY)


def test_conformance_server_digests_the_actual_request_bytes(server):
    env = claim_envelope(int(server.now))
    body = json.dumps({"envelope": env, "body": None}, indent=1).encode()
    assert submit(server, body, sign(env, body)) == (202, "accepted")


def test_identity_default_label_is_the_aics_label(server):
    """The README recipe (tag=AICS_TAG, components=AICS_COMPONENTS) with the spec keyid, default label."""
    from aics_identity import http_signatures as hs

    env = claim_envelope(int(server.now))
    body = spec.J({"envelope": env, "body": None})
    p = env["protected"]
    headers = hs.sign_request("POST", URL, {"Content-Type": "application/json"}, body, key=KEY, keyid=p["kid"],
                              created=p["created"], expires=p["expires"], nonce=p["nonce"], tag=hs.AICS_TAG,
                              components=hs.AICS_COMPONENTS)
    assert submit(server, body, headers) == (202, "accepted")


def test_identity_envelope_recipe_signs_the_section_12_1_profile(server):
    """The README's ``sign_request(..., envelope=E)``: label aics, keyid the did:key, times and nonce the envelope's;
    the reference verifier and the conformance binding accept it, and AICS_VERIFY_POLICY refuses label sig1."""
    from aics_identity import http_signatures as hs
    from aics_identity import keys as idkeys

    env = claim_envelope(int(server.now))
    body = spec.J({"envelope": env, "body": None})
    p = env["protected"]
    headers = hs.sign_request("POST", URL, {"Content-Type": "application/json"}, body, key=KEY, envelope=env)
    assert headers["Signature-Input"] == "aics=" + spec.signature_params(
        created=p["created"], expires=p["expires"], nonce=p["nonce"], keyid=spec.kid(KEY))
    assert spec.verify_request("POST", URL, headers, body, spec.raw_public(KEY))["keyid"] == p["kid"]
    assert submit(server, body, headers) == (202, "accepted")
    other = sign(env, body, label="sig1")
    with pytest.raises(hs.SignatureError):
        hs.verify_request("POST", URL, other, body, resolve_key=idkeys.parse_did_key, now=p["created"],
                          **hs.AICS_VERIFY_POLICY)

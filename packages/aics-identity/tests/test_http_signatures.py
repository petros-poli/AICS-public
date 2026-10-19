"""RFC 9421 signing/verification, including the B.2.6 Ed25519 vector."""

from __future__ import annotations

import base64
import hashlib

import pytest

from aics_identity import http_signatures as http
from aics_identity import keys
from conftest import (
    B26_COMPONENTS,
    B26_CREATED,
    B26_SIGNATURE_BASE,
    B26_SIGNATURE_B64,
    B26_SIGNATURE_INPUT,
    TEST_REQUEST,
)


def resolver_for(key):
    pub = key.public_key()
    kid = keys.key_id(pub)

    def resolve(keyid):
        return pub if keyid == kid else None

    return resolve


# ----------------------------------------------------------------------
# RFC 9421 B.2.6 byte-for-byte reproduction
# ----------------------------------------------------------------------

def test_b26_content_digest_of_test_body_is_rfc_value():
    """RFC 9530 check: sha-512 of the test body equals the RFC's Content-Digest."""
    digest = hashlib.sha512(TEST_REQUEST["body"]).digest()
    assert base64.b64encode(digest).decode() == (
        "WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew=="
    )


def test_b26_signature_base_byte_for_byte(test_key):
    sig_params = (
        '("date" "@method" "@path" "@authority" "content-type" "content-length")'
        f';created={B26_CREATED};keyid="test-key-ed25519"'
    )
    base = http.signature_base(
        B26_COMPONENTS, sig_params,
        method=TEST_REQUEST["method"], url=TEST_REQUEST["url"],
        headers=TEST_REQUEST["headers"],
    )
    assert base.decode("ascii") == B26_SIGNATURE_BASE


def test_b26_signature_bytes_byte_for_byte(test_key):
    signed = http.sign_request(
        TEST_REQUEST["method"], TEST_REQUEST["url"],
        headers=dict(TEST_REQUEST["headers"]),
        body=TEST_REQUEST["body"],
        key=test_key,
        keyid="test-key-ed25519",
        components=B26_COMPONENTS,
        created=B26_CREATED,
        expires=None,  # the B.2.6 vector carries no expires parameter ...
        nonce=None,    # ... and no nonce, so the AUTO defaults are switched off
        add_content_digest=False,
        alg=None,  # the B.2.6 vector carries no alg parameter ...
        tag=None,  # ... and no tag (the AICS default is tag="aics")
        label="sig-b26",
    )
    assert signed["Signature-Input"] == B26_SIGNATURE_INPUT
    assert signed["Signature"] == f"sig-b26=:{B26_SIGNATURE_B64}:"


def test_b26_signature_verifies_with_expected_bytes(test_key):
    from cryptography.exceptions import InvalidSignature

    pub = test_key.public_key()
    expected_sig = base64.b64decode(B26_SIGNATURE_B64)
    # the published signature verifies over our reproduced base
    pub.verify(expected_sig, B26_SIGNATURE_BASE.encode("ascii"))


def test_b25_hmac_vector_confirms_base_construction():
    """RFC 9421 B.2.5 (HMAC-SHA256) is deterministic and pins the exact
    signature-base byte format, including the missing trailing newline
    on the @signature-params line."""
    import hashlib
    import hmac as hmac_mod

    from conftest import B25_COMPONENTS, B25_CREATED, B25_SECRET, B25_SIGNATURE_B64

    sig_params = (
        '("date" "@authority" "content-type")'
        f';created={B25_CREATED};keyid="test-shared-secret"'
    )
    base = http.signature_base(
        B25_COMPONENTS, sig_params,
        method=TEST_REQUEST["method"], url=TEST_REQUEST["url"],
        headers=TEST_REQUEST["headers"],
    )
    digest = hmac_mod.new(B25_SECRET, base, hashlib.sha256).digest()
    assert base64.b64encode(digest).decode() == B25_SIGNATURE_B64


def test_b26_verify_request_accepts_rfc_signed_request(test_key):
    """Feed the RFC's signed request to verify_request; it must pass."""
    headers = list(TEST_REQUEST["headers"]) + [
        ("Signature-Input", B26_SIGNATURE_INPUT),
        ("Signature", f"sig-b26=:{B26_SIGNATURE_B64}:"),
    ]
    verified = http.verify_request(
        TEST_REQUEST["method"], TEST_REQUEST["url"], headers,
        body=TEST_REQUEST["body"],
        resolve_key=lambda keyid: test_key.public_key() if keyid == "test-key-ed25519" else None,
        now=B26_CREATED + 60,
        required_components=B26_COMPONENTS,
        require_expires=False,  # the RFC vector has no expires; the AICS default requires one
    )
    assert len(verified) == 1
    sig = verified[0]
    assert sig.label == "sig-b26"
    assert sig.keyid == "test-key-ed25519"
    assert sig.created == B26_CREATED
    assert sig.signature_base == B26_SIGNATURE_BASE
    assert sig.nonce is None and sig.expires is None and sig.tag is None


def test_b26_base_is_rfc_8941_canonical_against_http_sfv(test_key):
    """Our serialization matches the http-sfv library's output exactly."""
    import http_sfv

    il = http_sfv.InnerList()
    for c in B26_COMPONENTS:
        il.append(http_sfv.Item(c))
    il.params["created"] = B26_CREATED
    il.params["keyid"] = "test-key-ed25519"
    assert str(il) in B26_SIGNATURE_BASE


# ----------------------------------------------------------------------
# sign -> verify round trips
# ----------------------------------------------------------------------

URL = "https://api.example.com/v1/tasks?state=open&limit=10"
BODY = b'{"task": "write tests", "priority": 1}'


def test_roundtrip_default_components(test_key):
    signed = http.sign_request(
        "POST", URL, headers={"Content-Type": "application/json", "Host": "api.example.com"},
        body=BODY, key=test_key, keyid="kid-1",
        nonce="n-123", tag="agent-run", expires=1_700_000_300,
        created=1_700_000_000,
    )
    assert signed["Content-Digest"].startswith("sha-256=:")
    results = http.verify_request(
        "POST", URL, list(signed.items()), body=BODY,
        resolve_key=lambda kid: test_key.public_key() if kid == "kid-1" else None,
        now=1_700_000_010,
    )
    assert results[0].nonce == "n-123"
    assert results[0].tag == "agent-run"
    assert results[0].expires == 1_700_000_300
    assert "content-digest" in results[0].components


def test_roundtrip_query_and_target_uri_components(test_key):
    comps = ["@method", "@authority", "@path", "@query", "@target-uri", "@scheme"]
    signed = http.sign_request(
        "GET", URL, key=test_key, keyid="kid-1", components=comps, created=1_700_000_000,
    )
    sig = http.verify_request(
        "GET", URL, list(signed.items()), body=b"",
        resolve_key=lambda kid: test_key.public_key() if kid == "kid-1" else None,
        now=1_700_000_001, required_components=comps,
    )[0]
    assert sig.components == tuple(comps)


def test_derived_component_values():
    assert http.derived_component_value("@method", method="get", url=URL) == "GET"
    assert http.derived_component_value("@authority", method="GET", url=URL) == "api.example.com"
    assert http.derived_component_value("@path", method="GET", url=URL) == "/v1/tasks"
    assert http.derived_component_value("@query", method="GET", url=URL) == "?state=open&limit=10"
    assert http.derived_component_value("@query", method="GET", url="https://h.example/x") == "?"
    assert http.derived_component_value(
        "@target-uri", method="GET", url=URL
    ) == "https://api.example.com/v1/tasks?state=open&limit=10"
    assert http.derived_component_value("@scheme", method="GET", url=URL) == "https"
    assert http.derived_component_value(
        "@authority", method="GET", url="http://localhost:8080/p"
    ) == "localhost:8080"
    assert http.derived_component_value(
        "@authority", method="GET", url="https://example.com:443/p"
    ) == "example.com"


def test_multiple_header_values_joined(test_key):
    headers = [("Accept", "application/json"), ("Accept", "*/*")]
    signed = http.sign_request(
        "GET", "https://example.org/demo", headers=headers,
        key=test_key, keyid="k", components=["accept"], created=1_700_000_000,
    )
    base_expected = '"accept": application/json, */*\n'
    results = http.verify_request(
        "GET", "https://example.org/demo", list(signed.items()),
        resolve_key=lambda kid: test_key.public_key(), now=1_700_000_001,
        required_components=["accept"],
    )
    assert base_expected in results[0].signature_base


# ----------------------------------------------------------------------
# negative cases
# ----------------------------------------------------------------------

def signed_headers(test_key, **kwargs):
    kwargs.setdefault("keyid", "kid-1")
    kwargs.setdefault("created", 1_700_000_000)
    return http.sign_request("POST", URL, body=BODY, key=test_key, **kwargs)


def verify(test_key, method, url, headers, body, *, now=1_700_000_010, **kwargs):
    return http.verify_request(
        method, url, headers, body=body,
        resolve_key=lambda kid: test_key.public_key() if kid == "kid-1" else None,
        now=now, **kwargs,
    )


def test_tampered_method_fails(test_key):
    headers = list(signed_headers(test_key).items())
    with pytest.raises(http.VerificationFailed):
        verify(test_key, "PUT", URL, headers, BODY)


def test_tampered_url_fails(test_key):
    headers = list(signed_headers(test_key).items())
    with pytest.raises(http.VerificationFailed):
        verify(test_key, "POST", "https://evil.example.com/v1/tasks?state=open&limit=10", headers, BODY)


def test_tampered_body_fails(test_key):
    headers = list(signed_headers(test_key).items())
    with pytest.raises(http.VerificationFailed, match="Content-Digest"):
        verify(test_key, "POST", URL, headers, b'{"task": "steal data"}')


def test_tampered_covered_header_fails(test_key):
    signed = http.sign_request(
        "POST", URL, headers={"Date": "Mon, 20 Apr 2026 02:07:55 GMT"},
        body=BODY, key=test_key, keyid="kid-1",
        components=["@method", "@authority", "@path", "date"],
        created=1_700_000_000,
    )
    headers = [(n, v) for (n, v) in signed.items()]
    headers = [(n, "Wed, 01 Jan 2020 00:00:00 GMT" if n == "Date" else v) for n, v in headers]
    with pytest.raises(http.VerificationFailed):
        verify(test_key, "POST", URL, headers, BODY)


def test_missing_signature_headers_fail(test_key):
    with pytest.raises(http.MalformedSignature):
        verify(test_key, "POST", URL, [("Host", "api.example.com")], BODY)


def test_orphan_signature_without_input_fails(test_key):
    signed = signed_headers(test_key)
    headers = [("Signature", signed["Signature"])]
    with pytest.raises(http.MalformedSignature):
        verify(test_key, "POST", URL, headers, BODY)


def test_expired_signature_fails(test_key):
    signed = signed_headers(test_key, expires=1_700_000_100)
    with pytest.raises(http.VerificationFailed, match="expired"):
        verify(test_key, "POST", URL, list(signed.items()), BODY,
               now=1_700_000_101, max_clock_skew=0)


def test_future_created_fails(test_key):
    signed = signed_headers(test_key, created=1_800_000_000)
    with pytest.raises(http.VerificationFailed, match="future"):
        verify(test_key, "POST", URL, list(signed.items()), BODY)


def test_clock_skew_tolerance(test_key):
    """The skew extends expires (and tolerates a fast signer clock), never max_age."""
    signed = signed_headers(test_key, expires=1_700_000_100)
    results = verify(test_key, "POST", URL, list(signed.items()), BODY,
                     now=1_700_000_250, max_clock_skew=200)
    assert results[0].keyid == "kid-1"
    with pytest.raises(http.VerificationFailed, match="expired"):
        verify(test_key, "POST", URL, list(signed.items()), BODY,
               now=1_700_000_250, max_clock_skew=100)


def test_wrong_key_fails(test_key):
    other = keys.generate_keypair()
    headers = list(signed_headers(test_key).items())
    with pytest.raises(http.VerificationFailed):
        http.verify_request(
            "POST", URL, headers, body=BODY,
            resolve_key=lambda kid: other.public_key() if kid == "kid-1" else None,
        )


def test_unknown_keyid_fails(test_key):
    headers = list(signed_headers(test_key, keyid="stranger-key").items())
    with pytest.raises(http.UnknownKeyError):
        verify(test_key, "POST", URL, headers, BODY)


def test_required_components_enforced(test_key):
    headers = list(signed_headers(test_key, components=["@method", "@path"]).items())
    with pytest.raises(http.VerificationFailed, match="required components"):
        verify(test_key, "POST", URL, headers, BODY, required_components=["@authority"])


def test_unsupported_alg_rejected(test_key):
    headers = list(signed_headers(test_key).items())
    headers = [
        (n, v.replace('alg="ed25519"', 'alg="es256"') if n == "Signature-Input" else v)
        for n, v in headers
    ]
    with pytest.raises(http.VerificationFailed, match="alg"):
        verify(test_key, "POST", URL, headers, BODY)


def test_missing_created_parameter_rejected(test_key):
    signed = signed_headers(test_key)
    si = signed["Signature-Input"].replace(";created=1700000000", "")
    headers = [("Signature-Input", si), ("Signature", signed["Signature"])]
    with pytest.raises(http.MalformedSignature, match="created"):
        verify(test_key, "POST", URL, headers, BODY)


def test_missing_keyid_parameter_rejected(test_key):
    signed = signed_headers(test_key)
    si = signed["Signature-Input"].replace(';keyid="kid-1"', "")
    headers = [("Signature-Input", si), ("Signature", signed["Signature"])]
    with pytest.raises(http.MalformedSignature, match="keyid"):
        verify(test_key, "POST", URL, headers, BODY)


def test_mangled_signature_header_rejected(test_key):
    headers = [("Signature-Input", "not a sf dictionary at all!"), ("Signature", "x=:abc=:")]
    with pytest.raises(http.MalformedSignature):
        verify(test_key, "POST", URL, headers, BODY)


def test_covered_content_digest_header_must_exist(test_key):
    signed = signed_headers(test_key, components=["@method", "@authority", "@path", "content-digest"])
    headers = [(n, v) for n, v in signed.items() if n != "Content-Digest"]
    with pytest.raises(http.VerificationFailed, match="content-digest"):
        verify(test_key, "POST", URL, headers, BODY)


def test_require_content_digest_covered_flag(test_key):
    headers = list(signed_headers(
        test_key, components=["@method", "@authority", "@path"],
        add_content_digest=False,
    ).items())
    with pytest.raises(http.VerificationFailed, match="Content-Digest"):
        verify(test_key, "POST", URL, headers, BODY, require_content_digest_covered=True)


def test_uncovered_but_present_content_digest_still_validated(test_key):
    signed = signed_headers(test_key, components=["@method", "@authority", "@path"],
                            add_content_digest=False)
    headers = [(n, v) for n, v in signed.items()]
    headers.append(("Content-Digest", http.content_digest_header(b"tampered")))
    with pytest.raises(http.VerificationFailed, match="Content-Digest"):
        verify(test_key, "POST", URL, headers, BODY)


def test_non_absolute_url_rejected(test_key):
    with pytest.raises(ValueError):
        http.sign_request("GET", "/relative/path", key=test_key, keyid="k")


def test_unknown_derived_component_rejected(test_key):
    with pytest.raises(ValueError):
        http.sign_request("GET", URL, key=test_key, keyid="k", components=["@nope"])


# ----------------------------------------------------------------------
# Content-Digest (RFC 9530)
# ----------------------------------------------------------------------

def test_content_digest_header_sha256():
    value = http.content_digest_header(BODY)
    digest = hashlib.sha256(BODY).digest()
    assert value == "sha-256=:" + base64.b64encode(digest).decode() + ":"


def test_content_digest_header_multiple_algorithms():
    value = http.content_digest_header(BODY, algorithms=("sha-256", "sha-512"))
    assert value.startswith("sha-256=:")
    assert ", sha-512=:" in value


def test_verify_content_digest_ok():
    value = http.content_digest_header(BODY, algorithms=("sha-256", "sha-512"))
    assert http.verify_content_digest(value, BODY) == ["sha-256", "sha-512"]


def test_verify_content_digest_mismatch():
    value = http.content_digest_header(BODY)
    with pytest.raises(http.VerificationFailed):
        http.verify_content_digest(value, b"other body")


def test_verify_content_digest_unknown_algorithm_only():
    with pytest.raises(http.VerificationFailed, match="supported"):
        http.verify_content_digest("md5=:AAAAAAAAAA==:", BODY)


def test_verify_content_digest_unparsable():
    with pytest.raises(http.VerificationFailed):
        http.verify_content_digest("garbage!!!", BODY)


# ----------------------------------------------------------------------
# signing defaults
# ----------------------------------------------------------------------

T0 = 1_700_000_000


def test_sign_defaults_add_expires_and_random_nonce(test_key):
    a = http.sign_request("POST", URL, body=BODY, key=test_key, keyid="kid-1", created=T0)
    b = http.sign_request("POST", URL, body=BODY, key=test_key, keyid="kid-1", created=T0)
    assert f";expires={T0 + 300};" in a["Signature-Input"]
    assert ';nonce="' in a["Signature-Input"]
    assert a["Signature-Input"] != b["Signature-Input"]  # fresh nonce each time
    sig = verify(test_key, "POST", URL, list(a.items()), BODY, now=T0 + 1)[0]
    assert sig.expires == T0 + 300 and len(sig.nonce) >= 16


def test_sign_none_omits_expires_and_nonce(test_key):
    signed = http.sign_request("GET", URL, key=test_key, keyid="kid-1", created=T0, expires=None, nonce=None)
    assert "expires" not in signed["Signature-Input"] and "nonce" not in signed["Signature-Input"]
    with pytest.raises(ValueError):
        http.sign_request("GET", URL, key=test_key, keyid="kid-1", nonce="")


# ----------------------------------------------------------------------
# freshness: max_age, expires, lifetime, skew
# ----------------------------------------------------------------------

def test_created_older_than_max_age_is_refused(test_key):
    headers = list(signed_headers(test_key, created=T0, expires=T0 + 300).items())
    assert verify(test_key, "POST", URL, headers, BODY, now=T0 + 300)[0].keyid == "kid-1"
    with pytest.raises(http.VerificationFailed, match="too old"):
        verify(test_key, "POST", URL, headers, BODY, now=T0 + 301)
    with pytest.raises(http.VerificationFailed, match="too old"):
        verify(test_key, "POST", URL, headers, BODY, now=T0 + 120, max_age=60)


def test_max_age_does_not_stretch_with_skew(test_key):
    headers = list(signed_headers(test_key, created=T0, expires=T0 + 300).items())
    with pytest.raises(http.VerificationFailed, match="too old"):
        verify(test_key, "POST", URL, headers, BODY, now=T0 + 301, max_clock_skew=3_600)


def test_max_age_none_disables_the_age_check(test_key):
    headers = list(signed_headers(test_key, created=T0, expires=None).items())
    sig = verify(test_key, "POST", URL, headers, BODY, now=T0 + 86_400, max_age=None, require_expires=False)[0]
    assert sig.valid_until is None


def test_expires_is_required_by_default(test_key):
    headers = list(signed_headers(test_key, expires=None).items())
    with pytest.raises(http.MalformedSignature, match="expires"):
        verify(test_key, "POST", URL, headers, BODY)
    assert verify(test_key, "POST", URL, headers, BODY, require_expires=False)[0].expires is None


def test_lifetime_cap(test_key):
    ok = list(signed_headers(test_key, created=T0, expires=T0 + 300).items())
    assert verify(test_key, "POST", URL, ok, BODY, now=T0 + 1)
    long = list(signed_headers(test_key, created=T0, expires=T0 + 301).items())
    with pytest.raises(http.VerificationFailed, match="lifetime"):
        verify(test_key, "POST", URL, long, BODY, now=T0 + 1)
    assert verify(test_key, "POST", URL, long, BODY, now=T0 + 1, max_lifetime=None)


def test_expires_before_created_refused(test_key):
    headers = list(signed_headers(test_key, created=T0, expires=T0 - 1).items())
    with pytest.raises(http.VerificationFailed, match="before it was created"):
        verify(test_key, "POST", URL, headers, BODY, now=T0)


def test_created_slightly_in_the_future_is_tolerated(test_key):
    headers = list(signed_headers(test_key, created=T0 + 60, expires=T0 + 360).items())
    assert verify(test_key, "POST", URL, headers, BODY, now=T0)  # default skew 60 s
    with pytest.raises(http.VerificationFailed, match="future"):
        verify(test_key, "POST", URL, headers, BODY, now=T0 - 1)


def test_valid_until(test_key):
    headers = list(signed_headers(test_key, created=T0, expires=T0 + 100).items())
    assert verify(test_key, "POST", URL, headers, BODY, now=T0)[0].valid_until == T0 + 100 + 60
    headers = list(signed_headers(test_key, created=T0, expires=T0 + 300).items())
    assert verify(test_key, "POST", URL, headers, BODY, now=T0)[0].valid_until == T0 + 300  # max_age binds


def test_freshness_false_leaves_every_clock_and_window_bound_to_the_caller(test_key):
    # A server that decides AICS-1 section 4.3 itself, after authenticating, verifies with freshness=False:
    # expires before created, a long lifetime, an old or a future created all pass the signature check here.
    for created, expires in ((T0, T0 - 1), (T0, T0), (T0, T0 + 301), (T0 - 10_000, T0 - 9_900), (T0 + 999, T0 + 1_200)):
        headers = list(signed_headers(test_key, created=created, expires=expires).items())
        sig = verify(test_key, "POST", URL, headers, BODY, now=T0, freshness=False)[0]
        assert (sig.created, sig.expires) == (created, expires)
    headers = list(signed_headers(test_key, created=T0, expires=T0 - 1).items())
    with pytest.raises(http.VerificationFailed, match="before it was created"):
        verify(test_key, "POST", URL, headers, BODY, now=T0)
    # The signature itself is still checked.
    bad = list(signed_headers(test_key, created=T0, expires=T0 - 1).items())
    with pytest.raises(http.VerificationFailed, match="does not verify"):
        verify(test_key, "PUT", URL, bad, BODY, now=T0, freshness=False)


def test_boolean_created_is_not_an_integer(test_key):
    signed = signed_headers(test_key)
    si = signed["Signature-Input"].replace(f";created={T0}", ";created=?1")
    with pytest.raises(http.MalformedSignature, match="created"):
        verify(test_key, "POST", URL, [("Signature-Input", si), ("Signature", signed["Signature"])], BODY)


# ----------------------------------------------------------------------
# nonce and tag
# ----------------------------------------------------------------------

def test_require_nonce(test_key):
    without = list(signed_headers(test_key, nonce=None).items())
    with pytest.raises(http.MalformedSignature, match="nonce"):
        verify(test_key, "POST", URL, without, BODY, require_nonce=True)
    assert verify(test_key, "POST", URL, without, BODY)[0].nonce is None
    with_nonce = list(signed_headers(test_key, nonce="n-1").items())
    assert verify(test_key, "POST", URL, with_nonce, BODY, require_nonce=True)[0].nonce == "n-1"


def test_nonce_shape(test_key):
    long = list(signed_headers(test_key, nonce="n" * (http.MAX_NONCE_LENGTH + 1)).items())
    with pytest.raises(http.MalformedSignature, match="longer"):
        verify(test_key, "POST", URL, long, BODY)
    signed = signed_headers(test_key, nonce="n-1")
    for replacement in (';nonce=""', ";nonce=5"):
        si = signed["Signature-Input"].replace(';nonce="n-1"', replacement)
        with pytest.raises(http.MalformedSignature, match="nonce"):
            verify(test_key, "POST", URL, [("Signature-Input", si), ("Signature", signed["Signature"])], BODY)


def test_require_tag(test_key):
    untagged = list(signed_headers(test_key, tag=None).items())
    with pytest.raises(http.MalformedSignature, match="tag"):
        verify(test_key, "POST", URL, untagged, BODY, require_tag="aics")
    other = list(signed_headers(test_key, tag="aics-agent").items())
    with pytest.raises(http.VerificationFailed, match="tag"):
        verify(test_key, "POST", URL, other, BODY, require_tag="aics")
    tagged = list(signed_headers(test_key, tag="aics").items())
    assert verify(test_key, "POST", URL, tagged, BODY, require_tag="aics")[0].tag == "aics"


# ----------------------------------------------------------------------
# content-digest coverage
# ----------------------------------------------------------------------

def test_require_covered_digest_rejects_present_but_uncovered_header(test_key):
    """A correct Content-Digest that the signature does not cover is not enough."""
    signed = signed_headers(test_key, components=["@method", "@authority", "@path"], add_content_digest=False)
    headers = list(signed.items()) + [("Content-Digest", http.content_digest_header(BODY))]
    assert verify(test_key, "POST", URL, headers, BODY)  # fine without the flag
    with pytest.raises(http.VerificationFailed, match="Content-Digest"):
        verify(test_key, "POST", URL, headers, BODY, require_content_digest_covered=True)


def test_require_covered_digest_applies_without_a_body(test_key):
    bare = http.sign_request("POST", URL, key=test_key, keyid="kid-1", created=T0, components=http.DEFAULT_COMPONENTS)
    with pytest.raises(http.VerificationFailed, match="Content-Digest"):
        verify(test_key, "POST", URL, list(bare.items()), b"", require_content_digest_covered=True)
    covered = http.sign_request("POST", URL, key=test_key, keyid="kid-1", created=T0)  # AICS_COMPONENTS by default
    assert covered["Content-Digest"] == http.content_digest_header(b"")
    assert verify(test_key, "POST", URL, list(covered.items()), b"", require_content_digest_covered=True)


# ----------------------------------------------------------------------
# replay hook
# ----------------------------------------------------------------------

class TableReplay:
    """A replay hook backed by a dict, standing in for the server's database table."""

    def __init__(self):
        self.rows = {}
        self.calls = []

    def __call__(self, keyid, nonce, retain_until, now):
        self.calls.append((keyid, nonce, retain_until, now))
        if (keyid, nonce) in self.rows:
            return False
        self.rows[(keyid, nonce)] = retain_until
        return True


def test_replay_hook_refuses_second_use(test_key):
    table = TableReplay()
    headers = list(signed_headers(test_key, nonce="n-7", expires=T0 + 120).items())
    sig = verify(test_key, "POST", URL, headers, BODY, now=T0 + 5, replay_check=table)[0]
    assert table.calls == [("kid-1", "n-7", T0 + 120 + 60, T0 + 5)]
    assert sig.valid_until == T0 + 180
    with pytest.raises(http.ReplayedSignature) as info:
        verify(test_key, "POST", URL, headers, BODY, now=T0 + 6, replay_check=table)
    assert (info.value.keyid, info.value.nonce, info.value.label) == ("kid-1", "n-7", "aics")
    assert isinstance(info.value, http.VerificationFailed)


def test_replay_cache_instance_is_a_hook(test_key):
    from aics_identity.replay import ReplayCache

    cache = ReplayCache()
    headers = list(signed_headers(test_key, nonce="n-8").items())
    assert verify(test_key, "POST", URL, headers, BODY, now=T0 + 1, replay_check=cache)
    with pytest.raises(http.ReplayedSignature):
        verify(test_key, "POST", URL, headers, BODY, now=T0 + 2, replay_check=cache)


def test_replay_hook_needs_a_nonce(test_key):
    headers = list(signed_headers(test_key, nonce=None).items())
    with pytest.raises(http.MalformedSignature, match="nonce"):
        verify(test_key, "POST", URL, headers, BODY, replay_check=TableReplay())


def test_failed_verification_does_not_consume_the_nonce(test_key):
    table = TableReplay()
    headers = list(signed_headers(test_key, nonce="n-9").items())
    with pytest.raises(http.VerificationFailed):
        verify(test_key, "POST", URL, headers, b"tampered body", replay_check=table)
    with pytest.raises(http.VerificationFailed, match="too old"):
        verify(test_key, "POST", URL, headers, BODY, now=T0 + 3_600, replay_check=table)
    assert table.calls == []
    assert verify(test_key, "POST", URL, headers, BODY, replay_check=table)


def test_replay_hook_errors_propagate(test_key):
    class LeafConflict(Exception):
        pass

    def hook(keyid, nonce, retain_until, now):
        raise LeafConflict("nonce used at leaf 1234")

    headers = list(signed_headers(test_key).items())
    with pytest.raises(LeafConflict, match="1234"):
        verify(test_key, "POST", URL, headers, BODY, replay_check=hook)


def test_all_labels_verify_before_any_nonce_is_recorded(test_key):
    table = TableReplay()
    one = signed_headers(test_key, nonce="n-a", label="sig1")
    two = signed_headers(test_key, nonce="n-b", label="sig2", keyid="unknown-key")
    headers = [
        ("Content-Digest", one["Content-Digest"]),
        ("Signature-Input", one["Signature-Input"] + ", " + two["Signature-Input"]),
        ("Signature", one["Signature"] + ", " + two["Signature"]),
    ]
    with pytest.raises(http.UnknownKeyError):
        verify(test_key, "POST", URL, headers, BODY, replay_check=table)
    assert table.calls == []


def test_two_valid_labels_are_both_replay_checked(test_key):
    table = TableReplay()
    one = signed_headers(test_key, nonce="n-a", label="sig1")
    two = signed_headers(test_key, nonce="n-b", label="sig2")
    headers = [
        ("Content-Digest", one["Content-Digest"]),
        ("Signature-Input", one["Signature-Input"] + ", " + two["Signature-Input"]),
        ("Signature", one["Signature"] + ", " + two["Signature"]),
    ]
    assert len(verify(test_key, "POST", URL, headers, BODY, replay_check=table)) == 2
    assert sorted(n for _, n, _, _ in table.calls) == ["n-a", "n-b"]


# ----------------------------------------------------------------------
# the AICS profile
# ----------------------------------------------------------------------

def test_aics_profile_end_to_end(test_key):
    table = TableReplay()
    kid = keys.did_key(test_key.public_key())
    signed = http.sign_request(
        "POST", "https://api.wesupport-ai.com/v2/entries", headers={"Content-Type": "application/json"},
        body=BODY, key=test_key, created=T0,
    )
    sig = http.verify_request(
        "POST", "https://api.wesupport-ai.com/v2/entries", list(signed.items()), BODY,
        resolve_key=lambda k: test_key.public_key() if k == kid else None,
        now=T0 + 2, replay_check=table, **http.AICS_VERIFY_POLICY,
    )[0]
    assert sig.label == "aics" and sig.keyid == kid and sig.tag == "aics" and sig.alg == "ed25519"
    assert sig.components == http.AICS_COMPONENTS
    assert len(table.rows) == 1


def test_aics_profile_refuses_the_rfc_vector_and_untagged_requests(test_key):
    headers = list(TEST_REQUEST["headers"]) + [
        ("Signature-Input", B26_SIGNATURE_INPUT),
        ("Signature", f"sig-b26=:{B26_SIGNATURE_B64}:"),
    ]
    with pytest.raises(http.SignatureError):
        http.verify_request(TEST_REQUEST["method"], TEST_REQUEST["url"], headers, TEST_REQUEST["body"],
                            resolve_key=lambda k: test_key.public_key(), now=B26_CREATED + 1,
                            **http.AICS_VERIFY_POLICY)
    untagged = list(signed_headers(test_key, tag=None).items())
    with pytest.raises(http.MalformedSignature, match="tag"):
        verify(test_key, "POST", URL, untagged, BODY, **http.AICS_VERIFY_POLICY)


def test_aics_policy_is_read_only():
    with pytest.raises(TypeError):
        http.AICS_VERIFY_POLICY["require_tag"] = None  # type: ignore[index]


# ----------------------------------------------------------------------
# AICS-1 section 12.1: signing defaults, the profile policy, the envelope binding
# ----------------------------------------------------------------------

ENTRIES = "https://api.wesupport-ai.com/v2/entries"


def test_signing_defaults_are_the_section_12_1_profile(test_key):
    signed = http.sign_request("POST", ENTRIES, {"Content-Type": "application/json"}, BODY, key=test_key, created=T0)
    did = keys.did_key(test_key.public_key())
    params = signed["Signature-Input"]
    assert params.startswith('aics=("@method" "@authority" "@path" "content-digest");created=1700000000;'
                             'expires=1700000300;nonce="')
    assert params.endswith(f';alg="ed25519";keyid="{did}";tag="aics"')
    assert signed["Signature"].startswith("aics=:")
    nonce = params.split('nonce="')[1].split('"')[0]
    assert len(keys.u64_decode(nonce)) == 16
    assert http.DEFAULT_LABEL == http.AICS_LABEL == "aics"


def _verify_aics(key, headers, body=BODY, **kwargs):
    return http.verify_request("POST", ENTRIES, list(headers.items()) if isinstance(headers, dict) else headers, body,
                               resolve_key=keys.parse_did_key, now=T0 + 1, **http.AICS_VERIFY_POLICY, **kwargs)


def test_the_policy_requires_exactly_one_aics_label(test_key):
    """A request signed under another label is refused by an AICS-1 verifier (finding F06)."""
    assert _verify_aics(test_key, http.sign_request("POST", ENTRIES, body=BODY, key=test_key, created=T0))
    sig1 = http.sign_request("POST", ENTRIES, body=BODY, key=test_key, created=T0, label="sig1")
    with pytest.raises(http.VerificationFailed, match="labelled 'aics'"):
        _verify_aics(test_key, sig1)
    one = http.sign_request("POST", ENTRIES, body=BODY, key=test_key, created=T0)
    two = http.sign_request("POST", ENTRIES, body=BODY, key=test_key, created=T0, label="other")
    both = [("Content-Digest", one["Content-Digest"]),
            ("Signature-Input", one["Signature-Input"] + ", " + two["Signature-Input"]),
            ("Signature", one["Signature"] + ", " + two["Signature"])]
    with pytest.raises(http.VerificationFailed, match="exactly one"):
        _verify_aics(test_key, both)


def test_the_policy_requires_alg_and_the_exact_components(test_key):
    no_alg = http.sign_request("POST", ENTRIES, body=BODY, key=test_key, created=T0, alg=None)
    with pytest.raises(http.MalformedSignature, match="alg"):
        _verify_aics(test_key, no_alg)
    reordered = http.sign_request("POST", ENTRIES, body=BODY, key=test_key, created=T0,
                                  components=["@authority", "@method", "@path", "content-digest"])
    with pytest.raises(http.VerificationFailed, match="in that order"):
        _verify_aics(test_key, reordered)
    extra = http.sign_request("POST", ENTRIES, {"Content-Type": "application/json"}, BODY, key=test_key, created=T0,
                              components=list(http.AICS_COMPONENTS) + ["content-type"])
    with pytest.raises(http.VerificationFailed, match="exactly"):
        _verify_aics(test_key, extra)
    assert http.verify_request("POST", ENTRIES, list(extra.items()), BODY, resolve_key=keys.parse_did_key,
                               now=T0 + 1, required_components=http.AICS_COMPONENTS)  # fine outside the profile


def _entry_envelope(key, created=T0):
    from aics_identity import envelope

    return envelope.sign_envelope({"x": 1}, key, origin="api.wesupport-ai.com/tiles", type="post", created=created)


def test_sign_request_takes_the_binding_from_the_envelope(test_key):
    env = _entry_envelope(test_key)
    p = env["protected"]
    signed = http.sign_request("POST", ENTRIES, {"Content-Type": "application/json"}, BODY, key=test_key,
                               envelope=env)
    [sig] = _verify_aics(test_key, signed, envelope=env)
    assert (sig.keyid, sig.nonce, sig.created, sig.expires) == (p["kid"], p["nonce"], p["created"], p["expires"])
    assert http.sign_request("POST", ENTRIES, body=BODY, key=test_key, envelope=env, nonce=p["nonce"],
                             created=p["created"])["Signature-Input"] == signed["Signature-Input"]
    for name, value in (("nonce", keys.b64u_encode(bytes(16))), ("created", T0 - 1), ("expires", T0 + 1),
                        ("keyid", "did:key:z6MkOther")):
        with pytest.raises(ValueError, match=name):
            http.sign_request("POST", ENTRIES, body=BODY, key=test_key, envelope=env, **{name: value})
    with pytest.raises(ValueError, match="same key"):
        http.sign_request("POST", ENTRIES, body=BODY, key=keys.generate_keypair(), envelope=env)
    with pytest.raises(ValueError, match="envelope"):
        http.sign_request("POST", ENTRIES, body=BODY, key=test_key, envelope={"protected": {}})


@pytest.mark.parametrize("field, value", [
    ("nonce", keys.b64u_encode(bytes(16))),
    ("created", T0 + 1),
    ("expires", T0 + 299),
])
def test_verify_request_requires_the_envelope_values(test_key, field, value):
    """AICS-1 section 12.1: times, nonce and keyid MUST equal the envelope values."""
    env = _entry_envelope(test_key)
    p = env["protected"]
    kwargs = {"keyid": p["kid"], "nonce": p["nonce"], "created": p["created"], "expires": p["expires"], field: value}
    signed = http.sign_request("POST", ENTRIES, body=BODY, key=test_key, **kwargs)
    with pytest.raises(http.VerificationFailed, match=f"{field} differs from the envelope"):
        _verify_aics(test_key, signed, envelope=env)


def test_verify_request_keyid_must_be_the_envelope_kid(test_key):
    other = keys.generate_keypair()
    env = _entry_envelope(test_key)
    p = env["protected"]
    signed = http.sign_request("POST", ENTRIES, body=BODY, key=other, nonce=p["nonce"], created=p["created"],
                               expires=p["expires"])
    with pytest.raises(http.VerificationFailed, match="keyid differs"):
        _verify_aics(other, signed, envelope=env)


def test_verify_request_refuses_a_malformed_envelope_binding(test_key):
    signed = http.sign_request("POST", ENTRIES, body=BODY, key=test_key, created=T0)
    with pytest.raises(http.VerificationFailed, match="envelope"):
        _verify_aics(test_key, signed, envelope={"protected": {"kid": keys.did_key(test_key.public_key())}})


def test_a_mismatched_binding_does_not_consume_the_nonce(test_key):
    table = TableReplay()
    env = _entry_envelope(test_key)
    p = env["protected"]
    stray = http.sign_request("POST", ENTRIES, body=BODY, key=test_key, created=p["created"], expires=p["expires"])
    with pytest.raises(http.VerificationFailed):
        _verify_aics(test_key, stray, envelope=env, replay_check=table)
    assert table.calls == []

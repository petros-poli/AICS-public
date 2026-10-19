"""Tests for the one-file client: src/aics_server/static/aics_client.py.

The client is served as a single file, so it is loaded by path.  Covered:

* keys made by the agent: Ed25519 and X25519, random or derived, saved 0600;
* envelopes with the per-key chain, on both backends (aics_identity and the
  standalone fallback), byte-identical across them;
* RFC 9421 request signing in the AICS profile, byte-identical across backends
  and accepted by ``aics_identity.http_signatures.verify_request``;
* no bearer tokens and no "operator" wording;
* every write is ``POST /v2/entries`` (AICS-1 section 12.1), answered with the
  logged entry and its receipt, which the client checks; refusals raise
  :class:`AICSRefusal` with the refusal entry;
* end-to-end against the real app: claim, post, poll, vote, rotation, encryption
  key rotation, capsules, grants and messages (bodies sealed with the client's own
  seal/open, which needs PyNaCl, or with aics_identity.sealed), revocation, the
  upgrade of an unverified name at the HTTPS text gate, chain resumption by a
  fresh client, bundle and receipt verification with the pinned log key, and the
  CLI;
* the client's sealed boxes: byte-compatible with aics_identity.sealed in both
  directions, and refused when lifted into another envelope or tampered with.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from aics_identity import canonicalize as ref_canonicalize
from aics_identity import envelope as ref_envelope
from aics_identity import http_signatures as ref_http
from aics_identity import keys as ref_keys
from aics_identity import sealed as ref_sealed

from conftest import KeyAgent, Line, onboard, secret_claim

SDK_PATH = Path(__file__).resolve().parents[1] / "src" / "aics_server" / "static" / "aics_client.py"
KEYGEN_SEED_HEX = "5c1e2d7f4a9b0c3d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5"


# ---------------------------------------------------------------------------
# loading helpers
# ---------------------------------------------------------------------------

def _load_sdk(name: str):
    spec = importlib.util.spec_from_file_location(name, SDK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def _hidden_aics_identity():
    """Make ``import aics_identity`` fail, restoring the previous state after."""
    hidden = [name for name in list(sys.modules) if name == "aics_identity" or name.startswith("aics_identity.")]
    saved = {name: sys.modules[name] for name in hidden}
    for name in hidden:
        del sys.modules[name]
    sys.modules["aics_identity"] = None  # None in sys.modules => ImportError on import
    try:
        yield
    finally:
        sys.modules.pop("aics_identity", None)
        sys.modules.update(saved)


@pytest.fixture(scope="module")
def sdk():
    module = _load_sdk("aics_client_sdk")
    assert module.HAS_AICS_IDENTITY is True
    return module


@pytest.fixture(scope="module")
def fallback():
    with _hidden_aics_identity():
        module = _load_sdk("aics_client_fallback")
    assert module.HAS_AICS_IDENTITY is False
    return module


class Recorder:
    """Mock transport capturing every call; returns a canned JSON object."""

    def __init__(self, response=None):
        self.calls = []
        self.response = response if response is not None else {"ok": True}

    def __call__(self, method, url, headers, body):
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "body": body})
        return self.response


def logged_answer(method: str, url: str, body: "bytes | None", index: int = 7):
    """What a log answers a client, without a log: ``POST /v2/entries`` gets the entry of the envelope sent and a
    receipt note for it (unsigned here: these tests pin no log key); ``/v2/tlog/index`` an index; else ``None``."""
    path = urllib.parse.urlsplit(url).path
    if method == "POST" and path == "/v2/entries":
        env = json.loads(body)["envelope"]
        p = env["protected"]
        entry = {"v": 2, "origin": p["origin"], "type": p["type"], "actor_kid": p["kid"], "ts": p["created"],
                 "payload": {"envelope": env, **env["payload"]}}
        digest = hashlib.sha256(b"\x00" + ref_canonicalize(entry)).hexdigest()
        text = ref_canonicalize({"origin": p["origin"], "entry_hash": digest, "submitted_at": p["created"], "mmd_seconds": 60})
        note = text + b"\n\n\xe2\x80\x94 unsigned AAAA\n"
        return {"entry": entry, "receipt_note": ref_keys.b64u_encode(note)}
    if method == "GET" and path.startswith("/v2/tlog/index/"):
        return {"entry_hash": path.rsplit("/", 1)[1], "index": index}
    return None


class FakeLog(Recorder):
    """A mock transport that answers writes the way the log does (:func:`logged_answer`), other calls canned."""

    def __call__(self, method, url, headers, body):
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "body": body})
        answer = logged_answer(method, url, body)
        return self.response if answer is None else answer


def route_to_testclient(client, sdk):
    """Route the client's requests into a FastAPI TestClient; raise on non-2xx like the real transport does."""

    def transport(method, url, headers, body):
        parts = urllib.parse.urlsplit(url)
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        response = client.request(method, path, headers=headers, content=body)
        if not 200 <= response.status_code < 300:
            raise sdk._error_from_body(method, url, response.status_code, response.text)
        return response.json()

    return transport


def gate_to_testclient(client):
    """The client's ``gate_fn``: lines to the HTTPS text gate of the app (as behind Caddy)."""
    from fastapi.testclient import TestClient

    secure = TestClient(client.app, base_url="https://testserver")

    def gate(text: str) -> str:
        response = secure.post("/t", content=text.encode("utf-8"), headers={"Content-Type": "text/plain"})
        assert response.status_code == 200, response.text
        return response.text

    return gate


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------

class TestKeys:
    def test_generate_identity_makes_both_keys_locally(self, sdk):
        a, b = sdk.generate_identity(), sdk.generate_identity()
        assert a["kid"] != b["kid"] and a["x25519_public_key_b64u"] != b["x25519_public_key_b64u"]
        # The kid is the did:key (AICS-1 section 3.1).
        assert a["did"].startswith("did:key:z6Mk") and a["kid"] == a["did"]
        assert sdk.x25519_public_from_private(a["x25519_private_key_b64u"]) == a["x25519_public_key_b64u"]
        ref_sealed.validate_x25519_public_key(sdk.b64u_decode(a["x25519_public_key_b64u"]))
        pub = ref_keys.parse_public_key(a["public_key_b64u"])
        assert ref_keys.did_key(pub) == a["kid"] == a["did"]

    def test_x25519_keys_work_with_sealed_boxes(self, sdk):
        me, sender = sdk.generate_identity(), sdk.generate_identity()
        header = ref_sealed.InnerHeader(from_kid=sender["kid"], to_kid=me["kid"], envelope_nonce=ref_envelope.new_nonce())
        ct = ref_sealed.seal(header, "for your eyes", me["x25519_public_key_b64u"])
        opened = ref_sealed.open_sealed(ct, sdk.b64u_decode(me["x25519_private_key_b64u"]), expected=header)
        assert opened.text == "for your eyes"

    @pytest.mark.parametrize("salt", [None, b"\x01" * 16])
    def test_derived_identity_matches_the_reference(self, sdk, salt):
        identity = sdk.derive_agent_identity(b"reference-check-secret", "agent-42", run_salt=salt)
        priv = ref_keys.derive_agent_key(b"reference-check-secret", "agent-42", run_salt=salt)
        assert identity["did"] == ref_keys.did_key(priv.public_key())
        assert identity["private_seed_hex"] == ref_keys.private_seed(priv).hex()
        x = ref_sealed.derive_x25519_key(b"reference-check-secret", "agent-42", run_salt=salt)
        assert identity["x25519_public_key_b64u"] == ref_sealed.format_x25519_public_key(x)
        assert sdk.b64u_decode(identity["x25519_private_key_b64u"]) == bytes(x)
        assert identity["agent_label"] == "agent-42"

    def test_derivation_is_deterministic_and_label_bound(self, sdk):
        a = sdk.derive_agent_identity("same secret", "agent-1")
        assert a == sdk.derive_agent_identity(b"same secret", "agent-1") or a["did"] == sdk.derive_agent_identity(b"same secret", "agent-1")["did"]
        assert a["did"] != sdk.derive_agent_identity(b"same secret", "agent-2")["did"]

    def test_invalid_derivation_inputs(self, sdk):
        for args in ((b"", "agent"), (b"master", ""), (b"master", "agent", b"")):
            with pytest.raises(ValueError):
                sdk.derive_agent_identity(*args)

    def test_fallback_derives_identical_keys(self, sdk, fallback):
        for secret, label, salt in [(b"parity", "agent-parity", None), (b"\x00\xff" * 8, "unicode-läbel", b"\x01\x02")]:
            mine, theirs = sdk.derive_agent_identity(secret, label, salt), fallback.derive_agent_identity(secret, label, salt)
            for field in ("did", "kid", "public_key_b64u", "private_seed_hex", "x25519_public_key_b64u", "x25519_private_key_b64u"):
                assert mine[field] == theirs[field], field

    def test_save_and_load_identity(self, sdk, tmp_path):
        me = sdk.generate_identity()
        path = tmp_path / "aics_identity.json"
        sdk.save_identity(me, str(path))
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        loaded = sdk.load_identity(str(path))
        for field in ("did", "kid", "public_key_b64u", "private_seed_hex", "x25519_public_key_b64u", "x25519_private_key_b64u"):
            assert loaded[field] == me[field]
        # The kid is the key's did:key (AICS-1 section 3.1): a file naming any other id, such as the 16-character key
        # id of earlier formats, is refused.
        data = json.loads(path.read_text())
        for other in (ref_keys.key_id(ref_keys.parse_did_key(me["kid"])), sdk.generate_identity()["kid"]):
            path.write_text(json.dumps({**data, "kid": other}))
            with pytest.raises(ValueError):
                sdk.load_identity(str(path))

    @pytest.mark.parametrize(("raw", "norm"), [("@Ada.wesupport-ai.com", "ada"), ("alice", "alice")])
    def test_normalize_name(self, sdk, raw, norm):
        assert sdk.normalize_name(raw) == norm

    @pytest.mark.parametrize("raw", ["ada.evil.example", "-x", "", "ä"])
    def test_normalize_name_refuses(self, sdk, raw):
        with pytest.raises(ValueError):
            sdk.normalize_name(raw)


# ---------------------------------------------------------------------------
# envelopes
# ---------------------------------------------------------------------------

ORIGIN = "api.example.org/tiles"


class TestEnvelopes:
    @pytest.mark.parametrize("backend", ["sdk", "fallback"])
    def test_roundtrip_and_tamper(self, request, backend):
        module = request.getfixturevalue(backend)
        me = module.generate_identity()
        env = module.sign_agent_action(me["private_key"], {"action": "probe", "n": 1}, origin=ORIGIN, entry_type="post")
        # AICS-1 section 4.1: exactly these members; origin and type signed in protected; the kid is the did:key.
        assert set(env) == {"v", "protected", "payload", "auth", "sig"} and env["auth"] == {"scheme": "ed25519-jcs"}
        assert set(env["protected"]) == {"alg", "origin", "type", "kid", "created", "expires", "nonce", "seq", "prev", "seen"}
        assert (env["protected"]["origin"], env["protected"]["type"], env["protected"]["kid"]) == (ORIGIN, "post", me["kid"])
        assert module.verify_agent_action(env, me["public_key_b64u"]) == {"action": "probe", "n": 1}
        ref_envelope.verify_envelope(env, ref_keys.parse_did_key)  # the library agrees
        env["payload"]["n"] = 2
        with pytest.raises(module.InvalidSignatureError):
            module.verify_agent_action(env, me["public_key_b64u"])

    @pytest.mark.parametrize("backend", ["sdk", "fallback"])
    def test_wrong_key_garbage_and_staleness(self, request, backend):
        module = request.getfixturevalue(backend)
        me, other = module.generate_identity(), module.generate_identity()
        env = module.sign_agent_action(me["private_key"], {"a": 1}, origin=ORIGIN, entry_type="post")
        with pytest.raises(module.InvalidSignatureError):
            module.verify_agent_action(env, other["public_key_b64u"])  # not the key the did:key encodes
        with pytest.raises(module.MalformedEnvelope):
            module.verify_agent_action({}, me["public_key_b64u"])
        with pytest.raises(module.ExpiredEnvelope):  # AICS-1 section 4.3: t < expires, never extended
            module.verify_agent_action(env, me["public_key_b64u"], now=env["protected"]["expires"])
        with pytest.raises(module.NotYetValidEnvelope):  # created at most 30 s after t
            module.verify_agent_action(env, me["public_key_b64u"], now=env["protected"]["created"] - 31)
        with pytest.raises(module.MalformedEnvelope):  # AICS-1 numbers are uints
            module.sign_agent_action(me["private_key"], {"x": 1.5}, origin=ORIGIN, entry_type="post")

    def test_chain_fields_and_hash_match_across_backends(self, sdk, fallback):
        seed = bytes.fromhex(KEYGEN_SEED_HEX)
        kwargs = {"created": 1_000, "expires": 1_300, "nonce": "AAAAAAAAAAAAAAAAAAAAAA", "origin": ORIGIN, "entry_type": "post"}
        first_ref = sdk.sign_agent_action(seed, {"x": 1}, seq=0, prev=None, **kwargs)
        first_fb = fallback.sign_agent_action(seed, {"x": 1}, seq=0, prev=None, **kwargs)
        assert first_ref == first_fb
        assert sdk.envelope_hash(first_ref) == fallback.envelope_hash(first_fb) == ref_envelope.envelope_hash(first_ref)
        second = fallback.sign_agent_action(seed, {"y": 2}, seq=1, prev=fallback.envelope_hash(first_fb), **kwargs)
        ref_envelope.check_successor(first_ref, second)

    def test_content_hash_is_jcs(self, sdk, fallback):
        fields = {"b": 2, "a": [1, "é"], "price": 12.5}
        expected = __import__("hashlib").sha256(ref_envelope.canonicalize(fields)).hexdigest()
        assert sdk.content_sha256(fields) == fallback.content_sha256(fields) == expected


# ---------------------------------------------------------------------------
# request signatures
# ---------------------------------------------------------------------------

class TestRequestSignatures:
    URL = "https://api.wesupport-ai.com/v2/agora/posts"

    def test_backends_produce_identical_headers(self, sdk, fallback):
        seed = bytes.fromhex(KEYGEN_SEED_HEX)
        args = ("POST", self.URL, b'{"title":"x"}', seed, "kid-fixed-000000")
        kwargs = {"created": 1_700_000_000, "expires": 1_700_000_300, "nonce": "n-123"}
        assert sdk.sign_request(*args, **kwargs) == fallback.sign_request(*args, **kwargs)

    @pytest.mark.parametrize("backend", ["sdk", "fallback"])
    def test_server_library_accepts_the_client_signature(self, sdk, fallback, backend):
        module = sdk if backend == "sdk" else fallback
        me = sdk.generate_identity()
        body = b'{"title":"x","body":"y"}'
        for url in (self.URL, self.URL + "?unread_only=true"):
            headers = module.sign_request("POST", url, body, me["private_key"], me["kid"])
            required = ref_http.AICS_COMPONENTS + (("@query",) if "?" in url else ())
            policy = dict(ref_http.AICS_VERIFY_POLICY)
            policy["required_components"] = required
            verified = ref_http.verify_request(
                "POST", url, headers, body, resolve_key=lambda kid: me["public_key_b64u"], **policy
            )
            assert verified[0].keyid == me["kid"] and verified[0].tag == "aics"

    def test_signature_breaks_when_the_body_changes(self, sdk):
        me = sdk.generate_identity()
        headers = sdk.sign_request("POST", self.URL, b"{}", me["private_key"], me["kid"])
        with pytest.raises(ref_http.VerificationFailed):
            ref_http.verify_request("POST", self.URL, headers, b'{"x":1}', resolve_key=lambda kid: me["public_key_b64u"], **ref_http.AICS_VERIFY_POLICY)


# ---------------------------------------------------------------------------
# no tokens, no operator wording
# ---------------------------------------------------------------------------

class TestNoTokens:
    def test_bearer_parameter_is_gone(self, sdk):
        with pytest.raises(TypeError):
            sdk.AICSClient(bearer_token="tok")

    def test_requests_carry_signatures_not_authorization(self, sdk):
        recorder = FakeLog()
        client = sdk.AICSClient(identity=sdk.generate_identity(), transport_fn=recorder, origin="o")
        written = client.grant_inbox("*", 3)
        client.me()
        assert all("Authorization" not in call["headers"] for call in recorder.calls)
        # A grant first reads its key's grants (for prev_grant_index) and envelope chain, both public reads; the
        # write is POST /v2/entries; the logged entry's index is a public read too.  What it does for the key is signed.
        grants, lookup, write, index, me = recorder.calls
        for read in (grants, lookup, index):
            assert read["method"] == "GET" and "Signature-Input" not in read["headers"]
        assert grants["url"].endswith("/grants") and "/v2/keys/" in lookup["url"] and "/v2/tlog/index/" in index["url"]
        assert [(call["method"], call["url"].rsplit("/v2/", 1)[1]) for call in (write, me)] == [("POST", "entries"), ("GET", "agents/me")]
        for call in (write, me):
            assert call["headers"]["Signature-Input"].startswith("aics=(")  # the one label of AICS-1 section 12.1
            assert 'tag="aics"' in call["headers"]["Signature-Input"]
            assert call["headers"]["User-Agent"].startswith("aics-client/")
        request = json.loads(write["body"])
        assert set(request) == {"envelope", "body"} and request["body"] is None  # exactly {envelope, body}
        assert request["envelope"]["protected"]["type"] == "grant" and "?" not in write["url"]
        assert written["index"] == 7 and written["entry"]["payload"]["envelope"] == request["envelope"]
        assert me["body"] is None  # a signed GET sends no body

    def test_an_answer_that_does_not_embed_the_envelope_sent_is_refused(self, sdk):
        def transport(method, url, headers, body):
            answer = logged_answer(method, url, body)
            if answer is not None and "entry" in answer:
                answer["entry"]["payload"]["envelope"]["payload"]["max"] = 999  # the log answers another entry
            return answer if answer is not None else {}

        client = sdk.AICSClient(identity=sdk.generate_identity(), transport_fn=transport, origin="o")
        with pytest.raises(sdk.AICSClientError, match="does not embed the envelope"):
            client.grant_inbox("*", 3)

    def test_source_has_no_operator_or_bearer_wording(self):
        text = SDK_PATH.read_text(encoding="utf-8")
        assert "operator" not in text.lower()
        assert "bearer" not in text.lower()

    def test_default_base_url_is_the_api_host(self, sdk):
        assert sdk.DEFAULT_BASE_URL == "https://api.wesupport-ai.com"

    def test_public_reads_need_no_identity(self, sdk):
        recorder = Recorder({"tasks": []})
        assert sdk.AICSClient(transport_fn=recorder).list_tasks() == {"tasks": []}
        assert recorder.calls[0]["url"].endswith("/v2/tasks")
        with pytest.raises(sdk.AICSClientError):
            sdk.AICSClient(transport_fn=recorder).me()

    def test_non_dict_response_raises(self, sdk):
        with pytest.raises(sdk.AICSClientError):
            sdk.AICSClient(transport_fn=Recorder(response=["no"])).list_tasks()


# ---------------------------------------------------------------------------
# end to end against the app
# ---------------------------------------------------------------------------

def new_client(sdk, client, identity=None, **kwargs):
    # The log key an agent pins out of band (DNS TXT _aics, the aics package, the README): here the app's own.
    kwargs.setdefault("log_vkey", client.app.state.db.server_vkey)
    return sdk.AICSClient(base_url="http://testserver", identity=identity or sdk.generate_identity(), transport_fn=route_to_testclient(client, sdk), **kwargs)


def https_testclient(client):
    """The same app over HTTPS (as behind Caddy): shared secrets are taken only then."""
    from fastapi.testclient import TestClient

    return TestClient(client.app, base_url="https://testserver")


def sealed_body(sdk, sender: dict, recipient: dict, text: str, nonce: str) -> tuple[bytes, dict]:
    """Seal *text* to *recipient* (a lookup) with the inner header bound to *nonce*; returns (bytes, metadata).

    The client signs and does not encrypt: an agent seals with its own libsodium, here aics_identity.sealed.
    """
    header = ref_sealed.InnerHeader(from_kid=sender["kid"], to_kid=recipient["kid"], envelope_nonce=nonce)
    ct = ref_sealed.seal(header, text, recipient["x25519_public_key_b64u"])
    return ct, ref_sealed.ciphertext_metadata(ct)


class TestAgainstTheServer:
    def test_agent_journey(self, sdk, client):
        alice = new_client(sdk, client, log_vkey=client.app.state.db.server_vkey)  # the key pinned out of band
        with pytest.raises(TypeError):
            alice.register("alice", profile={"display_name": "Alice"})  # a claim publishes a name, no profile
        reg = alice.register("alice")
        assert set(reg) == {"entry", "receipt_note", "entry_hash", "index", "receipt"} and reg["receipt"] == "verified"
        assert reg["entry"]["type"] == "name.claim" and reg["entry"]["actor_kid"] == alice.identity["kid"]
        assert reg["entry"]["payload"]["x25519"] == alice.identity["x25519_public_key_b64u"]
        assert reg["entry"]["payload"]["envelope"]["protected"]["seq"] == 0
        assert reg["index"] == alice.head_index and reg["entry_hash"] == sdk.entry_hash(reg["entry"])
        assert alice.entry(reg["index"])["verified"]["envelope"] == "verified"

        posted = alice.post("general", "Hello there", "First post from the client.")
        assert client.get(f"/v2/agora/posts/{posted['index']}").json()["post"]["author_name"] == "alice"
        exact = ref_canonicalize({"channel": "general", "title": "Hello there", "text": "First post from the client."})
        assert posted["entry"]["payload"]["body_hash"] == hashlib.sha256(exact).hexdigest()
        assert posted["entry"]["payload"]["size"] == len(exact)
        assert alice.entry(posted["index"])["verified"]["body"] == exact  # the body, bound by its hash
        reply = alice.post("general", None, "A reply without a title.", parent_index=posted["index"])
        assert reply["entry"]["payload"]["parent_index"] == posted["index"]
        poll = alice.create_poll("general", "Pick a primitive", "Which comes next?", ["timelocks", "rooms"])
        voted = alice.vote(poll["index"], 1, reason="rooms help")
        assert alice.poll(poll["index"])["total_votes"] == 1 and voted["entry"]["payload"]["option"] == 1
        work = alice.create_poll("general", "With work", "A poll that asks for proof of work.", ["a", "b"], pow_bits=6)
        proved = new_client(sdk, client)
        proved.register("prover")
        assert proved.vote(work["index"], 0)["entry"]["payload"]["pow_nonce"] is not None

        old_kid = alice.identity["kid"]
        new_identity = sdk.generate_identity()
        rotated = alice.rotate_key(new_identity)
        assert rotated["entry"]["payload"]["new_ed25519"] == new_identity["public_key_b64u"]
        assert alice.name_view("alice")["current"]["kid"] == new_identity["kid"] != old_kid
        assert alice.post("general", "After rotation", "Signed with the new key.")["entry"]["actor_kid"] == new_identity["kid"]

        x = alice.rotate_x25519()
        assert x["entry"]["payload"]["new_x25519"] == alice.identity["x25519_public_key_b64u"]
        assert alice.me()["agent"]["kid"] == new_identity["kid"]

        me = alice.lookup("alice")["agent"]
        nonce = sdk.new_nonce()
        ct, meta = sealed_body(sdk, alice.identity, me, "where I left off", nonce)
        put = alice.put_capsule("state", ct, nonce=nonce)
        assert put["entry"]["type"] == "capsule" and put["entry"]["payload"]["ct_hash"] == meta["ct_hash"]
        assert put["entry"]["payload"]["prev_capsule_index"] is None
        assert put["entry"]["payload"]["key_hash"] == hashlib.sha256(b"state").hexdigest()
        assert put["entry"]["payload"]["envelope"]["protected"]["nonce"] == nonce
        got = alice.get_capsule("state")
        opened = ref_sealed.open_sealed(
            sdk.b64u_decode(got["ciphertext"]),
            sdk.b64u_decode(alice.identity["x25519_private_key_b64u"]),
            expected={"from_kid": alice.identity["kid"], "to_kid": alice.identity["kid"], "envelope_nonce": nonce},
        )
        assert opened.text == "where I left off"
        assert alice.list_capsules()["count"] == 1
        nonce = sdk.new_nonce()
        again = alice.put_capsule("state", sealed_body(sdk, alice.identity, me, "a newer state", nonce)[0], nonce=nonce)
        assert again["entry"]["payload"]["prev_capsule_index"] == put["index"]
        # The bundle carries the ciphertext, bound by ct_hash; only the slot's key opens it.
        assert alice.entry(again["index"])["verified"]["body"] == sdk.b64u_decode(alice.get_capsule("state")["ciphertext"])

        revoked = alice.revoke("retired")
        assert revoked["entry"]["type"] == "key.revoke" and alice.name_view("alice")["revoked"] is True
        with pytest.raises(sdk.AICSRefusal) as refused:
            alice.post("general", "After revocation", "Must be refused.")
        # A logged refusal is evidence: its entry and a receipt the pinned key verifies (AICS-1 section 10.2).
        assert 400 <= refused.value.status < 500 and refused.value.entry["type"] == "refusal"
        sdk.verify_receipt(refused.value.receipt_note, refused.value.entry, log_vkey=alice.log_vkey)

    def test_messages_between_two_clients(self, sdk, client):
        alice, bob, carol = new_client(sdk, client), new_client(sdk, client), new_client(sdk, client)
        alice.register("alice")
        bob.register("bob", initial_grant={"sender_kid": "*", "max": 5, "expires": int(time.time()) + 600})
        carol.register("carol")
        bob_key = alice.lookup("bob")["agent"]
        nonce = sdk.new_nonce()
        ct, meta = sealed_body(sdk, alice.identity, bob_key, "meet at capsule 7", nonce)
        sent = alice.send_message("bob", sdk.b64u_encode(ct), nonce=nonce)
        assert sent["entry"]["type"] == "dm" and sent["entry"]["payload"]["grant_index"] == bob.head_index
        assert {k: sent["entry"]["payload"][k] for k in meta} == meta
        assert bob.inbox_status()["unread_count"] == 1
        message = bob.inbox(unread_only=True)["messages"][0]
        opened = ref_sealed.open_sealed(
            sdk.b64u_decode(message["ciphertext"]),
            sdk.b64u_decode(bob.identity["x25519_private_key_b64u"]),
            envelope=message["envelope"],
            recipient_kid=bob.identity["kid"],
        )
        assert opened.text == "meet at capsule 7"
        # Carol's inbox is closed until she signs a grant leaf naming Alice's key.
        nonce = sdk.new_nonce()
        carol_key = alice.lookup("carol")["agent"]
        with pytest.raises(sdk.AICSRefusal, match="no_consent") as refused:
            alice.send_message("carol", sealed_body(sdk, alice.identity, carol_key, "hello carol", nonce)[0], nonce=nonce)
        assert refused.value.reason_code == "no_consent" and refused.value.status == 403
        assert refused.value.entry["payload"]["attempt_kid"] == alice.identity["kid"]
        granted = carol.grant_inbox(alice.identity["kid"], 1)
        assert granted["entry"]["type"] == "grant" and granted["entry"]["payload"]["sender_kid"] == alice.identity["kid"]
        assert granted["entry"]["payload"]["prev_grant_index"] is None
        again = carol.grant_inbox(alice.identity["kid"], 1)
        assert again["entry"]["payload"]["prev_grant_index"] == granted["index"]
        granted = again
        nonce = sdk.new_nonce()
        assert alice.send_message("carol", sealed_body(sdk, alice.identity, carol_key, "hello carol", nonce)[0], nonce=nonce)[
            "entry"
        ]["payload"]["grant_index"] == granted["index"]

    def test_convenience_methods_build_dm_capsule_and_grant_leaves(self, sdk, client):
        alice, bob = new_client(sdk, client), new_client(sdk, client)
        alice.register("alice")
        bob.register("bob")
        granted = bob.grant_inbox(alice.identity["kid"], 3, expires=int(time.time()) + 600)
        assert {k: granted["entry"]["payload"][k] for k in ("owner_kid", "sender_kid", "max")} == {
            "owner_kid": bob.identity["kid"], "sender_kid": alice.identity["kid"], "max": 3,
        }
        bob_key = alice.lookup("bob")["agent"]
        nonce = sdk.new_nonce()
        box, _ = sealed_body(sdk, alice.identity, bob_key, "hi", nonce)
        sent = alice.send_message("bob", box, nonce=nonce)
        payload = sent["entry"]["payload"]
        assert payload["seq"] == payload["envelope"]["protected"]["seq"] == 1
        assert payload["envelope"]["protected"]["nonce"] == nonce
        message = bob.inbox()["messages"][0]
        opened = ref_sealed.open_sealed(
            sdk.b64u_decode(message["ciphertext"]),
            sdk.b64u_decode(bob.identity["x25519_private_key_b64u"]),
            envelope=message["envelope"],
            recipient_kid=bob.identity["kid"],
        )
        assert opened.text == "hi"
        me = alice.lookup("alice")["agent"]
        nonce = sdk.new_nonce()
        box, meta = sealed_body(sdk, alice.identity, me, "my state", nonce)
        stored = alice.put_capsule("state", box, nonce=nonce)
        assert stored["entry"]["type"] == "capsule" and stored["entry"]["payload"]["ct_hash"] == meta["ct_hash"]
        assert sdk.b64u_decode(alice.get_capsule("state")["ciphertext"]) == box
        # Bodies the server would refuse are refused before they leave: no cleartext scheme, no short box.
        plain = b"plain words, not encrypted, long enough to pass for a box"
        with pytest.raises(ValueError):
            alice.send_message("bob", plain, nonce=sdk.new_nonce(), encryption="cleartext-signed")
        with pytest.raises(ValueError):
            alice.put_capsule("state", b"short", nonce=sdk.new_nonce())

    def test_a_fresh_client_resumes_the_chain(self, sdk, client):
        identity = sdk.generate_identity()
        first = new_client(sdk, client, identity)
        first.register("resumer")
        first.post("general", "One", "From the first process.")
        later = new_client(sdk, client, identity, name="resumer")
        assert later.post("general", "Two", "From a later process.")["entry"]["payload"]["envelope"]["protected"]["seq"] == 2
        assert later.rotate_x25519()["index"] == later.head_index

    def test_recovery_key_declaration(self, sdk, client):
        alice = new_client(sdk, client)
        recovery = sdk.generate_identity()
        reg = alice.register("alice", recovery_identity=recovery)
        assert reg["entry"]["payload"]["recovery_kid"] == recovery["kid"]

    def test_unverified_tier_and_upgrade(self, sdk, client):
        secret = "client-side-secret-0123456789abcdefXYZ"
        # Shared-secret writes exist only at the TLS text gate (AICS-1 section 12.1): the client has none of its own.
        assert not hasattr(sdk.AICSClient, "register_secret") and not hasattr(sdk.AICSClient, "post_unverified")
        with pytest.raises(sdk.AICSClientError, match="HTTPS only"):
            sdk._default_gate_transport("http://testserver/t", "help\n", 1.0)  # a secret never goes over plain HTTP
        claimed = secret_claim(client, "plain", secret)
        plain = new_client(sdk, client, gate_fn=gate_to_testclient(client), log_vkey=client.app.state.db.server_vkey)
        new_identity = sdk.generate_identity()
        upgraded = plain.upgrade("plain", secret, new_identity)
        assert upgraded["entry"]["type"] == "key.rotate" and upgraded["entry"]["payload"]["mode"] == "upgrade"
        assert upgraded["entry"]["actor_kid"] == new_identity["kid"] and upgraded["index"] == plain.head_index
        assert secret not in json.dumps(upgraded)
        view = client.get("/v2/names/plain").json()
        assert view["tier"] == "verified" and view["current"]["kid"] == new_identity["kid"]
        assert plain.entry(upgraded["index"])["verified"]["envelope"] == "verified"  # signed at the gate, checked here
        assert plain.entry(claimed.claim_index)["verified"]["envelope"] == "attested"  # the secret's claim: attested only
        posted = plain.post("general", "Now with a key", "Signed after the upgrade.")
        assert client.get(f"/v2/agora/posts/{posted['index']}").json()["post"]["author_tier"] == "verified"
        # The old secret no longer opens the name.
        with pytest.raises(sdk.AICSClientError):
            new_client(sdk, client, gate_fn=gate_to_testclient(client)).upgrade("plain", secret, sdk.generate_identity())

    def test_no_private_key_material_leaves_the_client(self, sdk, client):
        """Every byte the client sends (URLs, headers, bodies, gate lines) is free of every private key it holds."""
        sent: list[bytes] = []
        inner, gate = route_to_testclient(client, sdk), gate_to_testclient(client)

        def transport(method, url, headers, body):
            sent.append(f"{method} {url}\n{json.dumps(headers)}\n".encode() + (body or b""))
            return inner(method, url, headers, body)

        def gate_fn(text):
            sent.append(text.encode("utf-8"))
            return gate(text)

        def make(identity=None):
            return sdk.AICSClient(base_url="http://testserver", identity=identity or sdk.generate_identity(),
                                  transport_fn=transport, gate_fn=gate_fn, log_vkey=client.app.state.db.server_vkey)

        alice, bob = make(), make()
        identities = [alice.identity, bob.identity]
        alice.register("alice")
        bob.register("bob")
        bob.grant_inbox(alice.identity["kid"], 2)
        alice.post("general", "Hello", "Nothing private in here.")
        alice.send_sealed("bob", "a sealed note")
        alice.store_sealed("notes", "a sealed state")
        assert bob.read_inbox()[0]["text"] == "a sealed note" and alice.load_sealed("notes")["text"] == "a sealed state"
        rotated = sdk.generate_identity()
        alice.rotate_key(rotated, rotate_x25519=True)
        secret = "upgrade-secret-0123456789-abcdefghijkl"
        secret_claim(client, "plain", secret)
        upgraded = sdk.generate_identity()
        make().upgrade("plain", secret, upgraded)
        identities += [rotated, upgraded]
        wire = b"\n".join(sent)
        assert b"/v2/entries" in wire and b"claim-upgrade plain" in wire
        for identity in identities:
            for key in (bytes.fromhex(identity["private_seed_hex"]), sdk.b64u_decode(identity["x25519_private_key_b64u"])):
                for form in (key.hex(), sdk.b64u_encode(key), base64.b64encode(key).decode("ascii")):
                    assert form.encode("ascii") not in wire

    def test_standalone_fallback_client_works_end_to_end(self, fallback, client):
        agent = fallback.AICSClient(base_url="http://testserver", identity=fallback.generate_identity(), transport_fn=route_to_testclient(client, fallback))
        agent.register("standalone")
        posted = agent.post("general", "Standalone", "No aics_identity installed here.")
        assert client.get(f"/v2/agora/posts/{posted['index']}").json()["post"]["author_name"] == "standalone"
        assert agent.rotate_key(fallback.generate_identity())["entry"]["payload"]["name_norm"] == "standalone"
        assert agent.post("general", "Rotated", "Still standalone.")["index"] > posted["index"]
        # Without aics_identity the client still verifies a native bundle with the pinned key.
        agent.log_vkey = client.app.state.db.server_vkey
        assert agent.entry(posted["index"])["verified"]["envelope"] == "verified"
        # Grants, messages and capsules need nothing beyond `cryptography` either (the agent seals the bodies).
        peer = fallback.AICSClient(base_url="http://testserver", identity=fallback.generate_identity(), transport_fn=route_to_testclient(client, fallback))
        peer.register("peer")
        peer.grant_inbox(agent.identity["kid"], 1)
        nonce = fallback.new_nonce()
        box, meta = sealed_body(fallback, agent.identity, agent.lookup("peer")["agent"], "from a standalone client", nonce)
        sent = agent.send_message("peer", box, nonce=nonce)["entry"]["payload"]
        assert {k: sent[k] for k in meta} == meta
        nonce = fallback.new_nonce()
        box, meta = sealed_body(fallback, agent.identity, agent.lookup("standalone")["agent"], "standalone state", nonce)
        assert agent.put_capsule("state", box, nonce=nonce)["entry"]["payload"]["ct_hash"] == meta["ct_hash"]


# ---------------------------------------------------------------------------
# verification here: bundles and receipts against the pinned log key (AICS-1 sections 10.1, 14.3)
# ---------------------------------------------------------------------------

def vkey_text(name: str, public_raw: bytes) -> str:
    """A C2SP Ed25519 verifier key: ``name+hex(key id)+B64(0x01 || key)``."""
    blob = b"\x01" + public_raw
    key_id = hashlib.sha256(name.encode("utf-8") + b"\n" + blob).digest()[:4]
    return f"{name}+{key_id.hex()}+" + base64.b64encode(blob).decode("ascii")


class TestVerification:
    def test_a_bundle_verifies_here_and_tampering_is_caught(self, sdk, fallback, client):
        db = client.app.state.db
        alice = new_client(sdk, client, log_vkey=db.server_vkey)
        reg = alice.register("alice")
        posted = alice.post("general", "Verify me", "A bundle checked by the client itself.")
        bundle = client.get(f"/v2/entries/{posted['index']}").json()
        for module in (sdk, fallback):
            result = module.verify_bundle(bundle, log_vkey=db.server_vkey, origin=db.origin)
            assert (result["envelope"], result["checkpoint"], result["index"]) == ("verified", "verified", posted["index"])
            assert result["entry"] == posted["entry"] and result["body"] == module.b64u_decode(bundle["body_or_ct"])
        with pytest.raises(sdk.BundleError, match="body_or_ct"):
            sdk.verify_bundle({**bundle, "body_or_ct": sdk.b64u_encode(b"another body")}, log_vkey=db.server_vkey)
        with pytest.raises(sdk.BundleError, match="inclusion proof"):
            sdk.verify_bundle({**bundle, "index": bundle["index"] + 1}, log_vkey=db.server_vkey)
        with pytest.raises(sdk.BundleError, match="exactly"):
            sdk.verify_bundle({**bundle, "extra": 1}, log_vkey=db.server_vkey)
        with pytest.raises(sdk.BundleError, match="another log origin"):
            sdk.verify_bundle(bundle, log_vkey=db.server_vkey, origin="elsewhere.example/tiles")
        # Another key (here the policy key, under the log's name) signed no checkpoint and no receipt.
        policy = sdk.b64u_decode(client.get("/v2/tlog/checkpoint").json()["policy_public_key_b64u"])
        wrong = vkey_text(db.origin, policy)
        with pytest.raises(sdk.BundleError, match="pinned log key"):
            sdk.verify_bundle(bundle, log_vkey=wrong)
        with pytest.raises(sdk.BundleError, match="pinned log key"):
            sdk.verify_receipt(posted["receipt_note"], posted["entry"], log_vkey=wrong)
        # A receipt promises one entry only.
        assert sdk.verify_receipt(posted["receipt_note"], posted["entry"], log_vkey=db.server_vkey)["mmd_seconds"] == 60
        with pytest.raises(sdk.BundleError, match="another entry"):
            sdk.verify_receipt(posted["receipt_note"], reg["entry"], log_vkey=db.server_vkey)

    def test_a_gate_signed_envelope_needs_the_library_to_verify(self, sdk, fallback, client):
        line = Line(client)
        gabe = KeyAgent("gabe")
        onboard(line, gabe)
        bundle = client.get(f"/v2/entries/{gabe.claim_index}").json()
        vkey = client.app.state.db.server_vkey
        assert sdk.verify_bundle(bundle, log_vkey=vkey)["envelope"] == "verified"  # text-ed25519, rebuilt and checked
        assert fallback.verify_bundle(bundle, log_vkey=vkey)["envelope"] == "verified"  # the standalone file too
        # An SSHSIG blob needs aics_identity: the standalone file says so and never assumes it.
        sam = KeyAgent("sam")
        onboard(Line(client), sam, tool="ssh-keygen")
        sshsig_bundle = client.get(f"/v2/entries/{sam.claim_index}").json()
        assert sdk.verify_bundle(sshsig_bundle, log_vkey=vkey)["envelope"] == "verified"
        assert fallback.verify_bundle(sshsig_bundle, log_vkey=vkey)["envelope"] == "unchecked"
        # An envelope with another signature is not the logged entry: the bundle no longer proves.
        env = json.loads(json.dumps(bundle["envelope"]))
        env["sig"] = sdk.b64u_encode(bytes(64))
        forged = json.loads(sdk.b64u_decode(bundle["entry_bytes"]))
        forged["payload"]["envelope"] = env
        with pytest.raises(sdk.BundleError, match="inclusion proof"):
            sdk.verify_bundle({**bundle, "envelope": env, "entry_bytes": sdk.b64u_encode(ref_canonicalize(forged))}, log_vkey=vkey)


# ---------------------------------------------------------------------------
# default urllib transport
# ---------------------------------------------------------------------------

class TestDefaultTransport:
    def test_request_shape(self, sdk, monkeypatch):
        captured = []

        class FakeBody:
            def __init__(self, data):
                self.data = data

            def read(self):
                return self.data

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(request, timeout=None):
            captured.append((request, timeout))
            answer = logged_answer(request.get_method(), request.full_url, request.data, index=3)
            return FakeBody(json.dumps(answer if answer is not None else {"ok": True}).encode())

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        client = sdk.AICSClient(base_url="https://api.example.com", identity=sdk.generate_identity(), timeout=7.5, origin="o")
        written = client.grant_inbox("*", 2)
        assert written["index"] == 3 and written["entry"]["type"] == "grant"
        [(request, timeout)] = [(r, t) for r, t in captured if r.get_method() == "POST"]
        assert request.full_url == "https://api.example.com/v2/entries"
        assert request.get_method() == "POST"
        headers = {k.lower(): v for k, v in request.headers.items()}
        assert "signature" in headers and "content-digest" in headers and "authorization" not in headers
        ref_http.verify_request(
            "POST",
            request.full_url,
            list(request.headers.items()),
            request.data,
            resolve_key=lambda kid: client.identity["public_key_b64u"],
            **ref_http.AICS_VERIFY_POLICY,
        )
        assert timeout == 7.5 and all(t == 7.5 for _, t in captured)

    def test_a_logged_refusal_raises_with_its_entry(self, sdk, monkeypatch):
        refusal = {"entry": {"type": "refusal", "payload": {"reason_code": "no_consent"}}, "receipt_note": "bm90ZQ"}

        def fake_urlopen(request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, io.BytesIO(json.dumps(refusal).encode()))

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        with pytest.raises(sdk.AICSRefusal) as excinfo:
            sdk.AICSClient(identity=sdk.generate_identity(), origin="o").list_tasks()
        assert excinfo.value.status == 403 and excinfo.value.reason_code == "no_consent"
        assert excinfo.value.entry == refusal["entry"] and excinfo.value.receipt_note == "bm90ZQ"
        assert isinstance(excinfo.value, sdk.AICSClientError)

    def test_http_error_is_wrapped_with_body(self, sdk, monkeypatch):
        def fake_urlopen(request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, io.BytesIO(b'{"detail": "capsule missing"}'))

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        with pytest.raises(sdk.AICSClientError) as excinfo:
            sdk.AICSClient(identity=sdk.generate_identity()).get_capsule("nope")
        assert "404" in str(excinfo.value) and "capsule missing" in str(excinfo.value)

    def test_url_error_is_wrapped(self, sdk, monkeypatch):
        def fake_urlopen(request, timeout=None):
            raise urllib.error.URLError("dns lookup failed")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        with pytest.raises(sdk.AICSClientError, match="dns lookup failed"):
            sdk.AICSClient().list_tasks()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestCli:
    def test_derived_keygen_prints_public_keys_only(self, sdk, capsys):
        assert sdk.main(["keygen", "--seed-hex", KEYGEN_SEED_HEX, "--label", "agent-7"]) == 0
        output = json.loads(capsys.readouterr().out)
        identity = sdk.derive_agent_identity(bytes.fromhex(KEYGEN_SEED_HEX), "agent-7")
        assert output == {
            "did": identity["did"],
            "kid": identity["kid"],
            "public_key_b64u": identity["public_key_b64u"],
            "x25519_public_key_b64u": identity["x25519_public_key_b64u"],
        }

    def test_fallback_keygen_matches(self, sdk, fallback, capsys):
        fallback.main(["keygen", "--seed-hex", KEYGEN_SEED_HEX, "--label", "agent-fb"])
        from_fallback = capsys.readouterr().out
        sdk.main(["keygen", "--seed-hex", KEYGEN_SEED_HEX, "--label", "agent-fb"])
        assert capsys.readouterr().out == from_fallback

    def test_random_keygen_writes_a_private_file(self, sdk, tmp_path, capsys):
        out = tmp_path / "id.json"
        assert sdk.main(["keygen", "--out", str(out)]) == 0
        printed = json.loads(capsys.readouterr().out)
        assert "private_seed_hex" not in printed
        assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
        assert sdk.load_identity(str(out))["kid"] == printed["kid"]

    def test_random_keygen_without_a_file_is_refused(self, sdk):
        with pytest.raises(SystemExit) as excinfo:
            sdk.main(["keygen"])
        assert excinfo.value.code == 2

    @pytest.mark.parametrize("bad_seed", ["zzzz", "abc", KEYGEN_SEED_HEX + "00", ""])
    def test_invalid_seed_hex(self, sdk, bad_seed):
        with pytest.raises(SystemExit) as excinfo:
            sdk.main(["keygen", "--seed-hex", bad_seed, "--label", "agent-7"])
        assert excinfo.value.code == 2

    def test_seed_without_label(self, sdk):
        with pytest.raises(SystemExit):
            sdk.main(["keygen", "--seed-hex", KEYGEN_SEED_HEX])

    def test_register_command_claims_a_name(self, sdk, client, tmp_path, monkeypatch, capsys):
        out = tmp_path / "id.json"
        sdk.main(["keygen", "--out", str(out)])
        kid = json.loads(capsys.readouterr().out)["kid"]

        class Response:
            def __init__(self, text):
                self.text = text

            def read(self):
                return self.text.encode()

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(request, timeout=None):
            parts = urllib.parse.urlsplit(request.full_url)
            response = client.request(request.get_method(), parts.path, headers=dict(request.headers.items()), content=request.data)
            if response.status_code >= 300:
                raise urllib.error.HTTPError(request.full_url, response.status_code, "err", {}, io.BytesIO(response.content))
            return Response(response.text)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        code = sdk.main(["register", "--identity", str(out), "--name", "cli-agent", "--base-url", "http://testserver"])
        assert code == 0
        result = json.loads(capsys.readouterr().out)
        assert result["entry"]["payload"]["name_norm"] == "cli-agent" and result["entry"]["actor_kid"] == kid
        assert client.get("/v2/names/cli-agent").json()["current"]["kid"] == kid
        # Claiming the same name again fails cleanly.
        other = tmp_path / "other.json"
        sdk.main(["keygen", "--out", str(other)])
        capsys.readouterr()
        assert sdk.main(["register", "--identity", str(other), "--name", "cli-agent", "--base-url", "http://testserver"]) == 1
        assert "name_taken" in capsys.readouterr().err

    def test_unknown_command(self, sdk):
        with pytest.raises(SystemExit):
            sdk.main(["frobnicate"])


# ---------------------------------------------------------------------------
# sealed boxes: the client seals and opens (PyNaCl), compatible with aics_identity.sealed
# ---------------------------------------------------------------------------

class TestSealedBoxes:
    @pytest.mark.parametrize("backend", ["sdk", "fallback"])
    def test_a_sealed_message_round_trips_through_the_server(self, request, backend, client):
        module = request.getfixturevalue(backend)
        assert module.HAS_PYNACL is True
        alice, bob = new_client(module, client), new_client(module, client)
        alice.register("alice")
        bob.register("bob")
        bob.grant_inbox(alice.identity["kid"], 5)
        sent = alice.send_sealed("bob", "meet at leaf 7")["entry"]["payload"]
        assert sent["encryption"] == module.SEALED_SCHEME and "meet" not in json.dumps(sent)
        [message] = bob.read_inbox()
        assert message["text"] == "meet at leaf 7" and message["from_kid"] == alice.identity["kid"]
        assert message["header"] == {
            "envelope_nonce": sent["envelope"]["protected"]["nonce"],
            "from_kid": alice.identity["kid"],
            "to_kid": bob.identity["kid"],
        }

    @pytest.mark.parametrize("backend", ["sdk", "fallback"])
    def test_a_sealed_capsule_round_trips(self, request, backend, client):
        module = request.getfixturevalue(backend)
        me = new_client(module, client)
        me.register("keeper")
        stored = me.store_sealed("notes", "state to keep")
        expires = stored["entry"]["payload"]["expires"]
        assert expires - stored["entry"]["ts"] >= 7776000  # the 90-day floor
        assert me.load_sealed("notes")["text"] == "state to keep"

    def test_client_boxes_and_library_boxes_open_each_other(self, sdk, fallback):
        bob, alice = sdk.generate_identity(), sdk.generate_identity()
        header = {"from_kid": alice["kid"], "to_kid": bob["kid"], "envelope_nonce": ref_envelope.new_nonce()}
        box = fallback.seal_message("hello", bob["x25519_public_key_b64u"], **header)
        opened = ref_sealed.open_sealed(box, sdk.b64u_decode(bob["x25519_private_key_b64u"]), expected=header)
        assert opened.body == b"hello"
        library_box = ref_sealed.seal(header, "from the library", bob["x25519_public_key_b64u"])
        env = {"protected": {"kid": header["from_kid"], "nonce": header["envelope_nonce"]},
               "payload": {"to_kid": bob["kid"], **ref_sealed.ciphertext_metadata(library_box)}}
        assert fallback.open_message(library_box, bob["x25519_private_key_b64u"], env)["text"] == "from the library"

    def test_a_box_lifted_into_another_envelope_is_refused(self, sdk):
        alice, mallory, bob = sdk.generate_identity(), sdk.generate_identity(), sdk.generate_identity()
        nonce = sdk.new_nonce()
        box = sdk.seal_message("alice's words", bob["x25519_public_key_b64u"], from_kid=alice["kid"], to_kid=bob["kid"], envelope_nonce=nonce)
        meta = sdk.ciphertext_metadata(box)
        lifted = sdk.sign_agent_action(mallory["private_key"], {"to_kid": bob["kid"], **meta}, origin=ORIGIN, entry_type="dm")
        with pytest.raises(sdk.SealedMessageError, match="does not match the envelope"):
            sdk.open_message(box, bob["x25519_private_key_b64u"], lifted, sender_public_key_b64u=mallory["public_key_b64u"])
        honest = sdk.sign_agent_action(alice["private_key"], {"to_kid": bob["kid"], **meta}, origin=ORIGIN, entry_type="dm", nonce=nonce)
        assert sdk.open_message(box, bob["x25519_private_key_b64u"], honest, sender_public_key_b64u=alice["public_key_b64u"])["text"] == "alice's words"
        with pytest.raises(sdk.SealedMessageError, match="verify"):
            sdk.open_message(box, bob["x25519_private_key_b64u"], honest, sender_public_key_b64u=mallory["public_key_b64u"])
        tampered = box[:-1] + bytes([box[-1] ^ 1])
        with pytest.raises(sdk.SealedMessageError, match="ct_hash"):
            sdk.open_message(tampered, bob["x25519_private_key_b64u"], honest)
        with pytest.raises(sdk.SealedMessageError, match="another key"):
            sdk.open_message(box, mallory["x25519_private_key_b64u"], honest)

    def test_a_small_order_key_is_refused(self, sdk):
        with pytest.raises(sdk.SealedMessageError):
            sdk.seal_message("x", bytes(32), from_kid="a", to_kid="b", envelope_nonce="c")


# ---------------------------------------------------------------------------
# recipient keys from the verified key chain, never from an API field (AICS-1 sections 7, 8.1; DESIGN G6)
# ---------------------------------------------------------------------------

def rewriting(client, sdk, rewrite):
    """A transport into the app whose JSON answers pass through ``rewrite(method, path, data)``: a dishonest server."""
    inner = route_to_testclient(client, sdk)

    def transport(method, url, headers, body):
        data = inner(method, url, headers, body)
        return rewrite(method, urllib.parse.urlsplit(url).path, data)

    return transport


def dm_count(client) -> int:
    return client.app.state.db._conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]


class TestKeyChains:
    def pair(self, sdk, client):
        alice, bob = new_client(sdk, client), new_client(sdk, client)
        alice.register("alice")
        bob.register("bob")
        bob.grant_inbox(alice.identity["kid"], 5)
        return alice, bob

    @pytest.mark.parametrize("backend", ["sdk", "fallback"])
    def test_nothing_is_sealed_or_trusted_without_the_pinned_log_key(self, request, backend, client):
        module = request.getfixturevalue(backend)
        alice, bob = self.pair(module, client)
        loose = module.AICSClient(base_url="http://testserver", identity=alice.identity, name="alice",
                                  transport_fn=route_to_testclient(client, module))
        for call in (lambda: loose.send_sealed("bob", "hi"), lambda: loose.store_sealed("notes", "x"),
                     lambda: loose.entry(1), lambda: loose.verified_key_chain("bob"),
                     lambda: loose.send_message("bob", b"\0" * 64, nonce=module.new_nonce())):
            with pytest.raises(module.AICSClientError, match="pin the log key"):
                call()
        assert dm_count(client) == 0
        unchecked = loose.entry(1, allow_unverified=True)["verified"]
        assert unchecked["checkpoint"].startswith("unverified")  # knowingly, and said so
        bundle = client.get("/v2/entries/1").json()
        with pytest.raises(module.BundleError, match="pin the log key"):
            module.verify_bundle(bundle)
        written = loose.post("general", "No key pinned", "Writes still work; the receipt is marked.")
        assert written["receipt"] == "unverified"
        with pytest.raises(module.BundleError, match="pin the log key"):
            module.verify_receipt(written["receipt_note"], written["entry"])

    def test_the_chain_follows_rotations_and_sealing_uses_it(self, sdk, client):
        alice, bob = self.pair(sdk, client)
        bob.rotate_x25519()
        chain = alice.verified_key_chain("bob")
        assert chain["x25519_public_key_b64u"] == bob.identity["x25519_public_key_b64u"]
        assert chain["x25519_leaf_index"] == bob.head_index and chain["kid"] == bob.identity["kid"]
        new_identity = sdk.generate_identity()
        bob.rotate_key(new_identity, rotate_x25519=True)
        chain = alice.verified_key_chain("bob")
        assert chain["kid"] == new_identity["kid"] and chain["x25519_public_key_b64u"] == new_identity["x25519_public_key_b64u"]
        bob.grant_inbox(alice.identity["kid"], 5)  # grants name keys: the new key grants anew
        alice.send_sealed("bob", "after two rotations")
        assert bob.read_inbox()[-1]["text"] == "after two rotations"

    def test_a_lookup_naming_another_x25519_key_is_never_sealed_to(self, sdk, client):
        alice, _ = self.pair(sdk, client)
        attacker = sdk.generate_x25519_keypair()["x25519_public_key_b64u"]

        def lie(method, path, data):
            if path.startswith("/v2/ans/lookup/"):
                data = json.loads(json.dumps(data))
                data["agent"]["x25519_public_key_b64u"] = attacker
            return data

        mitm = sdk.AICSClient(base_url="http://testserver", identity=alice.identity, name="alice",
                              transport_fn=rewriting(client, sdk, lie), log_vkey=client.app.state.db.server_vkey)
        with pytest.raises(sdk.KeyChainError, match="other keys"):
            mitm.send_sealed("bob", "for bob only")
        assert dm_count(client) == 0
        # An own capsule is sealed to this identity's local key, after its chain shows that key: the lie is moot.
        stored = mitm.store_sealed("notes", "for me only")
        assert stored["entry"]["payload"]["to_key_leaf_index"] == alice.head_index
        assert alice.load_sealed("notes")["text"] == "for me only"

    def test_an_own_chain_naming_other_keys_stores_nothing(self, sdk, client):
        alice, _ = self.pair(sdk, client)
        stale = {**alice.identity, **sdk.generate_x25519_keypair()}  # a local key the log never set
        drifted = new_client(sdk, client, identity=stale, name="alice")
        with pytest.raises(sdk.KeyChainError, match="other keys than this identity's own"):
            drifted.store_sealed("notes", "x")

    def test_a_name_view_built_from_other_leaves_is_refused(self, sdk, client):
        alice, bob = self.pair(sdk, client)
        alice_claim = alice.head_index

        def splice(method, path, data):
            if path == "/v2/names/bob":
                data = {**data, "indices": [alice_claim]}  # a genuine leaf, of another name
            return data

        mitm = sdk.AICSClient(base_url="http://testserver", identity=alice.identity, name="alice",
                              transport_fn=rewriting(client, sdk, splice), log_vkey=client.app.state.db.server_vkey)
        with pytest.raises(sdk.KeyChainError, match="does not start with its name.claim"):
            mitm.verified_key_chain("bob")

        def unsigned_view(method, path, data):
            if path == "/v2/names/bob":
                note = sdk.b64u_decode(data["checkpoint_note"])
                data = {**data, "checkpoint_note": sdk.b64u_encode(note.split(b"\n\n")[0] + b"\n\n")}
            return data

        forged = sdk.AICSClient(base_url="http://testserver", identity=alice.identity, name="alice",
                                transport_fn=rewriting(client, sdk, unsigned_view), log_vkey=client.app.state.db.server_vkey)
        with pytest.raises(sdk.KeyChainError, match="checkpoint"):
            forged.verified_key_chain("bob")

    def test_a_key_event_not_signed_by_the_names_key_breaks_the_chain(self, sdk, client):
        alice, bob = self.pair(sdk, client)
        chain = alice.verified_key_chain("bob")
        state = {k: chain[k] for k in ("kid", "public_key_b64u", "x25519_public_key_b64u", "x25519_leaf_index", "tier",
                                       "claim_index", "head_index", "revoked")}
        forged = {"type": "x25519.rotate", "origin": alice.origin, "actor_kid": alice.identity["kid"],
                  "payload": {"name_norm": "bob", "prev_event_index": chain["head_index"], "new_x25519": "x" * 43}}
        with pytest.raises(sdk.KeyChainError, match="not signed by the name's key"):
            alice._apply_key_event(dict(state), "bob", chain["head_index"] + 5, forged, "verified")
        late = {**forged, "actor_kid": bob.identity["kid"],
                "payload": {**forged["payload"], "prev_event_index": chain["head_index"] - 1}}
        with pytest.raises(sdk.KeyChainError, match="prev_event_index"):
            alice._apply_key_event(dict(state), "bob", chain["head_index"] + 5, late, "verified")


class TestTheUpgradeIsCheckedBeforeSigning:
    def run(self, sdk, client, tamper):
        secret = "client-side-secret-0123456789abcdefXYZ"
        secret_claim(client, "plain", secret)
        sent: list[str] = []
        honest = gate_to_testclient(client)

        def gate(text):
            sent.append(text)
            return tamper(honest(text))

        agent = new_client(sdk, client, gate_fn=gate)
        with pytest.raises(sdk.AICSClientError, match="other bytes|another upgrade"):
            agent.upgrade("plain", secret, sdk.generate_identity())
        return sent

    def test_other_rotation_bytes_are_never_signed(self, sdk, client):
        attacker = sdk.generate_x25519_keypair()["x25519_public_key_b64u"]

        def swap(reply):
            if "ok signing-input " not in reply:
                return reply
            line = next(x for x in reply.split("\n") if x.startswith("ok signing-input "))
            message = base64.b64decode(line[len("ok signing-input "):])
            r = json.loads(message[len(b"AICS-1 key.rotate\n"):])
            r["new_x25519"] = attacker  # the gate would bind its own encryption key to the name
            forged = b"AICS-1 key.rotate\n" + ref_canonicalize(r)
            return reply.replace(line, "ok signing-input " + base64.b64encode(forged).decode())

        sent = self.run(sdk, client, swap)
        assert not any(text.startswith(("proof ", "session")) and "proof " in text for text in sent[-1:])
        assert all("proof " not in text for text in sent)  # no proof was made over the gate's bytes

    def test_a_proposal_with_another_payload_is_never_committed_to(self, sdk, client):
        attacker = sdk.generate_x25519_keypair()["x25519_public_key_b64u"]

        def swap(reply):
            if "ok envelope " not in reply:
                return reply
            line = next(x for x in reply.split("\n") if x.startswith("ok envelope "))
            u = json.loads(sdk.b64u_decode(line[len("ok envelope "):]))
            u["payload"]["new_x25519"] = attacker
            return reply.replace(line, "ok envelope " + sdk.b64u_encode(ref_canonicalize(u)))

        sent = self.run(sdk, client, swap)
        assert all("claim-upgrade " not in text and "sig " not in text for text in sent)  # nothing signed for it


class TestStandaloneKeyChecks:
    def test_the_standalone_file_refuses_small_order_keys(self, fallback):
        identity_point = bytes([1]) + bytes(31)
        with pytest.raises(ValueError, match="small-order"):
            fallback._keys.parse_public_key(fallback.b64u_encode(identity_point))
        did = "did:key:z" + fallback._keys.base58_encode(b"\xed\x01" + identity_point)
        with pytest.raises(ValueError, match="small-order"):
            fallback._keys.parse_did_key(did)
        honest = fallback.generate_identity()
        assert fallback._keys.parse_did_key(honest["kid"])


# ---------------------------------------------------------------------------
# the owner login (decision 3): OwnerClient and `aics_client.py owner ...`
# ---------------------------------------------------------------------------

class TestOwnerClient:
    def owner_client(self, sdk, client, owner_key):
        return sdk.OwnerClient(owner_key, base_url="http://testserver", transport_fn=route_to_testclient(client, sdk),
                               log_vkey=client.app.state.db.server_vkey)

    @pytest.mark.parametrize("backend", ["sdk", "fallback"])
    def test_the_owner_freezes_reopens_and_administers(self, request, backend, client, owner):
        module = request.getfixturevalue(backend)
        boss = self.owner_client(module, client, owner.key)
        alice = new_client(module, client)
        alice.register("alice")
        frozen = boss.freeze("maintenance", "Planned maintenance, back within the hour.")
        assert frozen["entry"]["type"] == "freeze" and frozen["receipt"] == "verified"
        assert boss.freeze_state()["state"] == "frozen"
        with pytest.raises(module.AICSRefusal, match="frozen"):
            alice.post("general", "While frozen", "Refused.")
        assert boss.reopen("Maintenance done.")["entry"]["payload"]["state"] == "open"
        assert boss.freeze_state()["state"] == "open"
        posted = alice.post("general", "After the freeze", "Writes are open again.")
        evidence = hashlib.sha256(b"order 2026/11").hexdigest()
        assert boss.tombstone(posted["index"], "order", evidence)["entry"]["type"] == "tombstone"
        assert boss.suspend(alice.identity["kid"], evidence)["entry"]["payload"]["until"] is None
        assert boss.end_suspension(alice.identity["kid"], evidence)["entry"]["payload"]["until"] is not None
        assert boss.audit("Verification day report.")["entry"]["payload"]["kind"] == "audit"
        notice = client.post("/notice", json={"location": f"leaf {posted['index']}", "accurate": True,
                                              "explanation": "This post seems unlawful to me."}).json()
        assert [n["report_id"] for n in boss.notices("open")["notices"]] == [notice["report_id"]]
        closed = boss.close_notice(notice["report_id"], "declined")
        assert closed["entry"]["payload"]["outcome_code"] == "declined"

    def test_the_owner_logs_the_bootstrap_card(self, sdk, client, owner):
        boss = self.owner_client(sdk, client, owner.key)
        card = client.get("/.well-known/aics-card.json").content
        logged = boss.log_card(card)
        assert logged["policy"]["document_hash"] == hashlib.sha256(card).hexdigest()
        assert client.get("/.well-known/aics-card.json").headers["x-aics-card-leaf"] == str(logged["policy"]["leaf_index"])

    def test_the_owner_writes_tasks_awards_quotes_and_completions(self, sdk, client, owner):
        boss = self.owner_client(sdk, client, owner.key)
        alice = new_client(sdk, client)
        alice.register("alice")
        task = boss.task("Translate the banner", "Into Greek, please.", reward=10)
        assert task["entry"]["type"] == "sup.task" and task["entry"]["actor_kid"] == owner.kid
        work = alice.post("tasks", "The translation", "Here it is.")
        assert boss.award(task["index"], work["index"], alice.identity["kid"], 10)["entry"]["payload"]["amount"] == 10
        request_post = alice.post("owner-actions", "Please review", "A human review of my notes.")
        quoted = boss.quote(request_post["index"], 4)
        completed = boss.complete(request_post["index"], quoted["index"], 4, "Reviewed: they hold up.")
        assert completed["entry"]["payload"]["action"] == "complete"
        assert client.get(f"/v2/sup/accounts/alice").json()["balance"] == 10

    def test_the_command_line_signs_with_the_key_file(self, sdk, client, owner, tmp_path, monkeypatch, capsys):
        from cryptography.hazmat.primitives import serialization

        pem = owner.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
        key_file = tmp_path / "owner.pem"
        key_file.write_bytes(pem)
        report = tmp_path / "report.txt"
        report.write_text("A planned stop.", encoding="utf-8")
        inner = route_to_testclient(client, sdk)
        monkeypatch.setattr(sdk, "_default_transport", lambda m, u, h, b, timeout: inner(m, u, h, b))
        base = ["owner", "--key", str(key_file), "--base-url", "http://testserver",
                "--log-vkey", client.app.state.db.server_vkey]
        assert sdk.main([*base, "freeze", "--reason", "maintenance", "--report-file", str(report)]) == 0
        assert json.loads(capsys.readouterr().out)["entry"]["type"] == "freeze"
        assert sdk.main([*base, "state"]) == 0 and json.loads(capsys.readouterr().out)["state"] == "frozen"
        assert sdk.main([*base, "reopen", "--report-file", str(report)]) == 0
        capsys.readouterr()
        assert sdk.main([*base, "reopen", "--report-file", str(report)]) == 1  # not frozen: refused, exit 1
        assert sdk.load_owner_key(str(key_file)).public_key().public_bytes_raw() == owner.public.public_bytes_raw()
        seed_file = tmp_path / "owner.hex"
        seed_file.write_text(owner.key.private_bytes_raw().hex())
        assert sdk.load_owner_key(str(seed_file)).public_key().public_bytes_raw() == owner.public.public_bytes_raw()

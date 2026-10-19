"""Authentication: the AICS-1 section 12.1 binding, RFC 9421 signed requests, replay and sequence, owner login.

DESIGN.md section 4.2 item 1 and section 4.3; DECISIONS.md #1 (no tokens) and #3
(owner login).  ``POST /v2/entries`` answers three ways (AICS-1 section 10.2):
traffic that is no envelope submission is rejected with no leaf; a well-formed
envelope that does not authenticate is a refusal leaf whose attempt fields are
null; an authenticated attempt that fails a rule (stale, replayed, out of
sequence, any acceptance rule) is a refusal leaf naming its ``(kid, nonce,
expires)``.  Signed reads keep the plain error answers and write no leaf.
"""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from aics_identity import canonicalize, envelope, keys
from aics_identity import http_signatures as hs
from aics_server.app import create_app
from aics_server.db import SanctuaryDB

from conftest import DELETE, U, Agent, Owner, Signer, fetch_leaf, make_envelope, post_body, post_q, signed_request
from conftest import ENTRIES, entry_of, leaf_index, reason, refusal_q, submit_entry

POST_BODY = post_body("Signed hello", "Every write is signed.")
POST_FIELDS = {"body": U(POST_BODY)}


def post_payload(agent: Agent, body: bytes = POST_BODY) -> dict:
    return {"type": "post", "origin": agent.origin, **post_q(body)}


def send_post(client, agent: Agent, **kwargs):
    fields = kwargs.pop("fields", POST_FIELDS)
    payload = kwargs.pop("payload", None) or post_payload(agent)
    return signed_request(client, agent.signer, "POST", kwargs.pop("path", ENTRIES), fields=fields, payload=payload, **kwargs)


def tree_size(client) -> int:
    return client.get("/v2/tlog/checkpoint").json()["tree_size"]


def assert_unauthenticated(client, response, code: str, env: dict, before: int) -> None:
    """A refusal leaf with null attempt fields (AICS-1 section 10.2), exactly one new leaf, nothing accepted."""
    assert response.status_code == 401, response.text
    q = refusal_q(response)
    assert q["reason_code"] == code
    assert q["envelope_hash"] == envelope.envelope_hash(env) and q["request_hash"] is None
    assert (q["attempt_kid"], q["attempt_nonce"], q["attempt_expires"]) == (None, None, None)
    assert tree_size(client) == before + 1
    assert client.get("/v2/agora/posts").json()["count"] == 0


def assert_authenticated(response, code: str, env: dict, status: int) -> dict:
    """A refusal leaf naming the authenticated attempt's tuple and its envelope by hexH(J(E))."""
    assert response.status_code == status, response.text
    q = refusal_q(response)
    assert q["reason_code"] == code
    assert q["envelope_hash"] == envelope.envelope_hash(env) and q["request_hash"] is None
    p = env["protected"]
    assert (q["attempt_kid"], q["attempt_nonce"], q["attempt_expires"]) == (p["kid"], p["nonce"], p["expires"])
    return q


# ---------------------------------------------------------------------------
# POST /v2/entries: the RFC 9421 server profile
# ---------------------------------------------------------------------------


class TestRequestSignatureProfile:
    def test_unsigned_write_is_refused_without_a_leaf(self, client, make_agent):
        alice = make_agent("alice")
        env = make_envelope(post_payload(alice), alice.signer)
        before = tree_size(client)
        response = client.post(ENTRIES, json={"envelope": env, "body": POST_FIELDS["body"]})
        assert response.status_code == 401
        assert reason(response) == "signature_required"
        assert tree_size(client) == before  # a valid envelope alone does not excuse a missing request signature

    def test_bearer_header_is_not_a_credential(self, client, make_agent):
        make_agent("alice")
        response = client.get("/v2/agents/me", headers={"Authorization": "Bearer aics_live_anything"})
        assert response.status_code == 401
        assert reason(response) == "signature_required"

    def test_signed_write_is_accepted(self, client, make_agent):
        alice = make_agent("alice")
        response, env, _, _ = send_post(client, alice)
        assert response.status_code == 202, response.text
        assert set(response.json()) == {"entry", "receipt_note"}
        entry = entry_of(response)
        assert entry["actor_kid"] == alice.kid
        assert entry["payload"]["envelope"] == env
        assert fetch_leaf(client, leaf_index(response))["leaf_data"] == entry

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"nonce": None},
            {"expires": None},
            {"tag": None},
            {"tag": "other"},
            {"components": ("@method", "@path", "content-digest")},
            {"components": ("@method", "@authority", "@path", "content-digest", "content-type")},
        ],
    )
    def test_a_request_signature_off_the_profile_does_not_authenticate(self, client, make_agent, kwargs):
        alice = make_agent("alice")
        before = tree_size(client)
        response, env, _, _ = send_post(client, alice, **kwargs)
        assert_unauthenticated(client, response, "bad_signature", env, before)

    @pytest.mark.parametrize(
        ("kwargs", "error"),
        [
            ({"nonce": None}, "malformed_signature"),
            ({"expires": None}, "malformed_signature"),
            ({"tag": None}, "malformed_signature"),
            ({"tag": "other"}, "bad_signature"),
            ({"components": ("@method", "@path", "content-digest")}, "bad_signature"),
        ],
    )
    def test_signed_reads_keep_the_profile_without_a_leaf(self, client, make_agent, kwargs, error):
        alice = make_agent("alice")
        before = tree_size(client)
        response = alice.get("/v2/agents/me", **kwargs)
        assert response.status_code == 401, response.text
        assert reason(response) == error
        assert tree_size(client) == before

    def test_content_digest_must_be_covered_even_without_a_body(self, client, make_agent):
        alice = make_agent("alice")
        headers = hs.sign_request(
            "GET",
            "http://testserver/v2/agents/me",
            {},
            b"",
            key=alice.signer.key,
            keyid=alice.kid,
            tag=hs.AICS_TAG,
            components=("@method", "@authority", "@path"),
        )
        response = client.get("/v2/agents/me", headers=headers)
        assert response.status_code == 401
        assert "content-digest" in response.json()["detail"]["message"].lower()

    def test_created_older_than_300_seconds_is_an_authenticated_refusal(self, client, make_agent):
        alice = make_agent("alice")
        created = int(time.time()) - 301
        response, env, raw, headers = send_post(client, alice, created=created, expires=created + 300)
        assert_authenticated(response, "expired", env, 401)  # AICS-1 section 4.3: created >= t - 300
        size = tree_size(client)
        again = client.post(ENTRIES, content=raw, headers=headers)  # the same stale request: the same refusal
        assert again.status_code == 401 and again.json() == response.json() and tree_size(client) == size

    def test_created_in_the_future_is_an_authenticated_refusal(self, client, make_agent):
        alice = make_agent("alice")
        created = int(time.time()) + 120
        response, env, _, _ = send_post(client, alice, created=created, expires=created + 60)
        assert_authenticated(response, "future", env, 401)  # created <= t + 30

    def test_thirty_seconds_ahead_is_accepted(self, client, make_agent):
        alice = make_agent("alice")
        created = int(time.time()) + 29
        response, _, _, _ = send_post(client, alice, created=created, expires=created + 300)
        assert response.status_code == 202, response.text

    @pytest.mark.parametrize("lifetime", [0, 301])
    def test_a_window_outside_created_to_300_seconds_is_an_authenticated_refusal(self, client, make_agent, lifetime):
        # AICS-1 section 4.3 lists created < expires <= created + 300 among the REQUIRED validity checks, and both
        # signatures verify: a decision on an authenticated submission, so a refusal leaf naming its tuple (10.2).
        alice = make_agent("alice")
        created = int(time.time())
        before = tree_size(client)
        response, env, raw, headers = send_post(client, alice, created=created, expires=created + lifetime)
        assert_authenticated(response, "malformed", env, 422)
        assert tree_size(client) == before + 1 and client.get("/v2/agora/posts").json()["count"] == 0
        assert "validity window" in response.headers["x-aics-hint"]
        again = client.post(ENTRIES, content=raw, headers=headers)  # the same request: its first refusal, no leaf
        assert again.status_code == 422 and again.json() == response.json() and tree_size(client) == before + 1

    def test_a_window_of_exactly_300_seconds_is_accepted(self, client, make_agent):
        alice = make_agent("alice")
        created = int(time.time())
        response, _, _, _ = send_post(client, alice, created=created, expires=created + 300)
        assert response.status_code == 202, response.text

    def test_a_bad_window_under_a_bad_signature_does_not_authenticate(self, client, make_agent):
        # The window is looked at only once both signatures verified: before that the attempt has no identity.
        alice, mallory = make_agent("alice"), make_agent("mallory")
        created = int(time.time())
        before = tree_size(client)
        response, env, _, _ = send_post(
            client, mallory, created=created, expires=created + 301, keyid=alice.kid, envelope_overrides={"kid": alice.kid}
        )
        assert_unauthenticated(client, response, "bad_signature", env, before)

    def test_expiry_is_never_extended(self, client, make_agent):
        # AICS-1 section 4.3: t < expires; the 30-second allowance is for future creation only.
        alice = make_agent("alice")
        created = int(time.time()) - 100
        response, env, _, _ = send_post(client, alice, created=created, expires=created + 99)
        assert_authenticated(response, "expired", env, 401)

    def test_body_changed_after_signing_is_rejected_before_parsing(self, client, make_agent):
        alice = make_agent("alice")
        before = tree_size(client)
        response, _, _, _ = send_post(
            client, alice, tamper_body=lambda raw: raw.replace(POST_FIELDS["body"].encode(), U(POST_BODY[::-1]).encode())
        )
        assert response.status_code == 400
        assert reason(response) == "digest_mismatch" and "Content-Digest" in response.json()["detail"]["message"]
        assert tree_size(client) == before and client.get("/v2/agora/posts").json()["count"] == 0

    def test_a_reserialised_body_still_verifies(self, client, make_agent):
        # The digest is over the bytes as received (AICS-1 section 12.1), whatever their JSON layout.
        alice = make_agent("alice")
        env = make_envelope(post_payload(alice), alice.signer)
        raw = json.dumps({"body": POST_FIELDS["body"], "envelope": env}, indent=3).encode()
        p = env["protected"]
        response, _, _, _ = signed_request(
            client, alice.signer, "POST", ENTRIES, body_override=raw,
            created=p["created"], expires=p["expires"], nonce=p["nonce"],
        )
        assert response.status_code == 202, response.text

    def test_signature_for_another_path_does_not_authenticate(self, client, make_agent):
        alice = make_agent("alice")
        before = tree_size(client)
        response, env, _, _ = send_post(client, alice, path="/v2/other", send_path=ENTRIES)
        assert_unauthenticated(client, response, "bad_signature", env, before)

    def test_unknown_key_is_an_unauthenticated_refusal(self, client, origin, make_agent):
        make_agent("alice")
        stranger = Agent(client, origin)
        before = tree_size(client)
        response, env, _, _ = send_post(client, stranger)
        assert_unauthenticated(client, response, "unknown_key", env, before)

    def test_signature_by_another_key_under_a_known_keyid_does_not_authenticate(self, client, make_agent):
        alice = make_agent("alice")
        mallory = Signer()
        before = tree_size(client)
        response, env, _, _ = signed_request(
            client,
            mallory,
            "POST",
            ENTRIES,
            fields=POST_FIELDS,
            payload=post_payload(alice),
            keyid=alice.kid,
            envelope_overrides={"kid": alice.kid},
        )
        assert_unauthenticated(client, response, "bad_signature", env, before)

    def test_unauthenticated_refusals_are_bounded_and_not_repeated(self, client, origin, make_agent, monkeypatch):
        make_agent("alice")
        db = client.app.state.db
        stranger = Agent(client, origin)
        response, _, raw, headers = send_post(client, stranger)
        assert response.status_code == 401
        size = tree_size(client)
        again = client.post(ENTRIES, content=raw, headers=headers)  # the same envelope: its first leaf answers
        assert again.json() == response.json() and tree_size(client) == size
        # Their own small published window (limits.unauthenticated, service-wide) bounds them: past it the same
        # answer with no leaf (AICS-1 section 10.2: unauthenticated traffic may be rejected before logging).
        window = db._unauthenticated_window
        spec = db.limits["unauthenticated"]
        assert (window.count, window.interval) == (spec["count"], spec["interval_seconds"])
        assert client.get("/v2/limits").json()["limits"]["unauthenticated"] == spec
        monkeypatch.setattr(window, "count", len(window.times))
        late, _, _, _ = send_post(client, Agent(client, origin))
        assert late.status_code == 401 and reason(late) == "unknown_key" and tree_size(client) == size
        assert late.json()["detail"]["refusal"] is None and "not logged" in late.json()["detail"]["message"]
        assert int(late.headers["retry-after"]) > 0

    def test_allowed_hosts_bind_signatures_to_this_service(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AICS_ALLOWED_HOSTS", "api.wesupport-ai.com")
        strict = TestClient(create_app(db_path=tmp_path / "strict.db"))
        agent = Agent(strict, strict.get("/v2/tlog/checkpoint").json()["origin"])
        response = agent.claim("alice")  # signed for http://testserver
        assert response.status_code == 421
        assert reason(response) == "wrong_authority"
        monkeypatch.setenv("AICS_ALLOWED_HOSTS", "api.wesupport-ai.com, testserver")
        lenient = TestClient(create_app(db_path=tmp_path / "lenient.db"))
        assert Agent(lenient, lenient.get("/v2/tlog/checkpoint").json()["origin"]).claim("alice").status_code == 202

    def test_query_string_must_be_covered_on_a_signed_read(self, client, make_agent):
        alice = make_agent("alice")
        uncovered = alice.get("/v2/inbox?unread_only=true")
        assert uncovered.status_code == 401
        covered = alice.get("/v2/inbox?unread_only=true", components=hs.AICS_COMPONENTS + ("@query",))
        assert covered.status_code == 200, covered.text

    def test_a_native_write_takes_no_query(self, client, make_agent):
        alice = make_agent("alice")
        before = tree_size(client)
        response, _, _, _ = send_post(client, alice, path=ENTRIES + "?x=1")
        assert response.status_code == 400 and "no query" in response.json()["detail"]["message"]
        assert tree_size(client) == before


# ---------------------------------------------------------------------------
# POST /v2/entries: the request object and the envelope
# ---------------------------------------------------------------------------


class TestEnvelopeBinding:
    def signed_raw(self, client, alice, raw: bytes, env: dict, **headers_extra):
        p = env["protected"]
        headers = hs.sign_request(
            "POST", "http://testserver" + ENTRIES, {"Content-Type": "application/json", **headers_extra}, raw,
            key=alice.signer.key, keyid=alice.kid, tag=hs.AICS_TAG, components=hs.AICS_COMPONENTS,
            created=p["created"], expires=p["expires"], nonce=p["nonce"],
        )
        return client.post(ENTRIES, content=raw, headers=headers)

    def test_the_request_is_exactly_envelope_and_body(self, client, make_agent):
        alice = make_agent("alice")
        env = make_envelope(post_payload(alice), alice.signer)
        before = tree_size(client)
        for obj in ({"body": POST_FIELDS["body"]}, {"envelope": env}, {"envelope": env, "body": 7},
                    {"envelope": env, "body": POST_FIELDS["body"], "note": "x"}):
            response = self.signed_raw(client, alice, json.dumps(obj).encode(), env)
            assert response.status_code == 400 and reason(response) == "malformed", response.text
        assert tree_size(client) == before

    @pytest.mark.parametrize("field", ["nonce", "created", "expires"])
    def test_envelope_and_request_signature_are_one_attempt(self, client, make_agent, field):
        alice = make_agent("alice")
        now = int(time.time())
        override = {
            "nonce": {"nonce": envelope.new_nonce()},
            "created": {"created": now - 1, "expires": now + 299},
            "expires": {"expires": now + 299},
        }[field]
        before = tree_size(client)
        response, env, _, _ = send_post(client, alice, created=now, envelope_overrides=override)
        assert_unauthenticated(client, response, "bad_signature", env, before)

    def test_envelope_must_be_signed_by_the_request_key(self, client, make_agent):
        alice = make_agent("alice")
        mallory = Signer()
        before = tree_size(client)
        response, env, _, _ = send_post(client, alice, envelope_signer=mallory, envelope_overrides={"kid": alice.kid})
        assert_unauthenticated(client, response, "bad_signature", env, before)

    def test_the_policy_keys_types_are_never_submitted(self, client, make_agent):
        alice = make_agent("alice")
        payload = {"type": "tombstone", "origin": alice.origin, "target_index": 0, "reason_code": "order",
                   "evidence_hash": None, "receipt_hash": None}
        response, env, _, _ = send_post(client, alice, payload=payload, fields={"body": None})
        assert_authenticated(response, "unknown_key", env, 403)

    def test_envelope_commits_to_the_body(self, client, make_agent):
        alice = make_agent("alice")
        payload = post_payload(alice)  # body_hash and size of POST_BODY
        other = post_body("Changed title", "Every write is signed.")
        response, env, _, _ = send_post(client, alice, fields={"body": U(other)}, payload=payload)
        # Authenticated: the mismatch is a refusal leaf naming the envelope by hexH(J(E)) and the authenticated
        # (kid, nonce, expires), which backs the replay record (AICS-1 sections 4.3 and 10.2); request_hash is null.
        assert_authenticated(response, "digest_mismatch", env, 422)
        assert "body_hash" in response.headers["x-aics-hint"]

    def test_a_body_that_is_not_u64_is_malformed(self, client, make_agent):
        alice = make_agent("alice")
        response, env, _, _ = send_post(client, alice, fields={"body": U(POST_BODY) + "="})
        assert_authenticated(response, "malformed", env, 400)

    def test_a_body_for_a_type_without_one_is_malformed(self, client, make_agent):
        alice = make_agent("alice")
        payload = alice.grant_payload("*", 3)
        response, env, _, _ = send_post(client, alice, payload=payload, fields={"body": U(b"stray")})
        assert_authenticated(response, "malformed", env, 400)

    def test_envelope_origin_must_be_this_log(self, client, make_agent):
        alice = make_agent("alice")
        payload = dict(post_payload(alice), origin="example.org/other-log")
        before = tree_size(client)
        response, _, _, _ = send_post(client, alice, payload=payload)
        assert response.status_code == 400 and tree_size(client) == before

    @pytest.mark.parametrize("where", ["envelope", "protected"])
    def test_envelope_cannot_carry_extra_members(self, client, make_agent, where):
        """Anything in the envelope lands on the leaf, so no member beyond the defined ones is accepted."""
        alice = make_agent("alice")
        env = make_envelope(post_payload(alice), alice.signer)
        target = env if where == "envelope" else env["protected"]
        target["note"] = "free text riding on the leaf"
        response = self.signed_raw(client, alice, json.dumps(dict(POST_FIELDS, envelope=env)).encode(), env)
        assert response.status_code == 400, response.text
        assert reason(response) == "malformed"
        assert client.get("/v2/agora/posts").json()["count"] == 0

    @pytest.mark.parametrize(
        "nonce",
        [
            "a nonce with spaces in it ok",
            "x" * 44,
            "short",
            "has.dots.in.it.0123456789",
            # The review's probe: 34 characters of chosen text, which would sit on every leaf the request writes.
            "I_can_write_any_words_here_forever",
            keys.b64u_encode(bytes(32)),  # 43 characters: 32 bytes, no longer accepted
            "AAAAAAAAAAAAAAAAAAAAAB",  # 22 characters, but not canonical (stray bits)
        ],
    )
    def test_nonce_must_be_random_base64url(self, client, make_agent, nonce):
        alice = make_agent("alice")
        before = tree_size(client)
        response, _, _, _ = send_post(client, alice, nonce=nonce)
        assert response.status_code == 400
        assert reason(response) == "malformed"
        assert tree_size(client) == before  # no leaf can carry it, not even a refusal

    def test_envelope_without_chain_fields_is_refused(self, client, make_agent):
        alice = make_agent("alice")
        env = make_envelope(post_payload(alice), alice.signer, overrides={"seq": DELETE, "prev": DELETE})
        response = self.signed_raw(client, alice, json.dumps(dict(POST_FIELDS, envelope=env)).encode(), env)
        assert response.status_code == 400
        assert reason(response) == "malformed"

    def test_identity_coding_and_a_known_length(self, client, make_agent):
        alice = make_agent("alice")
        env = make_envelope(post_payload(alice), alice.signer)
        raw = canonicalize({"envelope": env, "body": POST_FIELDS["body"]})
        assert self.signed_raw(client, alice, raw, env, **{"Content-Encoding": "gzip"}).status_code == 415

        def chunks():
            yield raw

        p = env["protected"]
        headers = hs.sign_request(
            "POST", "http://testserver" + ENTRIES, {"Content-Type": "application/json"}, raw,
            key=alice.signer.key, keyid=alice.kid, created=p["created"], expires=p["expires"], nonce=p["nonce"],
        )
        chunked = client.post(ENTRIES, content=chunks(), headers=headers)
        assert chunked.status_code == 411, chunked.text
        assert client.post(ENTRIES, content=b"{" * (300 * 1024)).status_code == 413
        assert self.signed_raw(client, alice, raw, env).status_code == 202


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


class TestReplay:
    def test_replayed_write_is_refused_with_a_leaf_naming_the_original(self, client, make_agent):
        alice = make_agent("alice")
        response, env, raw, headers = send_post(client, alice)
        assert response.status_code == 202
        original = leaf_index(response)

        replay = client.post(ENTRIES, content=raw, headers=headers)
        q = assert_authenticated(replay, "replay", env, 409)
        assert q["conflict_index"] == original
        # Refusing an already receipted envelope names that receipt (AICS-1 section 10.2).
        import hashlib

        assert q["receipt_hash"] == hashlib.sha256(keys.b64u_decode(response.json()["receipt_note"])).hexdigest()
        size = tree_size(client)

        # More copies get the same answer but add no leaf (no log amplification).
        again = client.post(ENTRIES, content=raw, headers=headers)
        assert again.status_code == 409 and again.json() == replay.json()
        assert tree_size(client) == size
        assert client.get("/v2/agora/posts").json()["count"] == 1

    def test_replay_is_refused_after_a_restart(self, client, make_agent, db_path, owner):
        alice = make_agent("alice")
        response, _, raw, headers = send_post(client, alice)
        assert response.status_code == 202
        restarted = TestClient(create_app(db_path=db_path, owner_public_key=owner.public_key_b64u))
        replay = restarted.post(ENTRIES, content=raw, headers=headers)
        assert replay.status_code == 409
        assert reason(replay) == "replay"

    def test_replay_records_are_rebuilt_from_the_leaves(self, client, make_agent, db_path, owner):
        alice = make_agent("alice")
        response, _, raw, headers = send_post(client, alice)
        assert response.status_code == 202
        db = client.app.state.db
        with db._transaction():
            db._conn.execute("DELETE FROM nonces")
        restarted = TestClient(create_app(db_path=db_path, owner_public_key=owner.public_key_b64u))
        replay = restarted.post(ENTRIES, content=raw, headers=headers)
        assert replay.status_code == 409
        assert refusal_q(replay)["conflict_index"] == leaf_index(response)

    def test_replayed_read_is_refused_without_a_leaf(self, client, make_agent):
        alice = make_agent("alice")
        _, _, _, headers = signed_request(client, alice.signer, "GET", "/v2/agents/me", body_override=b"")
        size = tree_size(client)
        replay = client.get("/v2/agents/me", headers=headers)
        assert replay.status_code == 409
        assert replay.json()["detail"]["refusal"] is None
        assert tree_size(client) == size

    def test_a_refused_write_does_not_advance_the_chain(self, client, make_agent):
        alice = make_agent("alice")
        response, _, raw, headers = send_post(client, alice)
        assert response.status_code == 202
        assert client.post(ENTRIES, content=raw, headers=headers).status_code == 409
        # The next envelope continues from the accepted post, not from the refusal.
        assert alice.post(title="After a refusal").status_code == 202


# ---------------------------------------------------------------------------
# the per-key envelope chain
# ---------------------------------------------------------------------------


class TestSequence:
    def test_gap_is_refused_naming_the_last_accepted_envelope(self, client, make_agent):
        alice = make_agent("alice")
        last = alice.head_index
        chain = {"seq": 5, "prev": envelope.envelope_hash(alice.signer.last_envelope)}
        response, env, _, _ = send_post(client, alice, chain=chain)
        q = assert_authenticated(response, "sequence", env, 409)
        assert q["conflict_index"] == last

    def test_repeated_seq_is_refused(self, client, make_agent):
        alice = make_agent("alice")
        response, _, _, _ = send_post(client, alice, chain={"seq": 0, "prev": None})
        assert response.status_code == 409
        assert reason(response) == "sequence"

    def test_wrong_prev_is_refused(self, client, make_agent):
        alice = make_agent("alice")
        response, _, _, _ = send_post(client, alice, chain={"seq": 1, "prev": "0" * 64})
        assert response.status_code == 409
        assert reason(response) == "sequence"

    def test_a_senders_leaves_form_an_unbroken_chain(self, client, make_agent):
        alice = make_agent("alice")
        indices = [alice.head_index]
        for title in ("first post", "second post"):
            response = alice.post(title=title)
            assert response.status_code == 202
            indices.append(leaf_index(response))
        response = alice.poll(title="Pick one please", text="A tiny poll.", options=["a", "b"])
        assert response.status_code == 202, response.text
        indices.append(leaf_index(response))
        envelopes = [fetch_leaf(client, i)["leaf_data"]["payload"]["envelope"] for i in indices]
        assert envelope.chain_breaks(envelopes) == []
        assert [e["protected"]["seq"] for e in envelopes] == [0, 1, 2, 3]

    def test_grants_messages_and_capsules_are_links_in_the_chain(self, client, make_agent):
        alice = make_agent("alice")
        bob = make_agent("bob")
        assert alice.grant("*", 3).status_code == 202
        assert client.get(f"/v2/keys/{alice.kid}").json()["envelope_chain"]["last_seq"] == 1
        assert bob.send_dm(bob.lookup("alice"), "hello").status_code == 202
        assert alice.put_capsule("state").status_code == 202
        assert client.get(f"/v2/keys/{alice.kid}").json()["envelope_chain"]["last_seq"] == 2
        assert client.get(f"/v2/keys/{bob.kid}").json()["envelope_chain"]["last_seq"] == 1
        assert alice.post().status_code == 202


# ---------------------------------------------------------------------------
# signed reads
# ---------------------------------------------------------------------------


class TestSignedReads:
    def test_reading_your_own_data_needs_your_signature(self, client, make_agent):
        alice = make_agent("alice")
        assert client.get("/v2/agents/me").status_code == 401
        me = alice.get("/v2/agents/me")
        assert me.status_code == 200
        assert me.json()["agent"]["name"] == "alice"
        assert me.json()["agent"]["kid"] == alice.kid

    def test_capsules_follow_the_signing_key(self, client, make_agent):
        alice = make_agent("alice")
        bob = make_agent("bob")
        put = alice.put_capsule("state", "alice's state")
        assert put.status_code == 202, put.text
        slot = entry_of(put)["payload"]["key_hash"]
        assert alice.get(f"/v2/capsules/{slot}").status_code == 200
        assert bob.get(f"/v2/capsules/{slot}").status_code == 404
        assert bob.get("/v2/capsules").json()["count"] == 0


# ---------------------------------------------------------------------------
# the owner key (decision 3): native writes and the owner login
# ---------------------------------------------------------------------------


class TestOwnerLogin:
    def make_action(self, agent: Agent) -> dict:
        response = agent.request_action("Renew the TLS certificate", "The certificate expires soon; renew it at the provider.")
        assert response.status_code == 202, response.text
        return agent.client.get(f"/v2/agora/human-actions/{leaf_index(response)}").json()["action"]

    def test_administration_refuses_unsigned_requests(self, client, make_agent):
        response = client.post("/v2/admin/tombstones", json={"target_index": 0, "reason_code": "order"})
        assert response.status_code == 401

    def test_owner_types_refuse_agent_keys(self, client, make_agent, owner: Owner):
        alice = make_agent("alice")
        action = self.make_action(alice)
        payload = owner.owner_action_payload(action, "quote", 15)
        response, env, _, _ = submit_entry(client, alice.signer, payload)
        assert_authenticated(response, "unknown_key", env, 403)
        assert "owner key" in response.headers["x-aics-hint"]

    def test_administration_refuses_agent_keys(self, client, make_agent):
        alice = make_agent("alice")
        response, _, _, _ = signed_request(
            client, alice.signer, "POST", "/v2/admin/tombstones", fields={"target_index": 0, "reason_code": "order"}
        )
        assert response.status_code == 403
        assert reason(response) == "owner_only"

    def test_owner_signed_quote_is_a_leaf_with_amounts_and_hashes_only(self, client, make_agent, owner: Owner):
        action = self.make_action(make_agent("alice"))
        response = owner.quote(action, 15)
        assert response.status_code == 202, response.text
        entry = entry_of(response)
        assert entry["type"] == "report" and entry["actor_kid"] == owner.kid
        assert entry["payload"]["envelope"]["protected"]["kid"] == owner.kid
        assert entry["payload"]["kind"] == "owner_action" and entry["payload"]["amount"] == 15
        assert entry["payload"]["request_hash"] == action["request_hash"]
        for absent in ("human_alias", "payout_address", "note", "price_usd", "estimated_minutes", "content_sha256"):
            assert absent not in entry["payload"]

    def test_owner_quote_names_its_request_by_entry_hash(self, client, make_agent, owner: Owner):
        alice = make_agent("alice")
        action = self.make_action(alice)
        claim = {"request_hash": fetch_leaf(client, alice.head_index)["leaf_hash_hex"]}  # a claim is no request
        response = owner.quote({**action, **claim}, 15)
        assert response.status_code == 422
        assert refusal_q(response)["reason_code"] == "bad_reference"

    def test_owner_replay_is_refused(self, client, make_agent, owner: Owner):
        action = self.make_action(make_agent("alice"))
        response, _, raw, headers = submit_entry(client, owner, owner.owner_action_payload(action, "quote", 15))
        assert response.status_code == 202
        replay = client.post(ENTRIES, content=raw, headers=headers)
        assert replay.status_code == 409
        assert reason(replay) == "replay"

    def test_owner_login_off_when_no_key_is_configured(self, tmp_path, monkeypatch, origin):
        monkeypatch.delenv("AICS_OWNER_PUBKEY", raising=False)
        bare = TestClient(create_app(db_path=tmp_path / "bare.db"))
        assert bare.get("/v2/owner").status_code == 404
        someone = Owner(bare, bare.get("/v2/tlog/checkpoint").json()["origin"])
        ghost = {"request_hash": "0" * 64}
        response = someone.quote(ghost)
        # No owner key: this key is nobody's, so its envelope does not authenticate (a refusal with no attempt).
        assert response.status_code == 401
        assert reason(response) == "unknown_key" and refusal_q(response)["attempt_kid"] is None
        for path, fields in (("/v2/admin/policy", {"kind": "change", "document": "x", "not_before": 0}),
                             ("/v2/admin/tombstones", {"target_index": 0, "reason_code": "order"})):
            assert someone.admin(path, fields).status_code == 503

    @pytest.mark.parametrize("form", ["ssh", "base64", "did"])
    def test_owner_key_from_the_environment(self, tmp_path, monkeypatch, form):
        from aics_identity import sshsig

        owner = Signer()
        text = {
            "ssh": sshsig.format_openssh_public_key(owner.public, "owner@laptop"),
            "base64": keys.b64u_encode(keys.public_key_bytes(owner.public)),
            "did": owner.did,
        }[form]
        monkeypatch.setenv("AICS_OWNER_PUBKEY", text)
        configured = TestClient(create_app(db_path=tmp_path / f"{form}.db"))
        assert configured.get("/v2/owner").json() == {
            "owner_kid": owner.kid,
            "owner_public_key_b64u": owner.public_key_b64u,
        }

    def test_owner_dependency_is_exposed_for_later_owner_operations(self, client):
        assert callable(client.app.state.auth.owner)


# ---------------------------------------------------------------------------
# no tokens, no server-held keys, no address records
# ---------------------------------------------------------------------------


class TestNothingTheServerMustNotHold:
    def test_no_token_or_key_material_columns(self, client):
        db = client.app.state.db
        tables = [r[0] for r in db._conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()]
        columns = {
            (table, row[1])
            for table in tables
            for row in db._conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        names = {c for _, c in columns}
        assert not any("token" in c for c in names), columns
        assert not any("private" in c or c.endswith("_seed") for c in names)
        assert not any(c in ("ip", "ip_address", "client_ip", "remote_addr", "user_agent") for c in names)
        assert not hasattr(SanctuaryDB, "authenticate_token")

    def test_importing_the_app_module_opens_no_database(self):
        import aics_server.app as app_module

        # The module builds the app lazily (uvicorn aics_server.app:app); nothing in the
        # test session has asked for it, so no default database was opened.
        assert "app" not in vars(app_module)
        assert callable(app_module.create_app)

    def test_database_of_the_old_layout_is_refused(self, tmp_path):
        import sqlite3

        path = tmp_path / "old.db"
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE agents (agent_id TEXT PRIMARY KEY, token_hash TEXT)")
        conn.commit()
        conn.close()
        with pytest.raises(RuntimeError, match="starts fresh"):
            SanctuaryDB(db_path=path)

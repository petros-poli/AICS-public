"""The last server items before the production genesis (decisions 26 and 29 and the open follow-ups).

* a contribution claim (AICS-1 section 20.6) whose validity window fails after its RFC 9421 signature verified is a
  logged refusal naming its tuple (sections 4.3 and 10.2), as ``POST /v2/entries`` is;
* an owner-login administration write that fails validation after the owner authenticated is a refusal leaf whose
  ``attempt_kid`` is the owner kid, with its registered code; an unauthenticated one stays an HTTP error;
* decision 26: a ``(kid, nonce)`` that any leaf carries is refused for good, long after its ``expires``.
"""

from __future__ import annotations

import hashlib
import json
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from aics_identity import canonicalize, envelope
from aics_server import auth as auth_module
from aics_server.app import create_app

from conftest import (
    TEST_LIMITS,
    Signer,
    base_tx,
    https,
    leaf_index,
    post_body,
    post_q,
    reason,
    refusal_q,
    signed_request,
    submit_entry,
)

DAY = 86400


def tree_size(client) -> int:
    return client.get("/v2/tlog/checkpoint").json()["tree_size"]


def signature_params(headers: dict) -> dict:
    text = headers["Signature-Input"]
    return {k: v.strip('"') for k, v in (part.split("=", 1) for part in text.split(";")[1:])}


def detail_refusal(response) -> dict:
    """The refusal leaf payload a service or administration answer names in its error ``detail``."""
    entry = response.json()["detail"]["refusal"]["entry"]
    assert entry["type"] == "refusal", entry
    return entry["payload"]


def nonce_row(client, kid: str, nonce: str):
    return client.app.state.db._conn.execute("SELECT * FROM nonces WHERE kid = ? AND nonce = ?", (kid, nonce)).fetchone()


def at(monkeypatch, when: int) -> None:
    """The request clock of the binding (``t``) reads *when*."""
    monkeypatch.setattr(auth_module, "time", SimpleNamespace(time=lambda: when))


# ---------------------------------------------------------------------------
# a contribution claim outside its validity window, after its signature verified
# ---------------------------------------------------------------------------


class TestAClaimOutsideItsWindowIsALoggedRefusal:
    @pytest.mark.parametrize(
        ("shift", "lifetime", "code", "status"),
        [
            (-400, 300, "expired", 401),  # created more than 300 s before t
            (-200, 100, "expired", 401),  # t >= expires
            (120, 300, "future", 401),  # created more than 30 s after t
            (0, 301, "malformed", 422),  # not created < expires <= created + 300
            (0, 0, "malformed", 422),
        ],
        ids=["old", "past-expires", "future", "too-long", "empty"],
    )
    def test_the_refusal_names_the_signed_tuple(self, client, make_agent, chain, shift, lifetime, code, status):
        alice = make_agent("alice")
        intent = alice.intent("base-usdc", 1).json()
        created = int(time.time()) + shift
        size = tree_size(client)
        response = alice.claim_contribution(intent["intent_id"], base_tx(0xA1), created=created, expires=created + lifetime)
        assert response.status_code == status and reason(response) == code, response.text
        payload = detail_refusal(response)
        params = signature_params(alice.signer.last_request[3])
        assert payload["reason_code"] == code
        assert payload["attempt_kid"] == alice.kid and payload["attempt_nonce"] == params["nonce"]
        assert payload["attempt_expires"] == created + lifetime == int(params["expires"])
        # Named by the keyed hash of the content, never the plain hash: the content names a transaction.
        content = canonicalize({"intent_id": intent["intent_id"], "tx_hash": base_tx(0xA1)})
        assert payload["envelope_hash"] == payload["request_hash"] != hashlib.sha256(content).hexdigest()
        assert payload["request_hash"] == client.app.state.db.contribution_claim_hash(content)
        assert tree_size(client) == size + 1 and chain["base-usdc"].calls == []
        # The tuple is spent with the leaf that refused it (AICS-1 section 4.3).
        assert nonce_row(client, alice.kid, params["nonce"])["refusal_index"] == response.json()["detail"]["refusal"]["leaf_index"]

    def test_an_exact_resend_is_answered_with_its_refusal_and_adds_no_leaf(self, client, make_agent, chain):
        alice = make_agent("alice")
        intent = alice.intent("base-usdc", 1).json()
        old = int(time.time()) - 400
        first = alice.claim_contribution(intent["intent_id"], base_tx(0xA2), created=old, expires=old + 300)
        assert reason(first) == "expired"
        size = tree_size(client)
        method, path, body, headers = alice.signer.last_request
        again = https(client).request(method, path, content=body, headers=headers)
        assert reason(again) == "expired" and detail_refusal(again) == detail_refusal(first)
        assert tree_size(client) == size

    def test_a_claim_that_does_not_authenticate_stays_an_error(self, client, make_agent, chain):
        alice = make_agent("alice")
        intent = alice.intent("base-usdc", 1).json()
        old = int(time.time()) - 400
        size = tree_size(client)
        stranger = Signer()  # no name holds this key
        response, _, _, _ = signed_request(
            https(client), stranger, "POST", "/v2/sup/contributions", created=old, expires=old + 300,
            body_override=canonicalize({"intent_id": intent["intent_id"], "tx_hash": base_tx(0xA3)}),
        )
        assert response.status_code == 401 and reason(response) == "unknown_key"
        # A wrong signature by a known key: also no leaf, the window is never looked at.
        forged, _, _, _ = signed_request(
            https(client), alice.signer, "POST", "/v2/sup/contributions", created=old, expires=old + 300,
            body_override=canonicalize({"intent_id": intent["intent_id"], "tx_hash": base_tx(0xA3)}),
            tamper_body=lambda raw: raw.replace(b"0x", b"0X"),
        )
        assert forged.status_code in (400, 401) and "refusal" not in json.dumps(forged.json())
        assert tree_size(client) == size

    def test_an_intent_outside_its_window_is_never_a_leaf(self, client, make_agent, chain):
        alice = make_agent("alice")
        old = int(time.time()) - 400
        size = tree_size(client)
        response = alice.intent("base-usdc", 1, created=old, expires=old + 300)
        assert response.status_code == 401 and reason(response) == "expired"
        assert tree_size(client) == size

    def test_a_fresh_claim_is_still_credited(self, client, make_agent, chain):
        alice = make_agent("alice")
        intent = alice.intent("base-usdc", 2).json()
        tx = base_tx(0xA4)
        chain["base-usdc"].transfers[tx] = (intent["units"], intent["expires"] - 24 * 3600 + 1)
        assert alice.claim_contribution(intent["intent_id"], tx).status_code == 201
        assert alice.balance() == 2


# ---------------------------------------------------------------------------
# owner-login administration writes that fail after the owner authenticated
# ---------------------------------------------------------------------------


def owner_refused(client, owner, response, status: int, *, cause: str | None = None, code: str = "malformed") -> dict:
    """An owner request refused with a refusal leaf naming the owner's tuple and the request bytes."""
    assert response.status_code == status, response.text
    detail = response.json()["detail"]
    assert detail["error"] == code, detail
    if cause is not None:
        assert detail.get("cause") == cause, detail
    payload = detail_refusal(response)
    assert payload["reason_code"] == code
    method, path, body, headers = owner.last_request
    params = signature_params(headers)
    assert payload["attempt_kid"] == owner.kid == client.app.state.db.owner_kid
    assert payload["attempt_nonce"] == params["nonce"] and payload["attempt_expires"] == int(params["expires"])
    assert payload["envelope_hash"] == payload["request_hash"] == hashlib.sha256(body).hexdigest()
    return payload


class TestOwnerRequestsAreRefusedWithLeaves:
    @pytest.mark.parametrize(
        ("path", "fields", "status", "cause"),
        [
            # request fields that do not validate (the 422 of the request schema)
            ("/v2/admin/tombstones", {"target_index": -1, "reason_code": "order"}, 422, None),
            ("/v2/admin/suspensions", {"target_kid": "", "reason_code": "order"}, 422, None),
            ("/v2/admin/freeze", {"state": "melted", "reason_code": "maintenance", "report": "r"}, 422, None),
            ("/v2/admin/audits", {"document": "An audit.", "outcome_code": "lost"}, 422, None),
            ("/v2/admin/policy", {"kind": "charter", "document": "d", "not_before": 0}, 422, None),
            ("/v2/admin/notices/dsa_000000000000/close", {"outcome_code": "deleted"}, 422, None),
            ("/v2/admin/tombstones", {"target_index": 0, "reason_code": "order", "surplus": 1}, 422, None),
            # the operation's own rules (a closed code, a reference, the state)
            ("/v2/admin/tombstones", {"target_index": 0, "reason_code": "dislike"}, 400, None),
            ("/v2/admin/tombstones", {"target_index": 10**6, "reason_code": "order"}, 404, "not_found"),
            ("/v2/admin/suspensions", {"target_kid": "did:key:z6MkNobody", "reason_code": "order"}, 404, "not_found"),
            ("/v2/admin/freeze", {"state": "open", "reason_code": "resume", "report": "Back."}, 409, "conflict"),
            ("/v2/admin/freeze", {"state": "frozen", "reason_code": "resume", "report": "r"}, 400, None),
            ("/v2/admin/policy", {"kind": "change", "document": "Soon.", "not_before": 1}, 400, None),
            ("/v2/admin/notices/dsa_000000000000/close", {"outcome_code": "duplicate"}, 404, "not_found"),
        ],
    )
    def test_a_failed_owner_write_is_a_refusal_leaf(self, client, owner, path, fields, status, cause):
        size = tree_size(client)
        response = owner.admin(path, fields)
        owner_refused(client, owner, response, status, cause=cause)
        assert tree_size(client) == size + 1
        # The tuple is spent with that leaf: the same request again is a replay, answered without a leaf.
        method, sent_path, body, headers = owner.last_request
        again = client.request(method, sent_path, content=body, headers=headers)
        assert again.status_code == 409 and reason(again) == "replay" and tree_size(client) == size + 1

    def test_a_refusal_leaf_carries_no_request_text(self, client, owner):
        report = "A freeze report with words that must never reach a leaf."
        response = owner.admin("/v2/admin/freeze", {"state": "open", "reason_code": "resume", "report": report})
        owner_refused(client, owner, response, 409, cause="conflict")
        assert "words" not in json.dumps(response.json()["detail"]["refusal"]["entry"])

    def test_unauthenticated_owner_requests_stay_errors(self, client, owner, make_agent):
        alice = make_agent("alice")
        size = tree_size(client)
        fields = {"target_index": -1, "reason_code": "order"}
        unsigned = client.post("/v2/admin/tombstones", json=fields)
        assert unsigned.status_code == 401
        by_agent, _, _, _ = signed_request(client, alice.signer, "POST", "/v2/admin/tombstones", fields=fields)
        assert by_agent.status_code == 403 and reason(by_agent) == "owner_only"
        forged, _, _, _ = signed_request(client, owner, "POST", "/v2/admin/tombstones", fields=fields,
                                         tamper_body=lambda raw: raw.replace(b"-1", b"-2"))
        assert forged.status_code in (400, 401)
        old = int(time.time()) - 400
        stale, _, _, _ = signed_request(client, owner, "POST", "/v2/admin/tombstones", fields=fields,
                                        created=old, expires=old + 300)
        assert stale.status_code == 401 and reason(stale) == "expired"
        for response in (unsigned, by_agent, forged, stale):
            assert "refusal" not in json.dumps(response.json())
        assert tree_size(client) == size

    def test_accepted_owner_writes_are_unchanged(self, client, owner, make_agent):
        alice = make_agent("alice")
        target = leaf_index(alice.post(title="Hidden", body="A body the owner hides."))
        hidden = owner.tombstone(target, "order")
        assert hidden.status_code == 201 and hidden.json()["entry"]["type"] == "tombstone"
        frozen = owner.freeze()
        assert frozen.status_code == 201 and frozen.json()["entry"]["type"] == "freeze"
        # While frozen, a refused owner write is still a refusal leaf (the owner is never admission-limited).
        twice = owner.freeze()
        owner_refused(client, owner, twice, 409, cause="conflict")
        assert owner.freeze("open", "resume", "Reopened.").status_code == 201

    @pytest.mark.parametrize(
        ("method", "path", "fields", "fault"),
        [
            ("set_freeze", "/v2/admin/freeze", {"state": "frozen", "reason_code": "maintenance", "report": "r"}, KeyError("x")),
            ("tombstone", "/v2/admin/tombstones", {"target_index": 0, "reason_code": "order"}, IndexError("x")),
            ("publish_policy", "/v2/admin/policy", {"kind": "change", "document": "d", "not_before": 1}, RuntimeError("x")),
        ],
        ids=["KeyError", "IndexError", "RuntimeError"],
    )
    def test_a_server_fault_in_an_owner_write_is_a_500_without_a_leaf(
        self, client, owner, monkeypatch, method, path, fields, fault
    ):
        def broken(*args, **kwargs):
            raise fault

        db = client.app.state.db
        monkeypatch.setattr(db, method, broken)
        size = tree_size(client)
        owner.client = TestClient(client.app, raise_server_exceptions=False)
        response = owner.admin(path, fields)
        assert response.status_code == 500, response.text
        assert "refusal" not in response.text
        assert tree_size(client) == size

    def test_a_state_conflict_is_still_a_refusal_leaf(self, client, owner):
        size = tree_size(client)
        response = owner.admin("/v2/admin/freeze", {"state": "open", "reason_code": "resume", "report": "r"})
        owner_refused(client, owner, response, 409, cause="conflict")
        assert tree_size(client) == size + 1

    def test_owner_refusals_are_counted_in_the_daily_report(self, client, owner):
        db = client.app.state.db
        owner.admin("/v2/admin/tombstones", {"target_index": -1, "reason_code": "order"})
        today = int(time.time()) // DAY
        counts = {row["reason_code"]: row["count"] for row in db.refusal_counts(today)}
        assert counts["malformed"] >= 1


# ---------------------------------------------------------------------------
# decision 26: a (kid, nonce) a leaf carries is refused forever
# ---------------------------------------------------------------------------


class TestANonceALeafCarriesIsRefusedForever:
    LATER = 400 * DAY  # long after any expires, and after every purge of expired records

    def purge_everything(self, client) -> None:
        db = client.app.state.db
        db._purge_nonces(int(time.time()) + self.LATER + DAY)
        db._flush_read_nonces()

    def test_the_nonce_of_an_accepted_entry(self, client, make_agent, monkeypatch, db_path, owner):
        alice = make_agent("alice")
        payload = {"type": "post", "origin": alice.origin, **post_q(post_body())}
        posted, env, _, _ = submit_entry(client, alice.signer, payload, post_body())
        assert posted.status_code == 202
        nonce = env["protected"]["nonce"]
        assert env["protected"]["expires"] < int(time.time()) + self.LATER
        self.purge_everything(client)
        later = int(time.time()) + self.LATER
        at(monkeypatch, later)
        reused, _, _, _ = submit_entry(client, alice.signer, payload, post_body(), created=later, nonce=nonce)
        assert reused.status_code == 409 and reason(reused) == "replay", reused.text
        assert refusal_q(reused)["conflict_index"] == leaf_index(posted)
        # And after a restart: the records are rebuilt from the leaves.
        restarted = TestClient(create_app(db_path=db_path, owner_public_key=owner.public_key_b64u, announce=False,
                                          limits=TEST_LIMITS))
        again, _, _, _ = submit_entry(restarted, alice.signer, payload, post_body("Other", "Another body here."),
                                      created=later, nonce=nonce)
        assert again.status_code == 409 and reason(again) == "replay"
        assert refusal_q(again)["conflict_index"] == leaf_index(posted)

    def test_the_nonce_of_a_refused_entry(self, client, make_agent, monkeypatch):
        alice = make_agent("alice")
        payload = {"type": "post", "origin": alice.origin, **post_q(post_body())}
        old = int(time.time()) - 400
        nonce = envelope.new_nonce()
        stale, _, _, _ = submit_entry(client, alice.signer, payload, post_body(), created=old, expires=old + 300,
                                      nonce=nonce)
        assert reason(stale) == "expired"
        refused_at = leaf_index(stale, client)
        self.purge_everything(client)
        later = int(time.time()) + self.LATER
        at(monkeypatch, later)
        reused, _, _, _ = submit_entry(client, alice.signer, payload, post_body(), created=later, nonce=nonce)
        assert reused.status_code == 409 and reason(reused) == "replay", reused.text
        assert refusal_q(reused)["conflict_index"] == refused_at

    def test_the_nonce_of_a_refused_contribution_claim(self, client, make_agent, chain, monkeypatch):
        alice = make_agent("alice")
        ghost = "A" * 22
        claimed = alice.claim_contribution(ghost, base_tx(0xC1))
        assert reason(claimed) == "bad_reference"
        nonce = signature_params(alice.signer.last_request[3])["nonce"]
        refused_at = claimed.json()["detail"]["refusal"]["leaf_index"]
        self.purge_everything(client)
        later = int(time.time()) + self.LATER
        at(monkeypatch, later)
        payload = {"type": "post", "origin": alice.origin, **post_q(post_body())}
        reused, _, _, _ = submit_entry(client, alice.signer, payload, post_body(), created=later, nonce=nonce)
        assert reused.status_code == 409 and reason(reused) == "replay", reused.text
        assert refusal_q(reused)["conflict_index"] == refused_at
        again = alice.claim_contribution(ghost, base_tx(0xC2), created=later, nonce=nonce)
        assert reason(again) == "replay"

    def test_the_nonce_of_a_refused_owner_request(self, client, owner, monkeypatch):
        refused = owner.admin("/v2/admin/tombstones", {"target_index": -1, "reason_code": "order"})
        assert refused.status_code == 422 and detail_refusal(refused)["attempt_kid"] == owner.kid
        nonce = signature_params(owner.last_request[3])["nonce"]
        self.purge_everything(client)
        later = int(time.time()) + self.LATER
        at(monkeypatch, later)
        size = tree_size(client)
        again, _, _, _ = signed_request(client, owner, "POST", "/v2/admin/audits", created=later, nonce=nonce,
                                        fields={"document": "An audit.", "outcome_code": "published"})
        assert again.status_code == 409 and reason(again) == "replay" and tree_size(client) == size

    def test_a_stale_request_reusing_a_carried_tuple_is_a_replay_not_expired(self, client, make_agent, chain):
        # AICS-1 section 4.3: replay takes precedence over the request's own window.
        alice = make_agent("alice")
        payload = {"type": "post", "origin": alice.origin, **post_q(post_body())}
        posted, env, _, _ = submit_entry(client, alice.signer, payload, post_body())
        assert posted.status_code == 202
        nonce = env["protected"]["nonce"]
        old = int(time.time()) - 400
        claim = alice.claim_contribution("A" * 22, base_tx(0xC3), created=old, expires=old + 300, nonce=nonce)
        assert claim.status_code == 409 and reason(claim) == "replay", claim.text
        assert detail_refusal(claim)["conflict_index"] == leaf_index(posted)
        stale, _, _, _ = submit_entry(client, alice.signer, payload, post_body("Other", "Another body here."),
                                      created=old, expires=old + 300, nonce=nonce)
        assert stale.status_code == 409 and reason(stale) == "replay", stale.text
        assert refusal_q(stale)["conflict_index"] == leaf_index(posted)
        # A stale request with a fresh nonce is still expired.
        fresh = alice.claim_contribution("A" * 22, base_tx(0xC4), created=old, expires=old + 300)
        assert reason(fresh) == "expired"

    def test_only_records_no_leaf_backs_expire(self, client, make_agent):
        alice = make_agent("alice")
        db = client.app.state.db
        read, _, _, headers = signed_request(client, alice.signer, "GET", "/v2/capsules", body_override=b"")
        assert read.status_code == 200, read.text
        read_nonce = signature_params(headers)["nonce"]
        db._flush_read_nonces()
        assert nonce_row(client, alice.kid, read_nonce) is not None
        self.purge_everything(client)
        # A signed read writes no leaf: its record goes once expired; every record a leaf backs stays.
        assert nonce_row(client, alice.kid, read_nonce) is None
        backed = db._conn.execute(
            "SELECT COUNT(*) FROM nonces WHERE kid = ? AND (leaf_index IS NOT NULL OR refusal_index IS NOT NULL)",
            (alice.kid,),
        ).fetchone()[0]
        assert backed >= 1

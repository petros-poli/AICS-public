"""The second review of the AICS-1 server (decision 19): each class pins one finding's fix.

* the signed ``expires`` is the authenticated tuple's validity end, on every refusal (AICS-1 sections 4.3, 10.2);
* the ciphertext-byte budget of the card is positive and applied: eviction by earliest ``(ts, index)``, and
  resource exhaustion reported when that is not enough (section 8.2);
* refusals are deduplicated only for the exact same submission, never by ``(kid, nonce)`` alone (section 10.2);
* an owner-login write records its nonce durably before it acts (section 12.1);
* a nonce a leaf backs stays used for good (sections 4.3 and 14.3 step 3);
* a refusal answered from the per-cause cache still records its tuple (section 4.3);
* ending a suspension needs its reason and its evidence (section 10.3), and a swarm key can be suspended.
"""

from __future__ import annotations

import hashlib
import json
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from aics_identity import envelope
from aics_server import auth as auth_module
from aics_server.app import create_app
from aics_server.db import CIPHERTEXT_MINIMUM_SECONDS, load_limits

from conftest import (
    ENTRIES,
    TEST_LIMITS,
    Agent,
    Signer,
    entry_of,
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
    return dict(part.split("=", 1) for part in text.split(";")[1:])


# ---------------------------------------------------------------------------
# finding: the refusal of a contribution claim states the expires the client signed
# ---------------------------------------------------------------------------


class TestTheSignedExpiresIsTheRecord:
    def test_a_refused_claim_names_its_signed_expires(self, client, make_agent):
        alice = make_agent("alice")
        created = int(time.time())
        ghost = "A" * 22
        response = alice.claim_contribution(ghost, "0x" + "ab" * 32, created=created, expires=created + 120)
        assert response.status_code == 422 and reason(response) == "bad_reference", response.text
        payload = response.json()["detail"]["refusal"]["entry"]["payload"]
        # AICS-1 sections 4.3, 10.2 and 20.6: the authenticated tuple and its validity end, exactly as signed (not
        # the library's skew-widened valid_until, which would be created + 150 here).
        assert payload["attempt_expires"] == created + 120
        params = signature_params(alice.signer.last_request[3])
        assert int(params["expires"]) == created + 120 and payload["attempt_nonce"] == params["nonce"].strip('"')
        row = client.app.state.db._conn.execute(
            "SELECT expires FROM nonces WHERE kid = ? AND nonce = ?", (alice.kid, payload["attempt_nonce"])
        ).fetchone()
        assert row["expires"] == created + 120

    def test_a_replay_of_a_claim_names_its_own_signed_expires(self, client, make_agent):
        alice = make_agent("alice")
        created = int(time.time())
        first = alice.claim_contribution("A" * 22, "0x" + "ab" * 32, created=created, expires=created + 100)
        nonce = first.json()["detail"]["refusal"]["entry"]["payload"]["attempt_nonce"]
        other = alice.claim_contribution("B" * 22, "0x" + "cd" * 32, created=created, expires=created + 60, nonce=nonce)
        payload = other.json()["detail"]["refusal"]["entry"]["payload"]
        assert (payload["reason_code"], payload["attempt_expires"]) == ("replay", created + 60)


# ---------------------------------------------------------------------------
# finding: the ciphertext budget is published, positive and applied (AICS-1 section 8.2)
# ---------------------------------------------------------------------------


class TestTheCiphertextBudget:
    def test_the_budget_is_a_positive_published_limit(self, client):
        db = client.app.state.db
        card = client.get("/.well-known/aics-card.json").json()
        assert card["retention"]["ciphertext_budget_bytes"] == db.limits["ciphertext_budget_bytes"] == 8 * 1024**3
        assert client.get("/v2/limits").json()["limits"]["ciphertext_budget_bytes"] == 8 * 1024**3
        for bad in (0, -1, None, True, "1"):
            with pytest.raises((ValueError, TypeError)):
                load_limits({"ciphertext_budget_bytes": bad})
        assert load_limits({"ciphertext_budget_bytes": 1})["ciphertext_budget_bytes"] == 1

    def test_a_reviewed_card_with_another_budget_is_refused_at_start(self, tmp_path, owner, client, monkeypatch):
        body = {k: v for k, v in client.get("/.well-known/aics-card.json").json().items() if k != "signatures"}
        path = tmp_path / "card.json"
        path.write_text(json.dumps({**body, "retention": {**body["retention"], "ciphertext_budget_bytes": 1 << 30}}))
        monkeypatch.setenv("AICS_CARD_FILE", str(path))
        with pytest.raises(ValueError, match="ciphertext_budget_bytes"):
            create_app(db_path=tmp_path / "other.db", owner_public_key=owner.public_key_b64u, announce=False,
                       limits=TEST_LIMITS)
        ok = TestClient(create_app(db_path=tmp_path / "ok.db", owner_public_key=owner.public_key_b64u, announce=False,
                                   limits={**TEST_LIMITS, "ciphertext_budget_bytes": 1 << 30}))
        assert ok.get("/.well-known/aics-card.json").json()["retention"]["ciphertext_budget_bytes"] == 1 << 30

    def _messages(self, client, origin, count: int) -> tuple[list[int], int]:
        alice, bob = Agent(client, origin), Agent(client, origin)
        assert alice.claim("alice").status_code == 202 and bob.claim("bob").status_code == 202
        assert bob.grant(alice.kid, 50).status_code == 202
        indices = []
        for i in range(count):
            sent = alice.send_dm(alice.lookup("bob"), f"message {i}")
            assert sent.status_code == 202, sent.text
            indices.append(leaf_index(sent))
        size = entry_of(sent)["payload"]["size"]
        return indices, size

    def test_bodies_older_than_90_days_are_evicted_by_earliest_ts_and_index(self, client, origin):
        db = client.app.state.db
        indices, size = self._messages(client, origin, 4)
        stored = db._stored_ciphertext_bytes()
        assert stored == 4 * size
        db.limits["ciphertext_budget_bytes"] = 2 * size  # over budget by two bodies
        db._apply_ciphertext_budget(int(time.time()))  # every body is younger than 90 days: nothing is evicted
        assert db._stored_ciphertext_bytes() == stored
        exhausted = db.resource_exhaustion()
        assert exhausted["cause"] == "ciphertext_budget" and exhausted["stored_ciphertext_bytes"] == stored
        assert client.get("/healthz").json()["resource_exhaustion"]["ciphertext_budget_bytes"] == 2 * size
        assert client.get("/v2/limits").json()["resource_exhaustion"] == exhausted
        leaves_before = [client.get(f"/v2/tlog/proof/{i}").json()["leaf_hash_hex"] for i in indices]
        later = int(time.time()) + CIPHERTEXT_MINIMUM_SECONDS + 10
        assert db._apply_ciphertext_budget(later) == 2  # the two earliest, until within budget
        assert db._stored_ciphertext_bytes() == 2 * size and db.resource_exhaustion() is None
        for i in indices[:2]:
            body = db.entry_body(i)
            assert (body.state, body.data) == ("expired", None) and body.policy_index == 0  # the charter governed it
            status = client.get(f"/v2/entries/{i}").headers["x-aics-body-status"]
            assert status == "expired;policy_index=0"
        for i in indices[2:]:
            assert db.entry_body(i).state == "available"
        # Leaves are permanent: eviction changes no leaf.
        assert [client.get(f"/v2/tlog/proof/{i}").json()["leaf_hash_hex"] for i in indices] == leaves_before
        ct_hash = entry_of_index(client, indices[0])["payload"]["ct_hash"]
        assert client.get(f"/v2/bodies/{ct_hash}").json()["state"] == "expired"

    def test_a_store_that_crosses_the_budget_applies_the_rule_at_once(self, client, origin):
        db = client.app.state.db
        indices, size = self._messages(client, origin, 1)
        db.limits["ciphertext_budget_bytes"] = size  # within budget, exactly
        assert db._ciphertext_total == size and db.resource_exhaustion() is None
        carol = Agent(client, origin)
        assert carol.claim("carol").status_code == 202
        # One more body (a capsule) crosses the budget, and nothing is 90 days old yet: the rule runs at that store,
        # keeps the 90-day minimum and reports resource exhaustion (AICS-1 section 8.2).
        assert carol.put_capsule("state", "remember this").status_code == 202
        assert db.resource_exhaustion()["stored_ciphertext_bytes"] == db._stored_ciphertext_bytes() > size
        assert db.entry_body(indices[0]).state == "available"
        assert client.get("/healthz").json()["status"] == "DEGRADED"

    def test_a_hidden_body_is_never_evicted(self, client, origin, owner):
        db = client.app.state.db
        indices, size = self._messages(client, origin, 2)
        assert owner.tombstone(indices[0], "order", hashlib.sha256(b"an order").hexdigest()).status_code == 201
        db.limits["ciphertext_budget_bytes"] = 1
        db._apply_ciphertext_budget(int(time.time()) + CIPHERTEXT_MINIMUM_SECONDS + 10)
        assert db.entry_body(indices[0]).state == "tombstoned"  # its own rule (AICS-1 section 10.3)
        assert db.entry_body(indices[1]).state == "expired"
        assert db.resource_exhaustion() is not None  # the hidden body is still stored, and over budget


def entry_of_index(client, index: int) -> dict:
    return client.get(f"/v2/tlog/proof/{index}").json()["leaf_data"]


# ---------------------------------------------------------------------------
# finding: refusals are deduplicated by the exact submission, not by (kid, nonce)
# ---------------------------------------------------------------------------


class TestEachSubmissionGetsItsOwnRefusal:
    def test_another_envelope_reusing_a_replayed_tuple_gets_its_own_replay_refusal(self, client, make_agent):
        alice = make_agent("alice")
        posted, env, raw, headers = submit_entry(client, alice.signer, {"type": "post", "origin": alice.origin,
                                                                         **post_q(post_body())}, post_body())
        assert posted.status_code == 202
        identical = client.post(ENTRIES, content=raw, headers=headers)
        assert reason(identical) == "replay"
        size = tree_size(client)
        nonce = env["protected"]["nonce"]
        other_body = post_body("Another post", "Another body, same nonce.")
        other, other_env, _, _ = submit_entry(client, alice.signer, {"type": "post", "origin": alice.origin,
                                                                      **post_q(other_body)}, other_body, nonce=nonce)
        assert other.status_code == 409 and reason(other) == "replay"
        q = refusal_q(other)
        # Its own leaf, naming its own envelope, citing the accepted entry that used the nonce (AICS-1 section 10.2).
        assert q["envelope_hash"] == envelope.envelope_hash(other_env) != refusal_q(identical)["envelope_hash"]
        assert q["conflict_index"] == leaf_index(posted) and q["receipt_hash"] is None
        assert tree_size(client) == size + 1

    def test_a_stale_envelope_reusing_a_refused_tuple_gets_its_own_refusal(self, client, make_agent):
        alice = make_agent("alice")
        nonce = envelope.new_nonce()
        old = int(time.time()) - 400
        first, first_env, _, _ = submit_entry(client, alice.signer, {"type": "post", "origin": alice.origin,
                                                                      **post_q(post_body())}, post_body(),
                                              created=old, expires=old + 300, nonce=nonce)
        assert reason(first) == "expired"
        size = tree_size(client)
        second, second_env, _, _ = submit_entry(client, alice.signer, {"type": "post", "origin": alice.origin,
                                                                        **post_q(post_body())}, post_body(),
                                                created=old + 1, expires=old + 301, nonce=nonce)
        # Its own refusal leaf; and since a leaf carries the tuple, a replay before it is stale (AICS-1 section 4.3).
        assert reason(second) == "replay" and refusal_q(second)["envelope_hash"] == envelope.envelope_hash(second_env)
        assert refusal_q(second)["conflict_index"] == leaf_index(first, client)
        assert entry_of(second) != entry_of(first) and tree_size(client) == size + 1

    def test_a_resent_refused_envelope_is_answered_with_its_refusal_not_as_a_replay(self, client, make_agent):
        make_agent("taken")
        mallory = Agent(client, make_agent().origin)
        refused = mallory.claim("taken")
        assert reason(refused) == "name_taken"
        size = tree_size(client)
        method, path, body, headers = mallory.signer.last_request
        again = client.request(method, path, content=body, headers=headers)
        assert reason(again) == "name_taken" and entry_of(again) == entry_of(refused) and tree_size(client) == size
        assert "replay" not in again.headers["x-aics-hint"] and "refused before" in again.headers["x-aics-hint"]


# ---------------------------------------------------------------------------
# finding: the owner login records a write's nonce durably before it acts
# ---------------------------------------------------------------------------


class TestOwnerNoncesAreDurable:
    def test_an_owner_write_cannot_act_twice_even_across_a_restart(self, client, owner, db_path):
        db = client.app.state.db
        response, _, raw, headers = signed_request(
            client, owner, "POST", "/v2/admin/audits", fields={"document": "An audit.", "outcome_code": "published"}
        )
        assert response.status_code == 201
        nonce = signature_params(headers)["nonce"].strip('"')
        row = db._conn.execute("SELECT * FROM nonces WHERE kid = ? AND nonce = ?", (owner.kid, nonce)).fetchone()
        assert row is not None  # recorded before the leaf was written, not batched in memory
        size = tree_size(client)
        restarted = TestClient(create_app(db_path=db_path, owner_public_key=owner.public_key_b64u, announce=False,
                                          limits=TEST_LIMITS))
        again = restarted.post("/v2/admin/audits", content=raw, headers=headers)
        assert again.status_code == 409 and again.json()["detail"]["error"] == "replay"
        assert tree_size(restarted) == size  # no second leaf

    def test_an_owner_read_is_still_batched(self, client, owner):
        db = client.app.state.db
        _, _, _, headers = signed_request(client, owner, "GET", "/v2/admin/notices", body_override=b"")
        nonce = signature_params(headers)["nonce"].strip('"')
        assert (owner.kid, nonce) in db._read_nonces


# ---------------------------------------------------------------------------
# finding: a nonce a leaf backs is never reusable (AICS-1 sections 4.3 and 14.3 step 3)
# ---------------------------------------------------------------------------


class TestANonceIsUsedForGood:
    def test_a_new_envelope_with_the_nonce_of_an_old_accepted_one_is_a_replay(self, client, make_agent, monkeypatch):
        alice = make_agent("alice")
        payload = {"type": "post", "origin": alice.origin, **post_q(post_body())}
        posted, env, _, _ = submit_entry(client, alice.signer, payload, post_body())
        assert posted.status_code == 202
        nonce = env["protected"]["nonce"]
        later = int(time.time()) + 600  # the first envelope's window is long over
        monkeypatch.setattr(auth_module, "time", SimpleNamespace(time=lambda: later))
        reused, reused_env, _, _ = submit_entry(client, alice.signer, payload, post_body(), created=later, nonce=nonce)
        assert reused.status_code == 409 and reason(reused) == "replay", reused.text
        assert refusal_q(reused)["conflict_index"] == leaf_index(posted)
        fresh, _, _, _ = submit_entry(client, alice.signer, payload, post_body(), created=later)
        assert fresh.status_code == 202  # a fresh nonce at the same seq is accepted

    def test_purging_keeps_every_record_a_leaf_backs(self, client, make_agent):
        alice = make_agent("alice")
        db = client.app.state.db
        db._purge_nonces(int(time.time()) + 10 * DAY)
        row = db._conn.execute("SELECT * FROM nonces WHERE kid = ?", (alice.kid,)).fetchone()
        assert row is not None and row["leaf_index"] is not None


# ---------------------------------------------------------------------------
# finding: a refusal answered from the per-cause cache records its tuple
# ---------------------------------------------------------------------------


class TestCachedRefusalsRecordTheirTuple:
    def test_a_rate_limited_request_can_never_be_accepted_later(self, tmp_path, owner):
        limits = {**TEST_LIMITS, "writes": {"count": 2, "interval_seconds": 60}}
        client = TestClient(create_app(db_path=tmp_path / "w.db", owner_public_key=owner.public_key_b64u,
                                       announce=False, limits=limits))
        origin = client.get("/v2/tlog/checkpoint").json()["origin"]
        alice = Agent(client, origin)
        assert alice.claim("alice").status_code == 202
        assert alice.post().status_code == 202 and alice.post().status_code == 202
        first = alice.post()
        assert reason(first) == "rate_limit"
        cached = alice.post()  # the same cause: answered with the first leaf, no new leaf ...
        assert reason(cached) == "rate_limit" and entry_of(cached) == entry_of(first)
        method, path, body, headers = alice.signer.last_request
        db = client.app.state.db
        nonce = signature_params(headers)["nonce"].strip('"')
        row = db._conn.execute("SELECT * FROM nonces WHERE kid = ? AND nonce = ?", (alice.kid, nonce)).fetchone()
        assert row is not None and row["refusal_index"] == leaf_index(first, client)  # ... but its tuple is recorded
        db._admitted[alice.kid].times.clear()  # the window frees up
        again = client.request(method, path, content=body, headers=headers)
        assert again.status_code == 409 and reason(again) == "replay"  # never accepted later by whoever holds it
        assert refusal_q(again)["conflict_index"] == leaf_index(first, client)


# ---------------------------------------------------------------------------
# findings: no redirect inside the C2SP prefix; bounded counter keys; a constant-time /healthz; cached stats
# ---------------------------------------------------------------------------


class TestServing:
    @pytest.mark.parametrize("path", ["/tiles/", "/tiles/checkpoint/", "/tiles/tile/", "/checkpoint/", "/v2/stats/"])
    def test_no_path_redirects(self, client, path):
        # AICS-1 section 12.2: paths inside a C2SP prefix MUST NOT redirect (and nothing else here does either).
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 404 and "location" not in response.headers

    def test_the_tile_resources_are_served(self, client):
        assert client.get("/tiles/checkpoint").status_code == 200 and client.get("/tiles").status_code == 200

    def test_a_client_chosen_method_does_not_make_a_counter_key(self, client):
        db = client.app.state.db
        client.request("SOMEVERYLONGCLIENTCHOSENMETHODNAMEXXXXXXXXXXXXXXXXXXXXXXXXXXX", "/llms.txt")
        client.request("PROPFIND", "/llms.txt")
        keys = list(db.counters("http_requests:"))
        assert not any("SOMEVERY" in k or "PROPFIND" in k for k in keys)
        assert any(":OTHER " in k for k in keys), keys

    def test_healthz_is_constant_time(self, client, monkeypatch):
        db = client.app.state.db

        def no_scan():
            raise AssertionError("/healthz must not count rows")

        monkeypatch.setattr(db, "get_db_counts", no_scan)
        monkeypatch.setattr(db, "_count_rows", no_scan)
        health = client.get("/healthz")
        assert health.status_code == 200
        assert set(health.json()) == {"status", "tree_size", "published_size", "tiles_error", "diverged", "frozen",
                                      "freeze_index", "agent_writes_held", "resource_exhaustion", "served_size",
                                      "serving_uncosigned", "uncosigned_reason", "served_cosignature_age_seconds",
                                      "witnesses"}
        assert health.json()["status"] == "OPERATIONAL" and health.json()["tree_size"] >= 1
        # Without witnesses the served checkpoint is the published one, and no cosignature is expected (quorum 0).
        assert health.json()["served_size"] == health.json()["published_size"]
        assert health.json()["serving_uncosigned"] is False and health.json()["uncosigned_reason"] is None

    def test_stats_are_counted_outside_the_writer_lock_and_cached(self, client, monkeypatch):
        db = client.app.state.db
        calls = []
        original = db._count_rows

        def counted():
            assert not db._lock._is_owned(), "the counts never hold the writer lock"
            calls.append(1)
            return original()

        monkeypatch.setattr(db, "_count_rows", counted)
        db._stats_cache = None
        first = client.get("/v2/stats").json()["usage"]
        second = client.get("/v2/stats").json()["usage"]
        assert len(calls) == 1 and first["registered_agents"] == second["registered_agents"]
        assert first["tlog_tree_size"] == client.get("/healthz").json()["tree_size"]


# ---------------------------------------------------------------------------
# findings: ending a suspension repeats its reason and evidence; a swarm key can be suspended
# ---------------------------------------------------------------------------


class TestSuspensions:
    def suspend(self, owner, kid, until=None, evidence=None):
        return owner.admin("/v2/admin/suspensions",
                           {"target_kid": kid, "reason_code": "order", "until": until, "evidence_hash": evidence})

    def test_ending_a_suspension_repeats_its_reason_and_its_evidence(self, client, owner, make_agent):
        alice = make_agent("alice")
        evidence = hashlib.sha256(b"order 2026/9 naming this key").hexdigest()
        assert self.suspend(owner, alice.kid, evidence=evidence).status_code == 201
        assert reason(alice.post()) == "suspended"
        size = tree_size(client)
        for other in (None, hashlib.sha256(b"another order").hexdigest()):
            refused = self.suspend(owner, alice.kid, until=0, evidence=other)
            assert refused.status_code == 400 and "evidence_hash" in refused.text, refused.text
        # AICS-1 section 10.3: no ending event on other evidence; each refused owner request is a refusal leaf.
        assert tree_size(client) == size + 2
        assert reason(alice.post()) == "suspended"
        size = tree_size(client)
        ended = self.suspend(owner, alice.kid, until=0, evidence=evidence)
        assert ended.status_code == 201, ended.text
        view = client.get(f"/v2/suspensions/{alice.kid}").json()
        assert view["active"] is False and view["evidence_hash"] == evidence
        assert alice.post().status_code == 202

    def test_an_introduced_swarm_key_is_suspended_like_any_key(self, tmp_path, owner, monkeypatch):
        from test_swarms import member

        for name in ("AICS_CARD_FILE",):
            monkeypatch.delenv(name, raising=False)
        swarm_client = TestClient(create_app(db_path=tmp_path / "swarms.db", owner_public_key=owner.public_key_b64u,
                                             announce=False, limits=TEST_LIMITS, swarms=True))
        owner.client = swarm_client
        owner.origin = swarm_client.get("/v2/tlog/checkpoint").json()["origin"]
        m = member(swarm_client)  # introduced, no name: it writes under the swarms profile
        body = post_body("From a swarm key", "Posted before any name was claimed.")
        assert m.write("post", post_q(body), body).status_code == 202
        suspended = self.suspend(owner, m.kid)
        assert suspended.status_code == 201, suspended.text  # an order naming such a key can be met
        later = post_body("Again", "Posted while suspended.")
        assert reason(m.write("post", post_q(later), later)) == "suspended"

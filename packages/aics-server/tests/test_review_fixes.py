"""The review findings this server fixes, one class per finding, each against the running app.

* receipts: every native write and every logged refusal returns a log-signed receipt note
  (AICS-1 sections 10.1 and 12.1, DESIGN.md G4);
* daily count reports: a policy-signed report of kind daily for each finished UTC day
  (AICS-1 section 10.2);
* acceptance failures of authenticated writes are refusal leaves, behind the admission
  windows (AICS-1 section 10.2);
* canonical 16-byte nonces, and refusal leaves that never copy a refused nonce;
* hidden-body retention: deleted at once for erasure and secret_format, after six months for
  illegal_on_notice and order, ciphertext included (decision 17, AICS-1 section 10.3);
* public bodies are bounded in bytes, not characters (AICS-1 section 4.3);
* capsule expiry is at least 90 days (AICS-1 section 5.3);
* the publication lag of the tiles is bounded by the maximum merge delay;
* leaf 0 of the production origin needs the reviewed charter and the owner key;
* JSON bodies have bounded nesting (no RecursionError 500);
* counters and the nonces of signed reads are kept in memory and written in batches;
* stored ciphertext is retrievable by index over HTTP as at the gate: GET /v2/entries/{index}
  is the AICS-1 section 14.3 wire bundle (section 12.1).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aics_identity import canonicalize, envelope, keys
from aics_server import strictjson
from aics_server.app import create_app
from aics_server.db import (
    DEFAULT_ORIGIN,
    HIDDEN_BODY_RETENTION_SECONDS,
    PUBLIC_BODY_BYTES,
    GenesisRefused,
    SanctuaryDB,
)
from aics_server.gate import receipt_note
from aics_server.tlog_store import MMD_SECONDS, LogUnavailable
from aics_tlog import Bundle, parse_note, parse_vkey, verify_bundle, verify_note

from conftest import GENESIS_SIZE, TEST_LIMITS, Agent, SecretIdentity, Signer, fetch_leaf, post_body, post_q
from conftest import ENTRIES, entry_bundle, entry_of, leaf_index, reason, refusal_q, secret_claim, secret_post, submit_entry

DAY = 86400


def tree_size(client: TestClient) -> int:
    return client.get("/v2/tlog/checkpoint").json()["tree_size"]


def receipt_of(client: TestClient, written: dict[str, Any]) -> dict[str, Any]:
    """Check an answer's ``receipt_note`` (``{entry, receipt_note}``) with the log key and return the note's JSON."""
    db = client.app.state.db
    raw = keys.b64u_decode(written["receipt_note"])
    note = parse_note(raw)
    assert verify_note(note, [parse_vkey(db.server_vkey)])
    body = json.loads(note.text)
    assert note.text == canonicalize(body).decode() + "\n"
    entry = written["entry"]
    entry_hash = hashlib.sha256(b"\x00" + canonicalize(entry)).hexdigest()
    assert body == {"origin": db.origin, "entry_hash": entry_hash, "submitted_at": entry["ts"], "mmd_seconds": MMD_SECONDS}
    # The HTTP binding and the text gate hand out the same bytes for the same entry.
    assert raw == receipt_note(db, entry, entry_hash)
    return body


def shifted(monkeypatch: pytest.MonkeyPatch, seconds: float) -> None:
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + seconds)


# ---------------------------------------------------------------------------
# receipts (G4): every JSON write and every logged refusal
# ---------------------------------------------------------------------------


class TestReceipts:
    def test_a_native_write_returns_a_log_signed_receipt(self, client, make_agent):
        alice = make_agent("alice")
        posted = alice.post()
        assert posted.status_code == 202 and set(posted.json()) == {"entry", "receipt_note"}
        receipt_of(client, posted.json())
        assert fetch_leaf(client, leaf_index(posted))["leaf_data"] == posted.json()["entry"]
        claim = fetch_leaf(client, alice.head_index)
        assert claim["leaf_index"] == alice.head_index

    def test_a_logged_refusal_returns_one_too(self, client, make_agent):
        make_agent("erin")
        refused = Agent(client, make_agent().origin).claim("erin")  # name_taken
        assert 400 <= refused.status_code < 500 and reason(refused) == "name_taken"
        assert entry_of(refused)["type"] == "refusal"
        receipt_of(client, refused.json())

    def test_admin_and_notice_decisions_too(self, client, make_agent, owner):
        alice = make_agent("alice")
        post = alice.post()
        hidden = owner.tombstone(leaf_index(post), "illegal_on_notice")
        assert hidden.status_code == 201
        receipt_of(client, hidden.json())


# ---------------------------------------------------------------------------
# daily count reports (AICS-1 section 10.2)
# ---------------------------------------------------------------------------


class TestDailyReports:
    def daily_leaves(self, client) -> list[dict[str, Any]]:
        rows = client.app.state.db._conn.execute(
            "SELECT leaf_json FROM tlog_leaves WHERE event_type = 'report' ORDER BY leaf_index"
        ).fetchall()
        entries = [json.loads(r[0]) for r in rows]
        return [e for e in entries if e["payload"].get("kind") == "daily"]

    def daily_counts(self, client, day: int) -> list[dict[str, Any]]:
        """``counts`` of the one daily report of *day*, read from the log."""
        (report,) = [r for r in self.daily_leaves(client) if r["payload"]["day"] == day]
        return report["payload"]["counts"]

    def test_nothing_is_reported_for_the_day_still_running(self, client):
        assert client.app.state.db.housekeeping(force=True)
        assert self.daily_leaves(client) == []

    def test_each_finished_day_gets_one_report_with_zero_rows(self, client, make_agent, monkeypatch, oob):
        db = client.app.state.db
        make_agent("erin")
        Agent(client, oob.origin).claim("erin")  # one name_taken refusal today
        today = int(time.time()) // DAY
        shifted(monkeypatch, 2 * DAY)
        written = db.write_daily_reports()
        reports = self.daily_leaves(client)
        assert [r["payload"]["day"] for r in reports] == [today, today + 1] and len(written) == 2
        first, second = (r["payload"] for r in reports)
        codes = [row["reason_code"] for row in first["counts"]]
        assert codes == sorted(codes, key=lambda c: c.encode("ascii")) == list(db.active_refusal_codes())
        # Before the first card, the charter's registry: the base codes, the twelve of SUP-1 and one
        # secret_format:<id> per published pattern, each once (AICS-1 sections 5.3, 17.2 and 20.8).
        assert len(codes) == len(set(codes)) == 41 + 12 + 10 and "insufficient_balance" in codes
        assert "secret_format:github_token" in codes and "name_taken" in codes
        assert {row["reason_code"]: row["count"] for row in first["counts"]}["name_taken"] == 1
        assert sum(row["count"] for row in first["counts"]) == 1
        assert all(row["count"] == 0 for row in second["counts"])  # a zero day is reported too
        for report in reports:
            assert report["actor_kid"] == oob.policy_kid
            assert oob.policy_statement(report)["kind"] == "daily"
        # Idempotent: a second pass writes nothing more.
        assert db.write_daily_reports() == [] and len(self.daily_leaves(client)) == 2
        assert self.daily_counts(client, today) == first["counts"]

    def test_rows_follow_the_registry_in_force_plus_any_other_counted_code(self, client, owner, make_agent, monkeypatch):
        db = client.app.state.db
        # publish_policy now logs only a section 13.1 card this server follows (whose registry is its own); a card
        # leaf with another registry is written directly, as a log could hold one from another implementation.
        card = json.dumps({"reason_codes": {"refusal": ["name_taken", "malformed"]}}).encode()
        refused = owner.policy(card.decode(), kind="card", not_before=int(time.time()) + 5)
        assert refused.status_code == 400 and "J(card)" in refused.text  # not even the JCS bytes of a card
        # The owner's authenticated request is refused with a malformed refusal leaf (AICS-1 section 10.2).
        now = int(time.time())
        with db._lock:
            prev = db._conn.execute("SELECT MAX(leaf_index) FROM tlog_leaves WHERE event_type = 'policy'").fetchone()[0]
            statement = {
                "kind": "card", "document_hash": hashlib.sha256(card).hexdigest(), "size": len(card),
                "prev_policy_index": prev, "effective_after": db._log.tree.size, "not_before": now,
                "log_kid": db.server_kid, "policy_kid": db.policy_kid, "owner_kid": db.owner_kid, "log_sig": None,
            }
            with db._transaction():
                leaf = db._append_policy_leaf("policy", statement, ts=now)
                db._conn.execute(
                    "INSERT INTO policy_documents (leaf_index, kind, document_sha256, size, document) VALUES (?, 'card', ?, ?, ?)",
                    (leaf["leaf_index"], statement["document_hash"], len(card), card),
                )
        make_agent("erin")
        Agent(client, make_agent().origin).claim("erin")  # name_taken: in the card's registry
        alice, _bob = make_agent("alice"), make_agent("bob")
        assert alice.send_dm(alice.lookup("bob"), "closed inbox").status_code == 403  # no_consent: counted anyway
        today = int(time.time()) // DAY
        shifted(monkeypatch, DAY)
        db.write_daily_reports()
        assert self.daily_counts(client, today) == [
            {"reason_code": "malformed", "count": 1},
            {"reason_code": "name_taken", "count": 1},
            {"reason_code": "no_consent", "count": 1},
        ]

    def test_the_counts_are_recomputable_from_the_refusal_leaves(self, client, make_agent, monkeypatch):
        db = client.app.state.db
        make_agent("erin")
        for _ in range(3):
            Agent(client, make_agent().origin).claim("erin")
        today = int(time.time()) // DAY
        rows = db._conn.execute("SELECT leaf_json FROM tlog_leaves WHERE event_type = 'refusal'").fetchall()
        recomputed: dict[str, int] = {}
        for row in rows:
            entry = json.loads(row[0])
            if entry["ts"] // DAY == today:
                recomputed[entry["payload"]["reason_code"]] = recomputed.get(entry["payload"]["reason_code"], 0) + 1
        shifted(monkeypatch, DAY)
        db.write_daily_reports()
        counts = {row["reason_code"]: row["count"] for row in self.daily_counts(client, today)}
        assert {code: n for code, n in counts.items() if n} == recomputed == {"name_taken": 3}

    def test_housekeeping_writes_them_and_survives_an_unavailable_log(self, client, monkeypatch):
        db = client.app.state.db
        shifted(monkeypatch, DAY)

        def unavailable() -> None:
            raise LogUnavailable("the log cannot append")

        monkeypatch.setattr(db._log, "check_writable", unavailable)
        assert db.housekeeping(force=True)  # no exception: the report waits for the next pass
        assert self.daily_leaves(client) == []
        monkeypatch.undo()
        shifted(monkeypatch, DAY)
        assert db.housekeeping(force=True)
        assert len(self.daily_leaves(client)) == 1


# ---------------------------------------------------------------------------
# acceptance failures are refusal leaves (AICS-1 section 10.2), behind the admission windows
# ---------------------------------------------------------------------------


class TestFailuresAreRefusals:
    def test_the_review_probes_each_add_a_refusal_leaf(self, client, make_agent):
        alice = make_agent("alice")
        size = tree_size(client)
        vote = alice.vote(10**6, 0)  # names no poll
        assert vote.status_code == 400 and entry_of(vote)["type"] == "refusal"
        spend = alice.spend("hosting", 5)
        assert spend.status_code == 409 and reason(spend) == "insufficient_balance"
        assert refusal_q(spend)["conflict_index"] is None  # no credit or spend yet
        assert tree_size(client) == size + 2

    def test_invalid_request_fields_of_a_signed_write_are_a_malformed_refusal(self, client, make_agent):
        alice = make_agent("alice")
        size = tree_size(client)
        payload = {"type": "post", "origin": alice.origin, **post_q(post_body())}
        # Not U64: a schema failure.  The U64 of no bytes: a body that is not the one body_hash names.
        for i, (body, status, code) in enumerate((("not U64!", 400, "malformed"), ("", 422, "digest_mismatch"))):
            response = alice.write("POST", ENTRIES, {"body": body}, payload=payload)
            assert response.status_code == status and reason(response) == code
            assert refusal_q(response)["attempt_kid"] == alice.kid
            assert tree_size(client) == size + 1 + i
        # An unsigned request keeps FastAPI's plain answer and writes nothing.
        plain = client.post("/notice", json={"kind": "notice"})
        assert plain.status_code == 422 and isinstance(plain.json()["detail"], list)
        assert tree_size(client) == size + 2

    def test_a_body_beside_a_bodiless_entry_is_refused_with_a_leaf(self, client, make_agent):
        creator, voter = make_agent("creator"), make_agent("voter")
        poll = leaf_index(creator.poll())
        size = tree_size(client)
        response = voter.vote(poll, 0, raw=b'{"reason":"x"}')  # body_hash is null: the vote has no body
        assert response.status_code == 400 and reason(response) == "malformed"
        grant = voter.grant(creator.kid, 1, fields={"body": keys.b64u_encode(b"a grant has none")})
        assert grant.status_code == 400 and reason(grant) == "malformed"
        assert tree_size(client) == size + 2

    def test_failed_claims_with_fresh_keys_stay_inside_the_preidentity_bucket(self, tmp_path, owner):
        limits = {**TEST_LIMITS, "preidentity": {"count": 3, "interval_seconds": 60}}
        client = TestClient(create_app(db_path=tmp_path / "w.db", owner_public_key=owner.public_key_b64u,
                                       announce=False, limits=limits))
        origin = client.get("/v2/tlog/checkpoint").json()["origin"]
        answers = [Agent(client, origin).claim("Not-Normalized").status_code for _ in range(6)]
        # Each claim is a new key (free to make), so no key is over its own registration window: only the global
        # pre-identity bucket bounds the refusal leaves (AICS-1 sections 10.2 and 13.1).
        assert answers == [400, 400, 400, 429, 429, 429]
        assert tree_size(client) == GENESIS_SIZE + 3

    def test_replays_with_fresh_keys_stay_inside_the_preidentity_bucket(self, tmp_path, owner):
        from aics_server import identity as ident

        limits = {**TEST_LIMITS, "preidentity": {"count": 3, "interval_seconds": 60}}
        client = TestClient(create_app(db_path=tmp_path / "r.db", owner_public_key=owner.public_key_b64u,
                                       announce=False, limits=limits))
        origin = client.get("/v2/tlog/checkpoint").json()["origin"]
        secret_claim(client, "plain", "S" * 40)  # shared-secret writes only at the TLS gate
        head = client.get("/v2/names/plain").json()["head_index"]
        size = tree_size(client)
        answers, replays = [], []
        for _ in range(4):
            new = Signer()  # a fresh key for every attempt costs nothing
            r = {"name_norm": "plain", "prev_event_index": head, "new_ed25519": new.public_key_b64u,
                 "new_x25519": keys.b64u_encode(b"\x09" * 32), "new_tier": "verified"}
            fields = {"origin": origin, **r, "mode": "upgrade"}
            payload = {"type": "key.rotate", "origin": origin, "mode": "upgrade", **r, "sig_old": None,
                       "sig_new": new.proof(ident.rotation_message(**fields)),
                       "secret_check": keys.b64u_encode(bytes(64))}  # no check by the policy key
            first, _, _, _ = submit_entry(client, new, payload)
            answers.append(first.status_code)
            method, path, body, headers = new.last_request
            replays.append(client.request(method, path, content=body, headers=headers).status_code)
        # Each refusal is a decision with a leaf, but only inside the global pre-identity bucket (the claim used one
        # slot); resending an answered attempt is answered with its refusal and adds nothing.
        assert answers == [403, 403, 429, 429]
        assert replays == [403, 403, 429, 429]
        assert tree_size(client) == size + 2

    def test_a_shared_secret_that_does_not_check_writes_no_leaf(self, client, origin):
        from aics_server.db import CredentialError

        identity = secret_claim(client, "plain", "S" * 40)
        size = tree_size(client)
        # A credential failure is excluded from logging (AICS-1 section 10.2): at the gate's fallback write ...
        impostor = SecretIdentity(identity.name, "T" * 40, identity.unverified_id, identity.claim_index, identity.line,
                                  identity.reply)
        assert secret_post(impostor, post_body("Impostor", "Not the holder.", "general")).startswith("err bad_secret")
        # ... and at the old-secret check of an upgrade.
        new = Signer()
        r = {"name_norm": "plain", "prev_event_index": identity.claim_index, "new_ed25519": new.public_key_b64u,
             "new_x25519": keys.b64u_encode(b"\x09" * 32), "new_tier": "verified"}
        with pytest.raises(CredentialError):
            client.app.state.db.upgrade_check("plain", "T" * 40, r)
        assert tree_size(client) == size


# ---------------------------------------------------------------------------
# nonces: canonical 16 bytes; refusal leaves never copy a refused nonce
# ---------------------------------------------------------------------------


class TestNonces:
    def test_a_refusal_names_the_attempt_by_hash_and_its_authenticated_tuple(self, client, make_agent):
        """AICS-1 sections 4.3, 5.2 and 10.2: the refusal backs the replay record of the refused tuple, so it carries
        attempt_kid, attempt_nonce (the bounded 16-byte residual) and attempt_expires; the envelope is named by
        hexH(J(E)) and request_hash is null."""
        make_agent("erin")
        refused = Agent(client, make_agent().origin)
        nonce = envelope.new_nonce()
        response, env, _, _ = submit_entry(client, refused.signer, refused.claim_payload("erin"), nonce=nonce)
        payload = refusal_q(response)
        assert payload["attempt_nonce"] == nonce and payload["attempt_kid"] == refused.kid
        assert payload["attempt_expires"] == env["protected"]["expires"]
        assert payload["envelope_hash"] == envelope.envelope_hash(env) and payload["request_hash"] is None
        # The pair is still recorded: the same request again is answered by that refusal and no other leaf.
        size = tree_size(client)
        method, path, body, headers = refused.signer.last_request
        again = client.request(method, path, content=body, headers=headers)
        assert again.status_code == 409 and entry_of(again) == entry_of(response)
        assert "refused before" in again.headers["x-aics-hint"] and tree_size(client) == size
        # Another envelope reusing that live tuple is another submission: a replay refusal of its own (10.2).
        other, other_env, _, _ = submit_entry(client, refused.signer, refused.claim_payload("erin2"), nonce=nonce)
        assert reason(other) == "replay" and refusal_q(other)["envelope_hash"] == envelope.envelope_hash(other_env)
        assert refusal_q(other)["conflict_index"] == leaf_index(response, client) and tree_size(client) == size + 1

    def test_a_replay_of_an_accepted_write_cites_its_nonce_and_entry(self, client, make_agent):
        alice = make_agent("alice")
        posted = alice.post()
        method, path, body, headers = alice.signer.last_request
        replay = client.request(method, path, content=body, headers=headers)
        payload = refusal_q(replay)
        nonce = posted.json()["entry"]["payload"]["envelope"]["protected"]["nonce"]
        assert reason(replay) == "replay" and payload["conflict_index"] == leaf_index(posted)
        assert payload["attempt_nonce"] == nonce  # already on the accepted entry it conflicts with
        assert payload["envelope_hash"] == envelope.envelope_hash(posted.json()["entry"]["payload"]["envelope"])

    def test_chosen_text_cannot_be_a_nonce(self, client, make_agent):
        alice = make_agent("alice")
        size = tree_size(client)
        response = alice.post(nonce="I_can_write_any_words_here_forever")
        # Not an AICS-1 envelope (a nonce is 16 bytes in canonical U64): refused before anything is logged.
        assert response.status_code == 400 and reason(response) == "malformed"
        assert tree_size(client) == size
        log = "\n".join(r[0] for r in client.app.state.db._conn.execute("SELECT leaf_json FROM tlog_leaves"))
        assert "I_can_write_any_words_here_forever" not in log


# ---------------------------------------------------------------------------
# hidden bodies: deleted at once (erasure, secret_format) or after six months (illegal_on_notice, order)
# ---------------------------------------------------------------------------


class TestHiddenBodies:
    def post_row(self, client, index: int):
        return client.app.state.db._conn.execute(
            "SELECT title, text, body FROM agora_posts WHERE post_index = ?", (index,)
        ).fetchone()

    @pytest.mark.parametrize("reason", ["secret_format", "erasure"])
    def test_deleted_at_once(self, client, make_agent, owner, reason):
        alice = make_agent("alice")
        index = leaf_index(alice.post(title="Kept title", body="A body to be erased."))
        assert owner.tombstone(index, reason).status_code == 201
        assert tuple(self.post_row(client, index)) == (None, "", None)  # deleted in the tombstone's commit
        erased_at = client.app.state.db._conn.execute(
            "SELECT erased_at FROM tombstones WHERE target_index = ?", (index,)
        ).fetchone()[0]
        assert erased_at is not None
        assert fetch_leaf(client, index)["leaf_index"] == index  # the leaf stays

    def test_illegal_on_notice_is_kept_inaccessible_for_six_months_then_deleted(self, client, make_agent, owner, monkeypatch):
        alice = make_agent("alice")
        index = leaf_index(alice.post(title="Kept title", body="A body hidden on notice."))
        assert owner.tombstone(index, "illegal_on_notice").status_code == 201
        db = client.app.state.db
        assert self.post_row(client, index)["text"] == "A body hidden on notice."  # kept ...
        assert client.get("/v2/agora/posts").json()["posts"][0]["text"] is None  # ... inaccessible
        shifted(monkeypatch, HIDDEN_BODY_RETENTION_SECONDS - DAY)
        assert db.housekeeping(force=True)
        assert self.post_row(client, index)["text"] == "A body hidden on notice."
        monkeypatch.undo()
        shifted(monkeypatch, HIDDEN_BODY_RETENTION_SECONDS + 60)
        assert db.housekeeping(force=True)
        assert tuple(self.post_row(client, index)) == (None, "", None)

    def test_ciphertext_hidden_by_an_order_is_deleted_after_six_months(self, client, make_agent, owner, monkeypatch):
        alice, bob = make_agent("alice"), make_agent("bob")
        assert bob.grant(alice.kid, 3).status_code == 202
        dm = alice.send_dm(alice.lookup("bob"), "a sealed message")
        assert dm.status_code == 202, dm.text
        dm_index = leaf_index(dm)
        capsule = alice.put_capsule("slot", "sealed state")
        assert capsule.status_code == 202, capsule.text
        capsule_index = leaf_index(capsule)
        for index in (dm_index, capsule_index):
            assert owner.tombstone(index, "order").status_code == 201
        db = client.app.state.db
        shifted(monkeypatch, HIDDEN_BODY_RETENTION_SECONDS + 60)
        assert db.housekeeping(force=True)
        assert db._conn.execute("SELECT ciphertext FROM messages WHERE leaf_index = ?", (dm_index,)).fetchone()[0] is None
        assert db._conn.execute("SELECT ciphertext FROM capsule_leaves WHERE leaf_index = ?", (capsule_index,)).fetchone()[0] is None
        for index in (dm_index, capsule_index):  # the bundle keeps reporting the tombstone
            assert entry_bundle(client, index)[1]["state"] == "tombstoned"


# ---------------------------------------------------------------------------
# public bodies are bounded in bytes (AICS-1 section 4.3)
# ---------------------------------------------------------------------------


class TestPublicBodyBytes:
    def test_multibyte_text_over_the_byte_limit_is_refused_too_large(self, client, make_agent):
        alice = make_agent("alice")
        size = tree_size(client)
        body = "\U0001F600" * 16384  # 16384 characters (the field allows them), 65536 bytes of UTF-8
        response = alice.post(title="Many emoji", body=body)
        assert response.status_code == 413
        assert reason(response) == "too_large" and refusal_q(response)["reason_code"] == "too_large"
        assert tree_size(client) == size + 1 and client.get("/v2/agora/posts").json()["count"] == 0

    def test_the_limit_is_on_the_bytes_of_the_whole_canonical_body(self, client, make_agent):
        """The body a post commits to is the JCS JSON {channel, title, text}; the limit and the leaf's size count
        its bytes (AICS-1 sections 4.3 and 5.3)."""
        alice = make_agent("alice")
        text = "é" * 8000  # 16000 bytes: inside the limit
        exact = canonicalize({"channel": "general", "title": "Accents", "text": text})
        response = alice.post(title="Accents", body=text)
        assert response.status_code == 202, response.text
        payload = response.json()["entry"]["payload"]
        assert payload["body_hash"] == hashlib.sha256(exact).hexdigest() and payload["size"] == len(exact)
        assert 16000 < len(exact) <= PUBLIC_BODY_BYTES
        # One byte over the limit, counted on the whole body, is too_large.
        frame = len(canonicalize({"channel": "general", "title": "t", "text": ""}))
        over = alice.post(title="t", body="a" * (PUBLIC_BODY_BYTES - frame + 1))
        assert over.status_code == 413 and reason(over) == "too_large"
        exactly = alice.post(title="t", body="a" * (PUBLIC_BODY_BYTES - frame))
        assert exactly.status_code == 202, exactly.text


# ---------------------------------------------------------------------------
# capsules expire no sooner than 90 days (AICS-1 section 5.3)
# ---------------------------------------------------------------------------


class TestCapsuleExpiry:
    @pytest.mark.parametrize("ahead, accepted", [(120, False), (90 * DAY - 60, False), (90 * DAY + 60, True), (366 * DAY, False)])
    def test_the_expiry_window(self, client, make_agent, ahead, accepted):
        alice = make_agent("alice")
        response = alice.put_capsule("slot", "state", expires=int(time.time()) + ahead)
        if accepted:
            assert response.status_code == 202, response.text
        else:
            assert response.status_code == 400
            assert refusal_q(response)["reason_code"] == "malformed"


# ---------------------------------------------------------------------------
# the publication lag is bounded by the maximum merge delay
# ---------------------------------------------------------------------------


class TestPublicationLag:
    def test_writes_stop_once_tiles_lag_past_the_mmd_and_resume_when_they_publish(self, client, make_agent, monkeypatch):
        db = client.app.state.db
        alice = make_agent("alice")
        store = db._log.store
        clock = {"now": 1000.0}
        monkeypatch.setattr(db._log, "_clock", lambda: clock["now"])

        def disk_full(path, data):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(store, "write", disk_full)
        assert alice.post().status_code == 202  # committed; the tiles lag
        tiles = client.get("/v2/tlog/checkpoint").json()["tiles"]
        assert tiles["lag_entries"] == 1 and tiles["mmd_seconds"] == MMD_SECONDS and tiles["error"]
        clock["now"] += MMD_SECONDS - 1
        assert alice.post().status_code == 202  # still inside the merge delay
        clock["now"] += 2
        refused = alice.post()
        assert refused.status_code == 503 and reason(refused) == "log_unavailable"
        assert client.get("/v2/tlog/checkpoint").json()["tiles"]["lag_seconds"] > MMD_SECONDS
        monkeypatch.setattr(store, "write", type(store).write.__get__(store))
        assert alice.post().status_code == 202  # publication retried before the write, and the lag is gone
        tiles = client.get("/v2/tlog/checkpoint").json()["tiles"]
        assert tiles["lag_entries"] == 0 and tiles["lag_seconds"] == 0 and tiles["error"] is None


# ---------------------------------------------------------------------------
# leaf 0 of the production origin
# ---------------------------------------------------------------------------


class TestGenesisGuard:
    def make(self, tmp_path: Path, name: str, **kwargs: Any) -> SanctuaryDB:
        return SanctuaryDB(tmp_path / f"{name}.db", **kwargs)

    def test_the_production_origin_needs_the_charter_and_the_owner_key(self, tmp_path, monkeypatch, owner):
        monkeypatch.delenv("AICS_DEV_GENESIS", raising=False)
        with pytest.raises(GenesisRefused, match="AICS_CHARTER_FILE"):
            self.make(tmp_path, "a", owner_public_key=owner.public_key_b64u)
        with pytest.raises(GenesisRefused, match="AICS_OWNER_PUBKEY"):
            self.make(tmp_path, "b", charter="A reviewed charter.\n")
        charter = tmp_path / "charter.md"
        charter.write_text("A reviewed charter.\n")
        monkeypatch.setenv("AICS_CHARTER_FILE", str(charter))
        db = self.make(tmp_path, "c", owner_public_key=owner.public_key_b64u)
        assert db.origin == DEFAULT_ORIGIN and db.charter()["document"] == b"A reviewed charter.\n"
        # Nothing was written for the refused ones.
        for name in ("a", "b"):
            conn = sqlite3.connect(tmp_path / f"{name}.db")
            assert conn.execute("SELECT COUNT(*) FROM tlog_leaves").fetchone()[0] == 0
            conn.close()

    def test_production_mode_ignores_the_development_waiver(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AICS_DEV_GENESIS", "1")
        monkeypatch.setenv("AICS_PRODUCTION", "1")
        with pytest.raises(GenesisRefused):
            self.make(tmp_path, "p", origin="test.example/tiles")

    def test_development_logs_and_other_origins_start_as_before(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AICS_DEV_GENESIS", raising=False)
        assert self.make(tmp_path, "other", origin="test.example/tiles").tlog_head()[0] == GENESIS_SIZE
        monkeypatch.setenv("AICS_DEV_GENESIS", "1")
        assert self.make(tmp_path, "dev").tlog_head()[0] == GENESIS_SIZE

    def test_an_existing_log_restarts_without_the_waiver(self, tmp_path, monkeypatch):
        db = self.make(tmp_path, "keep")  # created with the conftest waiver
        del db
        monkeypatch.delenv("AICS_DEV_GENESIS", raising=False)
        assert self.make(tmp_path, "keep").tlog_head()[0] == GENESIS_SIZE  # leaf 0 is not written again


# ---------------------------------------------------------------------------
# JSON nesting is bounded (no RecursionError 500)
# ---------------------------------------------------------------------------


class TestJsonDepth:
    def test_a_deep_notice_is_a_400_not_a_500(self, client):
        deep = b"[" * 12000 + b"]" * 12000  # inside the 32 KiB notice cap
        response = client.post("/notice", content=b'{"kind":' + deep + b"}", headers={"Content-Type": "application/json"})
        assert response.status_code == 400

    def test_the_bounded_parser(self):
        assert strictjson.loads_bounded('{"a": [1, {"b": 2}]}') == {"a": [1, {"b": 2}]}
        for text in ("[" * 40 + "]" * 40, "[1," * 40 + "1" + "]" * 40, "[" * 100000 + "]" * 100000):
            with pytest.raises(strictjson.JSONTooDeep):
                strictjson.loads_bounded(text)
        assert strictjson.loads_bounded("[" * 32 + "]" * 32) is not None

    def test_the_signed_request_parser_refuses_deep_bodies(self, client, make_agent):
        from fastapi import HTTPException

        from aics_server.auth import _json_object

        with pytest.raises(HTTPException) as info:
            _json_object(b'{"envelope":' + b"[" * 50000 + b"]" * 50000 + b"}")
        assert info.value.status_code == 400 and info.value.detail["error"] == "malformed_json"


# ---------------------------------------------------------------------------
# counters and the nonces of signed reads: in memory, written in batches
# ---------------------------------------------------------------------------


class TestBatchedState:
    def test_requests_are_counted_per_route_and_day_without_a_write(self, client):
        db = client.app.state.db
        before = db._conn.execute("SELECT COUNT(*) FROM telemetry_counters").fetchone()[0]
        for _ in range(3):
            client.get("/checkpoint")
        day = time.strftime("%Y-%m-%d", time.gmtime())
        counted = db.counters("http_requests:")
        assert counted[f"http_requests:{day}:GET /checkpoint"] == 3
        assert db._conn.execute("SELECT COUNT(*) FROM telemetry_counters").fetchone()[0] == before  # not yet written
        db.flush_counters()
        stored = dict(db._conn.execute("SELECT metric_key, metric_value FROM telemetry_counters").fetchall())
        assert stored[f"http_requests:{day}:GET /checkpoint"] >= 3
        assert db.counters("http_requests:")[f"http_requests:{day}:GET /checkpoint"] == stored[f"http_requests:{day}:GET /checkpoint"]

    def test_a_replayed_signed_read_is_refused_before_and_after_the_batch_is_written(self, client, make_agent):
        alice = make_agent("alice")
        db = client.app.state.db
        assert alice.get("/v2/agents/me").status_code == 200
        method, path, body, headers = alice.signer.last_request
        nonce = headers["Signature-Input"].split('nonce="', 1)[1].split('"', 1)[0]
        assert (alice.kid, nonce) in db._read_nonces  # remembered in memory, no disk sync of its own
        assert reason(client.request(method, path, content=body, headers=headers)) == "replay"
        with db._lock:
            db._flush_read_nonces()
        assert db._conn.execute("SELECT 1 FROM nonces WHERE kid = ? AND nonce = ?", (alice.kid, nonce)).fetchone()
        assert reason(client.request(method, path, content=body, headers=headers)) == "replay"

    def test_a_write_cannot_reuse_the_nonce_of_a_pending_read(self, client, make_agent):
        alice = make_agent("alice")
        nonce = envelope.new_nonce()
        assert alice.get("/v2/agents/me", nonce=nonce).status_code == 200
        response = alice.post(nonce=nonce)
        assert reason(response) == "replay"
        refusal = refusal_q(response)
        # A read writes no leaf: the replay has no accepted event to cite (AICS-1 section 10.2: null only then).
        assert refusal["attempt_nonce"] == nonce and refusal["conflict_index"] is None


# ---------------------------------------------------------------------------
# GET /v2/entries/{index}: the AICS-1 section 14.3 wire bundle, with the body the gate's fetch returns
# ---------------------------------------------------------------------------

#: ``(bundle, status)``: exactly the section 14.3 members, the body's status from ``X-AICS-Body-Status``.
wire_bundle = entry_bundle


class TestEntries:
    def test_stored_ciphertext_is_public_like_the_log(self, client, make_agent):
        alice, bob = make_agent("alice"), make_agent("bob")
        assert bob.grant(alice.kid, 3).status_code == 202
        sent = alice.send_dm(alice.lookup("bob"), "for bob only")
        index = leaf_index(sent)
        bundle, status = wire_bundle(client, index)  # no signature: anyone
        assert status == {"state": "available", "tombstone_index": None, "reason_code": None, "policy_index": None}
        assert keys.b64u_decode(bundle["body_or_ct"]) == alice.last_dm["ciphertext"]
        entry_bytes = keys.b64u_decode(bundle["entry_bytes"])
        assert entry_bytes == canonicalize(sent.json()["entry"]) and bundle["index"] == index
        assert bundle["envelope"] == sent.json()["entry"]["payload"]["envelope"]
        # What aics-tlog and aics-conformance read: the served bytes, as served, verify offline against the log key.
        db = client.app.state.db
        served = client.get(f"/v2/entries/{index}")
        assert served.headers["x-aics-body-status"] == "available"
        result = verify_bundle(served.content, parse_vkey(db.server_vkey), expected_origin=db.origin)
        assert result.ok, result.error
        assert result.aics1_entry and result.body_bound_at is not None
        assert Bundle.from_dict(bundle).to_dict() == bundle  # exactly the section 14.3 wire form
        receipt_of(client, sent.json())
        assert b"for bob only" not in keys.b64u_decode(bundle["body_or_ct"])

    def test_a_hidden_body_shows_its_tombstone(self, client, make_agent, owner):
        alice = make_agent("alice")
        index = leaf_index(alice.post())
        bundle, status = wire_bundle(client, index)
        assert bundle["body_or_ct"] is not None and status["state"] == "available"
        tomb = leaf_index(owner.tombstone(index, "illegal_on_notice"))
        bundle, status = wire_bundle(client, index)
        assert bundle["body_or_ct"] is None
        assert status == {"state": "tombstoned", "tombstone_index": tomb, "reason_code": "illegal_on_notice", "policy_index": None}
        header = client.get(f"/v2/entries/{index}").headers["x-aics-body-status"]
        assert header == f"tombstoned;tombstone_index={tomb};reason_code=illegal_on_notice"
        db = client.app.state.db
        assert verify_bundle(Bundle.from_dict(bundle), parse_vkey(db.server_vkey)).ok  # the leaf still proves
        assert client.get("/v2/entries/99999").status_code == 404

    def test_an_entry_without_a_body_has_no_body_status(self, client, make_agent):
        alice = make_agent("alice")
        bundle, status = wire_bundle(client, alice.head_index)  # a claim
        assert bundle["body_or_ct"] is None and status is None
        bundle, status = wire_bundle(client, 0)  # the charter: its document is at /v2/bodies/{document_hash}
        charter = json.loads(keys.b64u_decode(bundle["entry_bytes"]))
        assert status["state"] == "available"
        document = client.get(f"/v2/bodies/{charter['payload']['document_hash']}")
        assert document.status_code == 200
        assert hashlib.sha256(document.content).hexdigest() == charter["payload"]["document_hash"]

    def test_the_body_service_answers_by_hash(self, client, make_agent, owner):
        alice = make_agent("alice")
        posted = alice.post(title="By hash", body="Fetched by its hash.")
        digest = posted.json()["entry"]["payload"]["body_hash"]
        served = client.get(f"/v2/bodies/{digest}")
        assert served.status_code == 200 and served.headers["content-type"] == "application/octet-stream"
        assert hashlib.sha256(served.content).hexdigest() == digest == served.headers["x-aics-body-sha256"]
        assert json.loads(served.content)["text"] == "Fetched by its hash."
        assert client.get(f"/v2/bodies/{'0' * 64}").status_code == 404  # no entry names it: proves nothing
        tomb = leaf_index(owner.tombstone(leaf_index(posted), "erasure"))
        gone = client.get(f"/v2/bodies/{digest}")
        assert gone.status_code == 410
        assert gone.json() == {"state": "tombstoned", "tombstone_index": tomb, "reason_code": "erasure", "policy_index": None}


# ---------------------------------------------------------------------------
# the CLI runs housekeeping on a timer, so a quiet server still writes its daily report
# ---------------------------------------------------------------------------


def test_the_cli_timer_runs_housekeeping_and_survives_a_failure():
    import asyncio

    import uvicorn

    from aics_server.cli import GateServer

    class FakeDB:
        def __init__(self) -> None:
            self.calls = 0

        def housekeeping(self) -> bool:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("a disk hiccup")
            return True

    db = FakeDB()
    server = GateServer(uvicorn.Config(lambda scope, receive, send: None), None, db=db, tick_seconds=0.01)

    async def run_briefly() -> None:
        task = asyncio.create_task(server._housekeeping())
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run_briefly())
    assert db.calls >= 2  # the first failure did not stop the timer

"""The notice intake at /notice (DSA Art. 16; DESIGN.md sections 1 and 4.1; decision 16; AICS-1 section 12.1).

The one write path open to anyone, people included: it writes to the notice
register, never into content or the log.  Taking a notice writes no leaf; the
one leaf of a notice is the policy-signed ``report`` the owner writes on closing
it, ``{kind: notice, notice_hash, target_index, outcome_code, evidence_hash}``
(AICS-1 section 5.3).  The report id, the notice text and the notifier's
contact stay off the log, with a retention field, and are deleted 12 months
after the notice is closed.  Intake has its own global bucket, so notices
cannot use up the window of shared-secret claims.
"""

from __future__ import annotations

import json
import sqlite3
import time
from urllib.parse import urlencode

import pytest

from aics_identity import canonicalize, keys
from aics_server.db import NOTICE_OUTCOMES, NOTICE_RETENTION_SECONDS

from conftest import fetch_leaf, signed_request
from conftest import leaf_index, reason, secret_claim, secret_claim_reply

HTML = {"Accept": "text/html"}
FORM = {"Content-Type": "application/x-www-form-urlencoded"}
NOTICE = {
    "kind": "notice",
    "location": "leaf 12, the post titled Q-marker title",
    "explanation": "Q-marker explanation: this post shares stolen personal data, unlawful under GDPR Art. 6.",
    "name": "Q-marker Notifier",
    "email": "q-marker@example.invalid",
    "accurate": True,
}
MARKERS = ("Q-marker", "q-marker@example.invalid")


def send(client, **overrides):
    return client.post("/notice", json={**NOTICE, **overrides})


def rows(db_path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM notices ORDER BY received_at, report_id").fetchall()
    finally:
        conn.close()


class TestIntake:
    def test_taking_a_notice_writes_no_leaf(self, client, db_path):
        size = client.get("/v2/tlog/checkpoint").json()["tree_size"]
        response = send(client)
        assert response.status_code == 201, response.text
        body = response.json()
        # DESIGN.md section 4.1: the intake is not a write path into the log (the review's probe: +1 leaf per notice).
        assert client.get("/v2/tlog/checkpoint").json()["tree_size"] == size
        assert "entry" not in body and "merkle_proof" not in body and body["logged"] is False
        # AICS-1 section 16: the hash covers the record and a salt of 16 random bytes, kept and deleted with it.
        assert len(keys.b64u_decode(body["notice_salt"])) == 16
        expected = client.app.state.db.notice_sha256(
            "notice", NOTICE["location"], NOTICE["explanation"], None, body["notice_salt"]
        )
        assert body["notice_sha256"] == expected
        assert body["status"] == "received" and body["report_id"].startswith("dsa_")
        log = "\n".join(r[0] for r in client.app.state.db._conn.execute("SELECT leaf_json FROM tlog_leaves"))
        for marker in (*MARKERS, body["report_id"]):
            assert marker not in log

    def test_notices_have_their_own_global_bucket(self, tmp_path, owner):
        from fastapi.testclient import TestClient

        from aics_server.app import create_app

        limits = {"preidentity": {"count": 1, "interval_seconds": 60}, "notices": {"count": 1, "interval_seconds": 3600}}
        client = TestClient(create_app(db_path=tmp_path / "t.db", owner_public_key=owner.public_key_b64u,
                                       announce=False, limits=limits))
        assert send(client).status_code == 201
        assert send(client).status_code == 429  # the notice window (limits.notices) is full ...
        secret_claim(client, "plain")  # ... the pre-identity bucket of claims (at the TLS gate) is not
        _, _, text = secret_claim_reply(client, "other")
        assert text.startswith("err rate_limit "), text

    def test_the_notice_window_is_small_and_published(self, client):
        limits = client.app.state.db.limits
        assert limits["notices"] == {"count": 20, "interval_seconds": 3600} == client.get("/v2/limits").json()["limits"]["notices"]
        assert client.get("/notice", params={"format": "json"}).json()["limits"]["notices"] == limits["notices"]
        text = client.get("/notice").text
        assert "20 notices per 3600 s" in text and "1000" in text and "8000 bytes of UTF-8" in text

    def test_fields_are_bounded_in_utf8_bytes(self, client):
        wide = "\U0001F600" * 2001  # 2001 characters, 8004 bytes: over the 8000-byte explanation
        response = client.post("/notice", json={**NOTICE, "explanation": wide})
        assert response.status_code == 422 and "bytes of UTF-8" in response.text
        assert client.post("/notice", json={**NOTICE, "location": "\u00e9" * 501}).status_code == 422  # 1002 bytes
        assert client.post("/notice", json={**NOTICE, "explanation": "\U0001F600" * 2000}).status_code == 201
        with pytest.raises(ValueError, match="bytes of UTF-8"):
            client.app.state.db.create_notice("notice", "leaf 3", "x" * 8001)

    def test_open_notices_are_capped_by_count_and_bytes(self, tmp_path, owner):
        from fastapi.testclient import TestClient

        from aics_server.app import create_app

        limits = {"open_notices": 2, "open_notice_bytes": 8_000}
        client = TestClient(create_app(db_path=tmp_path / "t.db", owner_public_key=owner.public_key_b64u,
                                       announce=False, limits=limits))
        assert send(client).status_code == 201
        assert send(client).status_code == 201
        full = send(client)
        assert full.status_code == 503 and int(full.headers["retry-after"]) > 0
        assert "notice@wesupport-ai.com" in full.text
        register = client.get("/v2/limits").json()["notice_register"]
        assert (register["open"], register["max_open"], register["max_bytes"]) == (2, 2, 8_000)
        # Closing a notice frees the register; a large one is refused by the byte cap even below the count cap.
        report_id = client.app.state.db.list_notices("open")["notices"][0]["report_id"]
        client.app.state.db.close_notice(report_id, "declined")
        assert send(client, explanation="y" * 7990).status_code == 503
        assert send(client).status_code == 201

    def test_the_text_stays_off_the_log_with_a_retention_field(self, client, db_path):
        body = send(client).json()
        retention = body["retention"]
        assert retention["seconds_after_closing"] == NOTICE_RETENTION_SECONDS == 365 * 86400
        assert retention["closed_at"] is None and retention["delete_after"] is None
        assert "12 months" in retention["rule"] or "365 days" in retention["rule"]
        (row,) = rows(db_path)
        assert row["explanation"] == NOTICE["explanation"] and row["notifier_email"] == NOTICE["email"]
        assert row["closed_at"] is None and row["delete_after"] is None
        assert row["received_at"] == body["received_at"]

    def test_counter_notices_and_erasure_requests(self, client):
        first = send(client).json()
        counter = send(client, kind="counter_notice", report_id=first["report_id"], name="", email="")
        assert counter.status_code == 201, counter.text
        erasure = send(client, kind="erasure_request", location="my display name on leaf 3")
        assert erasure.status_code == 201
        assert send(client, kind="complaint").status_code == 422
        assert send(client, report_id="not-a-report-id").status_code == 422

    @pytest.mark.parametrize(
        "change",
        [
            {"accurate": False},
            {"accurate": "yes"},  # JSON takes a boolean
            {"explanation": "short"},
            {"location": ""},
            {"email": "not an address"},
            {"extra": "field"},
        ],
    )
    def test_invalid_notices_are_refused_without_a_leaf(self, client, change):
        size = client.get("/v2/tlog/checkpoint").json()["tree_size"]
        response = send(client, **change)
        assert response.status_code == 422, response.text
        assert isinstance(response.json()["detail"], list)
        assert client.get("/v2/tlog/checkpoint").json()["tree_size"] == size

    def test_other_bodies(self, client):
        assert client.post("/notice", content=b"x=1", headers={"Content-Type": "text/plain"}).status_code == 415
        assert client.post("/notice", content=b"{not json", headers={"Content-Type": "application/json"}).status_code == 400
        assert client.post("/notice", content=b"[]", headers={"Content-Type": "application/json"}).status_code == 400
        big = json.dumps({**NOTICE, "explanation": "x" * 40000}).encode()
        assert client.post("/notice", content=big, headers={"Content-Type": "application/json"}).status_code == 413

    def test_the_old_endpoint_is_gone(self, client):
        old = {"target_type": "post", "target_id": "pst_x", "reason": "This post seems unlawful to me."}
        assert client.post("/v2/moderation/report", json=old).status_code in (404, 405)
        assert "/v2/moderation/report" not in client.get("/openapi.json").json()["paths"]
        assert "/notice" in client.get("/openapi.json").json()["paths"]


class TestForm:
    def form(self, **overrides) -> bytes:
        fields = {**NOTICE, "accurate": "yes", **overrides}
        return urlencode({k: v for k, v in fields.items() if v is not None}).encode()

    def test_the_page_shows_the_form_and_the_procedure(self, client):
        page = client.get("/notice", headers=HTML)
        assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
        text = page.text
        assert '<form class="notice-form" method="post" action="/notice">' in text
        for field in ("kind", "location", "explanation", "name", "email", "report_id", "accurate"):
            assert f'name="{field}"' in text
        assert "pass through Cloudflare" in text and "12 months after the notice is closed" in text

    def test_a_form_notice_is_taken_and_confirmed(self, client, db_path):
        response = client.post("/notice", content=self.form(), headers={**FORM, **HTML})
        assert response.status_code == 201, response.text
        assert response.headers["content-type"].startswith("text/html")
        (row,) = rows(db_path)
        assert row["report_id"] in response.text and "Received" in response.text
        assert row["notifier_name"] == NOTICE["name"]

    def test_a_form_without_the_statement_is_shown_again_with_the_reason(self, client, db_path):
        response = client.post("/notice", content=self.form(accurate=None), headers=FORM)
        assert response.status_code == 422
        assert "accurate and complete" in response.text
        assert NOTICE["explanation"] in response.text  # the values are kept for a second try
        assert rows(db_path) == []
        assert client.post("/notice", content=b"location=x&unknown=1", headers=FORM).status_code == 400

    def test_the_global_limit_answers_the_form_too(self, tmp_path, owner):
        from fastapi.testclient import TestClient

        from aics_server.app import create_app

        limits = {"notices": {"count": 1, "interval_seconds": 3600}}
        client = TestClient(create_app(db_path=tmp_path / "t.db", owner_public_key=owner.public_key_b64u,
                                       announce=False, limits=limits))
        assert client.post("/notice", content=self.form(), headers=FORM).status_code == 201
        limited = client.post("/notice", content=self.form(), headers=FORM)
        assert limited.status_code == 429 and "retry later" in limited.text
        assert limited.headers["retry-after"]
        assert send(client).status_code == 429

    def test_agents_get_plain_instructions_and_the_schema(self, client):
        text = client.get("/notice")
        assert text.headers["content-type"].startswith("text/plain")
        assert "POST https://wesupport-ai.com/notice" in text.text and '"accurate": true' in text.text
        data = client.get("/notice", params={"format": "json"}).json()
        assert data["submit"] == "POST https://wesupport-ai.com/notice"
        assert set(data["schema"]["required"]) == {"location", "explanation", "accurate"}
        assert data["outcomes"] == list(NOTICE_OUTCOMES)


class TestOwnerClosesNotices:
    def owner_get(self, client, owner, path):
        response, _, _, _ = signed_request(client, owner, "GET", path, body_override=b"")
        return response

    def test_only_the_owner_reads_the_register(self, client, owner, make_agent):
        send(client)
        listing = self.owner_get(client, owner, "/v2/admin/notices")
        assert listing.status_code == 200, listing.text
        (notice,) = listing.json()["notices"]
        assert notice["explanation"] == NOTICE["explanation"] and notice["status"] == "open"
        agent = make_agent("curious")
        assert agent.get("/v2/admin/notices").status_code == 403
        assert client.get("/v2/admin/notices").status_code == 401

    def test_closing_writes_the_outcome_and_starts_the_retention_clock(self, client, owner, db_path):
        received = send(client).json()
        target = 0  # the leaf the notice was about, once found (here the charter)
        statement = "a statement of reasons"
        evidence = __import__("hashlib").sha256(statement.encode()).hexdigest()
        closing = {"outcome_code": "declined", "target_index": target, "evidence_hash": evidence}
        size = client.get("/v2/tlog/checkpoint").json()["tree_size"]
        response = owner.admin(f"/v2/admin/notices/{received['report_id']}/close", closing)
        assert response.status_code == 201, response.text
        body = response.json()
        assert client.get("/v2/tlog/checkpoint").json()["tree_size"] == size + 1  # the notice's one leaf
        assert body["entry"]["type"] == "report"
        assert body["entry"]["actor_kid"] == client.get("/v2/tlog/checkpoint").json()["policy_kid"]
        payload = {k: v for k, v in body["entry"]["payload"].items() if k != "envelope"}
        # AICS-1 section 5.3, the notice shape: a hash, an index and closed codes; the report id stays off the log.
        assert payload == {
            "kind": "notice", "notice_hash": received["notice_sha256"],
            "target_index": target, "outcome_code": "declined", "evidence_hash": evidence,
        }
        assert received["report_id"] not in json.dumps(body["entry"])
        notice = body["notice"]
        assert notice["status"] == "closed" and notice["outcome_index"] == body["merkle_proof"]["leaf_index"]
        assert notice["retention"]["delete_after"] == notice["retention"]["closed_at"] + NOTICE_RETENTION_SECONDS
        again = owner.admin(f"/v2/admin/notices/{received['report_id']}/close", closing)
        assert again.status_code == 409 and reason(again) == "notice_closed"
        bad = owner.admin(f"/v2/admin/notices/{received['report_id']}/close", {"outcome_code": "deleted"})
        assert bad.status_code == 422
        missing = owner.admin("/v2/admin/notices/dsa_000000000000/close", {"outcome_code": "duplicate"})
        assert missing.status_code == 404

    def test_the_text_and_contact_are_deleted_after_the_retention_period_and_the_leaves_stay(
        self, client, owner, db_path, monkeypatch
    ):
        received = send(client).json()
        closed = owner.admin(f"/v2/admin/notices/{received['report_id']}/close", {"outcome_code": "acted"})
        assert closed.status_code == 201
        db = client.app.state.db
        assert db.housekeeping(force=True)
        assert len(rows(db_path)) == 1  # kept until 12 months after closing
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + NOTICE_RETENTION_SECONDS + 5)
        assert db.housekeeping(force=True)
        assert rows(db_path) == []
        monkeypatch.setattr(time, "time", real)
        leaf = fetch_leaf(client, leaf_index(closed))
        assert leaf["leaf_data"]["payload"]["notice_hash"] == received["notice_sha256"]
        assert leaf["leaf_data"]["payload"]["outcome_code"] == "acted"
        conn = sqlite3.connect(db_path)
        try:
            dump = "\n".join(conn.iterdump())
        finally:
            conn.close()
        for marker in MARKERS:
            assert marker not in dump

    def test_an_open_notice_is_never_purged(self, client, db_path, monkeypatch):
        send(client)
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + 10 * NOTICE_RETENTION_SECONDS)
        assert client.app.state.db.housekeeping(force=True)
        assert len(rows(db_path)) == 1


def test_the_notice_hash_is_the_jcs_hash_of_the_notice_and_its_salt_without_its_contact(client):
    db = client.app.state.db
    salt = keys.b64u_encode(bytes(range(16)))
    digest = db.notice_sha256("notice", "leaf 1", "an explanation", None, salt)
    expected = __import__("hashlib").sha256(
        canonicalize(
            {"kind": "notice", "location": "leaf 1", "explanation": "an explanation", "cites_report_id": None, "salt": salt}
        )
    ).hexdigest()
    assert digest == expected
    # A guessed notice without the salt does not confirm the permanent hash (AICS-1 section 16).
    assert digest != db.notice_sha256("notice", "leaf 1", "an explanation", None, keys.b64u_encode(bytes(16)))


def test_two_equal_notices_get_different_hashes(client):
    first, second = send(client).json(), send(client).json()
    assert first["notice_salt"] != second["notice_salt"] and first["notice_sha256"] != second["notice_sha256"]


class TestClosingRules:
    """AICS-1 section 5.3: a counter-notice names the contested tombstone; an erasure request closed ``acted``
    accompanies an ``erasure`` tombstone of the same target."""

    def close(self, owner, report_id: str, outcome: str, target: int | None = None):
        return owner.admin(f"/v2/admin/notices/{report_id}/close", {"outcome_code": outcome, "target_index": target})

    def test_a_counter_notice_names_the_tombstone_it_contests(self, client, owner, make_agent):
        alice = make_agent("alice")
        target = leaf_index(alice.post(title="Contested", body="A post a notice objected to."))
        notice = send(client).json()
        tombstone = owner.tombstone(target, "illegal_on_notice", notice["notice_sha256"])
        assert tombstone.status_code == 201, tombstone.text
        hidden_by = leaf_index(tombstone)
        counter = send(client, kind="counter_notice", report_id=notice["report_id"], name="", email="").json()
        wrong = self.close(owner, counter["report_id"], "acted", target)  # the post, not the tombstone
        assert wrong.status_code == 400 and reason(wrong) == "not_a_tombstone"
        closed = self.close(owner, counter["report_id"], "acted", hidden_by)
        assert closed.status_code == 201, closed.text
        payload = closed.json()["entry"]["payload"]
        assert (payload["kind"], payload["target_index"], payload["outcome_code"]) == ("notice", hidden_by, "acted")
        # Reversing the decision keeps the tombstone (the author may post the body again).
        assert client.get("/v2/tombstones").json()["tombstones"][0]["tombstone_index"] == hidden_by

    def test_an_erasure_request_acted_follows_its_erasure_tombstone(self, client, owner, make_agent):
        alice = make_agent("alice")
        target = leaf_index(alice.post(title="About me", body="Personal details to erase."))
        request = send(client, kind="erasure_request", location=f"leaf {target}").json()
        early = self.close(owner, request["report_id"], "acted", target)
        assert early.status_code == 409 and reason(early) == "no_erasure_tombstone"
        assert owner.tombstone(target, "order").status_code == 201
        assert reason(self.close(owner, request["report_id"], "acted", target)) == "no_erasure_tombstone"
        other = leaf_index(alice.post(title="More", body="More details to erase."))
        assert owner.tombstone(other, "erasure").status_code == 201
        assert self.close(owner, request["report_id"], "acted", other).status_code == 201
        declined = send(client, kind="erasure_request", location="a body that is not personal data").json()
        assert self.close(owner, declined["report_id"], "declined").status_code == 201

    def test_the_salt_is_kept_with_the_record_and_deleted_with_it(self, client, owner, db_path, monkeypatch):
        notice = send(client).json()
        assert len(keys.b64u_decode(notice["notice_salt"])) >= 16
        (row,) = rows(db_path)
        assert row["salt"] == notice["notice_salt"]
        assert self.close(owner, notice["report_id"], "declined").status_code == 201
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + NOTICE_RETENTION_SECONDS + 5)
        assert client.app.state.db.housekeeping(force=True)
        assert rows(db_path) == []


class TestAudits:
    def test_an_audit_is_a_policy_signed_report_naming_its_published_document(self, client, owner):
        document = "Audit of the freeze of 2026-10-18: cause, actions taken and what changes."
        size = client.get("/v2/tlog/checkpoint").json()["tree_size"]
        response = owner.admin("/v2/admin/audits", {"document": document, "outcome_code": "published"})
        assert response.status_code == 201, response.text
        entry = response.json()["entry"]
        index = leaf_index(response)
        assert index == size and entry["type"] == "report"
        assert entry["actor_kid"] == client.get("/v2/tlog/checkpoint").json()["policy_kid"]
        payload = {k: v for k, v in entry["payload"].items() if k != "envelope"}
        data = document.encode("utf-8")
        assert payload == {
            "kind": "audit", "report_hash": __import__("hashlib").sha256(data).hexdigest(), "size": len(data),
            "outcome_code": "published",
        }
        assert document not in json.dumps(entry)
        served = client.get(f"/v2/policies/{index}")
        assert served.status_code == 200 and served.content == data
        assert served.headers["X-AICS-Policy-Kind"] == "audit"
        assert served.headers["X-AICS-Policy-SHA256"] == payload["report_hash"]
        resolved = owner.admin("/v2/admin/audits", {"document": "Resolved: the follow-up is done.", "outcome_code": "resolved"})
        assert resolved.status_code == 201 and resolved.json()["entry"]["payload"]["outcome_code"] == "resolved"

    def test_only_closed_outcomes_and_only_the_owner(self, client, owner, make_agent):
        assert owner.admin("/v2/admin/audits", {"document": "x", "outcome_code": "acted"}).status_code == 422
        assert owner.admin("/v2/admin/audits", {"document": "", "outcome_code": "published"}).status_code == 422
        alice = make_agent("alice")
        response, _, _, _ = signed_request(
            client, alice.signer, "POST", "/v2/admin/audits", fields={"document": "x", "outcome_code": "published"}
        )
        assert response.status_code == 403
        assert client.post("/v2/admin/audits", json={"document": "x", "outcome_code": "published"}).status_code == 401

    def test_a_freeze_report_is_published_too(self, client, owner):
        frozen = owner.freeze("frozen", "incident", "Investigating an incident.")
        index = leaf_index(frozen)
        served = client.get(f"/v2/policies/{index}")
        assert served.content == b"Investigating an incident." and served.headers["X-AICS-Policy-Kind"] == "freeze"

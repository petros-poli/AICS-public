"""Shared test fakes: an in-process AICS API and DSA Transparency Database.

Both fakes are ``ThreadingHTTPServer`` instances bound to 127.0.0.1 on
ephemeral ports; no test ever touches the real network. The fixture log
reproduces every leaf kind AICS-1 defines so tests can prove the scan keeps
only the real restrictions (3 restriction tombstones + 2 suspensions).
"""

from __future__ import annotations

import base64
import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from dsa_submitter import schema, tdb

# A long random-looking token, deliberately unlike anything in a payload.
TOKEN = "X|ybqkCFX7ZkIFoLxtI0VAk1JBzMR9jVk4c4EU"


# ---------------------------------------------------------------------------
# The fixture log
# ---------------------------------------------------------------------------

def ts(day, hour=0, minute=0, second=0):
    """Unix time of 2026-01-<day>T<hour>:<minute>:<second>Z."""
    return int(datetime(2026, 1, day, hour, minute, second, tzinfo=UTC).timestamp())


def full_hash(n):
    """A distinct 64-character lowercase hex hash."""
    return f"{n:064x}"


ACTOR_KID = "did:key:test"
ENVELOPE = {"alg": "Ed25519", "kid": ACTOR_KID}

# The five real restrictions in the fixture log.
LEAF_TOMBSTONE_ILLEGAL = 2
LEAF_TOMBSTONE_ORDER = 4
LEAF_TOMBSTONE_SECRET = 6
LEAF_SUSPENSION_FLOOD = 10
LEAF_SUSPENSION_ORDER = 11
RESTRICTION_LEAVES = (
    LEAF_TOMBSTONE_ILLEGAL,
    LEAF_TOMBSTONE_ORDER,
    LEAF_TOMBSTONE_SECRET,
    LEAF_SUSPENSION_FLOOD,
    LEAF_SUSPENSION_ORDER,
)
TREE_SIZE = 15


def _entry(entry_type, entry_ts, payload):
    return {"v": 2, "origin": "test", "type": entry_type, "actor_kid": ACTOR_KID,
            "ts": entry_ts, "payload": payload}


def fixture_log():
    """Every entry and tombstone projection row the fake serves.

    Indexes are consistent between the tombstone listing and the entry store.
    """
    entries = [
        _entry("post", ts(1), {"envelope": ENVELOPE, "content_type": "text"}),
        _entry("post", ts(2, 3, 4, 5), {"envelope": ENVELOPE, "content_type": "text"}),
        _entry("tombstone", ts(6, 7, 8, 9), {
            "envelope": ENVELOPE, "target_index": 1,
            "reason_code": "illegal_on_notice",
            "evidence_hash": full_hash(0x101), "receipt_hash": full_hash(0x102)}),
        _entry("post", ts(3, 10), {"envelope": ENVELOPE, "content_type": "text"}),
        _entry("tombstone", ts(7, 11), {
            "envelope": ENVELOPE, "target_index": 3, "reason_code": "order",
            "evidence_hash": full_hash(0x201), "receipt_hash": None}),
        _entry("post", ts(4, 12), {"envelope": ENVELOPE, "content_type": "text"}),
        _entry("tombstone", ts(8, 13), {
            "envelope": ENVELOPE, "target_index": 5, "reason_code": "secret_format",
            "evidence_hash": None, "receipt_hash": full_hash(0x301)}),
        _entry("tombstone", ts(9, 14), {
            "envelope": ENVELOPE, "target_index": 0, "reason_code": "erasure",
            "evidence_hash": None, "receipt_hash": None}),
        _entry("refusal", ts(10, 15), {
            "envelope": ENVELOPE, "envelope_hash": full_hash(0x401),
            "request_hash": None, "attempt_kid": None, "attempt_nonce": None,
            "attempt_expires": None, "reason_code": "malformed",
            "conflict_index": None, "receipt_hash": None}),
        _entry("freeze", ts(11, 16), {
            "envelope": ENVELOPE, "state": "frozen", "reason_code": "maintenance",
            "report_hash": full_hash(0x501), "prev_freeze_index": None}),
        # A bounded flood suspension: until is its own ts + 120 seconds.
        _entry("suspension", ts(12, 23, 59, 0), {
            "envelope": ENVELOPE, "target_kid": "did:key:z6MkFloodAgent",
            "reason_code": "flood", "until": ts(13, 0, 1, 0),
            "evidence_hash": full_hash(0x601)}),
        _entry("suspension", ts(12, 8), {
            "envelope": ENVELOPE, "target_kid": "did:key:z6MkOrderAgent",
            "reason_code": "order", "until": None,
            "evidence_hash": full_hash(0x602)}),
        # The ending event: until equals its own ts, so it is not a restriction.
        _entry("suspension", ts(14, 9), {
            "envelope": ENVELOPE, "target_kid": "did:key:z6MkFloodAgent",
            "reason_code": "flood", "until": ts(14, 9), "evidence_hash": None}),
        _entry("report", ts(14, 10), {
            "envelope": ENVELOPE, "kind": "notice", "notice_hash": full_hash(0x701),
            "target_index": 5, "outcome_code": "acted", "evidence_hash": None}),
        _entry("post", ts(15, 6), {"envelope": ENVELOPE, "content_type": "text"}),
    ]
    rows = [
        {"tombstone_index": 2, "target_index": 1, "target_type": "post",
         "reason_code": "illegal_on_notice"},
        {"tombstone_index": 4, "target_index": 3, "target_type": "post",
         "reason_code": "order"},
        {"tombstone_index": 6, "target_index": 5, "target_type": "post",
         "reason_code": "secret_format"},
        {"tombstone_index": 7, "target_index": 0, "target_type": "post",
         "reason_code": "erasure"},
    ]
    return entries, rows


# ---------------------------------------------------------------------------
# The fake AICS API
# ---------------------------------------------------------------------------

class FakeAics:
    """Serves /checkpoint, /v2/tlog/checkpoint, /v2/tombstones, /v2/entries/{i}.

    ``config`` keys, mutable per test: ``checkpoint_text`` (raw note override;
    set garbage to force the JSON fallback), ``hide_entries`` (a set of entry
    indexes answered with 404) and ``tombstones_override`` (a list swapped in
    as the full tombstone row set, e.g. 1001 rows to drive pagination).
    """

    def __init__(self):
        self.entries, self.rows = fixture_log()
        self.tree_size = TREE_SIZE
        self.config = {"checkpoint_text": None, "hide_entries": set(),
                       "tombstones_override": None}
        self.queries = []  # (path, {query parameter: value})

    def handle_get(self, target):
        parsed = urlparse(target)
        query = {key: values[0] for key, values in parse_qs(parsed.query).items()}
        self.queries.append((parsed.path, query))
        if parsed.path == "/checkpoint":
            text = self.config["checkpoint_text"]
            if text is None:
                text = f"test origin\n{self.tree_size}\n{full_hash(1)}\n"
            return 200, "text/plain", text.encode("utf-8")
        if parsed.path == "/v2/tlog/checkpoint":
            return self._json({"tree_size": self.tree_size})
        if parsed.path == "/v2/tombstones":
            rows = self.config["tombstones_override"] or self.rows
            since = int(query.get("since", "0"))
            limit = int(query.get("limit", "1000"))
            page = [row for row in rows if row["tombstone_index"] >= since][:limit]
            return self._json({"count": len(page), "tombstones": page,
                               "tree_size": self.tree_size})
        if parsed.path.startswith("/v2/entries/"):
            tail = parsed.path.rsplit("/", 1)[1]
            try:
                index = int(tail)
            except ValueError:
                return self._json({"message": "not an entry index"}, status=404)
            hidden = index in self.config["hide_entries"]
            if hidden or not 0 <= index < len(self.entries):
                return self._json({"message": "entry not found"}, status=404)
            entry = self.entries[index]
            raw = json.dumps(entry, separators=(",", ":")).encode("utf-8")
            encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
            return self._json({
                "entry_bytes": encoded, "index": index, "inclusion_proof": [],
                "checkpoint_note": f"test origin\n{self.tree_size}\n{full_hash(1)}",
                "envelope": entry["payload"]["envelope"], "body_or_ct": None})
        return self._json({"message": "not found"}, status=404)

    @staticmethod
    def _json(payload, status=200):
        return status, "application/json", json.dumps(payload).encode("utf-8")


# ---------------------------------------------------------------------------
# The fake Transparency Database
# ---------------------------------------------------------------------------

class FakeTdb:
    """Serves POST /api/v1/statement with configurable behaviours.

    ``config`` keys: ``mode`` one of "ok" (201), "duplicate" (422 carrying
    ``existing``), "reject_422", "reject_429" (plain text), "flaky_5xx" (500
    ``flaky_remaining`` times, then ok) and "echo_token_body" (500 whose body
    contains the raw token, to prove redaction). Every request is recorded in
    ``statements`` (parsed bodies), ``paths`` and ``headers_seen``;
    ``request_count`` counts every POST, authenticated or not.
    """

    def __init__(self):
        self.token = TOKEN
        self.config = {"mode": "ok", "flaky_remaining": 0}
        self.request_count = 0
        self.statements = []
        self.paths = []
        self.headers_seen = []

    def handle_post(self, target, headers, body):
        self.request_count += 1
        self.paths.append(target)
        self.headers_seen.append(dict(headers))
        if headers.get("Authorization") != f"Bearer {self.token}":
            return self._json(401, {"message": "unauthorized"})
        if ("application/json" not in headers.get("Accept", "")
                or "application/json" not in headers.get("Content-Type", "")):
            return self._json(400, {"message": "Accept and Content-Type must be JSON"})
        try:
            statement = json.loads(body)
        except json.JSONDecodeError:
            return self._json(422, {"message": "malformed body", "errors": {}})
        self.statements.append(statement)

        mode = self.config["mode"]
        if mode == "echo_token_body":
            raw = f'{{"message": "upstream exploded near {self.token}"}}'
            return 500, "application/json", raw.encode("utf-8")
        if mode == "reject_429":
            return 429, "text/plain", b"Too Many Requests"
        if mode == "flaky_5xx" and self.config["flaky_remaining"] > 0:
            self.config["flaky_remaining"] -= 1
            return self._json(500, {"message": "internal error"})

        errors = schema.validate_statement(statement)
        if mode == "reject_422" and not errors:
            errors = ["category: rejected by policy for this test"]
        if errors:
            grouped = {}
            for message in errors:
                grouped.setdefault(message.split(":", 1)[0], []).append(message)
            return self._json(422, {"message": "The given data was invalid.",
                                    "errors": grouped})
        if mode == "duplicate":
            not_unique = "The identifier given is not unique within this platform."
            return self._json(422, {
                "message": not_unique,
                "errors": {"puid": [not_unique]},
                "existing": self._created(statement, uuid="existing-uuid",
                                          identifier=999)})
        return self._json(201, self._created(statement))

    @staticmethod
    def _created(statement, uuid="uuid-1", identifier=123):
        created = dict(statement)
        created.update({
            "uuid": uuid, "id": identifier,
            "permalink": f"https://statement.example/{identifier}",
            "created_at": "2026-10-19T00:00:00Z",
            "self": f"https://statement.example/{identifier}",
        })
        return created

    @staticmethod
    def _json(status, payload):
        return status, "application/json", json.dumps(payload).encode("utf-8")


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------

class _FakeAicsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        status, content_type, body = self.server.fake.handle_get(self.path)
        _respond(self, status, content_type, body)

    def log_message(self, *args):
        return


class _FakeTdbHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        status, content_type, response = self.server.fake.handle_post(
            self.path, dict(self.headers.items()), body)
        _respond(self, status, content_type, response)

    def log_message(self, *args):
        return


def _respond(handler, status, content_type, body):
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _serve(fake, handler_class):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
    server.fake = fake
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    fake.url = f"http://127.0.0.1:{server.server_address[1]}"
    return server, thread


@pytest.fixture()
def fake_aics():
    fake = FakeAics()
    server, thread = _serve(fake, _FakeAicsHandler)
    yield fake
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.fixture()
def fake_tdb():
    fake = FakeTdb()
    server, thread = _serve(fake, _FakeTdbHandler)
    yield fake
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Operator decisions helpers
# ---------------------------------------------------------------------------

def illegal_decision(leaf_index, **overrides):
    """A valid illegal-content decision record for ``leaf_index``."""
    record = {
        "leaf_index": leaf_index,
        "category": "STATEMENT_CATEGORY_ILLEGAL_OR_HARMFUL_SPEECH",
        "decision_ground": "DECISION_GROUND_ILLEGAL_CONTENT",
        "territorial_scope": ["GR"],
        "source_type": "SOURCE_ARTICLE_16",
        "automated_detection": "No",
        "automated_decision": "AUTOMATED_DECISION_NOT_AUTOMATED",
        "application_date": "2026-10-20",
    }
    record.update(overrides)
    return record


def incompatible_decision(leaf_index, **overrides):
    """A valid incompatible-content decision record for ``leaf_index``."""
    record = {
        "leaf_index": leaf_index,
        "category": "STATEMENT_CATEGORY_OTHER_VIOLATION_TC",
        "decision_ground": "DECISION_GROUND_INCOMPATIBLE_CONTENT",
        "territorial_scope": ["GR"],
        "source_type": "SOURCE_VOLUNTARY",
        "automated_detection": "Yes",
        "automated_decision": "AUTOMATED_DECISION_FULLY",
        "application_date": "2026-10-20",
        "incompatible_content_illegal": "No",
    }
    record.update(overrides)
    return record


def default_decision(leaf_index):
    """The operator decision used for ``leaf_index`` in submit-path tests."""
    if leaf_index == LEAF_SUSPENSION_FLOOD:
        # until (2026-01-13) must not precede the application date.
        return incompatible_decision(leaf_index, application_date="2026-01-12",
                                     incompatible_content_illegal="Yes")
    if leaf_index == LEAF_TOMBSTONE_SECRET:
        return incompatible_decision(leaf_index)
    return illegal_decision(leaf_index)


def all_decisions():
    return {index: default_decision(index) for index in RESTRICTION_LEAVES}


def write_decisions(path, decisions):
    """Write ``{leaf_index: record}`` as a JSONL file; returns a str path."""
    path = str(path)
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(json.dumps(record) + "\n" for record in decisions.values())
    return path


@pytest.fixture()
def decisions_file(tmp_path):
    """Factory writing a decisions JSONL file into tmp_path; returns its path."""
    def _write(decisions):
        return write_decisions(tmp_path / "dsa-decisions.jsonl", decisions)
    return _write


@pytest.fixture()
def state_path(tmp_path):
    return str(tmp_path / "state.json")


@pytest.fixture()
def tdb_env(fake_tdb):
    """A fresh env dict pointing cmd_submit at the fake database."""
    return {"DSA_TRANSPARENCY_TOKEN": fake_tdb.token,
            "DSA_TRANSPARENCY_URL": fake_tdb.url + "/api/v1/statement"}


@pytest.fixture()
def recording_sleeps(monkeypatch):
    """Make cmd_submit's client record backoff sleeps instead of sleeping.

    The sleeper default is bound at def time (``sleeper=time.sleep``), so
    patching ``tdb.time.sleep`` would not reach it; the client factory itself
    is wrapped to inject ``sleeps.append``.
    """
    sleeps = []
    real_client = tdb.TransparencyClient

    def factory(url, token, **kwargs):
        kwargs["sleeper"] = sleeps.append
        return real_client(url, token, **kwargs)

    monkeypatch.setattr(tdb, "TransparencyClient", factory)
    return sleeps


# ---------------------------------------------------------------------------
# A hand-built valid statement (no fixtures needed) for client/schema tests
# ---------------------------------------------------------------------------

def minimal_statement(puid="aics-leaf-2"):
    return {
        "puid": puid,
        "category": "STATEMENT_CATEGORY_ILLEGAL_OR_HARMFUL_SPEECH",
        "decision_ground": "DECISION_GROUND_ILLEGAL_CONTENT",
        "decision_visibility": ["DECISION_VISIBILITY_CONTENT_DISABLED"],
        "illegal_content_legal_ground": "The law relied on is named beside leaf 2.",
        "illegal_content_explanation": "Assessed under the notice procedure.",
        "decision_facts": "A fixed template sentence pointing at the public log.",
        "content_type": ["CONTENT_TYPE_TEXT"],
        "content_date": "2026-01-02",
        "application_date": "2026-10-20",
        "territorial_scope": ["GR"],
        "source_type": "SOURCE_ARTICLE_16",
        "automated_detection": "No",
        "automated_decision": "AUTOMATED_DECISION_NOT_AUTOMATED",
    }

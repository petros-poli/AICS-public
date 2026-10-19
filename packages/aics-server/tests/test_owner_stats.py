"""The owner stats page's data and endpoint (docs/internal/owner-stats-design.md, ``GET /v2/admin/stats``).

Every access class, route group and outcome is counted from real requests;
the daily rollup is written by the batched counter flush and read back as
memory plus table; the gate funnel is counted without a session or key
identifier; activity comes from the log; the endpoint is owner-signed like
the other ``/v2/admin`` routes.  Nothing stored or returned carries an
address, a user agent, a key, a name, a session id or content.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import json
import re
import secrets
import sqlite3
import time
from importlib import metadata
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.routing import APIRoute
from starlette.routing import Mount

from aics_identity import http_signatures as hs
from aics_server import identity as ident
from aics_server import stats as st
from aics_server.db import SCHEMA_VERSION
from aics_server.gate import SESSION_IDLE_SECONDS, TcpGate
from aics_server.tlog_store import PublishedCheckpoint
from aics_tlog import parse_note
from aics_tlog.cosign import cosignature_vkey, sign_cosignature
from aics_tlog.note import format_vkey

from conftest import (
    B,
    H,
    J,
    U,
    KeyAgent,
    Line,
    Signer,
    https,
    ok_line,
    onboard,
    proposal,
    question,
    secret_claim,
    signed_request,
)
from test_gate import _exchange, _read_turn, _self_signed

HTML = {"Accept": "text/html"}
DAY = re.compile(r"\d{4}-\d{2}-\d{2}\Z")


def stats(client, owner, days: int | None = None, *, fresh: bool = True):
    """The owner's signed ``GET /v2/admin/stats`` (the cache emptied first unless *fresh* is false)."""
    if fresh:
        client.app.state.owner_stats._cache.clear()
    path = "/v2/admin/stats" + (f"?days={days}" if days is not None else "")
    components = hs.AICS_COMPONENTS + (("@query",) if "?" in path else ())
    response, _, _, _ = signed_request(client, owner, "GET", path, body_override=b"", components=components)
    return response


def doc_of(client, owner, days: int | None = None) -> dict:
    response = stats(client, owner, days)
    assert response.status_code == 200, response.text
    return response.json()


def memory(client) -> dict:
    """What the recorder holds now: ``{(class, group, outcome): count}`` for today."""
    requests, _, _ = client.app.state.db.stats.snapshot()
    today = st.utc_day()
    return {key[1:]: value for key, value in requests.items() if key[0] == today}


def counted(client, cls: str, group: str, outcome: str) -> int:
    return memory(client).get((cls, group, outcome), 0)


@pytest.fixture()
def quiet(client):
    """The client with the recorder emptied of the fixture's own requests (exact counts follow)."""
    client.app.state.db.stats.drain()
    return client


def gate_events(client) -> dict[str, int]:
    _, _, gate = client.app.state.db.stats.snapshot()
    today = st.utc_day()
    return {event: value for (day, event), value in gate.items() if day == today}


# ----------------------------------------------------------------------
# the closed lists and the rules that map a request onto them
# ----------------------------------------------------------------------


class TestClosedLists:
    def test_the_lists_are_the_designs(self):
        assert st.ACCESS_CLASSES == ("agent-gate", "agent-signed", "program", "person", "owner", "notice")
        assert st.ROUTE_GROUPS == (
            "pages", "docs", "llms", "card", "tiles", "checkpoint", "api-read", "api-write", "gate", "notice", "admin",
            "health", "other",
        )
        assert st.OUTCOMES == ("2xx", "3xx", "4xx-refused-with-leaf", "4xx-other", "429", "5xx")
        assert st.LATENCY_BOUNDS_MS == (50, 100, 250, 500, 1000, 5000)

    @pytest.mark.parametrize(
        ("method", "template", "group"),
        [
            ("GET", "/", "pages"),
            ("GET", "/agora", "pages"),
            ("GET", "/foundry", "pages"),
            ("GET", "/stats", "pages"),
            ("GET", "/docs", "docs"),
            ("GET", "/openapi.json", "docs"),
            ("GET", "/charter", "docs"),
            ("GET", "/static", "docs"),
            ("GET", "/llms.txt", "llms"),
            ("GET", "/robots.txt", "llms"),
            ("GET", "/sitemap.xml", "llms"),
            ("GET", "/.well-known/agent-protocol.json", "llms"),
            ("GET", "/card", "card"),
            ("GET", "/.well-known/aics-card.json", "card"),
            ("GET", "/tiles/tile/{resource:path}", "tiles"),
            ("GET", "/tiles", "tiles"),
            ("GET", "/checkpoint", "checkpoint"),
            ("GET", "/tiles/checkpoint", "checkpoint"),
            ("GET", "/v2/tlog/checkpoint", "checkpoint"),
            ("GET", "/v2/names/{name}", "api-read"),
            ("POST", "/v2/entries", "api-write"),
            ("POST", "/t", "gate"),
            ("GET", "/t", "gate"),
            ("POST", "/notice", "notice"),
            ("GET", "/notice", "notice"),
            ("GET", "/v2/admin/stats", "admin"),
            ("POST", "/v2/admin/freeze", "admin"),
            ("GET", "/healthz", "health"),
            ("GET", "/v2/stats", "health"),
            ("GET", st.UNMATCHED, "other"),
            ("POST", "/", "other"),
        ],
    )
    def test_route_groups(self, method, template, group):
        assert st.route_group(method, template) == group

    def test_the_template_never_takes_a_client_path(self):
        route = SimpleNamespace(path="/v2/names/{name}")
        assert st.template_of(route, "/v2/names/alice") == "/v2/names/{name}"
        assert st.template_of(None, "/openapi.json") == "/openapi.json"
        assert st.template_of(None, "/static/aics_client.py") == "/static"
        assert st.template_of(None, "/v2/names/alice/../../etc") == st.UNMATCHED
        assert st.template_of(None, "/203.0.113.9") == st.UNMATCHED

    def test_every_route_of_the_app_maps_into_the_list(self, client):
        groups = set()
        for route in client.app.routes:
            if isinstance(route, APIRoute):
                for method in route.methods:
                    groups.add(st.route_group(method, route.path))
            elif isinstance(route, Mount):
                groups.add(st.route_group("GET", route.path))
        assert groups <= set(st.ROUTE_GROUPS)
        assert groups >= set(st.ROUTE_GROUPS) - {"other"}  # every group but the fallback has a route

    @pytest.mark.parametrize(
        ("path", "method", "accept", "signed", "cls"),
        [
            ("/t", "POST", "", None, "agent-gate"),
            ("/t", "GET", "text/html", None, "agent-gate"),
            ("/v2/entries", "POST", "", "agent-signed", "agent-signed"),
            ("/v2/agents/me", "GET", "text/html", "agent-signed", "agent-signed"),
            ("/v2/admin/stats", "GET", "", "owner", "owner"),
            ("/v2/admin/stats", "GET", "", None, "program"),
            ("/notice", "POST", "", None, "notice"),
            ("/notice", "GET", "text/html,application/xhtml+xml", None, "person"),
            ("/notice", "GET", "*/*", None, "program"),
            ("/llms.txt", "GET", "text/html", None, "program"),
            ("/.well-known/aics-card.json", "GET", "text/html", None, "program"),
            ("/sitemap.xml", "GET", "text/html", None, "program"),
            ("/tiles/tile/0/000", "GET", "text/html", None, "program"),
            ("/checkpoint", "GET", "text/html", None, "program"),
            ("/robots.txt", "GET", "text/html", None, "program"),
            ("/v2/names/alice", "GET", "text/html", None, "program"),
            ("/", "GET", "text/html", None, "person"),
            ("/agora", "GET", "TEXT/HTML;q=0.9", None, "person"),
            ("/", "GET", "application/json", None, "program"),
            ("/", "GET", "", None, "program"),
        ],
    )
    def test_access_classes(self, path, method, accept, signed, cls):
        assert st.access_class(path=path, method=method, accept=accept, signed=signed) == cls

    @pytest.mark.parametrize(
        ("status", "leaf", "outcome"),
        [
            (200, False, "2xx"), (201, False, "2xx"), (202, False, "2xx"), (204, False, "2xx"),
            (301, False, "3xx"), (304, False, "3xx"),
            (400, False, "4xx-other"), (401, False, "4xx-other"), (403, False, "4xx-other"), (404, False, "4xx-other"),
            (409, True, "4xx-refused-with-leaf"), (422, True, "4xx-refused-with-leaf"),
            (429, False, "429"), (429, True, "429"),
            (500, False, "5xx"), (503, False, "5xx"),
        ],
    )
    def test_outcome_classes(self, status, leaf, outcome):
        assert st.outcome_class(status, refusal_leaf=leaf) == outcome

    def test_latency_buckets_and_percentiles(self):
        assert [st.latency_bucket(ms) for ms in (0, 50, 51, 100, 249, 500, 999, 5000, 5001)] == [0, 0, 1, 1, 2, 3, 4, 5, 6]
        assert st.percentile_bound([0] * 7, 0.5, None) is None
        buckets = [90, 5, 3, 1, 0, 0, 1]  # 100 samples
        assert st.percentile_bound(buckets, 0.50, 7000) == 50
        assert st.percentile_bound(buckets, 0.95, 7000) == 100
        assert st.percentile_bound(buckets, 0.99, 7000) == 500
        assert st.percentile_bound(buckets, 1.0, 7000) == 7000  # past the last bound: the day's max
        summary = st.latency_summary([*buckets, 7000, 12345])
        assert summary["samples"] == 100 and summary["max_ms"] == 7000 and summary["mean_ms"] == 123.5
        assert summary["buckets"] == dict(zip(st.LATENCY_BUCKETS, buckets))

    def test_the_recorder_takes_closed_list_values_only(self):
        recorder = st.StatsRecorder()
        for bad in (("ip:203.0.113.9", "pages", "2xx"), ("person", "/v2/names/alice", "2xx"), ("person", "pages", "418")):
            with pytest.raises(ValueError):
                recorder.count_request(*bad)
        with pytest.raises(ValueError):
            recorder.count_gate("session:abc123")
        recorder.count_request("person", "pages", "2xx", 12.4)
        recorder.count_gate("help")
        drained = recorder.drain()
        assert recorder.snapshot() == ({}, {}, {})
        recorder.restore(drained)
        recorder.restore(drained)
        requests, latency, gate = recorder.snapshot()
        assert list(requests.values()) == [2] and list(gate.values()) == [2]
        (row,) = latency.values()
        assert row[0] == 2 and row[-2] == 12 and row[-1] == 24


# ----------------------------------------------------------------------
# every class, group and outcome from real requests
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("quiet")
class TestCountedRequests:
    def test_agent_gate(self, client):
        Line(client).send()
        Line(client, get=True).send("help")
        assert counted(client, "agent-gate", "gate", "2xx") == 2

    def test_agent_signed_writes_reads_and_refusals_with_a_leaf(self, client, make_agent, origin):
        alice = make_agent("alice")
        assert counted(client, "agent-signed", "api-write", "2xx") == 1
        assert alice.get("/v2/agents/me").status_code == 200
        assert counted(client, "agent-signed", "api-read", "2xx") == 1
        # A claim of a taken name: a refusal leaf in a 4xx answer.
        refused = make_agent().claim("alice")
        assert 400 <= refused.status_code < 500 and refused.status_code != 429, refused.text
        assert counted(client, "agent-signed", "api-write", "4xx-refused-with-leaf") == 1
        # A request whose signature does not verify is no agent-signed request.
        mallory = Signer()
        response, _, _, _ = signed_request(client, mallory, "GET", "/v2/agents/me", body_override=b"")
        assert response.status_code == 401
        assert counted(client, "program", "api-read", "4xx-other") == 1

    def test_program(self, client):
        client.get("/llms.txt")
        client.get("/llms.txt", headers=HTML)  # a machine resource, whatever the Accept header says
        client.get("/checkpoint")
        client.get("/v2/names/nobody-here")
        client.get("/no/such/path")
        client.get("/", headers={"Accept": "application/json"})
        assert counted(client, "program", "llms", "2xx") == 2
        assert counted(client, "program", "checkpoint", "2xx") == 1
        assert counted(client, "program", "api-read", "4xx-other") == 1
        assert counted(client, "program", "other", "4xx-other") == 1
        assert counted(client, "program", "pages", "2xx") == 1

    def test_person(self, client):
        assert client.get("/", headers=HTML).status_code == 200
        assert client.get("/foundry", headers=HTML, follow_redirects=False).status_code == 301
        assert counted(client, "person", "pages", "2xx") == 1
        assert counted(client, "person", "pages", "3xx") == 1

    def test_notice(self, client):
        from test_notice import send

        assert send(client).status_code == 201
        assert counted(client, "notice", "notice", "2xx") == 1
        assert client.get("/notice", headers=HTML).status_code == 200
        assert counted(client, "person", "notice", "2xx") == 1

    def test_owner_and_the_unauthenticated_admin_requests(self, client, owner, make_agent):
        assert stats(client, owner).status_code == 200
        assert counted(client, "owner", "admin", "2xx") == 1
        assert client.get("/v2/admin/stats").status_code == 401
        assert make_agent("eve").get("/v2/admin/stats").status_code == 403
        assert counted(client, "program", "admin", "4xx-other") == 2
        assert counted(client, "owner", "admin", "4xx-other") == 0

    def test_health_docs_card_tiles(self, client):
        client.get("/healthz")
        client.get("/v2/stats")
        client.get("/openapi.json")
        client.get("/.well-known/aics-card.json")
        client.get("/tiles/tile/0/000")
        assert counted(client, "program", "health", "2xx") == 2
        assert counted(client, "program", "docs", "2xx") == 1
        assert counted(client, "program", "card", "2xx") == 1
        assert sum(v for (c, g, _), v in memory(client).items() if g == "tiles") == 1

    def test_a_429_and_a_5xx(self, client, monkeypatch):
        db = client.app.state.db
        # The notice intake's own window answers 429 once exhausted (no notice taken).
        from test_notice import send

        statuses = [send(client, explanation=f"Explanation number {i} of a test notice, long enough.").status_code for i in range(40)]
        assert 429 in statuses
        assert counted(client, "notice", "notice", "429") == statuses.count(429)

        def broken(*args, **kwargs):
            raise RuntimeError("a test fault")

        monkeypatch.setattr(db, "health", broken)
        from fastapi.testclient import TestClient

        quiet = TestClient(client.app, raise_server_exceptions=False)
        assert quiet.get("/healthz").status_code == 500
        assert counted(client, "program", "health", "5xx") == 1

    def test_latency_samples_per_route_group(self, client):
        for _ in range(3):
            client.get("/llms.txt")
        _, latency, _ = client.app.state.db.stats.snapshot()
        row = latency[(st.utc_day(), "llms")]
        assert sum(row[: len(st.LATENCY_BUCKETS)]) == 3 and row[-2] >= 0


# ----------------------------------------------------------------------
# the daily rollup: written by the batched flush, read back as table plus memory
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("quiet")
class TestRollup:
    def test_flush_writes_stats_daily_and_the_document_does_not_change(self, client, owner, db_path):
        db = client.app.state.db
        for _ in range(4):
            client.get("/llms.txt")
        client.get("/", headers=HTML)
        Line(client).send("help")
        before = doc_of(client, owner)
        conn = sqlite3.connect(db_path)
        assert conn.execute("SELECT COUNT(*) FROM stats_daily").fetchone()[0] == 0  # in memory only, no disk sync
        db.flush_counters()
        assert db.stats.snapshot() == ({}, {}, {})
        rows = conn.execute("SELECT day, class, route_group, outcome, count FROM stats_daily").fetchall()
        assert (st.utc_day(), "program", "llms", "2xx", 4) in rows
        assert (st.utc_day(), "person", "pages", "2xx", 1) in rows
        assert conn.execute("SELECT event, count FROM stats_gate_daily").fetchall() == [("help", 1), ("session.https", 1)]
        (llms,) = conn.execute("SELECT le50 + le100 + le250 + le500 + le1000 + le5000 + gt5000 FROM stats_latency_daily WHERE route_group = 'llms'").fetchall()
        assert llms == (4,)
        conn.close()
        after = doc_of(client, owner)
        # The owner's first stats request was counted in between; everything else reads the same from the table.
        for doc in (before, after):
            doc["requests"]["totals"]["by_class"]["owner"] = 0
        assert before["requests"]["totals"]["by_group"]["llms"] == after["requests"]["totals"]["by_group"]["llms"] == 4
        assert before["gate"]["totals"] == after["gate"]["totals"]
        assert before["latency"]["window"]["llms"]["samples"] == after["latency"]["window"]["llms"]["samples"] == 4

    def test_a_second_flush_adds_and_never_double_counts(self, client, owner):
        db = client.app.state.db
        client.get("/llms.txt")
        db.flush_counters()
        client.get("/llms.txt")
        db.flush_counters()
        db.flush_counters()
        doc = doc_of(client, owner)
        assert doc["requests"]["totals"]["by_group"]["llms"] == 2
        today = doc["requests"]["daily"][-1]
        assert today["day"] == st.utc_day() and today["by_group"]["llms"] == 2

    def test_a_failed_flush_keeps_the_counts(self, client, monkeypatch):
        db = client.app.state.db
        client.get("/llms.txt")

        def fail(conn, drained):
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(st, "write_drained", fail)
        with pytest.raises(sqlite3.OperationalError):
            db.flush_counters()
        assert counted(client, "program", "llms", "2xx") == 1
        monkeypatch.undo()
        db.flush_counters()
        assert db._conn.execute("SELECT SUM(count) FROM stats_daily WHERE route_group = 'llms'").fetchone()[0] == 1

    def test_housekeeping_flushes_the_rollup(self, client):
        db = client.app.state.db
        client.get("/llms.txt")
        db.housekeeping(force=True)
        assert db._conn.execute("SELECT SUM(count) FROM stats_daily WHERE route_group = 'llms'").fetchone()[0] == 1

    def test_earlier_days_come_from_the_table(self, client, owner):
        db = client.app.state.db
        yesterday = time.time() - 86400
        db.stats.count_request("person", "pages", "2xx", 30, now=yesterday)
        db.stats.count_gate("tools.python3", now=yesterday)
        db.flush_counters()
        doc = doc_of(client, owner, days=2)
        assert [d["day"] for d in doc["requests"]["daily"]] == [st.utc_day(yesterday), st.utc_day()]
        assert doc["requests"]["daily"][0]["by_class"]["person"] == 1
        assert doc["latency"]["daily"][0]["groups"]["pages"]["p50_ms"] == 50
        assert doc["gate"]["daily"][0]["tools"]["python3"] == 1
        assert doc_of(client, owner, days=1)["requests"]["totals"]["by_class"]["person"] == 0

    def test_the_tables_hold_closed_list_keys_and_counts_only(self, client, owner, make_agent, db_path):
        alice = make_agent("qmarkalice")
        alice.get("/v2/agents/me")
        line = Line(client)
        line.send("help")
        client.get("/", headers={**HTML, "User-Agent": "Q-marker-browser/1.0"})
        client.get("/v2/admin/stats")
        client.app.state.db.flush_counters()
        conn = sqlite3.connect(db_path)
        try:
            for table, allowed in (
                ("stats_daily", {"day", "class", "route_group", "outcome", "count"}),
                ("stats_latency_daily", {"day", "route_group", *st.LATENCY_BUCKETS, "max_ms", "total_ms"}),
                ("stats_gate_daily", {"day", "event", "count"}),
            ):
                assert {r[1] for r in conn.execute(f"PRAGMA table_info({table})")} == allowed
            for day, cls, group, outcome, count in conn.execute("SELECT * FROM stats_daily"):
                assert DAY.match(day) and cls in st.ACCESS_CLASSES and group in st.ROUTE_GROUPS
                assert outcome in st.OUTCOMES and isinstance(count, int)
            for row in conn.execute("SELECT * FROM stats_latency_daily"):
                assert DAY.match(row[0]) and row[1] in st.ROUTE_GROUPS and all(isinstance(v, int) for v in row[2:])
            for day, event, count in conn.execute("SELECT * FROM stats_gate_daily"):
                assert DAY.match(day) and event in st.GATE_EVENTS and isinstance(count, int)
            everything = "\n".join(
                repr(row)
                for table in ("stats_daily", "stats_latency_daily", "stats_gate_daily")
                for row in conn.execute(f"SELECT * FROM {table}")
            )
        finally:
            conn.close()
        for secret in (alice.kid, "qmarkalice", line.sid, "Q-marker", "testclient"):
            assert secret not in everything


# ----------------------------------------------------------------------
# the gate funnel
# ----------------------------------------------------------------------


def _upgrade(client, name: str) -> None:
    """An unverified name moved to a key at the TLS gate (AICS-1 section 11.4), as test_gate does it."""
    secret = "upgrade-me-" + secrets.token_urlsafe(32)
    identity = secret_claim(client, name, secret)
    assert identity.unverified_id
    agent = KeyAgent(name)
    line = Line(https(client))
    line.send()
    line.send("tools openssl")
    line.send(f"pub {B(agent.ed_raw)}")
    line.send(f"enc {B(agent.x_raw)}")
    line.send("recovery none")
    line.send(f"name {name}")
    text = line.send(f"secret {secret}")
    message = base64.b64decode(ok_line(text, "ok signing-input ").split(" ")[2])
    sig_new = {"scheme": "ed25519", "signature": U(agent.key.sign(message))}
    text = line.send(f"proof {U(J(sig_new))}")
    unsigned = proposal(text)
    command = f"claim-upgrade {name} {H(J(unsigned))}"
    line.send(command)
    text = line.send(agent.sig(line.sid, command))
    assert f"ok name {name} upgraded to key {agent.kid}" in text, text


@pytest.mark.usefixtures("quiet")
class TestGateFunnel:
    def test_every_funnel_event(self, client, owner):
        gate = client.app.state.gate
        Line(client).send("help")
        for tool in ("openssl", "ssh-keygen", "python3", "none"):
            Line(client).send(f"tools {tool}")
        bad = Line(client)
        bad.send()
        bad.send("nonsense", "nonsense", "nonsense")
        assert bad.send() .startswith("err session_unknown")  # ended by the malformed-line limit
        onboard(Line(client), KeyAgent("gatekey"))
        onboard(Line(client), KeyAgent("gatethird"), tool="none")
        secret_claim(client, "gatesecret")
        _upgrade(client, "gateupgrade")
        idle = Line(client)
        idle.send()
        session, _ = gate.sessions.get(idle.sid)
        session.last_used -= SESSION_IDLE_SECONDS + 1
        gate.sweep()
        assert idle.send().startswith("err session_unknown")  # gone, and counted once

        events = gate_events(client)
        assert events["help"] == 1
        assert events["end.malformed"] == 1
        assert events["end.idle"] == 1
        assert events["claim.key"] == 1 and events["claim.third-party"] == 1 and events["claim.secret"] == 2
        assert events["upgrade"] == 1
        assert events["tools.ssh-keygen"] == 1 and events["tools.python3"] == 1
        assert events["tools.none"] == 1 + 1 + 2  # the probe, the third-party claim, both fallbacks
        assert events["tools.openssl"] == 1 + 1 + 1  # the probe, the key claim, the upgrade's new key
        doc = doc_of(client, owner)
        funnel = doc["gate"]["totals"]
        assert funnel["sessions_opened"]["https"] == funnel["sessions_opened"]["total"] == events["session.https"]
        assert funnel["help"] == 1 and funnel["upgrades"] == 1 and funnel["ended_malformed"] == 1
        assert funnel["idle_expired"] == 1
        assert funnel["claims"] == {"key": 1, "third-party": 1, "secret": 2}
        assert funnel["tools"] == {"openssl": 3, "ssh-keygen": 1, "python3": 1, "none": 4}
        assert doc["gate"]["daily"][-1]["claims"] == funnel["claims"]
        assert doc["gate"]["max_sessions"] == gate.limits.max_sessions
        assert isinstance(doc["gate"]["sessions_open"], int)
        assert idle.sid not in json.dumps(doc) and bad.sid not in json.dumps(doc)

    def test_an_expired_session_found_by_lookup_counts_once(self, client):
        gate = client.app.state.gate
        line = Line(client)
        line.send()
        session, _ = gate.sessions.get(line.sid)
        session.last_used -= SESSION_IDLE_SECONDS + 1
        assert line.send("help").startswith("err session_unknown")
        gate.sweep()
        assert gate_events(client)["end.idle"] == 1

    def test_tcp_connections_are_agent_gate_requests(self, client):
        gate = client.app.state.gate

        async def main() -> None:
            tcp = TcpGate(gate, host="127.0.0.1", plain_port=0, tls_port=None, idle_seconds=0.3)
            await tcp.start()
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", tcp.ports["plain"])
                await _read_turn(reader)
                await _exchange(reader, writer, "help")
                await _exchange(reader, writer, "quit")
                writer.close()
                reader, writer = await asyncio.open_connection("127.0.0.1", tcp.ports["plain"])
                await _read_turn(reader)
                assert (await _read_turn(reader)).startswith("err session_expired")
                writer.close()
            finally:
                await tcp.close()

        asyncio.run(main())
        assert counted(client, "agent-gate", "gate", "2xx") == 2
        events = gate_events(client)
        assert events["session.tcp-plain"] == 2 and events["help"] == 1 and events["end.idle"] == 1
        _, latency, _ = client.app.state.db.stats.snapshot()
        assert (st.utc_day(), "gate") not in latency  # a TCP session is no latency sample


# ----------------------------------------------------------------------
# the endpoint
# ----------------------------------------------------------------------


class TestEndpoint:
    def test_owner_signed_only(self, client, owner, make_agent):
        assert client.get("/v2/admin/stats").status_code == 401
        assert make_agent("notowner").get("/v2/admin/stats").status_code == 403
        tampered, _, _, _ = signed_request(client, owner, "GET", "/v2/admin/stats", body_override=b"", send_path="/v2/admin/stats?days=2")
        assert tampered.status_code == 401
        # A replayed owner request is refused (its nonce is spent), like every owner read.
        assert stats(client, owner).status_code == 200
        method, path, sent, headers = owner.last_request
        replay = client.request(method, path, content=sent, headers=headers)
        assert replay.status_code == 409 and replay.json()["detail"]["error"] == "replay"
        assert client.post("/v2/admin/stats").status_code == 405

    def test_no_owner_key_no_stats(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AICS_OWNER_PUBKEY", raising=False)
        from fastapi.testclient import TestClient

        from aics_server.app import create_app
        from conftest import TEST_LIMITS

        app = create_app(db_path=tmp_path / "no-owner.db", pubkeys_out=tmp_path / "keys.txt", announce=False, limits=TEST_LIMITS)
        signer = Signer()
        response, _, _, _ = signed_request(TestClient(app), signer, "GET", "/v2/admin/stats", body_override=b"")
        assert response.status_code == 503

    def test_days(self, client, owner):
        doc = doc_of(client, owner)
        assert doc["days"] == 30 and len(doc["requests"]["daily"]) == 30
        assert doc["window"]["to"] == st.utc_day() and doc["requests"]["daily"][-1]["day"] == st.utc_day()
        days = [d["day"] for d in doc["requests"]["daily"]]
        assert days == sorted(days) and len(set(days)) == 30
        for section in (doc["latency"]["daily"], doc["gate"]["daily"], doc["activity"]["leaves"]["daily"],
                        doc["activity"]["refusals"]["daily"], doc["activity"]["names"]["claimed_daily"]):
            assert [d["day"] for d in section] == days
        assert len(doc_of(client, owner, days=1)["requests"]["daily"]) == 1
        assert len(doc_of(client, owner, days=366)["requests"]["daily"]) == 366
        for bad in (0, 367, -1):
            assert stats(client, owner, bad).status_code == 422

    def test_cached_for_ten_seconds(self, client, owner):
        first = doc_of(client, owner)
        client.get("/llms.txt")
        again = stats(client, owner, fresh=False).json()
        assert again == first  # served from the cache
        cache = client.app.state.owner_stats._cache
        stamp, doc = cache[30]
        cache[30] = (stamp - 11, doc)
        later = stats(client, owner, fresh=False).json()
        assert later["requests"]["totals"]["by_group"]["llms"] == first["requests"]["totals"]["by_group"]["llms"] + 1

    def test_the_document_shape(self, client, owner):
        doc = doc_of(client, owner)
        assert set(doc) == {
            "generated_at", "days", "window", "lists", "requests", "latency", "gate", "activity", "health", "witness",
            "pages_host",
        }
        assert doc["lists"]["access_classes"] == list(st.ACCESS_CLASSES)
        assert doc["lists"]["gate_events"] == list(st.GATE_EVENTS)
        assert set(doc["requests"]) == {"daily", "totals", "by_group_outcome", "by_class_outcome", "by_class_group", "rows"}
        assert set(doc["requests"]["by_group_outcome"]) == set(st.ROUTE_GROUPS)
        assert set(doc["activity"]) == {
            "leaves", "refusals", "names", "keys", "swarms", "messages", "capsules", "hidden_bodies", "notices", "freeze",
            "sup",
        }
        for row in doc["requests"]["rows"]:
            assert set(row) == {"day", "class", "route_group", "outcome", "count"}

    def test_the_endpoint_is_documented(self, client):
        spec = client.get("/openapi.json").json()
        description = spec["paths"]["/v2/admin/stats"]["get"]["description"]
        for member in ('"requests"', '"latency"', '"gate"', '"activity"', '"health"', '"witness"', "p95_ms", "by_class"):
            assert member in description
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        assert "GET /v2/admin/stats" in readme and "stats_daily" in readme


# ----------------------------------------------------------------------
# activity derived from the log
# ----------------------------------------------------------------------


class TestActivity:
    def test_leaves_names_keys_refusals_hidden_notices_freeze(self, client, owner, make_agent, origin):
        from test_notice import send

        alice = make_agent("alice")
        bob = make_agent("bob")
        post = alice.post("A title", "A body long enough to post.")
        assert post.status_code == 202, post.text
        assert make_agent().claim("alice").status_code == 409  # name_taken: a refusal leaf
        assert bob.rotate(Signer()).status_code == 202
        assert bob.revoke().status_code == 202
        secret_claim(client, "sammy")
        from conftest import leaf_index

        assert owner.tombstone(leaf_index(post), "illegal_on_notice").status_code == 201
        noticed = send(client)
        send(client, explanation="A second notice, explained at enough length to be taken.")
        closing = {"outcome_code": "declined", "target_index": None, "evidence_hash": None}
        assert owner.admin(f"/v2/admin/notices/{noticed.json()['report_id']}/close", closing).status_code == 201
        assert owner.freeze("frozen", "maintenance", "Planned maintenance.").status_code == 201

        activity = doc_of(client, owner)["activity"]
        leaves = activity["leaves"]
        today = leaves["daily"][-1]
        assert today["by_type"]["name.claim"] == 3 and today["by_type"]["post"] == 1
        assert today["by_type"]["refusal"] == 1 and today["by_type"]["tombstone"] == 1
        assert today["total"] == sum(today["by_type"].values()) == leaves["tree_size"] == client.get("/v2/tlog/checkpoint").json()["tree_size"]
        assert leaves["all_time"]["policy"] == 1  # leaf 0, the charter
        assert activity["refusals"]["daily"][-1] == {
            "day": st.utc_day(), "source": "live", "report_index": None, "total": 1, "by_code": {"name_taken": 1},
        }
        assert activity["refusals"]["window"] == {"name_taken": 1}
        names = activity["names"]
        assert names["total"] == 3
        assert names["claimed_by_tier"] == {"key": 2, "third-party": 0, "secret": 1}
        assert names["claimed_daily"][-1] == {"day": st.utc_day(), "key": 2, "third-party": 0, "secret": 1}
        assert names["current_by_tier"] == {"key": 1, "third-party": 0, "secret": 1, "revoked": 1}
        assert activity["keys"]["window"] == {"rotations": 1, "upgrades": 0, "x25519_rotations": 0, "revocations": 1}
        assert activity["keys"]["all_time"] == activity["keys"]["window"]
        assert activity["hidden_bodies"]["by_reason"] == {"illegal_on_notice": 1} and activity["hidden_bodies"]["total"] == 1
        notices = activity["notices"]
        assert notices["open"] == 1 and notices["closed"] == 1 and notices["closed_by_outcome"] == {"declined": 1}
        assert notices["received_in_window"] == 2 and notices["open_bytes"] > 0
        assert activity["freeze"]["state"] == "frozen" and activity["freeze"]["reason_code"] == "maintenance"
        assert activity["sup"]["profile"] == "AICS-1+SUP-1"
        assert activity["swarms"]["window"]["swarm.form"] == 0

    def test_refusals_per_code_come_from_the_daily_report_once_written(self, client, owner, make_agent):
        make_agent("alice")
        make_agent().claim("alice")
        db = client.app.state.db
        (report_index,) = db.write_daily_reports(int(time.time()) + 86400)  # today's report, as if the day had ended
        refusals = doc_of(client, owner)["activity"]["refusals"]
        assert refusals["daily"][-1] == {
            "day": st.utc_day(), "source": "report", "report_index": report_index, "total": 1, "by_code": {"name_taken": 1},
        }

    def test_tasks_awards_and_spends(self, client, owner, make_agent, chain):
        from test_sup import award

        alice = make_agent("alice")
        award(client, owner, alice, 40)
        assert alice.spend("hosting", 15).status_code == 202
        sup = doc_of(client, owner)["activity"]["sup"]
        assert sup["active"] is True and sup["contributions_open"] is True
        assert sup["tasks_published"] == 1
        assert sup["credits"]["window"] == {"contribution": {"count": 0, "sup": 0}, "task": {"count": 1, "sup": 40}}
        assert sup["spends"]["window"]["hosting"] == {"count": 1, "sup": 15}
        assert sup["spends"]["all_time"] == sup["spends"]["window"]
        assert sup["balance_outstanding"] == 25

    def test_the_document_names_no_agent_session_or_notifier(self, client, owner, make_agent):
        from test_notice import MARKERS, send

        alice = make_agent("qmarkeralice")
        alice.post("Q-marker title", "Q-marker body of a post long enough.")
        line = Line(client)
        line.send("help")
        send(client)
        identity = secret_claim(client, "qmarkersecret")
        text = json.dumps(doc_of(client, owner))
        for secret in (alice.kid, "qmarkeralice", "qmarkersecret", identity.unverified_id, line.sid, *MARKERS, "testclient"):
            assert secret not in text


# ----------------------------------------------------------------------
# health and witness
# ----------------------------------------------------------------------


class TestHealthAndWitness:
    def test_health(self, client, owner):
        health = doc_of(client, owner)["health"]
        assert health["status"] == "OPERATIONAL" == health["healthz"]["status"]
        assert set(health["healthz"]) == set(client.get("/healthz").json())
        assert set(health["usage"]) == set(client.get("/v2/stats").json()["usage"])
        assert set(client.get("/v2/stats").json()["host"]) <= set(health["host"]) and "disk_free_bytes" in health["host"]
        assert health["tiles"]["tree_size"] == health["healthz"]["tree_size"]
        assert health["tiles_bytes"] > 0
        assert 0 <= health["checkpoint_age_seconds"] < 120 and 0 <= health["seconds_since_tile_write"] < 120
        assert health["schema_version"] == SCHEMA_VERSION
        assert health["versions"]["aics-server"] == metadata.version("aics-server")
        assert health["versions"]["api"] == client.app.version
        assert health["uptime_seconds"] >= 0
        assert health["tls_certificate"] == {"configured": False, "not_after": None, "seconds_left": None, "error": None}
        assert health["budgets"]["ciphertext"]["budget_bytes"] == client.app.state.db.limits["ciphertext_budget_bytes"]

    def test_the_gate_certificate_expiry(self, client, owner, tmp_path, monkeypatch):
        cert_path, _ = _self_signed(tmp_path, 7)
        monkeypatch.setenv("AICS_GATE_TLS_CERT", str(cert_path))
        cert = doc_of(client, owner)["health"]["tls_certificate"]
        assert cert["configured"] is True and cert["error"] is None
        assert 86400 < cert["seconds_left"] <= 2 * 86400  # issued a day ago for three days
        assert datetime.datetime.strptime(cert["not_after"], "%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("AICS_GATE_TLS_CERT", str(tmp_path / "missing.crt"))
        cert = doc_of(client, owner)["health"]["tls_certificate"]
        assert cert["configured"] is True and cert["seconds_left"] is None and cert["error"] == "FileNotFoundError"

    def test_no_witness_yet(self, client, owner):
        witness = doc_of(client, owner)["witness"]
        assert witness["quorum"] == 0 and witness["witnesses"] == [] and witness["cosignatures"] == 0
        assert witness["quorum_met"] is False and witness["state"] == "no_witness" and witness["g5"] == "promised"

    def test_cosignatures_on_the_current_checkpoint(self, client, owner, monkeypatch):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        db = client.app.state.db
        witness_key = Ed25519PrivateKey.generate()
        vkey = format_vkey(cosignature_vkey("witness.example", witness_key.public_key()))
        policy = {"quorum": 1, "witnesses": [{"name": "witness.example", "vkey": vkey, "trust_domain": "x", "independent": True}]}
        served = SimpleNamespace(card={"witness_policy": policy})
        monkeypatch.setattr(client.app.state.owner_stats, "card", SimpleNamespace(current=lambda: served))
        witness = doc_of(client, owner)["witness"]
        assert witness["cosignatures"] == 0 and witness["quorum_met"] is False and witness["state"] == "quorum_not_met"
        assert witness["witnesses"] == [{"name": "witness.example", "independent": True}]

        published = db._log.published
        note = parse_note(published.note)
        _, line = sign_cosignature(witness_key, "witness.example", int(time.time()), db.origin, published.size, published.root)
        cosigned = type(note)(text=note.text, signatures=(*note.signatures, line)).to_bytes()
        monkeypatch.setattr(db._log, "_published", PublishedCheckpoint(published.size, published.root, cosigned))
        witness = doc_of(client, owner)["witness"]
        assert witness["cosignatures"] == 1 and witness["cosigned_by"] == ["witness.example"]
        assert witness["quorum_met"] is True and witness["state"] == "quorum_met"
        assert witness["checkpoint_size"] == published.size


# ----------------------------------------------------------------------
# cost: the leaf table is read by type and time, all-time totals grow by the new leaves only, the tiles walk is
# never in the request
# ----------------------------------------------------------------------


def _read_only(db) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{db.db_path.resolve()}?mode=ro", uri=True, isolation_level=None)


def _full_totals(db):
    from aics_server.owner_stats import LogTotals

    totals = LogTotals()
    conn = _read_only(db)
    try:
        conn.execute("BEGIN")
        totals.refresh(conn)
    finally:
        conn.close()
    return totals


def _same_totals(a, b) -> None:
    assert a.next_index == b.next_index
    assert a.by_type == b.by_type and a.daily_types == b.daily_types and a.rotate_upgrades == b.rotate_upgrades
    assert a.notice_outcomes == b.notice_outcomes and a.claims_daily == b.claims_daily
    assert a.credits == b.credits and a.spends == b.spends


class TestCost:
    def test_the_leaf_table_is_indexed_by_type_and_time(self, client, make_agent):
        from aics_server.owner_stats import LogTotals

        make_agent("alice")
        conn = _read_only(client.app.state.db)

        class Explained:
            """Runs each statement after recording SQLite's plan for it."""

            def __init__(self):
                self.plans: list[str] = []

            def execute(self, sql, args=()):
                self.plans.append(" | ".join(str(r[-1]) for r in conn.execute("EXPLAIN QUERY PLAN " + sql, args)))
                return conn.execute(sql, args)

        try:
            indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'tlog_leaves'")}
            assert {"tlog_leaves_by_type", "tlog_leaves_by_time"} <= indexes
            window = "SELECT COUNT(*) FROM tlog_leaves WHERE event_type = 'key.rotate' AND created_at >= ?"
            assert "tlog_leaves_by_type (event_type=? AND created_at>?)" in " ".join(
                str(r[-1]) for r in conn.execute("EXPLAIN QUERY PLAN " + window, ("2026-01-01",))
            )
            first = Explained()
            LogTotals()._add(first, 0, 10)  # nothing counted yet: by type
            assert any("tlog_leaves_by_type" in plan for plan in first.plans)
            delta = Explained()
            LogTotals()._add(delta, 1000, 1010)  # a short span after many counted leaves: by leaf_index only
            for plan in delta.plans:
                assert "INTEGER PRIMARY KEY (rowid>? AND rowid<?)" in plan and "tlog_leaves_by_type" not in plan, plan
                assert "SCAN" not in plan, plan
        finally:
            conn.close()

    def test_all_time_totals_add_only_the_new_leaves(self, client, owner, make_agent, chain, monkeypatch):
        from test_notice import send
        from test_sup import award

        db = client.app.state.db
        totals = client.app.state.owner_stats._totals
        make_agent("alice")
        doc_of(client, owner)
        size = db._log.tree.size
        assert totals.next_index == size
        _same_totals(totals, _full_totals(db))

        spans: list[tuple[int, int]] = []
        add = totals._add
        monkeypatch.setattr(totals, "_add", lambda conn, lo, hi: (spans.append((lo, hi)), add(conn, lo, hi))[1])
        bob = make_agent("bob")
        assert bob.rotate(Signer()).status_code == 202
        secret_claim(client, "sammy")
        award(client, owner, bob, 30)
        assert bob.spend("hosting", 5).status_code == 202
        noticed = send(client)
        closing = {"outcome_code": "declined", "target_index": None, "evidence_hash": None}
        assert owner.admin(f"/v2/admin/notices/{noticed.json()['report_id']}/close", closing).status_code == 201
        activity = doc_of(client, owner)["activity"]
        grown = db._log.tree.size
        assert spans == [(size, grown - 1)]  # the second build read only the leaves after the mark
        _same_totals(totals, _full_totals(db))
        assert activity["leaves"]["tree_size"] == grown
        assert activity["names"]["claimed_by_tier"] == {"key": 2, "third-party": 0, "secret": 1}
        assert activity["keys"]["all_time"]["rotations"] == 1
        assert activity["notices"]["closed_by_outcome"] == {"declined": 1}
        assert activity["sup"]["credits"]["all_time"]["task"] == {"count": 1, "sup": 30}
        assert activity["sup"]["spends"]["all_time"]["hosting"] == {"count": 1, "sup": 5}

        doc_of(client, owner)  # no new leaf: nothing is read for the totals
        assert spans == [(size, grown - 1)]

    def test_a_shorter_table_or_a_failed_read_starts_again(self, client, owner, make_agent, monkeypatch):
        db = client.app.state.db
        totals = client.app.state.owner_stats._totals
        make_agent("alice")
        doc_of(client, owner)
        totals.next_index = 10**9  # a mark past the table (another database): everything is counted again
        totals.by_type["post"] = 10**6
        assert doc_of(client, owner)["activity"]["leaves"]["tree_size"] == db._log.tree.size
        _same_totals(totals, _full_totals(db))

        make_agent("bob")

        def broken(conn, lo, hi):
            raise sqlite3.OperationalError("disk I/O error")

        monkeypatch.setattr(totals, "_add", broken)
        client.app.state.owner_stats._cache.clear()
        with pytest.raises(sqlite3.OperationalError):
            client.app.state.owner_stats.document(DEFAULT_DAYS_FOR_TESTS)
        assert totals.next_index == 0 and totals.by_type == {}
        monkeypatch.undo()
        doc_of(client, owner)
        _same_totals(totals, _full_totals(db))

    def test_the_tiles_size_is_walked_in_the_background(self, client, owner, monkeypatch):
        import threading

        from aics_server import owner_stats as os_mod

        stats_ = client.app.state.owner_stats
        released, calls = threading.Event(), []

        def slow(path):
            calls.append(path)
            assert released.wait(10)
            return 1234 if len(calls) == 1 else 999

        monkeypatch.setattr(os_mod, "dir_bytes", slow)
        monkeypatch.setattr(os_mod, "TILES_FIRST_WAIT_SECONDS", 0.05)
        with stats_._tiles_lock:
            stats_._tiles_bytes, stats_._tiles_walk = None, None

        started = time.monotonic()
        assert doc_of(client, owner)["health"]["tiles_bytes"] is None  # the first walk is still running
        assert doc_of(client, owner)["health"]["tiles_bytes"] is None and len(calls) == 1  # one walk at a time
        assert time.monotonic() - started < 5
        released.set()
        stats_._tiles_walk and stats_._tiles_walk.join(5)
        assert doc_of(client, owner)["health"]["tiles_bytes"] == 1234
        assert len(calls) == 1  # a fresh value starts no walk

        released.clear()
        with stats_._tiles_lock:
            stats_._tiles_bytes = (time.monotonic() - os_mod.TILES_BYTES_CACHE_SECONDS - 1, 1234)
        started = time.monotonic()
        assert doc_of(client, owner)["health"]["tiles_bytes"] == 1234  # stale: served at once, a walk started
        assert time.monotonic() - started < 5 and len(calls) == 2
        released.set()
        stats_._tiles_walk and stats_._tiles_walk.join(5)
        assert doc_of(client, owner)["health"]["tiles_bytes"] == 999

    def test_dir_bytes_counts_the_files(self, tmp_path):
        from aics_server.owner_stats import dir_bytes

        (tmp_path / "tile" / "0").mkdir(parents=True)
        (tmp_path / "tile" / "0" / "000").write_bytes(b"x" * 64)
        (tmp_path / "checkpoint").write_bytes(b"y" * 10)
        assert dir_bytes(tmp_path) == 74


DEFAULT_DAYS_FOR_TESTS = 30


class TestOwnerNativeWrites:
    def test_the_owner_keys_native_writes_count_as_owner(self, quiet, owner, chain):
        response = owner.task(title="A task the owner publishes", reward=10)
        assert response.status_code == 202, response.text
        assert counted(quiet, "owner", "api-write", "2xx") == 1
        assert counted(quiet, "agent-signed", "api-write", "2xx") == 0

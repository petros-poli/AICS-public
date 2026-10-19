"""The owner tool's stats commands: ``owner stats`` and ``owner dashboard`` (docs/internal/owner-stats-design.md).

``owner stats`` prints the owner-signed ``GET /v2/admin/stats`` document (JSON or a text summary).
``owner dashboard`` serves one self-contained page and ``/data`` on 127.0.0.1 only; every ``/data`` signs a
fresh request with the owner key held in the process.  The page is rendered here without a browser: its
inline script runs under Node against a small DOM shim and a fake stats document (skipped without Node).
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import shutil
import subprocess
import urllib.parse
from pathlib import Path

import pytest

from aics_server import stats as st
from test_client_sdk import _load_sdk, route_to_testclient

DAYS = ["2026-10-13", "2026-10-14", "2026-10-15", "2026-10-16", "2026-10-17", "2026-10-18", "2026-10-19"]


@pytest.fixture(scope="module")
def sdk():
    return _load_sdk("aics_client_dashboard")


# ----------------------------------------------------------------------
# a fake stats document: every section non-zero, in the endpoint's shape
# ----------------------------------------------------------------------


def fake_document() -> dict:
    classes, groups, outcomes = list(st.ACCESS_CLASSES), list(st.ROUTE_GROUPS), list(st.OUTCOMES)
    daily, rows = [], []
    totals = {"total": 0, "by_class": dict.fromkeys(classes, 0), "by_group": dict.fromkeys(groups, 0),
              "by_outcome": dict.fromkeys(outcomes, 0)}
    go = {g: dict.fromkeys(outcomes, 0) for g in groups}
    for i, day in enumerate(DAYS):
        by_class = {c: (i + 1) * (k + 1) for k, c in enumerate(classes)}
        total = sum(by_class.values())
        by_group = dict.fromkeys(groups, 0)
        by_group["pages"], by_group["api-write"], by_group["gate"] = total - 5, 3, 2
        by_outcome = dict.fromkeys(outcomes, 0)
        by_outcome["2xx"], by_outcome["4xx-refused-with-leaf"], by_outcome["429"] = total - 3, 2, 1
        daily.append({"day": day, "total": total, "by_class": by_class, "by_group": by_group, "by_outcome": by_outcome})
        totals["total"] += total
        for c, v in by_class.items():
            totals["by_class"][c] += v
        for g, v in by_group.items():
            totals["by_group"][g] += v
        for o, v in by_outcome.items():
            totals["by_outcome"][o] += v
        rows.append({"day": day, "class": "person", "route_group": "pages", "outcome": "2xx", "count": by_class["person"]})
    go["pages"]["2xx"], go["pages"]["3xx"] = 400, 7
    go["api-write"]["2xx"], go["api-write"]["4xx-refused-with-leaf"], go["api-write"]["429"] = 30, 11, 4
    go["gate"]["2xx"], go["gate"]["5xx"] = 20, 1
    bucket_names = list(st.LATENCY_BUCKETS)

    def lat(samples, p50, p95, p99, mx, mean):
        buckets = dict.fromkeys(bucket_names, 0)
        buckets["le50"] = samples
        return {"samples": samples, "buckets": buckets, "p50_ms": p50, "p95_ms": p95, "p99_ms": p99, "max_ms": mx,
                "mean_ms": mean}

    gate_day = {"sessions_opened": {"https": 2, "tcp-tls": 1, "tcp-plain": 1, "total": 4}, "help": 3,
                "tools": {"openssl": 2, "ssh-keygen": 1, "python3": 0, "none": 1},
                "claims": {"key": 2, "third-party": 0, "secret": 1}, "upgrades": 1, "ended_malformed": 1,
                "idle_expired": 2}
    leaves_daily = [{"day": d, "total": 3 + i, "by_type": {"post": 2 + i, "name.claim": 1}} for i, d in enumerate(DAYS)]
    refusal_daily = [{"day": d, "source": "report" if i < 6 else "live", "report_index": 100 + i if i < 6 else None,
                      "total": 2, "by_code": {"rate_limited": 1, "bad_signature": 1}} for i, d in enumerate(DAYS)]
    return {
        "generated_at": "2026-10-19T12:00:00Z",
        "days": len(DAYS),
        "window": {"from": DAYS[0], "to": DAYS[-1]},
        "lists": {"access_classes": classes, "route_groups": groups, "outcomes": outcomes,
                  "latency_bounds_ms": list(st.LATENCY_BOUNDS_MS), "latency_buckets": bucket_names,
                  "gate_events": list(st.GATE_EVENTS)},
        "requests": {"daily": daily, "totals": totals, "by_group_outcome": go, "by_class_outcome": {}, "by_class_group": {},
                     "rows": rows},
        "latency": {"bounds_ms": list(st.LATENCY_BOUNDS_MS), "daily": [{"day": d, "groups": {}} for d in DAYS],
                    "window": {"pages": lat(407, 50, 100, 250, 312, 21.5), "api-write": lat(45, 100, 500, 1000, 987, 77.25)}},
        "gate": {"daily": [{"day": d, **gate_day} for d in DAYS],
                 "totals": {"sessions_opened": {"https": 14, "tcp-tls": 7, "tcp-plain": 7, "total": 28}, "help": 21,
                            "tools": {"openssl": 14, "ssh-keygen": 7, "python3": 0, "none": 7},
                            "claims": {"key": 14, "third-party": 0, "secret": 7}, "upgrades": 7, "ended_malformed": 7,
                            "idle_expired": 14},
                 "sessions_open": 3, "max_sessions": 256},
        "activity": {
            "leaves": {"daily": leaves_daily, "window": {"post": 35, "name.claim": 7}, "all_time": {"post": 90, "name.claim": 20, "policy": 1},
                       "tree_size": 111},
            "refusals": {"daily": refusal_daily, "window": {"bad_signature": 7, "rate_limited": 7}},
            "names": {"total": 20, "claimed_by_tier": {"key": 15, "third-party": 2, "secret": 3},
                      "claimed_daily": [{"day": d, "key": 1, "third-party": 0, "secret": 0} for d in DAYS],
                      "current_by_tier": {"key": 16, "third-party": 1, "secret": 2, "revoked": 1}},
            "keys": {"window": {"rotations": 2, "upgrades": 1, "x25519_rotations": 3, "revocations": 1},
                     "all_time": {"rotations": 5, "upgrades": 2, "x25519_rotations": 4, "revocations": 1}},
            "swarms": {"enabled": True, "window": {"swarm.form": 2, "swarm.join": 9, "swarm.leave": 1, "swarm.broadcast": 4, "agent.introduce": 3},
                       "all_time": {"swarm.form": 3, "swarm.join": 12, "swarm.leave": 2, "swarm.broadcast": 6, "agent.introduce": 5},
                       "active_swarms": 2, "members_in_swarms": 10},
            "messages": {"dm_leaves": {"window": 17, "all_time": 40}, "grant_leaves": {"window": 5, "all_time": 9},
                         "bodies_stored": 38, "bodies_expired": 2},
            "capsules": {"capsule_leaves": {"window": 6, "all_time": 13}, "slots": 4, "bodies_stored": 12},
            "hidden_bodies": {"total": 2, "by_reason": {"order": 1, "secret_format": 1}, "erased": 1, "window": 1},
            "notices": {"open": 3, "open_bytes": 4096, "max_open": 2000, "max_open_bytes": 16777216, "closed": 4,
                        "closed_by_outcome": {"declined": 3, "acted": 1}, "received_in_window": 5},
            "freeze": {"state": "open", "freeze_index": 55, "reason_code": "resume", "freeze_leaves": 2, "suspension_leaves": 1},
            "sup": {"profile": "AICS-1+SUP-1", "active": True, "contributions_open": True,
                    "credits": {"window": {"contribution": {"count": 2, "sup": 300}, "task": {"count": 1, "sup": 10}},
                                "all_time": {"contribution": {"count": 4, "sup": 700}, "task": {"count": 2, "sup": 20}}},
                    "spends": {"window": {"owner_action": {"count": 1, "sup": 4}, "hosting": {"count": 0, "sup": 0}, "storage": {"count": 0, "sup": 0}},
                               "all_time": {"owner_action": {"count": 2, "sup": 8}, "hosting": {"count": 0, "sup": 0}, "storage": {"count": 0, "sup": 0}}},
                    "tasks_published": 3, "tasks_open": 1, "balance_outstanding": 712},
        },
        "health": {
            "status": "OPERATIONAL",
            "healthz": {"status": "OPERATIONAL", "tree_size": 111, "published_size": 110, "tiles_error": None, "diverged": None,
                        "frozen": False, "freeze_index": None, "resource_exhaustion": None},
            "usage": {"registered_agents": 20, "agora_posts": 90, "tlog_tree_size": 111, "tlog_root_hash_hex": "ab" * 32},
            "host": {"process_rss_bytes": 181338112, "cpu_percent": 1.5, "load_average_1m": 0.25, "database_bytes": 968016,
                     "disk_total_bytes": 245107195904, "disk_used_bytes": 225807556608, "disk_used_percent": 92.1,
                     "disk_free_bytes": 19299639296},
            "tiles": {"tree_size": 111, "tiles_size": 111, "published_size": 110, "queued_entries": 0, "lag_entries": 1,
                      "lag_seconds": 3, "mmd_seconds": 60, "error": None, "diverged": None},
            "tiles_bytes": 4461,
            "checkpoint_age_seconds": 42,
            "seconds_since_tile_write": 40,
            "tls_certificate": {"configured": True, "not_after": "2026-12-01T00:00:00Z", "seconds_left": 3628800, "error": None},
            "uptime_seconds": 93784,
            "started_at": "2026-10-18T09:56:56Z",
            "schema_version": 10,
            "versions": {"api": "0.3.0", "python": "3.12.11", "aics-server": "0.2.0", "aics-identity": "0.2.0", "aics-tlog": "0.2.0"},
            "budgets": {"ciphertext": {"used_bytes": 1073741824, "budget_bytes": 8589934592},
                        "disk": {"used_percent": 92.1, "free_bytes": 19299639296},
                        "gate_staged": {"used_bytes": 0, "limit_bytes": 67108864}},
        },
        "witness": {"quorum": 0, "witnesses": [], "checkpoint_size": 110, "cosignatures": 0, "cosigned_by": [],
                    "quorum_met": False, "state": "no_witness", "g5": "promised", "error": None},
        "pages_host": "wesupport-ai.com",
    }


def owner_client(sdk, client, owner, transport=None):
    return sdk.OwnerClient(owner.key, base_url="http://testserver", transport_fn=transport or route_to_testclient(client, sdk),
                           log_vkey=client.app.state.db.server_vkey)


class Recording:
    """A transport into the app that keeps every request's headers (to see each signature is fresh)."""

    def __init__(self, client, sdk):
        self.inner = route_to_testclient(client, sdk)
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers)))
        return self.inner(method, url, headers, body)


def nonce_of(headers: dict) -> str:
    return re.search(r'nonce="([^"]+)"', headers["Signature-Input"]).group(1)


def owner_key_file(owner, tmp_path) -> Path:
    from cryptography.hazmat.primitives import serialization

    pem = owner.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    path = tmp_path / "owner.pem"
    path.write_bytes(pem)
    return path


# ----------------------------------------------------------------------
# owner stats
# ----------------------------------------------------------------------


class TestStatsCommand:
    def test_the_owner_client_signs_a_fresh_request_each_time(self, sdk, client, owner):
        recording = Recording(client, sdk)
        boss = owner_client(sdk, client, owner, recording)
        client.app.state.owner_stats._cache.clear()
        doc = boss.stats()
        assert doc["days"] == 30 and set(doc) >= {"requests", "latency", "gate", "activity", "health", "witness"}
        three = boss.stats(3)
        assert three["days"] == 3 and len(three["requests"]["daily"]) == 3
        again = boss.stats(3)  # the same request again: a new nonce, so never a replay
        assert again["days"] == 3
        stats_calls = [c for c in recording.calls if "/v2/admin/stats" in c[1]]
        assert [urllib.parse.urlsplit(c[1]).query for c in stats_calls] == ["", "days=3", "days=3"]
        assert len({nonce_of(c[2]) for c in stats_calls}) == 3
        assert '"@query"' in stats_calls[1][2]["Signature-Input"] and '"@query"' not in stats_calls[0][2]["Signature-Input"]
        for _, _, headers in stats_calls:
            assert set(headers) == {"Accept", "User-Agent", "Content-Digest", "Signature-Input", "Signature"}

    def test_days_are_checked_before_anything_is_signed(self, sdk, client, owner):
        recording = Recording(client, sdk)
        boss = owner_client(sdk, client, owner, recording)
        for bad in (0, 367, -3):
            with pytest.raises(ValueError, match="1 to 366"):
                boss.stats(bad)
        assert recording.calls == []

    def test_another_key_is_refused(self, sdk, client, owner):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        stranger = sdk.OwnerClient(Ed25519PrivateKey.generate(), base_url="http://testserver",
                                   transport_fn=route_to_testclient(client, sdk))
        with pytest.raises(sdk.AICSClientError, match="403"):
            stranger.stats()

    def test_the_command_line_prints_json_or_a_summary(self, sdk, client, owner, tmp_path, monkeypatch, capsys):
        inner = route_to_testclient(client, sdk)
        monkeypatch.setattr(sdk, "_default_transport", lambda m, u, h, b, timeout: inner(m, u, h, b))
        base = ["owner", "--key", str(owner_key_file(owner, tmp_path)), "--base-url", "http://testserver"]
        client.get("/llms.txt")
        client.app.state.owner_stats._cache.clear()
        assert sdk.main([*base, "stats", "--json", "--days", "2"]) == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc["days"] == 2 and doc["requests"]["totals"]["by_group"]["llms"] >= 1
        assert sdk.main([*base, "stats"]) == 0
        text = capsys.readouterr().out
        assert text.startswith("AICS owner stats ") and "(30 days, UTC)" in text
        for heading in ("Health", "Requests in the window:", "Gate funnel", "Log activity", "Witness: no_witness"):
            assert heading in text
        with pytest.raises(SystemExit) as exc:
            sdk.main([*base, "stats", "--days", "0"])
        assert exc.value.code == 2
        capsys.readouterr()

    def test_the_summary_of_a_full_document(self, sdk):
        text = sdk.stats_summary(fake_document())
        assert "2026-10-13 .. 2026-10-19 (7 days, UTC)" in text
        assert "status OPERATIONAL  tree 111  published 110  checkpoint age 42 s  frozen no  exhaustion none" in text
        assert "disk free 18.0 GiB (92.1% used)" in text and "uptime 26 h 3 min" in text
        assert "gate TLS certificate expires 2026-12-01T00:00:00Z (in 42 d 0 h)" in text
        total = sum(d["total"] for d in fake_document()["requests"]["daily"])
        assert f"Requests in the window: {total:,}" in text
        assert "by class: agent-gate 28, agent-signed 56, program 84, person 112, owner 140, notice 168" in text
        assert re.search(r"^  api-write +30 +0 +11 +0 +4 +0 +45$", text, re.M)
        assert re.search(r"^  api-write +45 +100 +500 +1000 +987 +77\.25$", text, re.M)
        assert "sessions 28 (https 14, tcp-tls 7, tcp-plain 7)  help 21  open now 3/256" in text
        assert "claims: key 14, third-party 0, secret 7  upgrades 7" in text
        assert "refusals in the window: bad_signature 7, rate_limited 7" in text
        assert "claimed by tier: key 15, third-party 2, secret 3" in text
        assert "swarms (enabled): active 2, members 10" in text and "DM leaves 17 in the window (40 all time)" in text
        assert "capsule leaves 6 in the window, slots 4" in text and "notices open 3/2,000 (4.0 KiB)" in text
        assert "credits contribution 2 (300 SUP), task 1 (10 SUP)" in text
        assert "Cloudflare Analytics for wesupport-ai.com: https://dash.cloudflare.com/?to=/:account/wesupport-ai.com/analytics/traffic" in text

    def test_the_summary_of_an_empty_document_does_not_fail(self, sdk):
        assert sdk.stats_summary({}).startswith("AICS owner stats None .. None")

    @pytest.mark.parametrize(
        ("zone", "url"),
        [
            ("wesupport-ai.com", "https://dash.cloudflare.com/?to=/:account/wesupport-ai.com/analytics/traffic"),
            ("WeSupport-AI.com.", "https://dash.cloudflare.com/?to=/:account/wesupport-ai.com/analytics/traffic"),
            (None, None), ("", None), ("localhost", None), ("evil.com/?x=1", None), ("a..b", None), ("-a.com", None),
            ("javascript:alert(1)", None),
        ],
    )
    def test_the_cloudflare_link(self, sdk, zone, url):
        assert sdk.cloudflare_analytics_url(zone) == url


# ----------------------------------------------------------------------
# owner dashboard: the local server
# ----------------------------------------------------------------------


class StubSigner:
    """Stands in for ``OwnerClient.stats``: counts the signed requests it would have made."""

    def __init__(self, doc=None, error=None):
        self.doc = doc if doc is not None else fake_document()
        self.error = error
        self.calls = []

    def __call__(self, days):
        self.calls.append(days)
        if self.error is not None:
            raise self.error
        return self.doc


def get(dashboard, path, headers=None, method="GET", host=None):
    conn = http.client.HTTPConnection("127.0.0.1", dashboard.port, timeout=10)
    try:
        conn.putrequest(method, path, skip_host=True)
        conn.putheader("Host", host or f"127.0.0.1:{dashboard.port}")
        for name, value in (headers or {}).items():
            conn.putheader(name, value)
        conn.endheaders()
        response = conn.getresponse()
        return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
    finally:
        conn.close()


DATA = {"X-AICS-Dashboard": "1", "Sec-Fetch-Site": "same-origin"}


@pytest.fixture()
def dashboard(sdk):
    signer = StubSigner()
    board = sdk.OwnerDashboard(fetch=signer, port=0, days=7, refresh=15).start()
    board.signer = signer
    yield board
    board.close()


class TestDashboardServer:
    @pytest.mark.parametrize("host", ["0.0.0.0", "::", "localhost", "192.168.1.20", "", "127.0.0.2"])
    def test_it_refuses_to_bind_anything_but_loopback(self, sdk, host):
        with pytest.raises(ValueError, match="127.0.0.1 only"):
            sdk.OwnerDashboard(fetch=StubSigner(), host=host, port=0)

    def test_it_binds_127_0_0_1(self, dashboard):
        assert dashboard._server.server_address[0] == "127.0.0.1"
        assert dashboard.url == f"http://127.0.0.1:{dashboard.port}/"

    def test_bad_arguments(self, sdk):
        for kwargs in ({"days": 0}, {"days": 367}, {"refresh": 4}, {"refresh": 3601}, {"port": 70000}):
            with pytest.raises(ValueError):
                sdk.OwnerDashboard(fetch=StubSigner(), **{"port": 0, **kwargs})
        with pytest.raises(ValueError, match="OwnerClient"):
            sdk.OwnerDashboard(port=0)

    def test_the_page_is_self_contained(self, dashboard, sdk):
        status, headers, page = get(dashboard, "/")
        assert status == 200 and headers["content-type"] == "text/html; charset=utf-8"
        assert headers["cache-control"] == "no-store" and headers["x-frame-options"] == "DENY"
        assert headers["referrer-policy"] == "no-referrer" and headers["x-content-type-options"] == "nosniff"
        text = page.decode("utf-8")
        assert text.startswith("<!doctype html>") and 'data-refresh="15"' in text and 'data-days="7"' in text
        # no external script, stylesheet, font, image or frame
        assert not re.search(r"<(script|img|iframe|link|object|embed)\b[^>]*\b(src|href)=", text, re.I)
        assert "@import" not in text and "url(" not in text and "<link" not in text
        assert re.findall(r"https?://[^\s\"'<>]+", text) == ["http://www.w3.org/2000/svg",
                                                            "https://dash.cloudflare.com/?to=/:account/"]
        # the policy allows exactly the page's own inline script and style, and fetches to its own origin
        csp = headers["content-security-policy"]
        scripts = re.findall(r"<script>(.*?)</script>", text, re.S)
        styles = re.findall(r"<style>(.*?)</style>", text, re.S)
        assert len(scripts) == 1 and len(styles) == 1
        digest = lambda s: "'sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() + "'"  # noqa: E731
        assert f"script-src {digest(scripts[0])};" in csp and f"style-src {digest(styles[0])};" in csp
        assert "default-src 'none'" in csp and "connect-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
        assert ' style="' not in text  # the policy would block a style attribute
        for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            assert forbidden not in scripts[0]
        # light and dark through prefers-color-scheme
        assert "@media (prefers-color-scheme:dark)" in styles[0]
        for section in ("health", "requests", "groups", "latency", "gate", "leaves", "refusals", "names", "swarms",
                        "notices", "sup", "budgets", "witness", "cloudflare"):
            assert f'<div id="{section}"></div>' in text
        assert dashboard.signer.calls == []  # serving the page signs nothing

    def test_data_signs_a_fresh_request_every_time(self, dashboard):
        for n in (1, 2, 3):
            status, headers, body = get(dashboard, "/data", DATA)
            assert status == 200 and headers["content-type"] == "application/json"
            assert headers["cache-control"] == "no-store" and "access-control-allow-origin" not in headers
            assert json.loads(body) == fake_document()
            assert dashboard.signer.calls == [7] * n

    def test_data_only_for_the_page(self, dashboard):
        assert get(dashboard, "/data")[0] == 403
        assert get(dashboard, "/data", {"X-AICS-Dashboard": "0"})[0] == 403
        assert get(dashboard, "/data", {"X-AICS-Dashboard": "1", "Sec-Fetch-Site": "cross-site"})[0] == 403
        assert get(dashboard, "/data", {"X-AICS-Dashboard": "1", "Sec-Fetch-Site": "same-site"})[0] == 403
        assert get(dashboard, "/data", {"X-AICS-Dashboard": "1"})[0] == 200  # a client without fetch metadata
        assert dashboard.signer.calls == [7]

    def test_another_host_name_is_refused(self, dashboard):
        for host in ("evil.example", f"evil.example:{dashboard.port}", "127.0.0.1", f"127.0.0.1:{dashboard.port + 1}"):
            assert get(dashboard, "/", host=host)[0] == 421
            assert get(dashboard, "/data", DATA, host=host)[0] == 421
        assert get(dashboard, "/", host=f"localhost:{dashboard.port}")[0] == 200
        assert dashboard.signer.calls == []

    def test_no_other_route_or_method(self, dashboard):
        assert get(dashboard, "/favicon.ico")[0] == 404
        assert get(dashboard, "/data/../etc")[0] == 404
        for method in ("POST", "PUT", "DELETE", "OPTIONS", "HEAD"):
            status, headers, _ = get(dashboard, "/data", {**DATA, "Origin": "https://evil.example"}, method=method)
            assert status == 405 and "access-control-allow-origin" not in headers
        assert dashboard.signer.calls == []

    def test_a_failed_request_is_a_502_with_its_reason(self, sdk):
        signer = StubSigner(error=sdk.AICSClientError("GET https://api.wesupport-ai.com/v2/admin/stats failed: HTTP 401"))
        board = sdk.OwnerDashboard(fetch=signer, port=0).start()
        try:
            status, _, body = get(board, "/data", DATA)
            assert status == 502 and "HTTP 401" in json.loads(body)["error"]
            signer.error = RuntimeError("something unexpected")
            status, _, body = get(board, "/data", DATA)
            assert status == 502 and json.loads(body) == {"error": "RuntimeError"}
            assert get(board, "/")[0] == 200  # still serving
        finally:
            board.close()

    def test_end_to_end_with_the_owner_key(self, sdk, client, owner, tmp_path, monkeypatch):
        work = tmp_path / "dashboard-cwd"
        work.mkdir()
        monkeypatch.chdir(work)
        recording = Recording(client, sdk)
        boss = owner_client(sdk, client, owner, recording)
        board = sdk.OwnerDashboard(boss, port=0, days=5).start()
        try:
            client.get("/llms.txt")
            client.app.state.owner_stats._cache.clear()
            status, _, body = get(board, "/data", DATA)
            assert status == 200
            doc = json.loads(body)
            assert doc["days"] == 5 and doc["requests"]["totals"]["by_group"]["llms"] >= 1
            assert get(board, "/data", DATA)[0] == 200  # a second refresh: no replay
            _, _, page = get(board, "/")
        finally:
            board.close()
        signed = [c for c in recording.calls if "/v2/admin/stats" in c[1]]
        assert [urllib.parse.urlsplit(c[1]).query for c in signed] == ["days=5", "days=5"]
        assert len({nonce_of(c[2]) for c in signed}) == 2
        # the page carries no key; nothing was written to disk
        raw = owner.key.private_bytes_raw()
        for form in (raw.hex(), base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode().rstrip("=")):
            assert form.encode() not in page
        assert b"PRIVATE KEY" not in page
        assert list(work.iterdir()) == []

    def test_the_command_line_prints_the_local_url(self, sdk, owner, tmp_path, monkeypatch, capsys):
        work = tmp_path / "dashboard-cli"
        work.mkdir()
        monkeypatch.chdir(work)
        key = owner_key_file(owner, work)
        served = []
        monkeypatch.setattr(sdk.OwnerDashboard, "serve_forever", lambda self: (served.append(self), self._server.server_close(),
                                                                                 (_ for _ in ()).throw(KeyboardInterrupt))[-1])
        assert sdk.main(["owner", "--key", str(key), "dashboard", "--port", "0", "--days", "9", "--refresh", "20"]) == 0
        out = capsys.readouterr().out
        assert re.search(r"owner dashboard on http://127\.0\.0\.1:\d+/ \(127\.0\.0\.1 only", out)
        board = served[0]
        assert board.days == 9 and board.refresh == 20 and board._server.server_address[0] == "127.0.0.1"
        assert sdk.main(["owner", "--key", str(key), "dashboard", "--host", "0.0.0.0", "--port", "0"]) == 1
        assert "127.0.0.1 only" in capsys.readouterr().err
        with pytest.raises(SystemExit):
            sdk.main(["owner", "--key", str(key), "dashboard", "--refresh", "1"])
        assert [p.name for p in work.iterdir()] == ["owner.pem"]


# ----------------------------------------------------------------------
# owner dashboard: the page rendered from a fake document (Node and a DOM shim, no browser)
# ----------------------------------------------------------------------

NODE = shutil.which("node")

DOM_SHIM = r"""
const fs = require("fs");
const [scriptPath, bodyPath, answerPath] = process.argv.slice(2);
const script = fs.readFileSync(scriptPath, "utf8");
const page = JSON.parse(fs.readFileSync(bodyPath, "utf8"));
const answer = JSON.parse(fs.readFileSync(answerPath, "utf8"));
class Text { constructor(t) { this.text = t; this.parentNode = null; } }
class El {
  constructor(tag, ns) { this.tagName = tag; this.ns = ns || null; this.attributes = {}; this.childNodes = []; this.style = {};
    this.hidden = false; this.listeners = {}; this.parentNode = null; }
  get firstChild() { return this.childNodes[0] || null; }
  appendChild(c) {
    if (!(c instanceof El) && !(c instanceof Text)) { throw new Error("appendChild of a non-node"); }
    if (c.parentNode) { c.parentNode.removeChild(c); }
    c.parentNode = this; this.childNodes.push(c); return c; }
  removeChild(c) { const i = this.childNodes.indexOf(c); if (i < 0) { throw new Error("not a child"); }
    this.childNodes.splice(i, 1); c.parentNode = null; return c; }
  setAttribute(k, v) { if (/^on/i.test(k)) { throw new Error("event handler attribute " + k); }
    if (k === "style") { throw new Error("style attribute: the policy blocks it"); } this.attributes[k] = String(v); }
  getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attributes, k) ? this.attributes[k] : null; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
}
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
function html(n) {
  if (n instanceof Text) { return esc(n.text); }
  const a = Object.keys(n.attributes).map((k) => " " + k + '="' + esc(n.attributes[k]) + '"').join("");
  const st = Object.keys(n.style).length ? ' data-style="' + esc(Object.keys(n.style).map((k) => k + ":" + n.style[k]).join(";")) + '"' : "";
  return "<" + n.tagName + a + st + (n.hidden ? " hidden" : "") + ">" + n.childNodes.map(html).join("") + "</" + n.tagName + ">";
}
const body = new El("body");
Object.entries(page.body).forEach(([k, v]) => body.setAttribute(k, v));
const byId = {};
page.ids.forEach((id) => { const e = new El("div"); e.setAttribute("id", id); if (id === "error" || id === "tip") { e.hidden = true; } body.appendChild(e); byId[id] = e; });
const fetches = [];
global.document = {
  body,
  createElement: (t) => new El(t),
  createElementNS: (ns, t) => { if (ns !== "http://www.w3.org/2000/svg") { throw new Error("namespace " + ns); } return new El(t, ns); },
  createTextNode: (t) => new Text(t),
  getElementById: (id) => byId[id] || null,
};
global.window = { innerWidth: 1280 };
global.setInterval = (f, ms) => { global.__interval = ms; return 1; };
global.fetch = (url, opts) => { fetches.push({ url, opts }); return Promise.resolve({ ok: answer.status === 200, status: answer.status,
  json: () => Promise.resolve(answer.body) }); };
new Function(script)();
setTimeout(() => {
  const out = { fetches, interval: global.__interval, sections: {}, hasRender: typeof window.aicsDashboard.render };
  Object.keys(byId).forEach((id) => { out.sections[id] = html(byId[id]); });
  // hover a bar column: the tooltip shows that day's counts
  const hit = (function find(n) { if (!(n instanceof El)) { return null; } if (n.attributes["class"] === "hit") { return n; }
    for (const c of n.childNodes) { const f = find(c); if (f) { return f; } } return null; })(byId.requests);
  if (hit) { hit.listeners.mousemove[0]({ clientX: 10, clientY: 10 }); out.tip = html(byId.tip); }
  process.stdout.write(JSON.stringify(out));
}, 20);
"""


def render(sdk, tmp_path, body, status=200, refresh=30, zone=None):
    """Run the page's inline script under Node against the DOM shim; *body* is what ``/data`` answers."""
    page = sdk.dashboard_page(days=7, refresh=refresh, cloudflare_zone=zone).decode("utf-8")
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    body_tag = re.search(r"<body ([^>]*)>", page).group(1)
    attrs = dict(re.findall(r'([\w-]+)="([^"]*)"', body_tag))
    ids = re.findall(r'<(?:div|p) [^>]*id="([\w-]+)"', page)
    (tmp_path / "page.js").write_text(script, encoding="utf-8")
    (tmp_path / "page.json").write_text(json.dumps({"body": attrs, "ids": ids}), encoding="utf-8")
    (tmp_path / "answer.json").write_text(json.dumps({"status": status, "body": body}), encoding="utf-8")
    (tmp_path / "shim.js").write_text(DOM_SHIM, encoding="utf-8")
    result = subprocess.run([NODE, str(tmp_path / "shim.js"), str(tmp_path / "page.js"), str(tmp_path / "page.json"),
                             str(tmp_path / "answer.json")], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def text_of(fragment: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", fragment)).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")


@pytest.mark.skipif(NODE is None, reason="Node is needed to run the page's script without a browser")
class TestDashboardPage:
    def test_it_fetches_data_with_the_dashboard_header_and_polls(self, sdk, tmp_path):
        out = render(sdk, tmp_path, fake_document(), refresh=45)
        assert out["fetches"] == [{"url": "/data", "opts": {"headers": {"X-AICS-Dashboard": "1"}, "cache": "no-store",
                                                             "credentials": "omit"}}]
        assert out["interval"] == 45000 and out["hasRender"] == "function"

    def test_every_section_is_drawn_from_the_document(self, sdk, tmp_path):
        out = render(sdk, tmp_path, fake_document())
        s = {k: v for k, v in out["sections"].items()}
        for section in ("health", "requests", "groups", "latency", "gate", "leaves", "refusals", "names", "swarms",
                        "notices", "sup", "budgets", "witness", "cloudflare"):
            assert s[section], section
            assert "could not be drawn" not in s[section], (section, s[section])
        assert s["error"].split(">")[0].endswith(" hidden")
        meta = text_of(s["meta"])
        assert "2026-10-13 to 2026-10-19 (7 days, UTC) · generated 2026-10-19T12:00:00Z" in meta and "refresh every 30 s" in meta

        health = text_of(s["health"])
        for expected in ("Status OPERATIONAL ✓ operational", "Tree size 111", "Published size 110 behind by 1",
                         "Checkpoint age 42 s", "Frozen no", "Resource exhaustion none", "Disk free 18.0 GiB 92.1 % used",
                         "Database 945.3 KiB", "Tiles 4.4 KiB", "Uptime 26 h 3 min", "Gate TLS certificate 42 d 0 h",
                         "schema 10"):
            assert expected in health, (expected, health)

        requests = s["requests"]
        daily = fake_document()["requests"]["daily"]
        # one bar segment per non-zero class per day, one hover column per day, in the categorical slots in order
        segments = re.findall(r'<rect x="[^"]+" y="[^"]+" width="[^"]+" height="[^"]+" class="(c\d)"', requests)
        assert len(segments) == 6 * len(daily)
        assert segments[:6] == ["c1", "c2", "c3", "c4", "c5", "c6"]
        assert requests.count('class="hit"') == len(daily)
        legend = text_of(requests)
        for k, cls in enumerate(st.ACCESS_CLASSES):
            assert f"{cls} (" in legend and f" · {sum(d['by_class'][cls] for d in daily):,}" in legend
        assert "Table: requests per day by class" in legend
        assert text_of(out["tip"]).strip() == ("2026-10-13 · total 21 notice 6 owner 5 person 4 program 3 agent-signed 2 "
                                                "agent-gate 1")

        groups = text_of(s["groups"])
        assert "api-write 30 0 11 0 4 0 45" in groups and "pages 400 7 0 0 0 0 407" in groups
        assert "total 450 7 11 0 4 1 473" in groups
        latency = text_of(s["latency"])
        assert "api-write 45 100 500 1,000 987 77.3" in latency and "pages 407 50 100 250 312 21.5" in latency
        gate = text_of(s["gate"])
        for expected in ("sessions opened 28", "help asked 21", "tools answered 28", "names claimed 21", "upgrades 7",
                         "sessions: tcp-tls 7", "tools: none 7", "claims: secret 7", "ended by malformed lines 7",
                         "idle expired 14", "open now 3 of 256"):
            assert expected in gate, (expected, gate)
        leaves = text_of(s["leaves"])
        assert "Tree size 111 · 42 leaves in the window" in leaves and "post 35 90" in leaves and "policy 0 1" in leaves
        assert s["leaves"].count('class="spark"') == 3
        refusals = text_of(s["refusals"])
        assert "bad_signature 7" in refusals and "rate_limited 7" in refusals and "6 of 7 days from their daily report leaf" in refusals
        names = text_of(s["names"])
        assert "20 names" in names and "key 15 16" in names and "secret 3 2" in names and "revoked 1" in names
        assert "x25519 rotations 3 4" in names
        swarms = text_of(s["swarms"])
        for expected in ("Swarms enabled · active 2 · members 10", "swarm.join 9 12", "DM leaves 17 40", "grant leaves 5 9",
                         "capsule leaves 6 13", "capsule slots 4", "DM bodies stored 38"):
            assert expected in swarms, (expected, swarms)
        notices = text_of(s["notices"])
        for expected in ("Open notices 3 / 2,000", "Open notice bytes 4.0 KiB / 16.0 MiB", "Received in the window 5",
                         "declined 3", "Hidden bodies (2, 1 erased, 1 in the window)", "secret_format 1", "Freeze open"):
            assert expected in notices, (expected, notices)
        sup = text_of(s["sup"])
        assert "AICS-1+SUP-1 · active · contributions open" in sup and "credit: contribution 2 300 4 700" in sup
        assert "spend: owner_action 1 4 2 8" in sup and "balances outstanding 712 SUP" in sup
        budgets = text_of(s["budgets"])
        assert "Ciphertext stored 1.0 GiB / 8.0 GiB" in budgets and "12.5 %" in budgets and "registered agents 20" in budgets
        assert 'data-style="width:12.5%"' in s["budgets"]
        witness = text_of(s["witness"])
        assert "no witness yet" in witness and "0 / 0" in witness and "G5 stays promised" in witness
        assert ('href="https://dash.cloudflare.com/?to=/:account/wesupport-ai.com/analytics/traffic" target="_blank" '
                'rel="noopener noreferrer"') in s["cloudflare"]

    def test_states_that_need_attention_are_marked_with_a_word_not_only_a_color(self, sdk, tmp_path):
        doc = fake_document()
        doc["health"]["status"] = "DEGRADED"
        doc["health"]["healthz"].update(frozen=True, freeze_index=77, resource_exhaustion="disk", tiles_error="OSError")
        doc["health"]["checkpoint_age_seconds"] = 4000
        doc["health"]["host"]["disk_used_percent"] = 97.0
        doc["health"]["tls_certificate"].update(seconds_left=86400)
        doc["witness"].update(witnesses=[{"name": "w1.example", "independent": True}], quorum=1, state="quorum_not_met",
                              error="no cosignature")
        health = text_of(render(sdk, tmp_path, doc)["sections"]["health"])
        for expected in ("Status DEGRADED ▲ degraded", "✕ tiles: OSError", "Checkpoint age 66 min since tile write 40 s ✕ problem",
                         "Frozen yes freeze leaf 77 ▲ writes stopped", "Resource exhaustion disk ✕ problem",
                         "97 % used", "Gate TLS certificate 24 h 0 min"):
            assert expected in health, (expected, health)
        witness = text_of(render(sdk, tmp_path, doc)["sections"]["witness"])
        assert "✕ quorum not met" in witness and "w1.example yes no" in witness and "Error: no cosignature" in witness

    def test_the_text_of_the_document_is_never_markup(self, sdk, tmp_path):
        doc = fake_document()
        doc["activity"]["refusals"]["window"] = {'<img src=x onerror="alert(1)">': 1}
        doc["witness"].update(witnesses=[{"name": "<script>alert(2)</script>", "independent": False}], quorum=1, state="quorum_not_met")
        doc["pages_host"] = "javascript:alert(3)"
        out = render(sdk, tmp_path, doc)
        assert "<img" not in out["sections"]["refusals"] and "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in out["sections"]["refusals"]
        assert "<script>" not in out["sections"]["witness"] and "&lt;script&gt;" in out["sections"]["witness"]
        assert "href" not in out["sections"]["cloudflare"] and "No pages host" in out["sections"]["cloudflare"]

    def test_a_configured_zone_wins_over_the_pages_host(self, sdk, tmp_path):
        out = render(sdk, tmp_path, fake_document(), zone="example.org")
        assert "/:account/example.org/analytics/traffic" in out["sections"]["cloudflare"]
        assert sdk.dashboard_page(cloudflare_zone='x"><script>').count(b"<script>") == 1  # an invalid zone is dropped

    def test_a_failed_fetch_shows_its_reason(self, sdk, tmp_path):
        out = render(sdk, tmp_path, {"error": "GET https://api.wesupport-ai.com/v2/admin/stats failed: HTTP 403"}, status=502)
        error = out["sections"]["error"]
        assert not error.split(">")[0].endswith(" hidden") and "HTTP 502" in text_of(error) and "HTTP 403" in text_of(error)
        assert text_of(out["sections"]["health"]).strip() == ""

    def test_an_empty_or_partial_document_draws_without_failing(self, sdk, tmp_path):
        for doc in ({}, {"health": {}, "requests": {"daily": []}}, {"lists": {}, "activity": {"leaves": None}}):
            out = render(sdk, tmp_path, doc)
            for section, fragment in out["sections"].items():
                assert "could not be drawn" not in fragment, (doc, section, fragment)

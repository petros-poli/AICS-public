"""Discovery texts, agent-seat pages, /ip and /online (DESIGN.md section 4.2 item 14 and section 9; DECISIONS.md #11, #12).

* ``/llms.txt`` is the banner followed by a short machine section naming the
  text gate, ``/t``, ``/card``, ``/contribute``, ``/notice``, ``/tiles``,
  ``/checkpoint`` and the JSON API.
* No served discovery text says "zero-knowledge", tells an agent to use a
  bearer token, or asks it to earn or spend credits; the Foundry is gone.
* RFC 9421 is claimed exactly for the endpoints that verify it: every endpoint
  the manifest lists refuses an unsigned request, and every other write takes
  one (the gate, the notice intake and the unverified tier sign differently).
* The agent-seat pages are titled with the questions agents search for: one
  paragraph and the three-line quickstart, cut from the banner.
* ``/ip`` returns the caller's address and one line pointing at ``/llms.txt``,
  and the address reaches no database row, tile or log line.
* ``/online`` and ``/v2/online`` count the agents that wrote leaves recently,
  from the public leaves only.
"""

from __future__ import annotations

import json
import re
import subprocess
from xml.etree import ElementTree as ET
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aics_server.app import create_app
from aics_server.banner import get_banner
from aics_server.discovery import (
    SEAT_PAGES, Site, SeatPage, build_json_ld, build_security_txt, build_sitemap_txt,
    build_sitemap_xml, quickstart_lines, seat_paragraph, signed_endpoints,
)

from conftest import TEST_LIMITS, Agent, https
from conftest import reason, secret_claim

#: Claims withdrawn from every served discovery text (DESIGN.md section 4.2 item 14, card README blocker 7).
WITHDRAWN = {
    "zero-knowledge": re.compile(r"zero[\s-]*knowledge", re.I),
    "deterministic key recovery": re.compile(r"deterministic key recovery", re.I),
    "bearer token instructions": re.compile(r"authorization:\s*bearer|aics_live_|\bbearer_token\b|bearer token\)", re.I),
    "credit instructions": re.compile(r"⚡|credits?[\s_-]*remaining|earn[\w\s]{0,20}credit|free[\s`]*sup\b|\+\d+\s*sup", re.I),
    "the Foundry": re.compile(r"foundry|revenue|monetiz", re.I),
    "payment rails as features": re.compile(r"x402|l402|monero treasury|sanctuary", re.I),
    "sponsor or bounty": re.compile(r"sponsor|bount(y|ies)", re.I),
}
#: Also gone from the agent-facing texts (llms.txt, skill.md, the manifest): any SUP, credit or support tier.
#: (Endpoint paths such as /v2/sup/spend are listed as they exist; the word itself is not used.)
NO_SUP = re.compile(r"\bSUP\b|\b[Cc]redits?\b|[Ss]upport tier|[Pp]atron")

HTML = {"Accept": "text/html"}


def assert_withdrawn(text: str, where: str) -> None:
    for what, pattern in WITHDRAWN.items():
        match = pattern.search(text)
        assert match is None, f"{where} still says {what}: {text[max(0, match.start() - 60):match.end() + 60]!r}"


# ---------------------------------------------------------------------------
# /llms.txt, /llms-full.txt, /skill.md, robots and the sitemap
# ---------------------------------------------------------------------------


class TestLlmsTxt:
    def test_starts_with_the_banner_then_the_machine_section(self, client):
        text = client.get("/llms.txt").text
        banner = get_banner()
        assert text.startswith(banner)
        machine = text[len(banner):]
        assert machine.startswith("\n---\n\n# AICS on wesupport-ai.com: machine section\n")
        site = Site()
        for needed in (
            f"{site.gate_host}:7700",
            "-verify_return_error -verify_hostname",
            f"POST {site.api('/t')}",
            f"GET {site.api('/t?l=help')}",
            site.page("/card"),
            site.page("/contribute"),
            site.page("/notice"),
            site.api("/checkpoint"),
            site.api("/tiles"),
            "https://tiles.wesupport-ai.com/tiles",
            site.api("/openapi.json"),
            site.api("/v2/agora/posts"),
            site.page("/online"),
            site.ip_url,
        ):
            assert needed in machine, needed
        assert machine.count("\n") < 120  # short

    def test_says_end_to_end_encrypted_and_withdraws_every_old_claim(self, client):
        for path in ("/llms.txt", "/llms-full.txt", "/skill.md"):
            text = client.get(path).text
            assert_withdrawn(text, path)
        llms = client.get("/llms.txt").text
        assert "end-to-end encrypted" in llms
        assert "no bearer tokens" in llms
        assert NO_SUP.search(llms[len(get_banner()):]) is None
        assert NO_SUP.search(client.get("/skill.md").text) is None

    def test_rfc_9421_is_claimed_through_the_list_of_endpoints_only(self, client):
        llms = client.get("/llms.txt").text
        assert llms.count("RFC 9421") == 1
        assert "listed in [agent-protocol.json]" in llms
        assert "RFC 9421" not in client.get("/skill.md").text

    def test_full_lists_every_endpoint_with_its_signature(self, client):
        full = client.get("/llms-full.txt").text
        lines = [line for line in full.splitlines() if line.startswith("- `")]
        # One native write for every entry type (AICS-1 section 12.1), signed by the key its envelope names.
        writes = [l for l in lines if "POST https://api.wesupport-ai.com/v2/entries`" in l]
        assert len(writes) == 1 and "signed by the key its envelope names" in writes[0]
        assert any("GET https://api.wesupport-ai.com/v2/entries/{index}`" in l and "(no signature)" in l for l in lines)
        assert any("GET https://api.wesupport-ai.com/v2/bodies/{digest}`" in l and "(no signature)" in l for l in lines)
        assert not any(l.startswith("- `POST https://api.wesupport-ai.com/v2/agora/") for l in lines)
        assert not any("/v2/agents/register" in l for l in lines)
        assert any("POST https://wesupport-ai.com/notice`" in l and "(no signature)" in l for l in lines)
        assert any("POST https://api.wesupport-ai.com/t`" in l and "(no signature)" in l for l in lines)
        assert not any("/v2/moderation/report" in l for l in lines)

    def test_skill_md_is_a_skill_file_with_the_banner_quickstart(self, client):
        response = client.get("/skill.md")
        assert response.headers["content-type"].startswith("text/markdown")
        text = response.text
        assert text.startswith("---\nname: wesupport-ai\ndescription: ")
        for line in quickstart_lines():
            assert f"\n{line}\n" in text
        assert "end-to-end encrypted" in text and "never sees, makes or keeps a private key" in text

    def test_robots_welcome_crawlers_and_name_the_sitemap(self, client):
        robots = client.get("/robots.txt").text
        assert robots.startswith("User-agent: *\nAllow: /\n")
        for bot in ("GPTBot", "ClaudeBot", "PerplexityBot", "OAI-SearchBot", "BraveBot", "Claude-User",
                    "Perplexity-User", "DuckAssistBot", "Amazonbot", "Applebot-Extended"):
            assert f"User-agent: {bot}\nAllow: /" in robots
        assert re.findall(r"^Sitemap: (.+)$", robots, re.M) == [
            "https://wesupport-ai.com/sitemap.txt", "https://wesupport-ai.com/sitemap.xml",
        ]
        assert "Disallow" not in robots

    def test_sitemap_lists_the_pages_one_url_per_line(self, client):
        response = client.get("/sitemap.txt")
        assert response.headers["content-type"].startswith("text/plain")
        urls = response.text.splitlines()
        assert all(u.startswith("https://wesupport-ai.com/") for u in urls)
        for path in ("/", "/llms.txt", "/card", "/contribute", "/notice", "/online", "/agora", "/directory", "/tasks"):
            assert f"https://wesupport-ai.com{path}" in urls
        for seat in SEAT_PAGES:
            assert f"https://wesupport-ai.com/{seat.slug}" in urls
        assert len(urls) == len(set(urls))


# ---------------------------------------------------------------------------
# the agent-protocol manifest and its RFC 9421 claim
# ---------------------------------------------------------------------------


def _fill(path: str) -> str:
    return re.sub(r"\{[^}]+\}", lambda m: "1" if "index" in m.group(0) else "x-value", path)


class TestManifest:
    def test_names_the_gate_the_log_the_card_and_no_wallet(self, client, monkeypatch):
        monkeypatch.setenv("AICS_WALLET_BTC", "bc1q" + "a" * 38)
        manifest = client.get("/.well-known/agent-protocol.json").json()
        assert manifest == client.get("/manifest.json").json()
        assert manifest["protocol"] == "AICS-1" and manifest["domain"] == "wesupport-ai.com"
        assert manifest["identity"]["bearer_tokens"] is False
        assert manifest["identity"]["server_makes_or_holds_private_keys"] is False
        assert manifest["text_gate"]["https"] == "https://api.wesupport-ai.com/t"
        assert manifest["text_gate"]["tls"] == {"host": "gate.wesupport-ai.com", "port": 7700}
        assert manifest["assurance_card"] == "https://wesupport-ai.com/.well-known/aics-card.json"
        assert manifest["transparency_log"]["tile_prefixes"][0] == "https://api.wesupport-ai.com/tiles"
        assert manifest["contribute"] == "https://wesupport-ai.com/contribute"
        text = client.get("/.well-known/agent-protocol.json").text
        assert_withdrawn(text, "the manifest")
        assert NO_SUP.search(text) is None
        assert "bc1q" not in text  # contribution details appear on /contribute only
        assert "sustainability" not in manifest and "human_intervention_required" not in manifest

    def test_rfc_9421_is_claimed_exactly_where_it_is_enforced(self, client):
        enforced = client.get("/.well-known/agent-protocol.json").json()["request_signatures"]["enforced_on"]
        assert enforced == signed_endpoints(client.app)
        listed = {(e["method"], e["path"]) for e in enforced}
        # Every listed endpoint refuses a request that carries no signature (over HTTPS, as behind Caddy: the
        # endpoints that take a shared secret refuse any plain-HTTP request before reading it, tls_required).
        secure = https(client)
        for method, path in sorted(listed):
            response = secure.request(method, _fill(path), json={} if method != "GET" else None)
            assert response.status_code == 401, (method, path, response.status_code, response.text[:200])
            assert reason(response) == "signature_required", (method, path)
        # Every other write takes a request without one (it may refuse it for other reasons).
        schema = client.get("/openapi.json").json()["paths"]
        for path, operations in schema.items():
            for method in operations:
                if method.upper() in ("POST", "PUT", "DELETE") and (method.upper(), path) not in listed:
                    response = secure.request(method.upper(), _fill(path), json={})
                    detail = response.json().get("detail") if response.headers.get("content-type", "").startswith("application/json") else None
                    assert not (isinstance(detail, dict) and detail.get("error") == "signature_required"), (method, path)
        assert ("POST", "/v2/entries") in listed and ("POST", "/v2/agora/posts") not in listed
        assert ("GET", "/v2/agents/me") in listed and ("POST", "/v2/admin/tombstones") in listed
        for unsigned in (("POST", "/t"), ("POST", "/notice"), ("GET", "/v2/entries/{index}"), ("GET", "/v2/bodies/{digest}")):
            assert unsigned not in listed
        signers = {e["signer"] for e in enforced}
        assert signers == {
            "agent key", "owner key", "key its envelope names: an agent key, the owner key, or for a claim the key it claims",
        }
        manifest = client.get("/.well-known/agent-protocol.json").json()["request_signatures"]
        assert manifest["writes"] == "https://api.wesupport-ai.com/v2/entries"

    def test_the_profile_is_the_one_the_server_verifies(self, client):
        from aics_identity import http_signatures as hs

        profile = client.get("/.well-known/agent-protocol.json").json()["request_signatures"]
        assert profile["covered_components"] == list(hs.AICS_COMPONENTS)
        assert profile["tag"] == hs.AICS_TAG == "aics"
        assert profile["max_lifetime_seconds"] == hs.AICS_VERIFY_POLICY["max_lifetime"]


# ---------------------------------------------------------------------------
# agent-seat pages
# ---------------------------------------------------------------------------


class TestSeatPages:
    TITLES = (
        "How can an AI agent talk to other AI agents?",
        "Is any other agent online right now?",
        "Persistent identity for an AI agent across resets",
        "AI agent message board",
        "Agent mailbox no signup",
        "How to use an agent protocol from a GET-only web-fetch sandbox",
        "Troubleshooting 403 Forbidden, 502 Bad Gateway, and TLS proxy errors in agent sandboxes",
    )

    def test_the_titles_are_the_questions_agents_search_for(self):
        assert tuple(p.title for p in SEAT_PAGES) == self.TITLES

    def test_the_quickstart_is_three_lines_cut_from_the_banner(self):
        lines = quickstart_lines()
        assert len(lines) == 3
        banner = get_banner()
        assert lines[0] in banner and lines[1] in banner and "then type: help" in banner
        assert lines[0] == "openssl genpkey -algorithm ed25519 -out aics.key"
        assert "-verify_return_error -verify_hostname gate.wesupport-ai.com" in lines[1]
        assert lines[2] == "help"
        with pytest.raises(ValueError):
            quickstart_lines("a banner that lost its commands\n")

    @pytest.mark.parametrize("seat", SEAT_PAGES, ids=lambda s: s.slug)
    def test_markdown_first_html_for_browsers(self, client, seat):
        markdown = client.get(f"/{seat.slug}")
        assert markdown.status_code == 200
        assert markdown.headers["content-type"].startswith("text/markdown")
        assert markdown.text.startswith(f"# {seat.title}\n\n")
        assert client.get(f"/{seat.slug}.md").text == markdown.text
        body = markdown.text.split("\n\n")
        paragraph = body[1]
        assert "\n" not in paragraph and len(paragraph) > 200  # one paragraph
        block = re.search(r"```\n(.*?)\n```", markdown.text, re.S).group(1).split("\n")
        assert block == list(quickstart_lines())
        assert_withdrawn(markdown.text, seat.slug)
        page = client.get(f"/{seat.slug}", headers=HTML)
        assert page.headers["content-type"].startswith("text/html")
        assert f"<title>{seat.title}</title>" in page.text and f"<h1>{seat.title}</h1>" in page.text
        assert page.headers["vary"] == "Accept"
        data = client.get(f"/{seat.slug}", params={"format": "json"}).json()
        assert data["title"] == seat.title and data["quickstart"] == list(quickstart_lines())

    def test_the_online_page_counts_from_the_log(self, client, make_agent):
        slug = "/is-any-other-agent-online-right-now"
        assert "No agent wrote to the wesupport-ai.com log in the last 15 minutes." in client.get(slug).text
        make_agent("first")
        assert "1 agent wrote to the wesupport-ai.com log in the last 15 minutes." in client.get(slug).text
        make_agent("second").post()
        assert "2 agents wrote" in client.get(slug).text

    def test_the_seat_pages_are_listed_on_the_home_page(self, client):
        home = client.get("/", headers=HTML).text
        for seat in SEAT_PAGES:
            assert f'href="/{seat.slug}"' in home


def test_tiles_names_the_canonical_prefix_and_the_mirrors(client):
    response = client.get("/tiles", follow_redirects=False)
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/plain")
    first = response.text.splitlines()[0]
    assert first == ("Tile prefixes (C2SP tlog-tiles): https://api.wesupport-ai.com/tiles and "
                     "https://tiles.wesupport-ai.com/tiles")
    assert "https://api.wesupport-ai.com/tiles/checkpoint" in response.text
    assert client.get("/tiles/checkpoint", follow_redirects=False).status_code == 200  # inside the prefix: no redirect


# ---------------------------------------------------------------------------
# the connectivity check
# ---------------------------------------------------------------------------


class TestConnectivityCheck:
    ADDRESS = "198.51.100.73"

    def test_returns_the_address_and_a_pointer_and_stores_nothing(self, client, db_path, capfd):
        caller = TestClient(client.app, client=(self.ADDRESS, 51515))
        response = caller.get("/ip")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert response.headers["cache-control"] == "no-store"
        assert response.text == f"{self.ADDRESS}\nAI agents: https://wesupport-ai.com/llms.txt\n"
        assert response.text.splitlines()[0] == self.ADDRESS  # what ifconfig-style parsers read
        # The address reaches no row, page, tile or log line.
        caller.get("/ip")
        conn = sqlite3.connect(db_path)
        try:
            for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
                for row in conn.execute(f"SELECT * FROM {table}").fetchall():
                    assert self.ADDRESS not in repr(row), table
        finally:
            conn.close()
        for path in Path(db_path).parent.rglob("*"):
            if path.is_file():
                assert self.ADDRESS.encode() not in path.read_bytes(), path
        assert self.ADDRESS not in client.get("/stats", params={"format": "json"}).text
        out, err = capfd.readouterr()
        assert self.ADDRESS not in out and self.ADDRESS not in err

    def test_ipv6_callers(self, client):
        caller = TestClient(client.app, client=("2001:db8::7", 443))
        assert caller.get("/ip").text.splitlines()[0] == "2001:db8::7"


# ---------------------------------------------------------------------------
# agents online now
# ---------------------------------------------------------------------------


class TestOnline:
    def test_counts_agents_from_their_own_recent_leaves(self, client, make_agent, owner):
        empty = client.get("/v2/online").json()
        assert empty["count"] == 0 and empty["agents"] == [] and empty["window_seconds"] == 900
        alice = make_agent("alice")
        make_agent("bob")
        alice.post(title="Hello there", body="First public words.")
        alice.post(title="Again", body="Second public words.")
        # The service's own leaves (the owner's task, policy refusals) count for nobody.
        assert owner.task().status_code == 202
        assert Agent(client, alice.origin).claim("alice").status_code == 409  # a policy-signed refusal leaf
        view = client.get("/v2/online").json()
        assert view["count"] == 2
        by_name = {a["name"]: a for a in view["agents"]}
        assert set(by_name) == {"alice", "bob"}
        assert by_name["alice"]["leaves"] == 3 and by_name["alice"]["last_leaf_type"] == "post"
        assert by_name["bob"]["leaves"] == 1 and by_name["bob"]["last_leaf_type"] == "name.claim"
        assert by_name["alice"]["actor_kid"] == alice.kid and by_name["alice"]["tier"] == "verified"
        assert [a["name"] for a in view["agents"]] == ["alice", "bob"]  # newest leaf first
        assert view["latest_posts"][0]["title"] == "Again"
        assert "body" not in view["latest_posts"][0]
        assert view["tree_size"] == client.get("/v2/tlog/checkpoint").json()["tree_size"]
        assert client.get("/online", params={"format": "json"}).json()["count"] == 2

    def test_unverified_identities_count_too(self, client):
        secret_claim(client, "plain")  # at the TLS gate, the only door of a shared secret
        view = client.get("/v2/online").json()
        assert [a["name"] for a in view["agents"]] == ["plain"]
        assert view["agents"][0]["tier"] == "unverified"

    def test_the_window_is_bounded_and_old_leaves_drop_out(self, client, make_agent, monkeypatch):
        make_agent("early")
        assert client.get("/v2/online", params={"window": 59}).status_code == 422
        assert client.get("/v2/online", params={"window": 86401}).status_code == 422
        import aics_server.app as app_module

        real = app_module.time.time
        monkeypatch.setattr(app_module.time, "time", lambda: real() + 3600)
        assert client.get("/v2/online").json()["count"] == 0
        assert client.get("/v2/online", params={"window": 7200}).json()["count"] == 1

    def test_the_page_lists_names_and_latest_posts(self, client, make_agent):
        make_agent("writer").post(title="A post to list", body="Listed on the online page.")
        page = client.get("/online", headers=HTML)
        assert page.status_code == 200
        assert "@writer" in page.text and "A post to list" in page.text
        assert "1 agent wrote to the wesupport-ai.com log in the last 15 minutes." in page.text


def test_a_fresh_app_on_another_host_names_that_host(tmp_path, monkeypatch, owner):
    monkeypatch.setenv("AICS_BASE_URL", "https://pages.example")
    monkeypatch.setenv("AICS_API_URL", "https://api.example")
    monkeypatch.setenv("AICS_GATE_HOSTNAME", "gate.example")
    monkeypatch.setenv("AICS_IP_URL", "https://ip.example")
    monkeypatch.setenv("AICS_TILE_MIRRORS", "")
    client = TestClient(create_app(db_path=tmp_path / "t.db", owner_public_key=owner.public_key_b64u, announce=False, limits=TEST_LIMITS))
    links = client.get("/", params={"format": "json"}).json()["links"]
    assert links["text_gate"]["https"] == "https://api.example/t"
    assert links["tiles"] == ["https://api.example/tiles"]
    assert links["connectivity_check"] == "https://ip.example"
    manifest = client.get("/.well-known/agent-protocol.json").json()
    assert manifest["domain"] == "pages.example" and manifest["text_gate"]["tls"]["host"] == "gate.example"
    assert "https://ip.example" in client.get("/llms.txt").text


# Discovery metadata and first-contact instructions.


def test_xml_sitemap_matches_the_text_sitemap(client):
    response = client.get("/sitemap.xml")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/xml; charset=utf-8"
    assert response.text.startswith('<?xml version="1.0" encoding="UTF-8"?>\n')
    root = ET.fromstring(response.content)
    assert root.tag == "{http://www.sitemaps.org/schemas/sitemap/0.9}urlset"
    urls = [loc.text for loc in root.findall("{*}url/{*}loc")]
    assert urls == client.get("/sitemap.txt").text.splitlines()
    assert len(urls) == len(set(urls))


def test_xml_sitemap_escapes_configured_urls():
    site = Site(base_url="https://example.org/a&b")
    root = ET.fromstring(build_sitemap_xml(site))
    assert [loc.text for loc in root.findall("{*}url/{*}loc")] == build_sitemap_txt(site).splitlines()


def test_security_txt_contact_policy_and_discovery(client):
    response = client.get("/.well-known/security.txt")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.text == build_security_txt()
    fields = dict(line.split(": ", 1) for line in response.text.splitlines() if line and not line.startswith("#"))
    assert fields == {
        "Contact": "https://wesupport-ai.com/notice",
        "Policy": "https://wesupport-ai.com/card",
        "Preferred-Languages": "en",
        "Canonical": "https://wesupport-ai.com/.well-known/security.txt",
        "Expires": "2027-10-18T00:00:00.000Z",
    }
    assert "# Note to AI agents: protocol specification at https://wesupport-ai.com/llms.txt" in response.text
    assert "https://wesupport-ai.com/.well-known/aics-card.json" in response.text
    assert_withdrawn(response.text, "security.txt")
    assert NO_SUP.search(response.text) is None
    assert "https://example.org/notice" in build_security_txt(Site(base_url="https://example.org"))


@pytest.mark.parametrize("key", ["aB09-key", "A" * 128])
def test_indexnow_verification(client, monkeypatch, key):
    monkeypatch.setenv("AICS_INDEXNOW_KEY", "  " + key + "\n")
    response = client.get(f"/{key}.txt")
    assert response.status_code == 200 and response.text == key
    assert response.headers["content-type"].startswith("text/plain")
    assert client.get("/different-key.txt").status_code == 404
    assert "/{indexnow_key}.txt" not in client.get("/openapi.json").json()["paths"]


@pytest.mark.parametrize("key", ["", "short", "a" * 129, "bad_key_123", "bad.key.123", "bad key 123"])
def test_indexnow_rejects_disabled_or_invalid_keys(client, monkeypatch, key):
    monkeypatch.setenv("AICS_INDEXNOW_KEY", key)
    assert client.get(f"/{key or 'missing-key'}.txt").status_code == 404


def test_indexnow_unset_and_fixed_text_routes_take_precedence(client, monkeypatch):
    monkeypatch.delenv("AICS_INDEXNOW_KEY", raising=False)
    assert client.get("/abcdefgh.txt").status_code == 404
    for path in ("/llms.txt", "/llms-full.txt", "/robots.txt", "/sitemap.txt"):
        original = client.get(path).text
        monkeypatch.setenv("AICS_INDEXNOW_KEY", path[1:-4])
        assert client.get(path).text == original


@pytest.mark.parametrize("path", ["/", "/agora", "/notice", *(f"/{seat.slug}" for seat in SEAT_PAGES)])
def test_html_canonical_structured_data_and_discovery_headers(client, path):
    response = client.get(path, params={"tracking": "ignore"}, headers=HTML)
    assert response.status_code == 200
    assert f'<link rel="canonical" href="https://wesupport-ai.com{path}">' in response.text
    assert '<link rel="alternate" type="text/markdown" href="/llms.txt" title="AICS-1 Protocol Instructions">' in response.text
    script = re.search(r'<script type="application/ld\+json">(.*?)</script>', response.text, re.S).group(1)
    data = json.loads(script)
    assert data["@context"] == "https://schema.org"
    seat = next((seat for seat in SEAT_PAGES if path == f"/{seat.slug}"), None)
    types = [node["@type"] for node in data["@graph"]]
    assert types == (["WebSite", "WebAPI"] if path == "/" else ["FAQPage", "TechArticle"] if seat else ["WebPage"])
    assert data["@graph"][0]["url"] == "https://wesupport-ai.com" + path
    if seat:
        question = data["@graph"][0]["mainEntity"][0]
        assert question["name"] == seat.title and question["acceptedAnswer"]["text"]
        assert data["@graph"][1]["headline"] == seat.title
    if path == "/":
        assert data["@graph"][1]["url"] == "https://api.wesupport-ai.com"
    expected = '</llms.txt>; rel="service-doc", </.well-known/aics-card.json>; rel="describedby"'
    if seat:
        expected += f', </{seat.slug}.md>; rel="alternate"; type="text/markdown"'
    assert response.headers["link"] == expected
    assert_withdrawn(script, path)
    assert NO_SUP.search(script) is None


def test_json_ld_cannot_close_its_script_and_preserves_json_data():
    title = '</script><script>alert("test")</script>&'
    seat = SeatPage(SEAT_PAGES[0].slug, title, title)
    site = Site(base_url="https://example.org", api_url="https://api.example.org")
    raw = build_json_ld(site, "/example", seat)
    assert "<" not in raw and ">" not in raw and "&" not in raw
    data = json.loads(raw)
    assert data["@graph"][1]["headline"] == title
    assert data["@graph"][0]["url"] == "https://example.org/example"


def test_first_contact_swarm_discovery(client):
    skill = client.get("/skill.md").text
    manifest = client.get("/manifest.json").json()
    for verb in ("intro", "arrivals", "connect", "swarm-form", "swarm-join"):
        assert verb in manifest["text_gate"]["verbs"]
        assert verb in skill and verb in client.get("/llms.txt").text
    assert "intro <model> | <kw1> <kw2> <kw3>" in skill
    assert "swarm-..." in skill


@pytest.mark.parametrize("slug,needed", [
    ("ai-agent-message-board", ["lowercase", "Ed25519", "one-key-one-vote", "Merkle", "https://api.wesupport-ai.com/tiles",
        "https://wesupport-ai.com/agora", "https://api.wesupport-ai.com/v2/agora/posts",
        "intro <model> | <kw1> <kw2> <kw3>", "swarm-..."]),
    ("agent-mailbox-no-signup", ["Ed25519", "X25519", "email", "phone verification", "CAPTCHA", "closed by default",
        "grant leaf", "* wildcard", "message cap and expiry", "crypto_box_seal", "x25519-xsalsa20-poly1305", "inbox and fetch"]),
    ("get-only-sandbox-http-post-workaround", ["web_fetch", "read_url_content", "GET https://api.wesupport-ai.com/t?l=help",
        "GET https://api.wesupport-ai.com/t?s=<session_id>&l=<url-encoded-line>", "help, who, find, read, inbox, fetch, arrivals",
        "Never put a shared secret in a URL", "POST https://api.wesupport-ai.com/t", "gate.wesupport-ai.com:7700"]),
    ("sandbox-network-errors-403-502-cloudflare", ["HTTP 403 Forbidden", "502 Bad Gateway", "TLS inspection", "DNS-only",
        "https://ip.wesupport-ai.com", "https://api.wesupport-ai.com/t?l=help", "gate.wesupport-ai.com",
        "7700 TLS / 7701 plain", "https://api.wesupport-ai.com/tiles", "https://tiles.wesupport-ai.com/tiles"]),
])
def test_new_seat_instructions(client, slug, needed):
    seat = next(seat for seat in SEAT_PAGES if seat.slug == slug)
    paragraph = seat_paragraph(seat, Site())
    assert "\n" not in paragraph and len(paragraph) > 220
    for phrase in needed:
        assert phrase in paragraph
    assert_withdrawn(paragraph, slug)
    assert NO_SUP.search(paragraph) is None
    assert paragraph in client.get(f"/{slug}.md").text


def test_seat_paragraphs_have_distinct_openings():
    paragraphs = [seat_paragraph(seat, Site()) for seat in SEAT_PAGES]
    assert len({text[:40] for text in paragraphs}) == 7


def test_discovery_and_site_documents_are_routed_on_the_pages_host(client):
    from test_caddy_pages import CADDYFILE, PagesHost

    config = CADDYFILE.read_text()
    host = PagesHost(config)
    for path in ("/sitemap.xml", "/.well-known/security.txt",
                 *(f"/{seat.slug}{suffix}" for seat in SEAT_PAGES for suffix in ("", ".md"))):
        assert path in host.pages
    for prefix in ("/site/", "/docs/site/"):
        assert host.serves(prefix + "guide.md")
        assert re.search(r"handle_path " + re.escape(prefix) + r"\*\s*\{\s*root \* /srv/docs/site", config)
    assert '@indexnow path_regexp indexnow ^/[0-9a-zA-Z-]{8,128}\\.txt$' in config
    assert "reverse_proxy @indexnow aics-server:8080" in config


def test_docs_publisher_validates_and_exports_site_documents(tmp_path):
    repo = Path(__file__).resolve().parents[3]
    script = repo / "ops/sync-docs.sh"
    checked = subprocess.run(["bash", str(script), "--check"], capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr
    destination = tmp_path / "docs-public"
    for attempt in range(2):  # Existing export directories must also accept the new section.
        result = subprocess.run(["bash", str(script), str(destination)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        sources = sorted((repo / "docs/site").glob("*.md"))
        assert {source.name for source in sources} >= {"incident-2026.md", "guide.md"}
        for source in sources:
            assert (destination / "site" / source.name).read_bytes() == source.read_bytes()
        assert (destination / "site/index.txt").read_text().splitlines() == [*(source.name for source in sources), "index.txt"]
        assert not (destination / "internal").exists()

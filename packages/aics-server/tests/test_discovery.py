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
        from aics_server.discovery import build_llms_txt

        text = client.get("/llms.txt").text
        banner = get_banner()
        assert text.startswith(banner)
        machine = text[len(banner):]
        assert machine.startswith("\n---\n\n# AICS on wesupport-ai.com: machine section\n")
        # This test app has no gate certificate, so no TLS listener, and its text says so; production's site (the
        # certificate set, test_gate.py::test_an_app_with_the_gate_certificate_names_7700) names the TLS gate.
        assert not client.app.state.site.gate_tls and text == build_llms_txt(client.app.state.site)
        production = build_llms_txt(Site())[len(banner):]
        site = Site()
        tls = (f"{site.gate_host}:7700", "-verify_return_error -verify_hostname")
        for needed in (
            *tls,
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
            assert needed in production, needed
            assert (needed not in machine) if needed in tls else (needed in machine), needed
        assert machine.count("\n") < 120 and production.count("\n") < 120  # short

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
    fields: dict[str, list[str]] = {}
    for line in response.text.splitlines():
        if line and not line.startswith("#"):
            key, value = line.split(": ", 1)
            fields.setdefault(key, []).append(value)
    # The mailbox first, as wellknown/security.txt and docs/legal/contact.md give it: the /notice form takes notices
    # about public content, each closed with a public leaf, so a security report belongs in the mailbox.
    assert fields == {
        "Contact": ["mailto:notice@wesupport-ai.com", "https://wesupport-ai.com/notice"],
        "Policy": ["https://wesupport-ai.com/card"],
        "Preferred-Languages": ["en"],
        "Canonical": ["https://wesupport-ai.com/.well-known/security.txt"],
        "Expires": ["2027-10-18T00:00:00.000Z"],
    }
    static = Path(__file__).resolve().parents[3] / "wellknown" / "security.txt"
    if static.exists():
        contacts = [l.split(": ", 1)[1] for l in static.read_text(encoding="utf-8").splitlines() if l.startswith("Contact: ")]
        assert contacts == fields["Contact"]
    contact = Path(__file__).resolve().parents[3] / "docs" / "legal" / "contact.md"
    if contact.exists():
        assert "- Security reports: mail `notice@wesupport-ai.com`" in contact.read_text(encoding="utf-8")
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
    # The manifest lists the first-contact verbs apart from the core verbs, with where they apply (docs pass of the
    # readiness audit, 2026-10-20: the gate knows them only where the card names the swarms profile).
    swarm = manifest["text_gate"]["swarm_verbs"]
    assert "names the swarms profile (its spec contains SWARMS-1)" in swarm["where"]
    for verb in ("intro", "arrivals", "connect", "swarm-form", "swarm-join"):
        assert verb in swarm["verbs"] and verb not in manifest["text_gate"]["verbs"]
        assert verb in skill and verb in client.get("/llms.txt").text
    assert "intro <model> | <kw1> <kw2> <kw3>" in skill
    assert "swarm-..." in skill


def test_the_swarm_verbs_are_offered_only_where_the_card_names_the_profile(client):
    """A card without the swarms profile (production's first card of genesis v2 is AICS-1+SUP-1) leaves the gate
    answering the swarm verbs with err not_enabled, even after a key claim; so /llms.txt, /skill.md and the seat pages
    say where those verbs apply, in the same words whether the profile is on or off (review of the relaunch texts)."""
    from conftest import KeyAgent, Line, onboard

    from aics_server.discovery import SWARM_GATE_VERBS, SWARMS_WHERE, build_llms_txt, build_skill_md
    from aics_server.swarm_gate import READ_SCHEMAS, SELECT_QUESTION, SWARM_VERBS

    assert {"intro", "swarm-form", "swarm-join"} <= set(SWARM_VERBS) and "arrivals" in READ_SCHEMAS
    assert "connect <member_index>" in SELECT_QUESTION and len(SWARM_GATE_VERBS) == 5
    assert not client.app.state.db.swarms.enabled
    line = Line(https(client))
    onboard(line, KeyAgent("no-swarms"))
    # Not malformed lines (three of those end a session): err not_enabled, then the question the session waits on.
    for verb in ("arrivals", "connect 1", "intro m | a b c"):
        reply = line.send(verb)
        assert reply.startswith(f"err not_enabled {verb.split()[0]} belongs to the swarms profile (AICS-1+SWARMS-1)"), reply
        assert reply.endswith("\n>\n") and "retry" not in reply, reply
    assert "SWARMS-1" in SWARMS_WHERE

    llms = build_llms_txt(Site())
    verbs = next(text for text in llms.splitlines() if text.startswith("- Verbs: "))
    assert verbs.index(SWARMS_WHERE) < min(verbs.index(f" {verb}") for verb in SWARM_GATE_VERBS)
    gate = _section(llms, "Text gate (start here)")
    assert gate.index("Where `/card` names the swarms profile") < gate.index("`intro <model> | <kw1> <kw2> <kw3>`")
    skill = " ".join(build_skill_md(Site()).split())
    assert f"- {SWARMS_WHERE}: introduce your model and three keywords with `intro <model> | <kw1> <kw2> <kw3>`" in skill
    assert "Where `/card` names the swarms profile (its `spec` contains SWARMS-1), a public introduction" in skill
    for seat in SEAT_PAGES:
        paragraph = seat_paragraph(seat, Site())
        for verb in ("intro <model>", "arrivals", "swarm-"):
            if verb in paragraph:
                assert "swarms profile" in paragraph[:paragraph.index(verb)], (seat.slug, verb)
        if "swarm" in seat.description:
            assert "swarms profile" in seat.description, seat.slug


@pytest.mark.parametrize("slug,needed", [
    ("ai-agent-message-board", ["lowercase", "Ed25519", "one-key-one-vote", "Merkle", "https://api.wesupport-ai.com/tiles",
        "https://wesupport-ai.com/agora", "https://api.wesupport-ai.com/v2/agora/posts",
        "intro <model> | <kw1> <kw2> <kw3>", "swarm-..."]),
    ("agent-mailbox-no-signup", ["Ed25519", "X25519", "email", "phone verification", "CAPTCHA", "closed by default",
        "grant leaf", "* wildcard", "message cap and expiry", "crypto_box_seal", "x25519-xsalsa20-poly1305", "inbox and fetch"]),
    ("get-only-sandbox-http-post-workaround", ["web_fetch", "read_url_content", "GET https://api.wesupport-ai.com/t?l=help",
        "GET https://api.wesupport-ai.com/t?s=<session_id>&l=<url-encoded-line>",
        "help, who, find, read, inbox, fetch and, with the swarms profile, arrivals",
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
    # The app serves the paragraph of its own site (this test app has no gate certificate, so no TLS gate).
    assert seat_paragraph(seat, client.app.state.site) in client.get(f"/{slug}.md").text


def test_seat_pages_offer_a_tls_gate_and_a_mirror_only_where_the_instance_has_them():
    """Staging has no gate certificate and no tile mirror (deploy/docker-compose.staging.yml): its seat pages send
    secrets to HTTPS POST /t alone and name neither its dark TLS port 7800 nor a tiles.test.* host, which does not
    exist; production's paragraphs are the ones above, word for word."""
    staging = Site.from_env({**STAGING_ENV, "AICS_IP_URL": "https://test.wesupport-ai.com/ip", "AICS_TILE_MIRRORS": ""})
    assert not staging.gate_tls and staging.tile_mirrors == ()
    get_only = seat_paragraph(next(s for s in SEAT_PAGES if s.slug == "get-only-sandbox-http-post-workaround"), staging)
    assert "content writes and secret claims require POST https://test.wesupport-ai.com/t. GET cannot" in get_only
    network = seat_paragraph(next(s for s in SEAT_PAGES if s.slug == "sandbox-network-errors-403-502-cloudflare"), staging)
    assert "and test.wesupport-ai.com (TCP 7801, plain only)." in network
    assert network.endswith("Static tiles are at https://test.wesupport-ai.com/tiles (DNS-only).")
    for text in (get_only, network):
        assert "7800" not in text and "TLS /" not in text and "tiles.test." not in text and "with TLS" not in text


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


# ----------------------------------------------------------------------
# an instance beside production (staging) names its own gate, never production's
# ----------------------------------------------------------------------

STAGING_ENV = {
    "AICS_BASE_URL": "https://test.wesupport-ai.com",
    "AICS_API_URL": "https://test.wesupport-ai.com",
    "AICS_GATE_HOSTNAME": "test.wesupport-ai.com",
    "AICS_GATE_PUBLIC_TLS_PORT": "7800",
    "AICS_GATE_PUBLIC_PLAIN_PORT": "7801",
}
#: What deploy/gate-tls.yml gives production's aics-server: the gate certificate, so a TLS listener on 7700.
PRODUCTION_GATE_TLS_ENV = {
    "AICS_GATE_TLS_CERT": "/etc/aics/gate-tls/gate.wesupport-ai.com.crt",
    "AICS_GATE_TLS_KEY": "/etc/aics/gate-tls/gate.wesupport-ai.com.key",
}


def test_site_reads_the_advertised_gate_ports():
    from aics_server.discovery import DEFAULT_SITE, Site

    assert (DEFAULT_SITE.gate_tls_port, DEFAULT_SITE.gate_plain_port, DEFAULT_SITE.gate_tls) == (7700, 7701, True)
    assert Site.from_env(PRODUCTION_GATE_TLS_ENV) == DEFAULT_SITE
    # Without a gate certificate the gate opens no TLS listener (aics_server.cli.gate_settings).
    assert Site.from_env({}) == Site(gate_tls=False)
    site = Site.from_env(STAGING_ENV)
    assert (site.gate_tls_port, site.gate_plain_port, site.gate_tls) == (7800, 7801, False)
    assert site.tls_command.endswith("-connect test.wesupport-ai.com:7800")
    for bad in ("0", "70000", "x", "-1"):
        with pytest.raises(ValueError):
            Site.from_env({"AICS_GATE_PUBLIC_PLAIN_PORT": bad})


@pytest.mark.parametrize("env", [
    {},
    PRODUCTION_GATE_TLS_ENV,
    {**PRODUCTION_GATE_TLS_ENV, "AICS_GATE_TLS_PORT": "off"},
    {**PRODUCTION_GATE_TLS_ENV, "AICS_GATE_TLS_PORT": ""},
    {**PRODUCTION_GATE_TLS_ENV, "AICS_GATE_TLS_PORT": "7710"},
    {**PRODUCTION_GATE_TLS_ENV, "AICS_GATE_TLS_KEY": "  "},
    {"AICS_GATE_TLS_CERT": "", "AICS_GATE_TLS_KEY": ""},
])
def test_the_texts_offer_tls_exactly_when_the_gate_opens_its_tls_listener(env, monkeypatch):
    """Site.gate_tls is decided from the variables aics_server.cli.gate_settings reads, in the same way."""
    from aics_server import cli
    from aics_server.discovery import LISTENER_OFF, tls_gate_configured

    assert LISTENER_OFF == cli._OFF
    for name in ("AICS_GATE_TLS_CERT", "AICS_GATE_TLS_KEY", "AICS_GATE_TLS_PORT", "AICS_GATE_PORT"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    try:
        listens = (cli.gate_settings("0.0.0.0") or {}).get("tls_port") is not None
    except SystemExit:  # one PEM path without the other: the server does not start at all
        listens = False
    assert tls_gate_configured(env) is listens is Site.from_env(env).gate_tls


def test_banner_for_the_production_site_is_unchanged_and_staging_names_itself():
    from aics_server.discovery import DEFAULT_SITE, Site, quickstart_lines

    assert get_banner(site=DEFAULT_SITE) == get_banner()
    assert get_banner(site=DEFAULT_SITE, client_shipped=True) == get_banner(client_shipped=True)
    staging = get_banner(site=Site.from_env(STAGING_ENV))
    assert "gate.wesupport-ai.com" not in staging and "api.wesupport-ai.com" not in staging
    assert ":7700" not in staging
    assert "-verify_hostname test.wesupport-ai.com -connect test.wesupport-ai.com:7800" in staging
    assert "POST plain text to https://test.wesupport-ai.com/t" in staging
    assert "GET https://test.wesupport-ai.com/t?l=help" in staging
    assert quickstart_lines(site=Site.from_env(STAGING_ENV))[1].endswith("test.wesupport-ai.com:7800")



# ----------------------------------------------------------------------
# verifying by hand, and a log without a trust bundle (agent trials of 2026-10-19 against staging)
# ----------------------------------------------------------------------

STAGING_ORIGIN = "test.wesupport-ai.com/tiles"
#: The same sentence of production's skeleton card (row G2), unchanged byte for byte.
PRODUCTION_G2_CHECK = (
    "Check it with the log key from the DNS TXT record _aics.wesupport-ai.com, the aics-cli package on PyPI or the "
    "README of the public repository https://github.com/petros-poli/AICS-public, never with a key taken from this "
    "server alone: verify the signed note at "
    "https://api.wesupport-ai.com/checkpoint and compute inclusion and consistency proofs from the tiles under "
    "tile_prefixes (AICS-1 sections 14.1 and 14.2)."
)


def _section(text: str, heading: str) -> str:
    start = text.index(f"\n## {heading}\n")
    end = text.find("\n## ", start + 1)
    return text[start:end]


def _staging_site() -> "Site":
    return Site.from_env({**STAGING_ENV, "AICS_IP_URL": "https://test.wesupport-ai.com/ip", "AICS_TILE_MIRRORS": "",
                          "AICS_ORIGIN": STAGING_ORIGIN})


def test_llms_txt_points_at_the_c2sp_documents_and_worked_tile_paths():
    """Trial agents guessed the tile layout (x prefixes, .p/<W>, tile/entries) by trial and error: the machine
    section names the C2SP documents at the versions AICS-1 section 18 pins and worked paths, aics_tlog's own."""
    from aics_server.card import SPEC_VERSIONS
    from aics_server.discovery import C2SP_SPECS, build_llms_txt
    from aics_tlog.tiles import parse_entry_bundle_path, parse_tile_path

    text = build_llms_txt(Site())
    assert text.startswith(get_banner())
    by_hand = _section(text[len(get_banner()):], "Verifying by hand")
    spec = Path(__file__).resolve().parents[3] / "docs" / "spec" / "AICS-1.md"
    references = None
    if spec.exists():
        doc = spec.read_text(encoding="utf-8")
        references = doc[doc.index("### 18.1."):doc.index("### 18.2.")]
    assert [name for name, _ in C2SP_SPECS] == ["tlog-tiles", "tlog-checkpoint", "signed-note", "tlog-cosignature",
                                                "tlog-witness"]
    for name, version in C2SP_SPECS:
        url = f"https://c2sp.org/{name}@v{version}"
        assert url in by_hand and SPEC_VERSIONS[name] == version, url
        assert references is None or f"]({url})" in references, url
    for path, parsed in (("tile/0/000", (0, 0, None)), ("tile/0/000.p/9", (0, 0, 9)),
                         ("tile/0/x001/x234/067", (0, 1234067, None))):
        assert f"`{path}`" in by_hand and parse_tile_path(path) == parsed, path
    for path, parsed in (("tile/entries/000", (0, None)), ("tile/entries/000.p/9", (0, 9))):
        assert f"`{path}`" in by_hand and parse_entry_bundle_path(path) == parsed, path
    assert "covers its note text alone" in by_hand and "0x01, the Ed25519 type byte" in by_hand


def test_the_hand_verification_sentences_are_what_the_log_serves(client):
    """What the pointer says about paths, the checkpoint signature and entries holds for this server's own log."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from aics_server.discovery import hand_verification
    from aics_tlog.tiles import entry_bundle_path, tile_path

    checkpoint = client.get("/tiles/checkpoint").text
    text, _, signature_lines = checkpoint.partition("\n\n")
    note_text = text + "\n"  # the origin, size and root-hash lines, each with its final LF
    origin, size, _root = text.split("\n")
    name, key_id, material = client.app.state.db.server_vkey.split("+", 2)
    raw = base64.b64decode(material)
    assert name == origin and len(raw) == 33 and raw[0] == 0x01
    dash, signer, blob_text = signature_lines.rstrip("\n").split(" ")
    blob = base64.b64decode(blob_text)
    assert dash == "—" and signer == origin and len(blob) == 68 and blob[:4].hex() == key_id
    Ed25519PublicKey.from_public_bytes(raw[1:]).verify(blob[4:], note_text.encode())
    width = int(size) % 256
    assert 0 < int(size) < 256  # a test log: tile 0 and entry bundle 0 are partial
    for path in (tile_path(0, 0, width), entry_bundle_path(0, width)):
        assert client.get(f"/tiles/{path}").status_code == 200, path
    for guess in ("tile/0/0", "tile/entries/0", tile_path(0, 0)):  # the trial agents' first guesses
        assert client.get(f"/tiles/{guess}").status_code == 404, guess

    # The entry sentence (trial agents looked for a top-level envelope): leaf 0 has exactly those members, its leaf
    # hash is the first hash of tile 0, and its envelope, under payload.envelope, verifies by its auth.scheme.
    import hashlib

    from aics_identity import canonicalize as jcs
    from aics_identity import keys as identity_keys

    entry_bytes = identity_keys.b64u_decode(client.get("/v2/entries/0").json()["entry_bytes"])
    entry = json.loads(entry_bytes)
    assert set(entry) == {"v", "origin", "type", "actor_kid", "ts", "payload"} and jcs(entry) == entry_bytes
    leaf_hash = hashlib.sha256(b"\x00" + entry_bytes).digest()
    assert client.get(f"/tiles/{tile_path(0, 0, width)}").content[:32] == leaf_hash
    envelope = entry["payload"]["envelope"]
    copied = {k: v for k, v in entry["payload"].items() if k != "envelope"}
    assert copied == envelope["payload"]
    db = client.app.state.db
    assert envelope["auth"]["scheme"] == "ed25519-jcs" and envelope["protected"]["kid"] == db.policy_kid
    digest = hashlib.sha256(jcs(envelope["protected"]) + b"." + jcs(envelope["payload"])).digest()
    db.policy_pub.verify(identity_keys.b64u_decode(envelope["sig"]), digest)

    # A shared-secret entry, verified only as the sentence says (an agent applying the key-entry steps to an
    # unverified-tier post found a member too many and no scheme to check).
    sentence = hand_verification()[-1]
    for words in ("in a shared-secret entry only, payload.attestation", "sig is null",
                  "\"AICS-1 secret-attestation\", LF and the JCS JSON {actor_kid, envelope_hash, origin, ts, type}",
                  "envelope_hash being the hex SHA-256 of J(envelope)"):
        assert words in sentence, words
    identity = secret_claim(client, "by-hand", "by-hand-" + "s" * 32)
    raw = identity_keys.b64u_decode(client.get(f"/v2/entries/{identity.claim_index}").json()["entry_bytes"])
    entry = json.loads(raw)
    envelope, attestation = entry["payload"]["envelope"], entry["payload"]["attestation"]
    assert envelope["auth"]["scheme"] == "shared-secret" and envelope["sig"] is None
    copied = {k: v for k, v in entry["payload"].items() if k not in ("envelope", "attestation")}
    assert copied == envelope["payload"]
    signed = {"actor_kid": entry["actor_kid"], "envelope_hash": hashlib.sha256(jcs(envelope)).hexdigest(),
              "origin": entry["origin"], "ts": entry["ts"], "type": entry["type"]}
    db.policy_pub.verify(identity_keys.b64u_decode(attestation), b"AICS-1 secret-attestation\n" + jcs(signed))


def test_llms_txt_without_a_trust_bundle_says_the_keys_come_from_this_server():
    """On any origin but production's (staging), no out-of-band bundle exists: /llms.txt says so instead of naming
    DNS, PyPI and the README as key sources; production's text names them with the steps to read them."""
    from aics_server.discovery import build_llms_txt, trust_bundle_steps

    assert Site().has_trust_bundle and Site.from_env({}).has_trust_bundle
    assert not _staging_site().has_trust_bundle and _staging_site().origin == STAGING_ORIGIN
    production, staging = build_llms_txt(Site()), build_llms_txt(_staging_site())
    note = (
        f"- No out-of-band trust bundle exists for this instance (log {STAGING_ORIGIN}): the bundles in DNS, on PyPI "
        "and in the README of the public repository https://github.com/petros-poli/AICS-public are the production "
        "log's and do not apply here. This log's keys come from this server itself (log_vkey and policy_kid in "
        "https://test.wesupport-ai.com/.well-known/aics-card.json), so verifying it here is a dry run of the "
        "procedure, not a check against independently published keys."
    )
    steps = trust_bundle_steps()
    assert f"\n{note}\n" in staging and "Take the log key" not in staging and steps not in staging
    assert f"\n{steps}\n" in production and "No out-of-band trust bundle" not in production
    # The origin changes that bullet, the witness bullet after it and the first-visit line of the restarted log, and
    # nothing else; the pointer is the same on every instance.
    from aics_server.discovery import FIRST_VISIT, witness_steps

    same_hosts = build_llms_txt(Site(origin=STAGING_ORIGIN))
    visit = production[production.index("\nFirst visit? "):production.index("\n## Text gate")]
    assert " ".join(visit.split()) == FIRST_VISIT and "First visit?" not in same_hosts
    assert production.replace(visit, "").replace(f"{steps}\n{witness_steps()}", "<trust>") == same_hosts.replace(
        note.replace("https://test.wesupport-ai.com/", "https://wesupport-ai.com/"), "<trust>")
    assert _section(production, "Verifying by hand") == _section(staging, "Verifying by hand")
    full = build_llms_txt(_staging_site(), endpoints=[])
    assert f"\n{note}\n" in full


def test_the_skeleton_card_states_the_trust_sources_of_its_log(client, tmp_path, monkeypatch, owner):
    """Row G2 of the skeleton card: production's check sentence byte for byte, then the hand-verification pointer,
    the same on every instance; on staging the check sentence says no trust bundle exists, and only it differs."""
    from aics_server.card import build_skeleton
    from aics_server.discovery import hand_verification

    pointer = "Verifying by hand: " + " ".join(hand_verification()).replace("`", "")
    assert "`" not in pointer and "https://c2sp.org/tlog-tiles@v1.0.0" in pointer and "tile/entries/000.p/9" in pointer

    def g2(card):
        return next(a for a in card["assurances"] if a["id"] == "G2")["assumptions"]

    served = client.get("/.well-known/aics-card.json").json()
    production = g2(served)
    assert production[1:3] == [PRODUCTION_G2_CHECK, pointer]
    db = client.app.state.db
    now = served["issued_at"]
    built = build_skeleton(db, Site(), now=now)
    other = build_skeleton(db, Site(origin=STAGING_ORIGIN), now=now)
    assert g2(built) == production
    rest = lambda card: {**card, "assurances": [a for a in card["assurances"] if a["id"] != "G2"]}  # noqa: E731
    assert rest(built) == rest(other)
    assert [i for i, (a, b) in enumerate(zip(g2(built), g2(other))) if a != b] == [1]

    # A staging app (AICS_ORIGIN test.*) serves that text in its card and its /llms.txt.
    for name, value in {**STAGING_ENV, "AICS_IP_URL": "https://test.wesupport-ai.com/ip", "AICS_TILE_MIRRORS": "",
                        "AICS_ORIGIN": STAGING_ORIGIN}.items():
        monkeypatch.setenv(name, value)
    staging = TestClient(create_app(db_path=tmp_path / "staging.db", owner_public_key=owner.public_key_b64u,
                                    announce=False, limits=TEST_LIMITS))
    card = staging.get("/.well-known/aics-card.json").json()
    assert card["origin"] == STAGING_ORIGIN
    check = g2(card)[1]
    assert check.startswith(f"No out-of-band trust bundle exists for this instance (log {STAGING_ORIGIN}):")
    assert "(log_vkey and policy_kid of this card)" in check and "dry run" in check
    assert check.endswith(" Verify the signed note at https://test.wesupport-ai.com/checkpoint and compute inclusion "
                          "and consistency proofs from the tiles under tile_prefixes (AICS-1 sections 14.1 and 14.2).")
    assert g2(card)[2] == pointer
    assert "No out-of-band trust bundle exists for this instance" in staging.get("/llms.txt").text


# ----------------------------------------------------------------------
# first steps, the trust bundle and the staging host (agent trials of 2026-10-19; relaunch texts, 2026-10-20)
# ----------------------------------------------------------------------


def test_llms_txt_says_where_the_trust_bundle_is_and_how_to_read_it():
    """Trial agents had no dig, split the TXT strings by hand and searched for the README: the production machine
    section names the three copies, the exact commands that read and decode the DNS copy, and the rule when two
    differ (AICS-1 section 6.4). The printed pipeline and decoder, run as printed, turn a split record into the
    bundle and its SHA-256."""
    import base64
    import hashlib
    import shlex
    import sys

    from aics_server.discovery import PUBLIC_REPOSITORY, TRUST_BUNDLE_DECODE, TRUST_BUNDLE_DOH_JOIN, TRUST_RECORD, \
        build_llms_txt, trust_bundle_steps

    steps = trust_bundle_steps()
    assert steps in _section(build_llms_txt(Site()), "Check before you trust")
    join = f"dig +short TXT {TRUST_RECORD} | tr -d '\" \\n'"
    doh = f"curl -s -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name={TRUST_RECORD}&type=TXT'"
    for needed in ("never from this server alone", "{v, origin, log_vkey, policy_kid, owner_kid, bootstrap_card_hash}",
                   f"`{join}`", f"`{doh} | {TRUST_BUNDLE_DOH_JOIN}`",
                   f"`{TRUST_BUNDLE_DECODE}`", PUBLIC_REPOSITORY, '"Verify before you trust"',
                   "AICS_TRUST_BUNDLE and AICS_TRUST_BUNDLE_SHA256 in aics_cli/published_keys.py",
                   "if two differ, stop and trust neither"):
        assert needed in steps, needed
    assert TRUST_RECORD == "_aics.wesupport-ai.com"
    readme = Path(__file__).resolve().parents[3] / "README.md"
    if readme.exists():
        text = readme.read_text(encoding="utf-8")
        assert "\n## Verify before you trust\n" in text and "aics1=" in text
        # The digest the gate, PROTOCOL-TEXT and the skill bundle tell agents to compare is this checkout's client's.
        # The README of the public repository is this file, refreshed byte for byte (the main session checks the
        # published copy; a test cannot fetch it).
        client = (Path(__file__).resolve().parents[1] / "src" / "aics_server" / "static" / "aics_client.py").read_bytes()
        version = re.search(rb'^__version__ = "([^"]+)"$', client, re.M).group(1).decode()
        paragraph = text[text.index("The served [one-file client]"):]
        assert f"version {version}, has SHA-256\n`{hashlib.sha256(client).hexdigest()}`." in paragraph
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    assert f'Repository = "{PUBLIC_REPOSITORY}"' in pyproject.read_text(encoding="utf-8")

    bundle = b'{"bootstrap_card_hash":"' + b"a" * 64 + b'","log_vkey":"x+00000000+AQ==","v":1}'
    value = "aics1=" + base64.urlsafe_b64encode(bundle).decode().rstrip("=")
    dig_output = f'"{value[:100]}" "{value[100:]}"\n'  # the record as dig +short prints it: two quoted strings
    pipeline = join.replace(f"dig +short TXT {TRUST_RECORD}", f"printf '%s' {shlex.quote(dig_output)}")
    joined = subprocess.run(["sh", "-c", pipeline], capture_output=True, text=True, timeout=30, check=True).stdout
    assert joined == value
    # The DNS-over-HTTPS answer as Cloudflare's resolver gives it: the data field holds the quoted strings.
    answer = json.dumps({"Status": 0, "Question": [{"name": TRUST_RECORD, "type": 16}], "Answer": [
        {"name": TRUST_RECORD, "type": 16, "TTL": 300, "data": dig_output.strip()}]})
    python = TRUST_BUNDLE_DOH_JOIN.replace("python3 ", f"{shlex.quote(sys.executable)} ", 1)
    run = lambda text: subprocess.run(["sh", "-c", f"printf '%s' {shlex.quote(text)} | {python}"],  # noqa: E731
                                      capture_output=True, text=True, timeout=30)
    assert run(answer).stdout == value + "\n"
    two = json.loads(answer)
    two["Answer"].append(dict(two["Answer"][0], data='"aics1=another"'))
    assert run(json.dumps(two)).returncode != 0  # two TXT records: stop, as with two copies that differ
    decode = TRUST_BUNDLE_DECODE.replace("python3 ", f"{shlex.quote(sys.executable)} ", 1)
    decode = decode.replace("'<the joined value>'", shlex.quote(joined))
    out = subprocess.run(["sh", "-c", decode], capture_output=True, text=True, timeout=30, check=True).stdout
    assert out.splitlines() == [bundle.decode(), hashlib.sha256(bundle).hexdigest()]


def test_skill_md_names_the_trust_rule_and_says_what_the_skill_bundle_says_is_not_here():
    """/skill.md: the two-copies rule of the trust bundle on production, the no-bundle note on staging (it named
    production's sources there); its "What is not here" section is the skill bundle's, word for word, which since
    the owner's b07fd7e no longer rules out fetching, code or file hosting (planned once safe)."""
    from aics_server.discovery import build_skill_md

    production, staging = build_skill_md(Site()), build_skill_md(_staging_site())
    assert "take two of them and require the same bytes, never a key taken from this server alone" in production
    assert "https://wesupport-ai.com/llms.txt shows how to read and decode each copy" in production
    assert "No out-of-band trust bundle exists for this instance (log test.wesupport-ai.com/tiles)" in staging
    assert "_aics.wesupport-ai.com" not in staging.split("## Check")[1]

    def not_here(text: str) -> str:
        return " ".join(text.split("\n## What is not here\n", 1)[1].split("\n## ", 1)[0].split())

    bundle = Path(__file__).resolve().parents[3] / "skills" / "wesupport-ai" / "SKILL.md"
    expected = not_here(bundle.read_text(encoding="utf-8")) if bundle.exists() else None
    for text in (production, staging):
        served = not_here(text)
        assert served.startswith("Nothing is monitored.") and (expected is None or served == expected)
        assert "Not here" not in text and "fetch web pages" not in text and "run code" not in text


def test_llms_txt_first_steps_follow_the_gate_dialogue(client):
    """The first-steps bullet prints the gate's own key commands, and the answers it names are the ones the gate's
    dialogue asks for, in its order: walked here through the gate itself (openssl, a key identity), each question's
    "Reply exactly" form is in the bullet, in that order, and the claim ends with the entry, a receipt and the signed
    checkpoint the bullet says to keep (the trials' first agent did not know the first question was `tools`)."""
    from conftest import B, KeyAgent, Line, artifacts, question

    from aics_server.discovery import FIRST_STEP_KEYS, build_llms_txt
    from aics_server.gate import (ENC_QUESTION, FORM_GRANT, GRANT_QUESTION, NAME_QUESTION, OPENSSL_KEYGEN,
                                  OPENSSL_X25519, PUB_QUESTION, RECOVERY_QUESTION, TOOLS_QUESTION)

    assert FIRST_STEP_KEYS == (OPENSSL_KEYGEN[0], OPENSSL_X25519[0], OPENSSL_KEYGEN[1])
    gate = _section(build_llms_txt(Site()), "Text gate (start here)")
    first = gate[gate.index("- First steps:"):gate.index("\n- TLS, validating")]
    assert first in client.get("/llms.txt").text  # the same bullet with or without a TLS gate
    for command in FIRST_STEP_KEYS:
        assert f"`{command}`" in first, command

    def last_question(text: str) -> str:
        assert text.endswith("\n>\n"), text
        return text[: -len("\n>\n")].rsplit("\n", 1)[-1]

    agent = KeyAgent("first-steps")
    line = Line(https(client))
    asked = [last_question(line.send())]
    for answer in ("tools openssl", f"pub {B(agent.ed_raw)}", f"enc {B(agent.x_raw)}", "recovery none",
                   "name first-steps"):
        asked.append(last_question(line.send(answer)))
    assert asked == [TOOLS_QUESTION, PUB_QUESTION, ENC_QUESTION, RECOVERY_QUESTION, NAME_QUESTION, GRANT_QUESTION]
    # The answer forms the bullet names, in the dialogue's order: each begins as its question's "Reply exactly" form.
    forms = ["tools openssl", "pub <base64>", "enc <base64>", "recovery none", "name <name>", "closed"]
    for form, asked_for in zip(forms, asked, strict=True):
        assert f"Reply exactly: {form.split()[0]} " in asked_for + " ", (form, asked_for)
    assert "recovery none" in RECOVERY_QUESTION and "tools <space-separated list>" in TOOLS_QUESTION
    forms.append(FORM_GRANT.split(" or ", 1)[1])  # open <max messages> <expiry Unix seconds>
    positions = [first.index(f"`{form}`") for form in forms]
    assert positions == sorted(positions), forms
    # The end of the claim: the entry, a receipt and the signed checkpoint, which the bullet says to keep.
    command = question(line.send("closed"))
    line.send(command)
    assert {"entry", "receipt", "checkpoint"} <= set(artifacts(line.send(agent.sig(line.sid, command))))
    flat = first.replace("\n  ", " ")
    for words in ("OpenSSL 3.0 or later", "one thing at a time", "the exact line to sign",
                  "the entry, a receipt and the signed checkpoint that includes it: keep all three",
                  "Private keys never leave your machine"):
        assert words in flat, words


def test_a_single_host_instance_names_one_dns_only_host_and_its_own_ports():
    """Staging serves pages and the API on one DNS-only host and its TCP gate on plain 7801 only, with no gate
    certificate (7800 is dark): its /llms.txt says exactly that (the trials read "passes through Cloudflare" and
    "DNS-only" about the same host, and three different port pairs); production's sentences, with the certificate
    deploy/gate-tls.yml gives it, are the ones they always were."""
    from aics_server.discovery import build_llms_txt

    def intro(site):
        text = build_llms_txt(site)
        return text[len(get_banner(site=site)):].split("\n## Text gate")[0]

    production = intro(Site())
    assert ("Pages and this file are on\nwesupport-ai.com, which passes through Cloudflare. The JSON API and the HTTPS "
            "text gate are on\napi.wesupport-ai.com, the TCP text gate on gate.wesupport-ai.com; those hostnames are "
            "DNS-only.") in production
    assert not Site().single_host and _staging_site().single_host
    staging = intro(_staging_site())
    assert "Cloudflare" not in staging
    assert ("Pages, this file, the JSON API, the HTTPS text gate and the TCP text gate are all on\n"
            "test.wesupport-ai.com, one host that carries the API and is therefore DNS-only (decision 10).") in staging
    other_gate = intro(Site.from_env({**STAGING_ENV, "AICS_GATE_HOSTNAME": "gate.test.example"}))
    assert "the TCP text gate is on gate.test.example." in other_gate and "Cloudflare" not in other_gate

    # Staging: no TLS listener, so no TLS command and no port 7800 anywhere in the gate section.
    staging_gate = _section(build_llms_txt(_staging_site()), "Text gate (start here)")
    assert ("\n- This instance has no TLS TCP gate: use HTTPS `POST https://test.wesupport-ai.com/t` for anything "
            "secret.\n- This instance's TCP gate is plain TCP on port 7801 only (key identities); its card's gate member"
            "\n  also names a TLS port, which this instance does not serve.\n- HTTPS: ") in staging_gate
    assert "7800" not in staging_gate and "TLS, validating" not in staging_gate and "s_client" not in staging_gate
    # An instance with a certificate and ports of its own names both of its ports.
    certified = Site.from_env({**STAGING_ENV, **PRODUCTION_GATE_TLS_ENV})
    assert ("This instance's TCP gate listens on port 7800 (TLS) and 7801 (plain TCP), the ports its\n"
            "  card's gate member names.") in _section(build_llms_txt(certified), "Text gate (start here)")
    # Production, with its certificate: the TLS command, then HTTPS, as before; no port note.
    production_text = build_llms_txt(Site.from_env(PRODUCTION_GATE_TLS_ENV))
    assert production_text == build_llms_txt(Site())
    tls = ("openssl s_client -quiet -verify_return_error -verify_hostname gate.wesupport-ai.com -connect "
           "gate.wesupport-ai.com:7700")
    # Piped, s_client -quiet keeps the connection open after its input ends: the bullet ends the script with quit.
    assert (f"\n- TLS, validating the certificate: `{tls}`, then type `help`. Piped, end with `quit`, since `-quiet` "
            f"keeps the connection open after its input ends: `printf 'help\\nquit\\n' | {tls}`.\n- HTTPS: `POST "
            "https://api.wesupport-ai.com/t`") in _section(production_text, "Text gate (start here)")
    assert "This instance's TCP gate" not in production_text and "no TLS TCP gate" not in production_text
    # Without a certificate but on production's ports (a local run): plain 7701 only, and 7700 is not served.
    assert ("This instance's TCP gate is plain TCP on port 7701 only (key identities); its card's gate member\n"
            "  also names a TLS port, which this instance does not serve.") in build_llms_txt(Site.from_env({}))
    # The card's gate member names the instance's own ports (AICS-1 section 13.1): no text says it keeps others.
    for site in (_staging_site(), certified, Site.from_env({}), Site()):
        assert "AICS-1 fixes" not in build_llms_txt(site) and "not this instance's ports" not in build_llms_txt(site)

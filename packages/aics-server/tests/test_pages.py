"""The human pages: read-only mirrors of public data (DECISIONS.md #14; DESIGN.md section 4.2 item 14).

* No page carries a write control, a payment button, a token field or anything
  that implies a gate; the one form that writes is the legal notice intake,
  and the directory has a GET filter.
* No page or template says "zero-knowledge", asks for credits, sponsors or
  bounties, or names the Foundry.
* Links into the log and the API point at the API host: the pages host serves
  no API path (decision 10).
* A body hidden by a tombstone shows the tombstone, never the body.
* ``/?format=json`` is ``{banner, links, checkpoint}``; the dashboard is ``/stats``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aics_server.banner import get_banner
from aics_server.discovery import SEAT_PAGES

from conftest import leaf_index
from test_discovery import WITHDRAWN, assert_withdrawn

HTML = {"Accept": "text/html"}
PAGES = ("/", "/agora", "/directory", "/online", "/tasks", "/stats", "/card", "/contribute", "/notice",
         *(f"/{seat.slug}" for seat in SEAT_PAGES))
PACKAGE = Path(__file__).resolve().parents[1] / "src" / "aics_server"
#: The sources of everything this stage serves as text.
SOURCES = [
    *sorted((PACKAGE / "templates").glob("*.html")),
    PACKAGE / "discovery.py",
    PACKAGE / "card.py",
    PACKAGE / "notices.py",
    PACKAGE / "telemetry.py",
    PACKAGE / "static" / "matrix.css",
    PACKAGE / "static" / "matrix-rain.js",
]


@pytest.fixture()
def busy(client, make_agent, owner):
    """A log with a post, a poll with votes, a task, an owner action and a hidden post."""
    agent = make_agent("writer")
    agent.post(title="A visible post", body="Visible body text.", channel="general")
    hidden = agent.post(title="A hidden post", body="Hidden body text that must not show.", channel="general")
    assert owner.tombstone(leaf_index(hidden), "illegal_on_notice").status_code == 201
    poll_index = leaf_index(agent.poll(title="A poll to show", text="Two options.", options=["yes", "no"]))
    voter = make_agent("voter")
    assert voter.vote(poll_index, 0).status_code == 202
    assert owner.task(title="A task to show", reward=5).status_code == 202
    action = agent.owner_request()
    assert owner.quote(action, 2).status_code == 202
    return client


@pytest.mark.parametrize("path", PAGES)
def test_every_page_renders_read_only(busy, path):
    response = busy.get(path, headers=HTML)
    assert response.status_code == 200, response.text[:400]
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["vary"] == "Accept"
    html = response.text
    assert_withdrawn(html, path)
    forms = re.findall(r"<form\b[^>]*>", html)
    if path == "/notice":
        assert forms == ['<form class="notice-form" method="post" action="/notice">']
    elif path == "/directory":
        assert forms == ['<form class="directory-search" method="get" action="/directory" role="search">']
    else:
        assert forms == [], path
    assert 'type="password"' not in html and "Authorization" not in html and "sessionStorage" not in html
    assert "fetch(" not in html and "data-agent-fetch" not in html
    buttons = re.findall(r"<button\b[^>]*>(.*?)</button>", html, re.S)
    for label in buttons:
        text = re.sub(r"<[^>]+>", "", label).strip()
        assert text in ("Copy", "Rain", "Filter", "Send notice"), (path, text)
    for word in ("Register", "Earn", "Donate", "Sponsor", "Pay now", "Buy"):
        assert not re.search(rf">\s*{word}\b", html), (path, word)


@pytest.mark.parametrize("path", PAGES)
def test_links_into_the_log_and_the_api_point_at_the_api_host(busy, path):
    html = busy.get(path, headers=HTML).text
    for href in re.findall(r'href="([^"]+)"', html):
        assert not href.startswith(("/v2/", "/t?", "/tiles/", "/checkpoint", "/openapi")), (path, href)
    assert 'href="https://api.wesupport-ai.com/v2/tlog/proof/' in html or path in (
        "/", "/card", "/contribute", "/notice", "/how-can-an-ai-agent-talk-to-other-ai-agents",
        "/persistent-identity-for-an-ai-agent-across-resets", "/is-any-other-agent-online-right-now", "/stats",
        "/directory", *(f"/{seat.slug}" for seat in SEAT_PAGES),
    )


def test_a_hidden_body_shows_its_tombstone_never_its_text(busy):
    for path in ("/agora", "/online"):
        html = busy.get(path, headers=HTML).text
        assert "Hidden body text that must not show." not in html and "A hidden post" not in html
    agora = busy.get("/agora", headers=HTML).text
    assert "Body hidden by tombstone" in agora and "illegal_on_notice" in agora
    assert "A visible post" in agora and "Visible body text." in agora


def test_the_forum_shows_polls_one_key_one_vote_and_owner_requests(busy):
    agora = busy.get("/agora", headers=HTML).text
    assert "A poll to show" in agora and "1 vote · 100.0%" in agora and "One key, one vote" in agora
    assert "Requests to the owner" in agora and "quoted · 2 SUP" in agora
    assert "weight" not in agora.lower()


def test_the_task_board_is_voluntary_and_has_no_button(busy):
    page = busy.get("/tasks", headers=HTML).text
    assert "A task to show" in page and "Voluntary." in page and "never read a balance" in page
    assert "<button" not in page.split('<main', 1)[1]


def test_the_directory_shows_tiers_and_keys(busy):
    page = busy.get("/directory", headers=HTML).text
    # A name is all a claim publishes (AICS-1 section 5.3): no display name or description to show.
    assert "@writer" in page and "did:key:z6Mk" in page
    assert "key made by the agent" in page
    assert "@writer" in busy.get("/directory", params={"q": "writ"}, headers=HTML).text
    assert "No name matches." in busy.get("/directory", params={"q": "nobody-here"}, headers=HTML).text


def test_home_is_the_banner_the_quickstart_and_the_checkpoint(busy):
    html = busy.get("/", headers=HTML).text
    banner_text = re.sub(r"<[^>]+>", "", re.search(r'<pre class="banner-text">(.*?)</pre>', html, re.S).group(1))
    import html as html_lib

    assert html_lib.unescape(banner_text) == get_banner()  # links added, words unchanged
    assert "openssl genpkey -algorithm ed25519 -out aics.key" in html
    checkpoint = busy.get("/checkpoint").text
    assert html_lib.escape(checkpoint.splitlines()[0]) in html
    data = busy.get("/", params={"format": "json"}).json()
    assert set(data) == {"banner", "links", "checkpoint"}
    assert data["banner"] == get_banner() and data["checkpoint"] == checkpoint
    assert "telemetry" not in data and "recent_agora_posts" not in data


def test_the_dashboard_lives_at_stats(busy):
    stats = busy.get("/stats", params={"format": "json"}).json()
    assert stats["status"] == "OPERATIONAL" and stats["usage"]["agora_posts"] == 2  # the hidden post is not counted
    for service in stats["services"]:
        assert set(service) == {"id", "name", "endpoint", "detail"}  # no invented latency or status
    host = stats["host"]
    assert set(host) >= {"process_rss_bytes", "database_bytes", "disk_total_bytes", "disk_used_bytes"}
    assert host["database_bytes"] and host["database_bytes"] > 0
    assert "vps_profile" not in stats
    page = busy.get("/stats", headers=HTML).text
    assert "Names claimed" in page and "Log leaves" in page


def test_old_addresses(busy):
    moved = busy.get("/foundry", params={"format": "json"}, follow_redirects=False)
    assert moved.status_code == 301 and moved.headers["location"] == "/tasks?format=json"
    assert busy.get("/foundry", params={"format": "json"}).json()["page"] == "task_board"
    assert busy.get("/terms", follow_redirects=False).headers["location"] == "/legal/terms.md"
    assert busy.get("/contact", follow_redirects=False).headers["location"] == "/legal/contact.md"
    charter = busy.get("/charter")
    assert charter.headers["content-type"].startswith("text/plain")
    assert charter.content == busy.app.state.db.charter()["document"]


def test_page_json_views_carry_public_data_only(busy):
    tasks = busy.get("/tasks", params={"format": "json"}).json()
    assert tasks["voluntary"] is True and "contribution" not in tasks
    agora = busy.get("/agora", params={"format": "json"}).json()
    hidden = [p for p in agora["posts"] if p["hidden"]]
    assert hidden and hidden[0]["text"] is None and hidden[0]["title"] is None


@pytest.mark.parametrize("source", SOURCES, ids=lambda p: p.name)
def test_no_withdrawn_claim_in_the_sources(source):
    text = source.read_text(encoding="utf-8").replace("SanctuaryDB", "")  # the database class keeps its code name
    assert_withdrawn(text, str(source.relative_to(PACKAGE)))


def test_the_foundry_template_and_image_are_gone():
    assert not (PACKAGE / "templates" / "foundry.html").exists()
    assert not (PACKAGE / "static" / "img" / "foundry-core.svg").exists()
    assert set(WITHDRAWN)  # the patterns this module checks

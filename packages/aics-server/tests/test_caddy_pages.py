"""Every page the server links on the pages host is one deploy/Caddyfile serves there.

The pages host (wesupport-ai.com, www, Cloudflare-proxied: decision 10) forwards an
explicit allowlist to the app and answers everything else with a pointer to the API
host.  A page the server links on that host (``Site.page`` in /llms.txt, /skill.md,
/sitemap.txt, /?format=json, the agent-protocol manifest, the agent-seat pages) or
links relatively from its own HTML must be on that allowlist, or the advertised link
is a 404 (the review found /online, /tasks, /sitemap.txt and the agent-seat pages
missing).  This test reads the Caddyfile and the links the running app emits.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from aics_server.discovery import SEAT_PAGES

CADDYFILE = Path(__file__).resolve().parents[3] / "deploy" / "Caddyfile"
PAGES_SITE = "wesupport-ai.com, www.wesupport-ai.com {"
HTML = {"Accept": "text/html"}


def _block(text: str, opener: str) -> str:
    """The body of the Caddy site block that starts with *opener* (brace matching)."""
    start = text.index(opener) + len(opener)
    depth, i = 1, start
    while depth:
        ch = text[i]
        depth += ch == "{"
        depth -= ch == "}"
        i += 1
    return text[start : i - 1]


def _uncommented(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


class PagesHost:
    """What the pages-host block of the Caddyfile serves: proxied pages, file prefixes, fixed answers."""

    def __init__(self, caddyfile: str) -> None:
        block = _uncommented(_block(caddyfile, PAGES_SITE))
        pages = re.search(r"@pages\s*\{(.*?)\}", block, re.S)
        assert pages is not None, "the pages host has no @pages matcher"
        path_line = re.search(r"^\s*path\s+(.+)$", pages.group(1), re.M)
        assert path_line is not None
        self.pages = path_line.group(1).split()
        self.prefixes = re.findall(r"^\s*handle_path\s+(\S+)\s*\{", block, re.M)
        top = re.search(r"^\s*@top_docs\s+path\s+(.+)$", block, re.M)
        self.documents = top.group(1).split() if top else []
        self.handled: dict[str, str] = {}
        for path, body in re.findall(r"^\s*handle\s+(/\S*)\s*\{(.*?)^\s*\}", block, re.M | re.S):
            self.handled[path] = body

    @staticmethod
    def _match(pattern: str, path: str) -> bool:
        return path.startswith(pattern[:-1]) if pattern.endswith("*") else path == pattern

    def serves(self, path: str) -> bool:
        if any(self._match(p, path) for p in (*self.pages, *self.prefixes, *self.documents)):
            return True
        body = self.handled.get(path)
        # A handled path serves when it reaches the app, or answers with a 200 of its own.
        return body is not None and ("reverse_proxy" in body or re.search(r"respond\s+\".*\"\s+200", body, re.S) is not None)


@pytest.fixture(scope="module")
def pages_host() -> PagesHost:
    if not CADDYFILE.exists():
        pytest.skip("deploy/Caddyfile is not next to this package")
    return PagesHost(CADDYFILE.read_text(encoding="utf-8"))


def _absolute_paths(text: str, host: str) -> set[str]:
    found = set()
    for url in re.findall(rf"https://(?:www\.)?{re.escape(host)}(?:/[^\s\"'<>)\]`]*)?", text):
        path = urlsplit(url.rstrip(".,;:")).path or "/"
        found.add(path)
    return found


def _relative_links(html: str) -> set[str]:
    return {urlsplit(link).path for link in re.findall(r"""(?:href|src|action)="(/[^"]*)\"""", html) if not link.startswith("//")}


def test_the_parser_reads_the_pages_host(pages_host):
    assert "/llms.txt" in pages_host.pages and "/static/*" in pages_host.pages
    assert pages_host.serves("/static/aics_client.py") and pages_host.serves("/legal/terms.md")
    assert pages_host.serves("/notice") and not pages_host.serves("/checkpoint")  # /checkpoint points to the API
    assert not pages_host.serves("/v2/limits") and not pages_host.serves("/t")


def test_every_page_the_server_links_on_the_pages_host_is_served_there(client, make_agent, pages_host):
    make_agent("alice").post(title="A post for the pages", body="Pages link to posts and names.")
    site = client.app.state.site
    texts = [
        client.get(path).text
        for path in ("/llms.txt", "/llms-full.txt", "/skill.md", "/robots.txt", "/sitemap.txt", "/notice", "/tiles",
                     "/.well-known/agent-protocol.json", "/manifest.json", "/card")
    ]
    texts.append(client.get("/", params={"format": "json"}).text)
    for seat in SEAT_PAGES:
        texts.append(client.get(f"/{seat.slug}.md").text)
        texts.append(client.get(f"/{seat.slug}", params={"format": "json"}).text)
    linked = set().union(*(_absolute_paths(text, site.pages_host) for text in texts))
    html_pages = ["/", "/agora", "/directory", "/tasks", "/stats", "/online", "/contribute", "/card", "/notice",
                  *(f"/{seat.slug}" for seat in SEAT_PAGES)]
    for page in html_pages:
        response = client.get(page, headers=HTML)
        assert response.status_code == 200, page
        linked |= _relative_links(response.text)
    # The pages the review found unreachable are among them, so this check covers them.
    assert {"/online", "/tasks", "/sitemap.txt", *(f"/{s.slug}" for s in SEAT_PAGES), *(f"/{s.slug}.md" for s in SEAT_PAGES)} <= linked
    missing = sorted(path for path in linked if not pages_host.serves(path))
    assert missing == [], f"linked on {site.pages_host} but not served there by deploy/Caddyfile: {missing}"


def test_the_sitemap_robots_points_to_is_served(client, pages_host):
    robots = client.get("/robots.txt").text
    sitemap = re.search(r"^Sitemap:\s*(\S+)$", robots, re.M).group(1)
    assert pages_host.serves(urlsplit(sitemap).path)
    for line in client.get("/sitemap.txt").text.splitlines():
        assert pages_host.serves(urlsplit(line).path), line


def test_foundry_redirects_to_a_served_page(client, pages_host):
    moved = client.get("/foundry", follow_redirects=False)
    assert moved.status_code == 301 and pages_host.serves(urlsplit(moved.headers["location"]).path)


def test_nested_doc_aliases_precede_app_and_generic_doc_fallbacks(tmp_path):
    """Docs must enter a matching handle before the unconditional app fallback."""
    import subprocess

    config = _uncommented(_block(CADDYFILE.read_text(), PAGES_SITE))
    # A bare top-level `route` is sorted after `handle`, including its unconditional
    # app fallback. The outer path-matching handle must select the docs branch first;
    # only then does `route` preserve nested alias order ahead of /docs/*.
    docs_handle = _block(config, "handle /docs/* {")
    docs_route = _block(docs_handle, "route {")
    mappings = []
    for match in re.finditer(r"handle_path (/docs/\S*) \{", docs_route):
        body = _block(docs_route[match.start():], match.group(0))
        root = re.search(r"root \* (/srv/docs/\S+)", body).group(1)
        mappings.append((match.group(1), root))
    repo = CADDYFILE.parents[1]
    export = tmp_path / "docs-public"
    subprocess.run(["bash", str(repo / "ops/sync-docs.sh"), str(export)], check=True,
                   capture_output=True, text=True)
    for path, source in [
        ("/docs/spec/AICS-1.md", repo / "docs/spec/AICS-1.md"),
        ("/docs/legal/charter.md", repo / "docs/legal/charter.md"),
        ("/docs/site/guide.md", repo / "docs/site/guide.md"),
        ("/docs/BANNER.md", repo / "docs/BANNER.md"),
    ]:
        pattern, root = next((pattern, root) for pattern, root in mappings
                             if PagesHost._match(pattern, path))
        relative = Path(root).relative_to("/srv/docs") / path.removeprefix(pattern[:-1])
        assert (export / relative).read_bytes() == source.read_bytes(), path

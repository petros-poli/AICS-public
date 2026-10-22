"""Every page the server links on the pages host is one deploy/Caddyfile serves there.

The pages host (wesupport-ai.com, www, Cloudflare-proxied: decision 10) forwards an
explicit allowlist to the app and answers everything else with a pointer to the API
host.  A page the server links on that host (``Site.page`` in /llms.txt, /skill.md,
/sitemap.txt, /?format=json, the agent-protocol manifest, the agent-seat pages) or
links relatively from its own HTML must be on that allowlist, or the advertised link
is a 404 (the review found /online, /tasks, /sitemap.txt and the agent-seat pages
missing).  This test reads the Caddyfile and the links the running app emits.

The staging host (test.wesupport-ai.com) proxies everything to the aics-staging instance
except the published documents, which it serves from files exactly as the pages host does
(the ``published_docs`` snippet): the staging instance links them on its own host, and the
first agent trial found them 404 there.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from aics_server.discovery import SEAT_PAGES

CADDYFILE = Path(__file__).resolve().parents[3] / "deploy" / "Caddyfile"
PAGES_ADDRESS = "wesupport-ai.com, www.wesupport-ai.com"
STAGING_HOST = "test.wesupport-ai.com"
HTML = {"Accept": "text/html"}


def _body_from(text: str, start: int) -> str:
    """The body of the block whose opening brace ends just before *start* (brace matching)."""
    depth, i = 1, start
    while depth:
        ch = text[i]
        depth += ch == "{"
        depth -= ch == "}"
        i += 1
    return text[start : i - 1]


def _block(text: str, opener: str) -> str:
    """The body of the Caddy block that starts with *opener* (brace matching)."""
    return _body_from(text, text.index(opener) + len(opener))


def _uncommented(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _top_level_blocks(caddyfile: str) -> dict[str, str]:
    """Every top-level block of the Caddyfile (sites and snippets): its address line -> its body (comments removed)."""
    text = _uncommented(caddyfile)
    blocks: dict[str, str] = {}
    depth, i, line_start = 0, 0, 0
    while i < len(text):
        ch = text[i]
        if ch == "\n":
            line_start = i + 1
        elif ch == "{":
            if depth == 0:
                address = text[line_start:i].strip()
                body = _block(text[line_start:], text[line_start : i + 1])
                if address:  # the global options block has no address
                    blocks[address] = body
                i = line_start + len(text[line_start : i + 1]) + len(body) + 1
                continue
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    return blocks


def _sites(caddyfile: str) -> dict[str, str]:
    """Every site block of the Caddyfile: its address line -> its body, comments removed and each
    ``import <snippet>`` replaced by the snippet's body, as Caddy expands it.  Snippets
    (``(name) { ... }``) are not sites; an import of anything else fails here."""
    blocks = _top_level_blocks(caddyfile)
    def is_snippet(address: str) -> bool:
        return address.startswith("(") and address.endswith(")")

    snippets = {address[1:-1]: body for address, body in blocks.items() if is_snippet(address)}

    def expand(match: re.Match) -> str:
        assert match.group(1) in snippets, f"import {match.group(1)}: not a snippet of deploy/Caddyfile"
        return snippets[match.group(1)]

    sites = {}
    for address, body in blocks.items():
        if is_snippet(address):
            continue
        body = re.sub(r"^[ \t]*import[ \t]+(\S+)[ \t]*$", expand, body, flags=re.M)
        assert not re.search(r"^\s*import\b", body, re.M), f"{address}: an import this parser does not expand"
        sites[address] = body
    return sites


def _directives(body: str) -> list[tuple[str, str | None]]:
    """The top-level directives of a site body, in order: (head line, block body or None)."""
    found: list[tuple[str, str | None]] = []
    i = 0
    while i < len(body):
        end = body.find("\n", i)
        end = len(body) if end < 0 else end
        line = body[i:end].strip()
        if line.endswith("{"):
            opening = i + body[i:end].rindex("{")
            inner = _body_from(body, opening + 1)
            found.append((line[:-1].strip(), inner))
            i = opening + 1 + len(inner) + 1
            continue
        if line:
            found.append((line, None))
        i = end + 1
    return found


def _serves_files(block: str) -> bool:
    return re.search(r"^\s*file_server\b", block, re.M) is not None


def _documents(body: str) -> dict[str, str]:
    """A site's file-serving handlers: every top-level ``handle``/``handle_path`` whose block serves
    files, keyed by its matcher, with the definition of a named matcher it uses, whitespace-normalised
    so that two copies of the same lines compare equal."""
    directives = _directives(body)
    matchers = {head.split()[0]: head for head, inner in directives if head.startswith("@") and inner is None}
    found = {}
    for head, inner in directives:
        name, *args = head.split()
        if name in ("handle", "handle_path") and args and inner is not None and _serves_files(inner):
            found[args[0]] = " ".join(f"{matchers.get(args[0], '')} {head} {{ {inner} }}".split())
    return found


def _file_routes(body: str) -> list[tuple[str, str, bool]]:
    """Where a site block answers from files: (path pattern, root, prefix stripped) for every
    file-serving ``handle_path`` at any depth and every path of a named matcher that a
    file-serving ``handle`` uses."""
    routes = []
    for match in re.finditer(r"^[ \t]*(handle_path|handle)[ \t]+(\S+)[ \t]*\{", body, re.M):
        kind, matcher = match.groups()
        inner = _body_from(body, match.end())
        root = re.search(r"^\s*root\s+\*\s+(\S+)", inner, re.M)
        if root is None or not _serves_files(inner):
            continue
        if kind == "handle_path":
            routes.append((matcher, root.group(1), True))
        elif matcher.startswith("@"):
            paths = re.search(rf"^[ \t]*{re.escape(matcher)}[ \t]+path[ \t]+(.+)$", body, re.M)
            assert paths is not None, f"{matcher}: no path matcher"
            routes.extend((path, root.group(1), False) for path in paths.group(1).split())
    return routes


def _file_for(routes: list[tuple[str, str, bool]], path: str) -> str | None:
    """The file a request path is answered with (the most specific matching route wins), or None."""
    matching = [route for route in routes if PagesHost._match(route[0], path)]
    if not matching:
        return None
    pattern, root, stripped = max(matching, key=lambda route: len(route[0].rstrip("*")))
    return str(Path(root) / (path.removeprefix(pattern[:-1]) if stripped else path.lstrip("/")))


class PagesHost:
    """What the pages-host block of the Caddyfile serves: proxied pages, file prefixes, fixed answers."""

    def __init__(self, caddyfile: str) -> None:
        block = _sites(caddyfile)[PAGES_ADDRESS]
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
def sites() -> dict[str, str]:
    if not CADDYFILE.exists():
        pytest.skip("deploy/Caddyfile is not next to this package")
    return _sites(CADDYFILE.read_text(encoding="utf-8"))


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


@pytest.mark.parametrize("address", [PAGES_ADDRESS, STAGING_HOST])
def test_nested_doc_aliases_precede_app_and_generic_doc_fallbacks(tmp_path, address):
    """Docs must enter a matching handle before the unconditional app (or staging) fallback."""
    import subprocess

    config = _sites(CADDYFILE.read_text(encoding="utf-8"))[address]
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
        # The evidence a card names by hash (docs/evidence/README.md): inside the /docs/ export.
        ("/docs/evidence/README.md", repo / "docs/evidence/README.md"),
    ]:
        pattern, root = next((pattern, root) for pattern, root in mappings
                             if PagesHost._match(pattern, path))
        relative = Path(root).relative_to("/srv/docs") / path.removeprefix(pattern[:-1])
        assert (export / relative).read_bytes() == source.read_bytes(), path


# ---------------------------------------------------------------------------
# Staging (deploy/docker-compose.staging.yml): test.wesupport-ai.com routes to aics-staging
# only, apart from the published documents it serves from files like the pages host, and no
# production host ever routes there.
# ---------------------------------------------------------------------------


def _upstreams(body: str) -> set[str]:
    return set(re.findall(r"^\s*reverse_proxy\s+(?:@\S+\s+)?([^\s{]+)", body, re.M))


def _header_lines(body: str) -> list[str]:
    block = _block(body, "header {")
    return [line.strip() for line in block.splitlines() if line.strip()]


def test_the_site_parser_finds_every_host(sites):
    assert set(sites) == {
        PAGES_ADDRESS, "tiles.wesupport-ai.com", "api.wesupport-ai.com",
        "gate.wesupport-ai.com", "ip.wesupport-ai.com", STAGING_HOST,
    }
    assert _upstreams(sites["api.wesupport-ai.com"]) == {"aics-server:8080"}
    assert _upstreams(sites[PAGES_ADDRESS]) == {"aics-server:8080"}
    # Snippets are not sites; an imported one is part of the importing site's body.
    assert "(published_docs)" in _top_level_blocks(CADDYFILE.read_text(encoding="utf-8"))
    assert "handle_path /spec/*" in sites[STAGING_HOST]


def test_the_staging_host_serves_the_pages_hosts_documents(sites):
    """The staging instance links the published documents on its own host (/llms.txt names
    /docs/PROTOCOL-TEXT.md, the banner and card /spec/AICS-1.md and /legal/terms.md); the first
    agent trial found them 404 there.  The staging block serves exactly the pages host's file
    handlers: the same paths, the same roots in the read-only /srv/docs export, the same headers."""
    pages, staging = _documents(sites[PAGES_ADDRESS]), _documents(sites[STAGING_HOST])
    assert set(pages) == {"/spec/*", "/legal/*", "/site/*", "/docs/*", "@top_docs"}
    assert staging == pages
    for text in staging.values():
        # Files only: nothing in them proxies, answers, rewrites or redirects.
        assert not re.search(r"\b(reverse_proxy|respond|rewrite|redir|uri|try_files)\b", text), text
        assert set(re.findall(r"\broot \* (\S+)", text)) <= {"/srv/docs/spec", "/srv/docs/legal", "/srv/docs/site", "/srv/docs/docs"}
    routes = _file_routes(sites[STAGING_HOST])
    assert routes == _file_routes(sites[PAGES_ADDRESS])
    for path, file in [
        ("/spec/AICS-1.md", "spec/AICS-1.md"),
        ("/legal/terms.md", "legal/terms.md"),
        ("/legal/secret-patterns.json", "legal/secret-patterns.json"),
        ("/site/guide.md", "site/guide.md"),
        ("/docs/PROTOCOL-TEXT.md", "docs/PROTOCOL-TEXT.md"),
        ("/docs/spec/AICS-1.md", "spec/AICS-1.md"),
        ("/docs/legal/charter.md", "legal/charter.md"),
        ("/PROTOCOL-TEXT.md", "docs/PROTOCOL-TEXT.md"),
        ("/BANNER.md", "docs/BANNER.md"),
    ]:
        assert _file_for(routes, path) == f"/srv/docs/{file}", path
    # The instance's own pages, API, gate, tiles and OpenAPI page are not files.
    for path in ("/", "/llms.txt", "/card", "/terms", "/v2/limits", "/t", "/tiles/checkpoint", "/docs", "/ip"):
        assert _file_for(routes, path) is None, path


def test_production_hosts_never_route_to_staging(sites):
    for address, body in sites.items():
        if address == STAGING_HOST:
            continue
        assert STAGING_HOST not in address
        assert "aics-staging" not in body, address
        assert all(not up.startswith("aics-staging") for up in _upstreams(body)), address


def test_the_staging_host_routes_to_staging_only(sites):
    body = sites[STAGING_HOST]
    assert _upstreams(body) == {"aics-staging:8080"}
    assert "aics-server" not in body
    assert len(re.findall(r"^\s*reverse_proxy\b", body, re.M)) == 1
    directives = _directives(body)
    documents = _documents(body)
    # Besides the published documents (files, above), pages, API, /t and /tiles of the staging
    # instance all reach it through one unconditional handle; nothing is rewritten or redirected.
    assert {head.split()[0] for head, _ in directives} == {
        "tls", "encode", "header", "handle_path", "@top_docs", "handle", "handle_errors"}
    matched = [head.split()[1] for head, _ in directives if head.split()[0] in ("handle", "handle_path") and head != "handle"]
    assert sorted(matched) == sorted(documents)
    fallback = [inner for head, inner in directives if head == "handle"]
    assert len(fallback) == 1 and fallback[0].split() == ["reverse_proxy", "aics-staging:8080"]
    # The "not running" answer is for proxy failures only: a missing document is a plain 404,
    # as on the pages host, not a claim that staging is down.
    errors = [(head, inner) for head, inner in directives if head.startswith("handle_errors")]
    assert len(errors) == 1 and errors[0][0].split() == ["handle_errors", "502", "503", "504"]
    assert "not running" in errors[0][1]


def test_the_staging_host_is_dns_only_with_the_api_hosts_headers(sites):
    body, api = sites[STAGING_HOST], sites["api.wesupport-ai.com"]
    # DNS-only like api.*: ordinary HTTP-01, no Cloudflare DNS-01. The one tls block pins Let's Encrypt, as gate.*
    # does, so deploy/gate-tls-staging.yml finds the certificate under the Let's Encrypt directory.
    tls = [inner for head, inner in _directives(body) if head == "tls"]
    assert len(tls) == 1 and tls[0].split() == ["issuer", "acme"], tls
    assert "cloudflare" not in body.split("encode zstd gzip")[0]
    # The only files are the published documents (read-only /srv/docs): never production's tile
    # volume (/srv/tiles; the staging instance serves its own tiles) or any other mount.
    assert set(re.findall(r"/srv/[\w.-]+", body)) == {"/srv/docs"}
    assert "encode zstd gzip" in body
    staging_headers = _header_lines(body)
    assert [h for h in staging_headers if not h.startswith("X-Robots-Tag")] == _header_lines(api)
    assert 'X-Robots-Tag "noindex, nofollow"' in staging_headers

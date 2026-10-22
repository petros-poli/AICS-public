"""Routing and published documents after the first-visit readiness audit of 2026-10-20.

What the five cold walk-throughs found on the live site, each fixed in deploy/Caddyfile, the app or
ops/sync-docs.sh and checked here from the files:

* the banner's ``/checkpoint`` and ``/tiles`` did not resolve on the pages host (they live on the API host);
* ``/retention`` and ``/privacy``, which the texts cite, answered 404 and the footer had no privacy link;
* tiles.wesupport-ai.com sent no Content-Type and let the checkpoint be cached for 30 s (C2SP tlog-tiles v1.0.0:
  ``text/plain; charset=utf-8``, and a mutable endpoint is not cached beyond a few seconds; a cached checkpoint can
  lack the witness cosignature a quorum-1 verifier needs);
* the published documents carried a link into docs/internal, published the internal docs/DECISIONS.md and had
  spec links that answer 404 on the site.
"""

from __future__ import annotations

import posixpath
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from test_caddy_pages import CADDYFILE, PAGES_ADDRESS, STAGING_HOST, PagesHost, _block, _directives, _file_for, \
    _file_routes, _sites

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "ops" / "sync-docs.sh"
TILES_HOST = "tiles.wesupport-ai.com"
API = "https://api.wesupport-ai.com"
HTML = {"Accept": "text/html"}


@pytest.fixture(scope="module")
def sites() -> dict[str, str]:
    if not CADDYFILE.exists():
        pytest.skip("deploy/Caddyfile is not next to this package")
    return _sites(CADDYFILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def export(tmp_path_factory) -> Path:
    """A fresh ops/sync-docs.sh export, as deploy/docs-public is made before a deploy."""
    if not SCRIPT.exists():
        pytest.skip("ops/sync-docs.sh is not next to this package")
    destination = tmp_path_factory.mktemp("published") / "docs-public"
    subprocess.run(["bash", str(SCRIPT), str(destination)], check=True, capture_output=True, text=True, timeout=120)
    return destination


def _handled(body: str) -> dict[str, str]:
    """``handle <path> { ... }`` blocks at the top of a site body: path -> block body."""
    return {head.split()[1]: inner for head, inner in _directives(body)
            if head.startswith("handle ") and len(head.split()) == 2 and inner is not None}


# ----------------------------------------------------------------------
# the pages host
# ----------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/checkpoint", "/tiles", "/tiles/*"])
def test_the_banner_paths_redirect_to_the_api_host(sites, path):
    """The banner says "signed checkpoint at /checkpoint, tiles at /tiles"; on wesupport-ai.com those answered 404
    and a bare text.  They are permanent redirects (308: method and body kept) to the same path on the API host."""
    block = _handled(sites[PAGES_ADDRESS])[path]
    assert block.split() == ["redir", f"{API}{{uri}}", "308"], block


def test_the_redirects_point_at_paths_the_api_serves(client):
    """The targets exist: /checkpoint and /tiles on the API host are the app's (AICS-1 section 12.2)."""
    assert client.get("/checkpoint").status_code == 200
    tiles = client.get("/tiles")
    assert tiles.status_code == 200 and tiles.text.startswith("Tile prefixes (C2SP tlog-tiles): ")
    assert client.get("/tiles/checkpoint").text == client.get("/checkpoint").text


def test_no_tile_prefix_on_the_card_is_the_pages_host(client):
    """C2SP: resources inside a tile prefix never redirect.  The pages host is no prefix the card lists."""
    prefixes = client.get("/.well-known/aics-card.json").json()["tile_prefixes"]
    assert all(urlsplit(p).hostname != "wesupport-ai.com" for p in prefixes), prefixes


@pytest.mark.parametrize("path, document", [
    ("/retention", "retention.md"), ("/privacy", "retention.md"),
    ("/lawful-requests", "lawful-requests.md"), ("/cloudflare", "cloudflare-disclosure.md"),
])
def test_the_legal_paths_the_texts_cite_reach_the_published_document(client, sites, export, path, document):
    """/retention (cited by the terms) and /privacy (the footer) answered 404 on the pages host; like /terms they
    now redirect to the published document, and the pages host forwards them to the app."""
    host = PagesHost(CADDYFILE.read_text(encoding="utf-8"))
    assert path in host.pages
    moved = client.get(path, follow_redirects=False)
    assert moved.status_code == 302 and moved.headers["location"] == f"/legal/{document}"
    # HEAD as well (`curl -I`, link checkers): the route answered it 405.
    head = client.head(path, follow_redirects=False)
    assert head.status_code == 302 and head.headers["location"] == f"/legal/{document}"
    routes = _file_routes(sites[PAGES_ADDRESS])
    target = _file_for(routes, moved.headers["location"])
    assert target == f"/srv/docs/legal/{document}"
    assert (export / "legal" / document).read_bytes() == (REPO / "docs" / "legal" / document).read_bytes()
    # The staging host serves the same documents (its published_docs snippet) and its app redirects alike.
    assert _file_for(_file_routes(sites[STAGING_HOST]), f"/legal/{document}") == target


@pytest.mark.parametrize("path, document", [
    ("/terms", "terms.md"), ("/contact", "contact.md"), ("/retention", "retention.md"), ("/privacy", "retention.md"),
    ("/lawful-requests", "lawful-requests.md"), ("/cloudflare", "cloudflare-disclosure.md"),
])
def test_every_legal_redirect_answers_head_as_it_answers_get(client, sites, path, document):
    """`curl -sI https://wesupport-ai.com/terms` answered 405: FastAPI adds no HEAD to a GET route.  The pages host
    passes HEAD to the app (its @pages matcher), so each legal redirect answers HEAD with the same 302."""
    pages = re.search(r"@pages\s*\{(.*?)\}", sites[PAGES_ADDRESS], re.S)
    assert "HEAD" in re.search(r"^\s*method\s+(.+)$", pages.group(1), re.M).group(1).split()
    for method in ("GET", "HEAD"):
        moved = client.request(method, path, follow_redirects=False)
        assert (moved.status_code, moved.headers.get("location")) == (302, f"/legal/{document}"), method


def test_the_footer_links_the_privacy_text(client):
    page = client.get("/agora", headers=HTML).text
    footer = page[page.index('<footer class="matrix-footer'):]
    assert '<a href="/privacy">privacy</a>' in footer
    assert footer.index('href="/terms"') < footer.index('href="/privacy"') < footer.index('href="/contact"')


# ----------------------------------------------------------------------
# the tile mirror
# ----------------------------------------------------------------------

def _header_rules(body: str) -> list[tuple[str, dict[str, str]]]:
    """Every ``header <matcher> ...`` directive at any depth: (matcher, {field: value})."""
    rules = []
    for match in re.finditer(r"^[ \t]*header[ \t]+(\S+)[ \t]*(\{)?[ \t]*(.*)$", body, re.M):
        matcher, brace, rest = match.groups()
        if brace:
            inner = _block(body[match.start():], match.group(0)[: match.group(0).index("{") + 1].lstrip())
            fields = dict(re.findall(r'^\s*(\S+)\s+"([^"]*)"\s*$', inner, re.M))
        else:
            field, _, value = rest.partition(" ")
            fields = {field: value.strip().strip('"')}
        rules.append((matcher, fields))
    return rules


def test_the_tile_mirror_serves_the_checkpoint_as_text_never_cached(sites):
    body = sites[TILES_HOST]
    rules = _header_rules(body)
    checkpoint = [fields for matcher, fields in rules if matcher == "/checkpoint"]
    # /checkpoint at the top and /tiles/checkpoint inside handle_path /tiles/* (its prefix stripped).
    assert len(checkpoint) == 2, rules
    for fields in checkpoint:
        assert fields == {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"}, fields
    assert "max-age=30" not in body
    handler = _block(body, "handle_path /tiles/* {")
    assert ("/tile/*", {"Content-Type": "application/octet-stream"}) in _header_rules(handler)
    # Tile bytes keep their cache lives: full tiles immutable, partial ones a minute.
    assert ("@full", {"Cache-Control": "public, max-age=604800, immutable"}) in _header_rules(handler)
    assert ("@partial", {"Cache-Control": "public, max-age=60"}) in _header_rules(handler)
    # No redirect anywhere on the mirror (C2SP tlog-tiles: tile resources MUST NOT redirect).
    assert not re.search(r"^\s*redir\b", body, re.M)


def test_the_operator_note_on_cloudflare_caching_names_the_checkpoint():
    notes = (REPO / "ops" / "dns-records.md").read_text(encoding="utf-8")
    caching = notes[notes.index("- **Caching:**"):]
    caching = caching[: caching.index("\n- ", 3)]
    for words in ("no-store", "/checkpoint", "/tiles/checkpoint", "Bypass cache", "Browser Cache TTL"):
        assert words in caching, words
    assert "30 s for" not in caching


# ----------------------------------------------------------------------
# what ops/sync-docs.sh publishes
# ----------------------------------------------------------------------

def test_decisions_is_not_published(sites, export):
    """docs/DECISIONS.md is the owner's internal record: neither exported nor routed on any host."""
    assert not (export / "docs" / "DECISIONS.md").exists()
    assert "DECISIONS.md" not in (export / "docs" / "index.txt").read_text(encoding="utf-8").split()
    for address in (PAGES_ADDRESS, STAGING_HOST):
        assert "/DECISIONS.md" not in sites[address], address
    refused = subprocess.run(["bash", str(SCRIPT), "--check", str(REPO / "docs" / "DECISIONS.md")],
                             capture_output=True, text=True, timeout=120)
    assert refused.returncode == 1 and "outside the public allowlist" in refused.stderr


def test_an_export_removes_a_top_level_document_it_no_longer_publishes(tmp_path):
    """deploy/docs-public kept the docs/DECISIONS.md of an export made before 2026-10-20, and the next export refused
    to run ("REFUSED unexpected destination file") until it was removed by hand.  A stale top-level document is an
    old public Markdown file like those of spec/, legal/ and site/: the export removes it.  A stale evidence file or
    any other unexpected file still refuses the export, and stays where it is."""
    if not SCRIPT.exists():
        pytest.skip("ops/sync-docs.sh is not next to this package")

    def export(destination: Path) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(SCRIPT), str(destination)], capture_output=True, text=True, timeout=120)

    destination = tmp_path / "docs-public"
    assert export(destination).returncode == 0
    stale = destination / "docs" / "DECISIONS.md"
    stale.write_text("# The owner's decisions (an export of 2026-10-19)\n", encoding="utf-8")
    done = export(destination)
    assert done.returncode == 0, done.stderr
    assert not stale.exists()
    assert "DECISIONS.md" not in (destination / "docs" / "index.txt").read_text(encoding="utf-8").split()
    for planted in (destination / "docs" / "notes.txt", destination / "stray.md",
                    destination / "docs" / "evidence" / "conformance-1999-01-01-gone.md"):
        planted.write_text("not a published document\n", encoding="utf-8")
        refused = export(destination)
        assert refused.returncode == 1 and "REFUSED unexpected destination file" in refused.stderr, refused.stderr
        assert planted.exists()
        planted.unlink()


def test_the_usage_names_the_three_top_level_documents():
    """The usage text listed "the four top-level documents" after DECISIONS.md left the export."""
    usage = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True, timeout=60).stdout
    flat = " ".join(usage.split())
    assert "four top-level" not in flat and flat.count("three top-level documents") == 2
    assert "(BANNER.md, DESIGN.md, PROTOCOL-TEXT.md; never DECISIONS.md" in flat


def _published(export: Path) -> dict[str, Path]:
    """Every published document by the site path it is served at (its canonical path and its aliases)."""
    served: dict[str, Path] = {}
    for file in export.rglob("*"):
        if not file.is_file():
            continue
        relative = file.relative_to(export).as_posix()
        served["/" + relative] = file
        section = relative.split("/", 1)[0]
        if section in ("spec", "legal", "site"):
            served["/docs/" + relative] = file
        elif section == "docs" and relative.count("/") == 1:
            served["/" + relative.split("/", 1)[1]] = file  # the root alias of a top-level document
    return served


def test_every_relative_link_in_the_published_documents_resolves(export):
    """Two spec links answered 404 on the site (../../packages, ../../research) and the specifications linked
    ../DECISIONS.md, which is no longer published.  Every relative link of every published Markdown document,
    read at each path the site serves it at, names a published document; repository-only material is linked by
    its public repository URL (ops/sync-docs.sh usage)."""
    served = _published(export)
    broken = []
    for path, file in sorted(served.items()):
        if file.suffix != ".md":
            continue
        text = file.read_text(encoding="utf-8")
        text = re.sub(r"```.*?```", "", text, flags=re.S)  # code blocks hold examples, not links
        text = re.sub(r"`[^`\n]*`", "", text)  # and so do code spans (a regex such as [a-z](...))
        for target in re.findall(r"\]\(([^)\s]+)\)", text):
            if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                continue  # absolute URLs and same-page anchors
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target.split("#", 1)[0]))
            if resolved.endswith("/") or resolved + "/index.txt" in served or target.endswith("/"):
                resolved = resolved.rstrip("/") + "/index.txt"
            if resolved not in served:
                broken.append(f"{path} -> {target}")
    assert broken == [], broken


def test_no_published_text_links_into_docs_internal(client, export):
    """The owner stats route's description named docs/internal/owner-stats-design.md, and /llms-full.txt and
    /openapi.json carried it to every visitor.  No served text names docs/internal."""
    for path in ("/llms.txt", "/llms-full.txt", "/openapi.json", "/skill.md", "/.well-known/agent-protocol.json"):
        assert "docs/internal" not in client.get(path).text, path
    for file in export.rglob("*.md"):
        text = file.read_text(encoding="utf-8")
        assert not re.search(r"\]\([^)]*internal/", text), file

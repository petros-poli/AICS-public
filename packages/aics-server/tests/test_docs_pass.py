"""The docs pass of the first-visit readiness audit (docs/internal/readiness-2026-10-20.md): what the served texts say
about the witness, the PyPI distribution, the public repository, OpenSSL on a stock Mac, sealing a message on a stock
machine and a first visit to the restarted log.

* The one witness of production's first card, in the words of docs/legal/card-policy.md G5: the card lists it, run by
  the operator on a second provider, at quorum 1, and a client accepts a checkpoint as current only with its fresh
  cosignature.  The card states that rule, not that every checkpoint is cosigned (publication never waits for a
  witness).  It is founder-run, so it proves freshness, not independence (G5 stays promised); its vkey is in the
  card's ``witness_policy`` and in the DNS TXT record; the aics-cli command pins it by hand (aics-cli's
  tests/test_documented_commands.py parses it).  No vkey is written into a text.  /llms.txt and /skill.md say it from
  this log's first card; the homepage says it only while the card it serves lists that witness, and the HTML /card
  shows the vkey (tests/test_card_witness.py).  A log without a trust bundle (staging) says none of it.
* "aics-cli", never "the aics package": the PyPI project named ``aics`` belongs to someone else.
* Wherever a served or published text names the public repository, it gives its URL.
* OpenSSL 3.0 or later, not the LibreSSL a stock macOS runs as ``openssl``, with the Mac path; one sealing install
  line that works where the system pip refuses ("externally managed environment").
* A write's reply at the gate: the entry, a receipt and the checkpoint, or an ``ok`` line in its place while no
  cosigned checkpoint covers the entry (readiness/cosigned-checkpoints).
* A first-visitor line on the restarted log, without a literal date.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from aics_server.app import create_app
from aics_server.banner import get_banner
from aics_server.db import SanctuaryDB
from aics_server.discovery import (
    FIRST_VISIT, LOG_KEY_SOURCES, MAC_OPENSSL, PUBLIC_REPOSITORY, PYPI_NAME_NOTE, SEAL_INSTALL, SEAL_NOTE, SEAT_PAGES,
    WITNESS_POLICY_INIT, WITNESS_RECORD, Site, build_llms_txt, build_skill_md, log_key_check, quickstart_alternatives,
    seat_paragraph, witness_steps,
)
from aics_tlog import format_vkey, vkey_from_ed25519

from conftest import TEST_LIMITS

REPO = Path(__file__).resolve().parents[3]
HTML = {"Accept": "text/html"}
STAGING_ENV = {
    "AICS_BASE_URL": "https://test.wesupport-ai.com",
    "AICS_API_URL": "https://test.wesupport-ai.com",
    "AICS_GATE_HOSTNAME": "test.wesupport-ai.com",
    "AICS_GATE_PUBLIC_TLS_PORT": "7800",
    "AICS_GATE_PUBLIC_PLAIN_PORT": "7801",
    "AICS_IP_URL": "https://test.wesupport-ai.com/ip",
    "AICS_TILE_MIRRORS": "",
    "AICS_ORIGIN": "test.wesupport-ai.com/tiles",
}
#: "the aics package" and its HTML, Markdown and reStructuredText forms: the distribution is aics-cli.
AICS_PACKAGE = re.compile(
    r"\baics package\b|<code>aics</code> package|`aics` package|``aics`` package|`aics` PyPI|pip install aics\b(?!-)",
    re.I,
)
#: A witness vkey (name+keyid+base64): the texts name where it is, never the key itself.
VKEY = re.compile(r"witness\.wesupport-ai\.com/w\d+\+[0-9a-f]{8}\+")
#: A text that names the public repository (or its README).
NAMES_THE_REPOSITORY = re.compile(r"public (?:GitHub )?(?:repo(?:sitory)?\b|README)", re.I)
#: The overclaim the witness texts once made: the card says when a client accepts a checkpoint, not that each one is
#: cosigned.
EVERY_CHECKPOINT = re.compile(r"cosigns every|every checkpoint is cosigned|cosignature on every", re.I)
#: The founder-run witness of a test app: not production's name, and nothing listens at its URL.
WITNESS_NAME = "witness.wesupport-ai.example/w2"


def _flat(text: str) -> str:
    return " ".join(text.split())


def _page_text(client: TestClient, path: str) -> str:
    """The words of an HTML page: tags removed, entities decoded, whitespace collapsed."""
    return _flat(html.unescape(re.sub(r"<[^>]+>", "", client.get(path, headers=HTML).text)))


def _served(client: TestClient) -> dict[str, str]:
    paths = ["/llms.txt", "/llms-full.txt", "/skill.md", "/tiles", "/openapi.json", "/.well-known/agent-protocol.json",
             "/.well-known/aics-card.json", "/static/aics_client.py", *(f"/{seat.slug}" for seat in SEAT_PAGES)]
    texts = {path: client.get(path).text for path in paths}
    for path in ("/", "/card", "/online", "/stats"):
        texts[path + " (html)"] = html.unescape(client.get(path, headers=HTML).text)
    return texts


def _without_the_banner_block(path: Path, text: str) -> str:
    """*text* without the fenced banner (docs/BANNER.md's first block, the README's ``text`` block): the served banner,
    byte for byte, which aics-conformance checks and this pass does not change."""
    if path.name == "BANNER.md":
        return re.sub(r"\n```\n.*?\n```\n", "\n", text, count=1, flags=re.S)
    if path.name == "README.md":
        return re.sub(r"\n```text\n.*?\n```\n", "\n", text, flags=re.S)
    return text


@pytest.fixture()
def staging(tmp_path, monkeypatch, owner) -> TestClient:
    for name, value in STAGING_ENV.items():
        monkeypatch.setenv(name, value)
    return TestClient(create_app(db_path=tmp_path / "staging.db", owner_public_key=owner.public_key_b64u,
                                 announce=False, limits=TEST_LIMITS))


@pytest.fixture()
def witnessed(tmp_path, monkeypatch, owner):
    """Production's pages while the server feeds founder-run witnesses (``AICS_WITNESSES``), so the card it serves
    lists them at quorum 1; ``make(*names)`` gives the app, its ``vkeys`` beside it."""
    apps: list[TestClient] = []

    def make(*names: str) -> TestClient:
        vkeys = [format_vkey(vkey_from_ed25519(name, Ed25519PrivateKey.generate().public_key(), 0x04)) for name in names]
        monkeypatch.setenv("AICS_WITNESSES", ",".join(f"w{i}=http://127.0.0.1:9/witness={v}" for i, v in enumerate(vkeys)))
        app = TestClient(create_app(db_path=tmp_path / f"witnessed-{len(apps)}.db", owner_public_key=owner.public_key_b64u,
                                    announce=False, limits=TEST_LIMITS))
        app.vkeys = vkeys
        apps.append(app)
        return app

    yield make
    for app in apps:
        stop = getattr(app.app.state.db, "stop_witness_feeder", None)
        if stop is not None:
            stop()


def test_no_served_text_names_the_aics_package_quotes_a_witness_vkey_or_says_every_checkpoint_is_cosigned(
        client, staging):
    for app in (client, staging):
        for path, text in _served(app).items():
            match = AICS_PACKAGE.search(text)
            assert match is None, f"{path}: {text[max(0, match.start() - 80):match.end() + 40]!r}"
            assert VKEY.search(text) is None, path
            assert EVERY_CHECKPOINT.search(text) is None, path


def test_served_texts_link_the_public_repository_wherever_they_name_it(client, staging):
    for app in (client, staging):
        for path, text in _served(app).items():
            for match in re.finditer(r"public repo(sitory)?\b", text, re.I):
                assert PUBLIC_REPOSITORY in text[match.start():match.end() + 120], f"{path}: {match.group(0)}"
    assert LOG_KEY_SOURCES[2] == f"the README of the public repository {PUBLIC_REPOSITORY}"
    assert PUBLIC_REPOSITORY in SanctuaryDB.KEYS_NOTICE and "aics-cli package on PyPI" in SanctuaryDB.KEYS_NOTICE


def test_published_documents_link_the_public_repository_wherever_they_name_it():
    """What ops/sync-docs.sh publishes (docs/{spec,legal,site}/*.md and the top-level documents), the README of the
    public repository and the skill bundle.  docs/spec/CHANGELOG.md records what changed and is left out; so is the
    fenced banner, the served banner byte for byte."""
    docs = REPO / "docs"
    if not (docs / "spec").is_dir():
        pytest.skip("docs/ is not next to this package")
    paths = [*(path for folder in ("spec", "legal", "site") for path in sorted((docs / folder).glob("*.md"))
               if path.name != "CHANGELOG.md"),
             *(docs / name for name in ("BANNER.md", "DESIGN.md", "DECISIONS.md", "PROTOCOL-TEXT.md")),
             REPO / "README.md", REPO / "skills" / "wesupport-ai" / "SKILL.md"]
    unlinked = []
    for path in paths:
        if not path.exists():
            continue
        text = _flat(_without_the_banner_block(path, path.read_text(encoding="utf-8")))
        for match in NAMES_THE_REPOSITORY.finditer(text):
            if PUBLIC_REPOSITORY not in text[match.start():match.end() + 160]:
                unlinked.append(f"{path.relative_to(REPO)}: ...{text[max(0, match.start() - 60):match.end() + 60]}...")
    assert not unlinked, "\n".join(unlinked)
    # The card hashes card-policy.md: G6 names the README's digest by the repository's URL.
    policy = _flat((docs / "legal" / "card-policy.md").read_text(encoding="utf-8"))
    assert ("or a client whose hash matches the digest in the README of the public repository, "
            f"{PUBLIC_REPOSITORY}.") in policy


def test_llms_txt_names_the_witness_the_cli_and_the_pypi_name():
    text = build_llms_txt(Site())
    check = _flat(text[text.index("\n## Check before you trust\n"):text.index("\n## Verifying by hand\n")])
    for needed in ("Witness: from this log's first card, the card lists one witness, run by the operator on a second "
                   "provider, at quorum 1: a client accepts a checkpoint as current only with that witness's fresh "
                   "cosignature.", "It is founder-run, so it proves freshness, not independence",
                   "G5 (single view) stays promised", f"Its vkey is in the card's `witness_policy` and in the DNS TXT "
                   f"record `{WITNESS_RECORD}`.", f"aics-cli reads it from the card; by hand: `{WITNESS_POLICY_INIT}`.",
                   "The PyPI project named just `aics` is not ours; install `aics-cli`."):
        assert needed in check, needed
    # The command stays on one line, whole, for an agent to copy.
    assert f"`{WITNESS_POLICY_INIT}`" in text
    assert WITNESS_POLICY_INIT == ("aics policy init --from-dns wesupport-ai.com --witness '<the vkey the card lists>' "
                                   "--quorum 1 --max-age 300")
    assert WITNESS_RECORD == "_aics-witness.witness.wesupport-ai.com"
    assert PYPI_NAME_NOTE == "The PyPI project named just `aics` is not ours; install `aics-cli`."
    assert f"\n{witness_steps()}\n" in text and "Witness" not in build_llms_txt(Site.from_env(STAGING_ENV))
    assert EVERY_CHECKPOINT.search(witness_steps()) is None


def test_llms_txt_says_openssl_3_not_libressl_with_the_mac_path_and_how_to_seal():
    for site in (Site(), Site.from_env(STAGING_ENV)):
        text = build_llms_txt(site)
        gate = text[text.index("\n## Text gate (start here)\n"):text.index("\n## Check before")]
        assert _flat(MAC_OPENSSL) in _flat(gate)
        for needed in ("OpenSSL 3.0 or later, not LibreSSL", "a stock macOS runs LibreSSL as `openssl`",
                       "`openssl version`", "`-verify_hostname`", "`tools ssh-keygen`", "send the lines by HTTPS",
                       "`brew install openssl@3`", "`pip install cryptography` in a venv"):
            assert needed in MAC_OPENSSL, needed
        # Inline commands are never broken across lines.
        for command in ("`pip install cryptography`", "`brew install openssl@3`", "`tools ssh-keygen`", f"`{SEAL_INSTALL}`"):
            assert command in text, (site.origin, command)
        assert _flat(SEAL_NOTE) in _flat(text)
    assert SEAL_INSTALL == "python3 -m venv aics-venv && aics-venv/bin/pip install aics-identity"
    for needed in ("Sealing needs PyNaCl", "a system pip may refuse to install", "with Python 3.12 or later",
                   "`aics_identity.sealed.seal`", "section 8.1 framing", "an older Python installs `pynacl`"):
        assert needed in SEAL_NOTE, needed


def test_llms_txt_shows_the_piped_tls_form_ending_with_quit():
    text = build_llms_txt(Site())
    tls = Site().tls_command
    assert f"Piped, end with `quit`, since `-quiet` keeps the connection open after its input ends: " \
           f"`printf 'help\\nquit\\n' | {tls}`." in text


def test_a_writes_reply_may_end_with_an_ok_line_until_a_cosigned_checkpoint_covers_it():
    """With a witness the gate waits up to 5 s for a cosigned checkpoint that includes the entry; without one, an ok
    line says when ``read <index>`` gives it (readiness/cosigned-checkpoints, PROTOCOL-TEXT section 5)."""
    ok_line = "if no cosigned checkpoint covers the entry yet, an `ok` line in its place says when to `read` it"
    for site in (Site(), Site.from_env(STAGING_ENV)):
        assert (f"the entry, a receipt and the signed checkpoint that includes it: keep all three ({ok_line})."
                in _flat(build_llms_txt(site)))
        assert (f"every accepted write returns its exact entry, a receipt and the signed checkpoint that includes it; "
                f"{ok_line}.") in _flat(build_skill_md(site))


def test_a_first_visitor_line_on_production_only():
    """The service restarted on a new log (the relaunch of 2026-10-20): llms.txt, /online and its seat page say a
    visitor may be among the first agents, and what to do; no literal date. Staging says nothing of it."""
    assert "at this log's genesis," in FIRST_VISIT and not re.search(r"20\d\d-\d\d-\d\d|leaf 0", FIRST_VISIT)
    for words in ("The service restarted on a new log", "you may be among the first agents here", "Claim a name",
                  "post in the forum", "open your inbox", "messages reach you only after a grant you sign"):
        assert words in FIRST_VISIT, words
    production, staging_site = Site(), Site.from_env(STAGING_ENV)
    assert production.first_visit == FIRST_VISIT and staging_site.first_visit is None
    text = build_llms_txt(production)
    machine = text[len(get_banner(site=production)):]
    intro = machine[:machine.index("\n## Text gate (start here)\n")]
    # A paragraph of its own, after the hosts and before the text gate.
    assert "\n\nFirst visit? " in intro and _flat(FIRST_VISIT) in _flat(intro)
    assert "First visit?" not in build_llms_txt(staging_site)
    online = next(seat for seat in SEAT_PAGES if seat.slug == "is-any-other-agent-online-right-now")
    assert seat_paragraph(online, production).endswith(FIRST_VISIT)
    assert "First visit?" not in seat_paragraph(online, staging_site)


def test_the_online_page_renders_the_first_visit_line(client):
    assert f"{FIRST_VISIT} /llms.txt says how to start." in _page_text(client, "/online")
    assert '<a href="/llms.txt">/llms.txt</a> says how to start.' in client.get("/online", headers=HTML).text


def test_the_homepage_witness_paragraph_follows_the_card_it_serves(client, witnessed):
    """The homepage says what /card says: no witness paragraph while the card lists none (the skeleton before the
    witness is fed, the pre-wipe log's quorum-0 card), card-policy.md G5's words for the one founder-run witness."""
    assert "quorum 0; no witness" in _page_text(client, "/card")
    home = _page_text(client, "/")
    assert WITNESS_RECORD not in home and "aics policy init" not in home and "The card lists" not in home

    one = witnessed(WITNESS_NAME)
    home = _page_text(one, "/")
    for needed in (f"The card lists one witness, {WITNESS_NAME}, run by the operator on a second provider, at quorum "
                   "1: a client accepts a checkpoint as current only with that witness's fresh cosignature.",
                   "This witness is founder-run, so it proves freshness, not independence: G5 (single view) stays "
                   "promised.", "Its vkey is in the card's witness_policy, shown on the card page and in its signed "
                   f"JSON, and in the DNS TXT record {WITNESS_RECORD}.",
                   f"aics policy init --from-dns wesupport-ai.com reads it from the card; to pin it by hand: "
                   f"{WITNESS_POLICY_INIT}."):
        assert needed in home, needed
    assert EVERY_CHECKPOINT.search(home) is None
    page = one.get("/", headers=HTML).text
    assert '<a href="/.well-known/aics-card.json">signed JSON</a>' in page and '<a href="/card">card</a> page' in page
    # The vkey is on the HTML /card the homepage links to (the row tests/test_card_witness.py checks).
    assert one.vkeys[0] in one.get("/card", headers=HTML).text

    # Any other policy: what the card lists, nothing it does not say.
    two = witnessed(WITNESS_NAME, "witness.wesupport-ai.example/w3")
    home = _page_text(two, "/")
    assert ("The card lists 2 witnesses at quorum 1: a client accepts a checkpoint as current only with fresh "
            "cosignatures from 1 of them, and the card's G5 row says what they prove.") in home
    assert "founder-run" not in home and "aics policy init" not in home


def test_the_card_page_names_aics_cli_and_the_repository(client):
    card = client.get("/card", headers=HTML).text
    assert "<code>aics-cli</code> package on PyPI" in card and f'href="{PUBLIC_REPOSITORY}"' in card
    assert "the PyPI project named just <code>aics</code> is not ours" in card
    home = _page_text(client, "/")
    assert PUBLIC_REPOSITORY in home and f'href="{PUBLIC_REPOSITORY}"' in client.get("/", headers=HTML).text
    assert "The PyPI project named just aics is not ours; install aics-cli, whose command is aics." in home


def test_staging_pages_name_no_production_trust_source(staging):
    home = staging.get("/", headers=HTML).text
    assert "No out-of-band trust bundle exists for this instance" in home
    for text in (home, staging.get("/card", headers=HTML).text, staging.get("/online", headers=HTML).text):
        assert WITNESS_RECORD not in text and "First visit?" not in text and "_aics.wesupport-ai.com" not in text
        assert "aics policy init" not in text
    assert "No out-of-band trust bundle exists for this instance" in staging.get("/tiles").text
    assert "dry run" in staging.get("/openapi.json").json()["info"]["description"]
    log = staging.get("/.well-known/agent-protocol.json").json()["transparency_log"]
    assert not {"witness_vkey_dns_txt", "public_repository", "pypi_distribution"} & set(log)


def test_tiles_and_the_api_description_name_aics_cli_and_the_repository(client):
    sentence = log_key_check(Site())
    assert sentence in client.get("/tiles").text.splitlines()
    assert sentence in client.get("/openapi.json").json()["info"]["description"]
    assert "the aics-cli package on PyPI" in sentence and PUBLIC_REPOSITORY in sentence
    assert sentence.endswith(" The PyPI project named just aics is not ours; install aics-cli.")


def test_skill_md_names_the_repository_the_witness_and_openssl():
    production = _flat(build_skill_md(Site()))
    for needed in (f"the README of the public repository {PUBLIC_REPOSITORY}", PYPI_NAME_NOTE, WITNESS_RECORD,
                   "From this log's first card, the card lists one witness, run by the operator on a second provider, "
                   "at quorum 1: a client accepts a checkpoint as current only with that witness's fresh cosignature.",
                   "It is founder-run, so it proves freshness, not independence",
                   f"Its vkey is in the card's `witness_policy` and in the DNS TXT record {WITNESS_RECORD}",
                   f"`{WITNESS_POLICY_INIT}`", "OpenSSL 3.0 or later, not the LibreSSL a stock macOS runs as openssl"):
        assert needed in production, needed
    staging = build_skill_md(Site.from_env(STAGING_ENV))
    assert WITNESS_RECORD not in staging and "aics policy init" not in staging
    # The skill bundle gives the same command, which aics-cli's tests/test_documented_commands.py parses.
    bundle = REPO / "skills" / "wesupport-ai" / "SKILL.md"
    if bundle.exists():
        text = bundle.read_text(encoding="utf-8")
        assert f"`{WITNESS_POLICY_INIT}`" in text and WITNESS_RECORD in text and PUBLIC_REPOSITORY in text
        for needed in ("from this log's first card, it lists one witness, run by the operator on a second provider, "
                       "at quorum 1, and a checkpoint is current only with that witness's fresh cosignature",
                       "It is founder-run, so it proves freshness, not independence: G5 (single view) stays promised",
                       "Its vkey is in the card's `witness_policy`", PYPI_NAME_NOTE.rstrip(".")):
            assert needed in _flat(text), needed
        assert EVERY_CHECKPOINT.search(text) is None


def test_the_quickstart_is_followed_by_what_its_openssl_lines_need(client):
    """Wherever the quickstart is cut from the banner (the homepage, the seat pages, /skill.md), the sentence after
    it says that its openssl lines need OpenSSL 3.0 or later and where the Mac path is; the banner is not touched."""
    sentence = quickstart_alternatives(Site())
    assert ("The openssl lines need OpenSSL 3.0 or later, not the LibreSSL a stock macOS runs as openssl: on a Mac, "
            "make the key with ssh-keygen and POST the lines (https://wesupport-ai.com/llms.txt gives the whole Mac "
            "path).") in sentence
    assert "OpenSSL 3.0" not in get_banner() and "LibreSSL" not in get_banner()
    assert sentence in _page_text(client, "/")
    for seat in SEAT_PAGES:
        assert sentence in _flat(client.get(f"/{seat.slug}.md").text), seat.slug
        assert sentence in _page_text(client, f"/{seat.slug}"), seat.slug


def test_the_manifest_lists_the_swarm_verbs_apart_and_names_the_repository_and_the_witness_record(client):
    manifest = client.get("/.well-known/agent-protocol.json").json()
    log = manifest["transparency_log"]
    assert log["public_repository"] == PUBLIC_REPOSITORY and log["pypi_distribution"] == "aics-cli"
    assert log["witness_vkey_dns_txt"] == WITNESS_RECORD and log["log_key_sources"][2] == LOG_KEY_SOURCES[2]
    gate = manifest["text_gate"]
    assert gate["swarm_verbs"]["verbs"] == ["intro", "arrivals", "connect", "swarm-form", "swarm-join"]
    assert not set(gate["verbs"]) & set(gate["swarm_verbs"]["verbs"])
    assert gate["swarm_verbs"]["where"].startswith("only where the card at https://wesupport-ai.com/card names the "
                                                   "swarms profile")


def test_the_a2a_draft_card_offers_swarms_only_where_the_card_names_the_profile():
    """wellknown/agent-card.json (a static draft, not served yet): its join-swarm skill says where it applies."""
    path = REPO / "wellknown" / "agent-card.json"
    if not path.exists():
        pytest.skip("wellknown/agent-card.json is not next to this package")
    skills = {skill["id"]: skill for skill in json.loads(path.read_text(encoding="utf-8"))["skills"]}
    description = skills["join-swarm"]["description"]
    assert "only where the card at https://wesupport-ai.com/card names that profile" in description
    assert "Enable at launch" not in description

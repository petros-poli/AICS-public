"""The staging override (deploy/docker-compose.staging.yml) shares nothing with production.

It adds one service, aics-staging, beside aics-server on the same VPS: its own volumes, its
own origin and base URL, AICS_PRODUCTION empty, its own gate ports, and none of production's
secrets (the seed only through the distinct AICS_STAGING_SEED_HEX, the owner key only through
AICS_STAGING_OWNER_PUBKEY). deploy/deploy-vps.sh must not depend on it. This test reads the
compose files as YAML, merges the override into the base file the way COMPOSE_FILE does for
a service the base does not define, and starts the app with the staging environment.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from test_caddy_pages import CADDYFILE, _absolute_paths, _file_for, _file_routes, _sites

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parents[3]
DEPLOY = REPO / "deploy"
STAGING_HOST = "test.wesupport-ai.com"


def _load(name: str) -> dict:
    path = DEPLOY / name
    if not path.exists():
        pytest.skip(f"deploy/{name} is not next to this package")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _env(service: dict) -> dict[str, str]:
    environment = service.get("environment", [])
    if isinstance(environment, dict):
        return {k: "" if v is None else str(v) for k, v in environment.items()}
    return dict(item.split("=", 1) if "=" in item else (item, "") for item in environment)


def _named_volumes(service: dict) -> set[str]:
    names = set()
    for volume in service.get("volumes", []):
        if isinstance(volume, str):
            source = volume.split(":", 1)[0]
            if not source.startswith((".", "/")):
                names.add(source)
        elif volume.get("type") == "volume":
            names.add(volume["source"])
    return names


def _binds(service: dict) -> dict[str, tuple[str, bool]]:
    return {
        v["target"]: (v["source"], bool(v.get("read_only")))
        for v in service.get("volumes", [])
        if isinstance(v, dict) and v.get("type") == "bind"
    }


def _host_ports(service: dict) -> set[str]:
    return {str(p).split(":", 1)[0] for p in service.get("ports", [])}


@pytest.fixture(scope="module")
def merged() -> dict:
    base, staging = _load("docker-compose.yml"), _load("docker-compose.staging.yml")
    # The override only adds: no service or volume of the base file is redefined by it.
    assert set(staging["services"]).isdisjoint(base["services"])
    assert set(staging.get("volumes", {})).isdisjoint(base.get("volumes", {}))
    return {
        "services": {**base["services"], **staging["services"]},
        "volumes": {**base.get("volumes", {}), **staging.get("volumes", {})},
        "base": base,
        "staging": staging,
    }


def test_the_override_adds_only_the_staging_service(merged):
    assert set(merged["staging"]["services"]) == {"aics-staging"}
    assert set(merged["staging"]["volumes"]) == {"aics_staging_data", "aics_staging_tiles"}


def test_staging_has_its_own_volumes(merged):
    staging, server = merged["services"]["aics-staging"], merged["services"]["aics-server"]
    production_volumes = set(merged["base"]["volumes"]) | {"gate_tls"}
    assert _named_volumes(staging) == {"aics_staging_data", "aics_staging_tiles"}
    assert _named_volumes(staging).isdisjoint(production_volumes)
    assert _named_volumes(staging).isdisjoint(_named_volumes(server))
    assert "aics_staging_data:/data" in staging["volumes"]
    assert "aics_staging_tiles:/data/tiles" in staging["volumes"]
    # Fixed volume names, so the runbook's wipe command can never match a production volume.
    for key, spec in merged["staging"]["volumes"].items():
        assert spec["name"] == key
    # Caddy mounts no staging volume: staging's tiles are served by the app on test.* only.
    assert _named_volumes(merged["services"]["caddy"]).isdisjoint(_named_volumes(staging))


def test_staging_is_not_production(merged):
    env = _env(merged["services"]["aics-staging"])
    assert env["AICS_PRODUCTION"] == ""
    assert env["AICS_ORIGIN"] == f"{STAGING_HOST}/tiles"
    assert env["AICS_BASE_URL"] == f"https://{STAGING_HOST}"
    assert env["AICS_API_URL"] == f"https://{STAGING_HOST}"
    assert env["AICS_ALLOWED_HOSTS"] == STAGING_HOST
    assert env["AICS_TILE_MIRRORS"] == ""
    assert env["AICS_DB_PATH"] == "/data/aics.db"
    assert env["AICS_TILES_DIR"] == "/data/tiles"
    assert env["AICS_WORKERS"] == "1"
    assert "AICS_DEV_GENESIS" not in env
    production = _env(merged["services"]["aics-server"])
    for name in ("AICS_ORIGIN", "AICS_BASE_URL", "AICS_ALLOWED_HOSTS"):
        assert env[name] != production.get(name), name


def test_staging_receives_no_production_secret(merged):
    staging = merged["services"]["aics-staging"]
    env = _env(staging)
    assert "env_file" not in staging
    # The seed only through the distinct staging variable, never production's.
    assert env["AICS_SERVER_SEED_HEX"] == "${AICS_STAGING_SEED_HEX:-}"
    assert env["AICS_OWNER_PUBKEY"] == "${AICS_STAGING_OWNER_PUBKEY:-}"
    referenced = set(re.findall(r"\$\{(\w+)", "\n".join(env.values())))
    assert referenced == {"AICS_STAGING_SEED_HEX", "AICS_STAGING_OWNER_PUBKEY"}
    text = (DEPLOY / "docker-compose.staging.yml").read_text(encoding="utf-8")
    for secret in ("${AICS_SERVER_SEED_HEX", "${AICS_OWNER_PUBKEY", "${CLOUDFLARE_API_TOKEN", "${AICS_INDEXNOW_KEY",
                   "${AICS_WALLET_"):
        assert secret not in text, secret
    # No gate TLS: neither the certificate variables nor the gate certificate volume.
    assert not {"AICS_GATE_TLS_CERT", "AICS_GATE_TLS_KEY"} & set(env)
    assert "depends_on" not in staging


def test_staging_gate_ports_do_not_collide_with_production(merged):
    staging = merged["services"]["aics-staging"]
    assert staging["ports"] == ["7800:7700", "7801:7701"]
    published = set()
    for name, service in merged["services"].items():
        if name != "aics-staging":
            published |= _host_ports(service)
    assert _host_ports(staging).isdisjoint(published)
    assert staging["container_name"] != merged["services"]["aics-server"]["container_name"]


def test_staging_runs_the_production_image_with_the_same_documents(merged):
    staging, server = merged["services"]["aics-staging"], merged["services"]["aics-server"]
    assert staging["build"] == server["build"]
    assert staging["restart"] == "unless-stopped"
    assert staging["healthcheck"]["test"] == server["healthcheck"]["test"]
    assert staging["labels"]["wesupport-ai.disposable"] == "true"
    binds, production_binds = _binds(staging), _binds(server)
    legal = {"/etc/aics/charter.md", "/etc/aics/terms.md", "/etc/aics/retention.md", "/etc/aics/secret-patterns.json"}
    assert set(binds) == legal
    for target in legal:
        assert binds[target] == production_binds[target]
        assert binds[target][1] is True, target
    env, production = _env(staging), _env(server)
    for name in ("AICS_CHARTER_FILE", "AICS_TERMS_FILE", "AICS_PRIVACY_FILE", "AICS_SECRET_PATTERNS_FILE"):
        assert env[name] == production[name], name
    # The staging share of the VPS is smaller than production's.
    limits, production_limits = staging["deploy"]["resources"]["limits"], server["deploy"]["resources"]["limits"]
    assert float(limits["cpus"]) < float(production_limits["cpus"])


def test_the_other_overrides_leave_staging_alone():
    for name in ("docker-compose.pilot.yml", "gate-tls.yml"):
        assert "aics-staging" not in _load(name)["services"], name


def test_deploy_script_targets_the_production_container_only():
    script = (DEPLOY / "deploy-vps.sh").read_text(encoding="utf-8")
    assert "aics-staging" not in script
    targets = set(re.findall(r"docker compose (?:exec -T|logs --tail \d+) (\S+)", script))
    targets |= set(re.findall(r"docker compose run [^\n]*?--entrypoint \S+ (\S+)", script))
    assert targets == {"aics-server"}


def test_env_example_documents_the_staging_switch():
    example = (DEPLOY / ".env.example").read_text(encoding="utf-8")
    assert "COMPOSE_FILE=docker-compose.yml:docker-compose.staging.yml" in example
    # Documented commented out: an uncommented COMPOSE_FILE or staging key in the example would
    # switch staging on for whoever copies it.
    assert not re.search(r"^(COMPOSE_FILE|AICS_STAGING_\w+)=", example, re.M)
    assert "#   AICS_STAGING_SEED_HEX=" in example and "#   AICS_STAGING_OWNER_PUBKEY=" in example


def _staging_client(merged, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from aics_server.app import create_app

    env = _env(merged["services"]["aics-staging"])
    mounts = {target: REPO / "docs" / "legal" / Path(target).name for target in _binds(merged["services"]["aics-staging"])}
    env.update(
        AICS_DB_PATH=str(tmp_path / "aics.db"),
        AICS_TILES_DIR=str(tmp_path / "tiles"),
        AICS_PUBKEYS_OUT=str(tmp_path / "pubkeys.txt"),
        AICS_SERVER_SEED_HEX="",
        AICS_OWNER_PUBKEY="",
    )
    for name in ("AICS_CHARTER_FILE", "AICS_TERMS_FILE", "AICS_PRIVACY_FILE", "AICS_SECRET_PATTERNS_FILE"):
        env[name] = str(mounts[env[name]])
    monkeypatch.delenv("AICS_DEV_GENESIS", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return TestClient(create_app(announce=False))


def test_the_app_starts_a_disposable_log_with_the_staging_environment(merged, tmp_path, monkeypatch):
    """The staging environment, paths aside, creates a log on test.* without any owner key."""
    client = _staging_client(merged, tmp_path, monkeypatch)
    assert client.get("/healthz").status_code == 200
    assert client.get("/v2/tlog/checkpoint").json()["origin"] == f"{STAGING_HOST}/tiles"
    assert client.get("/tiles/checkpoint").text.splitlines()[0] == f"{STAGING_HOST}/tiles"
    assert f"https://{STAGING_HOST}" in client.get("/llms.txt").text


#: Addresses of production on this single-IP VPS: no staging text may send an agent there.
_PRODUCTION_ADDRESS = re.compile(r"(?:api|gate)\.wesupport-ai\.com|(?<![\d.])77(?:00|01)(?![\d])")


def test_staging_advertises_its_own_gate_ports(merged):
    env = _env(merged["services"]["aics-staging"])
    published = {p.split(":", 1)[0] for p in merged["services"]["aics-staging"]["ports"]}
    assert env["AICS_GATE_HOSTNAME"] == STAGING_HOST
    assert {env["AICS_GATE_PUBLIC_TLS_PORT"], env["AICS_GATE_PUBLIC_PLAIN_PORT"]} == published == {"7800", "7801"}


def test_no_staging_text_points_at_production(merged, tmp_path, monkeypatch):
    """Banner, llms.txt, skill.md, home JSON, seat pages and a gate session on staging name only
    test.wesupport-ai.com, its /t and its own ports 7800/7801 (on this VPS 7700/7701 are production's)."""
    from aics_server.discovery import SEAT_PAGES

    client = _staging_client(merged, tmp_path, monkeypatch)
    texts = {
        "/llms.txt": client.get("/llms.txt").text,
        "/llms-full.txt": client.get("/llms-full.txt").text,
        "/skill.md": client.get("/skill.md").text,
        "/?format=json": client.get("/?format=json").text,
        "/t?l=help": client.get("/t?l=help").text,
        "POST /t": client.post("/t", content=b"help\n").text,
    }
    for seat in SEAT_PAGES:
        texts[seat.slug] = client.get(f"/{seat.slug}.md").text
    for where, text in texts.items():
        found = _PRODUCTION_ADDRESS.findall(text)
        assert not found, (where, found)
    banner = client.get("/?format=json").json()["banner"]
    assert f"-connect {STAGING_HOST}:7800" in banner and f"https://{STAGING_HOST}/t" in banner
    assert f"{STAGING_HOST}:7801" in texts["/llms.txt"]
    # The plaintext gate refuses a secret without naming production's port (staging has no TLS listener: HTTPS).
    session = client.post("/t", content=b"help\n").text.splitlines()[0].split()[1]
    reply = client.post("/t", content=f"{session}\nfallback\n".encode()).text
    assert "err tls_required use HTTPS" in reply.splitlines()


def test_only_the_gate_certificate_gives_the_texts_a_tls_gate(merged, tmp_path, monkeypatch):
    """deploy/gate-tls.yml gives production's aics-server the gate certificate, so its site is the default one and
    its texts offer the TLS gate on 7700; staging gets none (its published 7800 is dark), so its /llms.txt sends
    secrets to HTTPS POST /t alone and names no 7800 in its gate section (review of the relaunch texts, 2026-10-20)."""
    from aics_server.discovery import DEFAULT_SITE, Site

    production = {**_env(merged["services"]["aics-server"]), **_env(_load("gate-tls.yml")["services"]["aics-server"])}
    assert Site.from_env(production) == DEFAULT_SITE and DEFAULT_SITE.gate_tls
    assert not Site.from_env(_env(merged["services"]["aics-staging"])).gate_tls
    text = _staging_client(merged, tmp_path, monkeypatch).get("/llms.txt").text
    gate = text[text.index("\n## Text gate (start here)\n"):text.index("\n## Check before you trust\n")]
    assert f"- This instance has no TLS TCP gate: use HTTPS `POST https://{STAGING_HOST}/t` for anything secret." in gate
    assert "7800" not in gate and "s_client" not in gate and f"Plain TCP `{STAGING_HOST}:7801`" in gate


def test_the_staging_skeleton_card_names_one_dns_only_host(merged, tmp_path, monkeypatch):
    """Staging serves its skeleton card (it logs no reviewed card), whose N2 said that Cloudflare terminated TLS for
    test.wesupport-ai.com and listed www.test.wesupport-ai.com (agent trial sonnet-1, 2026-10-19): its one host is
    DNS-only and carries pages, the API, the plaintext-only TCP gate and the connectivity check."""
    import json

    card = _staging_client(merged, tmp_path, monkeypatch).get("/.well-known/aics-card.json").json()
    assert card["proxy"] == [{"host": STAGING_HOST, "mode": "dns-only", "tls_termination":
                              "origin Caddy, Let's Encrypt certificate; TCP gate: no TLS listener; port 7801 is "
                              "plaintext TCP"}]
    text = json.dumps(card)
    assert "Cloudflare terminates TLS" not in text and f"www.{STAGING_HOST}" not in text and "pass through" not in text
    n2 = " ".join(next(a for a in card["assurances"] if a["id"] == "N2")["assumptions"])
    assert f"No hostname of this instance passes through Cloudflare; {STAGING_HOST} is DNS-only." in n2
    g10 = " ".join(next(a for a in card["assurances"] if a["id"] == "G10")["assumptions"])
    assert f"No proxy carries https://{STAGING_HOST}/.well-known/aics-card.json" in g10


def test_every_page_link_staging_emits_on_its_own_host_resolves_there(merged, tmp_path, monkeypatch):
    """The first agent trial against staging followed /llms.txt to /docs/PROTOCOL-TEXT.md and got a
    404: the instance links the published documents on its own host, and the staging block of
    deploy/Caddyfile proxied them to the app, which does not serve them.  Every page link staging
    emits on test.wesupport-ai.com is either a published document that block serves from the
    export (here a fresh ops/sync-docs.sh export, as deploy/docs-public is made) or answered by the app."""
    import subprocess

    from aics_server.discovery import SEAT_PAGES

    client = _staging_client(merged, tmp_path, monkeypatch)
    texts = [client.get(path).text for path in (
        "/llms.txt", "/llms-full.txt", "/skill.md", "/robots.txt", "/sitemap.txt", "/notice", "/tiles", "/card",
        "/manifest.json", "/.well-known/agent-protocol.json", "/.well-known/aics-card.json", "/?format=json")]
    texts += [client.get(f"/{seat.slug}.md").text for seat in SEAT_PAGES]
    linked = set().union(*(_absolute_paths(text, STAGING_HOST) for text in texts))
    # Pages only: the API (the /v2 prefix and its resources, often templates such as {kid}) answers
    # 404 for a missing resource by design, and a backslash is JSON-escaped text, not a path.
    linked = {path for path in linked if not re.match(r"/v2(/|$)", path) and not re.search(r"[{}<>*\\]", path)}
    for page in ("/terms", "/contact"):  # the app redirects these to published documents
        linked.add(urlsplit(client.get(page, follow_redirects=False).headers["location"]).path)
    assert {"/docs/PROTOCOL-TEXT.md", "/spec/AICS-1.md", "/legal/terms.md"} <= linked
    export = tmp_path / "docs-public"
    subprocess.run(["bash", str(REPO / "ops" / "sync-docs.sh"), str(export)], check=True, capture_output=True, text=True)
    routes = _file_routes(_sites(CADDYFILE.read_text(encoding="utf-8"))[STAGING_HOST])
    unresolved = []
    for path in sorted(linked):
        file = _file_for(routes, path)
        if file is None:
            served = client.get(path).status_code != 404
        else:
            target = export / Path(file).relative_to("/srv/docs")
            served = target.is_file() or (target / "index.txt").is_file()
        if not served:
            unresolved.append(path)
    assert unresolved == [], f"linked on {STAGING_HOST} but not served there: {unresolved}"


# ----------------------------------------------------------------------
# deploy/staging.sh: staging alone, and never with production's keys
# ----------------------------------------------------------------------

def _run_staging_script(tmp_path, action, config):
    """Run deploy/staging.sh with a fake docker that serves ``config`` and records every other call."""
    import json
    import os
    import shutil
    import subprocess

    if shutil.which("python3") is None:
        pytest.skip("python3 not on PATH")
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    shutil.copy(DEPLOY / "staging.sh", deploy / "staging.sh")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (tmp_path / "config.json").write_text(json.dumps(config))
    calls = tmp_path / "calls.txt"
    (bindir / "docker").write_text(
        "#!/bin/sh\n"
        f'if [ "$2" = config ]; then cat "{tmp_path / "config.json"}"; exit 0; fi\n'
        f'echo "$*" >> "{calls}"\n'
    )
    (bindir / "docker").chmod(0o755)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    result = subprocess.run(["bash", str(deploy / "staging.sh"), action], capture_output=True, text=True, env=env)
    return result, (calls.read_text().splitlines() if calls.exists() else [])


def _config(staging_env, production_env=None):
    return {"services": {
        "aics-server": {"environment": production_env or {"AICS_SERVER_SEED_HEX": "AB" * 32,
                                                          "AICS_OWNER_PUBKEY": "ed25519:prodowner"}},
        "aics-staging": {"environment": {"AICS_ORIGIN": "test.wesupport-ai.com/tiles", "AICS_PRODUCTION": "",
                                         **staging_env}},
        "caddy": {},
    }}


def test_staging_script_starts_only_staging(tmp_path):
    result, calls = _run_staging_script(tmp_path, "up", _config({"AICS_SERVER_SEED_HEX": "cd" * 32}))
    assert result.returncode == 0, result.stderr
    assert calls == [
        "compose build aics-staging",
        "compose up -d --no-deps aics-staging",
        "compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile",
    ]


@pytest.mark.parametrize("staging_env", [
    {"AICS_SERVER_SEED_HEX": "ab" * 32},  # production's seed (case differs)
    {"AICS_OWNER_PUBKEY": "ed25519:prodowner"},
    {"AICS_PRODUCTION": "1"},
    {"AICS_ORIGIN": "api.wesupport-ai.com/tiles"},
])
def test_staging_script_refuses_production_keys_without_printing_them(tmp_path, staging_env):
    result, calls = _run_staging_script(tmp_path, "up", _config(staging_env))
    assert result.returncode != 0 and calls == []
    assert "Refusing" in result.stderr
    assert "ab" * 32 not in result.stderr.lower() and "prodowner" not in result.stderr


def test_staging_script_refuses_when_staging_is_not_configured(tmp_path):
    config = _config({})
    del config["services"]["aics-staging"]
    result, calls = _run_staging_script(tmp_path, "up", config)
    assert result.returncode != 0 and calls == [] and "COMPOSE_FILE" in result.stderr


# ----------------------------------------------------------------------
# readiness audit of 2026-10-20: staging's TLS gate on 7800 and a card that names staging's own gate
# ----------------------------------------------------------------------

#: Where Caddy keeps test.wesupport-ai.com's certificate: the Let's Encrypt directory the test.* block pins.
STAGING_CERT_DIR = "/caddy-data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/test.wesupport-ai.com"


def _merge_service(base: dict, override: dict) -> dict:
    """One service of a Compose override merged as COMPOSE_FILE merges it: environment by name, volumes by target,
    depends_on by service, other keys replaced."""
    out = dict(base)
    for key, value in override.items():
        if key == "environment":
            out[key] = [f"{k}={v}" for k, v in {**_env(base), **_env(override)}.items()]
        elif key == "volumes":
            def target(volume):
                return volume.split(":")[1] if isinstance(volume, str) else volume["target"]
            kept = [v for v in base.get("volumes", []) if target(v) not in {target(o) for o in value}]
            out[key] = kept + list(value)
        elif key == "depends_on":
            out[key] = {**base.get("depends_on", {}), **value}
        else:
            out[key] = value
    return out


@pytest.fixture(scope="module")
def tls_override() -> dict:
    return _load("gate-tls-staging.yml")


@pytest.fixture(scope="module")
def merged_tls(merged, tls_override) -> dict:
    services = dict(merged["services"])
    for name, service in tls_override["services"].items():
        services[name] = _merge_service(services.get(name, {}), service)
    return {"services": services, "volumes": {**merged["volumes"], **tls_override["volumes"]}}


def test_the_tls_override_adds_only_staging_s_certificate_copy(merged, tls_override):
    """deploy/gate-tls-staging.yml follows deploy/gate-tls.yml: a one-shot copy of one certificate into a volume
    of the instance's own, never Caddy's store mounted into the app; it never names a production service or
    volume."""
    assert set(tls_override["services"]) == {"staging-gate-cert", "aics-staging"}
    assert set(tls_override["services"]).isdisjoint(merged["base"]["services"])
    assert set(tls_override["volumes"]) == {"aics_staging_gate_tls"}
    spec = tls_override["volumes"]["aics_staging_gate_tls"]
    assert spec["name"] == "aics_staging_gate_tls" and spec["labels"]["wesupport-ai.disposable"] == "true"
    text = (DEPLOY / "gate-tls-staging.yml").read_text(encoding="utf-8")
    code = re.sub(r"#.*", "", text)
    assert "aics-server" not in code and not re.search(r"(?<!\w)gate_tls\b", code)  # production's volume
    copy = tls_override["services"]["staging-gate-cert"]
    production_copy = _load("gate-tls.yml")["services"]["gate-cert"]
    for key in ("image", "pull_policy", "network_mode", "restart", "user"):
        assert copy[key] == production_copy[key], key
    assert copy["volumes"] == ["caddy_data:/caddy-data:ro", "aics_staging_gate_tls:/gate-tls"]
    script = copy["entrypoint"][2]
    assert f"src={STAGING_CERT_DIR}" in script and "gate.wesupport-ai.com" not in script
    assert "chown 10001:10001" in script and "chmod 0400 /gate-tls/test.wesupport-ai.com.key.new" in script
    assert "useradd --system --uid 10001" in (DEPLOY / "Dockerfile").read_text(encoding="utf-8")


def test_staging_s_tls_gate_reads_the_copy_and_never_blocks_a_production_deploy(merged_tls):
    staging = merged_tls["services"]["aics-staging"]
    env = _env(staging)
    assert env["AICS_GATE_TLS_CERT"] == "/etc/aics/gate-tls/test.wesupport-ai.com.crt"
    assert env["AICS_GATE_TLS_KEY"] == "/etc/aics/gate-tls/test.wesupport-ai.com.key"
    assert "aics_staging_gate_tls:/etc/aics/gate-tls:ro" in staging["volumes"]
    # Everything the staging override set is still there (the merge adds; nothing of production comes in).
    assert env["AICS_ORIGIN"] == f"{STAGING_HOST}/tiles" and env["AICS_PRODUCTION"] == ""
    assert {"AICS_STAGING_SEED_HEX", "AICS_STAGING_OWNER_PUBKEY"} == set(
        re.findall(r"\$\{(\w+)", "\n".join(env.values())))
    assert staging["ports"] == ["7800:7700", "7801:7701"]
    # deploy-vps.sh's `docker compose up -d` (under set -eu) starts every service: staging does not wait on its
    # certificate copy, so a missing test.* certificate cannot fail a production deploy whatever the Compose version;
    # deploy/staging.sh up runs the copy first (test_staging_script_copies_the_certificate_before_starting_staging).
    assert "depends_on" not in staging
    assert _load("gate-tls-staging.yml")["services"]["aics-staging"].keys() == {"environment", "volumes"}
    assert _named_volumes(staging).isdisjoint(set(merged_tls["volumes"]) - {
        "aics_staging_data", "aics_staging_tiles", "aics_staging_gate_tls"})
    assert "depends_on" not in merged_tls["services"]["aics-server"] or \
        "staging-gate-cert" not in merged_tls["services"]["aics-server"]["depends_on"]


def test_the_certificate_path_is_the_one_the_caddyfile_pins(tls_override):
    """The copy reads the Let's Encrypt directory; the test.* block pins that one issuer (no ZeroSSL fallback)."""
    body = _sites(CADDYFILE.read_text(encoding="utf-8"))[STAGING_HOST]
    tls = re.search(r"^\s*tls\s*\{([^}]*)\}", body, re.M)
    assert tls is not None and tls.group(1).split() == ["issuer", "acme"]
    assert "acme-v02.api.letsencrypt.org-directory" in tls_override["services"]["staging-gate-cert"]["entrypoint"][2]


def test_the_copy_script_copies_one_certificate_for_the_app_user(tmp_path, tls_override):
    """The entrypoint, run as written (paths moved into tmp_path, chown recorded): the certificate and key of
    test.wesupport-ai.com end up beside each other, the key at 0400, and a missing certificate fails loudly."""
    import os
    import shutil
    import subprocess

    if shutil.which("sh") is None:
        pytest.skip("sh is not installed")
    script = tls_override["services"]["staging-gate-cert"]["entrypoint"][2].replace("$$", "$")
    store, out, bindir = tmp_path / "store", tmp_path / "gate-tls", tmp_path / "bin"
    for directory in (out, bindir):
        directory.mkdir()
    script = script.replace("/caddy-data", str(store)).replace("/gate-tls", str(out))
    (bindir / "chown").write_text(f'#!/bin/sh\necho "$@" >> "{tmp_path / "chown.txt"}"\n')
    (bindir / "chown").chmod(0o755)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
    missing = subprocess.run(["sh", "-euc", script], capture_output=True, text=True, env=env, timeout=60)
    assert missing.returncode == 1 and "has not issued" in missing.stderr
    source = store / STAGING_CERT_DIR.removeprefix("/caddy-data/")
    source.mkdir(parents=True)
    (source / "test.wesupport-ai.com.crt").write_text("CERT\n")
    (source / "test.wesupport-ai.com.key").write_text("KEY\n")
    (source / "other.key").write_text("not copied\n")
    done = subprocess.run(["sh", "-euc", script], capture_output=True, text=True, env=env, timeout=60)
    assert done.returncode == 0, done.stderr
    assert sorted(p.name for p in out.iterdir()) == ["test.wesupport-ai.com.crt", "test.wesupport-ai.com.key"]
    assert (out / "test.wesupport-ai.com.key").read_text() == "KEY\n"
    assert oct((out / "test.wesupport-ai.com.key").stat().st_mode & 0o777) == "0o400"
    assert oct((out / "test.wesupport-ai.com.crt").stat().st_mode & 0o777) == "0o444"
    assert (tmp_path / "chown.txt").read_text().split()[0] == "10001:10001"


def test_staging_script_copies_the_certificate_before_starting_staging(tmp_path):
    config = _config({"AICS_SERVER_SEED_HEX": "cd" * 32})
    config["services"]["staging-gate-cert"] = {}
    result, calls = _run_staging_script(tmp_path, "up", config)
    assert result.returncode == 0, result.stderr
    assert calls == [
        "compose build aics-staging",
        "compose run --rm staging-gate-cert",
        "compose up -d --no-deps aics-staging",
        "compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile",
    ]
    assert "-connect test.wesupport-ai.com:7800" in result.stdout


def test_the_daily_staging_certificate_copy_never_touches_production():
    unit = (REPO / "ops" / "systemd" / "aics-staging-gate-cert.service").read_text(encoding="utf-8")
    timer = (REPO / "ops" / "systemd" / "aics-staging-gate-cert.timer").read_text(encoding="utf-8")
    assert "ConditionPathExists=/opt/wesupport-ai/deploy/gate-tls-staging.yml" in unit
    assert "grep -qx staging-gate-cert" in unit
    assert re.findall(r"^ExecStart=(.*)$", unit, re.M) == ["/usr/bin/docker compose run --rm staging-gate-cert"]
    assert "aics-server" not in unit and " gate-cert" not in unit
    assert "Unit=aics-staging-gate-cert.service" in timer
    production = (REPO / "ops" / "systemd" / "aics-gate-cert.timer").read_text(encoding="utf-8")
    assert re.search(r"OnCalendar=(.*)", timer).group(1) != re.search(r"OnCalendar=(.*)", production).group(1)


def test_the_staging_card_names_staging_s_own_gate_and_one_dns_only_host(merged_tls, tmp_path, monkeypatch):
    """The signed staging card said gate ports 7700/7701, production's gates on the same address (a tester who
    trusted it wrote to production), listed test.* as Cloudflare-proxied with a www alias that does not exist, and
    its N2 named an empty DNS-only host list.  With its TLS override (deploy/gate-tls-staging.yml) it now states
    7800/7801, one DNS-only host and no Cloudflare."""
    from aics_server.card import card_problems
    from aics_server.discovery import Site

    client = _staging_client(merged_tls, tmp_path, monkeypatch)
    card = client.get("/.well-known/aics-card.json").json()
    assert card["gate"] == {"tls_host": STAGING_HOST, "tls_port": 7800, "plaintext_port": 7801,
                            "https_url": f"https://{STAGING_HOST}/t"}
    assert [(p["host"], p["mode"]) for p in card["proxy"]] == [(STAGING_HOST, "dns-only")]
    termination = card["proxy"][0]["tls_termination"]
    assert "cloudflare" not in termination.lower() and "port 7800" in termination and "7801 is plaintext" in termination
    rows = {a["id"]: a for a in card["assurances"]}
    n2 = " ".join(rows["N2"]["assumptions"])
    assert f"{STAGING_HOST} is DNS-only" in n2 and "passes through Cloudflare" in n2  # "no host ... passes through"
    assert "Cloudflare terminates" not in n2 and ";  are" not in n2 and f"www.{STAGING_HOST}" not in n2
    g10 = " ".join(rows["G10"]["assumptions"])
    assert STAGING_HOST in g10 and "DNS-only host" in g10 and "pass through Cloudflare" not in g10
    statements = [s for a in card["assurances"] for s in (a["claim"], *a["assumptions"])]
    statements += [p["tls_termination"] for p in card["proxy"]]
    assert not [s for s in statements if _PRODUCTION_ADDRESS.search(s)], "a staging card statement names production"
    # The server logs and follows a staging card only with staging's own ports.
    db, site = client.app.state.db, client.app.state.site
    parent = db.list_policies()["policies"][-1]["leaf_index"]
    assert not [p for p in card_problems(card, db, parent_index=parent, site=site) if p.startswith("gate ")]
    gate_problems = [p for p in card_problems(card, db, parent_index=parent, site=Site()) if p.startswith("gate ")]
    assert gate_problems == ["gate is exactly {tls_host, tls_port: 7700, plaintext_port: 7701, https_url}, the "
                             "ports this instance's gate is reached on (AICS-1 section 13.1)"]

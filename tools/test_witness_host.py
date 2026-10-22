"""ops/witness/: the founder-run witness host's compose project, Caddyfile and scripts, checked offline.

There is no Docker or Caddy on the development machine, so this is the dry run: the compose file is
parsed with PyYAML and interpolated the way `docker compose config` does with ops/witness/.env.example,
and the Caddyfile and scripts are checked for the properties the runbook (step 6) relies on.
"""

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "ops/witness"
COMPOSE = HERE / "compose.yml"
CADDYFILE = HERE / "Caddyfile"
SCRIPTS = [HERE / "bootstrap-witness-host.sh", HERE / "backup-witness.sh"]
PACKAGE_COMPOSE = ROOT / "packages/aics-witness/compose.witness.yml"


def env_example() -> dict[str, str]:
    env = {}
    for line in (HERE / ".env.example").read_text().splitlines():
        if line and not line.startswith("#"):
            k, _, v = line.partition("=")
            env[k] = v
    return env


def interpolate(text: str, env: dict[str, str]) -> str:
    """The subset of compose interpolation this file uses: ${VAR}, ${VAR:-default}, ${VAR:?message}."""
    def sub(m: re.Match) -> str:
        name, op, arg = m.group(1), m.group(2), m.group(3)
        value = env.get(name, "")
        if op == ":?" and not value:
            raise KeyError(f"{name}: {arg}")
        if op == ":-" and not value:
            return arg
        return value
    return re.sub(r"\$\{([A-Z_][A-Z0-9_]*)(?:(:\?|:-)([^}]*))?\}", sub, text)


def resolved(env: dict[str, str] | None = None) -> dict:
    return yaml.safe_load(interpolate(COMPOSE.read_text(), env_example() if env is None else env))


def mem_bytes(text: str) -> int:
    m = re.fullmatch(r"(\d+)([KMG])", text)
    assert m, text
    return int(m.group(1)) * {"K": 2**10, "M": 2**20, "G": 2**30}[m.group(2)]


def test_compose_resolves_with_the_example_env_and_refuses_without_a_domain():
    doc = resolved()
    assert doc["name"] == "aics-witness"
    assert set(doc["services"]) == {"aics-witness", "caddy"}
    assert doc["services"]["caddy"]["environment"]["WITNESS_DOMAIN"] == "witness.wesupport-ai.com"
    with pytest.raises(KeyError, match="WITNESS_DOMAIN"):
        resolved({})


def test_witness_service_builds_the_package_image_and_publishes_loopback_only():
    w = resolved()["services"]["aics-witness"]
    context = (HERE / w["build"]["context"]).resolve()
    assert context == ROOT / "packages"
    assert (context / w["build"]["dockerfile"]).is_file()
    assert (context / "aics-tlog/pyproject.toml").is_file()
    version = re.search(r'"([^"]+)"', (ROOT / "packages/aics-witness/src/aics_witness/_version.py").read_text())
    assert w["image"] == f"aics-witness:{version.group(1)}"
    assert w["ports"] == ["127.0.0.1:7380:7380"]
    assert w["volumes"] == ["witness_data:/data"]
    assert w["read_only"] is True and w["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in w["security_opt"]
    assert "WITNESS_SEED_HEX" not in (w.get("environment") or {})  # the key lives in the volume only


def test_same_identity_guard_as_the_package_compose_file():
    """Same project, volume and container name: the two files can never run one key twice."""
    pkg = yaml.safe_load(PACKAGE_COMPOSE.read_text())
    ours = resolved()
    assert ours["name"] == pkg["name"]
    assert ours["services"]["aics-witness"]["container_name"] == pkg["services"]["aics-witness"]["container_name"]
    assert "witness_data" in ours["volumes"] and "witness_data" in pkg["volumes"]


def test_memory_fits_a_1gb_box_and_agents_are_killed_first():
    services = resolved()["services"]
    total = 0
    for name, svc in services.items():
        limit = mem_bytes(svc["deploy"]["resources"]["limits"]["memory"])
        assert limit <= 128 * 2**20, name
        total += limit
        assert svc["oom_score_adj"] < 0, name
        assert svc["restart"] == "unless-stopped"
        assert svc["logging"]["options"]["max-file"] == "3"
    assert total <= 256 * 2**20


def test_caddy_is_pinned_and_mounts_config_and_page_read_only():
    caddy = resolved()["services"]["caddy"]
    base = re.search(r"^FROM (caddy:[^ ]+-alpine@sha256:[0-9a-f]{64})$",
                     (ROOT / "ops/Dockerfile.caddy-cloudflare").read_text(), re.M)
    assert caddy["image"] == base.group(1)
    assert sorted(caddy["ports"]) == ["443:443", "80:80"]
    assert "./Caddyfile:/etc/caddy/Caddyfile:ro" in caddy["volumes"]
    assert "./site:/srv/site:ro" in caddy["volumes"]


def test_caddyfile_publishes_only_the_witness_endpoints_and_logs_no_clients():
    text = CADDYFILE.read_text()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "{$WITNESS_DOMAIN} {" in code
    assert re.search(r"fields \{\s*request delete\s*\}", code)
    site = code[code.index("{$WITNESS_DOMAIN} {"):]
    assert not re.search(r"^\s*log\b", site, re.M)  # no access log
    assert "path /add-checkpoint" in site and "method POST" in site
    assert "^/(healthz|[0-9a-f]{64}/checkpoint)$" in site
    assert "path / /vkey.txt /witness.json" in site
    assert set(re.findall(r"reverse_proxy (\S+)", site)) == {"aics-witness:7380"}
    assert 'respond "not found" 404' in site
    # The body cap equals the witness's max_body_bytes default (256 KiB).
    assert "max_size 256KiB" in site
    assert re.search(r"DEFAULT_MAX_BODY_BYTES = 256 \* 1024",
                     (ROOT / "packages/aics-witness/src/aics_witness/config.py").read_text())
    assert "protocols h1 h2" in code


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_scripts_parse_and_pass_shellcheck(script):
    assert os.access(script, os.X_OK)
    subprocess.run(["bash", "-n", str(script)], check=True)
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", "-x", str(script)], check=True)


def test_bootstrap_refuses_staging_origins_before_touching_anything():
    for origin in ("test.wesupport-ai.com/tiles", "pilot.wesupport-ai.com/tiles"):
        r = subprocess.run(["bash", str(HERE / "bootstrap-witness-host.sh"), "--origin", origin,
                            "--log-vkey", "x"], capture_output=True, text=True)
        assert r.returncode == 1 and "never goes into a witness" in r.stderr
    r = subprocess.run(["bash", str(HERE / "bootstrap-witness-host.sh"), "--initial-size", "3"],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "go together" in r.stderr


def test_backup_never_reads_the_key():
    text = (HERE / "backup-witness.sh").read_text()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "/data/witness.key" not in code
    assert "witness_data:" not in code  # no volume mount around the running witness


def test_systemd_units_point_at_this_directory():
    service = (HERE / "systemd/aics-witness-backup.service").read_text()
    assert "ExecStart=/home/ubuntu/aics/ops/witness/backup-witness.sh" in service
    assert "Environment=AICS_WITNESS_DIR=/home/ubuntu/aics/ops/witness" in service
    assert "Unit=aics-witness-backup.service" in (HERE / "systemd/aics-witness-backup.timer").read_text()


def test_no_secret_material_and_host_files_ignored():
    for path in HERE.rglob("*"):
        if path.is_file():
            text = path.read_text()
            assert not re.search(r"\b[0-9a-f]{64}\b", text.replace(
                "d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f", "")), path
            assert "PRIVATE KEY" not in text, path
    ignored = (HERE / ".gitignore").read_text().splitlines()
    assert ".env" in ignored and "site/" in ignored


def test_runbook_step_6_matches_the_files():
    runbook = (ROOT / "ops/RUNBOOK-first-deploy.md").read_text()
    step = runbook[runbook.index("## Step 6"):runbook.index("## Step 7")]
    for needle in ("ops/witness/bootstrap-witness-host.sh", "ops/cloudflare-dns.sh --witness",
                   "witness.wesupport-ai.com", "--origin", "--log-vkey", "--initial-size",
                   "/healthz", "backup-witness.sh", "aics-witness-backup.timer"):
        assert needle in step, needle

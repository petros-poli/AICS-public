"""ops/cloudflare-dns.sh offline dry run: the decision-10 record split, and --staging adds test only."""

import json
from pathlib import Path
import subprocess

SCRIPT = Path(__file__).resolve().parents[1] / "ops/cloudflare-dns.sh"
IP = "192.0.2.1"  # documentation address


def dry_run(*args):
    result = subprocess.run(["bash", str(SCRIPT), *args], text=True, capture_output=True,
                            env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"})
    records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    return result, records


def test_default_plan_is_the_production_split():
    result, records = dry_run(IP)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("DRY RUN:")
    proxied = {r["name"]: r["proxied"] for r in records}
    assert proxied == {
        "wesupport-ai.com": True, "www.wesupport-ai.com": True, "tiles.wesupport-ai.com": True,
        "api.wesupport-ai.com": False, "gate.wesupport-ai.com": False, "ip.wesupport-ai.com": False,
    }
    assert "test.wesupport-ai.com" not in result.stdout


def test_staging_adds_one_dns_only_record_and_changes_nothing_else():
    base, base_records = dry_run(IP)
    result, records = dry_run("--staging", IP)
    assert result.returncode == 0, result.stderr
    added = [r for r in records if r not in base_records]
    assert added == [{"type": "A", "name": "test.wesupport-ai.com", "content": IP, "proxied": False, "ttl": 1}]
    assert [r for r in records if r not in added] == base_records
    # Flag order does not matter, and it combines with --bundle like any other flag.
    assert dry_run(IP, "--staging")[1] == records


def test_staging_with_bundle(tmp_path):
    bundle = tmp_path / "bundle.txt"
    bundle.write_text("aics1=AbC-_\n")
    result, records = dry_run("--staging", "--bundle", str(bundle), IP)
    assert result.returncode == 0, result.stderr
    names = [r["name"] for r in records]
    assert "test.wesupport-ai.com" in names and "_aics.wesupport-ai.com" in names


def test_dry_run_makes_no_api_call_and_needs_no_token():
    result, _ = dry_run("--staging", IP)
    assert "no API calls" in result.stdout
    assert "CLOUDFLARE_API_TOKEN" not in result.stderr


WITNESS_IP = "198.51.100.7"  # documentation address, another host


def test_witness_adds_one_dns_only_record_on_the_witness_host():
    _, base_records = dry_run(IP)
    result, records = dry_run("--witness", WITNESS_IP, IP)
    assert result.returncode == 0, result.stderr
    added = [r for r in records if r not in base_records]
    assert added == [{"type": "A", "name": "witness.wesupport-ai.com", "content": WITNESS_IP,
                      "proxied": False, "ttl": 1}]
    assert [r for r in records if r not in added] == base_records
    assert dry_run(IP, "--staging", "--witness", WITNESS_IP)[1] == dry_run("--witness", WITNESS_IP, "--staging", IP)[1]


def test_witness_refuses_the_vps_address_and_bad_input():
    same, _ = dry_run("--witness", IP, IP)
    assert same.returncode != 0 and "another host" in same.stderr
    bad, _ = dry_run("--witness", "999.1.1.1", IP)
    assert bad.returncode != 0 and "invalid witness IPv4" in bad.stderr
    missing, _ = dry_run(IP, "--witness")
    assert missing.returncode != 0 and "--witness requires" in missing.stderr


W2 = "witness.wesupport-ai.com/w2+1a2b3c4d+BAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="


def test_witness_txt_adds_the_witness_vkey_record_under_the_witness_host(tmp_path):
    vkey = tmp_path / "witness.vkey"
    vkey.write_text(W2 + "\n")
    _, base_records = dry_run(IP)
    result, records = dry_run("--witness-txt", str(vkey), IP)
    assert result.returncode == 0, result.stderr
    added = [r for r in records if r not in base_records]
    assert added == [{"type": "TXT", "name": "_aics-witness.witness.wesupport-ai.com",
                      "content": "aics-witness-vkey " + W2, "ttl": 1}]
    assert [r for r in records if r not in added] == base_records
    assert "_aics TXT: untouched" in result.stdout and "_aics-witness TXT" not in result.stdout


def test_witness_txt_refuses_a_vkey_outside_the_zone_or_more_than_one(tmp_path):
    vkey = tmp_path / "witness.vkey"
    for text in ("witness.example.org/w2+1a2b3c4d+AAAA", "not a vkey", W2 + "\n" + W2):
        vkey.write_text(text + "\n")
        result, _ = dry_run("--witness-txt", str(vkey), IP)
        assert result.returncode != 0 and "--witness-txt must hold one witness vkey" in result.stderr, text
    missing, _ = dry_run(IP, "--witness-txt")
    assert missing.returncode != 0 and "--witness-txt requires" in missing.stderr

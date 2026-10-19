"""The command line: validate_card.py card-content.json and the launch fill flow."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys

import rfc8785

import validate_card as vc
from helpers import CARD_DIR, CARD_PATH, PATTERN_DEFINITIONS, REPO, assurance, dump, fill_values, load_template


def run(*args: str) -> tuple[int, dict]:
    proc = subprocess.run([sys.executable, str(CARD_DIR / "validate_card.py"), *args],
                          capture_output=True, text=True, cwd=CARD_DIR, check=False)
    return proc.returncode, json.loads(proc.stdout)


def test_cli_passes_on_the_card():
    code, report = run("card-content.json")
    assert code == 0, report["errors"]
    assert report["ok"] and report["mode"] == "template" and not report["ready_to_sign"]
    assert report["profile"] == "AICS-1+SUP-1" and report["patterns"] is None
    assert "<FILL:LOG_VKEY>" in report["placeholders"]
    # G1 is promised and carries no evidence; G2 is the first proven row.
    assert report["placeholders"]["<FILL:SHA256:docs/spec/AICS-1.md>"][0] == "$.assurances[1].evidence[0].hash"
    payload = vc.unsigned_payload(load_template())
    assert report["payload"] == {"what": report["payload"]["what"], "bytes": len(payload),
                                 "sha256": hashlib.sha256(payload).hexdigest()}


def test_cli_final_fails_on_the_template():
    code, report = run("card-content.json", "--final")
    assert code == 1 and not report["ok"]
    assert any("not filled (--final)" in e for e in report["errors"])
    assert any("--final needs the pattern-definition document" in e for e in report["errors"])


def test_cli_fails_on_a_violation(tmp_path):
    card = load_template()
    assurance(card, "G5")["status"] = "proven"
    code, report = run(str(dump(card, tmp_path / "bad.json")))
    assert code == 1
    assert any("G5 cannot be proven with witness quorum 0" in e for e in report["errors"])


def test_cli_input_errors_exit_2(tmp_path):
    (tmp_path / "dup.json").write_text('{"spec": "AICS-1", "spec": "AICS-1"}')
    code, report = run(str(tmp_path / "dup.json"))
    assert code == 2 and "duplicate JSON member" in report["input_error"]
    code, report = run(str(tmp_path / "missing.json"))
    assert code == 2 and "input_error" in report
    code, report = run("card-content.json", "--patterns", str(tmp_path / "missing-patterns.json"))
    assert code == 2 and "input_error" in report


def test_cli_fill_write_and_jcs_out(tmp_path):
    sets = [f"--set={k}={v}" for k, v in fill_values().items()]
    patterns = dump(PATTERN_DEFINITIONS, tmp_path / "secret-patterns.json")
    out, jcs_out = tmp_path / "filled" / "card-unsigned.json", tmp_path / "filled" / "card-unsigned.jcs"
    code, report = run("card-content.json", "--fill-hashes", str(REPO), "--patterns", str(patterns), *sets,
                       "--final", "--write", str(out), "--jcs-out", str(jcs_out))
    assert code == 0, report["errors"]
    assert report["ready_to_sign"] and report["placeholders"] == {} and report["patterns"] == str(patterns)
    written = vc.load_json(out.read_bytes())
    assert jcs_out.read_bytes() == rfc8785.dumps(written)
    assert report["payload"]["sha256"] == hashlib.sha256(jcs_out.read_bytes()).hexdigest()
    # The filled body validates on its own against the same definitions, and the template on disk is untouched.
    assert run(str(out), "--final", "--patterns", str(patterns))[0] == 0
    assert run(str(out), "--final")[0] == 1
    assert vc.load_json(CARD_PATH.read_bytes())["log_vkey"] == "<FILL:LOG_VKEY>"


def test_cli_jcs_out_needs_checked_pattern_hashes(tmp_path):
    sets = [f"--set={k}={v}" for k, v in fill_values().items()]
    sets += [f"--set=SECRET_PATTERN_HASH:{p['id']}={'ab' * 32}" for p in PATTERN_DEFINITIONS]
    code, report = run("card-content.json", "--fill-hashes", str(REPO), *sets, "--jcs-out", str(tmp_path / "x.jcs"))
    assert code == 1 and not report["ready_to_sign"]
    assert any("pattern hashes were not checked" in e for e in report["errors"])
    assert not (tmp_path / "x.jcs").exists()


def test_cli_jcs_out_needs_a_ready_card(tmp_path):
    code, report = run("card-content.json", "--jcs-out", str(tmp_path / "x.jcs"))
    assert code == 1 and any("nothing written" in e for e in report["errors"])
    assert not (tmp_path / "x.jcs").exists()


def test_cli_refuses_to_overwrite_the_template():
    code, report = run("card-content.json", "--set", "ISSUED_AT=1", "--write", "card-content.json")
    assert code == 2 and "refusing to overwrite" in report["input_error"]


def test_cli_rejects_unknown_set_names():
    code, report = run("card-content.json", "--set", "LOG_KEY=x")
    assert code == 2 and "names no placeholder" in report["input_error"]
    for gone in ("DM_SECONDS=7776000", "WITNESS_NAME=w"):  # fixed by the charter / no witness at launch
        code, report = run("card-content.json", "--set", gone)
        assert code == 2 and "names no placeholder" in report["input_error"]

"""The command line: validate_card.py card-content.json and the launch fill flow."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys

import pytest
import rfc8785

import validate_card as vc
from helpers import (
    CARD_DIR,
    CARD_PATH,
    CONFORMANCE_QUORUMS,
    CONFORMANCE_REPORTS,
    PATTERN_DEFINITIONS,
    PATTERN_DOCUMENT,
    REPO,
    assurance,
    conformance_report,
    dump,
    fill_values,
    load_template,
    run_policy,
)


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
    # Since genesis v2 G1 is proven, so the first evidence slot is its own; each conformance row names both reports.
    assert report["placeholders"]["<FILL:SHA256:docs/spec/AICS-1.md>"][0] == "$.assurances[0].evidence[0].hash"
    card = load_template()
    rows = [i for i, a in enumerate(card["assurances"]) if a["id"] in vc.CONFORMANCE_ROWS]
    for rel in CONFORMANCE_REPORTS:
        slots = [re.fullmatch(r"\$\.assurances\[(\d+)\]\.evidence\[(\d+)\]\.hash", path)
                 for path in report["placeholders"][f"<FILL:SHA256:{rel}>"]]
        assert [int(m.group(1)) for m in slots] == rows
        assert all(card["assurances"][int(m.group(1))]["evidence"][int(m.group(2))]["hash"] == f"<FILL:SHA256:{rel}>"
                   for m in slots)
    assert report["conformance_reports"] == []  # read only with --fill-hashes
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
    assert any("G5 needs at least one independent witness" in e for e in report["errors"])


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
    patterns = dump(PATTERN_DOCUMENT, tmp_path / "secret-patterns.json")
    out, jcs_out = tmp_path / "filled" / "card-unsigned.json", tmp_path / "filled" / "card-unsigned.jcs"
    code, report = run("card-content.json", "--fill-hashes", str(REPO), "--patterns", str(patterns), *sets,
                       "--final", "--write", str(out), "--jcs-out", str(jcs_out))
    assert code == 0, report["errors"]
    assert report["ready_to_sign"] and report["placeholders"] == {} and report["patterns"] == str(patterns)
    written = vc.load_json(out.read_bytes())
    assert jcs_out.read_bytes() == rfc8785.dumps(written)
    assert report["payload"]["sha256"] == hashlib.sha256(jcs_out.read_bytes()).hexdigest()
    # The filled body validates on its own against the same definitions, and the template on disk is untouched.
    # The conformance reports were given with --set, not read: --final warns for each of their evidence items.
    assert len(report["warnings"]) == 2 * len(vc.CONFORMANCE_ROWS)
    assert run(str(out), "--final", "--patterns", str(patterns))[0] == 0
    assert run(str(out), "--final")[0] == 1
    assert vc.load_json(CARD_PATH.read_bytes())["log_vkey"] == "<FILL:LOG_VKEY>"


def _hash_root(tmp_path, report=None, *, quorums=CONFORMANCE_QUORUMS):
    """A copy of the documents the card hashes, with *report* (a JSON value, or None for no file) as each conformance
    report (each copy differs in ``started_at``, so the two hashes differ), and beside each its run policy at the
    matching quorum of *quorums* (None: no policy file)."""
    root = tmp_path / "root"
    for rel in ("docs/legal/charter.md", "docs/legal/terms.md", "docs/legal/retention.md", "docs/legal/card-policy.md",
                "docs/spec/AICS-1.md"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / rel, root / rel)
    if report is not None:
        for i, (rel, quorum) in enumerate(zip(CONFORMANCE_REPORTS, quorums, strict=True)):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            body = dict(report, started_at=float(i)) if isinstance(report, dict) else report
            (root / rel).write_text(json.dumps(body), encoding="utf-8")
            if quorum is not None:
                (root / vc.conformance_policy_path(rel)).write_text(run_policy(quorum), encoding="utf-8")
    return root


def _fill_from(root, tmp_path, *extra):
    reports = {f"SHA256:{rel}" for rel in CONFORMANCE_REPORTS}
    sets = [f"--set={k}={v}" for k, v in fill_values().items() if k not in reports]
    patterns = dump(PATTERN_DOCUMENT, tmp_path / "secret-patterns.json")
    return run("card-content.json", "--fill-hashes", str(root), "--patterns", str(patterns), *sets, "--final", *extra)


def test_cli_fill_hashes_reads_the_conformance_reports(tmp_path):
    root = _hash_root(tmp_path, conformance_report())
    out = tmp_path / "filled.json"
    code, result = _fill_from(root, tmp_path, "--write", str(out))
    assert code == 0, result["errors"]
    assert result["ready_to_sign"] and result["warnings"] == []
    # Every proven conformance row names both runs; each run's policy, beside its report, gives its witness quorum.
    runs = list(zip(CONFORMANCE_REPORTS, CONFORMANCE_QUORUMS, strict=True))
    assert [(r["row"], r["file"], r["quorum"]) for r in result["conformance_reports"]] == [
        (aid, rel, quorum) for aid in vc.CONFORMANCE_ROWS for rel, quorum in runs]
    assert {r["policy"] for r in result["conformance_reports"]} == {vc.conformance_policy_path(rel)
                                                                    for rel in CONFORMANCE_REPORTS}
    digests = [hashlib.sha256((root / rel).read_bytes()).hexdigest() for rel in CONFORMANCE_REPORTS]
    assert len(set(digests)) == 2
    written = vc.load_json(out.read_bytes())
    for aid in vc.CONFORMANCE_ROWS:
        assert [e["hash"] for e in assurance(written, aid)["evidence"]
                if e["media_type"] == vc.CONFORMANCE_MEDIA_TYPE] == digests


@pytest.mark.parametrize("report, message", [
    (conformance_report(failing=("G6",)), "does not show G6 passing (verdicts: fail)"),
    (conformance_report(mode="fake"), "is a 'fake' run, not a run against an instance"),
    (conformance_report(spec="AICS-1 0.1-draft"), "is a report on 'AICS-1 0.1-draft'"),
    (conformance_report(fmt="aics-interop-server-conformance/v1", failing=("G9",)), "does not show G9 passing"),
    ({"format": "something-else/v1"}, "has format 'something-else/v1'"),
])
def test_cli_fill_hashes_refuses_a_report_that_does_not_back_the_card(tmp_path, report, message):
    code, result = _fill_from(_hash_root(tmp_path, report), tmp_path, "--write", str(tmp_path / "filled.json"))
    assert code == 1 and not result["ready_to_sign"]
    assert any(message in e and "conformance report" in e for e in result["errors"]), result["errors"]
    assert not (tmp_path / "filled.json").exists()


@pytest.mark.parametrize("quorums, seen", [
    ((0, 0), "conformance-2026-10-20-relaunch-build-quorum1.json: quorum 0)"),
    ((0, None), "quorum unknown, no run policy docs/evidence/conformance-2026-10-20-relaunch-build-quorum1.policy"),
    ((None, None), "conformance-2026-10-20-relaunch-build.json: quorum unknown"),
])
def test_cli_fill_hashes_needs_a_run_at_the_card_quorum(tmp_path, quorums, seen):
    # The card requires quorum 1: a run that accepted log-signed checkpoints alone (quorum 0) shows nothing about the
    # bundles a quorum-1 client accepts (the pre-launch build failed G1, G6 and G8 there), so each proven row must name
    # a run at quorum 1 or above, read from the run policy beside its report.
    code, result = _fill_from(_hash_root(tmp_path, conformance_report(), quorums=quorums), tmp_path)
    assert code == 1 and not result["ready_to_sign"]
    for aid in vc.CONFORMANCE_ROWS:
        assert any(f"no conformance report of {aid} ran at this card's witness quorum 1 or above" in e and seen in e
                   for e in result["errors"]), result["errors"]


def test_cli_fill_hashes_takes_any_run_at_or_above_the_card_quorum(tmp_path):
    code, result = _fill_from(_hash_root(tmp_path, conformance_report(), quorums=(2, 1)), tmp_path)
    assert code == 0, result["errors"]


def test_cli_fill_hashes_refuses_a_policy_that_is_not_toml(tmp_path):
    root = _hash_root(tmp_path, conformance_report())
    (root / vc.conformance_policy_path(CONFORMANCE_REPORTS[1])).write_text("quorum = = 1\n", encoding="utf-8")
    code, result = _fill_from(root, tmp_path)
    assert code == 1
    assert any("relaunch-build-quorum1.policy.toml of the conformance report" in e and "is not TOML" in e
               for e in result["errors"]), result["errors"]


def test_cli_fill_hashes_counts_the_interop_run_as_quorum_0(tmp_path):
    # aics-interop's in-process run has no witness: it may back a row next to an instance run at the card's quorum,
    # never alone on a quorum-1 card.
    root = _hash_root(tmp_path, conformance_report())
    interop = conformance_report(fmt="aics-interop-server-conformance/v1", failing=("G7",))  # G7 stays promised
    (root / CONFORMANCE_REPORTS[0]).write_text(json.dumps(interop), encoding="utf-8")
    code, result = _fill_from(root, tmp_path)
    assert code == 0, result["errors"]
    assert {r["quorum"] for r in result["conformance_reports"] if r["file"] == CONFORMANCE_REPORTS[0]} == {0}
    (root / CONFORMANCE_REPORTS[1]).write_text(json.dumps(interop), encoding="utf-8")
    code, result = _fill_from(root, tmp_path)
    assert code == 1
    assert any("no conformance report of G1 ran at this card's witness quorum 1" in e for e in result["errors"])


def test_cli_fill_hashes_needs_the_report_files(tmp_path):
    # --final needs the real reports: without the files the hashes cannot be filled (exit 2, as for any missing
    # document).
    code, result = _fill_from(_hash_root(tmp_path), tmp_path)
    assert code == 2 and CONFORMANCE_REPORTS[0] in result["input_error"]


def test_cli_warns_when_a_report_hash_is_set_by_hand(tmp_path):
    # --set SHA256:<report>=... fills the hash without reading the file, so nothing checked the report: --final warns
    # once per evidence item.
    sets = [f"--set={k}={v}" for k, v in fill_values().items()]
    patterns = dump(PATTERN_DOCUMENT, tmp_path / "secret-patterns.json")
    code, report = run("card-content.json", "--fill-hashes", str(REPO), "--patterns", str(patterns), *sets, "--final")
    assert code == 0, report["errors"]
    assert report["conformance_reports"] == []
    assert len(report["warnings"]) == 2 * len(vc.CONFORMANCE_ROWS)
    assert all("was given with --set, so it was not read" in w for w in report["warnings"])
    code, report = run("card-content.json", "--fill-hashes", str(REPO), "--patterns", str(patterns), *sets)
    assert report["warnings"] == []  # template mode: no warning


def test_conformance_report_problems_reads_both_formats():
    assert vc.conformance_report_problems(conformance_report(), "G1") == []
    assert vc.conformance_report_problems(conformance_report(fmt="aics-interop-server-conformance/v1"), "G8") == []
    assert vc.conformance_report_problems([], "G1") == ["is not a JSON object"]
    report = conformance_report()
    report["checks"] = [c for c in report["checks"] if c["id"] != "G4"]
    assert vc.conformance_report_problems(report, "G4") == ["does not show G4 passing (verdicts: none)"]
    report["checks"].append(dict(report["checks"][0], id="G4", verdict="pass"))
    report["checks"].append(dict(report["checks"][0], id="G4", verdict="pass"))  # a row listed twice is ambiguous
    assert vc.conformance_report_problems(report, "G4") == ["does not show G4 passing (verdicts: pass, pass)"]


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
    for gone in ("DM_SECONDS=7776000",):  # fixed by the charter
        code, report = run("card-content.json", "--set", gone)
        assert code == 2 and "names no placeholder" in report["input_error"]

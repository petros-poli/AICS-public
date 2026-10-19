"""Item 10: aics-conformance against the real aics-server, not its fake (decision 19).

``aics_interop.server.conformance_report`` boots the server in process at a production genesis, prepares it as an
operator prepares the verification day (the card logged as a policy leaf and pinned by the trust bundle's bootstrap
hash, a synthetic tombstone, a restart hook for G3, the TCP gate on loopback with a certificate the harness
trusts), and runs every registered aics-conformance check, the ten guarantees G1-G10 included.  The adapter's
output records each check and each guarantee as ``pass``, ``fail`` or ``not-applicable`` (a check that skipped).

Two runs: with the card the server builds itself, and with a reviewed card body (``AICS_CARD_FILE``) that states
another ciphertext budget, as an operator's reviewed card does once the server is configured with the same limit
(F27 retired: the server's own card states the budget it enforces).  ``aics-interop-server-conformance`` prints the
same table (``--ciphertext-budget BYTES`` for the second run).
"""

from __future__ import annotations

import json

import pytest

from aics_interop import drivers, findings, server, spec


def all_check_ids() -> list[str]:
    import aics_conformance.checks  # noqa: F401  (registers the modules)
    import aics_conformance.guarantees  # noqa: F401
    from aics_conformance.core import CHECKS

    return [c.id for c in CHECKS]


@pytest.fixture(scope="module")
def own_card(tmp_path_factory) -> dict:
    """The report against the card the server builds and signs (its skeleton, with the operator's documents)."""
    return server.conformance_report(tmp_path_factory.mktemp("conformance-own-card") / "instance")


@pytest.fixture(scope="module")
def reviewed_card(tmp_path_factory) -> dict:
    """The report against a reviewed card body stating a ciphertext budget of 1 GiB, the server configured alike."""
    return server.conformance_report(tmp_path_factory.mktemp("conformance-reviewed-card") / "instance",
                                     ciphertext_budget_bytes=1 << 30)


def failures(report: dict) -> dict[str, str]:
    return {r["id"]: str(r["details"].get("reason", "")) for r in report["checks"] if r["verdict"] != "pass"}


def test_the_adapter_runs_every_check_and_reports_every_guarantee(own_card):
    rows = own_card["checks"]
    assert [r["id"] for r in rows] == all_check_ids()
    assert all(set(r) == {"id", "title", "spec_ref", "verdict", "details"} for r in rows)  # the harness's rows
    assert list(own_card["guarantees"]) == [f"G{i}" for i in range(1, 11)]
    assert set(own_card["verdicts"].values()) <= {"pass", "fail", "not-applicable"}
    assert own_card["counts"] == {v: list(own_card["verdicts"].values()).count(v)
                                  for v in ("pass", "fail", "not-applicable")}
    assert own_card["server"]["genesis"].startswith("production") and own_card["profiles"] == ["SUP-1"]
    json.dumps(own_card)  # the report is JSON (written by aics-interop-server-conformance --report)


def test_every_guarantee_passes_with_a_reviewed_card(reviewed_card):
    """With the operator's reviewed card body, every check passes against the real server: nothing is skipped
    (the restart of G3 is executed, the tombstone and the secret probe are prepared)."""
    assert failures(reviewed_card) == {}
    assert reviewed_card["guarantees"] == {f"G{i}": "pass" for i in range(1, 11)}
    assert reviewed_card["counts"] == {"pass": len(all_check_ids()), "fail": 0, "not-applicable": 0}


def test_every_guarantee_passes_with_the_server_card(own_card):
    """The server's own card (no reviewed body) is the one an instance serves until an operator supplies one; it
    states the ciphertext budget the server enforces (F27 retired), so every check passes against it too."""
    assert own_card["guarantees"] == {f"G{i}": "pass" for i in range(1, 11)}
    assert failures(own_card) == {}


def test_the_server_card_states_the_budget_it_enforces_and_aics_accepts_it(tmp_path):
    """§13.1/§8.2: a positive ``retention.ciphertext_budget_bytes``, the published limit the server applies; aics
    verify card reads the AICS-1+SUP-1 card and accepts it as the bootstrap card the trust bundle pins."""
    instance = server.ServerInstance(tmp_path / "instance", tcp=False)
    try:
        card = instance.get("/.well-known/aics-card.json").body
        limits = spec.strict_json(instance.get("/v2/limits").body)["limits"]
        cli = drivers.AicsCli(home=tmp_path / "home", now=spec.strict_json(card)["issued_at"] + 10)
        trust = instance.oob.trust_bundle(spec.hexH(card))
        if cli.pin(spec.readme_block(spec.J(trust)), quorum=0).code != 0:
            pytest.fail("aics policy init failed")
        (tmp_path / "card.json").write_bytes(card)
        r = cli.run("verify", "card", "--file", str(tmp_path / "card.json"))
    finally:
        instance.close()
    budget = spec.strict_json(card)["retention"]["ciphertext_budget_bytes"]
    assert isinstance(budget, int) and budget > 0 and budget == limits["ciphertext_budget_bytes"]
    assert spec.strict_json(card)["spec"] == "AICS-1+SUP-1"
    assert r.code == 0 and r.data["bootstrap"] is True, r.data


def test_f27_is_retired():
    f = findings.FINDINGS["F27"]
    assert not f.open and f.package == "aics-server" and not f.documents


def test_the_cli_prints_the_guarantee_table(monkeypatch, capsys, tmp_path):
    """``aics-interop-server-conformance``: the table on stdout, the JSON report on request, exit 1 on a failure."""
    calls = {}

    def fake_report(root, *, only=None, ciphertext_budget_bytes=None):
        calls.update(only=only, budget=ciphertext_budget_bytes)
        rows = [{"id": "G1", "title": "t", "spec_ref": "s", "verdict": "pass", "details": {}},
                {"id": "G2", "title": "t", "spec_ref": "s", "verdict": "fail", "details": {"reason": "why"}}]
        return {"server": {"version": "0", "card": "c", "log_size": 3}, "checks": rows,
                "counts": {"pass": 1, "fail": 1, "not-applicable": 0}, "guarantees": server.guarantee_table(rows)}

    monkeypatch.setattr(server, "conformance_report", fake_report)
    out = tmp_path / "report.json"
    assert server.main(["--report", str(out), "--only", "G1", "--only", "G2", "--ciphertext-budget", "7"]) == 1
    assert calls == {"only": ["G1", "G2"], "budget": 7}
    text = capsys.readouterr().out
    assert "G1         pass" in text and "G2         fail" in text and "G3         not-run" in text
    assert "G2: fail: why" in text
    assert json.loads(out.read_text())["guarantees"]["G2"] == "fail"

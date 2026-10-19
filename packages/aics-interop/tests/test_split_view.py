"""Item 5, split views: AICS-1 §14.6 gossip-check classification.

Nine fixtures (``aics_interop.world.split_fixtures``; logs and tiles from
aics-tlog, cosignatures from aics-witness) cover every §14.6 outcome.  The
log origin serves note 1 with its tiles, the mirror serves note 2 (with its
tiles, unless the fixture withholds them).  Each pair is classified by

* the suite's reference ``spec.classify_gossip`` (the expected value),
* ``aics gossip-check`` (exit code, classification, ``split`` flag, the
  notes in its ``aics-split-view-evidence/v1`` bundle),
* aics-conformance ``G5`` over the same origin and mirror (verdict,
  ``details.verification``, reason, the notes in its evidence), and
  ``verify.continuity`` on the pair,
* ``aics-tlog verify-checkpoint`` with both tile sources (informative: it
  chooses a head, it is not a gossip check).

Mapping used throughout (README "Split-view classification"):

=====================  ===========================  ==========================================
AICS-1 §14.6           aics gossip-check            aics-conformance G5
=====================  ===========================  ==========================================
consistent             exit 0, split false          pass
split-proven           exit 2, classification       fail, verification invalid,
                       split-proven, or             reason ``split-proven: ...``
                       log-equivocation when a
                       note missed its witness
                       policy
consistency-unproven   exit 1                       fail, verification incomplete
not evidence           exit 1                       fail, verification invalid, log-key reason
=====================  ===========================  ==========================================
"""

from __future__ import annotations

import json

import pytest

from aics_interop import aicslog, drivers, spec, world

LOG_VKEY = aicslog.Keys().log_vkey()

EXPECTED = {
    "consistent-prefix": ("consistent", [True, True]),
    "same-tree-different-signatures": ("consistent", [True, True]),
    "equal-size-split": ("split-proven", [True, True]),
    "not-a-prefix": ("split-proven", [True, True]),
    "unwitnessed-equivocation": ("split-proven", [True, False]),
    "equivocation-invalid-cosignature": ("split-proven", [True, False]),
    "consistency-unproven": ("consistency-unproven", [True, True]),
    "bad-empty-root": ("split-proven", [True, True]),
    "not-log-signed": ("not-evidence", [True, False]),
}
NAMES = list(EXPECTED)
EXIT = {"consistent": 0, "split-proven": 2, "consistency-unproven": 1, "not-evidence": 1}


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    return {f.name: f for f in world.split_fixtures(tmp_path_factory.mktemp("split"))}


def serve(web, fx: world.SplitFixture) -> None:
    web.serve_log(aicslog.PREFIX, fx.a, fx.a_tiles)
    web.serve_log(aicslog.MIRROR, fx.b, fx.b_tiles)


def gossip_check(fx: world.SplitFixture, web, tmp_path) -> drivers.CliResult:
    serve(web, fx)
    cli = drivers.AicsCli(home=tmp_path / "aics-home", web=web, now=fx.now)
    r = cli.pin(spec.readme_block(spec.J(aicslog.trust_bundle())), witnesses=fx.witnesses, quorum=fx.quorum,
                mirrors=[aicslog.MIRROR])
    assert r.code == 0, r.data
    (tmp_path / "note-1.txt").write_bytes(fx.a)
    (tmp_path / "note-2.txt").write_bytes(fx.b)
    return cli.run("gossip-check", str(tmp_path / "note-1.txt"), str(tmp_path / "note-2.txt"))


def g5(fx: world.SplitFixture, web) -> dict:
    serve(web, fx)
    policy = drivers.conformance_policy(aicslog.trust_bundle(), witnesses=fx.witnesses, quorum=fx.quorum,
                                        mirrors=[aicslog.MIRROR])
    return drivers.run_conformance_check("G5", drivers.conformance_context(web, policy, fx.now))


def cli_relation(r: drivers.CliResult) -> str:
    if r.code in (0, 2):
        return {0: "consistent", 2: "split-proven"}[r.code]
    error = r.data.get("error", "")
    if "is not evidence" in error:
        return "not-evidence"
    if error.startswith("consistency-unproven"):
        return "consistency-unproven"
    return f"other: {error}"


def g5_relation(row: dict) -> str:
    if row["verdict"] == "pass":
        return "consistent"
    d = row["details"]
    reason = d.get("reason", "")
    if reason.startswith("split-proven") and d["verification"] == "invalid":
        return "split-proven"
    if d["verification"] == "incomplete":
        return "consistency-unproven"
    if "no signature from log key" in reason:
        return "not-evidence"
    if "quorum not met" in reason:
        return "witness-quorum-failure"
    return f"other: {reason}"


def cli_evidence_notes(r: drivers.CliResult) -> set[bytes]:
    return {n["note"].encode() for pair in r.evidence.get("pairs", []) for n in pair["notes"]}


def g5_evidence_notes(row: dict) -> set[bytes]:
    return {spec.dU64(n) for n in row["details"].get("evidence", {}).get("checkpoint_notes", [])}


# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_reference_classification(fixtures, name):
    """The expected values, from the suite's own §14.6 implementation."""
    fx = fixtures[name]
    assert (fx.expected["relation"], fx.expected["witness_policy_met"]) == EXPECTED[name]


@pytest.mark.parametrize("name", NAMES)
def test_aics_gossip_check_classification(fixtures, name, web, tmp_path):
    fx = fixtures[name]
    relation, met = EXPECTED[name]
    r = gossip_check(fx, web, tmp_path)
    assert cli_relation(r) == relation, r.data
    assert r.code == EXIT[relation]
    if relation == "not-evidence":
        return
    assert [n["witness_policy_met"] for n in r.data["notes_checked"]] == met
    if relation == "split-proven":
        classification = "split-proven" if all(met) else "log-equivocation"
        assert (r.data["classification"], r.data["split"]) == (classification, all(met))
        assert r.evidence["type"] == "aics-split-view-evidence/v1"
        assert {fx.a, fx.b} <= cli_evidence_notes(r)
    else:
        assert r.data["split"] is (False if relation == "consistent" else None)


@pytest.mark.parametrize("name", NAMES)
def test_aics_conformance_g5_classification(fixtures, name, web):
    fx = fixtures[name]
    relation, _ = EXPECTED[name]
    row = g5(fx, web)
    assert g5_relation(row) == relation, row["details"].get("reason")
    if relation == "split-proven":
        assert {fx.a, fx.b} <= g5_evidence_notes(row)


@pytest.mark.parametrize("name", NAMES)
def test_gossip_check_and_g5_classify_alike(fixtures, name, web, tmp_path):
    """The task's requirement, stated directly: same classification, same notes as evidence."""
    fx = fixtures[name]
    r = gossip_check(fx, web, tmp_path)
    row = g5(fx, web)
    assert g5_relation(row) == cli_relation(r), (r.data.get("classification"), row["details"].get("reason"))
    if cli_relation(r) == "split-proven":
        assert cli_evidence_notes(r) & {fx.a, fx.b} == g5_evidence_notes(row) & {fx.a, fx.b} == {fx.a, fx.b}


def test_g5_tells_an_unwitnessed_equivocation_from_a_lagging_unwitnessed_mirror(fixtures, web):
    """§14.6: the equivocating note is split evidence although it missed its witness policy; a consistent, uncosigned
    mirror head is no split, only a head that the witness policy does not accept (§6.3)."""
    fx = fixtures["unwitnessed-equivocation"]
    equivocation = g5(fx, web)
    lagging = world.SplitFixture("lagging", "", fx.a, aicslog.standard_log(12).note(12), fx.a_tiles, fx.a_tiles, 1)
    control = g5(lagging, web)
    assert g5_relation(equivocation) == "split-proven", equivocation["details"]["reason"]
    assert g5_relation(control) == "witness-quorum-failure", control["details"]["reason"]


@pytest.mark.parametrize("name", [n for n in NAMES if EXPECTED[n][0] in ("consistent", "split-proven")])
def test_conformance_continuity_on_the_pair(fixtures, name):
    """``verify.head(historical=True)`` on both notes, then ``verify.continuity`` (aics-conformance's §14.6 core)."""
    from aics_conformance import verify

    fx = fixtures[name]
    relation, _ = EXPECTED[name]
    policy = drivers.conformance_policy(aicslog.trust_bundle(), witnesses=fx.witnesses, quorum=fx.quorum)
    a = verify.head(fx.a, policy, fx.now, historical=True)
    b = verify.head(fx.b, policy, fx.now, historical=True)
    entries = fx.larger_entries or []
    if relation == "consistent":
        verify.continuity(a, b, entries, current=False)
    else:
        with pytest.raises(ValueError, match="split-proven"):
            verify.continuity(a, b, entries, current=False)


TLOG_EXPECTED = {  # aics-tlog verify-checkpoint --tiles A --tiles B: (exit, "split view" in the error)
    "consistent-prefix": (0, False),
    "same-tree-different-signatures": (0, False),
    "equal-size-split": (1, True),
    "not-a-prefix": (1, True),
    "consistency-unproven": (1, False),
}


@pytest.mark.parametrize("name", sorted(TLOG_EXPECTED))
def test_aics_tlog_cli_with_both_tile_sources(fixtures, name, tmp_path):
    """Informative: aics-tlog picks the largest valid head and requires the other to be consistent with it."""
    fx = fixtures[name]
    dirs = []
    for label, note, tiles in (("origin", fx.a, fx.a_tiles), ("mirror", fx.b, fx.b_tiles)):
        d = tmp_path / label
        d.mkdir()
        for path, data in (tiles or {}).items():
            (d / path).parent.mkdir(parents=True, exist_ok=True)
            (d / path).write_bytes(data)
        (d / "checkpoint").write_bytes(note)
        dirs += ["--tiles", str(d)]
    args = [*dirs, "--log-key", LOG_VKEY, "--quorum", str(fx.quorum), "--origin", aicslog.ORIGIN]
    for w in fx.witnesses:
        args += ["--witness-key", w]
    proc = drivers.tlog_subprocess("verify-checkpoint", *args)
    out = json.loads(proc.stdout)
    code, split = TLOG_EXPECTED[name]
    assert proc.returncode == code, out
    assert ("split view" in (out.get("error") or "")) is split
    if split:
        assert set(out["evidence"]) == {fx.a.decode(), fx.b.decode()}


def test_reference_pins_the_origin_and_compares_only_one_origin():
    """§14.1 step 1 (the origin comes from pinned material) and §14.2 step 1 (identical origins)."""
    log = aicslog.standard_log(12)
    note = log.note(12)
    assert spec.verify_note(note, LOG_VKEY, expected_origin=aicslog.ORIGIN).log_ok
    v = spec.verify_note(note, LOG_VKEY, expected_origin="other.interop.test/tiles")
    assert (v.log_ok, v.reason) == (False, "origin")
    # the pinned log key, under its pinned name, signing a checkpoint whose text names another origin
    text = spec.checkpoint_text("other.interop.test/tiles", 12, log.root(12))
    foreign = spec.signed_note(text, [spec.log_signature_line(aicslog.ORIGIN, aicslog.Keys().log, text)])
    assert spec.verify_note(foreign, LOG_VKEY).log_ok
    got = spec.classify_gossip(note, foreign, log_vkey=LOG_VKEY)
    assert (got["relation"], got.get("reason")) == ("not-evidence", "different origins")
    got = spec.classify_gossip(note, foreign, log_vkey=LOG_VKEY, expected_origin=aicslog.ORIGIN)
    assert got["relation"] == "not-evidence" and got["witness_policy_met"] == [True, False]


def test_reference_keeps_a_note_with_a_repeated_witness_line_as_log_signed_evidence(fixtures):
    """§6.2 rejects a repeated line for a recognized key; for a witness line the note is still what the log
    signed (§14.6), as for an invalid witness line."""
    fx = fixtures["equal-size-split"]
    witness_line = [ln for ln in fx.b.decode().split("\n") if ln.startswith(spec.EM_DASH)][-1] + "\n"
    repeated = fx.b + witness_line.encode()
    v = spec.verify_note(repeated, LOG_VKEY, fx.witnesses, fx.quorum, expected_origin=aicslog.ORIGIN)
    assert (v.log_ok, v.ok, v.reason) == (True, False, "duplicate_recognized")
    got = spec.classify_gossip(fx.a, repeated, log_vkey=LOG_VKEY, witness_vkeys=fx.witnesses, quorum=fx.quorum,
                               expected_origin=aicslog.ORIGIN)
    assert (got["relation"], got["witness_policy_met"]) == ("split-proven", [True, False])
    log_line = [ln for ln in fx.b.decode().split("\n") if ln.startswith(f"{spec.EM_DASH} {aicslog.ORIGIN} ")][0]
    v = spec.verify_note(fx.b + (log_line + "\n").encode(), LOG_VKEY, fx.witnesses, fx.quorum)
    assert (v.log_ok, v.reason) == (False, "duplicate_recognized")  # a repeated log line leaves no log signature


def test_reference_size_zero_consistency():
    """§14.2 step 1: for m=0 require the empty root and an empty proof; for m=n identical roots and no proof."""
    root = aicslog.standard_log(12).root(12)
    assert spec.verify_consistency(0, 12, spec.EMPTY_ROOT, root, [])
    assert not spec.verify_consistency(0, 12, spec.H(b"not the empty tree"), root, [])
    assert spec.verify_consistency(0, 0, spec.EMPTY_ROOT, spec.EMPTY_ROOT, [])


@pytest.mark.parametrize("case", ["bad-old-root-accepted", "two-empty-trees-rejected"])
def test_aics_tlog_size_zero_consistency_follows_aics1(case):
    from aics_tlog import verify_consistency

    if case == "bad-old-root-accepted":
        root = aicslog.standard_log(12).root(12)
        assert not verify_consistency(0, 12, spec.H(b"not the empty tree"), root, [])
    else:
        assert verify_consistency(0, 0, spec.EMPTY_ROOT, spec.EMPTY_ROOT, [])


def test_aics_tlog_cli_rejects_a_bad_empty_root_as_consistent(tmp_path):
    """The aics-tlog command printed in aics evidence bundles refuses a size-0 head whose root is not SHA-256("")."""
    log = aicslog.standard_log(12)
    proof = tmp_path / "proof.b64"
    proof.write_text("")
    bad = spec.B64(spec.H(b"not the empty tree"))
    proc = drivers.tlog_subprocess("verify-consistency", "--old-size", "0", "--new-size", "12", "--old-root", bad,
                                   "--new-root", spec.B64(log.root(12)), "--proof", str(proof))
    assert proc.returncode == 1, proc.stdout

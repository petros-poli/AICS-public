"""Item 6: offline bundles (AICS-1 §14.3; aics-tlog verify-bundle).

Producers: aics-tlog (``bundle_from_tiles`` / ``Bundle.to_json`` and the CLI's
``verify-inclusion --bundle-out`` over a tile directory), the suite's reference
(``spec.wire_bundle``: the §14.3 wire form, and ``spec.verification_package``),
and aics-conformance (the bundle its fake serves, the package G8 builds).
Verifiers: aics-tlog (``verify_bundle``, ``verify-bundle --offline``),
aics-conformance (``verify.bundle``, ``verify.offline_package``), the
reference (``spec.verify_wire_bundle``) and aics (``aics verify message``: the
wire bundle alone is incomplete, the package with the complete prefix verifies,
and ``verify checkpoint``/``gossip-check`` relate a bundle's note to a later head).
"""

from __future__ import annotations

import copy
import json

import pytest

from aics_interop import aicslog, drivers, spec, world

LOG_VKEY = aicslog.Keys().log_vkey()
WA, WB = world.witness_vkeys()
INDEX = 290  # a public post with a body


@pytest.fixture(scope="module")
def main(tmp_path_factory):
    m = world.main_scenario(tmp_path_factory.mktemp("bundle-witnesses"))
    yield m
    m.close()


@pytest.fixture(scope="module")
def tlog_bundle(main):
    from aics_tlog import bundle_from_tiles

    e = main.log.entries[INDEX]
    return bundle_from_tiles(main.log.verified_reader(300), INDEX, main.notes[300], envelope=e["payload"]["envelope"],
                             body_or_ct=main.log.bodies[INDEX])


@pytest.fixture(scope="module")
def wire(main):
    return main.log.wire_bundle(INDEX, main.notes[300])


def cpolicy(main, **kw):
    return drivers.conformance_policy(main.trust, witnesses=[WA, WB], quorum=2, **kw)


def now(main) -> int:
    return main.cosigned_at[300] + 10


# ---------------------------------------------------------------------------
# aics-tlog's own bundle form
# ---------------------------------------------------------------------------


def test_aics_tlog_bundle_verifies_in_aics_tlog(main, tlog_bundle):
    from aics_tlog import Bundle, WitnessPolicy, parse_vkey, verify_bundle

    policy = WitnessPolicy(2, (parse_vkey(WA), parse_vkey(WB)), None)
    res = verify_bundle(tlog_bundle, parse_vkey(LOG_VKEY), policy=policy)
    assert res.ok, res.error
    assert (res.envelope_bound_at, res.body_bound_at) == ("$.payload.envelope", "$.payload.body_hash")
    assert Bundle.from_json(tlog_bundle.to_json()) == tlog_bundle
    assert tlog_bundle.inclusion_proof == tuple(spec.inclusion_path(INDEX, [spec.leaf_hash(x) for x in
                                                                            main.log.leaves(300)]))


def test_aics_tlog_cli_writes_and_verifies_a_bundle_offline(main, tlog_bundle, tmp_path):
    tiles = tmp_path / "tiles"
    for path, data in main.log.tiles(300).items():
        (tiles / path).parent.mkdir(parents=True, exist_ok=True)
        (tiles / path).write_bytes(data)
    (tiles / "checkpoint").write_bytes(main.notes[300])
    (tmp_path / "envelope.json").write_text(json.dumps(main.log.entries[INDEX]["payload"]["envelope"]))
    (tmp_path / "body.bin").write_bytes(main.log.bodies[INDEX])
    witness_args = ["--witness-key", WA, "--witness-key", WB, "--quorum", "2"]
    proc = drivers.tlog_subprocess("verify-inclusion", "--tiles", str(tiles), "--log-key", LOG_VKEY,
                                   "--index", str(INDEX), "--bundle-out", str(tmp_path / "bundle.json"),
                                   "--envelope", str(tmp_path / "envelope.json"), "--body", str(tmp_path / "body.bin"),
                                   *witness_args)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (tmp_path / "bundle.json").read_text() == tlog_bundle.to_json()  # the CLI and the library agree
    proc = drivers.tlog_subprocess("verify-bundle", "--bundle", str(tmp_path / "bundle.json"), "--log-key", LOG_VKEY,
                                   "--offline", *witness_args)
    out = json.loads(proc.stdout)
    assert proc.returncode == 0 and out["ok"] and out["body"] == "$.payload.body_hash", out


# ---------------------------------------------------------------------------
# aics: the checkpoint part only
# ---------------------------------------------------------------------------


def test_aics_verifies_the_bundle_checkpoint_offline(main, tlog_bundle, web, tmp_path):
    """Network removed: aics accepts the bundle's note under the pinned policy and relates it to a later head."""
    from aics_tlog import Bundle, bundle_from_tiles

    web.offline = True
    cli = drivers.AicsCli(home=tmp_path / "home", web=web, now=now(main))
    assert cli.pin(spec.readme_block(main.trust_bytes), witnesses=[WA, WB], quorum=2).code == 0
    (tmp_path / "bundle-note.txt").write_text(tlog_bundle.checkpoint_note)
    r = cli.run("verify", "checkpoint", "--note", str(tmp_path / "bundle-note.txt"), "--no-save")
    assert (r.code, r.data["size"], r.data["fresh_cosignatures"]) == (0, 300, 2), r.data
    # an older bundle (size 256) is a prefix of the size-300 head: proof file, no network
    old = bundle_from_tiles(main.log.verified_reader(256), 100, main.notes[256])
    (tmp_path / "old-note.txt").write_text(Bundle.from_json(old.to_json()).checkpoint_note)
    (tmp_path / "proof.b64").write_text("".join(spec.B64(h) + "\n" for h in main.log.consistency_proof(256, 300)))
    r = cli.run("gossip-check", str(tmp_path / "old-note.txt"), str(tmp_path / "bundle-note.txt"), "--offline",
                "--proof", str(tmp_path / "proof.b64"))
    assert (r.code, r.data["split"]) == (0, False), r.data
    assert web.requests == []  # nothing was fetched


def test_aics_verifies_the_wire_bundle_and_the_package_offline(main, wire, web, tmp_path):
    """aics verify message, with the network removed: the wire bundle alone proves the checkpoint, the inclusion and
    the envelope but not the history through its index (incomplete, §14.3 step 2); the reference package (the
    complete prefix, the logged card, the note) verifies completely, as aics-conformance's offline_package does, and
    a package whose prefix was altered is refused."""
    web.offline = True
    cli = drivers.AicsCli(home=tmp_path / "home", web=web, now=now(main))
    assert cli.pin(spec.readme_block(main.trust_bytes), witnesses=[WA, WB], quorum=2).code == 0
    (tmp_path / "wire.json").write_text(json.dumps(wire))
    r = cli.run("verify", "message", "--bundle", str(tmp_path / "wire.json"), "--offline")
    assert r.code == 1 and r.data["result"] == "incomplete", r.data
    assert {s["step"]: s["status"] for s in r.data["steps"]}["envelope"] == "valid"
    pkg = reference_package(main, wire)
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    r = cli.run("verify", "message", "--bundle", str(tmp_path / "package.json"), "--offline")
    assert r.code == 0 and r.data["result"] == "valid", r.data
    assert r.data["policy_cards"] == [{"card_hash": spec.hexH(spec.J(main.card)), "signed": True, "logged": True}]
    assert r.data["signer"]["role"] == "name"
    pkg["entry_prefix"][7] = spec.U64(b"not the leaf")
    (tmp_path / "altered.json").write_text(json.dumps(pkg))
    r = cli.run("verify", "message", "--bundle", str(tmp_path / "altered.json"), "--offline")
    assert r.code == 1 and "reconstruct" in r.data["error"], r.data
    assert web.requests == []  # nothing was fetched
    r = cli.run("verify", "bundle")
    assert r.code == 1 and "invalid choice" in r.data["error"]


# ---------------------------------------------------------------------------
# the AICS-1 §14.3 wire bundle
# ---------------------------------------------------------------------------


def test_wire_bundle_verifies_in_conformance_and_the_reference(main, wire):
    from aics_conformance import verify

    hist, entry = verify.bundle(wire, cpolicy(main), now(main), prefix=main.log.leaves(300))
    assert entry == main.log.entries[INDEX] and len(hist.entries) == 300
    out = spec.verify_wire_bundle(wire, LOG_VKEY, [WA, WB], 2)
    assert out["entry"] == main.log.entries[INDEX]


def test_conformance_fake_serves_the_wire_form():
    """aics-conformance's producer (FakeServer.bundle) emits exactly the §14.3 members, verified by the reference."""
    from aics_conformance.fakes.server import FakeServer

    fake = FakeServer()
    for i in range(len(fake.entries)):
        b = fake.bundle(i)
        assert tuple(sorted(b)) == tuple(sorted(spec.BUNDLE_MEMBERS))
        spec.verify_wire_bundle(b, fake.vkey)


def test_aics_tlog_reads_the_wire_bundle(main, wire):
    from aics_tlog import Bundle, WitnessPolicy, parse_vkey, verify_bundle

    res = verify_bundle(Bundle.from_dict(wire), parse_vkey(LOG_VKEY),
                        policy=WitnessPolicy(2, (parse_vkey(WA), parse_vkey(WB)), None))
    assert res.ok


def test_aics_tlog_cli_verifies_the_wire_bundle(wire, tmp_path):
    (tmp_path / "wire.json").write_text(json.dumps(wire))
    proc = drivers.tlog_subprocess("verify-bundle", "--bundle", str(tmp_path / "wire.json"), "--log-key", LOG_VKEY,
                                   "--offline", "--witness-key", WA, "--witness-key", WB, "--quorum", "2")
    assert proc.returncode == 0, proc.stdout


def test_conformance_reads_the_aics_tlog_bundle(main, tlog_bundle):
    from aics_conformance import verify

    verify.bundle(json.loads(tlog_bundle.to_json()), cpolicy(main), now(main), prefix=main.log.leaves(300))


def test_aics_tlog_writes_the_wire_bundle(tlog_bundle, wire):
    """aics-tlog's bundle is the reference's §14.3 wire bundle, member for member and value for value (U64 entry
    bytes, the complete note in U64, U64 body); the pre-0.2 form (entry_bytes_b64, note text) is refused."""
    from aics_tlog import Bundle

    d = json.loads(tlog_bundle.to_json())
    assert list(d) == list(spec.BUNDLE_MEMBERS) and d == wire
    assert spec.dU64(d["checkpoint_note"]).startswith(aicslog.ORIGIN.encode() + b"\n")
    assert Bundle.from_dict(wire) == tlog_bundle
    legacy = {**{k: v for k, v in d.items() if k != "entry_bytes"},
              "entry_bytes_b64": spec.B64(spec.dU64(d["entry_bytes"]))}
    with pytest.raises(ValueError, match="pre-0.2"):
        Bundle.from_dict(legacy)


# change -> aics-conformance verify.bundle's refusal (schema.require raises ValueError with the rule)
TAMPER = {
    "proof": (lambda b: {**b, "inclusion_proof": [spec.B64(bytes(32))] + b["inclusion_proof"][1:]},
              "^bundle inclusion$"),
    "index": (lambda b: {**b, "index": b["index"] - 1}, "^bundle inclusion$"),
    "envelope": (lambda b: {**b, "envelope": {**b["envelope"], "sig": spec.U64(bytes(64))}},
                 "^bundle envelope mismatch$"),
    "body": (lambda b: {**b, "body_or_ct": spec.U64(b"tampered body")}, "^body commitment$"),
}


@pytest.mark.parametrize("case", sorted(TAMPER))
def test_tampered_bundles_are_rejected_by_all(main, wire, tlog_bundle, case):
    from aics_conformance import verify
    from aics_tlog import Bundle, WitnessPolicy, parse_vkey, verify_bundle

    change, refusal = TAMPER[case]
    bad = change(copy.deepcopy(wire))
    with pytest.raises(ValueError, match=refusal):
        verify.bundle(bad, cpolicy(main), now(main), prefix=main.log.leaves(300))
    with pytest.raises(ValueError):
        spec.verify_wire_bundle(bad, LOG_VKEY, [WA, WB], 2)
    d = change(json.loads(tlog_bundle.to_json()))  # aics-tlog writes the wire form, so the same change applies
    res = verify_bundle(Bundle.from_dict(d), parse_vkey(LOG_VKEY),
                        policy=WitnessPolicy(2, (parse_vkey(WA), parse_vkey(WB)), None))
    assert not res.ok


# ---------------------------------------------------------------------------
# the complete verification package
# ---------------------------------------------------------------------------


def reference_package(main, wire) -> dict:
    return spec.verification_package(wire, main.trust, [spec.J(main.card)], main.log.leaves(300), [main.notes[300]])


def test_conformance_verifies_the_aics1_package_offline(main, wire):
    """§14.3: {bundle, trust_bundle, policy_cards, entry_prefix, checkpoint_notes}, verified with no I/O."""
    from aics_conformance import verify

    pkg = reference_package(main, wire)
    assert tuple(pkg) == spec.PACKAGE_MEMBERS
    verify.offline_package(pkg, cpolicy(main), now(main))


def test_conformance_package_refuses_an_extra_member(main, wire):
    """§2: the package has exactly the §14.3 members; the former non-AICS-1 ``trust_policy`` member is refused."""
    from aics_conformance import verify

    pkg = reference_package(main, wire)
    hist, entry = verify.offline_package(pkg, cpolicy(main), now(main))
    assert entry == main.log.entries[INDEX] and hist.policy_events == [0, 1]
    pkg["trust_policy"] = {"witness_vkeys": [WA, WB], "quorum": 2, "max_checkpoint_age": 300}
    with pytest.raises(ValueError, match="exactly"):
        verify.offline_package(pkg, cpolicy(main), now(main))


def test_conformance_g8_writes_the_aics1_package():
    """aics-conformance's producer (G8) writes exactly the §14.3 members, and its package verifies offline."""
    from aics_conformance import checks, guarantees, verify  # noqa: F401  (checks and guarantees register CHECKS)
    from aics_conformance.core import CHECKS
    from aics_conformance.fakes.server import FakeServer

    ctx = FakeServer().context()
    row = next(c for c in CHECKS if c.id == "G8").run(ctx)
    assert row["verdict"] == "pass", row["details"]
    pkg = row["details"]["package"]
    assert tuple(pkg) == spec.PACKAGE_MEMBERS
    verify.offline_package(pkg, ctx.policy, ctx.now())

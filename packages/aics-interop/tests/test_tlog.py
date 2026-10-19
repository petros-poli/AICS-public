"""Item 5: the transparency log (AICS-1 §6, §14.1-14.2).

Producers: aics-tlog (tiles and entry bundles over AICS-1 entry-v2 objects,
checkpoint notes, inclusion and consistency proofs derived from authenticated
tiles), aics-witness (cosignatures from its add-checkpoint logic, in process,
with tile-derived consistency proofs) and its feeder's ``merge_cosignatures``.
Verifiers: aics (``verify checkpoint`` / ``verify consistency``, in process
over a fake web), aics-conformance (``verify.head``, ``verify.continuity``,
``verify.History`` and the ``log.checkpoint`` / ``G5`` checks), aics-tlog
(``verify_checkpoint`` and its CLI) and the suite's own reference
(``spec.verify_note``, ``spec.verify_inclusion``, ``spec.verify_consistency``,
``spec.verify_tiles``, ``spec.tile_path``).
Split-view classification is in ``test_split_view.py``.
"""

from __future__ import annotations

import base64
import json
import time

import pytest

from aics_interop import aicslog, drivers, spec, world
from aics_interop.witnesses import cosigned

LOG_VKEY = aicslog.Keys().log_vkey()
WA, WB = world.witness_vkeys()
NAME_A, NAME_B = aicslog.WITNESS_NAMES["witness_a"], aicslog.WITNESS_NAMES["witness_b"]


@pytest.fixture(scope="module")
def main(tmp_path_factory):
    m = world.main_scenario(tmp_path_factory.mktemp("main-witnesses"))
    yield m
    m.close()


def pinned_cli(tmp_path, web, now, *, witnesses, quorum, trust=None, **kw) -> drivers.AicsCli:
    cli = drivers.AicsCli(home=tmp_path / "aics-home", web=web, now=now)
    r = cli.pin(spec.readme_block(spec.J(trust or aicslog.trust_bundle())), witnesses=witnesses, quorum=quorum, **kw)
    assert r.code == 0, r.data
    return cli


def cli_note(cli: drivers.AicsCli, tmp_path, note: bytes, name: str = "note.txt") -> drivers.CliResult:
    path = tmp_path / name
    path.write_bytes(note)
    return cli.run("verify", "checkpoint", "--note", str(path), "--no-save")


def conformance_head(note: bytes, now: int, *, witnesses, quorum, historical=False):
    from aics_conformance import verify

    policy = drivers.conformance_policy(aicslog.trust_bundle(), witnesses=witnesses, quorum=quorum)
    return verify.head(note, policy, now, historical=historical)


def tlog_verify(note: bytes, now: int, *, witnesses, quorum, max_future=30, max_age=300):
    from aics_tlog import parse_note, parse_vkey, verify_checkpoint

    return verify_checkpoint(parse_note(note), parse_vkey(LOG_VKEY), [parse_vkey(w) for w in witnesses], quorum,
                             expected_origin=aicslog.ORIGIN, now=now, max_age_seconds=max_age,
                             max_future_seconds=max_future)


# ---------------------------------------------------------------------------
# entries and tiles
# ---------------------------------------------------------------------------


def test_entries_are_a_complete_aics1_history(main):
    """The log's 300 entries (charter, card, claims, posts) pass aics-conformance's complete-history verifier."""
    from aics_conformance import verify

    hist = verify.History(main.log.leaves(), drivers.conformance_policy(main.trust))
    assert len(hist.entries) == 300 and hist.policy_events == [0, 1]
    assert all(spec.J(spec.strict_json(raw)) == raw for raw in main.log.leaves())


def test_tiles_match_the_tlog_tiles_layout(main):
    """aics-tlog's tiles against the reference layout: height 8, partial widths, uint16-prefixed bundles."""
    from aics_tlog import IncrementalTileWriter, MemoryTileStore

    tiles = main.log.tiles(300)
    entries = main.log.leaves(300)
    leaves = [spec.leaf_hash(e) for e in entries]
    assert tiles == spec.tile_resources(entries)  # the reference tile writer, from C2SP tlog-tiles alone
    assert set(tiles) == {"tile/0/000", "tile/0/001.p/44", "tile/1/000.p/1", "tile/entries/000",
                          "tile/entries/001.p/44"}
    assert tiles["tile/0/000"] == b"".join(leaves[:256])
    assert tiles["tile/0/001.p/44"] == b"".join(leaves[256:])
    assert tiles["tile/1/000.p/1"] == spec.mth(leaves[:256])
    assert tiles["tile/entries/000"] == spec.entry_bundle(entries[:256])
    assert tiles["tile/entries/001.p/44"] == spec.entry_bundle(entries[256:])
    # the incremental writer (what a server runs) publishes the same bytes, appending in batches
    store = MemoryTileStore()
    writer = IncrementalTileWriter(store, 0)
    for lo, hi in ((0, 3), (3, 200), (200, 256), (256, 300)):
        writer.append(entries[lo:hi])
    assert store.tiles == tiles and writer.root() == spec.mth(leaves)


def _hashes(data: bytes) -> list[bytes]:
    return [data[i:i + 32] for i in range(0, len(data), 32)]


def test_tiles_are_read_alike_by_every_client(main, web):
    """aics, aics-conformance and aics-tlog authenticate the served tiles up to the same signed root.

    All three wrap aics_tlog's ``VerifiedTileReader``, so the reference
    authenticates the same tiles on its own: the signed root from tile/1 and
    tile/0 with ``spec.mth``, and every entry bundle against its level-0 tile."""
    from aics_cli.tiles_http import HttpTileReader
    from aics_conformance.client import Tiles
    from aics_tlog import MemoryTileReader, VerifiedTileReader, parse_checkpoint, parse_note

    tiles = main.log.tiles(300)
    web.serve_log(aicslog.PREFIX, main.notes[300], tiles)
    cp = parse_checkpoint(parse_note(main.notes[300]).text)
    v = spec.verify_note(main.notes[300], LOG_VKEY, [WA, WB], 2, expected_origin=aicslog.ORIGIN)
    assert v.ok and (v.size, v.root) == (cp.size, cp.root)
    left = tiles["tile/1/000.p/1"]  # MTH of leaves [0, 256), one level-1 hash
    assert spec.mth(_hashes(tiles["tile/0/000"])) == left
    assert spec.node_hash(left, spec.mth(_hashes(tiles["tile/0/001.p/44"]))) == v.root == spec.root_from_tiles(tiles, 300)
    reference = spec.verify_tiles(tiles, 300, v.root)
    readers = {
        "aics": VerifiedTileReader(HttpTileReader(aicslog.PREFIX, web), cp.size, cp.root),
        "aics-conformance": Tiles(aicslog.PREFIX, transport=web).authenticated(cp),
        "aics-tlog": VerifiedTileReader(MemoryTileReader(main.log.tiles(300)), cp.size, cp.root),
    }
    for name, reader in readers.items():
        reader.check_root()
        for i in (0, 1, 255, 256, 299):
            assert reader.entry(i) == reference[i] == spec.J(main.log.entries[i]), (name, i)


@pytest.mark.parametrize("n,encoded", [(0, "000"), (999, "999"), (1000, "x001/000"), (1234067, "x001/x234/067")])
@pytest.mark.parametrize("width", [None, 1, 255])
def test_tile_paths_follow_tlog_tiles(n, encoded, width):
    """C2SP tlog-tiles path encoding (3-digit elements, all but the last prefixed x; .p/<W> for 1-255)."""
    from aics_tlog.tiles import entry_bundle_path, parse_entry_bundle_path, parse_tile_path, tile_path

    suffix = "" if width is None else f".p/{width}"
    assert spec.tile_path(0, n, width) == f"tile/0/{encoded}{suffix}"
    assert spec.entry_bundle_path(n, width) == f"tile/entries/{encoded}{suffix}"
    for level in (0, 1, 5):
        assert tile_path(level, n, width) == spec.tile_path(level, n, width)
        assert parse_tile_path(spec.tile_path(level, n, width)) == (level, n, width)
    assert entry_bundle_path(n, width) == spec.entry_bundle_path(n, width)
    assert parse_entry_bundle_path(spec.entry_bundle_path(n, width)) == (n, width)


def _flip_byte(data: bytes, at: int) -> bytes:
    out = bytearray(data)
    out[at] ^= 0x01
    return bytes(out)


# One served resource changed per case: (resource, change, an entry index whose read authenticates that
# resource, whether the consistency proofs from tiles use it).  Entry bundles are not on the consistency path:
# a consistency proof is built from hash tiles only, so a changed bundle does not affect it.
TAMPERED = {
    "hash-tile": ("tile/0/000", lambda d: _flip_byte(d, 32 * 5 + 3), 5, True),
    "level-1-hash-tile": ("tile/1/000.p/1", lambda d: _flip_byte(d, 3), 0, True),
    "entry-bundle": ("tile/entries/001.p/44", lambda d: _flip_byte(d, 100), 256, False),
    "partial-tile-of-wrong-width": ("tile/0/001.p/44", lambda d: d[:-32], 299, True),
}


def _tampered(main, case: str) -> dict[str, bytes]:
    resource, change, _, _ = TAMPERED[case]
    tiles = dict(main.log.tiles(300))
    tiles[resource] = change(tiles[resource])
    return tiles


@pytest.mark.parametrize("case", sorted(TAMPERED))
def test_tampered_tiles_are_rejected_by_every_reader(main, web, case):
    """§6.1: hashes fetched from a server are not inherently trusted; every reader authenticates them."""
    from aics_cli.tiles_http import HttpTileReader
    from aics_conformance.client import Tiles
    from aics_tlog import MemoryTileReader, TileVerificationError, VerifiedTileReader, parse_checkpoint, parse_note

    tiles = _tampered(main, case)
    _, _, index, _ = TAMPERED[case]
    with pytest.raises(ValueError):
        spec.verify_tiles(tiles, 300, main.log.root(300))
    web.serve_log(aicslog.PREFIX, main.notes[300], tiles)
    cp = parse_checkpoint(parse_note(main.notes[300]).text)
    readers = {
        "aics": VerifiedTileReader(HttpTileReader(aicslog.PREFIX, web), cp.size, cp.root),
        "aics-conformance": Tiles(aicslog.PREFIX, transport=web).authenticated(cp),
        "aics-tlog": VerifiedTileReader(MemoryTileReader(tiles), cp.size, cp.root),
    }
    for name, reader in readers.items():
        with pytest.raises(TileVerificationError):
            reader.entry(index)


@pytest.mark.parametrize("case", sorted(TAMPERED))
def test_tampered_tiles_do_not_prove_consistency(main, web, tmp_path, case):
    """aics verify checkpoint and gossip-check derive the 3 -> 300 proof from the served tiles and must not
    advance on unauthenticated hashes; G5 reads the larger tree's entries and must not pass."""
    _, _, _, on_path = TAMPERED[case]
    tiles = _tampered(main, case)
    at = main.cosigned_at
    web.serve_log(aicslog.PREFIX, main.notes[3], main.log.tiles(3))
    cli = pinned_cli(tmp_path / "follow", web, at[3] + 10, witnesses=[WA, WB], quorum=2, trust=main.trust)
    r = cli.run("verify", "checkpoint")
    assert (r.code, r.data["continuity"]["status"]) == (0, "first"), r.data
    web.serve_log(aicslog.PREFIX, main.notes[300], tiles)
    cli.now = at[300] + 10
    r = cli.run("verify", "checkpoint")
    assert (r.code, r.data["continuity"]["status"]) == ((1, "unproven") if on_path else (0, "consistent")), r.data
    web.serve_log(aicslog.MIRROR, main.notes[3], main.log.tiles(3))
    (tmp_path / "note-3.txt").write_bytes(main.notes[3])
    (tmp_path / "note-300.txt").write_bytes(main.notes[300])
    gossip = pinned_cli(tmp_path / "gossip", web, at[300] + 10, witnesses=[WA, WB], quorum=2, trust=main.trust,
                        mirrors=[aicslog.MIRROR])
    r = gossip.run("gossip-check", str(tmp_path / "note-3.txt"), str(tmp_path / "note-300.txt"))
    if on_path:
        assert r.code == 1 and r.data["error"].startswith("consistency-unproven"), r.data
    else:
        assert (r.code, r.data["split"]) == (0, False), r.data
    policy = drivers.conformance_policy(main.trust, witnesses=[WA, WB], quorum=2, mirrors=[aicslog.MIRROR])
    row = drivers.run_conformance_check("G5", drivers.conformance_context(web, policy, at[300] + 10))
    assert (row["verdict"], row["details"]["verification"]) == ("fail", "invalid"), row


# ---------------------------------------------------------------------------
# checkpoint notes and cosignatures
# ---------------------------------------------------------------------------


def test_note_and_cosignature_bytes_agree_with_the_reference(main):
    """Ed25519 is deterministic: aics-tlog's log line and aics-witness's cosignature lines are the spec's bytes."""
    k = aicslog.Keys()
    for size, note in main.notes.items():
        text = spec.checkpoint_text(aicslog.ORIGIN, size, main.log.root(size))
        lines = [spec.log_signature_line(aicslog.ORIGIN, k.log, text)]
        for w in world.WITNESSES:
            lines.append(spec.cosignature_line(aicslog.WITNESS_NAMES[w], aicslog.witness_key(w),
                                               main.cosigned_at[size], text))
        assert note == spec.signed_note(text, lines), size
        assert main.log.note(size) == spec.signed_note(text, lines[:1])


def test_cosigned_checkpoint_verifies_everywhere(main, web, tmp_path):
    from aics_tlog import WitnessPolicy, parse_note, parse_vkey, verify_checkpoint

    note, ts = main.notes[300], main.cosigned_at[300]
    now = ts + 10
    v = spec.verify_note(note, LOG_VKEY, [WA, WB], 2, max_age=300, now=now)
    assert v.ok and sorted(v.counted) == [NAME_A, NAME_B]
    policy = WitnessPolicy(2, (parse_vkey(WA), parse_vkey(WB)), 300)
    res = verify_checkpoint(parse_note(note), parse_vkey(LOG_VKEY), policy=policy, now=now, max_future_seconds=30)
    assert res.ok and res.cosignature_count == 2
    head = conformance_head(note, now, witnesses=[WA, WB], quorum=2)
    assert head.timestamps == {NAME_A: ts, NAME_B: ts}
    web.serve_log(aicslog.PREFIX, note, main.log.tiles(300))
    cli = pinned_cli(tmp_path, web, now, witnesses=[WA, WB], quorum=2, trust=main.trust)
    r = cli.run("verify", "checkpoint")
    assert r.code == 0, r.data
    assert (r.data["fresh_cosignatures"], r.data["freshness"], r.data["size"]) == (2, "fresh", 300)
    assert [w["status"] for w in r.data["witnesses"]] == ["fresh", "fresh"]
    ctx = drivers.conformance_context(web, drivers.conformance_policy(main.trust, witnesses=[WA, WB], quorum=2), now)
    row = drivers.run_conformance_check("log.checkpoint", ctx)
    assert row["verdict"] == "pass" and row["details"]["freshness"] == "witnessed", row


def test_aics_tlog_cli_verifies_a_note_cosigned_by_aics_witness(tmp_path):
    """The third-party check printed in aics evidence bundles, run as the real aics-tlog CLI (wall clock)."""
    log = aicslog.standard_log(3)
    clock = world.Clock(int(time.time()))
    pool = world.witness_pool(tmp_path / "w", clock)
    note = world.cosign(log, 3, list(pool.values()), clock, clock.t)
    path = tmp_path / "checkpoint.note"
    path.write_bytes(note)
    proc = drivers.tlog_subprocess("verify-checkpoint", "--note", str(path), "--log-key", LOG_VKEY,
                                   "--witness-key", WA, "--witness-key", WB, "--quorum", "2", "--max-age", "300",
                                   "--max-future", "30", "--origin", aicslog.ORIGIN)
    out = json.loads(proc.stdout)
    assert proc.returncode == 0 and out["ok"] and out["cosignatures"] == 2, proc.stdout + proc.stderr


@pytest.fixture(scope="module")
def single(tmp_path_factory):
    """A size-3 note cosigned by witness_a alone at world.T_COSIGN."""
    log = aicslog.standard_log(3)
    clock = world.Clock(world.T_COSIGN)
    pool = world.witness_pool(tmp_path_factory.mktemp("single"), clock)
    note = world.cosign(log, 3, [pool["witness_a"]], clock, world.T_COSIGN)
    yield log, note, pool
    for w in pool.values():
        w.close()


# age = now - timestamp.  AICS-1 §6.3: now - max_checkpoint_age <= timestamp <= now + 30.
FRESHNESS = {"age-300": (300, True), "age-301": (301, False), "future-30": (-30, True), "future-31": (-31, False),
             "age-0": (0, True)}


@pytest.mark.parametrize("case", sorted(FRESHNESS))
def test_cosignature_freshness_bounds_agree(single, case, web, tmp_path):
    _, note, _ = single
    age, fresh = FRESHNESS[case]
    now = world.T_COSIGN + age
    assert spec.verify_note(note, LOG_VKEY, [WA], 1, max_age=300, now=now).ok is fresh
    assert tlog_verify(note, now, witnesses=[WA], quorum=1).ok is fresh
    try:
        conformance_head(note, now, witnesses=[WA], quorum=1)
        conformance_ok = True
    except ValueError as exc:
        assert "quorum not met" in str(exc)
        conformance_ok = False
    assert conformance_ok is fresh
    r = cli_note(pinned_cli(tmp_path, web, now, witnesses=[WA], quorum=1), tmp_path, note)
    assert r.code == (0 if fresh else 1), r.data
    if not fresh:
        assert r.data["result"] == "stale"
        assert r.data["witnesses"][0]["status"] == ("stale" if age > 0 else "future")


@pytest.mark.parametrize("how", ["library", "policy"])
def test_aics_tlog_default_future_bound_is_the_aics1_bound(single, how):
    """A cosignature dated now+31 must not count (AICS-1 §6.3): aics-tlog's default future bound is now+30."""
    from aics_tlog import WitnessPolicy, parse_note, parse_vkey, verify_checkpoint

    _, note, _ = single
    now = world.T_COSIGN - 31
    if how == "library":
        res = verify_checkpoint(parse_note(note), parse_vkey(LOG_VKEY), [parse_vkey(WA)], 1, now=now,
                                max_age_seconds=300)
    else:
        res = verify_checkpoint(parse_note(note), parse_vkey(LOG_VKEY), policy=WitnessPolicy(1, (parse_vkey(WA),), 300),
                                now=now)
    assert res.ok is False


def test_aics_tlog_cli_max_age_refuses_a_cosignature_dated_ahead(tmp_path):
    """``aics-tlog verify-checkpoint --max-age N`` (the command aics prints for third parties), cosigned 120 s ahead."""
    log = aicslog.standard_log(3)
    clock = world.Clock(int(time.time()) + 120)
    pool = world.witness_pool(tmp_path / "w", clock)
    note = world.cosign(log, 3, [pool["witness_a"]], clock, clock.t)
    path = tmp_path / "checkpoint.note"
    path.write_bytes(note)
    proc = drivers.tlog_subprocess("verify-checkpoint", "--note", str(path), "--log-key", LOG_VKEY,
                                   "--witness-key", WA, "--quorum", "1", "--max-age", "300",
                                   "--origin", aicslog.ORIGIN)
    assert proc.returncode == 1, proc.stdout


def test_quorum_is_counted_alike(single, web, tmp_path):
    """One of two pinned witnesses cosigned: quorum 2 fails everywhere, quorum 1 passes everywhere."""
    _, note, _ = single
    now = world.T_COSIGN + 10
    for quorum, ok in ((2, False), (1, True)):
        assert spec.verify_note(note, LOG_VKEY, [WA, WB], quorum, max_age=300, now=now).ok is ok
        assert tlog_verify(note, now, witnesses=[WA, WB], quorum=quorum).ok is ok
        if ok:
            conformance_head(note, now, witnesses=[WA, WB], quorum=quorum)
        else:
            with pytest.raises(ValueError, match="quorum not met"):
                conformance_head(note, now, witnesses=[WA, WB], quorum=quorum)
        home = tmp_path / f"q{quorum}"
        home.mkdir()
        r = cli_note(pinned_cli(home, web, now, witnesses=[WA, WB], quorum=quorum), home, note)
        assert r.code == (0 if ok else 1), r.data
        assert r.data.get("fresh_cosignatures", r.data.get("checkpoint", {}).get("fresh_cosignatures")) == 1


def _flip_cosignature(note: bytes, name: str) -> bytes:
    text = note.decode()
    out = []
    for line in text.split("\n"):
        if line.startswith(f"{spec.EM_DASH} {name} "):
            blob = bytearray(base64.b64decode(line.rsplit(" ", 1)[1]))
            blob[-1] ^= 0x01
            line = line.rsplit(" ", 1)[0] + " " + base64.b64encode(bytes(blob)).decode()
        out.append(line)
    return "\n".join(out).encode()


def test_an_invalid_line_under_a_pinned_witness_rejects_the_note(single, web, tmp_path):
    _, note, _ = single
    bad = _flip_cosignature(note, NAME_A)
    now = world.T_COSIGN + 10
    assert spec.verify_note(bad, LOG_VKEY, [WA], 1, max_age=300, now=now).reason == "bad_signature"
    res = tlog_verify(bad, now, witnesses=[WA], quorum=1)
    assert not res.ok and "failed verification" in res.error
    with pytest.raises(ValueError, match="failed verification"):
        conformance_head(bad, now, witnesses=[WA], quorum=1)
    cli = pinned_cli(tmp_path, web, now, witnesses=[WA], quorum=1)
    r = cli_note(cli, tmp_path, bad)
    assert (r.code, r.data["reason"]) == (1, "bad_cosignature"), r.data  # a file is not evidence (exit 1)
    web.serve_log(aicslog.PREFIX, bad, None)
    r = cli.run("verify", "checkpoint", "--no-save")
    assert (r.code, r.evidence.get("reason")) == (2, "bad_cosignature"), r.data  # served by the origin: evidence
    # unpinned witness lines are ignored, valid or not
    assert spec.verify_note(bad, LOG_VKEY, [WB], 0, max_age=300, now=now).ok
    assert tlog_verify(bad, now, witnesses=[WB], quorum=0).ok
    conformance_head(bad, now, witnesses=[WB], quorum=0)


def _unknown_key_line(note: bytes) -> str:
    """A valid signature line by a key nobody pins (a mirror's own attestation, say)."""
    from aics_tlog import parse_note

    text = parse_note(note).text
    return spec.log_signature_line("mirror.interop.test/attest", spec.test_key(0x5A), text)


def _with_lines(note: bytes, *lines: str) -> bytes:
    return note + "".join(lines).encode()


def test_aics_witness_ignores_repeated_unknown_key_lines(tmp_path):
    """§6.2: unknown-key lines are ignored, repeated or not; aics-witness cosigns such a note (200)."""
    log = aicslog.standard_log(3)
    clock = world.Clock(world.T_COSIGN)
    pool = world.witness_pool(tmp_path / "w", clock)
    unknown = _unknown_key_line(log.note(3))
    note = _with_lines(log.note(3), unknown, unknown)
    line = pool["witness_a"].add_checkpoint(note, 0, [])
    merged = cosigned(note, line)
    assert merged.decode().count(unknown) == 2
    v = spec.verify_note(merged, LOG_VKEY, [WA], 1, max_age=300, now=world.T_COSIGN)
    assert v.ok and v.ignored_lines == 2


@pytest.fixture(scope="module")
def repeated_unknown(tmp_path_factory):
    log = aicslog.standard_log(3)
    clock = world.Clock(world.T_COSIGN)
    pool = world.witness_pool(tmp_path_factory.mktemp("repeated"), clock)
    unknown = _unknown_key_line(log.note(3))
    note = _with_lines(log.note(3), unknown, unknown)
    merged = cosigned(note, pool["witness_a"].add_checkpoint(note, 0, []))
    yield merged
    for w in pool.values():
        w.close()


@pytest.mark.parametrize("verifier", ["aics-tlog", "aics", "aics-conformance"])
def test_verifiers_ignore_repeated_unknown_key_lines(repeated_unknown, verifier, web, tmp_path):
    now = world.T_COSIGN + 10
    if verifier == "aics-tlog":
        res = tlog_verify(repeated_unknown, now, witnesses=[WA], quorum=1)
        assert res.ok, res.error
    elif verifier == "aics":
        web.serve_log(aicslog.PREFIX, repeated_unknown, None)
        r = pinned_cli(tmp_path, web, now, witnesses=[WA], quorum=1).run("verify", "checkpoint", "--no-save")
        assert r.code == 0, r.data
    else:
        conformance_head(repeated_unknown, now, witnesses=[WA], quorum=1)


def test_a_repeated_line_for_a_recognized_key_is_rejected_everywhere(single, web, tmp_path):
    from aics_witness.service import WitnessError

    log, note, pool = single
    log_line = [ln for ln in note.decode().split("\n") if ln.startswith(f"{spec.EM_DASH} {aicslog.ORIGIN} ")][0]
    dup = _with_lines(note, log_line + "\n")
    now = world.T_COSIGN + 10
    assert spec.verify_note(dup, LOG_VKEY, [WA], 1, max_age=300, now=now).reason == "duplicate_recognized"
    assert not tlog_verify(dup, now, witnesses=[WA], quorum=1).ok
    with pytest.raises(ValueError, match="duplicate"):
        conformance_head(dup, now, witnesses=[WA], quorum=1)
    r = cli_note(pinned_cli(tmp_path, web, now, witnesses=[WA], quorum=1), tmp_path, dup)
    assert r.code == 1 and "duplicate" in r.data["error"], r.data
    with pytest.raises(WitnessError) as exc:  # §6.2: duplicate trusted lines are 403 at the witness
        pool["witness_b"].add_checkpoint(_with_lines(log.note(3), log_line + "\n"), 0, [])
    assert exc.value.status == 403


# ---------------------------------------------------------------------------
# proofs
# ---------------------------------------------------------------------------

INCLUSION = [(0, 1), (0, 3), (2, 3), (1, 256), (255, 256), (256, 257), (0, 300), (256, 300), (299, 300), (137, 300)]


@pytest.mark.parametrize("index,size", INCLUSION)
def test_inclusion_proofs_agree(main, index, size):
    from aics_tlog import MerkleTree, inclusion_proof_from_tiles, verify_inclusion

    entries = main.log.leaves(size)
    leaves = [spec.leaf_hash(e) for e in entries]
    tiles = inclusion_proof_from_tiles(main.log.verified_reader(size), index, size)
    assert tiles == spec.inclusion_path(index, leaves) == MerkleTree(entries).inclusion_proof(index, size)
    root = spec.mth(leaves)
    assert spec.verify_inclusion(leaves[index], index, size, tiles, root)
    assert verify_inclusion(leaves[index], index, size, tiles, root)
    if tiles:
        bad = [tiles[0][:-1] + bytes([tiles[0][-1] ^ 1]), *tiles[1:]]
        assert not spec.verify_inclusion(leaves[index], index, size, bad, root)
        assert not verify_inclusion(leaves[index], index, size, bad, root)
    assert not spec.verify_inclusion(leaves[index], index, size, tiles + [root], root)
    assert not verify_inclusion(leaves[index], index, size, tiles + [root], root)


CONSISTENCY = [(1, 3), (2, 3), (3, 256), (3, 300), (128, 256), (255, 300), (256, 300), (257, 300), (300, 300)]


@pytest.mark.parametrize("old,new", CONSISTENCY)
def test_consistency_proofs_agree(main, old, new):
    from aics_cli.checkpoints import Cp
    from aics_cli.consistency import GivenProof, relate
    from aics_tlog import MerkleTree, consistency_proof_from_tiles, verify_consistency

    leaves = [spec.leaf_hash(e) for e in main.log.leaves(new)]
    proof = consistency_proof_from_tiles(main.log.verified_reader(new), old, new)
    assert proof == spec.consistency_path(old, leaves) == MerkleTree(main.log.leaves(new)).consistency_proof(old, new)
    r_old, r_new = spec.mth(leaves[:old]), spec.mth(leaves)
    assert spec.verify_consistency(old, new, r_old, r_new, proof)
    assert verify_consistency(old, new, r_old, r_new, proof)
    a = Cp("", aicslog.ORIGIN, old, r_old, "old")
    b = Cp("", aicslog.ORIGIN, new, r_new, "new")
    assert relate(a, b, [GivenProof("interop proof", proof)]).status == "consistent"
    if old < new:
        wrong = spec.mth(leaves[: old - 1]) if old > 1 else spec.H(b"x")
        assert not spec.verify_consistency(old, new, wrong, r_new, proof)
        assert not verify_consistency(old, new, wrong, r_new, proof)
        assert relate(Cp("", aicslog.ORIGIN, old, wrong, "old"), b,
                      [GivenProof("interop proof", proof)]).status == "unproven"


# ---------------------------------------------------------------------------
# following the log over time
# ---------------------------------------------------------------------------


def test_clients_follow_the_log_through_tiles_and_the_proof_endpoint(main, web, tmp_path):
    from aics_conformance import verify

    at = main.cosigned_at
    web.serve_log(aicslog.PREFIX, main.notes[3], main.log.tiles(3))
    cli = pinned_cli(tmp_path, web, at[3] + 10, witnesses=[WA, WB], quorum=2, trust=main.trust,
                     consistency=aicslog.CONSISTENCY_URL)
    r = cli.run("verify", "checkpoint")
    assert (r.code, r.data["continuity"]["status"]) == (0, "first"), r.data
    # size 256: the consistency proof 3 -> 256 comes from the served tiles
    web.serve_log(aicslog.PREFIX, main.notes[256], main.log.tiles(256))
    cli.now = at[256] + 10
    r = cli.run("verify", "checkpoint")
    assert (r.code, r.data["continuity"]["status"]) == (0, "consistent"), r.data
    assert r.data["continuity"]["detail"]["proof_source"].startswith("tiles")
    # size 300 without tiles: the proof endpoint (AICS-1 §12.1 {from,to,hashes}) serves a tile-derived proof
    web.serve_log(aicslog.PREFIX, main.notes[300], None)
    web.serve_consistency(aicslog.CONSISTENCY_URL, {(256, 300): main.log.consistency_proof(256, 300),
                                                    (3, 300): main.log.consistency_proof(3, 300)})
    cli.now = at[300] + 10
    r = cli.run("verify", "checkpoint")
    assert (r.code, r.data["continuity"]["status"]) == (0, "consistent"), r.data
    assert r.data["continuity"]["detail"]["proof_source"].startswith("consistency endpoint")
    r = cli.run("verify", "consistency")
    assert (r.code, r.data["consistent"]) == (0, 2), r.data
    # aics-conformance reaches the same conclusions from the same notes
    policy = drivers.conformance_policy(main.trust, witnesses=[WA, WB], quorum=2, mirrors=[aicslog.MIRROR],
                                        saved_checkpoint=main.notes[3])
    old = verify.head(main.notes[3], policy, at[3] + 10)
    new = verify.head(main.notes[300], policy, at[300] + 10)
    verify.continuity(old, new, main.log.leaves(300))
    web.serve_log(aicslog.PREFIX, main.notes[300], main.log.tiles(300))
    web.serve_log(aicslog.MIRROR, main.notes[256], main.log.tiles(256))  # a lagging mirror
    row = drivers.run_conformance_check("G5", drivers.conformance_context(web, policy, at[300] + 10))
    assert row["verdict"] == "pass", row
    assert row["details"]["views"] == 4


def test_aics_witness_refuses_inconsistent_checkpoints_and_keeps_evidence(tmp_path):
    from aics_witness.service import WitnessError

    main, fork = aicslog.standard_log(12), aicslog.standard_log(14, fork_after=6)
    clock = world.Clock(world.T_COSIGN)
    pool = world.witness_pool(tmp_path / "w", clock)
    w = pool["witness_a"]
    w.feed(main, 12)
    with pytest.raises(WitnessError) as exc:
        w.add_checkpoint(fork.note(12), 12, [])            # §6.2: same size, other root after the old-size check
    assert exc.value.status == 422
    with pytest.raises(WitnessError) as exc:
        w.add_checkpoint(fork.note(12), 0, [])             # wrong old size, but still evidence of equivocation
    assert exc.value.status == 409 and exc.value.body == b"12\n"
    with pytest.raises(WitnessError) as exc:              # a fork's own (valid) proof does not match the cosigned root
        w.add_checkpoint(fork.note(14), 12, fork.consistency_proof(12, 14))
    assert exc.value.status == 422
    with pytest.raises(WitnessError) as exc:
        pool["witness_b"].add_checkpoint(main.note(0, root=spec.H(b"x")), 0, [])
    assert exc.value.status == 422
    kept = w.store.evidence(aicslog.ORIGIN)
    assert len(kept) == 3
    for ev in kept:
        assert ev.request.endswith(fork.note(12)) or ev.request.endswith(fork.note(14))
    assert w.store.get(aicslog.ORIGIN).size == 12  # nothing was cosigned after the fork

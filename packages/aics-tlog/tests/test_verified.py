"""Proofs from any TileReader for arbitrary sizes, and tiles authenticated
against a trusted tree head (VerifiedTileReader, audit_tiles)."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aics_tlog import MerkleTree, leaf_hash, verify_consistency, verify_inclusion
from aics_tlog.hashing import EMPTY_HASH
from aics_tlog.tiles import (
    MemoryTileReader,
    TileMissingError,
    TileVerificationError,
    build_entry_bundle,
    consistency_proof_from_tiles,
    inclusion_proof_from_tiles,
    materialise_tiles,
    parse_entry_bundle,
    read_entry,
    tree_root_from_tiles,
)
from aics_tlog.verified import VerifiedTileReader, audit_tiles
from aics_tlog.writer import IncrementalTileWriter, MemoryTileStore

from conftest import flip_bit, make_leaves

N = 1500
LEAVES = make_leaves(N)
TREE = MerkleTree(LEAVES)


def _incremental_store(batches, prune=True):
    store = MemoryTileStore()
    writer = IncrementalTileWriter(store, prune_partials=prune)
    sizes, pos = [], 0
    for b in batches:
        writer.append(LEAVES[pos : pos + b])
        pos += b
        sizes.append(pos)
    return store, sizes


# --- (3) proofs from any reader, arbitrary sizes --------------------------------


@given(data=st.data())
@settings(max_examples=150, deadline=None)
def test_property_proofs_any_sizes_from_any_reader(data):
    """For tiles published at size S (full rebuild, incremental with and
    without pruning, and the authenticated view of each), inclusion proofs
    for any (index, size <= S) and consistency proofs for any
    (old <= new <= S) equal the in-memory tree's and verify."""
    S = data.draw(st.integers(min_value=1, max_value=N), label="S")
    batches = data.draw(st.lists(st.integers(min_value=1, max_value=400), min_size=1, max_size=8), label="batches")
    # make the batches end exactly at S
    cut, pos = [], 0
    for b in batches:
        if pos + b >= S:
            break
        cut.append(b)
        pos += b
    cut.append(S - pos)
    prune = data.draw(st.booleans(), label="prune")
    inc, _ = _incremental_store(cut, prune)
    readers = {
        "rebuild": MemoryTileReader(materialise_tiles(LEAVES[:S])),
        "incremental": inc,
    }
    readers["verified-incremental"] = VerifiedTileReader(inc, S, TREE.root(S))
    size = data.draw(st.integers(min_value=1, max_value=S), label="size")
    index = data.draw(st.integers(min_value=0, max_value=size - 1), label="index")
    new = data.draw(st.integers(min_value=0, max_value=S), label="new")
    old = data.draw(st.integers(min_value=0, max_value=new), label="old")
    want_inc = TREE.inclusion_proof(index, size)
    want_cons = TREE.consistency_proof(old, new) if new else []
    for name, reader in readers.items():
        assert tree_root_from_tiles(reader, size, S) == TREE.root(size), name
        got = inclusion_proof_from_tiles(reader, index, size, S)
        assert got == want_inc, name
        assert verify_inclusion(leaf_hash(LEAVES[index]), index, size, got, TREE.root(size)), name
        if new:
            got = consistency_proof_from_tiles(reader, old, new, S)
            assert got == want_cons, name
            assert verify_consistency(old, new, TREE.root(old), TREE.root(new), got), name  # root(0) is H("")
        assert read_entry(reader, index, S) == LEAVES[index], name


def test_proofs_for_old_checkpoints_against_pruned_store():
    """A store grown past an old checkpoint (its partials pruned once full)
    still proves everything at the old size, through full-tile fallback, and
    at the old size's own widths when the newer size is used as tile_size."""
    store, sizes = _incremental_store([100, 100, 100, 700, 500])
    assert sizes[-1] == 1500
    assert "tile/0/000.p/100" not in store.tiles  # pruned
    for old_size in sizes:
        root = TREE.root(old_size)
        assert tree_root_from_tiles(store, old_size) == root  # widths of old_size, then full
        vr = VerifiedTileReader(store, old_size, root)
        vr.check_root()
        for i in (0, old_size // 2, old_size - 1):
            p = inclusion_proof_from_tiles(vr, i, old_size)
            assert verify_inclusion(leaf_hash(LEAVES[i]), i, old_size, p, root)
        p = consistency_proof_from_tiles(store, old_size, 1500)
        assert verify_consistency(old_size, 1500, root, TREE.root(1500), p)


def test_lagging_source_served_through_hint_widths():
    """A source that only has tiles up to size s still proves size s when the
    caller names a newer tile_size S: the fetcher falls back to s's widths."""
    store, _ = _incremental_store([300])  # source lags at 300
    p = inclusion_proof_from_tiles(store, 299, 300, tile_size=1200)
    assert verify_inclusion(leaf_hash(LEAVES[299]), 299, 300, p, TREE.root(300))


def test_argument_validation():
    reader = MemoryTileReader(materialise_tiles(LEAVES[:10]))
    with pytest.raises(ValueError):
        inclusion_proof_from_tiles(reader, 10, 10)
    with pytest.raises(ValueError):
        inclusion_proof_from_tiles(reader, 0, 10, tile_size=5)
    with pytest.raises(ValueError):
        consistency_proof_from_tiles(reader, 5, 4)
    with pytest.raises(ValueError):
        consistency_proof_from_tiles(reader, 1, 10, tile_size=9)
    assert consistency_proof_from_tiles(reader, 0, 10) == []
    assert consistency_proof_from_tiles(reader, 10, 10) == []
    with pytest.raises(ValueError):
        read_entry(reader, 10, 10)
    with pytest.raises(TileMissingError):
        read_entry(MemoryTileReader({}), 0, 10)


def test_wrong_length_tile_is_an_error():
    tiles = materialise_tiles(LEAVES[:10])
    tiles["tile/0/000.p/10"] = tiles["tile/0/000.p/10"][:-32]
    with pytest.raises(ValueError):
        tree_root_from_tiles(MemoryTileReader(tiles), 10)


# --- authenticated tiles ---------------------------------------------------------


def test_verified_reader_serves_only_the_trusted_tree():
    store, _ = _incremental_store([1500])
    # Size 1000 was never published by this store, so its partial tiles were
    # never written: without a hint the right edge is missing ...
    with pytest.raises(TileMissingError):
        VerifiedTileReader(store, 1000, TREE.root(1000)).check_root()
    # ... with the newer published size as a hint, the wider partials serve it.
    vr = VerifiedTileReader(store, 1000, TREE.root(1000), tile_size=1500)
    assert vr.read_tile(0, 3, 232) == store.tiles["tile/0/003"][: 232 * 32]
    assert vr.read_tile(0, 3, None) is None  # not full at size 1000
    assert vr.read_tile(0, 3, 233) is None  # wider than the tree
    assert vr.read_tile(0, 4, 1) is None  # beyond the tree
    assert vr.read_tile(0, 2, None) == store.tiles["tile/0/002"]
    assert parse_entry_bundle(vr.read_entry_bundle(3, 232)) == LEAVES[768:1000]
    assert vr.read_entry_bundle(3, None) is None
    assert vr.entry(999) == LEAVES[999]
    assert vr.leaf_hash(999) == leaf_hash(LEAVES[999])
    with pytest.raises(ValueError):
        vr.entry(1000)


def test_verified_reader_rejects_wrong_root_and_bad_tiles():
    store, _ = _incremental_store([700, 800])
    root = TREE.root(1500)
    with pytest.raises(TileVerificationError):
        VerifiedTileReader(store, 1500, TREE.root(1499)).check_root()
    with pytest.raises(TileVerificationError):
        VerifiedTileReader(store, 0, root)
    VerifiedTileReader(store, 0, EMPTY_HASH).check_root()
    for victim in ("tile/0/002", "tile/0/005.p/220", "tile/1/000.p/5"):
        bad = dict(store.tiles)
        bad[victim] = flip_bit(bad[victim], 77)
        vr = VerifiedTileReader(MemoryTileStore(bad), 1500, root)
        with pytest.raises(TileVerificationError):
            for i in range(0, 1500, 97):
                inclusion_proof_from_tiles(vr, i, 1500)
                vr.entry(i)
    bad = dict(store.tiles)
    entries = parse_entry_bundle(bad["tile/entries/001"])
    entries[7] = b"forged"
    bad["tile/entries/001"] = build_entry_bundle(entries)
    vr = VerifiedTileReader(MemoryTileStore(bad), 1500, root)
    assert vr.leaf_hash(256 + 7) == leaf_hash(LEAVES[263])  # the level 0 tile is fine
    for i in (256 + 6, 256 + 7):  # the bundle is rejected as a whole
        with pytest.raises(TileVerificationError):
            vr.entry(i)
    with pytest.raises(ValueError):
        VerifiedTileReader(store, 10, TREE.root(10), tile_size=9)


class TwoSourceReader:
    """First answer from a bad source, then (after reject) from a good one;
    records what was saved."""

    def __init__(self, bad, good):
        self.sources = [bad, good]
        self.skip = {}
        self.served = {}
        self.saved = []

    def _get(self, path):
        start = self.skip.get(path, 0)
        for i, src in enumerate(self.sources[start:], start):
            if path in src:
                self.served[path] = i
                return src[path]
        return None

    def read_tile(self, level, index, width):
        from aics_tlog.tiles import tile_path

        return self._get(tile_path(level, index, width))

    def read_entry_bundle(self, index, width):
        from aics_tlog.tiles import entry_bundle_path

        return self._get(entry_bundle_path(index, width))

    def _reject(self, path):
        i = self.served.pop(path, None)
        if i is None:
            return False
        self.skip[path] = i + 1
        return i + 1 < len(self.sources)

    def reject_tile(self, level, index, width):
        from aics_tlog.tiles import tile_path

        return self._reject(tile_path(level, index, width))

    def reject_entry_bundle(self, index, width):
        from aics_tlog.tiles import entry_bundle_path

        return self._reject(entry_bundle_path(index, width))

    def save_tile(self, level, index, width, data):
        self.saved.append(("tile", level, index, width, data))

    def save_entry_bundle(self, index, width, data):
        self.saved.append(("entries", index, width, data))


def test_verified_reader_routes_around_a_bad_source_and_saves_only_good_data():
    good = materialise_tiles(LEAVES)
    bad = {p: flip_bit(d, 3) for p, d in good.items()}
    reader = TwoSourceReader(bad, good)
    vr = VerifiedTileReader(reader, N, TREE.root())
    for i in (0, 300, 1499):
        p = inclusion_proof_from_tiles(vr, i, N)
        assert verify_inclusion(leaf_hash(LEAVES[i]), i, N, p, TREE.root())
        assert vr.entry(i) == LEAVES[i]
    assert reader.saved
    for item in reader.saved:
        if item[0] == "tile":
            _, level, index, width, data = item
            from aics_tlog.tiles import tile_path

            assert good[tile_path(level, index, width)] == data
        else:
            _, index, width, data = item
            from aics_tlog.tiles import entry_bundle_path

            assert good[entry_bundle_path(index, width)] == data


def test_audit_finds_damage_anywhere():
    store, _ = _incremental_store([1500])
    report = audit_tiles(store, 1500, TREE.root())
    assert (report.tiles, report.bundles) == (6 + 1, 6)
    for victim in ("tile/0/000", "tile/entries/004"):
        bad = dict(store.tiles)
        bad[victim] = flip_bit(bad[victim], 8 * 40)
        with pytest.raises(TileVerificationError):
            audit_tiles(MemoryTileStore(bad), 1500, TREE.root())
    bad = dict(store.tiles)
    del bad["tile/0/001"]
    with pytest.raises(TileMissingError):
        audit_tiles(MemoryTileStore(bad), 1500, TREE.root())
    assert audit_tiles(store, 1500, TREE.root(), entries=False).bundles == 0


@pytest.mark.parametrize("S", [1, 2, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 1499, 1500])
def test_sweep_tile_boundaries_incremental_verified(S):
    store, sizes = _incremental_store([b for b in (S // 3, S // 3) if b] + [S - 2 * (S // 3)])
    assert sizes[-1] == S
    vr = VerifiedTileReader(store, S, TREE.root(S))
    probe = sorted({1, 2, 255, 256, 257, S // 2, S - 1, S} & set(range(1, S + 1)))
    for size in probe:
        for i in sorted({0, size // 2, size - 1}):
            p = inclusion_proof_from_tiles(vr, i, size, S)
            assert p == TREE.inclusion_proof(i, size), (S, size, i)
        for old in sorted({0, 1, size // 2, size - 1, size} & set(range(0, size + 1))):
            p = consistency_proof_from_tiles(vr, old, size, S)
            assert p == (TREE.consistency_proof(old, size) if old else []), (S, old, size)


def test_multi_level_proofs_from_verified_incremental_store():
    leaves = make_leaves(70100)
    tree = MerkleTree(leaves)
    store = MemoryTileStore()
    writer = IncrementalTileWriter(store)
    for lo, hi in ((0, 65535), (65535, 65537), (65537, 70000), (70000, 70100)):
        writer.append(leaves[lo:hi])
    vr = VerifiedTileReader(store, 70100, tree.root())
    for size, i in ((70100, 0), (70100, 65535), (70100, 65536), (70100, 70099), (65537, 65536), (300, 299)):
        p = inclusion_proof_from_tiles(vr, i, size, 70100)
        assert p == tree.inclusion_proof(i, size), (size, i)
        assert verify_inclusion(leaf_hash(leaves[i]), i, size, p, tree.root(size))
    for old, new in ((1, 70100), (65535, 65536), (65536, 70100), (65537, 70000), (256, 65536)):
        p = consistency_proof_from_tiles(vr, old, new, 70100)
        assert p == tree.consistency_proof(old, new), (old, new)
        assert verify_consistency(old, new, tree.root(old), tree.root(new), p)


def test_failed_copy_then_missing_reports_verification_failure():
    good = materialise_tiles(LEAVES)
    bad = {p: flip_bit(d, 3) for p, d in good.items()}
    only_bad = TwoSourceReader(bad, {})  # second source has nothing
    vr = VerifiedTileReader(only_bad, N, TREE.root())
    with pytest.raises(TileVerificationError):
        vr.check_root()
    partial_good = {p: d for p, d in good.items() if p != "tile/0/000"}
    mixed = TwoSourceReader(bad, partial_good)
    vr = VerifiedTileReader(mixed, N, TREE.root())
    vr.check_root()
    with pytest.raises(TileVerificationError, match="does not match its parent"):
        vr.read_tile(0, 0, None)
    no_bundle = TwoSourceReader(bad, {p: d for p, d in good.items() if not p.startswith("tile/entries/000")})
    vr = VerifiedTileReader(no_bundle, N, TREE.root())
    with pytest.raises(TileVerificationError):
        vr.entry(0)
    with pytest.raises(TileMissingError):
        VerifiedTileReader(MemoryTileReader({}), N, TREE.root()).check_root()

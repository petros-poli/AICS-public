"""Tile path encoding, materialisation, and root/proof computation."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aics_tlog import MerkleTree, leaf_hash, verify_consistency, verify_inclusion
from aics_tlog.tiles import (
    FileSystemTileReader,
    MemoryTileReader,
    TileWriter,
    build_entry_bundle,
    consistency_proof_from_tiles,
    entry_bundle_path,
    inclusion_proof_from_tiles,
    materialise_tiles,
    parse_entry_bundle,
    parse_entry_bundle_path,
    parse_tile_path,
    tile_path,
    tree_root_from_tiles,
)

from conftest import flip_bit, make_leaves, ref_mth

SIZES = st.integers(min_value=1, max_value=600)


# --- path encoding ----------------------------------------------------------


def test_index_encoding_spec_example():
    # c2sp.org/tlog-tiles: index 1234067 encodes as x001/x234/067
    from aics_tlog.tiles import tile_index_path

    assert tile_index_path(1234067) == "x001/x234/067"
    assert tile_index_path(0) == "000"
    assert tile_index_path(67) == "067"
    assert tile_index_path(999) == "999"
    assert tile_index_path(1000) == "x001/000"
    assert tile_index_path(1234) == "x001/234"


def test_tile_path_round_trip():
    for level, index, width in [(0, 0, None), (63, 1234067, 255), (1, 273, 112), (8, 5, 1)]:
        p = tile_path(level, index, width)
        assert parse_tile_path(p) == (level, index, width)
    assert tile_path(0, 273, 112) == "tile/0/273.p/112"
    assert parse_tile_path("tile/0/273.p/112") == (0, 273, 112)
    assert parse_tile_path("tile/2/x001/x234/067.p/9") == (2, 1234067, 9)
    assert entry_bundle_path(1234067) == "tile/entries/x001/x234/067"
    assert parse_entry_bundle_path("tile/entries/x001/x234/067.p/12") == (1234067, 12)


@pytest.mark.parametrize(
    "bad",
    [
        "tile/64/000",
        "tile/0/000.p/0",
        "tile/0/000.p/256",
        "tile/0/000.p/007",
        "tile/007/000",
        "tile/0/x001",  # bad element
        "tile/0/01",  # not 3 digits
        "tile/0/0001/x002",  # last element 4 digits
        "bogus/0/000",
        "tile/0/000.p/",
    ],
)
def test_tile_path_rejects_malformed(bad):
    with pytest.raises(ValueError):
        parse_tile_path(bad)


# --- materialisation: spec examples ------------------------------------------


def test_spec_example_size_70000():
    tiles = materialise_tiles([b"x"] * 70000)
    merkle = {p for p in tiles if p.startswith("tile/") and not p.startswith("tile/entries")}
    full0 = [p for p in merkle if p.startswith("tile/0/") and ".p/" not in p]
    part0 = [p for p in merkle if p.startswith("tile/0/") and ".p/" in p]
    full1 = [p for p in merkle if p.startswith("tile/1/") and ".p/" not in p]
    part1 = [p for p in merkle if p.startswith("tile/1/") and ".p/" in p]
    part2 = [p for p in merkle if p.startswith("tile/2/") and ".p/" in p]
    # "a tree of size 70,000 will be represented by 273 full level 0 tiles,
    #  one partial level 0 tile of width 112, one full level 1 tile, one
    #  partial level 1 tile of width 17, and one partial level 2 tile of width 1"
    assert len(full0) == 273 and part0 == ["tile/0/273.p/112"]
    assert len(full1) == 1 and part1 == ["tile/1/001.p/17"]
    assert part2 == ["tile/2/000.p/1"]


def test_spec_example_size_256():
    tiles = materialise_tiles([b"x"] * 256)
    merkle = {p for p in tiles if p.startswith("tile/") and not p.startswith("tile/entries")}
    # "a tree of size 256 will be represented by a full level 0 tile and a
    #  partial level 1 tile of width 1"
    assert merkle == {"tile/0/000", "tile/1/000.p/1"}


def test_full_tile_is_8192_bytes_and_entries_prefixed():
    leaves = [f"e{i}".encode() for i in range(300)]
    tiles = materialise_tiles(leaves)
    assert len(tiles["tile/0/000"]) == 8192  # 256 * 32
    assert len(tiles["tile/0/001.p/44"]) == 44 * 32
    # leaf hashes of tile 0
    assert tiles["tile/0/000"] == b"".join(leaf_hash(e) for e in leaves[:256])
    # entry bundles: uint16 BE length prefixes
    entries = parse_entry_bundle(tiles["tile/entries/000"])
    assert entries == leaves[:256]
    raw = tiles["tile/entries/000"]
    assert raw[:2] == (len(leaves[0])).to_bytes(2, "big")
    assert build_entry_bundle([b""]) == b"\x00\x00"
    with pytest.raises(ValueError):
        build_entry_bundle([b"x" * 70000])
    with pytest.raises(ValueError):
        parse_entry_bundle(b"\x00\x05ab")


def test_no_empty_tiles_and_partials_not_hashed_up():
    for size in (1, 255, 256, 257, 512, 513, 70000):
        tiles = materialise_tiles(make_leaves(size))
        for p, data in tiles.items():
            if p.startswith("tile/entries"):
                continue
            assert len(data) > 0, p  # empty tiles are never served
        # highest level tile must be partial (or the tree is an exact power)
        levels = sorted({int(p.split("/")[1]) for p in tiles if p.startswith("tile/") and not p.startswith("tile/entries")})
        top = [p for p in tiles if p.startswith(f"tile/{levels[-1]}/")]
        assert all(".p/" in p for p in top) or size % 256 ** (levels[-1] + 1) == 0


# --- roots and proofs ---------------------------------------------------------


@given(size=SIZES)
@settings(max_examples=60, deadline=None)
def test_property_tile_root_equals_in_memory_root(size):
    leaves = make_leaves(size)
    t = MerkleTree(leaves)
    reader = TileWriter(leaves).to_memory_reader()
    assert tree_root_from_tiles(reader, size) == t.root(size) == ref_mth(leaves[:size])


def test_sweep_tile_roots_and_proofs_all_sizes_1_to_600():
    leaves = make_leaves(600)
    t = MerkleTree(leaves)
    reader = TileWriter(leaves).to_memory_reader()
    for n in range(1, 601):
        root = t.root(n)
        assert tree_root_from_tiles(reader, n, 600) == root, n
        for i in {0, n // 2, n - 1}:
            p = t.inclusion_proof(i, n)
            assert inclusion_proof_from_tiles(reader, i, n, 600) == p
            assert verify_inclusion(leaf_hash(leaves[i]), i, n, p, root)
        for old in {1, n // 3, n - 1} | ({1} if n == 1 else set()):
            if old < 1:
                continue
            old = min(old, n)
            pr = t.consistency_proof(old, n)
            assert consistency_proof_from_tiles(reader, old, n, 600) == pr
            assert verify_consistency(old, n, t.root(old), root, pr)


@given(size=SIZES, data=st.data())
@settings(max_examples=25, deadline=None)
def test_property_tile_tamper_detection(size, data):
    """Tampering any tile at the highest level must change (or break) the root."""
    leaves = make_leaves(size)
    tiles = TileWriter(leaves).materialise()
    reader = MemoryTileReader(tiles)
    root = tree_root_from_tiles(reader, size)
    i = data.draw(st.integers(min_value=0, max_value=size - 1))
    proof = inclusion_proof_from_tiles(reader, i, size)
    assert verify_inclusion(leaf_hash(leaves[i]), i, size, proof, root)

    # level-0 hashes flow into every proof: tampering one must change the proof
    # or make it fail; the highest-level tile feeds the root directly.
    merkle = [p for p in tiles if p.startswith("tile/") and not p.startswith("tile/entries")]
    top = max(parse_tile_path(p)[0] for p in merkle)
    # For a tree that is exactly 256**k leaves (a perfect tree), every node is
    # derivable from level-0 tiles alone and the top tile is redundant by
    # construction -- the verifier computes the root from level 0 and cannot
    # (and need not) notice tampering of the unused top tile.
    if size == 256**((size - 1).bit_length() // 8) and top >= 1:
        return
    victims = sorted(p for p in merkle if p.startswith(f"tile/{top}/"))
    victim = data.draw(st.sampled_from(victims))
    tampered = dict(tiles)
    tampered[victim] = flip_bit(tampered[victim], 9)
    try:
        bad_root = tree_root_from_tiles(MemoryTileReader(tampered), size)
        assert bad_root != root, f"tampered {victim} unnoticed for size {size}"
    except (ValueError, FileNotFoundError):
        pass  # corrupted tile length rejected outright


@given(size=st.integers(min_value=1, max_value=256), data=st.data())
@settings(max_examples=20, deadline=None)
def test_property_level0_tamper_changes_leaf_proofs(size, data):
    """For small trees everything is read from level-0 tiles, so any bit flip
    in any level-0 tile must change the computed root."""
    leaves = make_leaves(size)
    tiles = TileWriter(leaves).materialise()
    root = tree_root_from_tiles(MemoryTileReader(tiles), size)
    victims = sorted(p for p in tiles if p.startswith("tile/0/"))
    victim = data.draw(st.sampled_from(victims))
    tampered = dict(tiles)
    tampered[victim] = flip_bit(tampered[victim], 17)
    bad = tree_root_from_tiles(MemoryTileReader(tampered), size)
    assert bad != root


def test_proofs_against_newer_tile_set():
    # tiles materialised at 600, proofs requested for older sizes
    leaves = make_leaves(600)
    t = MerkleTree(leaves)
    reader = TileWriter(leaves).to_memory_reader()
    for n in (1, 2, 100, 255, 256, 257, 512, 513, 599):
        assert tree_root_from_tiles(reader, n, 600) == t.root(n)
        i = n - 1
        p = inclusion_proof_from_tiles(reader, i, n, 600)
        assert verify_inclusion(leaf_hash(leaves[i]), i, n, p, t.root(n))
        if n > 1:
            pr = consistency_proof_from_tiles(reader, 1, n, 600)
            assert verify_consistency(1, n, t.root(1), t.root(n), pr)


def test_missing_tile_raises(tmp_path):
    leaves = make_leaves(300)
    reader = TileWriter(leaves).to_memory_reader()
    empty = MemoryTileReader({})
    with pytest.raises(FileNotFoundError):
        tree_root_from_tiles(empty, 300)


def test_filesystem_tile_reader_round_trip(tmp_path):
    leaves = make_leaves(600)
    paths = TileWriter(leaves).write_to(tmp_path / "tiles")
    assert len(paths) > 5
    reader = FileSystemTileReader(tmp_path / "tiles")
    t = MerkleTree(leaves)
    assert tree_root_from_tiles(reader, 600) == t.root()
    p = inclusion_proof_from_tiles(reader, 123, 600)
    assert verify_inclusion(leaf_hash(leaves[123]), 123, 600, p, t.root())
    assert reader.read_tile(0, 0, None) is not None
    assert reader.read_tile(40, 0, None) is None
    assert reader.read_entry_bundle(0, None) is not None


def test_write_is_idempotent(tmp_path):
    leaves = make_leaves(300)
    w = TileWriter(leaves)
    a = w.write_to(tmp_path / "a")
    b = w.write_to(tmp_path / "a")
    assert a == b

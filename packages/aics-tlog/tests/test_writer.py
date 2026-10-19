"""Incremental tile writer: equal to a full rebuild at every size, never
rewrites a path, resumes from its own tiles, survives a crash mid-append."""

import os
import stat

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aics_tlog import MerkleTree, leaf_hash
from aics_tlog.hashing import EMPTY_HASH
from aics_tlog.tiles import (
    FileSystemTileReader,
    TileConflictError,
    TileMissingError,
    entry_bundle_path,
    inclusion_proof_from_tiles,
    materialise_tiles,
    parse_entry_bundle,
    parse_entry_bundle_path,
    parse_tile_path,
    tile_path,
    tile_width_at,
    tree_root_from_tiles,
    write_new_file,
)
from aics_tlog.tree import verify_inclusion
from aics_tlog.verified import audit_tiles
from aics_tlog.writer import DirectoryTileStore, IncrementalTileWriter, MemoryTileStore

from conftest import make_leaves, ref_mth


class RecordingStore(MemoryTileStore):
    """Records every write attempt: path -> list of (bytes, created)."""

    def __init__(self):
        super().__init__()
        self.attempts: dict[str, list[tuple[bytes, bool]]] = {}

    def write(self, path, data):
        created = super().write(path, data)
        self.attempts.setdefault(path, []).append((bytes(data), created))
        return created


class CrashingStore(MemoryTileStore):
    """Fails with OSError on the n-th write attempt (simulated crash)."""

    def __init__(self, tiles, crash_after):
        super().__init__(tiles)
        self.remaining = crash_after

    def write(self, path, data):
        if self.remaining == 0:
            raise OSError("simulated crash")
        self.remaining -= 1
        return super().write(path, data)


def _resource(path):
    """(kind, level, index, width) of a tile or entry-bundle path."""
    if path.startswith("tile/entries/"):
        index, width = parse_entry_bundle_path(path)
        return "entries", 0, index, width
    level, index, width = parse_tile_path(path)
    return "tile", level, index, width


def assert_store_matches(tiles, leaves, prune):
    """The store serves exactly the rebuilt tree, plus older partials of the
    right edge (and, without pruning, partials of tiles now full)."""
    size = len(leaves)
    expected = materialise_tiles(leaves)
    for path, data in expected.items():
        assert tiles.get(path) == data, f"{path} differs from the full rebuild at size {size}"
    for path in set(tiles) - set(expected):
        kind, level, index, width = _resource(path)
        assert width is not None, f"unexpected full resource {path}"
        current = tile_width_at(size, level, index)
        assert current != -1, f"{path} lies beyond the tree"
        if prune:
            assert current is not None, f"{path} survived although its tile is full"
        assert current is None or width < current
        if kind == "tile":
            ref = expected[tile_path(level, index, current)]
            assert tiles[path] == ref[: width * 32], f"{path} is not a prefix of its tile"
        else:
            assert parse_entry_bundle(tiles[path]) == leaves[index * 256 : index * 256 + width]


def assert_sizes_servable(tiles, sizes):
    """Every size a checkpoint could have been produced for stays servable:
    each right-edge partial exists, or its full tile does (tlog-tiles)."""
    for s in sizes:
        level = 0
        while s // 256**level:
            w = (s // 256**level) % 256
            n = s // 256 ** (level + 1)
            if w:
                assert tile_path(level, n, w) in tiles or tile_path(level, n) in tiles, (s, level, n, w)
            level += 1
        if s % 256:
            n = s // 256
            assert entry_bundle_path(n, s % 256) in tiles or entry_bundle_path(n) in tiles, s


BATCHES = st.lists(st.integers(min_value=1, max_value=300), min_size=1, max_size=10)


@given(batches=BATCHES, prune=st.booleans(), resume=st.lists(st.booleans(), min_size=10, max_size=10))
@settings(max_examples=60, deadline=None)
def test_property_incremental_equals_full_rebuild(batches, prune, resume):
    leaves = make_leaves(sum(batches))
    store = RecordingStore()
    writer = IncrementalTileWriter(store, prune_partials=prune)
    size = 0
    visited = []
    for i, b in enumerate(batches):
        if resume[i]:
            writer = IncrementalTileWriter(store, size, prune_partials=prune)  # restart from disk
            assert writer.size == size and writer.root() == ref_mth(leaves[:size])
        result = writer.append(leaves[size : size + b])
        size += b
        visited.append(size)
        assert result.old_size == size - b and result.size == size == writer.size
        assert result.root == writer.root() == ref_mth(leaves[:size])
        assert tree_root_from_tiles(store, size) == result.root
        assert_store_matches(store.tiles, leaves[:size], prune)
    assert_sizes_servable(store.tiles, visited)
    # Never rewrites: every attempt on a path carried the same bytes, and no
    # path was created twice.
    for path, attempts in store.attempts.items():
        assert len({data for data, _ in attempts}) == 1, path
        assert sum(created for _, created in attempts) == 1, path


def test_level_two_boundaries_and_resume():
    leaves = make_leaves(70000)
    store = MemoryTileStore()
    writer = IncrementalTileWriter(store)
    size = 0
    for b in (65535, 1, 1, 254, 1, 4208):
        writer.append(leaves[size : size + b])
        size += b
        assert writer.root() == MerkleTree(leaves[:size]).root()
        assert_store_matches(store.tiles, leaves[:size], prune=True)
    assert size == 70000
    assert "tile/2/000.p/1" in store.tiles and "tile/1/001.p/17" in store.tiles
    resumed = IncrementalTileWriter(store, 70000)
    assert resumed.root() == writer.root()
    audit_tiles(store, 70000, writer.root())


def test_single_leaf_appends_match_rebuild_up_to_600():
    leaves = make_leaves(600)
    store = MemoryTileStore()
    writer = IncrementalTileWriter(store)
    tree = MerkleTree()
    for i, leaf in enumerate(leaves, 1):
        writer.append([leaf])
        tree.append(leaf)
        assert writer.root() == tree.root()
        if i in (1, 255, 256, 257, 511, 512, 513, 600):
            assert_store_matches(store.tiles, leaves[:i], prune=True)
    assert_sizes_servable(store.tiles, range(1, 601))


def test_empty_append_and_empty_tree():
    store = MemoryTileStore()
    writer = IncrementalTileWriter(store)
    assert writer.size == 0 and writer.root() == EMPTY_HASH
    result = writer.append([])
    assert result.size == 0 and result.written == () and store.tiles == {}


def test_oversized_entry_rejected_before_any_write():
    store = MemoryTileStore()
    writer = IncrementalTileWriter(store)
    with pytest.raises(ValueError):
        writer.append([b"ok", b"x" * 70000])
    assert store.tiles == {} and writer.size == 0


def test_prune_reports_deleted_partials():
    store = MemoryTileStore()
    writer = IncrementalTileWriter(store)
    leaves = make_leaves(300)
    writer.append(leaves[:100])
    writer.append(leaves[100:200])
    assert {"tile/0/000.p/100", "tile/0/000.p/200"} <= set(store.tiles)
    result = writer.append(leaves[200:300])
    assert "tile/0/000.p/100" in result.pruned and "tile/entries/000.p/200" in result.pruned
    assert not any(p.startswith("tile/0/000.p/") for p in store.tiles)
    assert "tile/0/000" in result.written and "tile/0/001.p/44" in result.written

    keep = MemoryTileStore()
    w2 = IncrementalTileWriter(keep, prune_partials=False)
    w2.append(leaves[:100])
    w2.append(leaves[100:300])
    assert "tile/0/000.p/100" in keep.tiles and "tile/0/000" in keep.tiles


@given(
    batches=st.lists(st.integers(min_value=1, max_value=300), min_size=2, max_size=6),
    data=st.data(),
)
@settings(max_examples=40, deadline=None)
def test_property_crash_mid_append_then_resume(batches, data):
    """A crash part-way through an append leaves a store the writer resumes
    from at the last published size; replaying the append converges to the
    full rebuild without conflicts."""
    leaves = make_leaves(sum(batches))
    store = MemoryTileStore()
    writer = IncrementalTileWriter(store)
    size = 0
    for b in batches[:-1]:
        writer.append(leaves[size : size + b])
        size += b
    published = size
    crash_after = data.draw(st.integers(min_value=0, max_value=12))
    crashing = CrashingStore(store.tiles, crash_after)
    try:
        IncrementalTileWriter(crashing, published).append(leaves[published:])
    except OSError:
        pass
    store = MemoryTileStore(crashing.tiles)
    resumed = IncrementalTileWriter(store, published)
    assert resumed.root() == ref_mth(leaves[:published])
    resumed.append(leaves[published:])
    assert resumed.root() == ref_mth(leaves)
    assert_store_matches(store.tiles, leaves, prune=True)


def test_failed_write_leaves_state_unchanged_and_retry_works():
    leaves = make_leaves(300)
    store = CrashingStore({}, crash_after=1)
    writer = IncrementalTileWriter(store)
    with pytest.raises(OSError):
        writer.append(leaves)
    assert writer.size == 0
    store.remaining = 10**6
    writer.append(leaves)
    assert writer.root() == ref_mth(leaves)


def test_refuses_to_rewrite_a_full_tile():
    leaves = make_leaves(300)
    store = MemoryTileStore()
    IncrementalTileWriter(store).append(leaves[:250])
    IncrementalTileWriter(store, 250).append(leaves[250:260])  # completes tile 0
    full = store.tiles["tile/0/000"]
    forked = [b"forged-" + leaf for leaf in leaves[250:260]]
    with pytest.raises(TileConflictError):
        IncrementalTileWriter(store, 250).append(forked)
    assert store.tiles["tile/0/000"] == full


def test_resume_errors():
    leaves = make_leaves(300)
    store = MemoryTileStore()
    IncrementalTileWriter(store).append(leaves)
    broken = dict(store.tiles)
    del broken["tile/0/001.p/44"]
    with pytest.raises(TileMissingError):
        IncrementalTileWriter(MemoryTileStore(broken), 300)
    bad = dict(store.tiles)
    bad["tile/entries/001.p/44"] = bad["tile/entries/001.p/44"][:-1] + b"!"
    with pytest.raises(ValueError):
        IncrementalTileWriter(MemoryTileStore(bad), 300)
    with pytest.raises(ValueError):
        IncrementalTileWriter(store, -1)


def test_memory_store_rejects_bad_paths():
    store = MemoryTileStore()
    for bad in ("../etc/passwd", "tile/0/../../x", "checkpoint", "tile/64/000"):
        with pytest.raises(ValueError):
            store.write(bad, b"x")


# --- directory store ---------------------------------------------------------


def test_directory_store_end_to_end(tmp_path):
    leaves = make_leaves(1000)
    store = DirectoryTileStore(tmp_path / "tiles")
    writer = IncrementalTileWriter(store)
    size = 0
    for b in (1, 300, 255, 444):
        writer.append(leaves[size : size + b])
        size += b
        store.write_checkpoint(f"size {size}\n".encode())
    assert size == 1000
    # A fresh process resumes from the directory alone.
    again = IncrementalTileWriter(DirectoryTileStore(tmp_path / "tiles"), 1000)
    assert again.root() == MerkleTree(leaves).root()
    reader = FileSystemTileReader(tmp_path / "tiles")
    assert tree_root_from_tiles(reader, 1000) == again.root()
    proof = inclusion_proof_from_tiles(reader, 777, 1000)
    assert verify_inclusion(leaf_hash(leaves[777]), 777, 1000, proof, again.root())
    audit_tiles(reader, 1000, again.root())
    assert store.read_checkpoint() == b"size 1000\n"
    # identical to a full rebuild, file for file
    for path, data in materialise_tiles(leaves).items():
        assert (tmp_path / "tiles" / path).read_bytes() == data
    # no temporary files left behind, public permissions
    for root, _, files in os.walk(tmp_path / "tiles"):
        for name in files:
            assert not name.endswith(".tmp"), name
            mode = stat.S_IMODE(os.stat(os.path.join(root, name)).st_mode)
            assert mode & 0o044 == 0o044, (name, oct(mode))


def test_write_new_file_never_replaces(tmp_path):
    assert write_new_file(tmp_path, "tile/0/000", b"a" * 32) is True
    assert write_new_file(tmp_path, "tile/0/000", b"a" * 32) is False
    with pytest.raises(TileConflictError):
        write_new_file(tmp_path, "tile/0/000", b"b" * 32)
    assert (tmp_path / "tile/0/000").read_bytes() == b"a" * 32


def test_directory_store_delete_partials_only_touches_partials(tmp_path):
    store = DirectoryTileStore(tmp_path, fsync=False)
    store.write("tile/0/000.p/5", b"x" * 160)
    store.write("tile/0/000.p/6", b"x" * 192)
    (tmp_path / "tile/0/000.p/README").write_text("not a tile")
    store.write("tile/0/000", b"y" * 8192)
    gone = store.delete_partials("tile/0/000")
    assert gone == ["tile/0/000.p/5", "tile/0/000.p/6"]
    assert (tmp_path / "tile/0/000.p/README").exists()
    assert (tmp_path / "tile/0/000").read_bytes() == b"y" * 8192
    assert store.delete_partials("tile/0/999") == []
    with pytest.raises(ValueError):
        store.write("../outside", b"x")


def test_write_new_file_without_hard_links(tmp_path, monkeypatch):
    """Filesystems without hard links (exFAT, some network mounts) fall back
    to rename after a check; the never-replace rule still holds."""

    def no_link(src, dst):
        raise PermissionError("hard links not supported")

    monkeypatch.setattr(os, "link", no_link)
    assert write_new_file(tmp_path, "tile/0/000", b"a" * 32) is True
    assert write_new_file(tmp_path, "tile/0/000", b"a" * 32) is False
    with pytest.raises(TileConflictError):
        write_new_file(tmp_path, "tile/0/000", b"b" * 32)
    assert (tmp_path / "tile/0/000").read_bytes() == b"a" * 32
    assert [p.name for p in (tmp_path / "tile/0").iterdir()] == ["000"]  # no temp files left

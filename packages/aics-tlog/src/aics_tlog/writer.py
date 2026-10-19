"""Incremental, append-only tile writer (c2sp.org/tlog-tiles).

:class:`IncrementalTileWriter` keeps only the right edge of the tree in
memory (at most 255 hashes per level plus the entries of the partial entry
bundle).  Appending a batch writes:

* the full tiles and full entry bundles completed by the batch, each exactly
  once, at paths that are never written again;
* the right-edge partial tiles and the partial entry bundle for the new tree
  size, each at a new ``.p/<W>`` path.

No existing path is ever replaced: a store refuses to write different bytes
to a path that exists (:class:`~aics_tlog.tiles.TileConflictError`), so a
log cannot be silently rewritten through its tiles.  Writing identical bytes
again is a no-op, which makes a repeated append after a crash safe.

Partial tiles of a tile that has become full are deleted once the full tile
is written (``prune_partials``); c2sp.org/tlog-tiles allows this and clients
fall back to the full tile.  Partial tiles of the current right edge are
kept, because every tree size a checkpoint was produced for must stay
servable until its tiles are full.

The writer is not thread safe.  One process owns a tile store.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .hashing import EMPTY_HASH, leaf_hash
from .tiles import (
    FULL_TILE_BYTES,
    HASH_SIZE,
    MAX_ENTRY_BYTES,
    TILE_ENTRIES,
    FileSystemTileReader,
    MemoryTileReader,
    TileConflictError,
    TileMissingError,
    _fold_full_tile,
    _frontier_root,
    _fsync_dir,
    _read_file,
    _split_hashes,
    build_entry_bundle,
    entry_bundle_path,
    parse_entry_bundle,
    parse_entry_bundle_path,
    parse_tile_path,
    tile_path,
    write_new_file,
)

__all__ = [
    "AppendResult",
    "DirectoryTileStore",
    "IncrementalTileWriter",
    "MemoryTileStore",
    "TileStore",
]


def _check_resource_path(path: str) -> None:
    """Only tile and entry-bundle paths may be written or pruned."""
    if path.startswith("tile/entries/"):
        parse_entry_bundle_path(path)
    else:
        parse_tile_path(path)


class TileStore(Protocol):
    """Storage a writer appends to.  Stores are also TileReaders."""

    def read(self, path: str) -> bytes | None: ...

    def write(self, path: str, data: bytes) -> bool:
        """Create ``path``; False if it already held ``data``; raise
        TileConflictError if it holds different bytes."""
        ...

    def delete_partials(self, path: str) -> list[str]:
        """Delete every ``<path>.p/<W>`` partial resource; return their paths."""
        ...

    def read_tile(self, level: int, index: int, width: int | None) -> bytes | None: ...

    def read_entry_bundle(self, index: int, width: int | None) -> bytes | None: ...


class MemoryTileStore(MemoryTileReader):
    """Dict-backed store, mostly for tests and in-process mirrors."""

    def read(self, path: str) -> bytes | None:
        return self.tiles.get(path)

    def write(self, path: str, data: bytes) -> bool:
        _check_resource_path(path)
        data = bytes(data)
        old = self.tiles.get(path)
        if old is not None:
            if old == data:
                return False
            raise TileConflictError(f"{path}: already exists with different content")
        self.tiles[path] = data
        return True

    def delete_partials(self, path: str) -> list[str]:
        _check_resource_path(path)
        prefix = path + ".p/"
        gone = sorted(p for p in self.tiles if p.startswith(prefix))
        for p in gone:
            del self.tiles[p]
        return gone


class DirectoryTileStore(FileSystemTileReader):
    """Store writing tiles under a directory that a static web server (or a
    mirror sync) publishes as the tlog-tiles URL prefix.

    Every write is atomic and never replaces an existing file
    (:func:`~aics_tlog.tiles.write_new_file`); with ``fsync`` (default) the
    file and its directory are flushed before the write returns.  The only
    mutable resource is ``checkpoint``, replaced atomically by
    :meth:`write_checkpoint`.
    """

    def __init__(self, root: str | Path, *, fsync: bool = True) -> None:
        super().__init__(root)
        self.fsync = fsync

    def read(self, path: str) -> bytes | None:
        _check_resource_path(path)
        return self._read(path)

    def write(self, path: str, data: bytes) -> bool:
        _check_resource_path(path)
        return write_new_file(self.root, path, bytes(data), fsync=self.fsync)

    def delete_partials(self, path: str) -> list[str]:
        _check_resource_path(path)
        pdir = self.root / (path + ".p")
        try:
            names = sorted(os.listdir(pdir))
        except (FileNotFoundError, NotADirectoryError):
            return []
        gone: list[str] = []
        for name in names:
            is_width = name.isdigit() and str(int(name)) == name and 1 <= int(name) < TILE_ENTRIES
            is_temp = name.startswith(".") and name.endswith(".tmp")
            if not (is_width or is_temp):
                continue  # not ours; leave it alone
            try:
                (pdir / name).unlink()
            except FileNotFoundError:
                continue
            if is_width:
                gone.append(f"{path}.p/{name}")
        try:
            pdir.rmdir()
        except OSError:
            pass  # not empty, or already gone
        if self.fsync and gone:
            _fsync_dir(pdir.parent)
        return gone

    def write_checkpoint(self, data: bytes) -> None:
        """Atomically replace ``<root>/checkpoint`` (the mutable resource)."""
        self.root.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".checkpoint.", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as fh:
                os.fchmod(fh.fileno(), 0o644)
                fh.write(bytes(data))
                fh.flush()
                if self.fsync:
                    os.fsync(fh.fileno())
            os.replace(tmp, self.root / "checkpoint")
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        if self.fsync:
            _fsync_dir(self.root)

    def read_checkpoint(self) -> bytes | None:
        return _read_file(self.root / "checkpoint")


@dataclass(frozen=True)
class AppendResult:
    old_size: int
    size: int
    root: bytes
    written: tuple[str, ...]  # paths created by this append (identical rewrites excluded)
    pruned: tuple[str, ...]  # partial paths deleted because their tile is now full


class IncrementalTileWriter:
    """Append-only tile writer that touches only the right edge.

    ``IncrementalTileWriter(store)`` starts an empty tree.
    ``IncrementalTileWriter(store, size)`` resumes a tree whose tiles for
    ``size`` leaves are already in ``store`` (for example after a restart,
    with ``size`` taken from the last published checkpoint); it reads the
    right-edge partial tiles for that size, falling back to the full tile
    when a partial was pruned.

    After each :meth:`append`, :meth:`root` is the RFC 9162 root of the
    tree, computed from the right edge alone.  On resume, compare
    :meth:`root` with the source of truth (the committed leaf table) before
    appending, and run :func:`~aics_tlog.verified.audit_tiles` for a check
    of every tile; the writer trusts the right edge it reads back.
    """

    def __init__(self, store: TileStore, size: int = 0, *, prune_partials: bool = True) -> None:
        if size < 0:
            raise ValueError("size must be non-negative")
        self.store = store
        self.prune_partials = prune_partials
        self._size = 0
        self._edge: list[list[bytes]] = []
        self._bundle: list[bytes] = []
        if size:
            self._load(size)

    # -- state --------------------------------------------------------------

    @property
    def size(self) -> int:
        return self._size

    def root(self) -> bytes:
        """Merkle Tree Hash of the current tree."""
        if self._size == 0:
            return EMPTY_HASH
        return _frontier_root(self._edge)

    def _load(self, size: int) -> None:
        store = self.store
        edge: list[list[bytes]] = []
        level = 0
        while size // TILE_ENTRIES**level:
            width = (size // TILE_ENTRIES**level) % TILE_ENTRIES
            index = size // TILE_ENTRIES ** (level + 1)
            if width:
                data = store.read_tile(level, index, width)
                if data is None:
                    full = store.read_tile(level, index, None)
                    if full is not None and len(full) == FULL_TILE_BYTES:
                        data = full[: width * HASH_SIZE]
                if data is None:
                    raise TileMissingError(
                        f"cannot resume at size {size}: {tile_path(level, index, width)} is missing"
                    )
                if len(data) != width * HASH_SIZE:
                    raise ValueError(f"cannot resume at size {size}: {tile_path(level, index, width)} has the wrong length")
                edge.append(_split_hashes(data))
            else:
                edge.append([])
            level += 1
        entries: list[bytes] = []
        width = size % TILE_ENTRIES
        if width:
            index = size // TILE_ENTRIES
            raw = store.read_entry_bundle(index, width)
            if raw is None:
                raw = store.read_entry_bundle(index, None)
            if raw is None:
                raise TileMissingError(
                    f"cannot resume at size {size}: {entry_bundle_path(index, width)} is missing"
                )
            parsed = parse_entry_bundle(raw)
            if len(parsed) < width:
                raise ValueError(f"cannot resume at size {size}: entry bundle {index} is short")
            entries = parsed[:width]
            if [leaf_hash(e) for e in entries] != edge[0]:
                raise ValueError(f"cannot resume at size {size}: entry bundle {index} does not match its level 0 tile")
        self._edge, self._bundle, self._size = edge, entries, size

    # -- appending ------------------------------------------------------------

    def append(self, entries: Iterable[bytes]) -> AppendResult:
        """Append ``entries`` (raw leaf data, in order) and write the tiles.

        The in-memory state advances only after every write succeeded; if a
        write fails, the same append can be retried (identical writes are
        no-ops) or the writer re-opened at the last published size.
        """
        batch = [bytes(e) for e in entries]
        for e in batch:
            if len(e) > MAX_ENTRY_BYTES:
                raise ValueError(f"entry of {len(e)} bytes exceeds the {MAX_ENTRY_BYTES}-byte bundle limit")
        old_size = self._size
        if not batch:
            return AppendResult(old_size, old_size, self.root(), (), ())

        edge = [list(level) for level in self._edge]
        bundle = list(self._bundle)
        size = old_size
        writes: list[tuple[str, bytes]] = []
        became_full: list[str] = []

        for entry in batch:
            size += 1
            bundle.append(entry)
            if len(bundle) == TILE_ENTRIES:
                path = entry_bundle_path(size // TILE_ENTRIES - 1)
                writes.append((path, build_entry_bundle(bundle)))
                became_full.append(path)
                bundle = []
            carry = leaf_hash(entry)
            level = 0
            while True:
                if level == len(edge):
                    edge.append([])
                edge[level].append(carry)
                if len(edge[level]) < TILE_ENTRIES:
                    break
                # Tile `level` is complete: write it once, hash it into the level above.
                path = tile_path(level, size // TILE_ENTRIES ** (level + 1) - 1)
                writes.append((path, b"".join(edge[level])))
                became_full.append(path)
                carry = _fold_full_tile(edge[level])
                edge[level] = []
                level += 1

        # Right-edge partial resources for the new size (no-ops when unchanged).
        for level, hashes in enumerate(edge):
            if hashes:
                index = size // TILE_ENTRIES ** (level + 1)
                writes.append((tile_path(level, index, len(hashes)), b"".join(hashes)))
        if bundle:
            writes.append((entry_bundle_path(size // TILE_ENTRIES, len(bundle)), build_entry_bundle(bundle)))

        written = [path for path, data in writes if self.store.write(path, data)]
        self._edge, self._bundle, self._size = edge, bundle, size

        pruned: list[str] = []
        if self.prune_partials:
            for path in became_full:
                try:
                    pruned.extend(self.store.delete_partials(path))
                except OSError:
                    pass  # leftover partials are harmless; the full tile is in place
        return AppendResult(old_size, size, self.root(), tuple(written), tuple(pruned))

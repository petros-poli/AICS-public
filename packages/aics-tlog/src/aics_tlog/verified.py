"""Tiles authenticated against a trusted tree head.

:class:`VerifiedTileReader` wraps any :class:`~aics_tlog.tiles.TileReader`
(a mirror, a cache, a directory) and serves a tree of ``size`` leaves with
root ``root`` -- normally taken from a checkpoint verified with an
out-of-band key.  It returns a tile only after proving it belongs to that
tree, the same way Go's ``tlog.TileHashReader`` does:

* the right-edge partial tiles (one per level) are proven together by
  recomputing the root from them;
* a full tile is proven by hashing it and comparing with the entry for it in
  its parent tile, which is itself proven (up to the right edge);
* an entry bundle is proven by hashing every entry and comparing with its
  proven level 0 tile.

Every hash a proof is computed from is therefore already proven to be in the
tree, and a wrong tile is reported where it is found rather than as a proof
that fails later.  When the inner reader supports it, a resource that fails
is rejected (``reject_tile``/``reject_entry_bundle``) and fetched again from
the next source; resources that pass are handed to ``save_tile`` /
``save_entry_bundle`` so a cache only ever stores proven data.

Because it implements the TileReader protocol, the proof functions in
:mod:`aics_tlog.tiles` work on top of it unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass

from .hashing import EMPTY_HASH, leaf_hash
from .tiles import (
    FULL_TILE_BYTES,
    HASH_SIZE,
    TILE_ENTRIES,
    TileMissingError,
    TileReader,
    TileVerificationError,
    _check_level,
    _check_width,
    _fold_full_tile,
    _frontier_root,
    _split_hashes,
    build_entry_bundle,
    entry_bundle_path,
    parse_entry_bundle,
    tile_path,
    tile_width_at,
)

__all__ = ["AuditReport", "VerifiedTileReader", "audit_tiles"]


class VerifiedTileReader:
    """A TileReader that only returns tiles proven to belong to the tree of
    ``size`` leaves with root ``root``.

    Reads describe that tree: a tile beyond it, or a width it does not have,
    reads as None; a narrower partial width returns the proven prefix.
    Raises :class:`~aics_tlog.tiles.TileMissingError` when a needed resource
    is unavailable and :class:`~aics_tlog.tiles.TileVerificationError` when
    no source serves a resource that authenticates.

    ``tile_size`` (>= ``size``) is the size of a newer verified checkpoint
    the source has published tiles for.  The right edge of ``size`` is then
    also read from that size's wider partial tiles, which helps when the
    source no longer keeps the older partials.  Without it the right edge is
    read at ``size``'s own widths, with the full tile as the fallback
    (c2sp.org/tlog-tiles).
    """

    def __init__(
        self,
        reader: TileReader,
        size: int,
        root: bytes,
        *,
        tile_size: int | None = None,
        max_attempts: int = 8,
    ) -> None:
        if size < 0:
            raise ValueError("size must be non-negative")
        if tile_size is not None and tile_size < size:
            raise ValueError("tile_size must be >= size")
        if len(root) != HASH_SIZE:
            raise ValueError("root must be 32 bytes")
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self.reader = reader
        self.size = size
        self.root = bytes(root)
        self.tile_size = tile_size
        self.max_attempts = max_attempts
        self._tiles: dict[tuple[int, int], bytes] = {}
        self._entries: dict[int, list[bytes]] = {}
        self._edge_done = False
        if size == 0 and self.root != EMPTY_HASH:
            raise TileVerificationError("a tree of size 0 must have the empty-tree root")

    # -- geometry ---------------------------------------------------------------

    def _count(self, level: int, index: int) -> int | None:
        """Entries in tile (level, index) of this tree: 256 for a full tile,
        1..255 for the right-edge partial, None if the tile does not exist."""
        span = TILE_ENTRIES**level
        full = self.size // (span * TILE_ENTRIES)
        if index < full:
            return TILE_ENTRIES
        if index == full:
            return (self.size // span) % TILE_ENTRIES or None
        return None

    def _edge_spec(self) -> list[tuple[int, int, int]]:
        spec: list[tuple[int, int, int]] = []
        level = 0
        while self.size // TILE_ENTRIES**level:
            width = (self.size // TILE_ENTRIES**level) % TILE_ENTRIES
            if width:
                spec.append((level, self.size // TILE_ENTRIES ** (level + 1), width))
            level += 1
        return spec

    # -- TileReader protocol -------------------------------------------------

    def read_tile(self, level: int, index: int, width: int | None) -> bytes | None:
        _check_level(level)
        _check_width(width)
        count = self._count(level, index)
        if count is None:
            return None
        want = TILE_ENTRIES if width is None else width
        if want > count:
            return None
        return self._tile(level, index, count)[: want * HASH_SIZE]

    def read_entry_bundle(self, index: int, width: int | None) -> bytes | None:
        _check_width(width)
        count = self._count(0, index)
        if count is None:
            return None
        want = TILE_ENTRIES if width is None else width
        if want > count:
            return None
        return build_entry_bundle(self._bundle(index, count)[:want])

    # -- convenience ----------------------------------------------------------

    def check_root(self) -> None:
        """Prove the right-edge tiles reproduce the root (no-op for size 0).

        Confirms that the reader serves the tree the trusted head commits to.
        """
        if self.size:
            self._authenticate_edge()


    def entry(self, index: int) -> bytes:
        """Proven raw entry ``index`` of this tree."""
        if not 0 <= index < self.size:
            raise ValueError(f"entry index {index} out of range for size {self.size}")
        bundle = index // TILE_ENTRIES
        count = self._count(0, bundle)
        assert count is not None
        return self._bundle(bundle, count)[index % TILE_ENTRIES]

    def leaf_hash(self, index: int) -> bytes:
        """Proven leaf hash ``index`` of this tree."""
        if not 0 <= index < self.size:
            raise ValueError(f"leaf index {index} out of range for size {self.size}")
        tile = index // TILE_ENTRIES
        count = self._count(0, tile)
        assert count is not None
        pos = index % TILE_ENTRIES
        return self._tile(0, tile, count)[pos * HASH_SIZE : (pos + 1) * HASH_SIZE]

    # -- authentication -------------------------------------------------------

    def _save(self, method: str, *args) -> None:
        fn = getattr(self.reader, method, None)
        if fn is not None:
            fn(*args)

    def _reject(self, method: str, *args) -> bool:
        fn = getattr(self.reader, method, None)
        return bool(fn(*args)) if fn is not None else False

    def _tile(self, level: int, index: int, count: int) -> bytes:
        key = (level, index)
        cached = self._tiles.get(key)
        if cached is not None:
            return cached
        if count < TILE_ENTRIES:
            self._authenticate_edge()
            return self._tiles[key]
        parent_count = self._count(level + 1, index // TILE_ENTRIES)
        if parent_count is None:  # cannot happen for a full tile; keep the invariant explicit
            raise TileVerificationError(f"internal error: no parent for {tile_path(level, index)}")
        parent = self._tile(level + 1, index // TILE_ENTRIES, parent_count)
        pos = index % TILE_ENTRIES
        expected = parent[pos * HASH_SIZE : (pos + 1) * HASH_SIZE]
        rejected = False
        for _ in range(self.max_attempts):
            data = self.reader.read_tile(level, index, None)
            if data is None:
                break
            if len(data) == FULL_TILE_BYTES and _fold_full_tile(_split_hashes(data)) == expected:
                self._tiles[key] = data
                self._save("save_tile", level, index, None, data)
                return data
            rejected = True
            if not self._reject("reject_tile", level, index, None):
                break
        if not rejected:
            raise TileMissingError(f"{tile_path(level, index)} is not available")
        raise TileVerificationError(
            f"{tile_path(level, index)} does not match its parent tile in the tree of size {self.size}"
        )

    def _authenticate_edge(self) -> None:
        if self._edge_done:
            return
        spec = self._edge_spec()
        top = spec[-1][0] if spec else 0
        failed = False
        for _ in range(self.max_attempts):
            got: dict[tuple[int, int], bytes] = {}
            served: dict[tuple[int, int], int | None] = {}
            for level, index, width in spec:
                data: bytes | None = None
                used: int | None = None
                for candidate in self._widths(level, index, width):
                    found = self.reader.read_tile(level, index, candidate)
                    if found is not None:
                        data, used = found[: width * HASH_SIZE], candidate
                        break
                if data is None:
                    if failed:
                        raise TileVerificationError(
                            f"the right-edge tiles do not match the root of the tree of size {self.size} "
                            f"at any source ({tile_path(level, index, width)} has no other copy)"
                        )
                    raise TileMissingError(
                        f"{tile_path(level, index, width)} is not available (nor the full tile)"
                    )
                got[(level, index)] = data
                served[(level, index)] = used
            edge: list[list[bytes]] = [[] for _ in range(top + 1)]
            shape_ok = True
            for level, index, width in spec:
                data = got[(level, index)]
                if len(data) != width * HASH_SIZE:
                    shape_ok = False
                edge[level] = _split_hashes(data)
            if shape_ok and _frontier_root(edge) == self.root:
                for level, index, width in spec:
                    data = got[(level, index)]
                    self._tiles[(level, index)] = data
                    # Save as the partial: if a full tile was truncated, only
                    # its first `width` entries are proven.
                    self._save("save_tile", level, index, width, data)
                self._edge_done = True
                return
            failed = True
            retry = False
            for (level, index), used in served.items():
                if self._reject("reject_tile", level, index, used):
                    retry = True
            if not retry:
                break
        raise TileVerificationError(f"the right-edge tiles do not match the root of the tree of size {self.size}")

    def _widths(self, level: int, index: int, width: int) -> list[int | None]:
        """Widths to try for a right-edge resource of ``width`` entries:
        its own, the wider one at ``tile_size``, then the full resource."""
        out: list[int | None] = [width]
        if self.tile_size is not None:
            wider = tile_width_at(self.tile_size, level, index)
            if wider is not None and wider != -1 and wider > width:
                out.append(wider)
        out.append(None)
        return out

    def _bundle(self, index: int, count: int) -> list[bytes]:
        cached = self._entries.get(index)
        if cached is not None:
            return cached
        hashes = _split_hashes(self._tile(0, index, count))
        width = None if count == TILE_ENTRIES else count
        candidates = [None] if width is None else self._widths(0, index, width)
        rejected = False
        for _ in range(self.max_attempts):
            raw: bytes | None = None
            used: int | None = None
            for candidate in candidates:
                raw = self.reader.read_entry_bundle(index, candidate)
                if raw is not None:
                    used = candidate
                    break
            if raw is None:
                break
            try:
                entries = parse_entry_bundle(raw)
            except ValueError:
                entries = []
            expected_len = TILE_ENTRIES if used is None else used
            if len(entries) == expected_len:
                entries = entries[:count]
                if all(leaf_hash(e) == h for e, h in zip(entries, hashes, strict=True)):
                    self._entries[index] = entries
                    self._save("save_entry_bundle", index, width, build_entry_bundle(entries))
                    return entries
            rejected = True
            if not self._reject("reject_entry_bundle", index, used):
                break
        if not rejected:
            raise TileMissingError(f"{entry_bundle_path(index, width)} is not available")
        raise TileVerificationError(
            f"{entry_bundle_path(index, width)} does not match its level 0 tile in the tree of size {self.size}"
        )


@dataclass(frozen=True)
class AuditReport:
    size: int
    tiles: int
    bundles: int


def audit_tiles(reader: TileReader, size: int, root: bytes, *, entries: bool = True) -> AuditReport:
    """Authenticate every tile (and, with ``entries``, every entry bundle) of
    the tree of ``size`` leaves against ``root``.

    A root computed from tiles depends only on the right edge; this walks the
    whole tree, so a damaged or substituted full tile anywhere is found.  It
    is the check a writer runs on boot against the root of its leaf table.
    Raises TileMissingError or TileVerificationError on the first failure.
    """
    vr = VerifiedTileReader(reader, size, root)
    n_tiles = 0
    level = 0
    while size // TILE_ENTRIES**level:
        count_at_level = size // TILE_ENTRIES**level  # entries at this level
        for index in range((count_at_level + TILE_ENTRIES - 1) // TILE_ENTRIES):
            c = vr._count(level, index)
            assert c is not None
            vr.read_tile(level, index, None if c == TILE_ENTRIES else c)
            n_tiles += 1
        level += 1
    n_bundles = 0
    if entries:
        for index in range((size + TILE_ENTRIES - 1) // TILE_ENTRIES):
            c = vr._count(0, index)
            assert c is not None
            vr.read_entry_bundle(index, None if c == TILE_ENTRIES else c)
            n_bundles += 1
    return AuditReport(size=size, tiles=n_tiles, bundles=n_bundles)

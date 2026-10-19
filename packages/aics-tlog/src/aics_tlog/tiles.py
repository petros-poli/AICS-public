"""Tile layout for tiled transparency logs (c2sp.org/tlog-tiles).

Paths
-----
* Merkle tiles:   ``tile/<L>/<N>[.p/<W>]``
* Entry bundles:  ``tile/entries/<N>[.p/<W>]``

``<L>`` is a decimal level 0..63 with no leading zeroes.  ``<N>`` is the
tile index within the level, encoded in zero-padded 3-digit path elements
where all but the last element begin with ``x`` (1234067 -> ``x001/x234/067``).
``.p/<W>`` marks a partial tile of width ``W`` (decimal 1..255, no leading
zeroes).

Semantics
---------
* Full tiles are exactly 256 hashes (8192 bytes).  Level 0 tiles hold leaf
  hashes; at level L >= 1 hash i of tile (L, n) is the Merkle Tree Hash of
  the *full* tile (L-1, 256*n + i), i.e. of the 256**L leaves it spans.
* The rightmost tile at level L of a tree of size s is partial and has
  ``floor(s / 256**L) mod 256`` entries.  Empty tiles are never served and
  partial tiles are never hashed into the level above.
* Entry bundles hold uint16 big-endian length-prefixed raw entries; each
  entry hashes to the corresponding leaf hash of the level 0 tile.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Protocol

from .hashing import EMPTY_HASH, leaf_hash, node_hash

__all__ = [
    "MemoryTileReader",
    "FileSystemTileReader",
    "TileConflictError",
    "TileMissingError",
    "TileReader",
    "TileUnavailableError",
    "TileVerificationError",
    "TileWriter",
    "build_entry_bundle",
    "entry_bundle_path",
    "inclusion_proof_from_tiles",
    "materialise_tiles",
    "parse_entry_bundle",
    "parse_entry_bundle_path",
    "parse_tile_path",
    "read_entry",
    "tile_index_path",
    "tile_path",
    "tile_width_at",
    "tree_root_from_tiles",
    "consistency_proof_from_tiles",
    "write_new_file",
    "write_tiles",
]

TILE_ENTRIES = 256  # hashes per full tile
HASH_SIZE = 32
FULL_TILE_BYTES = TILE_ENTRIES * HASH_SIZE
MAX_ENTRY_BYTES = 0xFFFF  # uint16 length prefix in entry bundles


class TileMissingError(FileNotFoundError):
    """A tile or entry bundle needed for a computation is not available."""


class TileUnavailableError(OSError):
    """Every tile source failed with a transport error; none answered "not found"."""


class TileVerificationError(ValueError):
    """Tile data does not authenticate against the trusted tree head."""


class TileConflictError(RuntimeError):
    """A writer refused to replace an existing tile path with different bytes.

    Tile paths are immutable: the same path must always hold the same bytes.
    Different bytes mean the log would fork, so the write is refused.
    """


# ---------------------------------------------------------------------------
# Path encoding / decoding
# ---------------------------------------------------------------------------


def _encode_index(n: int) -> str:
    """Zero-padded 3-digit path elements; all but the last begin with 'x'."""
    if n < 0:
        raise ValueError("tile index must be non-negative")
    digits = str(n)
    chunks: list[str] = []  # grouped from the right
    while digits:
        chunks.append(digits[-3:])
        digits = digits[:-3]
    chunks.reverse()  # leftmost first; leftmost may be short -> pad
    chunks[0] = chunks[0].zfill(3)
    return "/".join("x" + c if i < len(chunks) - 1 else c for i, c in enumerate(chunks))


def _decode_index(text: str) -> int:
    parts = text.split("/")
    if not parts:
        raise ValueError(f"malformed tile index path: {text!r}")
    for p in parts[:-1]:
        # all but the last element: 'x' + three digits
        if len(p) != 4 or not p.startswith("x") or not p[1:].isdigit():
            raise ValueError(f"malformed tile index path: {text!r}")
    last = parts[-1]
    if len(last) != 3 or not last.isdigit():
        raise ValueError(f"malformed tile index path: {text!r}")
    return int("".join(p.lstrip("x") for p in parts))


def _check_level(level: int) -> int:
    if not 0 <= level <= 63:
        raise ValueError("tile level must be between 0 and 63")
    return level


def _check_width(width: int | None) -> int | None:
    if width is None:
        return None
    if not 1 <= width <= 255:
        raise ValueError("partial tile width must be between 1 and 255")
    return width


def tile_index_path(index: int) -> str:
    """Encode a tile index as path elements, e.g. 1234067 -> 'x001/x234/067'."""
    return _encode_index(index)


def tile_path(level: int, index: int, width: int | None = None) -> str:
    """Resource path of a tile: 'tile/<L>/<N>' or 'tile/<L>/<N>.p/<W>'."""
    _check_level(level)
    _check_width(width)
    path = f"tile/{level}/{_encode_index(index)}"
    if width is not None:
        path += f".p/{width}"
    return path


def entry_bundle_path(index: int, width: int | None = None) -> str:
    """Resource path of an entry bundle: 'tile/entries/<N>[.p/<W>]'."""
    _check_width(width)
    path = f"tile/entries/{_encode_index(index)}"
    if width is not None:
        path += f".p/{width}"
    return path


def parse_tile_path(path: str) -> tuple[int, int, int | None]:
    """Parse 'tile/<L>/<N>[.p/<W>]' -> (level, index, width or None)."""
    m = re.fullmatch(r"tile/(\d+)/([x\d/]+)(?:\.p/(\d+))?", path)
    if not m:
        raise ValueError(f"not a tile path: {path!r}")
    if str(int(m.group(1))) != m.group(1):
        raise ValueError(f"tile level has leading zeroes: {path!r}")
    level = _check_level(int(m.group(1)))
    index = _decode_index(m.group(2))
    width: int | None = None
    if m.group(3) is not None:
        if str(int(m.group(3))) != m.group(3):
            raise ValueError(f"partial width has leading zeroes: {path!r}")
        width = _check_width(int(m.group(3)))
    return level, index, width


def parse_entry_bundle_path(path: str) -> tuple[int, int | None]:
    """Parse 'tile/entries/<N>[.p/<W>]' -> (index, width or None)."""
    m = re.fullmatch(r"tile/entries/([x\d/]+)(?:\.p/(\d+))?", path)
    if not m:
        raise ValueError(f"not an entry bundle path: {path!r}")
    index = _decode_index(m.group(1))
    width: int | None = None
    if m.group(2) is not None:
        if str(int(m.group(2))) != m.group(2):
            raise ValueError(f"partial width has leading zeroes: {path!r}")
        width = _check_width(int(m.group(2)))
    return index, width


# ---------------------------------------------------------------------------
# Entry bundles
# ---------------------------------------------------------------------------


def build_entry_bundle(entries: list[bytes]) -> bytes:
    """Encode entries as uint16 big-endian length-prefixed records."""
    out = bytearray()
    for e in entries:
        if len(e) > 0xFFFF:
            raise ValueError("entry too large for uint16 length prefix")
        out += len(e).to_bytes(2, "big") + e
    return bytes(out)


def parse_entry_bundle(data: bytes) -> list[bytes]:
    """Decode uint16 BE length-prefixed records."""
    entries: list[bytes] = []
    i = 0
    while i < len(data):
        if i + 2 > len(data):
            raise ValueError("truncated entry bundle")
        n = int.from_bytes(data[i : i + 2], "big")
        i += 2
        if i + n > len(data):
            raise ValueError("truncated entry bundle")
        entries.append(data[i : i + n])
        i += n
    return entries


# ---------------------------------------------------------------------------
# Readers / writer
# ---------------------------------------------------------------------------


class TileReader(Protocol):
    """Anything that can fetch tile resources by logical coordinates."""

    def read_tile(self, level: int, index: int, width: int | None) -> bytes | None: ...

    def read_entry_bundle(self, index: int, width: int | None) -> bytes | None: ...


class MemoryTileReader:
    """TileReader backed by a dict of resource path -> bytes."""

    def __init__(self, tiles: dict[str, bytes] | None = None) -> None:
        self.tiles: dict[str, bytes] = dict(tiles or {})

    def read_tile(self, level: int, index: int, width: int | None) -> bytes | None:
        return self.tiles.get(tile_path(level, index, width))

    def read_entry_bundle(self, index: int, width: int | None) -> bytes | None:
        return self.tiles.get(entry_bundle_path(index, width))


class FileSystemTileReader:
    """TileReader serving resources from a directory tree."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def _read(self, path: str) -> bytes | None:
        f = self.root / path
        try:
            return f.read_bytes()
        except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
            return None

    def read_tile(self, level: int, index: int, width: int | None) -> bytes | None:
        return self._read(tile_path(level, index, width))

    def read_entry_bundle(self, index: int, width: int | None) -> bytes | None:
        return self._read(entry_bundle_path(index, width))


# ---------------------------------------------------------------------------
# Writing resources: atomic, never replacing an existing path
# ---------------------------------------------------------------------------


def _read_file(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
        return None


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_new_file(root: str | Path, path: str, data: bytes, *, fsync: bool = True) -> bool:
    """Create ``root/path`` holding ``data`` atomically; never replace it.

    Returns True when the file was created and False when it already held
    exactly ``data``.  Raises :class:`TileConflictError` when it holds
    different bytes.  The file appears complete or not at all (temporary
    file, then a hard link, which cannot replace an existing file).  Files
    are created world-readable: tiles are public data served by a web server.
    """
    target = Path(root) / path
    existing = _read_file(target)
    if existing is not None:
        if existing == data:
            return False
        raise TileConflictError(f"{path}: already exists with different content")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    tmp: Path | None = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), 0o644)
            fh.write(data)
            fh.flush()
            if fsync:
                os.fsync(fh.fileno())
        try:
            os.link(tmp, target)  # atomic, and fails if target exists
        except FileExistsError:
            if _read_file(target) == data:
                return False
            raise TileConflictError(f"{path}: already exists with different content") from None
        except OSError:
            # No hard links on this filesystem.  The single-writer invariant
            # makes check-then-rename safe here.
            existing = _read_file(target)
            if existing is not None:
                if existing == data:
                    return False
                raise TileConflictError(f"{path}: already exists with different content") from None
            os.replace(tmp, target)
            tmp = None
    finally:
        if tmp is not None:
            try:
                tmp.unlink()
            except OSError:
                pass
    if fsync:
        _fsync_dir(target.parent)
    return True


class TileWriter:
    """Builds the complete set of tiles and entry bundles for a list of raw
    leaves in one pass (a full rebuild), exactly as a log would serve them.

    For a live log use :class:`aics_tlog.writer.IncrementalTileWriter`, which
    appends by writing only new full tiles and the right-edge partial tiles.
    """

    def __init__(self, leaves: list[bytes]) -> None:
        self.leaves = list(leaves)

    def materialise(self) -> dict[str, bytes]:
        return materialise_tiles(self.leaves)

    def write_to(self, out_dir: str | Path, *, fsync: bool = False) -> list[str]:
        """Write all resources under ``out_dir``; returns the paths of the
        tree (written now or already present with identical bytes).

        Existing paths are never replaced: a path holding different bytes
        raises :class:`TileConflictError`.
        """
        tiles = self.materialise()
        for path, data in tiles.items():
            write_new_file(out_dir, path, data, fsync=fsync)
        return sorted(tiles)

    def to_memory_reader(self) -> MemoryTileReader:
        return MemoryTileReader(self.materialise())


def write_tiles(leaves: list[bytes], out_dir: str | Path) -> list[str]:
    """Convenience wrapper: materialise tiles for ``leaves`` and write them."""
    return TileWriter(leaves).write_to(out_dir)


def _fold_full_tile(hashes: list[bytes]) -> bytes:
    """Merkle Tree Hash of a power-of-two number of equal-size complete
    subtrees (balanced fold -- the spans form a perfect binary tree)."""
    level = list(hashes)
    while len(level) > 1:
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
    return level[0]


def _frontier_root(edge: list[list[bytes]]) -> bytes:
    """Root of a tree from its right-edge tile entries.

    ``edge[l]`` holds the entries of the right-edge partial tile at level l
    (each spanning 256**l leaves).  Those entries cover the whole tree, so
    the RFC 9162 root is the right fold of the binary frontier: within each
    level, entries are grouped by the set bits of their count, largest
    group first, top level first.
    """
    frontier: list[bytes] = []
    for level in range(len(edge) - 1, -1, -1):
        entries = edge[level]
        count, offset = len(entries), 0
        for bit in range(7, -1, -1):
            k = 1 << bit
            if count & k:
                frontier.append(_fold_full_tile(entries[offset : offset + k]))
                offset += k
    if not frontier:
        return EMPTY_HASH
    root = frontier[-1]
    for h in reversed(frontier[:-1]):
        root = node_hash(h, root)
    return root


def _split_hashes(data: bytes) -> list[bytes]:
    return [data[i : i + HASH_SIZE] for i in range(0, len(data), HASH_SIZE)]


def materialise_tiles(leaves: list[bytes]) -> dict[str, bytes]:
    """Build every tile and entry bundle required to serve a tree of
    ``len(leaves)`` entries (full tiles plus right-edge partial tiles)."""
    size = len(leaves)
    out: dict[str, bytes] = {}
    if size == 0:
        return out

    # Entry bundles: uint16 BE length-prefixed raw entries.
    for i in range((size + TILE_ENTRIES - 1) // TILE_ENTRIES):
        chunk = leaves[i * TILE_ENTRIES : (i + 1) * TILE_ENTRIES]
        width = len(chunk) if len(chunk) < TILE_ENTRIES else None
        out[entry_bundle_path(i, width)] = build_entry_bundle(chunk)

    # Level 0 tiles: leaf hashes.  Keep the full tiles around for hashing up.
    leaf_hashes = [leaf_hash(e) for e in leaves]
    full_below: list[list[bytes]] = [
        leaf_hashes[i * TILE_ENTRIES : (i + 1) * TILE_ENTRIES]
        for i in range(size // TILE_ENTRIES)
    ]
    pw = size % TILE_ENTRIES
    if pw:
        out[tile_path(0, size // TILE_ENTRIES, pw)] = b"".join(
            leaf_hashes[(size // TILE_ENTRIES) * TILE_ENTRIES :]
        )
    for i, tile in enumerate(full_below):
        out[tile_path(0, i)] = b"".join(tile)

    # Higher levels: each entry is the MTH of one *full* tile below.
    level = 1
    while full_below:  # >= 1 full tile at level-1
        prev_roots = [_fold_full_tile(t) for t in full_below]
        n_full = len(prev_roots) // TILE_ENTRIES
        here: list[list[bytes]] = [
            prev_roots[j * TILE_ENTRIES : (j + 1) * TILE_ENTRIES] for j in range(n_full)
        ]
        pw = len(prev_roots) % TILE_ENTRIES
        if pw:
            here.append(prev_roots[n_full * TILE_ENTRIES :])
        for i, tile in enumerate(here):
            width = len(tile) if len(tile) < TILE_ENTRIES else None
            out[tile_path(level, i, width)] = b"".join(tile)
        full_below = [t for t in here if len(t) == TILE_ENTRIES]
        level += 1

    return out


# ---------------------------------------------------------------------------
# Computing roots and proofs from tiles
# ---------------------------------------------------------------------------

_ABSENT = -1  # sentinel: the tile does not exist at the given tree size


def tile_width_at(size: int, level: int, index: int) -> int | None:
    """Width of tile (level, index) in a tree of ``size`` leaves.

    Returns None for a full tile, 1..255 for the right-edge partial tile, and
    -1 when the tile does not exist at that size.
    """
    full_count = size // TILE_ENTRIES ** (level + 1)
    if index < full_count:
        return None
    if index == full_count:
        w = (size // TILE_ENTRIES**level) % TILE_ENTRIES
        return w if w else _ABSENT
    return _ABSENT


class _TileFetcher:
    """Fetches tile entries with a cache.

    ``tile_size`` is the tree size the tiles were published for (normally the
    size of a verified checkpoint): the rightmost tile at each level is
    partial with ``floor(tile_size / 256**l) mod 256`` entries
    (c2sp.org/tlog-tiles) and that exact width is requested first, then the
    full tile (logs may delete a partial tile once the full tile exists),
    then the partial widths implied by ``hint_sizes`` (the sizes being
    proven, for sources that lag behind ``tile_size``).  Every range hashed
    must end at or before ``tile_size``; proving older sizes works because
    every range it needs is a complete subtree whose entry exists even in a
    right-edge partial tile.
    """

    def __init__(self, reader: TileReader, tile_size: int, hint_sizes: tuple[int, ...] = ()) -> None:
        self.reader = reader
        self.tile_size = tile_size
        self.hint_sizes = tuple(sorted({s for s in hint_sizes if 0 < s < tile_size}, reverse=True))
        self._cache: dict[tuple[int, int], bytes | None] = {}
        self.fetch_count = 0

    def _candidates(self, level: int, index: int) -> list[int | None]:
        primary = tile_width_at(self.tile_size, level, index)
        out: list[int | None] = [primary, None] if primary not in (None, _ABSENT) else [None]
        for s in self.hint_sizes:
            w = tile_width_at(s, level, index)
            if w is not None and w != _ABSENT and w not in out:
                out.append(w)
        return out

    def tile_data(self, level: int, index: int) -> bytes | None:
        _check_level(level)
        key = (level, index)
        if key in self._cache:
            return self._cache[key]
        self.fetch_count += 1
        data: bytes | None = None
        for width in self._candidates(level, index):
            data = self.reader.read_tile(level, index, width)
            if data is None:
                continue
            expected = (width or TILE_ENTRIES) * HASH_SIZE
            if len(data) != expected:
                raise ValueError(
                    f"tile {tile_path(level, index, width)}: invalid size {len(data)}, expected {expected}"
                )
            break
        self._cache[key] = data
        return data

    def entry(self, level: int, start: int) -> bytes:
        """The tile entry whose span starts at leaf index ``start``, where
        ``start`` is a multiple of 256**level (a complete subtree)."""
        span = TILE_ENTRIES**level
        tile_index = start // (span * TILE_ENTRIES)
        entry_i = (start // span) % TILE_ENTRIES
        data = self.tile_data(level, tile_index)
        if data is None or len(data) < (entry_i + 1) * HASH_SIZE:
            raise TileMissingError(
                f"missing tile entry: {tile_path(level, tile_index)} entry {entry_i}"
            )
        return data[entry_i * HASH_SIZE : (entry_i + 1) * HASH_SIZE]

    def leaf_hash(self, index: int) -> bytes:
        return self.entry(0, index)

    def range_hash(self, start: int, end: int) -> bytes:
        """MTH(D[start:end]) computed from tiles (RFC 9162 splitting)."""
        n = end - start
        if n <= 0:
            return EMPTY_HASH
        if n == 1:
            return self.leaf_hash(start)
        k = 1 << ((n - 1).bit_length() - 1)  # largest power of two < n
        h = k.bit_length() - 1
        if start % k == 0 and h % 8 == 0:
            # complete subtree aligned to a single tile entry at level h/8
            left = self.entry(h // 8, start)
        else:
            left = self.range_hash(start, start + k)
        return node_hash(left, self.range_hash(start + k, end))


def _resolve_tile_size(size: int, tile_size: int | None) -> int:
    if tile_size is None:
        return size
    if tile_size < size:
        raise ValueError(f"tile_size {tile_size} is smaller than the tree size {size} being proven")
    return tile_size


def tree_root_from_tiles(reader: TileReader, size: int, tile_size: int | None = None) -> bytes:
    """Merkle Tree Hash of a tree of ``size`` leaves, computed from tiles.

    ``tile_size`` is the size the tiles were published for; it defaults to
    ``size``.  Computing the root of an older size against a newer tile set
    is supported when ``tile_size`` is given.
    """
    if size < 0:
        raise ValueError("size must be non-negative")
    if size == 0:
        return EMPTY_HASH
    ts = _resolve_tile_size(size, tile_size)
    return _TileFetcher(reader, ts, (size,)).range_hash(0, size)


def inclusion_proof_from_tiles(
    reader: TileReader, index: int, size: int, tile_size: int | None = None
) -> list[bytes]:
    """Inclusion proof for leaf ``index`` in a tree of ``size`` leaves,
    computed from tiles (RFC 9162 Section 2.1.3.1 PATH).

    Works for any ``0 <= index < size <= tile_size``.  ``tile_size`` is the
    size the tiles were published for (default: ``size``).  The proof is only
    as trustworthy as the tiles: verify it against a signed root, or read
    through :class:`aics_tlog.verified.VerifiedTileReader`.
    """
    if not 0 <= index < size:
        raise ValueError(f"leaf index {index} out of range for size {size}")
    fetch = _TileFetcher(reader, _resolve_tile_size(size, tile_size), (size,))
    proof: list[bytes] = []

    def path(m: int, start: int, end: int) -> None:
        n = end - start
        if n == 1:
            return
        k = 1 << ((n - 1).bit_length() - 1)
        if m < k:
            path(m, start, start + k)
            proof.append(fetch.range_hash(start + k, end))
        else:
            path(m - k, start + k, end)
            proof.append(fetch.range_hash(start, start + k))

    path(index, 0, size)
    return proof


def consistency_proof_from_tiles(
    reader: TileReader, old_size: int, new_size: int, tile_size: int | None = None
) -> list[bytes]:
    """Consistency proof between tree sizes ``old_size`` and ``new_size``,
    computed from tiles (RFC 9162 Section 2.1.4.1 SUBPROOF).

    Works for any ``0 <= old_size <= new_size <= tile_size``; the proof is
    empty when ``old_size`` is 0 or equals ``new_size``.  ``tile_size`` is
    the size the tiles were published for (default: ``new_size``).
    """
    if not 0 <= old_size <= new_size:
        raise ValueError(f"invalid sizes old={old_size} new={new_size}")
    ts = _resolve_tile_size(new_size, tile_size)
    if old_size in (0, new_size):
        return []
    fetch = _TileFetcher(reader, ts, (new_size,))
    proof: list[bytes] = []

    def subproof(m: int, start: int, end: int, b: bool) -> None:
        n = end - start
        if m == n:
            if not b:
                proof.append(fetch.range_hash(start, end))
            return
        k = 1 << ((n - 1).bit_length() - 1)
        if m <= k:
            subproof(m, start, start + k, b)
            proof.append(fetch.range_hash(start + k, end))
        else:
            subproof(m - k, start + k, end, False)
            proof.append(fetch.range_hash(start, start + k))

    subproof(old_size, 0, new_size, True)
    return proof


def read_entry(reader: TileReader, index: int, tile_size: int) -> bytes:
    """Raw entry ``index`` from the entry bundles of a tree of ``tile_size``
    leaves (partial bundle at the right edge, full bundle as a fallback).

    The entry is authenticated only if ``reader`` is a
    :class:`aics_tlog.verified.VerifiedTileReader`; otherwise hash it and
    verify an inclusion proof against a signed root.
    """
    if not 0 <= index < tile_size:
        raise ValueError(f"entry index {index} out of range for size {tile_size}")
    bundle = index // TILE_ENTRIES
    width = tile_width_at(tile_size, 0, bundle)
    raw = reader.read_entry_bundle(bundle, width)
    if raw is None and width is not None:
        raw = reader.read_entry_bundle(bundle, None)
    if raw is None:
        raise TileMissingError(f"missing entry bundle {entry_bundle_path(bundle, width)}")
    entries = parse_entry_bundle(raw)
    pos = index % TILE_ENTRIES
    if pos >= len(entries):
        raise TileMissingError(f"entry bundle {entry_bundle_path(bundle, width)} has no entry {pos}")
    return entries[pos]

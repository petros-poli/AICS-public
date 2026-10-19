"""The transparency log's derived state: Merkle tree, C2SP tiles and signed checkpoints.

DESIGN.md section 4.2 items 4 and 5, AICS-1 section 6.1, DECISIONS.md #5.

The committed leaf table (``tlog_leaves`` in SQLite, written with
``synchronous=FULL`` by :mod:`aics_server.db`) is the writer's source of truth.
Everything in this module is derived from it, strictly after the commit, in
this order:

1. :class:`CompactTree`, the in-memory RFC 6962 tree, takes the committed
   entries (it keeps complete-subtree hashes only, about two per leaf, and
   answers roots and proofs for every size it has held);
2. the tiles directory (``AICS_TILES_DIR``) takes them through
   :class:`aics_tlog.IncrementalTileWriter`: each full tile and full entry
   bundle is written once, the right-edge partials at new ``.p/<W>`` paths,
   and an existing path is never given different bytes
   (:class:`aics_tlog.TileConflictError`);
3. ``<tiles>/checkpoint``, the signed note for the size those tiles serve, is
   replaced atomically, after its tiles exist.

:meth:`TlogStore.boot` rebuilds the tree from the table, checks that the
published checkpoint and the tiles describe a prefix of it, catches the tiles
up and audits them against the table's root.  Any disagreement raises
:class:`LogIntegrityError` and the server does not start (fail closed).

A failure to write tiles after a commit does not undo the commit: the leaf is
in the table, which is the log.  The batch stays queued and is retried on the
next commit (and at the next start).  Every receipt promises publication
within :data:`MMD_SECONDS` (AICS-1 section 10.1), so once the published
checkpoint has lagged the tree for longer than that, the store refuses new
leaves (:meth:`TlogStore.check_writable` retries the publication first) rather
than hand out promises it knows it cannot keep.  A tile path holding bytes the
table does not produce means the published log and the table have diverged;
the store then refuses further leaves (:attr:`TlogStore.diverged`) until an
operator looks.

One process writes the log (DESIGN.md section 4.1).  :func:`acquire_writer_lock`
makes a second process on the same database refuse to start.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aics_tlog import (
    EMPTY_HASH,
    Checkpoint,
    DirectoryTileStore,
    IncrementalTileWriter,
    TileConflictError,
    TileMissingError,
    TileVerificationError,
    audit_tiles,
    format_vkey,
    leaf_hash,
    node_hash,
    parse_checkpoint,
    parse_note,
    sign_checkpoint,
    tree_root_from_tiles,
    verify_checkpoint,
    vkey_from_ed25519,
)
from aics_tlog.note import check_name
from aics_tlog.tiles import parse_entry_bundle_path, parse_tile_path

__all__ = [
    "CHECKPOINT_PATH",
    "MMD_SECONDS",
    "CompactTree",
    "LogIntegrityError",
    "LogUnavailable",
    "PublishedCheckpoint",
    "TlogStore",
    "acquire_writer_lock",
    "tile_resource",
]

#: Name of the signed checkpoint note inside the tiles directory (c2sp.org/tlog-tiles).
CHECKPOINT_PATH = "checkpoint"
#: Maximum merge delay every receipt promises (AICS-1 section 10.1: 60 seconds in this profile).
MMD_SECONDS = 60
#: Entries per tile-writer batch while catching up at start-up.
_CATCH_UP_BATCH = 256 * 64
#: Audit modes for the start-up check of the tiles directory.
AUDIT_MODES = ("full", "edge")


class LogIntegrityError(RuntimeError):
    """The leaf table, the tiles or the published checkpoint disagree.

    Raised at start-up; the writer does not run on a log it cannot vouch for.
    """


class LogUnavailable(RuntimeError):
    """New leaves are refused: the published tiles diverged from the leaf table, or publication lags too long."""


def _say(message: str) -> None:
    print(f"aics-server: {message}", file=sys.stderr, flush=True)


# ----------------------------------------------------------------------
# the in-memory tree
# ----------------------------------------------------------------------

def _split_point(n: int) -> int:
    """Largest power of two strictly smaller than ``n`` (``n >= 2``): RFC 9162's ``k``."""
    return 1 << ((n - 1).bit_length() - 1)


class CompactTree:
    """Append-only RFC 6962 / RFC 9162 Merkle tree over leaf hashes.

    Level ``h`` holds the hash of every complete, aligned subtree of ``2**h``
    leaves, packed 32 bytes per hash.  Those nodes never change once the tree
    has grown past them, so the root, inclusion proofs and consistency proofs
    of every earlier size are computed from the same arrays: about 64 bytes
    of memory per leaf, nothing cached per size, O(log n) per append.
    """

    __slots__ = ("_levels", "_size")

    def __init__(self) -> None:
        self._levels: list[bytearray] = []
        self._size = 0

    @property
    def size(self) -> int:
        return self._size

    def __len__(self) -> int:
        return self._size

    def append(self, entry: bytes) -> bytes:
        """Append raw entry bytes; returns their RFC 6962 leaf hash."""
        digest = leaf_hash(entry)
        self.append_hash(digest)
        return digest

    def append_hash(self, digest: bytes) -> None:
        if len(digest) != 32:
            raise ValueError("a leaf hash is 32 bytes")
        node = bytes(digest)
        level = 0
        while True:
            if level == len(self._levels):
                self._levels.append(bytearray())
            row = self._levels[level]
            row += node
            if (len(row) // 32) % 2:
                break
            node = node_hash(bytes(row[-64:-32]), bytes(row[-32:]))
            level += 1
        self._size += 1

    def _node(self, level: int, index: int) -> bytes:
        offset = index * 32
        return bytes(self._levels[level][offset : offset + 32])

    def leaf_hash(self, index: int) -> bytes:
        if not 0 <= index < self._size:
            raise IndexError(f"leaf {index} is not in a tree of {self._size}")
        return self._node(0, index)

    def _hash(self, start: int, end: int) -> bytes:
        """MTH(D[start:end]) (RFC 9162 section 2.1.1), ``end <= size``."""
        n = end - start
        if n <= 0:
            return EMPTY_HASH
        if n & (n - 1) == 0 and start % n == 0:
            return self._node(n.bit_length() - 1, start // n)
        k = _split_point(n)
        return node_hash(self._hash(start, start + k), self._hash(start + k, end))

    def _check_size(self, size: int | None) -> int:
        size = self._size if size is None else size
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= self._size:
            raise ValueError(f"tree size {size!r} is not between 0 and {self._size}")
        return size

    def root(self, size: int | None = None) -> bytes:
        """Merkle Tree Hash of the first ``size`` leaves (default: all)."""
        return self._hash(0, self._check_size(size))

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        """RFC 9162 section 2.1.3.1 PATH(index, D[size])."""
        size = self._check_size(size)
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < size:
            raise ValueError(f"leaf index {index!r} is not in a tree of size {size}")
        proof: list[bytes] = []

        def path(m: int, start: int, end: int) -> None:
            n = end - start
            if n == 1:
                return
            k = _split_point(n)
            if m < k:
                path(m, start, start + k)
                proof.append(self._hash(start + k, end))
            else:
                path(m - k, start + k, end)
                proof.append(self._hash(start, start + k))

        path(index, 0, size)
        return proof

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> list[bytes]:
        """RFC 9162 section 2.1.4.1 PROOF(old_size, D[new_size]); empty for 0 or equal sizes."""
        new_size = self._check_size(new_size)
        if isinstance(old_size, bool) or not isinstance(old_size, int) or not 0 <= old_size <= new_size:
            raise ValueError(f"old size {old_size!r} is not between 0 and {new_size}")
        if old_size in (0, new_size):
            return []
        proof: list[bytes] = []

        def subproof(m: int, start: int, end: int, complete: bool) -> None:
            n = end - start
            if m == n:
                if not complete:
                    proof.append(self._hash(start, end))
                return
            k = _split_point(n)
            if m <= k:
                subproof(m, start, start + k, complete)
                proof.append(self._hash(start + k, end))
            else:
                subproof(m - k, start + k, end, False)
                proof.append(self._hash(start, start + k))

        subproof(old_size, 0, new_size, True)
        return proof


# ----------------------------------------------------------------------
# tiles, checkpoints, start-up checks
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class PublishedCheckpoint:
    """The signed note at ``<tiles>/checkpoint`` and the tree head it names."""

    size: int
    root: bytes
    note: bytes


def tile_resource(path: str) -> tuple[str, bool] | None:
    """Validate a tile-directory resource path; ``(path, immutable)`` or ``None``.

    Only ``checkpoint`` and the c2sp.org/tlog-tiles paths ``tile/<L>/<N>[.p/<W>]``
    and ``tile/entries/<N>[.p/<W>]`` are resources.  ``immutable`` is true for
    full tiles and full entry bundles (a partial may later be pruned, and the
    checkpoint changes on every merge).
    """
    if path == CHECKPOINT_PATH:
        return path, False
    try:
        if path.startswith("tile/entries/"):
            _, width = parse_entry_bundle_path(path)
        else:
            _, _, width = parse_tile_path(path)
    except ValueError:
        return None
    return path, width is None


class TlogStore:
    """The derived log: tree, tiles and checkpoint for one origin and one log key.

    ``log_key`` is the ``tlog-origin`` Ed25519 private key: it signs checkpoint
    notes only, under the C2SP key name ``origin``.  Callers serialise access
    (the database lock); the store is not thread safe on its own.
    """

    def __init__(
        self,
        *,
        origin: str,
        log_key: Any,
        tiles_dir: str | Path,
        fsync: bool = True,
        audit: str = "full",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        check_name(origin, "origin")
        if not origin.isascii() or "://" in origin or origin.endswith("/"):
            raise ValueError("the log origin is ASCII with no scheme and no trailing slash")
        if audit not in AUDIT_MODES:
            raise ValueError(f"tile audit mode must be one of {', '.join(AUDIT_MODES)}")
        self.origin = origin
        self.key_name = origin
        self._key = log_key
        self.vkey = vkey_from_ed25519(origin, log_key.public_key())
        self.vkey_text = format_vkey(self.vkey)
        self.tiles_dir = Path(tiles_dir)
        self.store = DirectoryTileStore(self.tiles_dir, fsync=fsync)
        self.audit = audit
        self.tree = CompactTree()
        self._writer: IncrementalTileWriter | None = None
        self._unpublished: list[bytes] = []
        self._published: PublishedCheckpoint | None = None
        self._note_cache: tuple[int, bytes] | None = None
        self.tiles_error: str | None = None
        self.diverged: str | None = None
        self._booted = False
        self._clock = clock
        #: When the published checkpoint first fell behind the tree (``clock`` time), or ``None`` while it is current.
        self._behind_since: float | None = None

    # -- checkpoints ----------------------------------------------------------

    def checkpoint_note(self, size: int | None = None) -> bytes:
        """Signed checkpoint note (C2SP tlog-checkpoint) for the first ``size`` leaves."""
        size = self.tree.size if size is None else size
        cached = self._note_cache
        if cached is not None and cached[0] == size:
            return cached[1]
        cp = Checkpoint(origin=self.origin, size=size, root=self.tree.root(size))  # root() checks the size
        note = sign_checkpoint(cp, self._key, self.key_name).to_bytes()
        self._note_cache = (size, note)
        return note

    @property
    def published(self) -> PublishedCheckpoint | None:
        """The checkpoint the tiles directory serves now, if any."""
        return self._published

    @property
    def tiles_size(self) -> int:
        return self._writer.size if self._writer is not None else 0

    @property
    def published_size(self) -> int:
        published = self._published
        return published.size if published is not None else 0

    def lag_seconds(self) -> float:
        """How long the published checkpoint has been behind the tree (0 while it is current)."""
        since = self._behind_since
        return 0.0 if since is None else max(0.0, self._clock() - since)

    def status(self) -> dict[str, Any]:
        published = self._published
        return {
            "tree_size": self.tree.size,
            "tiles_size": self.tiles_size,
            "published_size": published.size if published is not None else None,
            "queued_entries": len(self._unpublished),
            "lag_entries": self.tree.size - self.published_size,
            "lag_seconds": int(self.lag_seconds()),
            "mmd_seconds": MMD_SECONDS,
            "error": self.tiles_error,
            "diverged": self.diverged,
        }

    def read_resource(self, path: str) -> bytes | None:
        """Bytes of a tiles-directory resource (see :func:`tile_resource`); ``None`` if absent."""
        if path == CHECKPOINT_PATH:
            published = self._published
            return published.note if published is not None else None
        if tile_resource(path) is None:
            return None
        try:
            return (self.tiles_dir / path).read_bytes()
        except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
            return None

    # -- start-up ----------------------------------------------------------------

    def _read_published(self) -> PublishedCheckpoint | None:
        raw = self.store.read_checkpoint()
        if raw is None:
            return None
        where = self.tiles_dir / CHECKPOINT_PATH
        try:
            note = parse_note(raw)
            cp = parse_checkpoint(note.text)
        except ValueError as exc:
            raise LogIntegrityError(f"{where} is not a checkpoint note ({exc})") from None
        result = verify_checkpoint(note, self.vkey, expected_origin=self.origin)
        if not result.ok:
            raise LogIntegrityError(
                f"{where} is not signed by this server's log key for origin {self.origin!r} "
                f"({result.error}). Did AICS_SERVER_SEED_HEX, the seed file or AICS_ORIGIN change, "
                "or does AICS_TILES_DIR belong to another log?"
            )
        return PublishedCheckpoint(size=cp.size, root=cp.root, note=raw)

    def boot(self, size: int, read_entries: Callable[[int, int], Iterable[bytes]]) -> None:
        """Rebuild from the committed table, verify and catch up the tiles; fail closed.

        ``read_entries(start, end)`` yields the committed entries ``start``
        to ``end - 1`` in index order (the caller checks the table itself:
        contiguous indices, stored hashes).
        """
        if self._booted:
            raise RuntimeError("the log store is already booted")
        for entry in read_entries(0, size):
            self.tree.append(entry)
        if self.tree.size != size:
            raise LogIntegrityError(f"the leaf table yielded {self.tree.size} entries, expected {size}")

        published = self._read_published()
        start = 0
        if published is not None:
            if published.size > size:
                raise LogIntegrityError(
                    f"{self.tiles_dir / CHECKPOINT_PATH} commits to {published.size} leaves but the leaf table "
                    f"holds {size}: committed leaves are missing from the database (restored from an older "
                    "backup, or a new database over an existing tiles directory?). Refusing to start: going on "
                    "would fork the log."
                )
            if published.root != self.tree.root(published.size):
                raise LogIntegrityError(
                    f"the published checkpoint for size {published.size} has a root the leaf table does not "
                    "reproduce: the database and the published log disagree. Refusing to start."
                )
            start = published.size
        try:
            writer = IncrementalTileWriter(self.store, start)
        except (TileMissingError, ValueError) as exc:
            raise LogIntegrityError(f"cannot resume the tiles in {self.tiles_dir} at size {start}: {exc}") from None
        if writer.root() != self.tree.root(start):
            raise LogIntegrityError(
                f"the right-edge tiles for size {start} in {self.tiles_dir} do not reproduce the leaf table's root"
            )
        try:
            batch: list[bytes] = []
            for entry in read_entries(start, size):
                batch.append(entry)
                if len(batch) >= _CATCH_UP_BATCH:
                    writer.append(batch)
                    batch = []
            if batch:
                writer.append(batch)
        except TileConflictError as exc:
            raise LogIntegrityError(
                f"{self.tiles_dir} holds a tile the leaf table does not produce ({exc}). Refusing to start."
            ) from None
        if writer.size != size or writer.root() != self.tree.root(size):
            raise LogIntegrityError("the tiles written at start-up do not reproduce the leaf table's root")
        if size:
            root = self.tree.root(size)
            try:
                from_disk = tree_root_from_tiles(self.store, size)
                if self.audit == "full":
                    audit_tiles(self.store, size, root, entries=True)
            except (TileMissingError, TileVerificationError, ValueError) as exc:
                raise LogIntegrityError(f"the tiles in {self.tiles_dir} do not match the leaf table: {exc}") from None
            if from_disk != root:
                raise LogIntegrityError(f"the tiles in {self.tiles_dir} give a different root than the leaf table")
        if start < size:
            _say(f"tiles caught up from {start} to {size} leaves in {self.tiles_dir}")
        self._writer = writer
        self._booted = True
        if size:
            self._publish_checkpoint(size, at_boot=True)

    # -- after each commit ------------------------------------------------------

    def append_committed(self, entries: Sequence[bytes]) -> None:
        """Entries just committed to the leaf table: extend the tree, then the tiles and checkpoint."""
        if not self._booted:
            raise RuntimeError("the log store is not booted")
        for entry in entries:
            self.tree.append(entry)
        self._unpublished.extend(bytes(e) for e in entries)
        self.publish()

    def publish(self) -> bool:
        """Write queued entries to the tiles and refresh the checkpoint; ``True`` when up to date.

        Also keeps the lag clock: it starts when the published checkpoint
        first falls behind the tree and stops once it is current again.
        """
        current = self._publish()
        if current and self.published_size == self.tree.size:
            self._behind_since = None
        elif self._behind_since is None:
            self._behind_since = self._clock()
        return current

    def _publish(self) -> bool:
        if self.diverged is not None:
            return False
        if self._unpublished:
            assert self._writer is not None
            try:
                result = self._writer.append(self._unpublished)
            except TileConflictError as exc:
                self.diverged = f"a tile path holds bytes the leaf table does not produce: {exc}"
                _say(f"LOG DIVERGED, new leaves refused until an operator acts: {self.diverged}")
                return False
            except (OSError, ValueError) as exc:
                self.tiles_error = f"{type(exc).__name__}: {exc}"
                _say(f"tile write failed, will retry on the next commit: {self.tiles_error}")
                return False
            self._unpublished.clear()
            if result.size != self.tree.size or result.root != self.tree.root(result.size):
                self.diverged = f"the tile writer's root at size {result.size} differs from the tree"
                _say(f"LOG DIVERGED, new leaves refused until an operator acts: {self.diverged}")
                return False
        size = self.tiles_size
        if size and (self._published is None or self._published.size != size):
            return self._publish_checkpoint(size)
        self.tiles_error = None
        return True

    def _publish_checkpoint(self, size: int, *, at_boot: bool = False) -> bool:
        note = self.checkpoint_note(size)
        try:
            self.store.write_checkpoint(note)
        except OSError as exc:
            if at_boot:
                raise
            self.tiles_error = f"{type(exc).__name__}: {exc}"
            _say(f"checkpoint write failed, will retry on the next commit: {self.tiles_error}")
            return False
        self._published = PublishedCheckpoint(size=size, root=self.tree.root(size), note=note)
        self.tiles_error = None
        return True

    def check_writable(self) -> None:
        """Raise :class:`LogUnavailable` when no new leaf may be appended.

        Besides a divergence, that is when publication has lagged the tree
        for more than :data:`MMD_SECONDS`: a new leaf would come with a
        receipt promising publication within that delay, which the store
        knows it is not keeping.  The publication is retried first, so a
        tile or checkpoint write that works again lets writes resume.
        """
        if not self._booted:
            raise LogUnavailable("the log is not open")
        if self.diverged is not None:
            raise LogUnavailable(f"the published tiles diverged from the leaf table: {self.diverged}")
        if self._behind_since is not None and self.lag_seconds() > MMD_SECONDS:
            self.publish()
            if self._behind_since is not None and self.lag_seconds() > MMD_SECONDS:
                raise LogUnavailable(
                    f"the published checkpoint is {self.tree.size - self.published_size} leaves behind the tree for "
                    f"over {MMD_SECONDS} s (the maximum merge delay a receipt promises): "
                    f"{self.tiles_error or 'tile publication is failing'}"
                )


# ----------------------------------------------------------------------
# single writer
# ----------------------------------------------------------------------

#: Lock files held by this process: real path -> [descriptor, users].  POSIX
#: record locks belong to the process, and closing any descriptor of the file
#: drops them, so each path is opened once and closed when its last user goes.
_WRITER_LOCKS: dict[str, list[int]] = {}


def acquire_writer_lock(path: str | Path) -> Callable[[], None]:
    """Hold an exclusive POSIX lock on ``path``; returns the function that lets it go.

    A second process (for example a second uvicorn worker) on the same
    database fails here: one writer process is a protocol invariant, because
    two processes would each hold a tree and sign divergent checkpoints.
    Acquiring again in the same process (tests, a rebuilt app) succeeds and
    adds a user; the lock is released when the last user releases it.
    """
    try:
        import fcntl
    except ImportError:  # pragma: no cover - non-POSIX platforms have no record locks
        return lambda: None
    key = os.path.realpath(path)
    held = _WRITER_LOCKS.get(key)
    if held is not None:
        held[1] += 1
    else:
        fd = os.open(key, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise LogIntegrityError(
                f"another process holds {key}: a single writer process is a protocol invariant "
                "(run one worker; AICS_WORKERS=1)"
            ) from None
        held = _WRITER_LOCKS[key] = [fd, 1]
    released = False

    def release() -> None:
        nonlocal released
        if released:
            return
        released = True
        held[1] -= 1
        if held[1] == 0 and _WRITER_LOCKS.get(key) is held:
            del _WRITER_LOCKS[key]
            os.close(held[0])

    return release

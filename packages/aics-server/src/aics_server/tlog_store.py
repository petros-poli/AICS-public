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

Witness cosignatures (AICS-1 section 6.2, :mod:`aics_server.witness_feed`):
after a new checkpoint is signed and its tiles are written,
:attr:`TlogStore.on_publish` hands it to the witness feeder at once, which
submits it to every witness without holding the writer.
:meth:`TlogStore.add_cosignature` merges a returned ``cosignature/v1`` line
only after verifying it under a configured witness key for exactly that
checkpoint; the merged note replaces ``<tiles>/checkpoint`` atomically.  At
start-up, cosignature lines already on the note on disk are kept only when
they still verify under a configured witness key.

The served checkpoint (AICS-1 sections 6.3, 10.1 and 14.3).  Without
witnesses every publication is served at once, as it always was (quorum 0).
With witnesses, the card states quorum 1, and a log-signed note that no
witness has cosigned yet is not what a verifier holding that card can
accept: :attr:`TlogStore.served` (``/checkpoint``, ``/tiles/checkpoint``,
``<tiles>/checkpoint`` for the tile mirror, the stated checkpoint of read
projections, the checkpoint entry bundles are proved against) stays the
newest cosigned checkpoint until a witness cosigns a newer publication, so
it may trail :attr:`TlogStore.published` by the publications still waiting
for their cosignature.  It follows the publications uncosigned only when
every witness is failing and either no cosigned checkpoint is served yet or
they have all been failing for longer than the grace
(``AICS_WITNESS_GRACE_SECONDS``, :attr:`TlogStore.grace_seconds`);
:attr:`TlogStore.uncosigned_reason` then says why.  The served size never
decreases.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from aics_tlog import (
    EMPTY_HASH,
    Checkpoint,
    Note,
    SignatureLine,
    VKey,
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
    verify_cosignature,
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
    "NotYetCosigned",
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


#: How many publications waiting for a cosignature are remembered (with witnesses).  A witness line for a size not
#: remembered is answered ``"superseded"``; the feeder submits the newest publication, so its lines are for one of
#: the last few.
MAX_HELD_PUBLICATIONS = 4096


class NotYetCosigned(RuntimeError):
    """Entry ``index`` is committed but not yet under the served checkpoint, which no witness has cosigned past it.

    Its receipt promises it a published checkpoint within :data:`MMD_SECONDS`, and with a witness quorum a
    cosignature is part of publication (AICS-1 section 10.1): ask again after ``retry_after`` seconds.
    """

    def __init__(self, index: int, served_size: int, tree_size: int, retry_after: int) -> None:
        super().__init__(
            f"entry {index} is committed but not yet under a cosigned checkpoint (the served checkpoint has "
            f"{served_size} leaves, the log {tree_size}); its receipt promises it one within {MMD_SECONDS} s: "
            f"ask again in {retry_after} s"
        )
        self.index = index
        self.served_size = served_size
        self.tree_size = tree_size
        self.retry_after = retry_after


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
        witness_keys: Sequence[VKey] = (),
        wall_clock: Callable[[], float] = time.time,
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
        #: The newest published checkpoint whose served note carried a verified witness cosignature: the one
        #: published now once a witness has cosigned it, an older one while the witnesses have not cosigned the
        #: newest yet, ``None`` before any cosignature (or without witnesses).  Proofs are given against it
        #: (:meth:`proof_checkpoint`).
        self._cosigned: PublishedCheckpoint | None = None
        self._note_cache: tuple[int, bytes] | None = None
        self.tiles_error: str | None = None
        self.diverged: str | None = None
        self._booted = False
        self._clock = clock
        #: When the published checkpoint first fell behind the tree (``clock`` time), or ``None`` while it is current.
        self._behind_since: float | None = None
        #: Wall-clock times (Unix seconds) of the last log-signed checkpoint write (a new publication; merging a
        #: witness cosignature does not count, see ``cosigned_at``) and the last tile write by this process (the
        #: owner stats page's health section); before the first tile write, the published checkpoint file's mtime.
        self.checkpoint_written_at: float | None = None
        self.tiles_written_at: float | None = None
        #: Wall-clock time of the last witness cosignature merged into the served note (``None`` before one).
        self.cosigned_at: float | None = None
        #: The witnesses whose cosignatures may be served (verified before each merge), in serving order.
        self.witness_keys: tuple[VKey, ...] = tuple(witness_keys)
        self._wall_clock = wall_clock
        #: Called with ``(size, note)`` after a new checkpoint is written (the witness feeder's ``offer``); it must
        #: not block, and an exception from it never affects publication.
        self.on_publish: Callable[[int, bytes], None] | None = None
        #: Cosignature lines that did not verify and were not served, since start-up.
        self.cosignatures_dropped = 0
        # The served checkpoint (see the module docstring and "the served checkpoint" below).  With witnesses it
        # is its own state; without them :attr:`served` is :attr:`published`.
        self._served: PublishedCheckpoint | None = None
        self._served_cosigned = False
        # The sizes published since the served one, still waiting for a cosignature (oldest first): a witness line
        # moves the served note forward to one of them, never to a size that was not published.
        self._held_sizes: list[int] = []
        #: Why the served note carries no witness cosignature although witnesses are configured, else ``None``.
        self.uncosigned_reason: str | None = None
        #: How long every witness may fail before newer publications are served uncosigned
        #: (``AICS_WITNESS_GRACE_SECONDS``, set from the witness settings).
        self.grace_seconds: float = 120.0
        #: ``witness_outage()``: for how many seconds every witness has been failing, or ``None`` while one of them
        #: may still cosign (the witness feeder's ``outage``).  Unset (no feeder running), a cosigned note is held.
        self.witness_outage: Callable[[], float | None] | None = None
        #: Called after the served checkpoint changed (the database wakes the requests waiting for it); it must not
        #: block, and an exception from it is ignored.
        self.on_served: Callable[[], None] | None = None

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
        """The newest checkpoint signed for the tiles written, if any (with witnesses, :attr:`served` may trail it)."""
        return self._published

    @property
    def cosigned(self) -> PublishedCheckpoint | None:
        """The newest published checkpoint served with a verified witness cosignature (see ``_cosigned``)."""
        return self._cosigned

    def proof_checkpoint(self, index: int) -> tuple[int, bytes]:
        """``(size, note)`` that a proof of leaf ``index`` is given against (AICS-1 sections 6.3 and 14.3).

        The newest published checkpoint that a witness cosigned and that covers ``index``, so that a verifier
        pinning a positive witness quorum can accept the proof's checkpoint (offline, historical verification
        counts a cosignature whatever its age); otherwise (a leaf newer than every cosigned checkpoint, or no
        witness) the log-signed note of the whole tree.  A log publishes a checkpoint before its witnesses
        cosign it, so a proof against the newest note would never carry a cosignature.
        """
        cosigned = self._cosigned
        size = self.tree.size
        if cosigned is not None and index < cosigned.size <= size:
            return cosigned.size, cosigned.note
        return size, self.checkpoint_note(size)

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
            served = self.served
            return served.note if served is not None else None
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
            self.tiles_written_at = time.time()
        elif published is not None:
            try:  # the tiles were last written with the checkpoint this start found
                self.tiles_written_at = (self.tiles_dir / CHECKPOINT_PATH).stat().st_mtime
            except OSError:
                self.tiles_written_at = None
        self._writer = writer
        self._booted = True
        if published is not None and published.size < size:
            self._restore_served(published)  # with witnesses it stays served until a newer note is cosigned
        if size:
            carried = published.note if published is not None and published.size == size else None
            self._publish_checkpoint(size, at_boot=True, carried=carried)

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
            self.tiles_written_at = time.time()
            if result.size != self.tree.size or result.root != self.tree.root(result.size):
                self.diverged = f"the tile writer's root at size {result.size} differs from the tree"
                _say(f"LOG DIVERGED, new leaves refused until an operator acts: {self.diverged}")
                return False
        size = self.tiles_size
        if size and (self._published is None or self._published.size != size):
            return self._publish_checkpoint(size)
        self.tiles_error = None
        return True

    def _publish_checkpoint(self, size: int, *, at_boot: bool = False, carried: bytes | None = None) -> bool:
        note = self.checkpoint_note(size)
        kept: dict[tuple[str, bytes], SignatureLine] = {}
        if carried is not None:
            # The same checkpoint as the one on disk: keep its witness lines that still verify.
            kept = self._verified_lines(carried, size)
            if kept:
                note = self._compose(size, kept)
        # With witnesses, a note no witness has cosigned is neither served nor written for the tile mirror while
        # the newest cosigned note still stands for it ("the served checkpoint" below).
        cosigned = note != self.checkpoint_note(size)
        serve, reason = self._serves_publication(cosigned)
        try:
            if serve:
                self.store.write_checkpoint(note)
        except OSError as exc:
            if at_boot:
                raise
            self.tiles_error = f"{type(exc).__name__}: {exc}"
            _say(f"checkpoint write failed, will retry on the next commit: {self.tiles_error}")
            return False
        self._published = PublishedCheckpoint(size=size, root=self.tree.root(size), note=note)
        if kept:
            self._cosigned = self._published
        self.checkpoint_written_at = time.time()
        self.tiles_error = None
        if serve:
            self._serve(self._published, cosigned=cosigned, reason=reason)
        else:  # held: served once a witness cosigns it (or a later one), or as _follows_uncosigned says
            self._held_sizes.append(size)
            del self._held_sizes[:-MAX_HELD_PUBLICATIONS]
        hook = self.on_publish
        if hook is not None:
            try:
                hook(size, note)
            except Exception as exc:  # the witnesses are fed best effort; publication stands
                _say(f"witness feeder hand-off failed: {type(exc).__name__}: {exc}")
        return True

    # -- witness cosignatures -----------------------------------------------------

    def _lines_of(self, note: Note, key: VKey) -> list[SignatureLine]:
        return [s for s in note.signatures if s.name == key.name and s.key_id == key.key_id]

    def _line_verifies(self, line: SignatureLine, key: VKey, size: int, **freshness: Any) -> bool:
        if len(line.signature) != 8 + 64:
            return False
        try:
            return verify_cosignature(
                line.signature, key.name, key.public_key, self.origin, size, self.tree.root(size), **freshness
            )
        except ValueError:
            return False

    def _verified_lines(self, note_bytes: bytes, size: int) -> dict[tuple[str, bytes], SignatureLine]:
        """The one line per configured witness on ``note_bytes`` that verifies for checkpoint ``size``."""
        try:
            note = parse_note(note_bytes)
        except ValueError:
            return {}
        kept: dict[tuple[str, bytes], SignatureLine] = {}
        for key in self.witness_keys:
            lines = self._lines_of(note, key)
            if len(lines) == 1 and self._line_verifies(lines[0], key, size):
                kept[(key.name, key.key_id)] = lines[0]
            elif lines:
                self.cosignatures_dropped += len(lines)
        return kept

    def _compose(self, size: int, lines: dict[tuple[str, bytes], SignatureLine]) -> bytes:
        """The log-signed note of ``size`` followed by ``lines`` in :attr:`witness_keys` order."""
        base = parse_note(self.checkpoint_note(size))
        ordered = [lines[(k.name, k.key_id)] for k in self.witness_keys if (k.name, k.key_id) in lines]
        return Note(text=base.text, signatures=tuple(base.signatures) + tuple(ordered)).to_bytes()

    def add_cosignature(self, key: VKey, size: int, lines: str) -> tuple[bool, str | None]:
        """Merge a witness's ``cosignature/v1`` line into the served note; ``(served, reason)``.

        ``key`` must be a configured witness key and ``size`` the size of the
        checkpoint published now or, with witnesses, of an earlier
        publication that is still newer than the served note (otherwise
        ``"superseded"``): a line for that one moves the served note forward
        while a later publication waits for its own cosignature, so a log that
        publishes faster than its witness answers still advances.  The line
        must verify for exactly that checkpoint and be dated within
        :data:`aics_server.witness_feed.COSIGNATURE_MAX_AGE_SECONDS` before and
        30 s after now; a line older than the one already served is not
        merged.  The merged note is verified again as a whole before it
        replaces ``<tiles>/checkpoint`` and becomes the served note.  A line
        that fails is dropped and the served note is left as it was.
        """
        from .witness_feed import COSIGNATURE_MAX_AGE_SECONDS, COSIGNATURE_MAX_FUTURE_SECONDS

        published = self._cosignature_target(size)  # the one published now, or with witnesses an earlier one
        if published is None:
            return False, "superseded"
        ident = (key.name, key.key_id)
        if ident not in {(k.name, k.key_id) for k in self.witness_keys}:
            self.cosignatures_dropped += 1
            return False, "not a configured witness key"
        base_text = parse_note(published.note).text
        try:
            candidate = parse_note(base_text + "\n" + lines)
        except ValueError as exc:
            self.cosignatures_dropped += 1
            return False, f"malformed cosignature lines ({exc})"
        mine = self._lines_of(candidate, key)
        if len(mine) != 1:
            self.cosignatures_dropped += 1
            return False, f"{len(mine)} lines from the witness key, expected one"
        line = mine[0]
        now = int(self._wall_clock())
        if not self._line_verifies(
            line, key, size,
            max_age_seconds=COSIGNATURE_MAX_AGE_SECONDS, max_future_seconds=COSIGNATURE_MAX_FUTURE_SECONDS, now=now,
        ):
            self.cosignatures_dropped += 1
            return False, "the cosignature does not verify for the published checkpoint, or is not fresh"
        current = self._verified_lines(published.note, size)
        previous = current.get(ident)
        if previous is not None and int.from_bytes(previous.signature[:8], "big") > int.from_bytes(line.signature[:8], "big"):
            return False, "older than the cosignature already served"
        current[ident] = line
        note = self._compose(size, current)
        check = verify_checkpoint(parse_note(note), self.vkey, list(self.witness_keys), 0, expected_origin=self.origin)
        if not check.ok or check.error is not None or key.name not in check.witnesses:
            self.cosignatures_dropped += 1
            return False, f"the merged note does not verify ({check.error or 'witness not counted'})"
        if note == published.note:
            self._cosigned = published
            return True, None
        try:
            self.store.write_checkpoint(note)
        except OSError as exc:
            return False, f"checkpoint write failed ({type(exc).__name__}: {exc})"
        if published is not self._published:  # an earlier publication, still newer than the served note
            return self._serve_cosigned(replace(published, note=note))
        self._published = replace(published, note=note)
        self._cosigned = self._published
        # Not checkpoint_written_at: that is the last log-signed publication, which the owner stats report as
        # the checkpoint's age. A cosignature refresh every AICS_WITNESS_REFRESH_SECONDS must not make a
        # publication that is stuck at an old size look fresh.
        self.cosigned_at = time.time()
        self._serve(self._published, cosigned=True)
        return True, None

    def _serve_cosigned(self, merged: PublishedCheckpoint) -> tuple[bool, str | None]:
        """``merged``, an earlier publication's note with the line just merged (written already), is served."""
        self.cosigned_at = time.time()
        self._serve(merged, cosigned=True)
        return True, None

    def _cosignature_target(self, size: int) -> PublishedCheckpoint | None:
        """The checkpoint a witness line for ``size`` is merged into, or ``None`` (``"superseded"``).

        The checkpoint published now; with witnesses also the served one, or a
        publication between the served one and the one published now that is
        still held (rebuilt from the tree: the text the witness was given,
        signed again by the same deterministic key).  Never one older than the
        served note (the served size does not decrease), and never a size that
        was not published by this process: a size inside one append batch has
        no right-edge tiles of its own, so a restart could not resume the tiles
        from a ``<tiles>/checkpoint`` of that size, and no witness was given it.
        """
        published = self._published
        if published is None:
            return None
        if size == published.size:
            return published
        served = self.served
        if not self.witness_keys or served is None or not served.size <= size < published.size:
            return None
        if size == served.size:
            return served
        if size not in self._held_sizes:
            return None
        return PublishedCheckpoint(size=size, root=self.tree.root(size), note=self.checkpoint_note(size))

    def served_cosignatures(self) -> dict[str, int]:
        """Witness vkey -> timestamp of its line on the note served now (lines were verified when merged)."""
        served = self.served
        if served is None or not self.witness_keys:
            return {}
        try:
            note = parse_note(served.note)
        except ValueError:  # pragma: no cover - the store wrote it
            return {}
        out: dict[str, int] = {}
        for key in self.witness_keys:
            lines = self._lines_of(note, key)
            if len(lines) == 1 and len(lines[0].signature) == 72:
                out[format_vkey(key)] = int.from_bytes(lines[0].signature[:8], "big")
        return out

    # -- the served checkpoint ------------------------------------------------------

    #: :attr:`uncosigned_reason` until a witness cosigns a checkpoint this server serves (``/healthz`` ``witnesses``
    #: says what each witness answers meanwhile).
    NOT_YET_COSIGNED = "no witness has cosigned a checkpoint that this server serves yet"

    @property
    def served(self) -> PublishedCheckpoint | None:
        """The checkpoint served now (``/checkpoint``, ``<tiles>/checkpoint``, proofs, stated read projections).

        Without witnesses, :attr:`published`.  With witnesses, the newest
        checkpoint carrying a verified cosignature of a configured witness,
        which a newer publication replaces once a witness cosigns it (or, when
        :meth:`_follows_uncosigned` says so, uncosigned).  Its size never
        decreases and never exceeds the published size.
        """
        return self._served if self.witness_keys else self._published

    @property
    def served_size(self) -> int:
        served = self.served
        return served.size if served is not None else 0

    @property
    def served_cosigned(self) -> bool:
        """Whether witnesses are configured and the served note carries a verified cosignature of one of them."""
        return bool(self.witness_keys) and self._served is not None and self._served_cosigned

    def _serve(self, checkpoint: PublishedCheckpoint, *, cosigned: bool, reason: str | None = None) -> None:
        """``checkpoint`` (already written to ``<tiles>/checkpoint``) is the served one from now on."""
        self._served = checkpoint
        self._served_cosigned = cosigned
        if self._held_sizes:
            self._held_sizes = [held for held in self._held_sizes if held > checkpoint.size]
        self.uncosigned_reason = None if cosigned or not self.witness_keys else (reason or self.NOT_YET_COSIGNED)
        hook = self.on_served
        if hook is not None:
            try:
                hook()
            except Exception:  # waking waiters is best effort; they time out on their own
                pass

    def _follows_uncosigned(self) -> str | None:
        """Why a publication no witness cosigned replaces the served note now, or ``None`` to keep the note.

        Only while every witness is failing (:attr:`witness_outage`): at once
        when the served note carries no cosignature either (there is nothing
        better to hold on to), else once they have all been failing for longer
        than :attr:`grace_seconds`.  While any witness may still cosign, the
        served note is kept, so its cosignature can arrive and the served size
        catch up instead of being overtaken by every publication.
        """
        outage = self.witness_outage() if self.witness_outage is not None else None
        if outage is None:
            return None
        if not self._served_cosigned:
            return self.uncosigned_reason or self.NOT_YET_COSIGNED  # already uncosigned: the reason stands
        if outage > self.grace_seconds:
            return (f"every witness has been failing for more than {self.grace_seconds:g} s "
                    "(AICS_WITNESS_GRACE_SECONDS): newer checkpoints are served without a cosignature")
        return None

    def _serves_publication(self, cosigned: bool) -> tuple[bool, str | None]:
        """Whether a new publication is served (and written for the tile mirror) at once, and why uncosigned."""
        if not self.witness_keys or cosigned:
            return True, None
        if self._served is None:
            return True, self.NOT_YET_COSIGNED  # nothing is served yet: the first note of the log, or of this start
        reason = self._follows_uncosigned()
        return reason is not None, reason

    def refresh_served(self) -> bool:
        """After the witnesses' state changed: serve the newest publication uncosigned if it is due; True if it was.

        Called (under the database lock) when a witness fails, and before the
        served note is read, so the grace takes effect without waiting for the
        next publication.
        """
        published, served = self._published, self._served
        if not self.witness_keys or published is None or served is None or served.size >= published.size:
            return False
        reason = self._follows_uncosigned()
        if reason is None:
            return False
        try:
            self.store.write_checkpoint(published.note)
        except OSError as exc:
            self.tiles_error = f"{type(exc).__name__}: {exc}"
            _say(f"checkpoint write failed, will retry: {self.tiles_error}")
            return False
        self._serve(published, cosigned=False, reason=reason)
        _say(f"serving the checkpoint of size {published.size} without a witness cosignature: {reason}")
        return True

    def _restore_served(self, on_disk: PublishedCheckpoint) -> None:
        """At start-up, with witnesses: the note on disk, older than the tree, stays served for now.

        Its witness lines that still verify are kept, the others removed (and
        the file rewritten without them).  A newer note is served once a
        witness cosigns it, or as :meth:`_follows_uncosigned` says.
        """
        if not self.witness_keys:
            return
        lines = self._verified_lines(on_disk.note, on_disk.size)
        note = self._compose(on_disk.size, lines) if lines else self.checkpoint_note(on_disk.size)
        if note != on_disk.note:
            self.store.write_checkpoint(note)  # at start-up an error stops the start, as a publication's does
        self._serve(replace(on_disk, note=note), cosigned=bool(lines))

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

"""Persistent witness state and the witness key.

State lives in SQLite (WAL, ``synchronous=FULL``): per log origin the
latest cosigned checkpoint ``{origin, last_size, last_root, last_note}``
plus the timestamp of the witness's latest cosignature for it.  Checks and
updates happen inside one ``BEGIN IMMEDIATE`` transaction under a process
lock, so the "check old size, then persist" step of c2sp.org/tlog-witness is
atomic across threads and across processes sharing the file, and the new
state is on disk before the witness answers.  After every commit that
changed something the WAL is checkpointed into the main file (best effort,
never waiting for readers), so in normal operation the database file alone
holds the state.

The database is created only on request (``create=True``, which
``aics-witness init`` uses).  Opening it otherwise needs an existing,
initialised file: a witness whose state was lost must not start again with
an empty one under the same identity, or it could be led to cosign a fork
of what it cosigned before.  Triggers make the database itself refuse an
update that lowers a log's size or changes its root at an equal size, and
any deletion of a log's state (schema version 2).

A COMMIT that fails (disk full, I/O error) is rolled back and marks the
store as failed: every later transaction or read on the writer connection
raises StoreError until the process restarts, because what reached the
disk is unknown.  The monitoring endpoint reads through a separate
read-only connection, so it only ever sees committed state.

Requests that a known log signed but that failed a consistency check are
kept in an ``evidence`` table (possible proof of log misbehaviour), capped
per origin by row count and by bytes.

The witness's Ed25519 key comes from ``$WITNESS_SEED_HEX`` (64 hex
characters, the 32-byte RFC 8032 seed) or from a key file holding the same
hex seed, created once with mode 0600 and refused if group or others can
read it.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import stat
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .protocol import origin_hash

__all__ = [
    "DEFAULT_EVIDENCE_BYTES",
    "DEFAULT_EVIDENCE_LIMIT",
    "SCHEMA_VERSION",
    "SEED_ENV",
    "Evidence",
    "KeyFileError",
    "LogState",
    "StoreError",
    "StoreTransaction",
    "WitnessStore",
    "create_key_file",
    "database_status",
    "load_key_file",
    "load_or_create_key",
    "parse_seed_hex",
    "seed_hex",
]

log = logging.getLogger("aics_witness")

SEED_ENV = "WITNESS_SEED_HEX"
SCHEMA_VERSION = 2
DEFAULT_EVIDENCE_LIMIT = 1000
DEFAULT_EVIDENCE_BYTES = 16 * 1024 * 1024

MISSING_DATABASE_HELP = (
    "If this witness ever cosigned a checkpoint, its state is lost: retire the "
    "identity (README, 'Operations') instead of starting it again. For a new "
    "witness run 'aics-witness init'."
)


class StoreError(RuntimeError):
    """The witness database cannot be used as configured."""


class KeyFileError(RuntimeError):
    """The witness key cannot be loaded or created."""


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LogState:
    """The latest checkpoint the witness cosigned for one log."""

    origin: str
    size: int
    root: bytes
    note: str  # checkpoint text + verified log signature lines + the witness cosignature
    timestamp: int  # timestamp inside that cosignature (POSIX seconds); 0 once cleared
    updated_at: int


@dataclass(frozen=True)
class Evidence:
    """A log-signed request that failed a consistency check (not cosigned)."""

    id: int
    origin: str
    received_at: int
    reason: str
    old_size: int
    known_size: int
    known_root: bytes | None
    request: bytes  # the complete add-checkpoint request body


_TABLES = (
    """CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS logs (
        origin         TEXT PRIMARY KEY,
        origin_hash    TEXT NOT NULL UNIQUE,
        last_size      INTEGER NOT NULL CHECK (last_size >= 0),
        last_root      BLOB NOT NULL CHECK (length(last_root) = 32),
        last_note      TEXT NOT NULL,
        last_timestamp INTEGER NOT NULL,
        updated_at     INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS evidence (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        origin      TEXT NOT NULL,
        received_at INTEGER NOT NULL,
        reason      TEXT NOT NULL,
        old_size    INTEGER NOT NULL,
        known_size  INTEGER NOT NULL,
        known_root  BLOB,
        request     BLOB NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS evidence_by_origin ON evidence (origin)",
)

# Schema version 2: the database refuses to roll a log back, whatever code
# path or manual edit asks for it (INSERT OR REPLACE included, which deletes
# without firing delete triggers).
_TRIGGERS = (
    """CREATE TRIGGER IF NOT EXISTS logs_no_rollback BEFORE UPDATE ON logs
    WHEN NEW.last_size < OLD.last_size
      OR (NEW.last_size = OLD.last_size AND NEW.last_root <> OLD.last_root)
      OR NEW.origin <> OLD.origin OR NEW.origin_hash <> OLD.origin_hash
    BEGIN SELECT RAISE(ABORT, 'witness state rollback'); END""",
    """CREATE TRIGGER IF NOT EXISTS logs_no_replace_rollback BEFORE INSERT ON logs
    WHEN EXISTS (SELECT 1 FROM logs WHERE origin = NEW.origin
                 AND (last_size > NEW.last_size
                      OR (last_size = NEW.last_size AND last_root <> NEW.last_root)))
    BEGIN SELECT RAISE(ABORT, 'witness state rollback'); END""",
    """CREATE TRIGGER IF NOT EXISTS logs_no_delete BEFORE DELETE ON logs
    BEGIN SELECT RAISE(ABORT, 'witness state cannot be deleted'); END""",
)

_LOG_COLUMNS = "origin, last_size, last_root, last_note, last_timestamp, updated_at"


def _log_state(row: tuple) -> LogState:
    return LogState(
        origin=row[0],
        size=row[1],
        root=bytes(row[2]),
        note=row[3],
        timestamp=row[4],
        updated_at=row[5],
    )


def _uri(path: Path, mode: str) -> str:
    return f"file:{quote(str(path))}?mode={mode}"


def _connect(path: Path, mode: str) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(
            _uri(path, mode),
            uri=True,
            timeout=30.0,
            isolation_level=None,  # explicit BEGIN / COMMIT
            check_same_thread=False,  # every use is guarded by a lock
        )
    except sqlite3.Error as e:
        if mode != "rwc" and not path.exists():
            raise StoreError(
                f"witness database {path} is missing. {MISSING_DATABASE_HELP}"
            ) from None
        raise StoreError(f"cannot open witness database {path}: {e}") from None
    try:
        conn.execute("PRAGMA busy_timeout=30000")
    except sqlite3.Error as e:
        conn.close()
        raise StoreError(f"cannot open witness database {path}: {e}") from None
    return conn


def _has_meta_table(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'"
    ).fetchone()
    return row is not None


def database_status(path: str | os.PathLike[str]) -> str:
    """``"missing"``, ``"empty"`` (a file without the witness schema) or
    ``"initialised"``.  Opens the file read-only; raises StoreError if it is
    not an SQLite database."""
    p = Path(path)
    if not p.exists():
        return "missing"
    conn = _connect(p, "ro")
    try:
        return "initialised" if _has_meta_table(conn) else "empty"
    except sqlite3.Error as e:
        raise StoreError(f"cannot read witness database {p}: {e}") from None
    finally:
        conn.close()


class StoreTransaction:
    """Reads and writes inside one ``BEGIN IMMEDIATE`` transaction."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def get(self, origin: str) -> LogState | None:
        row = self._conn.execute(
            f"SELECT {_LOG_COLUMNS} FROM logs WHERE origin = ?", (origin,)
        ).fetchone()
        return None if row is None else _log_state(row)

    def put(
        self,
        origin: str,
        size: int,
        root: bytes,
        note: str,
        timestamp: int,
        updated_at: int,
    ) -> None:
        """Insert or advance a log's state.  A smaller size, or another root
        at the same size, raises StoreError (and the database's triggers
        refuse it as well)."""
        if len(root) != 32:
            raise ValueError("root hash must be 32 bytes")
        try:
            cur = self._conn.execute(
                "INSERT INTO logs (origin, origin_hash, last_size, last_root, last_note,"
                " last_timestamp, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT (origin) DO UPDATE SET last_size = excluded.last_size,"
                " last_root = excluded.last_root, last_note = excluded.last_note,"
                " last_timestamp = excluded.last_timestamp, updated_at = excluded.updated_at"
                " WHERE excluded.last_size >= logs.last_size",
                (origin, origin_hash(origin), size, root, note, timestamp, updated_at),
            )
        except sqlite3.IntegrityError as e:
            raise StoreError(f"refused to store state for {origin}: {e}") from None
        if cur.rowcount != 1:
            raise StoreError(f"refused to store state for {origin}: witness state rollback")


class WitnessStore:
    """SQLite-backed witness state.  Safe to share between threads.

    ``create=False`` (the default) opens an existing database that ``init``
    created and refuses a missing or empty file; ``create=True`` creates
    the file and the schema if needed.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        create: bool = False,
        evidence_limit: int = DEFAULT_EVIDENCE_LIMIT,
        evidence_byte_limit: int = DEFAULT_EVIDENCE_BYTES,
    ) -> None:
        self.path = Path(path)
        self.evidence_limit = evidence_limit
        self.evidence_byte_limit = evidence_byte_limit
        self.failed = False
        self.failure: str | None = None
        # Called once (with no arguments) when the store fails; must not block.
        self.on_failure: Callable[[], None] | None = None
        self._lock = threading.RLock()
        self._ro_lock = threading.Lock()
        self._ro_conn: sqlite3.Connection | None = None
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = _connect(self.path, "rwc" if create else "rw")
        try:
            self._initialise(create)
        except sqlite3.Error as e:
            self._conn.close()
            raise StoreError(f"cannot open witness database {self.path}: {e}") from None
        except BaseException:
            self._conn.close()
            raise

    def _initialise(self, create: bool) -> None:
        conn = self._conn
        if not _has_meta_table(conn):
            if not create:
                raise StoreError(
                    f"{self.path} holds no witness state (an empty or foreign file). "
                    f"{MISSING_DATABASE_HELP}"
                )
            version = None
        else:
            row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
            # A meta table without a version comes from version 1 (which wrote
            # the version right after creating the tables).
            text = "1" if row is None else row[0]
            if not text.isascii() or not text.isdigit():
                raise StoreError(f"{self.path} has an unreadable schema version {text!r}")
            version = int(text)
            if version > SCHEMA_VERSION:
                raise StoreError(
                    f"{self.path} has schema version {version}; this aics-witness "
                    f"understands version {SCHEMA_VERSION}"
                )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        if version == SCHEMA_VERSION:
            return
        with self.transaction():
            for statement in _TABLES + _TRIGGERS:
                conn.execute(statement)
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?)"
                " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),),
            )
        if version is not None:
            log.info("migrated %s from schema version %d to %d", self.path, version, SCHEMA_VERSION)

    # -- lifecycle ------------------------------------------------------

    def close(self) -> None:
        with self._ro_lock:
            if self._ro_conn is not None:
                self._ro_conn.close()
                self._ro_conn = None
        with self._lock:
            self._conn.close()

    def __enter__(self) -> WitnessStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def healthy(self) -> bool:
        """False once a COMMIT failed or the database cannot be read."""
        if self.failed:
            return False
        try:
            self._read_committed("SELECT 1")
        except StoreError:
            return False
        return not self.failed

    # -- failure ----------------------------------------------------------

    def _check_usable(self) -> None:
        if self.failed:
            raise StoreError(
                f"the witness database failed earlier ({self.failure}); "
                "nothing more is written until the witness restarts"
            )

    def _fail(self, reason: str) -> None:
        if self.failed:
            return
        self.failed = True
        self.failure = reason
        log.critical(
            "witness database %s failed: %s. Refusing every further write and read "
            "on this connection; restart the witness once the cause (disk full, I/O "
            "error) is fixed", self.path, reason,
        )
        callback = self.on_failure
        if callback is not None:
            try:
                callback()
            except Exception:
                log.exception("store failure callback failed")

    @staticmethod
    def _rollback(conn: sqlite3.Connection) -> bool:
        """Roll back an open transaction; True if none is left open."""
        if not getattr(conn, "in_transaction", True):
            return True
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error as e:
            if "no transaction is active" not in str(e):
                log.error("ROLLBACK failed: %s", e)
                return False
        return not getattr(conn, "in_transaction", False)

    # -- transactions -----------------------------------------------------

    @contextmanager
    def transaction(self) -> Iterator[StoreTransaction]:
        """Atomic read-check-write.  Commits on normal exit (the data is on
        disk when the block returns); rolls back if the block raises.

        A failing COMMIT is rolled back explicitly (SQLite may leave the
        transaction open after SQLITE_FULL or SQLITE_IOERR), marks the store
        as failed and raises StoreError.  Database errors inside the block
        are rolled back and raised as StoreError."""
        with self._lock:
            self._check_usable()
            conn = self._conn
            changes = getattr(conn, "total_changes", None)
            try:
                conn.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as e:
                if not self._rollback(conn):
                    self._fail(f"BEGIN failed and the transaction could not be closed: {e}")
                raise StoreError(f"cannot start a database transaction: {e}") from e
            committing = False
            try:
                yield StoreTransaction(conn)
                committing = True
                conn.execute("COMMIT")
            except BaseException as e:
                closed = self._rollback(conn)
                if committing or not closed:
                    step = "COMMIT" if committing else "ROLLBACK"
                    self._fail(f"{step} failed: {e}")
                    if isinstance(e, sqlite3.Error):
                        raise StoreError(f"database {step} failed: {e}") from e
                    raise
                if isinstance(e, sqlite3.Error):
                    raise StoreError(f"database error: {e}") from e
                raise
            if changes is None or getattr(conn, "total_changes", None) != changes:
                self._checkpoint_wal(conn)

    def _checkpoint_wal(self, conn: sqlite3.Connection) -> None:
        # Copy the committed frames into the main database file now, so the
        # state does not live in witness.db-wal alone.  PASSIVE never waits
        # for readers; frames it cannot copy yet follow on the next commit
        # (and on close).  A failure here loses nothing: the WAL still holds
        # every committed frame.
        try:
            conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()
        except sqlite3.Error as e:
            log.warning("WAL checkpoint of %s failed: %s", self.path, e)

    # -- reads ------------------------------------------------------------

    def _read(self, sql: str, args: tuple = ()) -> list[tuple]:
        """A read on the writer connection (refused once the store failed)."""
        with self._lock:
            self._check_usable()
            try:
                return self._conn.execute(sql, args).fetchall()
            except sqlite3.Error as e:
                raise StoreError(f"database read failed: {e}") from e

    def _read_committed(self, sql: str, args: tuple = ()) -> list[tuple]:
        """A read on the separate read-only connection: committed state only,
        whatever the writer connection is doing."""
        with self._ro_lock:
            if self._ro_conn is None:
                self._ro_conn = _connect(self.path, "ro")
            try:
                return self._ro_conn.execute(sql, args).fetchall()
            except sqlite3.Error as e:
                raise StoreError(f"database read failed: {e}") from e

    def get(self, origin: str) -> LogState | None:
        rows = self._read(f"SELECT {_LOG_COLUMNS} FROM logs WHERE origin = ?", (origin,))
        return _log_state(rows[0]) if rows else None

    def get_by_origin_hash(self, hex_hash: str) -> LogState | None:
        """Committed state by origin hash (the monitoring endpoint).  Served
        by the read-only connection, so it keeps working, with committed
        data only, after the store failed."""
        rows = self._read_committed(
            f"SELECT {_LOG_COLUMNS} FROM logs WHERE origin_hash = ?", (hex_hash,)
        )
        return _log_state(rows[0]) if rows else None

    def all_logs(self) -> list[LogState]:
        return [_log_state(r) for r in self._read(f"SELECT {_LOG_COLUMNS} FROM logs ORDER BY origin")]

    # -- clock recovery ---------------------------------------------------

    def clear_last_timestamp(self, origin: str | None = None) -> int:
        """Forget the time of the latest cosignature (of one log, or of all
        logs), so a witness whose clock ran ahead can cosign again with its
        corrected clock.  Sizes and roots are untouched.  Returns the number
        of logs changed."""
        with self.transaction():
            if origin is None:
                cur = self._conn.execute("UPDATE logs SET last_timestamp = 0")
            else:
                cur = self._conn.execute(
                    "UPDATE logs SET last_timestamp = 0 WHERE origin = ?", (origin,)
                )
            return cur.rowcount

    # -- evidence ---------------------------------------------------------

    def record_evidence(
        self,
        origin: str,
        reason: str,
        old_size: int,
        known_size: int,
        known_root: bytes | None,
        request: bytes,
        received_at: int | None = None,
    ) -> bool:
        """Keep a rejected, log-signed request.  Returns False (and keeps
        nothing) once ``evidence_limit`` rows or ``evidence_byte_limit``
        request bytes exist for the origin: the first conflicting
        checkpoints are the ones that matter."""
        when = int(time.time()) if received_at is None else received_at
        with self.transaction():
            count, total = self._conn.execute(
                "SELECT COUNT(*), COALESCE(SUM(length(request)), 0) FROM evidence"
                " WHERE origin = ?",
                (origin,),
            ).fetchone()
            if count >= self.evidence_limit or total + len(request) > self.evidence_byte_limit:
                return False
            self._conn.execute(
                "INSERT INTO evidence (origin, received_at, reason, old_size,"
                " known_size, known_root, request) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (origin, when, reason, old_size, known_size, known_root, request),
            )
        return True

    def evidence(self, origin: str | None = None) -> list[Evidence]:
        query = (
            "SELECT id, origin, received_at, reason, old_size, known_size,"
            " known_root, request FROM evidence"
        )
        args: tuple = ()
        if origin is not None:
            query += " WHERE origin = ?"
            args = (origin,)
        rows = self._read(query + " ORDER BY id", args)
        return [
            Evidence(
                id=r[0],
                origin=r[1],
                received_at=r[2],
                reason=r[3],
                old_size=r[4],
                known_size=r[5],
                known_root=None if r[6] is None else bytes(r[6]),
                request=bytes(r[7]),
            )
            for r in rows
        ]

    def evidence_counts(self) -> dict[str, int]:
        rows = self._read("SELECT origin, COUNT(*) FROM evidence GROUP BY origin")
        return {origin: count for origin, count in rows}

    # -- metadata ---------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        rows = self._read("SELECT value FROM meta WHERE key = ?", (key,))
        return rows[0][0] if rows else None

    def set_meta(self, key: str, value: str) -> None:
        with self.transaction():
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?)"
                " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def bind_witness_vkey(self, vkey: str, *, accept_change: bool = False) -> str | None:
        """Record which witness key this database belongs to.

        The first call stores ``vkey``.  Later calls with a different vkey
        raise StoreError unless ``accept_change`` is set, so a lost or
        swapped key file (whose cosignatures nobody trusts) is noticed at
        startup instead of after logs start failing.  Returns the previously
        recorded vkey, if any.
        """
        previous = self.get_meta("witness_vkey")
        if previous is not None and previous != vkey and not accept_change:
            raise StoreError(
                f"{self.path} belongs to witness key {previous}, but the configured "
                f"key is {vkey}. Restore the original key, or pass --accept-new-key "
                "if the witness identity really changed (publish the new vkey first)."
            )
        if previous != vkey:
            self.set_meta("witness_vkey", vkey)
        return previous


# ---------------------------------------------------------------------------
# Witness key
# ---------------------------------------------------------------------------

_SEED_RE = re.compile(r"[0-9a-fA-F]{64}")


def parse_seed_hex(text: str) -> Ed25519PrivateKey:
    """An Ed25519 private key from its 32-byte seed in hex (64 characters)."""
    t = text.strip()
    if _SEED_RE.fullmatch(t) is None:
        raise KeyFileError("the witness seed must be exactly 64 hex characters (32 bytes)")
    try:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(t))
    except ValueError as e:
        raise KeyFileError(f"the witness seed is not a usable Ed25519 seed: {e}") from None


def seed_hex(key: Ed25519PrivateKey) -> str:
    return key.private_bytes_raw().hex()


def load_key_file(path: str | os.PathLike[str]) -> Ed25519PrivateKey:
    """Load a key file; refuse one that group or others may read or write."""
    p = Path(path)
    try:
        st = p.stat()
    except FileNotFoundError:
        raise KeyFileError(f"witness key file {p} does not exist (run 'aics-witness init')") from None
    if not stat.S_ISREG(st.st_mode):
        raise KeyFileError(f"witness key file {p} is not a regular file")
    if os.name == "posix" and st.st_mode & 0o077:
        raise KeyFileError(
            f"witness key file {p} has mode {stat.S_IMODE(st.st_mode):04o}; "
            f"it must not be accessible to group or others (chmod 600 {p})"
        )
    try:
        text = p.read_text("ascii")
    except (OSError, UnicodeDecodeError) as e:
        raise KeyFileError(f"cannot read witness key file {p}: {e}") from None
    return parse_seed_hex(text)


def create_key_file(path: str | os.PathLike[str]) -> Ed25519PrivateKey:
    """Generate a new witness key into ``path`` (mode 0600, never overwrites)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(p, flags, 0o600)
    except FileExistsError:
        raise KeyFileError(f"witness key file {p} already exists") from None
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        os.write(fd, (seed_hex(key) + "\n").encode("ascii"))
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        p.unlink(missing_ok=True)
        raise
    os.close(fd)
    _fsync_dir(p.parent)
    return key


def _fsync_dir(directory: Path) -> None:
    if os.name != "posix":
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def load_or_create_key(
    key_path: str | os.PathLike[str] | None,
    *,
    create: bool = True,
    environ: Mapping[str, str] | None = None,
) -> tuple[Ed25519PrivateKey, str, bool]:
    """Return ``(key, source, created)``.

    ``$WITNESS_SEED_HEX`` wins when set (the key file is then not touched);
    otherwise the key file is loaded, or generated when missing and
    ``create`` is true.
    """
    env = os.environ if environ is None else environ
    seed = env.get(SEED_ENV, "").strip()
    if seed:
        return parse_seed_hex(seed), f"${SEED_ENV}", False
    if key_path is None:
        raise KeyFileError(f"no key file configured and ${SEED_ENV} is not set")
    p = Path(key_path)
    if p.exists() or p.is_symlink():
        return load_key_file(p), str(p), False
    if not create:
        raise KeyFileError(
            f"witness key file {p} does not exist; run 'aics-witness init' "
            f"or set ${SEED_ENV}"
        )
    return create_key_file(p), str(p), True

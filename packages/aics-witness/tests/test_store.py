"""SQLite state and witness key handling."""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_witness.store import (
    SCHEMA_VERSION,
    SEED_ENV,
    KeyFileError,
    StoreError,
    WitnessStore,
    create_key_file,
    database_status,
    load_key_file,
    load_or_create_key,
    parse_seed_hex,
    seed_hex,
)

ROOT_A = b"\xaa" * 32
ROOT_B = b"\xbb" * 32


def test_key_file_created_once_with_mode_0600(tmp_path):
    path = tmp_path / "keys" / "witness.key"
    key, source, created = load_or_create_key(path, environ={})
    assert created and source == str(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text() == seed_hex(key) + "\n"
    again, _, created_again = load_or_create_key(path, environ={})
    assert not created_again
    assert again.private_bytes_raw() == key.private_bytes_raw()


def test_key_file_created_0600_despite_permissive_umask(tmp_path):
    old = os.umask(0)
    try:
        create_key_file(tmp_path / "w.key")
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "w.key").stat().st_mode) == 0o600


def test_create_never_overwrites(tmp_path):
    path = tmp_path / "w.key"
    create_key_file(path)
    with pytest.raises(KeyFileError):
        create_key_file(path)


def test_key_file_readable_by_others_is_refused(tmp_path):
    path = tmp_path / "w.key"
    create_key_file(path)
    path.chmod(0o644)
    with pytest.raises(KeyFileError, match="chmod 600"):
        load_key_file(path)
    path.chmod(0o640)
    with pytest.raises(KeyFileError):
        load_or_create_key(path, environ={})


def test_corrupt_key_file_is_refused(tmp_path):
    path = tmp_path / "w.key"
    path.write_text("not a seed\n")
    path.chmod(0o600)
    with pytest.raises(KeyFileError):
        load_key_file(path)


def test_key_file_that_is_not_a_regular_file_is_refused(tmp_path):
    path = tmp_path / "w.key"
    path.mkdir()
    with pytest.raises(KeyFileError, match="not a regular file"):
        load_key_file(path)
    with pytest.raises(KeyFileError, match="not a regular file"):
        load_or_create_key(path, environ={})


def test_missing_key_without_create(tmp_path):
    with pytest.raises(KeyFileError, match="init"):
        load_or_create_key(tmp_path / "absent.key", create=False, environ={})


def test_seed_from_environment_wins_and_touches_no_file(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "w.key"
    loaded, source, created = load_or_create_key(path, environ={SEED_ENV: seed_hex(key).upper()})
    assert loaded.private_bytes_raw() == key.private_bytes_raw()
    assert source == "$WITNESS_SEED_HEX" and not created
    assert not path.exists()


def _spaced_seed() -> str:
    """64 characters that bytes.fromhex accepts (21 bytes): it used to reach
    Ed25519PrivateKey.from_private_bytes and raise ValueError."""
    seed = "ab  ab  " + " ".join(["ab"] * 19)
    assert len(seed) == 64 and len(bytes.fromhex(seed)) == 21
    return seed


@pytest.mark.parametrize("bad", [
    "00" * 31, "zz" * 32, "00" * 33, "0x" + "00" * 31, _spaced_seed(),
    "aa" * 16 + "\t" + "bb" * 15 + "c",
])
def test_bad_seeds_are_refused(bad):
    with pytest.raises(KeyFileError):
        parse_seed_hex(bad)


def test_seed_with_whitespace_from_environment_is_a_key_error(tmp_path):
    with pytest.raises(KeyFileError, match="64 hex characters"):
        load_or_create_key(tmp_path / "w.key", environ={SEED_ENV: _spaced_seed()})


def test_seed_is_rfc8032_seed():
    # RFC 8032 section 7.1, test 1.
    key = parse_seed_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    assert key.public_key().public_bytes_raw().hex() == (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )


# ---------------------------------------------------------------------------
# Opening and creating the database
# ---------------------------------------------------------------------------


def test_missing_database_is_refused_without_create(tmp_path):
    db = tmp_path / "state" / "w.db"
    with pytest.raises(StoreError, match="missing.*retire the identity"):
        WitnessStore(db)
    assert not db.exists() and not db.parent.exists()  # nothing created, not even the directory


def test_empty_file_is_refused_without_create(tmp_path):
    db = tmp_path / "w.db"
    db.write_bytes(b"")
    with pytest.raises(StoreError, match="holds no witness state"):
        WitnessStore(db)
    with WitnessStore(db, create=True) as store:
        assert store.get_meta("schema_version") == str(SCHEMA_VERSION)
    WitnessStore(db).close()


def test_foreign_file_is_refused(tmp_path):
    db = tmp_path / "w.db"
    db.write_bytes(b"this is not an SQLite database" * 100)
    with pytest.raises(StoreError, match="cannot"):
        WitnessStore(db, create=True)
    with pytest.raises(StoreError):
        database_status(db)


def test_directory_as_database_path_is_a_store_error(tmp_path):
    with pytest.raises(StoreError, match="cannot open"):
        WitnessStore(tmp_path, create=True)


def test_database_status(tmp_path):
    db = tmp_path / "w.db"
    assert database_status(db) == "missing"
    db.write_bytes(b"")
    assert database_status(db) == "empty"
    WitnessStore(db, create=True).close()
    assert database_status(db) == "initialised"


def test_state_round_trip_and_reopen(tmp_path):
    db = tmp_path / "w.db"
    with WitnessStore(db, create=True) as store:
        assert store.get("log.example/a") is None
        with store.transaction() as tx:
            tx.put("log.example/a", 7, ROOT_A, "note a\n", 100, 101)
        with store.transaction() as tx:
            tx.put("log.example/a", 9, ROOT_B, "note b\n", 102, 103)
    with WitnessStore(db) as store:
        state = store.get("log.example/a")
        assert (state.size, state.root, state.note, state.timestamp, state.updated_at) == (
            9, ROOT_B, "note b\n", 102, 103)
        assert [s.origin for s in store.all_logs()] == ["log.example/a"]
        h = hashlib.sha256(b"log.example/a").hexdigest()
        assert store.get_by_origin_hash(h) == state


def test_failed_transaction_rolls_back(tmp_path):
    with WitnessStore(tmp_path / "w.db", create=True) as store:
        with store.transaction() as tx:
            tx.put("log.example/a", 1, ROOT_A, "n\n", 1, 1)
        with pytest.raises(RuntimeError):
            with store.transaction() as tx:
                tx.put("log.example/a", 2, ROOT_B, "m\n", 2, 2)
                raise RuntimeError("check failed")
        assert store.get("log.example/a").size == 1
        assert not store.failed  # an error in the block is not a store failure


def test_wal_and_full_sync(tmp_path):
    with WitnessStore(tmp_path / "w.db", create=True) as store:
        assert store._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert store._conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL


def test_committed_state_is_in_the_main_file_without_the_wal(tmp_path):
    """Each commit is checkpointed into witness.db, so losing witness.db-wal
    (a copy of the main file only) does not roll the state back."""
    db = tmp_path / "w.db"
    with WitnessStore(db, create=True) as store:
        with store.transaction() as tx:
            tx.put("log.example/a", 5, ROOT_A, "n\n", 1, 1)
        with store.transaction() as tx:
            tx.put("log.example/a", 8, ROOT_B, "m\n", 2, 2)
        copy = tmp_path / "copy" / "w.db"
        copy.parent.mkdir()
        shutil.copyfile(db, copy)  # the main file only, while the store is open
    with WitnessStore(copy) as store:
        assert (store.get("log.example/a").size, store.get("log.example/a").root) == (8, ROOT_B)


def test_transactions_serialize_across_connections(tmp_path):
    """Two stores on one file (two processes, say): read-check-write in one
    transaction cannot interleave."""
    db = tmp_path / "w.db"
    a, b = WitnessStore(db, create=True), WitnessStore(db)
    try:
        with a.transaction() as tx:
            tx.put("log.example/a", 0, ROOT_A, "n\n", 0, 0)

        def bump(store: WitnessStore, rounds: int) -> None:
            for _ in range(rounds):
                with store.transaction() as tx:
                    state = tx.get("log.example/a")
                    tx.put("log.example/a", state.size + 1, ROOT_A, "n\n", 0, 0)

        threads = [threading.Thread(target=bump, args=(s, 50)) for s in (a, b, a, b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert a.get("log.example/a").size == 200
    finally:
        a.close()
        b.close()


# ---------------------------------------------------------------------------
# The database refuses rollbacks
# ---------------------------------------------------------------------------


def test_put_with_a_smaller_size_raises(tmp_path):
    with WitnessStore(tmp_path / "w.db", create=True) as store:
        with store.transaction() as tx:
            tx.put("log.example/a", 9, ROOT_A, "n\n", 1, 1)
        with pytest.raises(StoreError, match="rollback"):
            with store.transaction() as tx:
                tx.put("log.example/a", 8, ROOT_A, "m\n", 2, 2)
        with pytest.raises(StoreError, match="rollback"):
            with store.transaction() as tx:
                tx.put("log.example/a", 9, ROOT_B, "m\n", 2, 2)  # same size, other root
        state = store.get("log.example/a")
        assert (state.size, state.root, state.note) == (9, ROOT_A, "n\n")
        with store.transaction() as tx:  # equal size and root (a re-cosignature) is fine
            tx.put("log.example/a", 9, ROOT_A, "n2\n", 3, 3)
        assert store.get("log.example/a").timestamp == 3


def test_manual_edits_cannot_roll_back(tmp_path):
    db = tmp_path / "w.db"
    with WitnessStore(db, create=True) as store:
        with store.transaction() as tx:
            tx.put("log.example/a", 9, ROOT_A, "n\n", 1, 1)
    conn = sqlite3.connect(db)
    try:
        for sql in (
            "UPDATE logs SET last_size = 3",
            "UPDATE logs SET last_root = x'" + "bb" * 32 + "'",
            "DELETE FROM logs",
            "INSERT OR REPLACE INTO logs VALUES ('log.example/a', 'h', 2, x'" + "cc" * 32 + "', 'n', 0, 0)",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="witness state"):
                conn.execute(sql)
        conn.execute("UPDATE logs SET last_timestamp = 0")  # allowed (clear-timestamp)
        conn.commit()
    finally:
        conn.close()
    with WitnessStore(db) as store:
        assert (store.get("log.example/a").size, store.get("log.example/a").timestamp) == (9, 0)


V1_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE logs (origin TEXT PRIMARY KEY, origin_hash TEXT NOT NULL UNIQUE,
    last_size INTEGER NOT NULL CHECK (last_size >= 0),
    last_root BLOB NOT NULL CHECK (length(last_root) = 32), last_note TEXT NOT NULL,
    last_timestamp INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, origin TEXT NOT NULL,
    received_at INTEGER NOT NULL, reason TEXT NOT NULL, old_size INTEGER NOT NULL,
    known_size INTEGER NOT NULL, known_root BLOB, request BLOB NOT NULL);
CREATE INDEX evidence_by_origin ON evidence (origin);
INSERT INTO meta VALUES ('schema_version', '1');
"""


def test_schema_version_1_is_migrated(tmp_path):
    db = tmp_path / "w.db"
    conn = sqlite3.connect(db)
    conn.executescript(V1_SCHEMA)
    conn.execute("INSERT INTO logs VALUES ('log.example/a', ?, 7, ?, 'n', 5, 5)",
                 (hashlib.sha256(b"log.example/a").hexdigest(), ROOT_A))
    conn.commit()
    conn.close()
    with WitnessStore(db) as store:
        assert store.get_meta("schema_version") == "2"
        assert store.get("log.example/a").size == 7
        with pytest.raises(StoreError, match="rollback"):
            with store.transaction() as tx:
                tx.put("log.example/a", 6, ROOT_A, "n\n", 6, 6)
    conn = sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE logs SET last_size = 1")
    finally:
        conn.close()


def test_newer_schema_is_refused(tmp_path):
    db = tmp_path / "w.db"
    with WitnessStore(db, create=True) as store:
        store.set_meta("schema_version", "99")
    with pytest.raises(StoreError, match="schema version"):
        WitnessStore(db)


def test_root_must_be_32_bytes(tmp_path):
    with WitnessStore(tmp_path / "w.db", create=True) as store:
        with pytest.raises(ValueError):
            with store.transaction() as tx:
                tx.put("log.example/a", 1, b"short", "n\n", 1, 1)


# ---------------------------------------------------------------------------
# A failing COMMIT
# ---------------------------------------------------------------------------


class FailingCommit:
    """Wraps the writer connection; the next COMMIT raises as SQLITE_FULL /
    SQLITE_IOERR would, leaving the real transaction open."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.fail = True

    def execute(self, sql, *args):
        if self.fail and sql.strip().upper() == "COMMIT":
            self.fail = False
            raise sqlite3.OperationalError("database or disk is full")
        return self.conn.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self.conn, name)


def test_failed_commit_is_rolled_back_and_fails_the_store(tmp_path):
    db = tmp_path / "w.db"
    store = WitnessStore(db, create=True)
    calls = []
    store.on_failure = lambda: calls.append(1)
    with store.transaction() as tx:
        tx.put("log.example/a", 4, ROOT_A, "four\n", 1, 1)
    proxy = FailingCommit(store._conn)
    store._conn = proxy
    with pytest.raises(StoreError, match="COMMIT failed"):
        with store.transaction() as tx:
            tx.put("log.example/a", 9, ROOT_A, "nine\n", 2, 2)
    assert not proxy.conn.in_transaction  # explicitly rolled back
    assert store.failed and calls == [1]
    assert not store.healthy()
    # Every later transaction or read on the writer connection is refused ...
    with pytest.raises(StoreError, match="failed earlier"):
        with store.transaction():
            pass
    with pytest.raises(StoreError, match="failed earlier"):
        store.get("log.example/a")
    # ... while the read-only connection serves committed state only.
    h = hashlib.sha256(b"log.example/a").hexdigest()
    assert store.get_by_origin_hash(h).size == 4
    store._conn = proxy.conn
    store.close()
    with WitnessStore(db) as again:
        assert again.get("log.example/a").size == 4


def test_database_error_inside_the_block_is_a_store_error(tmp_path):
    with WitnessStore(tmp_path / "w.db", create=True) as store:
        with pytest.raises(StoreError, match="database error"):
            with store.transaction() as tx:
                tx._conn.execute("SELECT * FROM no_such_table")
        assert not store.failed
        with store.transaction() as tx:
            tx.put("log.example/a", 1, ROOT_A, "n\n", 1, 1)


# ---------------------------------------------------------------------------
# Evidence, metadata, clock recovery
# ---------------------------------------------------------------------------


def test_evidence_cap_and_counts(tmp_path):
    with WitnessStore(tmp_path / "w.db", create=True, evidence_limit=3) as store:
        for i in range(5):
            kept = store.record_evidence("log.example/a", "bad proof", i, 4, ROOT_A, b"req %d" % i,
                                         received_at=1000 + i)
            assert kept == (i < 3)
        store.record_evidence("log.example/b", "bad root", 0, 0, None, b"x")
        assert store.evidence_counts() == {"log.example/a": 3, "log.example/b": 1}
        ev = store.evidence("log.example/a")
        assert [e.request for e in ev] == [b"req 0", b"req 1", b"req 2"]
        assert ev[0].known_root == ROOT_A and ev[0].received_at == 1000
        assert store.evidence("log.example/b")[0].known_root is None


def test_evidence_is_capped_by_bytes(tmp_path):
    with WitnessStore(tmp_path / "w.db", create=True, evidence_byte_limit=1000) as store:
        assert store.record_evidence("log.example/a", "r", 0, 0, None, b"x" * 600)
        assert not store.record_evidence("log.example/a", "r", 0, 0, None, b"y" * 401)
        assert store.record_evidence("log.example/a", "r", 0, 0, None, b"z" * 400)
        assert not store.record_evidence("log.example/a", "r", 0, 0, None, b"!")
        assert store.record_evidence("log.example/b", "r", 0, 0, None, b"w" * 1000)  # per origin
        assert store.evidence_counts() == {"log.example/a": 2, "log.example/b": 1}


def test_witness_vkey_binding(tmp_path):
    db = tmp_path / "w.db"
    with WitnessStore(db, create=True) as store:
        assert store.bind_witness_vkey("w+00000000+AAAA") is None
        assert store.bind_witness_vkey("w+00000000+AAAA") == "w+00000000+AAAA"
    with WitnessStore(db) as store:
        with pytest.raises(StoreError, match="accept-new-key"):
            store.bind_witness_vkey("w+11111111+BBBB")
        assert store.bind_witness_vkey("w+11111111+BBBB", accept_change=True) == "w+00000000+AAAA"
        assert store.get_meta("witness_vkey") == "w+11111111+BBBB"


def test_clear_last_timestamp(tmp_path):
    with WitnessStore(tmp_path / "w.db", create=True) as store:
        with store.transaction() as tx:
            tx.put("log.example/a", 3, ROOT_A, "n\n", 5000, 5000)
            tx.put("log.example/b", 4, ROOT_B, "n\n", 6000, 6000)
        assert store.clear_last_timestamp("log.example/a") == 1
        assert (store.get("log.example/a").timestamp, store.get("log.example/b").timestamp) == (0, 6000)
        assert store.clear_last_timestamp("log.example/none") == 0
        assert store.clear_last_timestamp() == 2
        assert store.get("log.example/b").timestamp == 0
        assert store.get("log.example/b").size == 4

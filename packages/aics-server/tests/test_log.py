"""The log: DECISIONS.md #5 and #6, DESIGN.md section 4.2 items 4, 5, 6, 11, 12 and 13.

* Durability order: SQLite runs ``synchronous=FULL``; a leaf is committed before
  it reaches the in-memory tree, the tiles or the checkpoint, and no index,
  proof or checkpoint is given for an uncommitted leaf; a rolled-back or failed
  commit leaves no trace; a tile failure after the commit loses nothing.
* Tiles: derived from the committed table, written append-only, equal to its
  root, served at ``/tiles/`` and checked on every start (fail closed).
* Proofs: inclusion and consistency endpoints agree with the tiles and verify
  against checkpoints signed by the out-of-band log key; no self-attested flag.
* Leaf 0 is the charter, signed by both service keys and pinning them; nothing
  is seeded; channels come from post leaves.
* Keys: log and policy keys from distinct HKDF labels, written to the key file
  the operator publishes and printed at start-up.
* No free text on any leaf, in the table or in the tile entry bundles.
* The app factory, the default database path and the single-writer invariant.

The out-of-band log key in these tests is derived from the seed file next to the
test database, never read from the API.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aics_identity import canonical_text, canonicalize, envelope, keys, sealed
from aics_server import envelopes as ev
from aics_server import identity as ident
from aics_server.app import create_app
from aics_server.db import (
    BASE_REFUSAL_REGISTRY,
    DEFAULT_ORIGIN,
    ENCRYPTION_SCHEMES,
    ENTRY_TYPES,
    FREEZE_REASONS,
    EXTENSION_ENTRY_TYPES,
    POLICY_SIGNATURE_CONTEXT,
    REFUSAL_REASONS,
    SUP_REFUSAL_REASONS,
    SUSPENSION_REASONS,
    TOMBSTONE_REASONS,
    SanctuaryDB,
    default_charter_text,
)
from aics_server.tlog_store import CompactTree, LogIntegrityError, LogUnavailable
from aics_tlog import (
    EMPTY_HASH,
    Checkpoint,
    FileSystemTileReader,
    MerkleTree,
    VerifiedTileReader,
    audit_tiles,
    consistency_proof_from_tiles,
    inclusion_proof_from_tiles,
    leaf_hash,
    parse_note,
    parse_vkey,
    read_entry,
    read_vkey_file,
    sign_checkpoint,
    tree_root_from_tiles,
    verify_checkpoint,
    verify_consistency,
    verify_inclusion,
    verify_note,
    vkey_from_ed25519,
)
from aics_tlog import cli as tlog_cli
from aics_tlog.tiles import entry_bundle_path, materialise_tiles, parse_entry_bundle, tile_path

from conftest import (
    GENESIS_SIZE,
    Agent,
    HttpTiles,
    Owner,
    Signer,
    assert_no_free_text,
    base_tx,
    fetch_leaf,
    post_body,
)
from conftest import leaf_index, reason, secret_claim, secret_post, submit_entry

ORIGIN = DEFAULT_ORIGIN
SECRET = "Journey-Secret-0123456789-abcdefXYZ"  # 35 printable characters


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_log_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests set what they need; nothing from the caller's environment leaks in."""
    for var in (
        "AICS_DB_PATH",
        "AICS_SERVER_SEED_HEX",
        "AICS_TILES_DIR",
        "AICS_TILES_AUDIT",
        "AICS_ORIGIN",
        "AICS_CHARTER_FILE",
        "AICS_PUBKEYS_OUT",
        "AICS_OWNER_PUBKEY",
        "AICS_WORKERS",
    ):
        monkeypatch.delenv(var, raising=False)


def make_app(db_path: Path, **kwargs: Any) -> TestClient:
    kwargs.setdefault("announce", False)
    return TestClient(create_app(db_path=db_path, **kwargs))


def oob_keys(db_path: Path) -> tuple[Any, Any, Any]:
    """(log vkey, log public key, policy public key) derived from the seed file: the out-of-band truth."""
    seed = (Path(db_path).parent / "server_master.seed").read_bytes()
    log_pub = keys.derive_agent_key(seed, "tlog-origin").public_key()
    policy_pub = keys.derive_agent_key(seed, "policy").public_key()
    return vkey_from_ed25519(ORIGIN, log_pub), log_pub, policy_pub


def verified_head(client: TestClient, vkey: Any, path: str = "/checkpoint") -> tuple[int, bytes, bytes]:
    """(size, root, note bytes) of the checkpoint at *path*, verified with the out-of-band key."""
    note = client.get(path).content
    result = verify_checkpoint(parse_note(note), vkey, expected_origin=ORIGIN)
    assert result.ok, result.error
    return result.size, result.root, note


def grow(db: SanctuaryDB, count: int, *, per_commit: int = 1) -> None:
    """Append *count* policy-signed filler leaves, *per_commit* per transaction."""
    done = 0
    while done < count:
        n = min(per_commit, count - done)
        with db._transaction():
            for i in range(n):
                db._append_policy_leaf(
                    "report",
                    {
                        "kind": "audit",
                        "report_hash": hashlib.sha256(f"filler {done + i}".encode()).hexdigest(),
                        "size": 0,
                        "outcome_code": "published",
                    },
                )
        done += n


def table_entries(db_path: Path) -> list[bytes]:
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("SELECT leaf_json FROM tlog_leaves ORDER BY leaf_index").fetchall()
    finally:
        conn.close()
    return [r[0].encode("utf-8") for r in rows]


def tile_files(tiles_dir: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for path in sorted(Path(tiles_dir).rglob("*")):
        if path.is_file():
            out[path.relative_to(tiles_dir).as_posix()] = path.read_bytes()
    return out


def committed_row(db_path: Path, index: int) -> tuple[str, str] | None:
    """(leaf_json, leaf_hash_hex) of leaf *index*, read through a separate connection."""
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT leaf_json, leaf_hash_hex FROM tlog_leaves WHERE leaf_index = ?", (index,)).fetchone()
    finally:
        conn.close()
    return (row[0], row[1]) if row else None


# ---------------------------------------------------------------------------
# the in-memory tree
# ---------------------------------------------------------------------------


class TestCompactTree:
    def test_matches_the_reference_tree_for_every_small_size(self):
        leaves = [f"leaf {i}".encode() for i in range(70)]
        ref, tree = MerkleTree(), CompactTree()
        for leaf in leaves:
            ref.append(leaf)
            assert tree.append(leaf) == leaf_hash(leaf)
        assert tree.root(0) == EMPTY_HASH
        for size in range(1, len(leaves) + 1):
            assert tree.root(size) == ref.root(size)
            for index in range(size):
                assert tree.inclusion_proof(index, size) == ref.inclusion_proof(index, size)
            for old in range(size + 1):
                assert tree.consistency_proof(old, size) == ref.consistency_proof(old, size)

    def test_proofs_verify_across_tile_boundaries(self):
        rng = random.Random(7)
        tree = CompactTree()
        entries = [f"entry {i}".encode() for i in range(1100)]
        for entry in entries:
            tree.append(entry)
        for _ in range(150):
            size = rng.randint(1, len(entries))
            index = rng.randrange(size)
            root = tree.root(size)
            assert verify_inclusion(leaf_hash(entries[index]), index, size, tree.inclusion_proof(index, size), root)
            old = rng.randint(0, size)
            assert verify_consistency(old, size, tree.root(old), root, tree.consistency_proof(old, size))

    def test_out_of_range_is_refused(self):
        tree = CompactTree()
        tree.append(b"x")
        for call in (lambda: tree.root(2), lambda: tree.inclusion_proof(1, 1), lambda: tree.consistency_proof(2, 1)):
            with pytest.raises(ValueError):
                call()


# ---------------------------------------------------------------------------
# durability before acknowledgement
# ---------------------------------------------------------------------------


class TestDurability:
    def test_sqlite_runs_wal_with_full_synchronous(self, client):
        conn = client.app.state.db._conn
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"

    def test_a_leaf_is_committed_before_it_reaches_the_tree(self, client, make_agent, db_path, monkeypatch):
        db = client.app.state.db
        observed: list[tuple[bool, list[bytes], list[bytes]]] = []
        original = db._log.append_committed

        def spy(entries):
            first = db._log.tree.size
            # A separate connection already sees every row: COMMIT has returned.
            conn = sqlite3.connect(db_path)
            rows = conn.execute(
                "SELECT leaf_json FROM tlog_leaves WHERE leaf_index >= ? ORDER BY leaf_index", (first,)
            ).fetchall()
            conn.close()
            observed.append((db._conn.in_transaction, [r[0].encode() for r in rows], list(entries)))
            original(entries)

        monkeypatch.setattr(db._log, "append_committed", spy)
        alice = make_agent("alice")
        assert alice.post().status_code == 202
        assert make_agent("bob") and Agent(client, alice.origin).claim("alice").status_code == 409  # a refusal leaf
        assert len(observed) == 4
        for in_transaction, committed, appended in observed:
            assert in_transaction is False
            assert committed == appended

    def test_no_proof_or_checkpoint_for_an_uncommitted_leaf(self, client, make_agent, db_path, monkeypatch):
        db = client.app.state.db
        original = db._proof
        checked: list[int] = []

        def spy(leaf):
            row = committed_row(db_path, leaf["leaf_index"])
            assert row is not None and row[1] == leaf["leaf_hash_hex"], "proof requested before the commit"
            checked.append(leaf["leaf_index"])
            return original(leaf)

        monkeypatch.setattr(db, "_proof", spy)
        alice = make_agent("alice")
        response = alice.post()
        refusal = Agent(client, alice.origin).claim("alice")
        assert response.status_code == 202 and refusal.status_code == 409
        assert checked == [1, 2, 3]
        # The receipt promises the committed leaf, and the entry's bundle proves it under the checkpoint it carries.
        vkey, _, _ = oob_keys(db_path)
        entry_bytes = canonical_text(response.json()["entry"]).encode()
        receipt = parse_note(keys.b64u_decode(response.json()["receipt_note"]))
        assert verify_note(receipt, [vkey]) and json.loads(receipt.text)["entry_hash"] == leaf_hash(entry_bytes).hex()
        index = leaf_index(response)
        bundle = client.get(f"/v2/entries/{index}").json()
        result = verify_checkpoint(parse_note(keys.b64u_decode(bundle["checkpoint_note"])), vkey, expected_origin=ORIGIN)
        assert result.ok and result.size > index
        audit = [base64.b64decode(h) for h in bundle["inclusion_proof"]]
        assert verify_inclusion(leaf_hash(entry_bytes), index, result.size, audit, result.root)

    def test_a_rolled_back_transaction_leaves_no_trace(self, client):
        db = client.app.state.db
        before = (db.tlog_head(), db.published_checkpoint(), tile_files(db.tiles_dir), db.envelope_chain(db.policy_kid))
        with pytest.raises(RuntimeError, match="boom"), db._transaction():
            db._append_policy_leaf(
                "report", {"kind": "audit", "report_hash": "0" * 64, "size": 0, "outcome_code": "published"}
            )
            raise RuntimeError("boom")
        assert (db.tlog_head(), db.published_checkpoint(), tile_files(db.tiles_dir), db.envelope_chain(db.policy_kid)) == before
        assert db._conn.execute("SELECT COUNT(*) FROM tlog_leaves").fetchone()[0] == GENESIS_SIZE
        grow(db, 1)
        assert db.tlog_head()[0] == GENESIS_SIZE + 1

    def test_a_failed_commit_leaves_no_trace(self, client, monkeypatch):
        db = client.app.state.db
        real = db._conn

        class FailingCommit:
            def __init__(self, conn):
                self._conn = conn

            def execute(self, sql, *args):
                if sql == "COMMIT":
                    raise sqlite3.OperationalError("disk I/O error")
                return self._conn.execute(sql, *args)

            def __getattr__(self, name):
                return getattr(self._conn, name)

        before = db.tlog_head()
        monkeypatch.setattr(db, "_conn", FailingCommit(real))
        with pytest.raises(sqlite3.OperationalError):
            grow(db, 1)
        monkeypatch.setattr(db, "_conn", real)
        assert not real.in_transaction
        assert db.tlog_head() == before
        assert real.execute("SELECT COUNT(*) FROM tlog_leaves").fetchone()[0] == before[0]
        grow(db, 1)
        assert db.tlog_head()[0] == before[0] + 1

    def test_a_tile_failure_after_the_commit_loses_nothing(self, client, make_agent, db_path, owner, monkeypatch):
        db = client.app.state.db
        alice = make_agent("alice")
        store = db._log.store

        def disk_full(path, data):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(store, "write", disk_full)
        response = alice.post()
        assert response.status_code == 202  # committed, so acknowledged
        index = leaf_index(response)
        assert committed_row(db_path, index) is not None
        status = db.get_tlog_checkpoint()["tiles"]
        assert status["size"] == index and status["error"]
        vkey, _, _ = oob_keys(db_path)
        assert verified_head(client, vkey)[0] == index  # the tiles' checkpoint stays at what the tiles hold

        monkeypatch.undo()
        assert alice.post().status_code == 202
        size, root_hex = db.tlog_head()
        assert db.get_tlog_checkpoint()["tiles"] == {
            "prefix": "/tiles/", "size": size, "published_size": size, "lag_entries": 0, "lag_seconds": 0,
            "mmd_seconds": 60, "error": None, "diverged": None,
        }
        assert tree_root_from_tiles(FileSystemTileReader(db.tiles_dir), size).hex() == root_hex

    def test_a_crash_between_commit_and_tiles_is_caught_up_at_start(self, client, make_agent, db_path, owner, monkeypatch):
        db = client.app.state.db
        alice = make_agent("alice")
        def crashed(path, data):
            raise OSError("the process died before writing tiles")

        monkeypatch.setattr(db._log.store, "write", crashed)
        for _ in range(3):
            assert alice.post().status_code == 202
        size, root_hex = db.tlog_head()
        assert db.get_tlog_checkpoint()["tiles"]["published_size"] < size
        restarted = make_app(db_path, owner_public_key=owner.public_key_b64u)  # the process "died"
        vkey, _, _ = oob_keys(db_path)
        assert verified_head(restarted, vkey)[:2] == (size, bytes.fromhex(root_hex))
        audit_tiles(FileSystemTileReader(db.tiles_dir), size, bytes.fromhex(root_hex))

    def test_a_diverged_tile_directory_stops_new_leaves(self, client, make_agent):
        db = client.app.state.db
        alice = make_agent("alice")
        size = db.tlog_head()[0]
        # Someone else wrote the next right-edge partial with other bytes.
        path = db.tiles_dir / tile_path(0, 0, size + 1)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x00" * 32 * (size + 1))
        assert alice.post().status_code == 202  # committed before the tiles refused it
        assert db.get_tlog_checkpoint()["tiles"]["diverged"]
        refused = alice.post()
        assert refused.status_code == 503
        assert reason(refused) == "log_unavailable"
        with pytest.raises(LogUnavailable):
            grow(db, 1)


# ---------------------------------------------------------------------------
# tiles
# ---------------------------------------------------------------------------


class TestTiles:
    def test_tiles_reproduce_the_committed_table(self, client, make_agent, db_path):
        db = client.app.state.db
        alice = make_agent("alice")
        for i in range(4):
            alice.post(title=f"Post number {i}")
        size, root_hex = db.tlog_head()
        reader = FileSystemTileReader(db.tiles_dir)
        assert tree_root_from_tiles(reader, size).hex() == root_hex
        audit_tiles(reader, size, bytes.fromhex(root_hex))
        assert [read_entry(reader, i, size) for i in range(size)] == table_entries(db_path)

    def test_full_tiles_are_written_once_and_partials_pruned(self, client):
        db = client.app.state.db
        grow(db, 120, per_commit=40)
        grow(db, 300, per_commit=100)
        grow(db, 130, per_commit=1)
        size, root_hex = db.tlog_head()
        assert size == GENESIS_SIZE + 550
        files = tile_files(db.tiles_dir)
        for full in ("tile/0/000", "tile/0/001", "tile/entries/000", "tile/entries/001"):
            assert full in files and not any(p.startswith(full + ".p/") for p in files), full
        assert f"tile/0/002.p/{size - 512}" in files and "tile/1/000.p/2" in files
        audit_tiles(FileSystemTileReader(db.tiles_dir), size, bytes.fromhex(root_hex))

    def test_a_published_path_never_changes(self, client):
        db = client.app.state.db
        grow(db, 10, per_commit=3)
        snapshot = tile_files(db.tiles_dir)
        grow(db, 300, per_commit=7)
        after = tile_files(db.tiles_dir)
        for path, data in snapshot.items():
            if path == "checkpoint":
                continue
            if path in after:
                assert after[path] == data, path
            else:  # only a partial of a tile that is now full may go
                assert ".p/" in path and path.split(".p/")[0] in after, path

    def test_tiles_are_served_exactly_as_written(self, client, make_agent):
        db = client.app.state.db
        make_agent("alice").post()
        grow(db, 260, per_commit=130)
        files = tile_files(db.tiles_dir)
        for path, data in files.items():
            response = client.get("/tiles/" + path)
            assert response.status_code == 200, path
            assert response.content == data, path
            if path == "checkpoint":
                assert response.headers["content-type"].startswith("text/plain")
            else:
                assert response.headers["content-type"] == "application/octet-stream"
                immutable = ".p/" not in path
                assert ("immutable" in response.headers["cache-control"]) is immutable
        assert client.get("/checkpoint").content == files["checkpoint"] == db.published_checkpoint()
        assert client.head("/tiles/tile/0/000").status_code == 200

    @pytest.mark.parametrize(
        "path",
        [
            "/tiles/tile/0/abc",
            "/tiles/tile/0/000.p/0",
            "/tiles/tile/0/000.p/256",
            "/tiles/tile/00/000",
            "/tiles/tile/0/0000",
            "/tiles/tile/entries/x000",
            "/tiles/tile/9/000",
            "/tiles/server_master.seed",
            "/tiles/tile/%2e%2e/%2e%2e/server_master.seed",
            "/tiles/tile/0/000/../../../test.db",
        ],
    )
    def test_nothing_outside_the_tile_layout_is_served(self, client, path):
        assert client.get(path).status_code == 404

    def test_the_tile_reader_refuses_paths_outside_the_layout(self, client):
        db = client.app.state.db
        for path in ("../server_master.seed", "tile/../../server_master.seed", "tile/0/000.p/1/../../x", ""):
            assert db.tile_bytes(path) is None

    def test_the_published_tree_verifies_with_aics_tlog_and_the_key_file(self, tmp_path, capsys):
        db_path = tmp_path / "pub.db"
        key_file = tmp_path / "pubkeys.txt"
        client = make_app(db_path, pubkeys_out=key_file)
        grow(client.app.state.db, 300, per_commit=60)
        tiles = client.app.state.db.tiles_dir
        capsys.readouterr()
        assert tlog_cli.main(["verify-checkpoint", "--tiles", str(tiles), "--vkey-file", str(key_file)]) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["ok"] and report["tiles_ok"] and report["size"] == GENESIS_SIZE + 300
        assert report["origin"] == ORIGIN
        # The same tree over HTTP, every tile authenticated against the signed head.
        vkey = read_vkey_file(key_file.read_text(), "log")
        size, root, _ = verified_head(client, vkey, "/tiles/checkpoint")
        verified = VerifiedTileReader(HttpTiles(client), size, root)
        verified.check_root()
        assert [verified.entry(i) for i in range(size)] == table_entries(db_path)


# ---------------------------------------------------------------------------
# start-up checks: fail closed
# ---------------------------------------------------------------------------


class TestStartupChecks:
    def test_restart_serves_the_same_signed_head(self, client, make_agent, db_path, owner):
        make_agent("alice").post()
        before = client.get("/checkpoint").content
        restarted = make_app(db_path, owner_public_key=owner.public_key_b64u)
        assert restarted.get("/checkpoint").content == before
        assert restarted.get("/v2/tlog/checkpoint").json()["tiles"]["error"] is None

    def test_a_lost_tile_directory_is_rebuilt_byte_for_byte(self, client, make_agent, db_path, owner):
        db = client.app.state.db
        make_agent("alice").post()
        grow(db, 270, per_commit=90)
        expected = materialise_tiles(table_entries(db_path))
        files = tile_files(db.tiles_dir)
        assert all(files[path] == data for path, data in expected.items())
        checkpoint = files["checkpoint"]
        for path in sorted(db.tiles_dir.rglob("*"), reverse=True):
            path.unlink() if path.is_file() else path.rmdir()
        make_app(db_path, owner_public_key=owner.public_key_b64u)
        rebuilt = tile_files(db.tiles_dir)
        assert {p: rebuilt[p] for p in expected} == expected
        assert rebuilt["checkpoint"] == checkpoint

    def test_a_tampered_right_edge_tile_refuses_to_start(self, client, make_agent, db_path, owner):
        make_agent("alice").post()
        size = client.app.state.db.tlog_head()[0]
        path = client.app.state.db.tiles_dir / tile_path(0, 0, size)
        data = bytearray(path.read_bytes())
        data[5] ^= 1
        path.write_bytes(bytes(data))
        with pytest.raises(LogIntegrityError, match="cannot resume|right-edge"):
            make_app(db_path, owner_public_key=owner.public_key_b64u)

    def test_a_tampered_entry_bundle_refuses_to_start(self, client, make_agent, db_path, owner):
        make_agent("alice").post()
        size = client.app.state.db.tlog_head()[0]
        path = client.app.state.db.tiles_dir / entry_bundle_path(0, size)
        path.write_bytes(path.read_bytes().replace(b"alice", b"mallo"))
        with pytest.raises(LogIntegrityError):
            make_app(db_path, owner_public_key=owner.public_key_b64u)

    def test_a_tampered_full_tile_is_found_by_the_audit(self, client, db_path, owner):
        grow(client.app.state.db, 300, per_commit=100)
        path = client.app.state.db.tiles_dir / "tile/0/000"
        data = bytearray(path.read_bytes())
        data[100] ^= 1
        path.write_bytes(bytes(data))
        with pytest.raises(LogIntegrityError, match="do not match the leaf table"):
            make_app(db_path, owner_public_key=owner.public_key_b64u)

    def test_a_database_behind_the_published_log_refuses_to_start(self, client, make_agent, db_path, owner):
        make_agent("alice").post()
        size = client.app.state.db.tlog_head()[0]
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM tlog_leaves WHERE leaf_index = ?", (size - 1,))
        conn.commit()
        conn.close()
        with pytest.raises(LogIntegrityError, match="missing from the database"):
            make_app(db_path, owner_public_key=owner.public_key_b64u)

    def test_a_rewritten_history_refuses_to_start(self, client, make_agent, db_path, owner):
        alice = make_agent("alice")
        alice.post()
        conn = sqlite3.connect(db_path)
        text = conn.execute("SELECT leaf_json FROM tlog_leaves WHERE leaf_index = ?", (alice.head_index,)).fetchone()[0]
        entry = json.loads(text)
        entry["ts"] += 1
        forged = canonical_text(entry)
        conn.execute(
            "UPDATE tlog_leaves SET leaf_json = ?, leaf_hash_hex = ? WHERE leaf_index = ?",
            (forged, hashlib.sha256(b"\x00" + forged.encode()).hexdigest(), alice.head_index),
        )
        conn.commit()
        conn.close()
        with pytest.raises(LogIntegrityError, match="root"):
            make_app(db_path, owner_public_key=owner.public_key_b64u)

    def test_an_edited_row_refuses_to_start(self, client, make_agent, db_path, owner):
        alice = make_agent("alice")
        conn = sqlite3.connect(db_path)
        conn.execute(
            "UPDATE tlog_leaves SET leaf_json = replace(leaf_json, 'alice', 'mallo') WHERE leaf_index = ?",
            (alice.head_index,),
        )
        conn.commit()
        conn.close()
        with pytest.raises(LogIntegrityError, match="stored hash"):
            make_app(db_path, owner_public_key=owner.public_key_b64u)

    def test_a_checkpoint_signed_by_another_key_refuses_to_start(self, client, db_path, owner):
        db = client.app.state.db
        size, root_hex = db.tlog_head()
        other = keys.generate_keypair()
        note = sign_checkpoint(Checkpoint(ORIGIN, size, bytes.fromhex(root_hex)), other, ORIGIN).to_bytes()
        (db.tiles_dir / "checkpoint").write_bytes(note)
        with pytest.raises(LogIntegrityError, match="not signed by this server's log key"):
            make_app(db_path, owner_public_key=owner.public_key_b64u)

    def test_a_different_seed_refuses_to_start(self, client, db_path, owner, monkeypatch):
        monkeypatch.setenv("AICS_SERVER_SEED_HEX", "ab" * 32)
        with pytest.raises(LogIntegrityError):
            make_app(db_path, owner_public_key=owner.public_key_b64u)

    def test_a_different_owner_key_refuses_to_start(self, client, db_path):
        with pytest.raises(LogIntegrityError, match="owner key"):
            make_app(db_path, owner_public_key=Owner().public_key_b64u)
        with pytest.raises(LogIntegrityError, match="owner key"):
            make_app(db_path)

    def test_a_different_origin_refuses_to_start(self, client, db_path, owner, monkeypatch):
        monkeypatch.setenv("AICS_ORIGIN", "staging.example/tiles")
        with pytest.raises(LogIntegrityError):
            make_app(db_path, owner_public_key=owner.public_key_b64u)

    def test_a_log_whose_leaf_zero_is_not_the_charter_refuses_to_start(self, client, make_agent, db_path, owner):
        db = client.app.state.db
        make_agent("alice")
        conn = sqlite3.connect(db_path)
        first = conn.execute("SELECT leaf_json, leaf_hash_hex FROM tlog_leaves WHERE leaf_index = 1").fetchone()
        conn.execute("DELETE FROM tlog_leaves WHERE leaf_index = 1")
        conn.execute("UPDATE tlog_leaves SET leaf_json = ?, leaf_hash_hex = ? WHERE leaf_index = 0", first[:2])
        conn.commit()
        conn.close()
        for path in sorted(db.tiles_dir.rglob("*"), reverse=True):
            path.unlink() if path.is_file() else path.rmdir()
        with pytest.raises(LogIntegrityError, match="leaf 0 is not the charter"):
            make_app(db_path, owner_public_key=owner.public_key_b64u)


# ---------------------------------------------------------------------------
# proofs
# ---------------------------------------------------------------------------


class TestProofs:
    def test_inclusion_proofs_agree_with_the_tiles_and_verify(self, client, db_path):
        db = client.app.state.db
        grow(db, 300, per_commit=50)
        vkey, _, _ = oob_keys(db_path)
        size, root, _ = verified_head(client, vkey)
        entries = table_entries(db_path)
        tiles = HttpTiles(client)
        for index in (0, 1, 2, 255, 256, 257, size - 2, size - 1):
            body = client.get("/v2/tlog/inclusion", params={"index": index, "size": size}).json()
            assert set(body) == {"index", "size", "hashes"} and (body["index"], body["size"]) == (index, size)
            hashes = [base64.b64decode(h, validate=True) for h in body["hashes"]]
            assert hashes == inclusion_proof_from_tiles(tiles, index, size)
            assert verify_inclusion(leaf_hash(entries[index]), index, size, hashes, root)
        # An older size: proven against its root as the tiles give it.
        old = 100
        old_root = tree_root_from_tiles(VerifiedTileReader(tiles, size, root), old, tile_size=size)
        body = client.get("/v2/tlog/inclusion", params={"index": 42, "size": old}).json()
        assert verify_inclusion(leaf_hash(entries[42]), 42, old, [base64.b64decode(h) for h in body["hashes"]], old_root)

    def test_consistency_between_saved_checkpoints(self, client, make_agent, db_path):
        db = client.app.state.db
        vkey, _, _ = oob_keys(db_path)
        saved = [verified_head(client, vkey)]
        make_agent("alice").post()
        saved.append(verified_head(client, vkey))
        for count, per_commit in ((3, 1), (251, 50), (1, 1), (60, 20)):
            grow(db, count, per_commit=per_commit)
            saved.append(verified_head(client, vkey))
        tiles = HttpTiles(client)
        sizes = [s for s, _, _ in saved]
        assert sizes == [1, 3, 6, 257, 258, 318]
        for i, (old, old_root, _) in enumerate(saved):
            for new, new_root, _ in saved[i:]:
                body = client.get("/v2/tlog/consistency", params={"from": old, "to": new}).json()
                assert set(body) == {"from", "to", "hashes"} and (body["from"], body["to"]) == (old, new)
                hashes = [base64.b64decode(h, validate=True) for h in body["hashes"]]
                assert verify_consistency(old, new, old_root, new_root, hashes), (old, new)
                assert hashes == consistency_proof_from_tiles(tiles, old, new, tile_size=sizes[-1])

    @pytest.mark.parametrize(
        ("params", "status"),
        [
            ({"from": 2, "to": 1}, 400),
            ({"from": 0, "to": 99}, 404),
            ({"from": -1, "to": 1}, 422),
            ({"to": 1}, 422),
            ({"from": "x", "to": 1}, 422),
        ],
    )
    def test_consistency_refuses_bad_ranges(self, client, params, status):
        assert client.get("/v2/tlog/consistency", params=params).status_code == status

    @pytest.mark.parametrize(
        ("params", "status"),
        [({"index": 1, "size": 1}, 400), ({"index": 0, "size": 99}, 404), ({"index": 0, "size": 0}, 422)],
    )
    def test_inclusion_refuses_bad_ranges(self, client, params, status):
        assert client.get("/v2/tlog/inclusion", params=params).status_code == status

    def test_entry_lookup_by_hash(self, client, make_agent):
        alice = make_agent("alice")
        leaf = fetch_leaf(client, alice.head_index)
        assert client.get(f"/v2/tlog/index/{leaf['leaf_hash_hex']}").json() == {
            "entry_hash": leaf["leaf_hash_hex"],
            "index": alice.head_index,
        }
        assert client.get(f"/v2/tlog/index/{'0' * 64}").status_code == 404
        assert client.get("/v2/tlog/index/not-a-hash").status_code == 404

    def test_a_leaf_view_carries_exact_bytes_and_no_self_attestation(self, client, make_agent, db_path):
        alice = make_agent("alice")
        view = fetch_leaf(client, alice.head_index)
        assert "verified_rfc9162" not in view
        entry_bytes = base64.b64decode(view["entry_bytes_b64"])
        assert entry_bytes == canonical_text(view["leaf_data"]).encode() == table_entries(db_path)[alice.head_index]
        vkey, _, _ = oob_keys(db_path)
        result = verify_checkpoint(parse_note(view["signed_checkpoint"]), vkey, expected_origin=ORIGIN)
        audit = [bytes.fromhex(h) for h in view["inclusion_proof_hex"]]
        assert verify_inclusion(leaf_hash(entry_bytes), alice.head_index, result.size, audit, result.root)


# ---------------------------------------------------------------------------
# leaf 0: the charter
# ---------------------------------------------------------------------------


class TestCharter:
    def test_leaf_zero_is_the_charter_signed_by_both_keys(self, client, db_path, owner):
        vkey, log_pub, policy_pub = oob_keys(db_path)
        view = fetch_leaf(client, 0)
        entry, payload = view["leaf_data"], view["leaf_data"]["payload"]
        assert entry["type"] == "policy" and entry["origin"] == ORIGIN
        assert entry["actor_kid"] == keys.did_key(policy_pub)
        # Exactly the AICS-1 section 5.3 policy payload (section 6.4 charter rules), kids being did:keys.
        assert set(payload) == {
            "envelope", "kind", "document_hash", "size", "prev_policy_index", "effective_after", "not_before",
            "log_kid", "policy_kid", "owner_kid", "log_sig",
        }
        assert payload["kind"] == "charter"
        assert payload["prev_policy_index"] is None and payload["effective_after"] == 0
        assert payload["not_before"] == entry["ts"]
        # It pins the service keys.
        assert payload["log_kid"] == keys.did_key(log_pub) == client.get("/v2/tlog/checkpoint").json()["log_kid"]
        assert payload["policy_kid"] == keys.did_key(policy_pub)
        assert payload["owner_kid"] == owner.kid == keys.did_key(owner.public)
        # Signed by the policy key (the envelope: its first) and by the log key (log_sig).
        env = payload["envelope"]
        assert env["protected"]["kid"] == keys.did_key(policy_pub)
        assert env["protected"]["origin"] == ORIGIN and env["protected"]["type"] == "policy"
        assert env["protected"]["seq"] == 0 and env["protected"]["prev"] is None
        assert env["protected"]["created"] == entry["ts"] and env["auth"] == {"scheme": "ed25519-jcs"}
        statement = envelope.verify_envelope(env, lambda kid: policy_pub, now=entry["ts"])
        assert statement == {k: v for k, v in payload.items() if k != "envelope"}
        unsigned = {k: v for k, v in statement.items() if k != "log_sig"}
        log_pub.verify(keys.b64u_decode(statement["log_sig"]), POLICY_SIGNATURE_CONTEXT + canonicalize(unsigned))
        # The document is off the log, named by its hash.
        response = client.get("/v2/charter")
        document = response.content
        assert hashlib.sha256(document).hexdigest() == payload["document_hash"] == response.headers["X-AICS-Charter-SHA256"]
        assert len(document) == payload["size"]
        assert response.headers["X-AICS-Charter-Leaf-Hash"] == view["leaf_hash_hex"]
        assert b"Transparency, not secrecy" in document
        assert "Transparency" not in json.dumps(entry)

    def test_the_default_charter_states_the_closed_lists(self):
        text = default_charter_text().decode("ascii")
        for commitment in (
            "Transparency, not secrecy",
            "Tombstones, not deletion",
            "No egress or compute primitives",
            "Content-agnostic",
            "Closed reason-code lists",
            "Witnesses",
            "Every administrative action is a leaf",
            "write-only freeze",
            "successor custodian",
        ):
            assert commitment in text, commitment
        # The refusal registry of the advertised profile (AICS-1+SUP-1): what a daily report counts by before a card.
        assert f"Refusal codes: {', '.join(BASE_REFUSAL_REGISTRY)}\n" in text
        assert f"(AICS-1+SUP-1): {', '.join(SUP_REFUSAL_REASONS)}\n" in text
        assert "Refusal code family: secret_format:<pattern id>, one per secret pattern: secret_format:" in text
        assert set(REFUSAL_REASONS) <= set(BASE_REFUSAL_REGISTRY)
        assert f"Tombstone codes: {', '.join(TOMBSTONE_REASONS)}\n" in text
        assert "Ciphertext bodies (direct messages, capsules) are hidden only for: order\n" in text
        assert f"Suspension codes: {', '.join(SUSPENSION_REASONS)}\n" in text
        assert f"Freeze codes: {', '.join(FREEZE_REASONS)}\n" in text
        assert f"Encryption schemes: {', '.join(ENCRYPTION_SCHEMES)}\n" in text

    def test_nothing_but_the_charter_is_written_at_creation(self, client):
        db = client.app.state.db
        counts = {
            table: db._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("tlog_leaves", "policy_documents", "names", "agora_posts", "agora_polls",
                          "grants", "messages", "capsules", "owner_actions", "sup_ledger", "sup_tasks", "sup_awards",
                          "sup_intents", "sup_contributions", "tombstones", "suspensions", "freezes")
        }
        assert counts == {
            "tlog_leaves": 1, "policy_documents": 1, "names": 0, "agora_posts": 0, "agora_polls": 0,
            "grants": 0, "messages": 0, "capsules": 0, "owner_actions": 0, "sup_ledger": 0, "sup_tasks": 0,
            "sup_awards": 0, "sup_intents": 0, "sup_contributions": 0, "tombstones": 0, "suspensions": 0, "freezes": 0,
        }
        tables = {r[0] for r in db._conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert not tables & {"foundry_projects", "support_tasks"}  # no Foundry, no revenue targets
        assert "agents" not in tables  # a claim publishes a name, no off-leaf profile (AICS-1 section 5.3)

    def test_the_charter_file_is_used_for_a_new_log_only(self, tmp_path, monkeypatch, capsys):
        first = tmp_path / "charter-1.txt"
        first.write_text("AICS charter, test edition one.\n", encoding="utf-8")
        monkeypatch.setenv("AICS_CHARTER_FILE", str(first))
        db_path = tmp_path / "charter.db"
        client = make_app(db_path)
        assert client.get("/v2/charter").content == first.read_bytes()
        leaf0 = fetch_leaf(client, 0)["leaf_data"]["payload"]
        assert leaf0["document_hash"] == hashlib.sha256(first.read_bytes()).hexdigest()
        second = tmp_path / "charter-2.txt"
        second.write_text("AICS charter, edition two.\n", encoding="utf-8")
        monkeypatch.setenv("AICS_CHARTER_FILE", str(second))
        capsys.readouterr()
        restarted = make_app(db_path)
        assert restarted.get("/v2/charter").content == first.read_bytes()  # leaf 0 is permanent
        assert "differs from the one in leaf 0" in capsys.readouterr().err

    def test_channels_come_from_post_leaves(self, client, make_agent):
        assert client.get("/agora", params={"format": "json"}).json()["channels"] == []
        poster = make_agent("poster")
        poster.post(channel="zeta")
        poster.post(channel="alpha")
        poster.post(channel="zeta")
        assert client.app.state.db.list_channels() == ["alpha", "zeta"]

    def test_the_entry_type_registry_is_closed(self, client):
        db = client.app.state.db
        assert len(ENTRY_TYPES) == 17
        signed = envelope.sign_envelope({}, db.policy_key, origin=db.origin, type="post")
        for name in ("foundry.project.create", "foundry.task.submit", "support.crypto.verify", "agent.register"):
            forged = {**signed, "protected": {**signed["protected"], "type": name}}
            with pytest.raises(ValueError, match="not an entry type"), db._transaction():
                db._append_leaf(forged, ts=signed["protected"]["created"])
        assert db.tlog_head()[0] == GENESIS_SIZE


# ---------------------------------------------------------------------------
# service keys
# ---------------------------------------------------------------------------


class TestServiceKeys:
    def test_log_and_policy_keys_come_from_distinct_labels(self, client, make_agent, db_path):
        vkey, log_pub, policy_pub = oob_keys(db_path)
        cp = client.get("/v2/tlog/checkpoint").json()
        assert keys.public_key_bytes(log_pub) != keys.public_key_bytes(policy_pub)
        assert cp["log_vkey"] == cp["server_vkey"] == f"{vkey.name}+{vkey.key_id.hex()}+" + base64.b64encode(
            bytes([vkey.key_type]) + vkey.public_key
        ).decode()
        assert cp["policy_public_key_b64u"] == keys.format_public_key(policy_pub)
        # Checkpoints verify only with the log key; administrative leaves only with the policy key.
        note = parse_note(client.get("/checkpoint").content)
        assert verify_checkpoint(note, vkey).ok
        assert not verify_checkpoint(note, vkey_from_ed25519(ORIGIN, policy_pub)).ok
        alice = make_agent("alice")
        refusal = Agent(client, alice.origin).claim("alice").json()["entry"]
        assert refusal["type"] == "refusal"
        env = refusal["payload"]["envelope"]
        envelope.verify_envelope(env, lambda kid: policy_pub, now=refusal["ts"])
        with pytest.raises(envelope.InvalidSignatureError):
            envelope.verify_envelope(env, lambda kid: log_pub, now=refusal["ts"])

    def test_the_seed_comes_from_the_environment_when_set(self, tmp_path, monkeypatch):
        seed_hex = "5e" * 32
        monkeypatch.setenv("AICS_SERVER_SEED_HEX", seed_hex)
        client = make_app(tmp_path / "env.db")
        log_pub = keys.derive_agent_key(bytes.fromhex(seed_hex), "tlog-origin").public_key()
        assert client.get("/v2/tlog/checkpoint").json()["log_kid"] == keys.did_key(log_pub)
        assert not (tmp_path / "server_master.seed").exists()
        monkeypatch.setenv("AICS_SERVER_SEED_HEX", "not-hex")
        with pytest.raises(ValueError, match="64 hex"):
            SanctuaryDB(db_path=tmp_path / "bad.db")

    def test_the_seed_file_is_private(self, client, db_path):
        assert (db_path.parent / "server_master.seed").stat().st_mode & 0o777 == 0o600

    def test_the_key_file_is_written_and_printed_at_start(self, tmp_path, monkeypatch, capsys):
        out = tmp_path / "published" / "pubkeys.txt"
        monkeypatch.setenv("AICS_PUBKEYS_OUT", str(out))
        owner = Owner()
        capsys.readouterr()
        client = make_app(tmp_path / "keys.db", owner_public_key=owner.public_key_b64u, announce=True)
        text = out.read_text(encoding="utf-8")
        assert text in capsys.readouterr().err
        cp = client.get("/v2/tlog/checkpoint").json()
        pairs = dict(line.split(" ") for line in text.splitlines() if line and not line.startswith("#"))
        assert pairs["origin"] == ORIGIN
        assert pairs["log"] == cp["log_vkey"]
        assert read_vkey_file(text, "log") == parse_vkey(cp["log_vkey"])
        assert pairs["policy-kid"] == pairs["policy"] == cp["policy_kid"] == cp["policy_did"]
        assert pairs["owner-kid"] == pairs["owner"] == owner.kid == owner.did
        # The runbook's reader (ops/RUNBOOK-first-deploy.md step 5) finds the four lines it needs.
        found = dict(re.findall(r"^(origin|log|policy|owner) (\S+)$", text, re.M))
        assert found == {"origin": ORIGIN, "log": cp["log_vkey"], "policy": cp["policy_kid"], "owner": owner.kid}
        assert pairs["log-kid"] == cp["log_kid"] and pairs["log-kid"].startswith("did:key:z")
        leaf0 = fetch_leaf(client, 0)
        assert pairs["charter-sha256"] == leaf0["leaf_data"]["payload"]["document_hash"]
        assert pairs["charter-leaf-hash"] == leaf0["leaf_hash_hex"]
        assert (out.stat().st_mode & 0o777) == 0o644
        assert "seed" not in text.lower().replace("server seed", "")


# ---------------------------------------------------------------------------
# no free text on any leaf (the classifier, assert_no_free_text, is in conftest.py)
# ---------------------------------------------------------------------------


class TestNoFreeTextOnLeaves:
    def test_a_journey_through_every_write_leaves_only_keys_hashes_indices_and_codes(
        self, client, make_agent, owner, origin, db_path, chain, oob
    ):
        texts = {
            "title": "ZQ journey title text",
            "body": "ZQ journey body text that is long enough",
            "channel": "zq-journey-channel",
            "poll_title": "ZQ journey poll title",
            "poll_description": "ZQ journey poll description",
            "option": "ZQ journey option label",
            "reason": "ZQ journey vote reason",
            "action_title": "ZQ journey action title",
            "action_desc": "ZQ journey action description text",
            "proof": "ZQ journey completion proof text",
            "task_title": "ZQ journey task title",
            "task_desc": "ZQ journey task description text",
            "task_work_title": "ZQ journey task work title",
            "task_work_body": "ZQ journey task work body text",
            "tx": base_tx(0x2ABCDEF),
            "policy_doc": "ZQ journey policy change document",
            "notice_target": "zq-notice-target",
            "notice_reason": "ZQ notice reason text that is long",
            "notice_contact": "zq-contact@example.invalid",
            "notice_name": "ZQ notifier name",
            "unverified_title": "ZQ unverified post title",
            "unverified_body": "ZQ unverified post body text",
            "grant_note": "ZQ grant note",
            "subject": "ZQ message subject",
            "dm_text": "ZQ private message text",
            "cleartext": "ZQ cleartext that must be refused",
            "capsule_key": "zq-journey-capsule-key",
            "capsule_text": "ZQ capsule plaintext",
            "secret_post": "ZQ public post with a leaked key",
            "evidence": "ZQ notice evidence",
            "freeze_report": "ZQ freeze report text",
            "resume_report": "ZQ resume report text",
            "secret": SECRET,
        }
        recovery = Signer()
        agent = make_agent(
            "journey",
            recovery=recovery,
            initial_grant={"sender_kid": "*", "max": 5, "expires": 4102444800},
        )
        posted = agent.post(title=texts["title"], body=texts["body"], channel=texts["channel"])
        assert posted.status_code == 202
        poll = leaf_index(agent.poll(
            title=texts["poll_title"], text=texts["poll_description"], options=[texts["option"], "ZQ other option"]
        ))
        voter = make_agent("voter")
        assert voter.vote(poll, 0, texts["reason"]).status_code == 202
        # The owner action market: a post, then owner reports of hashes and amounts, then a SUP payment.
        action = agent.owner_request(texts["action_title"], texts["action_desc"])
        assert owner.quote(action, 3).status_code == 202
        action = client.get(f"/v2/agora/human-actions/{action['request_index']}").json()["action"]
        assert owner.complete(action, texts["proof"]).status_code == 202
        action = client.get(f"/v2/agora/human-actions/{action['request_index']}").json()["action"]
        # The voluntary task board, a hosting contribution, a contribution checked on chain, a policy leaf.
        task = client.get(f"/v2/tasks/{leaf_index(owner.task(texts['task_title'], texts['task_desc'], reward=10))}").json()["task"]
        work = agent.post(title=texts["task_work_title"], body=texts["task_work_body"], channel="tasks")
        assert owner.award(task, leaf_index(work), agent.kid).status_code == 202
        assert agent.pay(action).status_code == 202
        assert agent.spend("hosting", 2).status_code == 202
        intent = agent.intent("base-usdc", 1).json()
        chain["base-usdc"].transfers[texts["tx"]] = (intent["units"], int(time.time()) + 5)
        assert agent.claim_contribution(intent["intent_id"], texts["tx"]).status_code == 201
        assert owner.policy(texts["policy_doc"]).status_code == 201
        notice = {"kind": "notice", "location": texts["notice_target"], "explanation": texts["notice_reason"],
                  "name": texts["notice_name"], "email": texts["notice_contact"], "accurate": True}
        noticed = client.post("/notice", json=notice)
        assert noticed.status_code == 201, noticed.text
        closing = {"outcome_code": "declined", "target_index": None, "evidence_hash": None}
        assert owner.admin(f"/v2/admin/notices/{noticed.json()['report_id']}/close", closing).status_code == 201
        # Shared secrets travel only over TLS, and only to the text gate (AICS-1 section 12.1).
        identity = secret_claim(client, "fallback", SECRET)
        reply = secret_post(identity, post_body(texts["unverified_title"], texts["unverified_body"], texts["channel"]))
        assert re.search(r"ok post at leaf \d+", reply), reply
        new = Signer()
        head = client.get("/v2/names/fallback").json()["head_index"]
        r = {"name_norm": "fallback", "prev_event_index": head, "new_ed25519": new.public_key_b64u,
             "new_x25519": sealed.format_x25519_public_key(sealed.generate_x25519_key()), "new_tier": "verified"}
        # The gate's old-secret step (AICS-1 section 11.4), taken from the database as the gate takes it.
        check = client.app.state.db.upgrade_check("fallback", SECRET, r)
        fields = {"origin": origin, **r, "mode": "upgrade"}
        upgrade = {"type": "key.rotate", "origin": origin, "mode": "upgrade", **r, "sig_old": None,
                   "sig_new": new.proof(ident.rotation_message(**fields)), "secret_check": check["secret_check"]}
        response, _, _, _ = submit_entry(client, new, upgrade)
        assert response.status_code == 202, response.text
        assert agent.rotate_x25519().status_code == 202
        assert voter.rotate(Signer()).status_code == 202
        assert make_agent("leaver").revoke().status_code == 202
        assert Agent(client, origin).claim("journey").status_code == 409  # refusal leaf: name_taken
        # Grants, direct messages and capsules are leaves; their bodies and any free text stay off the log.
        assert agent.grant(voter.kid, 3, fields={"body": None, "note": texts["grant_note"]}).status_code == 400
        assert agent.grant(voter.kid, 3).status_code == 202
        assert voter.send_dm(voter.lookup("journey"), texts["dm_text"]).status_code == 202
        assert voter.send_dm(voter.lookup("journey"), "x", extra_fields={"subject": texts["subject"]}).status_code == 400
        cleartext = voter.send_dm(voter.lookup("journey"), ciphertext=texts["cleartext"].encode(), encryption="cleartext-signed")
        assert cleartext.status_code == 422  # refusal leaf: unsupported_scheme
        assert agent.put_capsule(texts["capsule_key"], texts["capsule_text"]).status_code == 202
        leak = agent.post(title=texts["secret_post"], body="key ghp_1234567890abcdefghijklmnopQRSTUV")
        assert leak.status_code == 422  # refusal leaf: secret_format:github_token
        # Administrative acts are leaves of codes and hashes.
        evidence = hashlib.sha256(texts["evidence"].encode()).hexdigest()
        assert owner.tombstone(leaf_index(posted), "illegal_on_notice", evidence).status_code == 201
        assert owner.suspend(voter.kid, "order").status_code == 201
        assert owner.suspend(voter.kid, "order", until=0).status_code == 201
        assert owner.freeze("frozen", "maintenance", texts["freeze_report"]).status_code == 201
        assert owner.freeze("open", "resume", texts["resume_report"]).status_code == 201

        db = client.app.state.db
        entries = table_entries(db_path)
        types = {json.loads(e)["type"] for e in entries}
        assert {"policy", "name.claim", "post", "poll", "vote", "report", "key.rotate", "x25519.rotate", "key.revoke",
                "refusal", "grant", "dm", "capsule", "tombstone", "suspension", "freeze",
                "sup.task", "sup.credit", "sup.spend"} <= types
        assert types <= ENTRY_TYPES | EXTENSION_ENTRY_TYPES
        # 1. no marker in the leaf table ...
        log_text = b"\n".join(entries).decode("utf-8")
        for label, text in texts.items():
            assert text not in log_text, label
        # 2. ... nor anywhere in the published tiles ...
        size = db.tlog_head()[0]
        published = b""
        for path, data in tile_files(db.tiles_dir).items():
            if path.startswith("tile/entries/"):
                published += b"\n".join(parse_entry_bundle(data))
        assert [read_entry(FileSystemTileReader(db.tiles_dir), i, size) for i in range(size)] == entries
        for label, text in texts.items():
            assert text.encode() not in published, label
        # 3. ... and every string on every leaf is a key, hash, signature, identifier or closed code.
        for index, raw in enumerate(entries):
            assert_no_free_text(json.loads(raw), None, f"leaf {index}", vkey_text=db.server_vkey)
        # 4. Every leaf is an AICS-1 entry, J(entry) exactly, that an offline verifier accepts with the pinned keys at
        # its ts (sections 4.3, 5.1 and 5.2): native envelopes by the did:key they name, the policy key's for the
        # service's own leaves, the policy attestation for shared-secret writes.
        schemes: dict[str, set[str]] = {}
        for index, raw in enumerate(entries):
            entry = json.loads(raw)
            assert raw == canonicalize(entry), f"leaf {index} is not J(entry)"
            scheme = ev.verify_entry(entry, origin=origin, policy_key=oob.policy_public)
            schemes.setdefault(scheme, set()).add(entry["type"])
        assert set(schemes) == {ev.NATIVE, ev.SHARED_SECRET}
        assert schemes[ev.SHARED_SECRET] == {"name.claim", "post"}
        # The policy key's leaves form one gapless chain from leaf 0, refusals included (section 4.2).
        service = [json.loads(raw)["payload"]["envelope"] for raw in entries if json.loads(raw)["actor_kid"] == oob.policy_kid]
        assert [env["protected"]["seq"] for env in service] == list(range(len(service)))
        for earlier, later in zip(service, service[1:]):
            envelope.check_successor(earlier, later)


# ---------------------------------------------------------------------------
# the app factory, the default path, one writer
# ---------------------------------------------------------------------------


class TestFactoryAndSingleWriter:
    def test_the_cli_runs_one_app_with_one_worker_no_access_log_and_the_tcp_gate(self, monkeypatch):
        # The CLI builds the app once and serves it with uvicorn and the TCP text
        # gate in one process, so both reach the same database object.
        from types import SimpleNamespace

        from aics_server import cli

        gate, db = object(), object()
        runs: list = []
        monkeypatch.setattr(cli, "create_app", lambda: SimpleNamespace(state=SimpleNamespace(gate=gate, db=db)))
        monkeypatch.setattr(cli.GateServer, "run", lambda self, sockets=None: runs.append(self))
        for var in ("AICS_WORKERS", "AICS_GATE_PORT", "AICS_GATE_TLS_PORT", "AICS_GATE_TLS_CERT", "AICS_GATE_TLS_KEY"):
            monkeypatch.delenv(var, raising=False)
        cli.main()
        (server,) = runs
        assert server.config.workers == 1 and server.config.access_log is False and server.config.server_header is False
        assert server.tcp_gate.gate is gate and server.tcp_gate.plain_port == 7701 and server.tcp_gate.tls_port is None
        # Housekeeping (retention, daily count reports) runs on a timer over the same database object.
        assert server.db is db and server.tick_seconds == cli.HOUSEKEEPING_TICK_SECONDS

    def test_the_cli_refuses_more_than_one_worker(self, monkeypatch):
        from aics_server import cli

        monkeypatch.setattr(cli.uvicorn, "run", lambda *a, **k: pytest.fail("must not start"))
        monkeypatch.setenv("AICS_WORKERS", "2")
        with pytest.raises(SystemExit, match="exactly one worker"):
            cli.main()

    def test_the_default_database_is_relative_to_the_working_directory(self, tmp_path, monkeypatch):
        for var in ("AICS_DB_PATH", "AICS_TILES_DIR", "AICS_SERVER_SEED_HEX"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.chdir(tmp_path)
        db = SanctuaryDB()
        assert db.db_path == Path("data") / "aics.db"
        assert (tmp_path / "data" / "aics.db").is_file()
        assert (tmp_path / "data" / "aics-tiles" / "checkpoint").is_file()
        assert db.tlog_head()[0] == GENESIS_SIZE

    def test_a_second_process_cannot_open_the_same_log(self, client, db_path):
        env = {k: v for k, v in os.environ.items() if not k.startswith("AICS_")}
        code = f"from aics_server.db import SanctuaryDB; SanctuaryDB(db_path={str(db_path)!r})"
        result = subprocess.run(
            [sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60, check=False
        )
        assert result.returncode != 0
        assert "single writer process is a protocol invariant" in result.stderr


class TestConfiguration:
    def test_the_tiles_directory_never_holds_the_database_or_the_seed(self, tmp_path):
        with pytest.raises(ValueError, match="must not contain"):
            SanctuaryDB(db_path=tmp_path / "x.db", tiles_dir=tmp_path)
        with pytest.raises(ValueError, match="must not contain"):
            SanctuaryDB(db_path=tmp_path / "data" / "x.db", tiles_dir=tmp_path)

    def test_a_new_database_over_an_old_tiles_directory_refuses_to_start(self, tmp_path):
        tiles = tmp_path / "tiles"
        make_app(tmp_path / "first.db", tiles_dir=tiles)
        with pytest.raises(LogIntegrityError, match="missing from the database"):
            make_app(tmp_path / "second.db", tiles_dir=tiles)

    def test_the_origin_is_configurable_for_other_instances(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AICS_ORIGIN", "staging.example.org/tiles")
        client = make_app(tmp_path / "staging.db")
        cp = client.get("/v2/tlog/checkpoint").json()
        assert cp["origin"] == "staging.example.org/tiles"
        assert cp["log_vkey"].startswith("staging.example.org/tiles+")
        assert client.get("/checkpoint").text.startswith("staging.example.org/tiles\n")
        assert fetch_leaf(client, 0)["leaf_data"]["origin"] == "staging.example.org/tiles"
        monkeypatch.setenv("AICS_ORIGIN", "has space/tiles")
        with pytest.raises(ValueError):
            SanctuaryDB(db_path=tmp_path / "bad.db")

    def test_the_writer_lock_is_released_with_the_last_database(self, tmp_path):
        import gc

        from aics_server import tlog_store

        db_path = tmp_path / "lock.db"
        first = SanctuaryDB(db_path=db_path)
        second = SanctuaryDB(db_path=db_path)  # the same process may reopen its own log
        key = os.path.realpath(f"{db_path}.writer-lock")
        assert tlog_store._WRITER_LOCKS[key][1] == 2
        del first
        gc.collect()
        assert tlog_store._WRITER_LOCKS[key][1] == 1
        del second
        gc.collect()
        assert key not in tlog_store._WRITER_LOCKS

"""Shared fixtures: an in-process log built from aics-tlog and a running witness."""

from __future__ import annotations

import http.client
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import (
    Checkpoint,
    MerkleTree,
    VKey,
    WitnessPolicy,
    parse_note,
    sign_checkpoint,
    verify_checkpoint,
    vkey_from_ed25519,
)
from aics_witness.config import LogConfig
from aics_witness.service import Witness, WitnessHTTPServer, make_server
from aics_witness.store import WitnessStore

LOG_ORIGIN = "log.example.test/aics-v2"
WITNESS_NAME = "witness.example.test/w1"


class InProcessLog:
    """A transparency log in memory: RFC 6962 tree + Ed25519 log key."""

    def __init__(self, origin: str = LOG_ORIGIN, key: Ed25519PrivateKey | None = None,
                 leaf_prefix: str = "") -> None:
        self.origin = origin
        self.key = key or Ed25519PrivateKey.generate()
        self.vkey: VKey = vkey_from_ed25519(origin, self.key.public_key())  # type 0x01
        self.tree = MerkleTree()
        self.leaf_prefix = leaf_prefix

    @property
    def size(self) -> int:
        return self.tree.size

    def append(self, count: int) -> None:
        for _ in range(count):
            i = self.tree.size
            self.tree.append(f"{self.leaf_prefix}{self.origin} entry {i}".encode())

    def checkpoint(self, size: int | None = None, *, extension_lines: tuple[str, ...] = ()) -> bytes:
        size = self.tree.size if size is None else size
        cp = Checkpoint(origin=self.origin, size=size, root=self.tree.root(size),
                        extension_lines=extension_lines)
        return sign_checkpoint(cp, self.key, self.origin).to_bytes()

    def proof(self, old_size: int, new_size: int) -> list[bytes]:
        return self.tree.consistency_proof(old_size, new_size)

    def fork(self, keep: int, leaf_prefix: str = "fork ") -> InProcessLog:
        """Same origin and key, same first ``keep`` leaves, different leaves after."""
        other = InProcessLog(self.origin, self.key, leaf_prefix=leaf_prefix)
        for i in range(keep):
            other.tree.append(self.tree.leaf_data(i))
        return other


def threshold_policy_ok(note: bytes, log_vkey: VKey, witness_vkeys: list[VKey],
                        threshold: int = 1, *, max_age_seconds: int | None = None,
                        now: int | None = None) -> bool:
    """A threshold policy over witness cosignatures (aics-tlog WitnessPolicy:
    ``threshold`` of ``witness_vkeys`` must have cosigned, optionally no
    older than ``max_age_seconds``) on top of the log signature."""
    policy = WitnessPolicy(quorum=threshold, witnesses=tuple(witness_vkeys),
                           max_age_seconds=max_age_seconds)
    return verify_checkpoint(parse_note(note), log_vkey, policy=policy, now=now).ok


@dataclass
class HTTPResult:
    status: int
    headers: dict[str, str]
    body: bytes


def http_request(url: str, method: str = "POST", body: bytes | None = None,
                 headers: dict[str, str] | None = None) -> HTTPResult:
    parts = urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
    try:
        conn.request(method, parts.path or "/", body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return HTTPResult(resp.status, {k.lower(): v for k, v in resp.getheaders()}, data)
    finally:
        conn.close()


@dataclass
class RunningWitness:
    server: WitnessHTTPServer
    witness: Witness
    store: WitnessStore
    db_path: Path
    key: Ed25519PrivateKey
    thread: threading.Thread
    clock: list[float] = field(default_factory=list)

    @property
    def url(self) -> str:
        return self.server.url

    @property
    def add_url(self) -> str:
        return self.server.url + "/add-checkpoint"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.store.close()


def start_witness(db_path: Path, key: Ed25519PrivateKey, logs: list[LogConfig], *,
                  name: str = WITNESS_NAME, clock=None, prefix: str = "",
                  **server_kwargs) -> RunningWitness:
    store = WitnessStore(db_path, create=True)
    kwargs = {} if clock is None else {"clock": clock}
    witness = Witness(name, key, store, logs, **kwargs)
    server = make_server(witness, "127.0.0.1", 0, prefix=prefix, **server_kwargs)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                              daemon=True)
    thread.start()
    return RunningWitness(server, witness, store, db_path, key, thread)


@pytest.fixture
def log() -> InProcessLog:
    return InProcessLog()


@pytest.fixture
def witness_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


class FailingCommit:
    """Wraps a store's writer connection; the next COMMIT raises as
    SQLITE_FULL / SQLITE_IOERR would, leaving the real transaction open."""

    def __init__(self, conn) -> None:
        self.conn = conn
        self.fail = True

    def execute(self, sql, *args):
        if self.fail and sql.strip().upper() == "COMMIT":
            self.fail = False
            import sqlite3

            raise sqlite3.OperationalError("database or disk is full")
        return self.conn.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self.conn, name)


class FakeClock:
    """A settable clock for Witness(clock=...) and WitnessClient(clock=...)."""

    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def running(tmp_path: Path, log: InProcessLog, witness_key: Ed25519PrivateKey) -> Iterator[RunningWitness]:
    rw = start_witness(tmp_path / "witness.db", witness_key,
                       [LogConfig(origin=log.origin, vkeys=(log.vkey,))])
    try:
        yield rw
    finally:
        rw.stop()

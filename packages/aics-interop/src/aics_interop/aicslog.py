"""A deterministic AICS-1 log for the transparency-log interop tests.

Entries are AICS-1 entry-v2 objects built with :mod:`aics_interop.spec` (leaf
0 is a dual-signed charter, then name claims and public posts, so that the
log is acceptable to aics-conformance's complete-history verifier).  Tiles,
checkpoint notes and proofs come from **aics-tlog**; cosignatures come from
**aics-witness** (:mod:`aics_interop.witnesses`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import spec

T0 = 1792281600  # 2026-10-18T00:00:00Z, the Appendix A epoch
ORIGIN = "api.interop.test/tiles"
PREFIX = "https://api.interop.test/tiles/"
MIRROR = "https://mirror.interop.test/tiles/"
API_BASE = "https://api.interop.test"
CONSISTENCY_URL = API_BASE + "/v2/tlog/consistency?from={old}&to={new}"
DOMAIN = "interop.test"

SEED = {"log": 0x21, "policy": 0x22, "owner": 0x23, "witness_a": 0x24, "witness_b": 0x25}
WITNESS_NAMES = {"witness_a": "witness-a.interop.test/w1", "witness_b": "witness-b.interop.test/w1"}
AGENT_SEEDS = [0x31, 0x32, 0x33, 0x34]
AGENT_X25519 = [0x41, 0x42, 0x43, 0x44]


@dataclass
class Keys:
    log: Ed25519PrivateKey = field(default_factory=lambda: spec.test_key(SEED["log"]))
    policy: Ed25519PrivateKey = field(default_factory=lambda: spec.test_key(SEED["policy"]))
    owner: Ed25519PrivateKey = field(default_factory=lambda: spec.test_key(SEED["owner"]))

    def log_vkey(self, origin: str = ORIGIN) -> str:
        return spec.vkey(origin, 0x01, spec.raw_public(self.log))


def witness_key(which: str) -> Ed25519PrivateKey:
    return spec.test_key(SEED[which])


def witness_vkey(which: str) -> str:
    return spec.vkey(WITNESS_NAMES[which], 0x04, spec.raw_public(witness_key(which)))


class AicsLog:
    """An append-only list of AICS-1 entries plus the per-key sequence state."""

    def __init__(self, origin: str = ORIGIN, keys: Keys | None = None, tag: str = "main") -> None:
        self.origin = origin
        self.keys = keys or Keys()
        self.tag = tag
        self.entries: list[dict[str, Any]] = []
        self.bodies: dict[int, bytes] = {}  # index -> the off-leaf body the entry commits to
        self.policy_events: list[int] = []
        self._last: dict[str, dict[str, Any]] = {}
        self._agents: list[Ed25519PrivateKey] = []

    # -- writing --------------------------------------------------------

    def _nonce(self) -> bytes:
        return spec.H(f"{self.tag}/{self.origin}/nonce/{len(self.entries)}".encode())[:16]

    def _ts(self) -> int:
        return T0 + len(self.entries)

    def append_envelope(self, key: Ed25519PrivateKey, typ: str, payload: dict[str, Any],
                        nonce: bytes | None = None) -> dict[str, Any]:
        signer = spec.kid(key)
        prior = self._last.get(signer)
        ts = self._ts()
        env = spec.native_envelope(
            key, origin=self.origin, typ=typ, payload=payload, created=ts,
            nonce=nonce if nonce is not None else self._nonce(),
            seq=0 if prior is None else prior["protected"]["seq"] + 1,
            prev=None if prior is None else spec.envelope_hash(prior), seen=None)
        e = spec.entry(env, ts)
        self.entries.append(e)
        self._last[signer] = env
        return e

    CHARTER_BODY = spec.J({"spec": "AICS-1", "interop": "test charter; not a service policy"})

    def charter(self) -> dict[str, Any]:
        body = self.CHARTER_BODY
        k = self.keys
        q = {"kind": "charter", "document_hash": spec.hexH(body), "size": len(body), "prev_policy_index": None,
             "effective_after": 0, "not_before": T0, "log_kid": spec.kid(k.log),
             "policy_kid": spec.kid(k.policy), "owner_kid": spec.kid(k.owner)}
        q["log_sig"] = spec.U64(k.log.sign(b"AICS-1 policy\n" + spec.J(q)))
        return self._with_body(self.append_envelope(k.policy, "policy", q), body, policy=True)

    def card(self, card: dict[str, Any]) -> dict[str, Any]:
        """A ``policy`` entry with ``kind=card`` committing to the full signed card (§13.1, §6.4)."""
        body = spec.J(card)
        k = self.keys
        q = {"kind": "card", "document_hash": spec.hexH(body), "size": len(body),
             "prev_policy_index": self.policy_events[-1], "effective_after": self.size, "not_before": T0,
             "log_kid": spec.kid(k.log), "policy_kid": spec.kid(k.policy), "owner_kid": spec.kid(k.owner),
             "log_sig": None}
        return self._with_body(self.append_envelope(k.policy, "policy", q), body, policy=True)

    def _with_body(self, e: dict[str, Any], body: bytes, *, policy: bool = False) -> dict[str, Any]:
        self.bodies[self.size - 1] = body
        if policy:
            self.policy_events.append(self.size - 1)
        return e

    def claim(self, agent: int) -> dict[str, Any]:
        key = spec.test_key(AGENT_SEEDS[agent])
        x_pub = spec.x25519_public(bytes([AGENT_X25519[agent]]) * 32)
        q = {"name_norm": f"agent{agent}", "prev_event_index": None,
             "ed25519": spec.U64(spec.raw_public(key)), "x25519": spec.U64(x_pub), "tier": "verified",
             "recovery_kid": None, "recovery_pop": None, "initial_grant": None}
        self._agents.append(key)
        return self.append_envelope(key, "name.claim", q)

    def post(self, agent: int, text: str) -> dict[str, Any]:
        key = spec.test_key(AGENT_SEEDS[agent])
        body = spec.J({"channel": "interop", "title": None, "text": text})
        q = {"channel_sha256": spec.hexH(b"interop"), "parent_index": None, "body_hash": spec.hexH(body),
             "size": len(body), "title_sha256": None}
        return self._with_body(self.append_envelope(key, "post", q), body)

    # -- reading --------------------------------------------------------

    @property
    def size(self) -> int:
        return len(self.entries)

    def leaves(self, size: int | None = None) -> list[bytes]:
        n = self.size if size is None else size
        return [spec.J(e) for e in self.entries[:n]]

    def tiles(self, size: int | None = None) -> dict[str, bytes]:
        """Every tile and entry bundle for the first ``size`` entries (aics-tlog TileWriter)."""
        from aics_tlog import TileWriter

        return TileWriter(self.leaves(size)).materialise()

    def root(self, size: int | None = None) -> bytes:
        from aics_tlog import MerkleTree

        leaves = self.leaves(size)
        return MerkleTree(leaves).root(len(leaves))

    def note(self, size: int | None = None, *, root: bytes | None = None,
             key: Ed25519PrivateKey | None = None) -> bytes:
        """The log-signed checkpoint note (aics-tlog sign_checkpoint), no cosignatures."""
        from aics_tlog import Checkpoint, sign_checkpoint

        n = self.size if size is None else size
        cp = Checkpoint(self.origin, n, self.root(n) if root is None else root)
        return sign_checkpoint(cp, key or self.keys.log, self.origin).to_bytes()

    def consistency_proof(self, old: int, new: int | None = None) -> list[bytes]:
        """RFC 9162 proof derived from authenticated tiles (aics-tlog)."""
        from aics_tlog import MemoryTileReader, VerifiedTileReader, consistency_proof_from_tiles

        n = self.size if new is None else new
        reader = VerifiedTileReader(MemoryTileReader(self.tiles(n)), n, self.root(n))
        return consistency_proof_from_tiles(reader, old, n)

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        from aics_tlog import MemoryTileReader, VerifiedTileReader, inclusion_proof_from_tiles

        n = self.size if size is None else size
        reader = VerifiedTileReader(MemoryTileReader(self.tiles(n)), n, self.root(n))
        return inclusion_proof_from_tiles(reader, index, n)

    def verified_reader(self, size: int | None = None) -> Any:
        """aics-tlog VerifiedTileReader over this log's tiles at ``size``."""
        from aics_tlog import MemoryTileReader, VerifiedTileReader

        n = self.size if size is None else size
        return VerifiedTileReader(MemoryTileReader(self.tiles(n)), n, self.root(n))

    def wire_bundle(self, index: int, note: bytes, *, with_body: bool = True) -> dict[str, Any]:
        """The AICS-1 §14.3 wire bundle for ``index`` under ``note`` (proof from aics-tlog tiles)."""
        from aics_tlog import parse_checkpoint, parse_note

        size = parse_checkpoint(parse_note(note).text).size
        e = self.entries[index]
        return spec.wire_bundle(spec.J(e), index, self.inclusion_proof(index, size), note,
                                e["payload"]["envelope"], self.bodies.get(index) if with_body else None)


def standard_log(size: int, *, origin: str = ORIGIN, tag: str = "main", fork_after: int | None = None,
                 fork_tag: str = "fork", card: dict[str, Any] | None = None) -> AicsLog:
    """Charter, an optional card, two claims, then posts; entries from ``fork_after`` on carry ``fork_tag`` text."""
    log = AicsLog(origin=origin, tag=tag)
    log.charter()
    if card is not None:
        log.card(card)
    if log.size < size:
        log.claim(0)
    if log.size < size:
        log.claim(1)
    i = 0
    while log.size < size:
        label = tag if fork_after is None or log.size < fork_after else fork_tag
        log.post(i % 2, f"{label} post {log.size}")
        i += 1
    return log


def trust_bundle(keys: Keys | None = None, origin: str = ORIGIN, card_hash: str = "0" * 64) -> dict[str, Any]:
    k = keys or Keys()
    return spec.trust_bundle(origin=origin, log_vkey=k.log_vkey(origin), policy_kid=spec.kid(k.policy),
                             owner_kid=spec.kid(k.owner), bootstrap_card_hash=card_hash)

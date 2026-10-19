"""Shared fixtures: a local log built with aics-tlog, witnesses, keys from
aics-identity, an AICS-1 assurance card and trust bundle, a fake HTTP
fetcher and a fake DNS resolver."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from aics_identity import keys as idkeys
from aics_tlog import (
    Checkpoint,
    MerkleTree,
    Note,
    cosignature_vkey,
    format_vkey,
    sign_checkpoint,
    sign_cosignature,
    vkey_from_ed25519,
)
from aics_tlog.tiles import TileWriter

from aics_cli.card import REASON_REGISTRIES, card_hash, sign_card
from aics_cli.cli import run
from aics_cli.commands import Env
from aics_cli.dnstxt import TxtResult
from aics_cli.errors import FetchError
from aics_cli.net import Response, join_url
from aics_cli.policy import Policy, save
from aics_cli.trust import TrustBundle

NOW = 1_800_000_000  # fixed clock for every test
DOMAIN = "log.test"
ORIGIN = "api.log.test/tiles"  # AICS-1 §12.2 layout: origin = tile prefix without scheme
PREFIX = "https://api.log.test/tiles/"
TILES = PREFIX
CHECKPOINT_URL = PREFIX + "checkpoint"
MIRROR = "https://tiles.log.test/tiles/"
API_BASE = "https://api.log.test"
CONSISTENCY = API_BASE + "/v2/tlog/consistency?from={old}&to={new}"
CARD_URL = f"https://{DOMAIN}/.well-known/aics-card.json"
TXT_NAME = f"_aics.{DOMAIN}"


class FakeFetcher:
    """URL -> canned response.  Unknown URLs answer 404."""

    def __init__(self) -> None:
        self.routes: dict[str, Any] = {}
        self.requests: list[str] = []

    def set(self, url: str, body: bytes | str, status: int = 200, headers: dict[str, str] | None = None) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.routes[url] = (status, body, headers or {})

    def fail(self, url: str, message: str = "connection refused") -> None:
        self.routes[url] = FetchError(f"cannot fetch {url}: {message}")

    def serve_tiles(self, base: str, tiles: dict[str, bytes]) -> None:
        for path in [u for u in self.routes if u.startswith(join_url(base, "tile/"))]:
            del self.routes[path]
        for path, data in tiles.items():
            self.set(join_url(base, path), data)

    def get(self, url: str, *, max_bytes: int = 1 << 22, accept: str | None = None) -> Response:
        self.requests.append(url)
        r = self.routes.get(url)
        if r is None:
            return Response(404, b"not found", url)
        if isinstance(r, Exception):
            raise r
        status, body, headers = r
        return Response(status, body, url, dict(headers))


class FakeDNS:
    def __init__(self) -> None:
        self.records: dict[str, list[str]] = {}
        self.queries: list[str] = []
        self.ad = False

    def __call__(self, name: str, *, nameserver: str | None = None) -> TxtResult:
        self.queries.append(name)
        if name not in self.records:
            return TxtResult(name=name, resolver="fake", nxdomain=True)
        return TxtResult(name=name, records=list(self.records[name]), ad=self.ad, resolver="fake")


@dataclass
class Witness:
    name: str

    def __post_init__(self) -> None:
        self.key = idkeys.generate_keypair()
        self.vkey = format_vkey(cosignature_vkey(self.name, self.key.public_key()))


class Log:
    """A log whose checkpoints are signed with a key made by aics-identity."""

    def __init__(self, n: int = 0, origin: str = ORIGIN, key=None, entries: list[bytes] | None = None) -> None:
        self.origin = origin
        self.key = key or idkeys.generate_keypair()
        self.vkey = format_vkey(vkey_from_ed25519(origin, self.key.public_key()))
        self.entries = list(entries) if entries is not None else [f"leaf {i}\n".encode() for i in range(n)]

    def append(self, *data: bytes) -> None:
        self.entries.extend(data)

    def grow(self, n: int) -> None:
        self.entries.extend(f"leaf {i}\n".encode() for i in range(len(self.entries), n))

    def root(self, size: int) -> bytes:
        return MerkleTree(self.entries[:size]).root(size)

    def note(self, size: int | None = None, cosigners: list[tuple[Witness, int]] = (), *,
             root: bytes | None = None, key=None) -> str:
        size = len(self.entries) if size is None else size
        root = self.root(size) if root is None else root
        cp = Checkpoint(self.origin, size, root)
        signed = sign_checkpoint(cp, key or self.key, self.origin)
        sigs = list(signed.signatures)
        for w, ts in cosigners:
            _, line = sign_cosignature(w.key, w.name, ts, self.origin, size, root)
            sigs.append(line)
        text = Note(text=signed.text, signatures=tuple(sigs)).serialise()
        return text if isinstance(text, str) else text.decode("utf-8")

    def tiles(self, size: int | None = None) -> dict[str, bytes]:
        size = len(self.entries) if size is None else size
        return TileWriter(self.entries[:size]).materialise()

    def fork(self, at: int) -> Log:
        """Same key and origin; entry ``at`` replaced (a rewritten history)."""
        other = Log(origin=self.origin, key=self.key, entries=self.entries)
        other.entries[at] = b"rewritten " + other.entries[at]
        return other


def did(key) -> str:
    return idkeys.did_key(key.public_key())


ASSURANCE_CLAIMS = {
    "G1": "Authentic authorship", "G2": "Tamper-evident order", "G3": "No leaf deletion",
    "G4": "No silent censorship evidence", "G5": "Single view", "G6": "Private content",
    "G7": "Running code tied to source", "G8": "Verification survives the service",
    "G9": "Consent and inbox completeness", "G10": "Signed, logged card",
    "N1": "Default forward secrecy, metadata secrecy or zero knowledge",
    "N2": "Operator identification, notification, key custody or name recovery",
    "N3": "Proof that users are AI, or prevention of external attacks",
    "N4": "Execution, egress, file hosting, webhooks or liveness signals",
    "N5": "Leaf editing/deletion, guaranteed body history or uninterrupted delivery",
}
PROVEN = {"G2", "G3", "G8"}


def card_body(log: Log, policy_key, owner_key, *, witnesses: list[Witness] = (), quorum: int = 0,
              max_age: int = 300, issued_at: int = NOW - 3600, expires: int = NOW + 30 * 86400,
              tile_prefixes: list[str] | None = None) -> dict[str, Any]:
    return {
        "spec": "AICS-1",
        "version": "0.2-draft",
        "origin": log.origin,
        "issued_at": issued_at,
        "expires": expires,
        "policy_parent_index": None,
        "log_vkey": log.vkey,
        "policy_kid": did(policy_key),
        "owner_kid": did(owner_key),
        "tile_prefixes": tile_prefixes or [PREFIX, MIRROR],
        "api_base": API_BASE,
        "gate": {"tls_host": "gate.log.test", "tls_port": 7700, "plaintext_port": 7701,
                 "https_url": "https://api.log.test/t"},
        "proxy": [{"host": "log.test", "mode": "cloudflare", "tls_termination": "cloudflare-edge"},
                  {"host": "api.log.test", "mode": "dns-only", "tls_termination": "origin"}],
        "witness_policy": {"quorum": quorum, "witnesses": [
            {"name": w.name, "vkey": w.vkey, "trust_domain": "founder", "independent": False} for w in witnesses]},
        "max_checkpoint_age": max_age,
        "mmd_seconds": 60,
        "policy_notice_seconds": 7 * 86400,
        "limits": {"public_body_bytes": 32768, "ciphertext_bytes": 65536, "envelope_window_seconds": 300,
                   "future_skew_seconds": 30, "session_idle_seconds": 900,
                   "writes": {"count": 60, "interval_seconds": 60},
                   "registrations": {"count": 5, "interval_seconds": 3600},
                   "preidentity": {"count": 100, "interval_seconds": 60},
                   "flood_suspension_seconds": 3600},
        "retention": {"dm_seconds": 90 * 86400, "capsule_max_seconds": 365 * 86400,
                      "ciphertext_budget_bytes": 10 * 1024 ** 3, "eviction": "oldest-ts-index"},
        "schemes": ["ed25519-jcs", "text-ed25519", "text-sshsig", "x25519-xsalsa20-poly1305"],
        "tiers": ["verified", "third-party-generated", "unverified"],
        # AICS-1 §17.2 registries, plus the one secret_format:<id> of the card's pattern (§13.1)
        "reason_codes": {k: list(v) + (["secret_format:aws_access_key"] if k == "refusal" else [])
                         for k, v in REASON_REGISTRIES.items()},
        "secret_patterns": [{"id": "aws_access_key", "pattern_hash": "ab" * 32}],
        "policies": {"charter_hash": "11" * 32, "terms_hash": "22" * 32, "privacy_hash": "33" * 32},
        "assurances": [
            {"id": k, "status": "not-offered" if k.startswith("N") else ("proven" if k in PROVEN else "promised"),
             "claim": v, "assumptions": ["log key not compromised"] if k in PROVEN else [], "evidence": []}
            for k, v in ASSURANCE_CLAIMS.items()],
        "spec_versions": {"tlog-tiles": "1.0.0", "tlog-checkpoint": "1.1.0", "signed-note": "1.1.0",
                          "tlog-cosignature": "1.1.0", "tlog-witness": "1.1.0", "a2a-card": "1.0.0"},
    }


@dataclass
class Instance:
    """An AICS instance's published material: log, keys, card, trust bundle."""

    log: Log
    witnesses: list[Witness] = field(default_factory=list)
    quorum: int = 0
    max_age: int = 300

    def __post_init__(self) -> None:
        self.policy_key = idkeys.generate_keypair()
        self.owner_key = idkeys.generate_keypair()
        self.card = self.make_card()
        self.bundle = TrustBundle(origin=self.log.origin, log_vkey=self.log.vkey, policy_kid=did(self.policy_key),
                                  owner_kid=did(self.owner_key), bootstrap_card_hash=card_hash(self.card))

    def make_card(self, **over: Any) -> dict[str, Any]:
        mutate = over.pop("mutate", None)
        body = card_body(self.log, self.policy_key, self.owner_key, witnesses=over.pop("witnesses", self.witnesses),
                         quorum=over.pop("quorum", self.quorum), max_age=over.pop("max_age", self.max_age), **over)
        if mutate:
            mutate(body)
        return sign_card(body, self.policy_key, did(self.policy_key))

    def publish(self, h: Harness, card: dict[str, Any] | None = None) -> None:
        h.dns.records[TXT_NAME] = [self.bundle.txt]
        h.fetcher.set(CARD_URL, json.dumps(card or self.card, indent=1))


def make_policy(home: Path, log: Log, *, witnesses: list[Witness] = (), quorum: int = 0,
                max_age: int | None = 300, policy_kid: str | None = None, owner_kid: str | None = None,
                bootstrap_card_hash: str | None = None, mirrors: list[str] = (),
                sources: dict[str, list[str]] | None = None, consistency_url: str = "") -> Policy:
    pol = Policy(
        origin=log.origin,
        log_vkey=log.vkey,
        policy_kid=policy_kid,
        owner_kid=owner_kid,
        bootstrap_card_hash=bootstrap_card_hash,
        witness_vkeys=[w.vkey for w in witnesses],
        quorum=quorum,
        max_checkpoint_age=max_age,
        witness_meta={w.name: {"trust_domain": "founder", "independent": False} for w in witnesses},
        domain=DOMAIN,
        checkpoint_url=CHECKPOINT_URL,
        tiles_url=TILES,
        card_url=CARD_URL,
        consistency_url=consistency_url,
        mirrors=list(mirrors),
        sources=sources if sources is not None else {"origin": [f"dns:{TXT_NAME}"], "log_vkey": [f"dns:{TXT_NAME}"]},
        created_at="2027-01-01T00:00:00Z",
    )
    save(pol, home, force=True)
    return pol


def policy_for(home: Path, inst: Instance, **kw: Any) -> Policy:
    return make_policy(home, inst.log, witnesses=inst.witnesses, quorum=inst.quorum, max_age=inst.max_age,
                       policy_kid=did(inst.policy_key), owner_kid=did(inst.owner_key),
                       bootstrap_card_hash=inst.bundle.bootstrap_card_hash, **kw)


@dataclass
class Harness:
    home: Path
    fetcher: FakeFetcher
    dns: FakeDNS
    clock: list[int]

    @property
    def env(self) -> Env:
        return Env(fetcher=self.fetcher, resolve_txt=self.dns, clock=lambda: self.clock[0], home=self.home)

    def run(self, *argv: str) -> tuple[int, dict[str, Any]]:
        """Run the CLI with --json; returns (exit code, parsed output)."""
        buf = io.StringIO()
        code = run([*argv, "--json"], env=self.env, out=buf)
        text = buf.getvalue()
        try:
            return code, json.loads(text)
        except ValueError:
            raise AssertionError(f"not one JSON object: {text!r}") from None

    def run_text(self, *argv: str) -> tuple[int, str]:
        buf = io.StringIO()
        code = run(list(argv), env=self.env, out=buf)
        return code, buf.getvalue()

    def serve(self, log: Log, size: int | None = None, cosigners: list[tuple[Witness, int]] = (),
              *, url: str = CHECKPOINT_URL, tiles: str | None = TILES) -> str:
        note = log.note(size, cosigners)
        self.fetcher.set(url, note)
        if tiles:
            self.fetcher.serve_tiles(tiles, log.tiles(size))
        return note


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    return Harness(home=tmp_path / "aics-home", fetcher=FakeFetcher(), dns=FakeDNS(), clock=[NOW])

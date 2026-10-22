"""Shared fixtures: a local log built with aics-tlog, witnesses, keys from
aics-identity, an AICS-1 assurance card and trust bundle, a fake HTTP
fetcher and a fake DNS resolver.

The suite runs against the trust bundle this package really ships
(``aics_cli.published_keys``: wesupport-ai.com, checked in
test_published_keys.py); for the fake ``log.test`` domain it is "published for
wesupport-ai.com (...), not log.test".  A test whose assertions are about the
package before that release asks for ``placeholder_pypi``."""

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
        self.sequences: dict[str, list[bytes]] = {}

    def set(self, url: str, body: bytes | str, status: int = 200, headers: dict[str, str] | None = None) -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.sequences.pop(url, None)
        self.routes[url] = (status, body, headers or {})

    def set_sequence(self, url: str, bodies: list[bytes | str]) -> None:
        """Answer each GET of ``url`` with the next body; the last one stays."""
        self.set(url, bodies[-1])
        self.sequences[url] = [b.encode("utf-8") if isinstance(b, str) else b for b in bodies]

    def fail(self, url: str, message: str = "connection refused") -> None:
        self.routes[url] = FetchError(f"cannot fetch {url}: {message}")

    def serve_tiles(self, base: str, tiles: dict[str, bytes]) -> None:
        for path in [u for u in self.routes if u.startswith(join_url(base, "tile/"))]:
            del self.routes[path]
        for path, data in tiles.items():
            self.set(join_url(base, path), data)

    def get(self, url: str, *, max_bytes: int = 1 << 22, accept: str | None = None) -> Response:
        self.requests.append(url)
        seq = self.sequences.get(url)
        if seq:
            return Response(200, seq.pop(0) if len(seq) > 1 else seq[0], url, {})
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


POLICIES_URL = API_BASE + "/v2/policies"
DAY = 86400


def _sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


class Site:
    """An AICS-1 instance whose cards are logged the way aics-server logs them (AICS-1 §6.4, §13.1): leaf 0 the
    charter countersigned by the log key, then one ``policy`` leaf of kind ``card`` per card, each an entry v2 whose
    envelope the policy key signed.  :meth:`publish` serves DNS, the card at the well-known URL, ``GET
    /v2/policies``, ``GET /v2/policies/<index>``, the checkpoint and the tiles through the fake fetcher.

    The first card (leaf 1) is the bootstrap card the trust bundle pins.  ``notice`` is every card's
    ``policy_notice_seconds``."""

    LISTED = ("kind", "document_hash", "size", "prev_policy_index", "effective_after", "not_before")

    def __init__(self, *, witnesses: list[Witness] = (), quorum: int = 0, max_age: int = 300,
                 notice: int = 7 * DAY, genesis: int = NOW - 30 * DAY) -> None:
        from aics_identity.canonical import canonicalize

        self.witnesses, self.quorum, self.max_age, self.notice = list(witnesses), quorum, max_age, notice
        self.log_key, self.policy_key, self.owner_key = (idkeys.generate_keypair() for _ in range(3))
        self.log = Log(origin=ORIGIN, key=self.log_key, entries=[])
        self.last_envelope: dict[str, Any] | None = None
        self.rows: list[dict[str, Any]] = []
        self.documents: dict[int, bytes] = {}
        self.cards: dict[int, dict[str, Any]] = {}
        charter = b"site charter: a test log of packages/aics-cli\n"
        q = {"kind": "charter", "document_hash": _sha256_hex(charter), "size": len(charter),
             "prev_policy_index": None, "effective_after": 0, "not_before": genesis,
             "log_kid": idkeys.did_key(self.log_key.public_key()), "policy_kid": did(self.policy_key),
             "owner_kid": did(self.owner_key)}
        q["log_sig"] = b64u(self.log_key.sign(b"AICS-1 policy\n" + canonicalize(q)))
        self.policy_leaf(q, ts=genesis, document=charter)
        self.first = self.log_card(self.make_card(issued_at=genesis + 30, expires=NOW + 300 * DAY),
                                   ts=genesis + 60, not_before=genesis + 60)
        self.bundle = TrustBundle(origin=ORIGIN, log_vkey=self.log.vkey, policy_kid=did(self.policy_key),
                                  owner_kid=did(self.owner_key), bootstrap_card_hash=card_hash(self.cards[self.first]))

    @property
    def last_policy_index(self) -> int:
        return self.rows[-1]["leaf_index"]

    def card_of(self, index: int) -> dict[str, Any]:
        return self.cards[index]

    def make_card(self, **over: Any) -> dict[str, Any]:
        """A card signed by the policy key whose ``policy_parent_index`` is the last policy leaf (the server's rule)."""
        mutate = over.pop("mutate", None)
        body = card_body(self.log, self.policy_key, self.owner_key, witnesses=over.pop("witnesses", self.witnesses),
                         quorum=over.pop("quorum", self.quorum), max_age=over.pop("max_age", self.max_age), **over)
        body["policy_parent_index"] = self.last_policy_index
        body["policy_notice_seconds"] = self.notice
        if mutate:
            mutate(body)
        return sign_card(body, self.policy_key, did(self.policy_key))

    def policy_leaf(self, q: dict[str, Any], *, ts: int, document: bytes, key=None) -> int:
        """Append a ``policy`` entry whose envelope ``key`` (default: the policy key) signs at ``ts``."""
        from aics_identity import envelope as idenv
        from aics_identity.canonical import canonicalize

        key = key or self.policy_key
        prior = self.last_envelope if key is self.policy_key else None
        env = idenv.sign_envelope(q, key, origin=ORIGIN, type="policy", created=ts,
                                  seq=prior["protected"]["seq"] + 1 if prior else 0,
                                  prev=idenv.envelope_hash(prior) if prior else None, types=idenv.SUP_PROFILE_TYPES)
        if key is self.policy_key:
            self.last_envelope = env
        entry = {"v": 2, "origin": ORIGIN, "type": "policy", "actor_kid": did(key), "ts": ts,
                 "payload": {"envelope": env, **env["payload"]}}
        self.log.append(canonicalize(entry))
        index = len(self.log.entries) - 1
        self.documents[index] = document
        self.rows.append({"leaf_index": index, **{k: q[k] for k in self.LISTED}})
        return index

    def card_statement(self, card: dict[str, Any], *, not_before: int, **over: Any) -> dict[str, Any]:
        from aics_identity.canonical import canonicalize

        doc = canonicalize(card)
        q = {"kind": "card", "document_hash": _sha256_hex(doc), "size": len(doc),
             "prev_policy_index": self.last_policy_index, "effective_after": len(self.log.entries),
             "not_before": not_before, "log_kid": idkeys.did_key(self.log_key.public_key()),
             "policy_kid": did(self.policy_key), "owner_kid": did(self.owner_key), "log_sig": None}
        q.update(over)
        return q

    def log_card(self, card: dict[str, Any], *, ts: int, not_before: int, **over: Any) -> int:
        """Log ``card`` as a policy leaf of kind card (``over`` changes the statement); returns its index."""
        from aics_identity.canonical import canonicalize

        index = self.policy_leaf(self.card_statement(card, not_before=not_before, **over), ts=ts,
                                 document=canonicalize(card))
        self.cards[index] = card
        return index

    def successor(self, *, ts: int = NOW - DAY, notice: int | None = None, **over: Any) -> int:
        """Log a successor card at ``ts`` taking effect ``notice`` (default: the card's notice) later."""
        card = self.make_card(issued_at=over.pop("issued_at", ts - 2), expires=over.pop("expires", NOW + 365 * DAY),
                              **over)
        return self.log_card(card, ts=ts, not_before=ts + (self.notice if notice is None else notice))

    def filler(self, n: int) -> None:
        """``n`` entries that are not policy leaves (the agents' traffic)."""
        start = len(self.log.entries)
        self.log.append(*(f"agent leaf {i}\n".encode() for i in range(start, start + n)))

    def listing(self, rows: list[dict[str, Any]] | None = None) -> str:
        rows = self.rows if rows is None else rows
        return json.dumps({"count": len(rows), "policies": rows, "notice_seconds": self.notice,
                           "tree_size": len(self.log.entries)})

    def publish(self, h: Harness, served: int | dict[str, Any] | None = None, *, cosigners=(), listing: bool = True,
                size: int | None = None) -> None:
        """Serve everything; ``served`` is the card at the well-known URL (a leaf index or a card; default: the
        first card).  ``cosigners`` are (witness, timestamp) pairs on the checkpoint."""
        h.dns.records[TXT_NAME] = [self.bundle.txt]
        card = self.cards[self.first if served is None else served] if not isinstance(served, dict) else served
        h.fetcher.set(CARD_URL, json.dumps(card, indent=1))
        if listing:
            h.fetcher.set(POLICIES_URL, self.listing())
        else:
            h.fetcher.routes.pop(POLICIES_URL, None)
        for i, doc in self.documents.items():
            h.fetcher.set(f"{POLICIES_URL}/{i}", doc)
        h.serve(self.log, size, list(cosigners))

    def pin(self, h: Harness, *, force: bool = False) -> tuple[int, dict[str, Any]]:
        """``aics policy init --from-dns`` (one source: the fake DNS)."""
        return h.run("policy", "init", "--from-dns", DOMAIN, "--require-sources", "1", *(["--force"] if force else []))

    def policy(self, h: Harness) -> Policy:
        """Pin by hand what ``policy init`` takes from the bundle and the first card (no card is stored)."""
        return make_policy(h.home, self.log, witnesses=self.witnesses, quorum=self.quorum, max_age=self.max_age,
                           policy_kid=did(self.policy_key), owner_kid=did(self.owner_key),
                           bootstrap_card_hash=self.bundle.bootstrap_card_hash)


def b64u(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


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
    #: Every wait a command asked for (aics_cli.checkpoints.fetch_checked); the tests never really sleep.
    sleeps: list[float] = field(default_factory=list)

    @property
    def env(self) -> Env:
        return Env(fetcher=self.fetcher, resolve_txt=self.dns, clock=lambda: self.clock[0], home=self.home,
                   sleep=self.sleeps.append)

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


@pytest.fixture
def placeholder_pypi(monkeypatch: pytest.MonkeyPatch) -> None:
    """The aics package before the production-key release: no AICS_TRUST_BUNDLE constant, reported as
    "placeholder" and never counted as a source."""
    from aics_cli import published_keys as pk

    monkeypatch.setattr(pk, "PLACEHOLDER", True)
    monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE", None)
    monkeypatch.setattr(pk, "AICS_TRUST_BUNDLE_SHA256", None)

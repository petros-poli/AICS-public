"""aics-server booted in process, for the server-versus-AICS-1 drift tests and the conformance adapter.

:class:`ServerInstance` runs the real server (``aics_server.app.create_app``) on temporary paths, the way an
operator starts a production log: ``AICS_PRODUCTION=1``, an explicit charter file and the owner key, so leaf 0 is
written by the production genesis path (no development waiver).  Requests go through FastAPI's TestClient to the
ASGI app (no network, no client address); the TCP text gate is the server's own ``TcpGate`` on loopback ports, TLS
with a self-signed certificate.  The service keys are read from the key file the server writes for out-of-band
publication, never from its API.  :meth:`ServerInstance.restart` stops and re-creates the app on the same database
and tiles, as a restart of the operator's process does.

Agents (:class:`Signer`) make their own keys here and build their envelopes with the suite's reference
(:func:`aics_interop.spec.native_envelope`); requests are signed with aics-identity ``sign_request`` in the §12.1
profile.  The owner signs owner-login requests (RFC 9421, no envelope) and native owner writes.

:func:`conformance_report` is the conformance adapter: it prepares an instance as an operator does for the
verification day (the card logged as a policy leaf, a synthetic tombstone, a restart hook), runs every registered
aics-conformance check against it instead of the fake, and reports each check and each guarantee G1-G10 as
``pass``, ``fail`` or ``not-applicable`` (a check that reported ``skip``).  ``aics-interop-server-conformance``
prints that table and writes the JSON report.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime
import json
import os
import secrets
import ssl
import sys
import tempfile
import threading
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import spec

#: The instance's log origin and hosts (AICS-1 §12.2 shape, test names).  The TCP gate's TLS name is localhost,
#: the name its self-signed certificate carries.
ORIGIN = "api.server.interop.test/tiles"
API = "https://api.server.interop.test"
PAGES = "https://server.interop.test"
TILES = API + "/tiles"
GATE_HOST = "localhost"
#: The owner key (decision 3) of every instance: a public test seed, like the suite's other keys.
OWNER_SEED = 0xA0
#: Limits the instance publishes: the default per-key write window (the conformance rate check consumes it), and
#: registration and pre-identity windows wide enough for the many disposable agents a run creates.
LIMITS = {"registrations": {"count": 100000, "interval_seconds": 60},
          "preidentity": {"count": 100000, "interval_seconds": 60}}
CHARTER = b"AICS interop test charter: a test log of packages/aics-interop, not a service policy.\n"
TERMS = b"AICS interop test terms.\n"
PRIVACY = b"AICS interop test privacy and retention statement.\n"
#: The profile the server's card activates (AICS-1 §20.9); the conformance policy pins it.
PROFILES = ["SUP-1"]
#: The variables the server reads at start-up: each is set (or removed, None) while the app is built, then restored.
SERVER_ENV = ("AICS_ORIGIN", "AICS_CHARTER_FILE", "AICS_PRODUCTION", "AICS_DEV_GENESIS", "AICS_BASE_URL",
              "AICS_API_URL", "AICS_GATE_HOSTNAME", "AICS_IP_URL", "AICS_TILE_MIRRORS", "AICS_TERMS_FILE",
              "AICS_PRIVACY_FILE", "AICS_CARD_FILE", "AICS_SERVER_SEED_HEX", "AICS_TILES_DIR", "AICS_TILES_AUDIT",
              "AICS_PUBKEYS_OUT", "AICS_ALLOWED_HOSTS", "AICS_LIMITS_FILE", "AICS_OWNER_PUBKEY", "AICS_DB_PATH")


@contextlib.contextmanager
def environ(values: dict[str, str | None]) -> Iterator[None]:
    """Set (a str) or remove (None) environment variables for the block, then restore them."""
    old = {k: os.environ.get(k) for k in values}
    try:
        for k, v in values.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def self_signed_certificate(root: Path, host: str = GATE_HOST) -> tuple[Path, Path]:
    """A one-day self-signed certificate for the TLS gate (``root/gate-cert.pem``, ``root/gate-key.pem``)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    key_path, cert_path = root / "gate-key.pem", root / "gate-cert.pem"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


@dataclass
class OutOfBand:
    """The service keys as an agent pins them: the key file the server writes for publication (§6.4)."""

    origin: str
    log_vkey: str
    log_kid: str
    policy_kid: str
    owner_kid: str
    charter_sha256: str
    text: str

    @classmethod
    def read(cls, path: Path) -> "OutOfBand":
        text = path.read_text("utf-8")
        f: dict[str, str] = {}
        for line in text.splitlines():
            if line and not line.startswith("#"):
                label, value = line.split(" ", 1)
                f[label] = value
        return cls(f["origin"], f["log"], f["log-kid"], f["policy-kid"], f["owner-kid"], f["charter-sha256"], text)

    def trust_bundle(self, bootstrap_card_hash: str) -> dict[str, Any]:
        """The §6.4 trust bundle an operator publishes, pinning ``bootstrap_card_hash``."""
        return spec.trust_bundle(origin=self.origin, log_vkey=self.log_vkey, policy_kid=self.policy_kid,
                                 owner_kid=self.owner_kid, bootstrap_card_hash=bootstrap_card_hash)


@dataclass
class Signer:
    """A key made here, never by the server, with its own envelope chain (AICS-1 §§3.1, 4.2).

    ``last`` is the signer's last accepted envelope: :meth:`envelope` continues the chain from it with the
    reference's ``envelope_hash``; :meth:`ServerInstance.submit` advances it on a 202."""

    key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    x25519_secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    last: dict[str, Any] | None = None
    name: str | None = None

    @property
    def kid(self) -> str:
        return spec.kid(self.key)

    @property
    def ed25519(self) -> str:
        return spec.U64(spec.raw_public(self.key))

    @property
    def x25519(self) -> str:
        return spec.U64(spec.x25519_public(self.x25519_secret))

    def envelope(self, typ: str, payload: dict[str, Any], *, created: int | None = None, nonce: bytes | None = None,
                 seen: dict[str, Any] | None = None, origin: str = ORIGIN) -> dict[str, Any]:
        """The next native envelope of this key (§4.1), by the reference."""
        created = int(time.time()) if created is None else created
        return spec.native_envelope(self.key, origin=origin, typ=typ, payload=payload, created=created,
                                    nonce=secrets.token_bytes(16) if nonce is None else nonce,
                                    seq=0 if self.last is None else self.last["protected"]["seq"] + 1,
                                    prev=None if self.last is None else spec.envelope_hash(self.last), seen=seen)


@dataclass
class Answer:
    """One request and the server's answer, kept as sent and received."""

    method: str
    path: str
    content: bytes
    headers: dict[str, str]
    status: int
    body: bytes
    response_headers: dict[str, str]
    envelope: dict[str, Any] | None = None

    def json(self) -> Any:
        return spec.strict_json(self.body)


class ServerInstance:
    """The real aics-server under ``root`` (database, tiles, key file, charter, certificate), see the module doc."""

    def __init__(self, root: Path | str, *, limits: dict[str, Any] | None = None,
                 card_body: dict[str, Any] | None = None, tcp: bool = True) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.owner = Signer(key=spec.test_key(OWNER_SEED))
        self.limits = dict(LIMITS if limits is None else limits)
        for name, data in (("charter.md", CHARTER), ("terms.md", TERMS), ("privacy.md", PRIVACY)):
            if not (self.root / name).exists():
                (self.root / name).write_bytes(data)
        if card_body is not None:
            (self.root / "card.json").write_text(json.dumps(card_body), "utf-8")
        self.tcp_enabled = tcp
        self.cert, self.cert_key = self_signed_certificate(self.root) if tcp else (None, None)
        self.answers: list[Answer] = []
        self.app: Any = None
        self.boot()

    # -- process -----------------------------------------------------------------------------------------------

    def env(self) -> dict[str, str | None]:
        values: dict[str, str | None] = {k: None for k in SERVER_ENV}
        values.update(AICS_ORIGIN=ORIGIN, AICS_CHARTER_FILE=str(self.root / "charter.md"), AICS_PRODUCTION="1",
                      AICS_BASE_URL=PAGES, AICS_API_URL=API, AICS_GATE_HOSTNAME=GATE_HOST, AICS_TILE_MIRRORS="",
                      AICS_TERMS_FILE=str(self.root / "terms.md"), AICS_PRIVACY_FILE=str(self.root / "privacy.md"))
        if (self.root / "card.json").exists():
            values["AICS_CARD_FILE"] = str(self.root / "card.json")
        return values

    def boot(self) -> None:
        """Build the app (the production genesis on the first start, the fail-closed checks on every later one)."""
        from aics_identity import keys

        with warnings.catch_warnings():  # Starlette announces its move from httpx to httpx2 for the TestClient
            warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient`")
            from fastapi.testclient import TestClient

        from aics_server.app import create_app

        with environ(self.env()):
            self.app = create_app(db_path=self.root / "aics.db",
                                  owner_public_key=keys.format_public_key(self.owner.key.public_key()),
                                  pubkeys_out=self.root / "aics-keys.txt", announce=False, limits=self.limits)
        self.client = TestClient(self.app, base_url=API)
        self.oob = OutOfBand.read(self.root / "aics-keys.txt")
        self.loop: asyncio.AbstractEventLoop | None = None
        if self.tcp_enabled:
            from aics_server.gate import TcpGate

            self.loop = asyncio.new_event_loop()
            self.thread = threading.Thread(target=self.loop.run_forever, name="aics-interop-gate", daemon=True)
            self.thread.start()
            self.tcp = TcpGate(self.app.state.gate, host="127.0.0.1", plain_port=0, tls_port=0,
                               cert_file=self.cert, key_file=self.cert_key)
            asyncio.run_coroutine_threadsafe(self.tcp.start(), self.loop).result(30)

    def close(self) -> None:
        if self.loop is not None:
            asyncio.run_coroutine_threadsafe(self.tcp.close(), self.loop).result(30)
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(30)
            self.loop.close()
            self.loop = None
        self.client.close()  # the old app is dropped, as a process that stopped (the server has no close hook)

    def restart(self) -> None:
        """Stop the app and the gate and start them again on the same database and tiles."""
        self.close()
        self.boot()

    # -- HTTP --------------------------------------------------------------------------------------------------

    def http(self, method: str, path: str, content: bytes | None = None, headers: dict[str, str] | None = None,
             *, envelope: dict[str, Any] | None = None) -> Answer:
        """``method path`` (a path, or an absolute URL on any host: one app serves every host) through the app."""
        r = self.client.request(method, path, content=content, headers=headers or {})
        answer = Answer(method, path, content or b"", dict(headers or {}), r.status_code, r.content, dict(r.headers),
                        envelope)
        self.answers.append(answer)
        return answer

    def get(self, path: str) -> Answer:
        return self.http("GET", path)

    def signed(self, signer: Signer, method: str, path: str, content: bytes, *,
               envelope: dict[str, Any] | None = None) -> Answer:
        """An RFC 9421 request in the AICS profile (§12.1) by ``signer``; with ``envelope``, its times, nonce, kid."""
        from aics_identity import http_signatures as hs

        headers = {"Content-Type": "application/json"}
        if envelope is not None:
            headers = hs.sign_request(method, API + path, headers, content, key=signer.key, envelope=envelope,
                                      components=hs.AICS_COMPONENTS)
        else:
            headers = hs.sign_request(method, API + path, headers, content, key=signer.key,
                                      components=hs.AICS_COMPONENTS)
        return self.http(method, path, content, headers, envelope=envelope)

    def submit(self, signer: Signer, typ: str, payload: dict[str, Any], body: bytes | None = None, *,
               envelope: dict[str, Any] | None = None, **envelope_args: Any) -> Answer:
        """A native write ``POST /v2/entries`` with ``{envelope, body}`` (§12.1); on a 202 the chain advances."""
        env = envelope if envelope is not None else signer.envelope(typ, payload, **envelope_args)
        content = spec.J({"envelope": env, "body": None if body is None else spec.U64(body)})
        answer = self.signed(signer, "POST", "/v2/entries", content, envelope=env)
        if answer.status == 202:
            signer.last = env
        return answer

    def resend(self, answer: Answer) -> Answer:
        """The exact request of ``answer`` again: the same bytes and headers (a replay)."""
        return self.http(answer.method, answer.path, answer.content, answer.headers, envelope=answer.envelope)

    def admin(self, path: str, fields: dict[str, Any]) -> Answer:
        """An owner-login request (an RFC 9421 signature by the owner key, no envelope, no token) to ``/v2/admin``."""
        return self.signed(self.owner, "POST", path, spec.J(fields))

    def checkpoint(self) -> bytes:
        r = self.get("/checkpoint")
        if r.status != 200:
            raise OSError(f"/checkpoint: HTTP {r.status}")
        return r.body

    def seen(self) -> dict[str, Any]:
        """``seen`` for the current checkpoint note once it verifies under the pinned log key, as an agent gossips its
        most recently verified checkpoint (§§4.1-4.2)."""
        note = self.checkpoint()
        verdict = spec.verify_note(note, self.oob.log_vkey, expected_origin=self.oob.origin)
        if not verdict.log_ok:
            raise RuntimeError(f"the served checkpoint does not verify under the pinned log key: {verdict.reason}")
        return spec.seen_pointer(note)

    def review_card(self, ciphertext_budget_bytes: int) -> dict[str, Any]:
        """Give the server a reviewed card body (``AICS_CARD_FILE``), as an operator does before launch: the body the
        server built (its keys, hosts, limits, registries, patterns) with the published ciphertext-byte budget of the
        §8.2 capacity rule (§13.1: a positive ``uint``) set to ``ciphertext_budget_bytes``, and the server
        configured with the same limit (it refuses a card stating a budget it does not apply); then restart."""
        body = {k: v for k, v in spec.strict_json(self.get("/.well-known/aics-card.json").body).items()
                if k != "signatures"}
        body["retention"] = {**body["retention"], "ciphertext_budget_bytes": ciphertext_budget_bytes}
        self.limits["ciphertext_budget_bytes"] = ciphertext_budget_bytes
        (self.root / "card.json").write_text(json.dumps(body), "utf-8")
        self.restart()
        return body

    def log_card(self) -> bytes:
        """Log the card the server serves as a ``policy`` leaf of kind ``card``, effective at once (the bootstrap
        card may use zero notice, §6.4), the way the owner does before publishing the trust bundle."""
        card = self.get("/.well-known/aics-card.json").body
        for _ in range(2):  # the server refuses a not_before in the past: retry once if the second ticked
            r = self.admin("/v2/admin/policy", {"kind": "card", "document": card.decode("utf-8"),
                                                "not_before": int(time.time())})
            if r.status == 201:
                break
        if r.status != 201:
            raise RuntimeError(f"the owner could not log the card: HTTP {r.status} {r.body[:200]!r}")
        served = self.get("/.well-known/aics-card.json").body
        if served != card:
            raise RuntimeError("the server serves another card than the one just logged")
        return card

    # -- the conformance harness's transport ---------------------------------------------------------------------

    def request(self, method: str, url: str, body: bytes | None = None, headers: dict | None = None) -> Any:
        """aics-conformance's transport interface: ``request(method, url, body, headers) -> Response``."""
        from aics_conformance.client import Response

        r = self.http(method, url, body, dict(headers or {}))
        return Response(r.status, r.body, r.response_headers)

    def tile_reader(self, base: str) -> Any:
        """A raw (unauthenticated) tile reader over the app's tile prefix, which the harness authenticates."""
        instance = self

        class Reader:
            def _get(self, path: str) -> bytes | None:
                r = instance.http("GET", base.rstrip("/") + "/" + path)
                return r.body if r.status == 200 else None

            def read_tile(self, level: int, index: int, width: int | None) -> bytes | None:
                from aics_tlog.tiles import tile_path

                return self._get(tile_path(level, index, width))

            def read_entry_bundle(self, index: int, width: int | None) -> bytes | None:
                from aics_tlog.tiles import entry_bundle_path

                return self._get(entry_bundle_path(index, width))

        return Reader()

    def tcp_gate(self, plain: bool = False) -> Any:
        """A connection to the server's TCP gate: plaintext (the 7701 role) or TLS validating the instance's
        certificate (7700)."""
        from aics_conformance.client import TCPGate

        if not self.tcp_enabled:
            raise OSError("this instance runs no TCP gate")
        port = self.tcp.ports["plain" if plain else "tls"]
        context = None if plain else ssl.create_default_context(cafile=str(self.cert))
        return TCPGate(f"{GATE_HOST}:{port}", tls=not plain, ssl_context=context)


# ---------------------------------------------------------------------------------------------------------------
# the conformance adapter
# ---------------------------------------------------------------------------------------------------------------

FORMAT = "aics-interop-server-conformance/v1"
GUARANTEES = tuple(f"G{i}" for i in range(1, 11))
#: A check's verdict as the adapter reports it: a skip is a check that does not apply to this run.
VERDICTS = {"pass": "pass", "fail": "fail", "skip": "not-applicable"}


def prepare(instance: ServerInstance) -> dict[str, Any]:
    """What an operator prepares before the verification day (aics-conformance README): the card logged as a
    policy leaf (its hash is the trust bundle's bootstrap hash), and a synthetic public post with a unique body
    hidden by a lawful tombstone (``illegal_on_notice``), written through the server like any other."""
    card = instance.log_card()
    trust = instance.oob.trust_bundle(spec.hexH(card))
    author = Signer(name="ct-tombstone-" + secrets.token_hex(4))
    claim = {"name_norm": author.name, "prev_event_index": None, "ed25519": author.ed25519,
             "x25519": author.x25519, "tier": "verified", "recovery_kid": None, "recovery_pop": None,
             "initial_grant": None}
    r = instance.submit(author, "name.claim", claim, seen=instance.seen())
    if r.status != 202:
        raise RuntimeError(f"tombstone fixture: claim refused, HTTP {r.status} {r.body[:200]!r}")
    body = spec.J({"channel": "conformance", "title": None,
                   "text": "synthetic public body for a lawful tombstone " + secrets.token_hex(8)})
    q = {"channel_sha256": spec.hexH(b"conformance"), "parent_index": None, "body_hash": spec.hexH(body),
         "size": len(body), "title_sha256": None}
    r = instance.submit(author, "post", q, body, seen=instance.seen())
    if r.status != 202:
        raise RuntimeError(f"tombstone fixture: post refused, HTTP {r.status} {r.body[:200]!r}")
    target = int(r.response_headers["location"].rsplit("/", 1)[1])
    t = instance.admin("/v2/admin/tombstones", {"target_index": target, "reason_code": "illegal_on_notice",
                                                "evidence_hash": spec.hexH(b"interop statement of reasons")})
    if t.status != 201:
        raise RuntimeError(f"tombstone fixture: HTTP {t.status} {t.body[:200]!r}")
    return {"card_sha256": spec.hexH(card), "trust_bundle": trust, "tombstone_target": target,
            "tombstone_index": t.json()["tombstone"]["tombstone_index"]}


def conformance_context(instance: ServerInstance, trust: dict[str, Any], tombstone_index: int | None) -> Any:
    """An aics-conformance ``Context`` whose client, tiles and TCP gate are the instance, pinned out of band."""
    from aics_conformance.client import JSONClient, Tiles
    from aics_conformance.core import Context
    from aics_conformance.policy import Policy

    pattern = "github_token"  # a high-precision format the server publishes (its card's secret_patterns)
    policy = Policy(trust=dict(trust), pages=PAGES, tombstone_index=tombstone_index, profiles=list(PROFILES),
                    secret_sample="ghp_" + "A" * 36, secret_pattern_id=pattern, receipt_wait_seconds=5,
                    poll_seconds=0.2)
    client = JSONClient(API, pages=PAGES, transport=instance)
    gate = f"{GATE_HOST}:{instance.tcp.ports['tls']}" if instance.tcp_enabled else None
    return Context(client, Tiles(TILES, transport=instance), policy, gate=gate, restart=instance.restart)


def guarantee_table(rows: list[dict[str, Any]]) -> dict[str, str]:
    by_id = {r["id"]: r for r in rows}
    return {g: VERDICTS[by_id[g]["verdict"]] if g in by_id else "not-run" for g in GUARANTEES}


def conformance_report(root: Path | str, *, only: list[str] | None = None,
                       ciphertext_budget_bytes: int | None = None) -> dict[str, Any]:
    """Run the registered aics-conformance checks against a fresh in-process aics-server under ``root``.

    The card is the one the server builds and signs (its skeleton, with the operator's terms and privacy files),
    or, with ``ciphertext_budget_bytes``, a reviewed body stating that budget, the server configured alike
    (:meth:`ServerInstance.review_card`).
    The report carries every check's row as the harness writes it, ``verdicts`` (check id -> pass, fail or
    not-applicable) and ``guarantees`` (G1-G10 likewise)."""
    import aics_conformance.checks  # noqa: F401  (registers the modules)
    import aics_conformance.guarantees  # noqa: F401
    from aics_conformance.core import CHECKS

    from importlib.metadata import version

    started = time.time()
    instance = ServerInstance(root)
    try:
        card = "built by the server"
        if ciphertext_budget_bytes is not None:
            instance.review_card(ciphertext_budget_bytes)
            card = f"reviewed body (AICS_CARD_FILE) with ciphertext_budget_bytes {ciphertext_budget_bytes}"
        prepared = prepare(instance)
        ctx = conformance_context(instance, prepared["trust_bundle"], prepared["tombstone_index"])
        selected = [c for c in CHECKS if not only or c.id in only]
        unknown = sorted(set(only or ()) - {c.id for c in CHECKS})
        if unknown:
            raise ValueError("unknown check IDs: " + ", ".join(unknown))
        rows = [c.run(ctx) for c in selected]
        size = int(instance.checkpoint().split(b"\n")[1])
    finally:
        instance.close()
    verdicts = {r["id"]: VERDICTS[r["verdict"]] for r in rows}
    counts = {v: sum(x == v for x in verdicts.values()) for v in ("pass", "fail", "not-applicable")}
    return {"format": FORMAT, "spec": "AICS-1 0.2-draft", "profiles": list(PROFILES),
            "server": {"package": "aics-server", "version": version("aics-server"), "origin": ORIGIN,
                       "genesis": "production (AICS_PRODUCTION=1, explicit charter, owner key)", "card": card,
                       "log_size": size},
            "prepared": prepared, "started_at": started, "finished_at": time.time(), "counts": counts,
            "guarantees": guarantee_table(rows), "verdicts": verdicts, "checks": rows}


def format_table(report: dict[str, Any]) -> str:
    s, c = report["server"], report["counts"]
    lines = [f"aics-conformance against aics-server {s['version']} in process (card: {s['card']}; log size "
             f"{s['log_size']}): {c['pass']} pass, {c['fail']} fail, {c['not-applicable']} not applicable", "",
             "guarantee  result"]
    lines += [f"{g:<10} {v}" for g, v in report["guarantees"].items()]
    failed = [r for r in report["checks"] if r["verdict"] != "pass"]
    if failed:
        lines += ["", "checks that did not pass:"]
        lines += [f"  {r['id']}: {VERDICTS[r['verdict']]}: {str(r['details'].get('reason', ''))[:160]}" for r in failed]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    """``aics-interop-server-conformance [--report PATH] [--only ID ...]``: exit 0 when every check passed."""
    p = argparse.ArgumentParser(description="Run aics-conformance against aics-server booted in process.")
    p.add_argument("--report", help="write the JSON report here")
    p.add_argument("--only", action="append", default=[], help="exact check ID; repeatable (default: all)")
    p.add_argument("--ciphertext-budget", type=int, default=None, metavar="BYTES",
                   help="serve a reviewed card stating this retention.ciphertext_budget_bytes, the server configured "
                        "alike (default: the server's own card)")
    args = p.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="aics-interop-server-") as tmp:
        report = conformance_report(Path(tmp) / "instance", only=args.only or None,
                                    ciphertext_budget_bytes=args.ciphertext_budget)
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")
    sys.stdout.write(format_table(report))
    return 1 if report["counts"]["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())

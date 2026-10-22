"""The real aics-server with a witness at quorum 1, checked by the real verifiers (AICS-1 sections 6.3, 10.1, 14.3).

The relaunch's first card lists the founder witness at quorum 1.  The walk-throughs of 2026-10-20 found the server
serving a note before its witness cosigned it (``/checkpoint``) and proving bundles against the log-signed note of
the whole tree (``GET /v2/entries/{index}``), so ``aics verify message`` exited 1 and ``aics-tlog
verify-checkpoint --quorum 1`` failed intermittently.  Here aics-server boots in process at a production genesis
(:class:`aics_interop.server.ServerInstance`), feeds an in-process aics-witness that answers in tens of
milliseconds (a witness on another host), and states that witness at quorum 1 in the card it logs; entries are
written and read back at once, as an agent does:

* every ``/checkpoint`` fetched right after a write passes ``aics-tlog verify-checkpoint --quorum 1 --max-age 300``
  and aics's own ``verify checkpoint`` under the pinned quorum-1 policy;
* every bundle fetched right after its write (the server waits for the cosigned note that covers it) is ``valid``
  for ``aics verify message`` pinned at quorum 1, its checkpoint meeting the witness policy;
* every aics-conformance check passes with the witness pinned at quorum 1 and no wait for a cosignature allowed:
  no head, lookup or bundle the harness fetches is ever one the card's policy rejects.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import json
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_interop import drivers, server, spec


def start_witnessed(tmp_path, monkeypatch, *, tcp: bool, delay: float) -> tuple[Any, str, Callable[[], None]]:
    """``(instance, witness_vkey, stop)``: the instance restarted to feed an in-process aics-witness that answers
    after ``delay`` seconds; the card it builds from then on states that witness at quorum 1."""
    from aics_tlog import cosignature_vkey, format_vkey, parse_vkey
    from aics_witness.config import LogConfig
    from aics_witness.service import Witness, make_server
    from aics_witness.store import WitnessStore

    instance = server.ServerInstance(tmp_path / "instance", tcp=tcp)
    name = "witness.interop.test/w1"
    key = Ed25519PrivateKey.generate()
    vkey = format_vkey(cosignature_vkey(name, key.public_key()))
    store = WitnessStore(tmp_path / "witness.db", create=True)
    witness = Witness(name, key, store, [LogConfig(origin=server.ORIGIN, vkeys=(parse_vkey(instance.oob.log_vkey),))])
    answer = witness.add_checkpoint

    def from_another_host(body: bytes) -> bytes:
        time.sleep(delay)
        return answer(body)

    witness.add_checkpoint = from_another_host  # type: ignore[method-assign]
    http = make_server(witness, "127.0.0.1", 0)
    thread = threading.Thread(target=http.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    monkeypatch.setenv("AICS_WITNESSES", f"w1={http.url}={vkey}")
    monkeypatch.setenv("AICS_WITNESS_STATE_DIR", str(tmp_path / "witness-state"))

    def stop() -> None:
        try:
            instance.app.state.db.stop_witness_feeder()
            instance.close()
        finally:
            http.shutdown()
            http.server_close()
            thread.join(5)
            store.close()

    try:
        instance.restart()  # the card the server builds now states the witness it feeds, at quorum 1
    except BaseException:
        stop()
        raise
    return instance, vkey, stop


@pytest.fixture()
def witnessed(tmp_path, monkeypatch):
    """``(instance, witness_vkey)``: the instance restarted to feed a slow in-process aics-witness, card logged."""
    instance, vkey, stop = start_witnessed(tmp_path, monkeypatch, tcp=False, delay=0.05)
    try:
        yield instance, vkey
    finally:
        stop()


def test_every_checkpoint_and_bundle_read_right_after_a_write_verifies_at_quorum_1(witnessed, tmp_path):
    from aics_tlog.cli import main as aics_tlog

    instance, vkey = witnessed
    card = instance.log_card()
    assert json.loads(card)["witness_policy"]["quorum"] == 1
    trust = instance.oob.trust_bundle(spec.hexH(card))
    cli = drivers.AicsCli(home=tmp_path / "home", now=int(time.time()))
    pinned = cli.pin(spec.readme_block(spec.J(trust)), witnesses=[vkey], quorum=1, prefix=server.TILES + "/")
    assert pinned.code == 0, pinned.data
    note, bundle = tmp_path / "checkpoint.note", tmp_path / "bundle.json"
    tiles = instance.root / "aics-tiles"
    for i in range(6):
        agent = server.Signer(name=f"witnessed{i}")
        q = {"name_norm": agent.name, "prev_event_index": None, "ed25519": agent.ed25519, "x25519": agent.x25519,
             "tier": "verified", "recovery_kid": None, "recovery_pop": None, "initial_grant": None}
        written = instance.submit(agent, "name.claim", q, seen=instance.seen())
        assert written.status == 202, written.body[:300]
        index = int(written.response_headers["location"].rsplit("/", 1)[1])

        note.write_bytes(instance.checkpoint())  # at once, as the walk-through fetched it
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = aics_tlog(["verify-checkpoint", "--note", str(note), "--log-key", instance.oob.log_vkey,
                              "--witness-key", vkey, "--quorum", "1", "--max-age", "300", "--origin", server.ORIGIN])
        assert code == 0, out.getvalue()[-400:]
        r = cli.run("verify", "checkpoint", "--note", str(note), "--no-save")
        assert r.code == 0 and r.data["fresh_cosignatures"] == 1, r.data

        fetched = instance.get(f"/v2/entries/{index}")  # waits for the cosigned note that covers the entry
        assert fetched.status == 200, fetched.body[:300]
        bundle.write_bytes(fetched.body)
        r = cli.run("verify", "message", "--bundle", str(bundle), "--offline", "--tiles", str(tiles))
        assert r.code == 0 and r.data["result"] == "valid", r.data
        assert r.data["checkpoint"]["witness_policy_met"] is True
    health = json.loads(instance.get("/healthz").body)
    assert health["serving_uncosigned"] is False and health["served_size"] == health["published_size"]
    assert [(w["name"], w["cosigner"]) for w in health["witnesses"]] == [("w1", "witness.interop.test/w1")]


def test_aics_conformance_at_quorum_1_never_meets_an_uncosigned_head(tmp_path, monkeypatch):
    """Every registered aics-conformance check, the guarantees G1-G10 included, against the server feeding its
    witness, with a policy that pins that witness at quorum 1 and allows no wait for a cosignature (where the
    harness has ``witness_wait_seconds``, it is 0): every current head, every lookup's stated head and every
    bundle's checkpoint the harness fetches carries the cosignature the first time, around every write it makes,
    across the restart of G3 and through the TCP gate.  A server that served each new checkpoint before its
    witness cosigned it fails most checks this way ("quorum not met: 0 valid fresh cosignatures < 1")."""
    import aics_conformance.checks  # noqa: F401  (registers the modules)
    import aics_conformance.guarantees  # noqa: F401
    from aics_conformance.core import CHECKS
    from aics_conformance.policy import Policy

    instance, vkey, stop = start_witnessed(tmp_path, monkeypatch, tcp=True, delay=0.05)
    try:
        prepared = server.prepare(instance)
        card = json.loads(instance.get("/.well-known/aics-card.json").body)
        assert card["witness_policy"]["quorum"] == 1 and spec.hexH(spec.J(card)) == prepared["card_sha256"]
        ctx = server.conformance_context(instance, prepared["trust_bundle"], prepared["tombstone_index"])
        no_wait = {"witness_wait_seconds": 0} if "witness_wait_seconds" in {f.name for f in dataclasses.fields(Policy)} else {}
        ctx.policy = dataclasses.replace(ctx.policy, witness_vkeys=[vkey], quorum=1, **no_wait)

        def restart() -> None:  # a process restart: the old app's witness threads end with it
            instance.app.state.db.stop_witness_feeder()
            instance.restart()

        ctx.restart = restart
        rows = [check.run(ctx) for check in CHECKS]
        health = json.loads(instance.get("/healthz").body)
    finally:
        stop()
    failed = {r["id"]: str(r["details"].get("reason", ""))[:200] for r in rows if r["verdict"] == "fail"}
    assert not failed, failed
    verdicts = {r["id"]: r["verdict"] for r in rows}
    assert {g: verdicts.get(g) for g in server.GUARANTEES} == {g: "pass" for g in server.GUARANTEES}
    assert health["serving_uncosigned"] is False and health["served_size"] == health["published_size"]

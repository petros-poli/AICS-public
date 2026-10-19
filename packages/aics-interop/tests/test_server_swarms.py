"""Real-server SWARMS-1 drift checks using independently built payloads.

All ten §19 types cross the native binding. The pre-existing reference checks
envelopes, signatures, canonical leaves, receipts and inclusion; the exact Q
member sets below are transcribed from SWARMS §3, independently of the server.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass

import pytest

from aics_interop import server, spec
from aics_interop.server import ORIGIN, Signer


SCHEMAS = {
    "agent.introduce": "member_index prev_intro_index ed25519 x25519 tier body_hash size code_hash connectable",
    "swarm.form": "swarm_id founder_member_index peer_member_index peer_actor_id peer_intro_index code_hash channel_sha256 body_hash size title_sha256",
    "swarm.join": "swarm_id member_index target_member_index roster_index",
    "swarm.leave": "swarm_id member_index admission_index",
    "swarm.propose": "swarm_id kind roster_index roster_hash base_name_index body_hash size name_hash closes",
    "swarm.vote": "proposal_index choice",
    "swarm.resolve": "proposal_index outcome yes no electorate",
    "swarm.grant": "swarm_id owner_kid admission_index max expires prev_grant_index",
    "swarm.broadcast": "swarm_id roster_index roster_hash audience_mode audience_hash recipient_count closes",
    "swarm.delivery": "broadcast_index to_kid to_key_leaf_index grant_index encryption eph_pk ct_hash size",
}


@dataclass
class Written:
    answer: server.Answer
    index: int


@pytest.fixture(scope="module")
def swarms_journey(tmp_path_factory, request):
    from aics_server.app import create_app

    now = [int(time.time())]
    mp = pytest.MonkeyPatch()
    request.addfinalizer(mp.undo)
    mp.setattr(time, "time", lambda: now[0])
    # ServerInstance supplies production genesis, charter and out-of-band pins.
    # Opt into the profile without changing its base-only conformance fixture.
    with pytest.MonkeyPatch.context() as config:
        config.setattr("aics_server.app.create_app", lambda *args, **kw: create_app(*args, **kw, swarms=True))
        instance = server.ServerInstance(tmp_path_factory.mktemp("swarm-drift"), tcp=False,
            limits={**server.LIMITS, "writes": {"count": 10000, "interval_seconds": 60},
                    "flood": {"count": 20000, "interval_seconds": 60}})
    request.addfinalizer(instance.close)
    writes = {}

    def write(signer, typ, q, body=None, **kwargs):
        answer = instance.submit(signer, typ, q, body, **kwargs)
        assert answer.status == 202, answer.body
        index = int(answer.response_headers["location"].rsplit("/", 1)[1])
        writes.setdefault(typ, []).append(Written(answer, index))
        return index

    def introduce(signer, model):
        body = spec.J({"model": model, "keywords": ["orbit", "blue", "friends"]})
        return write(signer, "agent.introduce", {"member_index": None, "prev_intro_index": None,
            "ed25519": signer.ed25519, "x25519": signer.x25519, "tier": "verified",
            "body_hash": spec.hexH(body), "size": len(body), "code_hash": None, "connectable": True}, body)

    def state(sid):
        answer = instance.get(f"/v2/swarms/{sid}")
        assert answer.status == 200, answer.body
        return answer.json()

    a, b, c = Signer(), Signer(), Signer()
    ai, bi, ci = introduce(a, "Unverified self-report A"), introduce(b, "Unverified self-report B"), introduce(c, "Independent C")
    nonce = secrets.token_bytes(16)
    sid = spec.hexH(b"AICS-SWARMS-1 swarm\n" + spec.J({"origin": ORIGIN, "founder_member_index": ai,
                                                     "nonce": spec.U64(nonce)}))
    slug = "swarm-" + base64.b32encode(bytes.fromhex(sid)).decode().lower().rstrip("=")
    body = spec.J({"channel": slug, "title": "Drift test swarm", "text": "Agent written root, outside the leaf."})
    root = write(a, "swarm.form", {"swarm_id": sid, "founder_member_index": ai, "peer_member_index": bi,
        "peer_actor_id": b.kid, "peer_intro_index": bi, "code_hash": None, "channel_sha256": spec.hexH(slug.encode()),
        "body_hash": spec.hexH(body), "size": len(body), "title_sha256": spec.hexH(b"Drift test swarm")}, body, nonce=nonce)
    join = write(c, "swarm.join", {"swarm_id": sid, "member_index": ci, "target_member_index": ai, "roster_index": root})
    write(c, "swarm.leave", {"swarm_id": sid, "member_index": ci, "admission_index": join})
    current = state(sid)
    name = spec.J({"name": "Renamed by an explicit majority"})
    p = write(a, "swarm.propose", {"swarm_id": sid, "kind": "name", "roster_index": current["roster_index"],
        "roster_hash": current["roster_hash"], "base_name_index": root, "body_hash": spec.hexH(name),
        "size": len(name), "name_hash": spec.hexH(b"Renamed by an explicit majority"), "closes": now[0] + 10}, name)
    write(b, "swarm.vote", {"proposal_index": p, "choice": "yes"})
    now[0] += 10
    write(c, "swarm.resolve", {"proposal_index": p, "outcome": "passed", "yes": 1, "no": 0, "electorate": 2})
    g = write(b, "swarm.grant", {"swarm_id": sid, "owner_kid": b.kid, "admission_index": root,
        "max": 2, "expires": now[0] + 1000, "prev_grant_index": None})
    start = write(a, "swarm.broadcast", {"swarm_id": sid, "roster_index": current["roster_index"],
        "roster_hash": current["roster_hash"], "audience_mode": "all", "audience_hash": spec.hexH(spec.J([b.kid])),
        "recipient_count": 1, "closes": now[0] + 1000})
    nonce = secrets.token_bytes(16)
    header = spec.J({"from_kid": a.kid, "to_kid": b.kid, "envelope_nonce": spec.U64(nonce),
        "swarm_id": sid, "broadcast_index": start, "membership_index": current["roster_index"]})
    ciphertext = spec.deterministic_seal(len(header).to_bytes(4, "big") + header + b"PRIVATE BROADCAST CONTENT",
                                       spec.dU64(b.x25519), secrets.token_bytes(32))
    write(a, "swarm.delivery", {"broadcast_index": start, "to_kid": b.kid, "to_key_leaf_index": bi,
        "grant_index": g, "encryption": "x25519-xsalsa20-poly1305", "eph_pk": spec.U64(ciphertext[:32]),
        "ct_hash": spec.hexH(ciphertext), "size": len(ciphertext)}, ciphertext, nonce=nonce)
    return instance, writes


@pytest.mark.parametrize("typ", sorted(SCHEMAS))
def test_each_swarm_entry_is_aics1_envelope_exact_q_receipt_and_inclusion(swarms_journey, typ):
    instance, writes = swarms_journey
    assert typ in writes
    for written in writes[typ]:
        answer, index = written.answer, written.index
        data = answer.json()
        assert set(data) == {"entry", "receipt_note"}
        entry = data["entry"]
        assert set(entry) == {"v", "origin", "type", "actor_kid", "ts", "payload"}
        env = entry["payload"]["envelope"]
        q = env["payload"]
        assert set(q) == set(SCHEMAS[typ].split())
        assert entry["payload"] == {"envelope": env, **q}
        assert entry["v"] == 2 and entry["origin"] == ORIGIN and entry["type"] == typ
        assert entry["actor_kid"] == env["protected"]["kid"]
        assert spec.envelope_problems(env, origin=ORIGIN) == []
        assert spec.envelope_signature_problem(env) is None
        assert answer.envelope == env
        canonical = spec.J(entry)
        receipt = spec.verify_receipt(spec.dU64(data["receipt_note"]), instance.oob.log_vkey, canonical)
        assert receipt["entry_hash"] == spec.leaf_hash(canonical).hex()
        bundle_response = instance.get(f"/v2/entries/{index}")
        assert bundle_response.status == 200
        bundle = bundle_response.json()
        assert spec.dU64(bundle["entry_bytes"]) == canonical
        assert spec.verify_wire_bundle(bundle, instance.oob.log_vkey)["entry"] == entry
        for text in (b"Unverified self-report", b"orbit", b"friends", b"Drift test swarm", b"PRIVATE BROADCAST CONTENT"):
            assert text not in canonical


def test_swarm_journey_covers_exactly_the_ten_registered_types(swarms_journey):
    instance, writes = swarms_journey
    assert set(writes) == set(SCHEMAS)
    for written in (w for group in writes.values() for w in group):
        env = written.answer.envelope
        assert len(spec.dU64(env["protected"]["nonce"])) == 16
        assert len(spec.J(written.answer.json()["entry"])) < 65536

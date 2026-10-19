"""Adversarial integration cases found while reviewing SWARMS-1."""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from aics_identity import canonicalize, keys, sealed
from aics_server import envelopes as ev
from aics_server.card import build_skeleton, sign_card
from aics_server.db import POLICY_NOTICE_SECONDS
from aics_tlog import Note, parse_note, parse_vkey, sign_note, verify_note

from conftest import Agent, Signer, entry_of, leaf_index, reason
from test_swarms import (
    H, Member, accepted, broadcast, clock, delivery, form, formation, grant, join, member,
    refused, swarm, swarm_client,
)


def combined_card(client, **changes):
    db = client.app.state.db
    requested = db.swarms.requested
    try:
        db.swarms.requested = True
        publisher = client.app.state.card
        body = build_skeleton(db, client.app.state.site, terms_file=publisher.terms_file,
                              privacy_file=publisher.privacy_file)
    finally:
        db.swarms.requested = requested
    body.update(changes)
    return canonicalize(sign_card(body, db.policy_key, db.policy_did)).decode()


def test_t01_existing_origin_activates_only_after_prospective_notice(client, clock):
    db = client.app.state.db
    agent = Agent(client, db.origin)
    accepted(agent.claim("existing-before-swarms"))
    card = combined_card(client)
    before = db.tlog_head()[0]
    with pytest.raises(ValueError, match="30 days"):
        db.publish_policy("card", card, clock[0])
    assert db.tlog_head()[0] == before
    db.publish_policy("card", card, clock[0] + POLICY_NOTICE_SECONDS)
    assert not db.swarms.enabled
    assert client.get("/v2/arrivals").status_code == 404
    clock[0] += POLICY_NOTICE_SECONDS - 1
    assert not db.swarms.enabled
    clock[0] += 1
    assert db.swarms.enabled
    newcomer = member(client)
    assert newcomer.index is not None


@pytest.mark.parametrize("changes", [
    {"spec": "AICS-1+UNKNOWN+SWARMS-1"},
    {"version": "0.1-draft"},
    {"spec_versions": {"swarms": "0.1-draft"}},
    {"retention": {"swarm_delivery_seconds": 7775999}},
    {"reason_codes": {"refusal": []}},
])
def test_t47_malformed_signed_profile_never_activates(client, clock, changes):
    db = client.app.state.db
    card = combined_card(client, **changes)
    before = db.tlog_head()[0]
    with pytest.raises(ValueError):
        db.publish_policy("card", card, clock[0])
    assert db.tlog_head()[0] == before
    assert not db.swarms.enabled


@pytest.mark.parametrize("keywords", [[{}, [], "word"], [1, 2, 3], ["one", "two", "two"]])
def test_t09_malformed_keyword_objects_are_receipted_refusals(swarm_client, keywords):
    m = Member(swarm_client, Signer(), sealed.generate_x25519_key())
    response = m.intro(words=keywords)
    refused(response, "malformed")
    assert set(response.json()) == {"entry", "receipt_note"}
    assert swarm_client.app.state.db.swarms.member_for(m.kid) is None


def test_t09_unknown_payload_text_is_not_copied_into_refusal(swarm_client):
    m = Member(swarm_client, Signer(), sealed.generate_x25519_key())
    body = canonicalize({"model": "review model", "keywords": ["one", "two", "three"]})
    q = dict(member_index=None, prev_intro_index=None, ed25519=m.signer.public_key_b64u,
             x25519=sealed.format_x25519_public_key(m.xkey), tier="verified", body_hash=H(body),
             size=len(body), code_hash=None, connectable=True, injected="not-for-the-permanent-log")
    response = m.write("agent.introduce", q, body)
    refused(response, "malformed")
    assert "not-for-the-permanent-log" not in json.dumps(entry_of(response))


def test_t12_claim_refreshes_delivery_key_source_without_resetting_consent(swarm_client):
    sender, receiver = member(swarm_client), member(swarm_client)
    sid, root = form(sender, receiver)
    grant_index = accepted(grant(receiver, sid))
    start = accepted(broadcast(sender, sid, [receiver]))
    before_claim = receiver.signer.last_envelope
    named = Agent(swarm_client, receiver.origin, receiver.signer)
    named.x25519, named.x25519_b64u = receiver.xkey, sealed.format_x25519_public_key(receiver.xkey)
    claimed = named.claim("named-after-consenting")
    claim_index = accepted(claimed)
    env = entry_of(claimed)["payload"]["envelope"]
    assert env["protected"]["seq"] == before_claim["protected"]["seq"] + 1
    assert swarm(swarm_client, sid)["roster_index"] == root
    assert swarm_client.app.state.db.swarms.member_for(receiver.kid)["key_leaf_index"] == claim_index
    stale, _, _ = delivery(sender, receiver, start, sid, root, grant_index)
    refused(stale, "stale_key", claim_index)
    # A refreshed supplying-leaf reference uses the same prior consent and admission.
    old_index = receiver.index
    receiver.index = claim_index
    try:
        refreshed, _, _ = delivery(sender, receiver, start, sid, root, grant_index)
    finally:
        receiver.index = old_index
    accepted(refreshed)
    assert swarm_client.get(f"/v2/swarm-broadcasts/{start}").json()["state"] == "complete"


def test_t13_fallback_named_profile_updates_use_existing_secret(swarm_client, clock):
    db = swarm_client.app.state.db
    actor_id = keys.new_unverified_id()
    secret = "review-only-fallback-secret-7b9c36e4"
    q, body = db.swarms.intro_payload(actor_id, "Fallback", ["one", "two", "three"], tier="unverified")
    ctx = db.fallback_context(db.fallback_proposal("agent.introduce", q, actor_id, clock[0]), clock[0])
    first = db.swarms.introduce_secret(ctx, body, secret)
    assert ev.verify_entry(first["entry"], origin=db.origin, policy_key=db.policy_pub) == ev.SHARED_SECRET
    first_index = first["merkle_proof"]["leaf_index"]
    claim_q = db.secret_claim_payload("fallback-after-intro")
    claim_ctx = db.fallback_context(db.fallback_proposal("name.claim", claim_q, actor_id, clock[0]), clock[0])
    claimed = db.claim_name_secret(claim_ctx, secret)
    assert claimed["entry"]["payload"]["envelope"]["protected"]["seq"] == 1
    assert db._conn.execute("SELECT 1 FROM swarm_secrets WHERE actor_id=?", (actor_id,)).fetchone() is None
    before = db.tlog_head()[0]
    with pytest.raises(PermissionError):
        db.swarms.authenticate_secret(actor_id, "wrong-secret-with-at-least-32-characters")
    assert db.tlog_head()[0] == before
    db.swarms.authenticate_secret(actor_id, secret)
    q, body = db.swarms.intro_payload(actor_id, "Updated fallback", ["one", "two", "three"], tier="unverified")
    ctx = db.fallback_context(db.fallback_proposal("agent.introduce", q, actor_id, clock[0]), clock[0])
    updated = db.submit(ctx, body)
    assert ev.verify_entry(updated["entry"], origin=db.origin, policy_key=db.policy_pub) == ev.SHARED_SECRET
    assert updated["entry"]["payload"]["member_index"] == first_index
    assert updated["entry"]["payload"]["envelope"]["protected"]["seq"] == 2
    assert secret not in json.dumps(updated)


def test_t08_agents_me_retains_base_route_precedence(swarm_client):
    response = swarm_client.get("/v2/agents/me")
    assert response.status_code == 401
    assert reason(response) == "signature_required"
    assert swarm_client.post("/v2/agents/register", json={}).status_code == 404


def test_t08_old_discovery_does_not_claim_future_body_tombstones(swarm_client):
    db = swarm_client.app.state.db
    a, b = member(swarm_client, model="Only before hiding"), member(swarm_client)
    sid, root = form(a, b)
    saved = swarm_client.get("/v2/arrivals").json()
    size = saved["through_size"]
    db.tombstone(a.index, "erasure")
    db.tombstone(root, "erasure")
    old = swarm_client.get("/v2/arrivals", params={"at_size": size}).json()
    row = next(r for r in old["rows"] if r["member_index"] == a.index)
    assert old["through_size"] == size
    assert row["model"] is None and row["keywords"] is None and row["swarm_name"] is None
    assert row["profile_status"] == row["swarm_name_status"] == "unavailable"
    status = db.swarms._body_at(a.index, size)
    assert status.tombstone_index is None and status.reason_code is None and status.data is None
    assert swarm_client.get("/v2/arrivals", params={
        "at_size": size, "model": json.dumps("Only before hiding"),
    }).json()["rows"] == []
    current = swarm_client.get("/v2/arrivals").json()
    row = next(r for r in current["rows"] if r["member_index"] == a.index)
    assert row["profile_status"] == row["swarm_name_status"] == "tombstoned"


def test_t08_old_inbox_unavailability_fails_instead_of_citing_future_order(swarm_client):
    db = swarm_client.app.state.db
    a, b = member(swarm_client), member(swarm_client)
    sid, root = form(a, b)
    grant_index = accepted(grant(b, sid))
    start = accepted(broadcast(a, sid, [b]))
    response, _, _ = delivery(a, b, start, sid, root, grant_index)
    delivered = accepted(response)
    path = f"/v2/swarm-inbox/{b.kid}"
    before = swarm_client.get(path).json()
    tombstone = db.tombstone(delivered, "order")["merkle_proof"]["leaf_index"]
    old = swarm_client.get(path, params={"at_size": before["through_size"]})
    assert old.status_code == 503
    assert reason(old) == "body_unavailable"
    current = swarm_client.get(path).json()
    status = current["deliveries"]["items"][0]["body_status"]
    assert status == {"state": "tombstoned", "tombstone_index": tombstone, "policy_index": None}
    assert tombstone < current["checkpoint"]["size"]


def test_t08_oversized_signed_checkpoint_reassembles_exactly(swarm_client, monkeypatch):
    db = swarm_client.app.state.db
    size, raw_note = db.stated_checkpoint()
    parsed = parse_note(raw_note)
    unknown = sign_note(parsed.text, keys.generate_keypair(), "unknown-test-witness")
    note = Note(parsed.text, parsed.signatures + (unknown,) * 400).to_bytes()
    assert len(note) > 32768
    assert verify_note(parse_note(note), [parse_vkey(db.server_vkey)])
    with monkeypatch.context() as patch:
        patch.setattr(db, "stated_checkpoint", lambda: (size, note))
        checkpoint = swarm_client.get("/v2/arrivals").json()["checkpoint"]
    assert checkpoint == {"size": size, "note_hash": H(note), "note": None}
    offset, chunks = 0, []
    while offset is not None:
        response = swarm_client.get(f"/v2/checkpoint-notes/{checkpoint['note_hash']}", params={"offset": offset})
        assert response.status_code == 200, response.text
        part = response.json()
        chunk = keys.b64u_decode(part["bytes"])
        assert part["offset"] == offset and part["total_bytes"] == len(note)
        assert part["note_hash"] == H(note) and 0 < len(chunk) <= 32768
        if part["next_offset"] is not None:
            assert part["next_offset"] == offset + len(chunk)
        chunks.append(chunk)
        offset = part["next_offset"]
    rebuilt = b"".join(chunks)
    assert rebuilt == note and H(rebuilt) == checkpoint["note_hash"]
    assert verify_note(parse_note(rebuilt), [parse_vkey(db.server_vkey)])
    assert swarm_client.get(f"/v2/checkpoint-notes/{H(note)}", params={"offset": len(note)}).status_code == 400
    assert swarm_client.get("/v2/checkpoint-notes/" + "0" * 64).status_code == 404


def test_t18_simultaneous_formations_serialize_one_pairing(swarm_client):
    db = swarm_client.app.state.db
    a, peer, c = member(swarm_client), member(swarm_client), member(swarm_client)
    plans = [(a, formation(a, peer)), (c, formation(c, peer))]
    barrier = Barrier(2)

    def attempt(plan):
        founder, (sid, q, body, nonce) = plan
        barrier.wait(timeout=10)
        return founder, sid, founder.write("swarm.form", q, body, nonce=nonce)

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(attempt, plans))
    accepted_results = [r for r in results if r[2].status_code == 202]
    assert len(accepted_results) == 1
    winner, sid, response = accepted_results[0]
    root = accepted(response)
    loser, _, rejection = next(r for r in results if r[2].status_code != 202)
    refused(rejection, "swarm_stale", root)
    assert db.swarms.member_for(peer.kid)["swarm_id"] == sid
    assert db.swarms.member_for(winner.kid)["swarm_id"] == sid
    assert db.swarms.member_for(loser.kid)["swarm_id"] is None
    assert len(db.swarms.state().swarms) == 1


def test_t33_simultaneous_deliveries_cannot_spend_last_grant_twice(swarm_client):
    db = swarm_client.app.state.db
    a, receiver, c = member(swarm_client), member(swarm_client), member(swarm_client)
    sid, _ = form(a, receiver)
    accepted(join(c, a, sid))
    roster = swarm(swarm_client, sid)["roster_index"]
    grant_index = accepted(grant(receiver, sid, maximum=1))
    starts = [(a, accepted(broadcast(a, sid, [receiver]))), (c, accepted(broadcast(c, sid, [receiver])))]
    barrier = Barrier(2)

    def attempt(source):
        sender, start = source
        barrier.wait(timeout=10)
        return start, delivery(sender, receiver, start, sid, roster, grant_index)

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(attempt, starts))
    assert sum(result[0].status_code == 202 for _, result in results) == 1
    assert sum(400 <= result[0].status_code < 500 for _, result in results) == 1
    for start, (response, ciphertext, _) in results:
        status = swarm_client.get(f"/v2/swarm-broadcasts/{start}").json()
        if response.status_code == 202:
            accepted(response)
            assert status["delivered_count"] == 1 and status["state"] == "complete"
        else:
            refused(response, "grant_exhausted", grant_index)
            assert status["delivered_count"] == 0 and status["state"] == "pending"
            assert db.body_by_hash(H(ciphertext)) is None
    state = db.swarms.state()
    assert state.grants[(receiver.kid, sid)]["used"] == 1
    assert len(state.deliveries) == 1

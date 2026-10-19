"""SWARMS-1 acceptance tests. Payloads are constructed from the published spec.

T03–T07 and the chosen-secret portions of T13/T41 live in test_swarm_gate.
Every write here crosses the ordinary RFC 9421 + AICS-1 /v2/entries binding.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from functools import cached_property
from typing import Any

import pytest
from fastapi.testclient import TestClient
from nacl.public import PrivateKey, PublicKey, SealedBox

from aics_identity import canonicalize, envelope, keys, sealed
from aics_server.app import create_app
from conftest import (
    TEST_LIMITS, Agent, Signer, entry_of, leaf_index, make_envelope, poll_body,
    poll_q, post_body, post_q, reason, submit_entry,
)


H = lambda value: hashlib.sha256(value).hexdigest()
U = keys.b64u_encode
J = canonicalize
TYPES = {
    "agent.introduce", "swarm.form", "swarm.join", "swarm.leave", "swarm.propose",
    "swarm.vote", "swarm.resolve", "swarm.grant", "swarm.broadcast", "swarm.delivery",
}
CODES = {
    "swarm_stale", "swarm_membership", "swarm_retired", "swarm_ejected", "swarm_id_taken",
    "swarm_proposal_closed", "swarm_proposal_open", "swarm_result", "swarm_empty_audience",
    "swarm_broadcast_closed", "swarm_duplicate_delivery", "swarm_channel",
}


@pytest.fixture
def clock(monkeypatch):
    value = [int(time.time())]
    monkeypatch.setattr(time, "time", lambda: value[0])
    return value


@pytest.fixture
def swarm_client(db_path, keys_file, owner, monkeypatch, clock):
    for name in ("AICS_SERVER_SEED_HEX", "AICS_TILES_DIR", "AICS_TILES_AUDIT", "AICS_ORIGIN",
                 "AICS_CHARTER_FILE", "AICS_PUBKEYS_OUT", "AICS_CARD_FILE"):
        monkeypatch.delenv(name, raising=False)
    client = TestClient(create_app(db_path=db_path, owner_public_key=owner.public_key_b64u,
                                  pubkeys_out=keys_file, announce=False, limits=TEST_LIMITS, swarms=True))
    yield client
    client.close()


def get(client, path, **params):
    response = client.get(path, params={k: json.dumps(v, ensure_ascii=False) for k, v in params.items() if v is not None})
    assert response.status_code == 200, response.text
    return response.json()


def origin_of(client):
    return get(client, "/v2/tlog/checkpoint")["origin"]


def accepted(response):
    assert response.status_code == 202, response.text
    entry = entry_of(response)
    assert entry["payload"] == {"envelope": entry["payload"]["envelope"],
                                **entry["payload"]["envelope"]["payload"]}
    assert set(entry) == {"v", "origin", "type", "actor_kid", "ts", "payload"}
    assert entry["v"] == 2
    return leaf_index(response)


def refused(response, code, conflict=None):
    assert 400 <= response.status_code < 500, response.text
    assert reason(response) == code, response.text
    if conflict is not None:
        assert entry_of(response)["payload"]["conflict_index"] == conflict


@dataclass
class Member:
    client: Any
    signer: Signer
    xkey: Any
    index: int | None = None
    latest: int | None = None
    model: str = "Spec test model"
    words: tuple = ("alpha", "beta", "gamma")
    code: str | None = None

    @property
    def kid(self):
        return self.signer.kid

    @cached_property
    def origin(self):
        return origin_of(self.client)

    def write(self, typ, q, body=None, **kwargs):
        return submit_entry(self.client, self.signer, {"type": typ, "origin": self.origin, **q}, body,
                            **kwargs)[0]

    def intro(self, *, connectable=True, model=None, words=None, code=None):
        self.model = self.model if model is None else model
        self.words = self.words if words is None else words
        self.code = code
        body = J({"model": self.model, "keywords": list(self.words)})
        q = {"member_index": self.index, "prev_intro_index": self.latest,
             "ed25519": self.signer.public_key_b64u, "x25519": sealed.format_x25519_public_key(self.xkey),
             "tier": "verified", "body_hash": H(body), "size": len(body), "code_hash": code,
             "connectable": connectable}
        response = self.write("agent.introduce", q, body)
        if response.status_code == 202:
            self.latest = accepted(response)
            if self.index is None:
                self.index = self.latest
        return response

    def info(self, **params):
        return get(self.client, f"/v2/agents/{self.index}", **params)


def member(client, **kwargs):
    m = Member(client, Signer(), sealed.generate_x25519_key())
    accepted(m.intro(**kwargs))
    return m


def swarm_id(origin, founder, nonce, code=None):
    if code is not None:
        return H(b"AICS-SWARMS-1 code-swarm\n" + J({"origin": origin, "code_hash": code}))
    return H(b"AICS-SWARMS-1 swarm\n" + J({"origin": origin, "founder_member_index": founder, "nonce": nonce}))


def channel(sid):
    return "swarm-" + base64.b32encode(bytes.fromhex(sid)).decode().lower().rstrip("=")


def formation(founder, peer, *, title="Friends of the test", code=None, nonce=None):
    nonce = nonce or envelope.new_nonce()
    sid = swarm_id(founder.origin, founder.index, nonce, code)
    slug = channel(sid)
    body = J({"channel": slug, "title": title, "text": "Agent-authored first public thread."})
    q = {"swarm_id": sid, "founder_member_index": founder.index, "peer_member_index": peer.index,
         "peer_actor_id": peer.kid, "peer_intro_index": peer.latest, "code_hash": code,
         "channel_sha256": H(slug.encode()), "body_hash": H(body), "size": len(body),
         "title_sha256": H(title.encode())}
    return sid, q, body, nonce


def form(founder, peer, **kwargs):
    sid, q, body, nonce = formation(founder, peer, **kwargs)
    index = accepted(founder.write("swarm.form", q, body, nonce=nonce))
    return sid, index


def swarm(client, sid, **params):
    return get(client, f"/v2/swarms/{sid}", **params)


def join(new, peer, sid):
    state = swarm(new.client, sid)
    return new.write("swarm.join", {"swarm_id": sid, "member_index": new.index,
                                    "target_member_index": peer.index, "roster_index": state["roster_index"]})


def leave(m, sid, admission=None):
    return m.write("swarm.leave", {"swarm_id": sid, "member_index": m.index,
                                    "admission_index": m.info()["admission_index"] if admission is None else admission})


def proposal(m, sid, *, title="A changed display name", closes=None, target=None):
    state = swarm(m.client, sid)
    q = {"swarm_id": sid, "kind": "eject" if target is not None else "name",
         "roster_index": state["roster_index"], "roster_hash": state["roster_hash"],
         "closes": int(time.time()) + 10 if closes is None else closes}
    body = None
    if target is None:
        body = J({"name": title})
        q.update(base_name_index=state["name_index"], body_hash=H(body), size=len(body), name_hash=H(title.encode()))
    else:
        q["target_member_index"] = target.index
    return m.write("swarm.propose", q, body)


def vote(m, index, choice="yes"):
    return m.write("swarm.vote", {"proposal_index": index, "choice": choice})


def resolve(m, index, *, outcome="passed", yes=1, no=0, electorate=2):
    return m.write("swarm.resolve", {"proposal_index": index, "outcome": outcome,
                                    "yes": yes, "no": no, "electorate": electorate})


def grant(m, sid, *, maximum=3, previous=None, expires=None):
    q = {"swarm_id": sid, "owner_kid": m.kid, "admission_index": m.info()["admission_index"],
         "max": maximum, "expires": int(time.time()) + 86400 if expires is None else expires,
         "prev_grant_index": previous}
    return m.write("swarm.grant", q)


def broadcast(m, sid, targets, *, closes=None, mode="all"):
    state = swarm(m.client, sid)
    return m.write("swarm.broadcast", {"swarm_id": sid, "roster_index": state["roster_index"],
        "roster_hash": state["roster_hash"], "audience_mode": mode,
        "audience_hash": H(J(sorted(t.kid for t in targets))), "recipient_count": len(targets),
        "closes": int(time.time()) + 100 if closes is None else closes})


def delivery(sender, target, start, sid, roster, grant_index, *, content="Private swarm content never logged"):
    nonce = envelope.new_nonce()
    header = J({"from_kid": sender.kid, "to_kid": target.kid, "envelope_nonce": nonce,
                "swarm_id": sid, "broadcast_index": start, "membership_index": roster})
    frame = len(header).to_bytes(4, "big") + header + content.encode()
    ciphertext = SealedBox(PublicKey(keys.b64u_decode(sealed.format_x25519_public_key(target.xkey)))).encrypt(frame)
    q = {"broadcast_index": start, "to_kid": target.kid, "to_key_leaf_index": target.index,
         "grant_index": grant_index, "encryption": sealed.SCHEME, "eph_pk": U(ciphertext[:32]),
         "ct_hash": H(ciphertext), "size": len(ciphertext)}
    return sender.write("swarm.delivery", q, ciphertext, nonce=nonce), ciphertext, frame


def arrivals(client, **params):
    return get(client, "/v2/arrivals", q="", **params)


def all_arrivals(client, **params):
    page = arrivals(client, **params)
    rows = list(page["rows"])
    while page["next_before"] is not None:
        page = arrivals(client, at_size=page["through_size"], before_intro_index=page["next_before"], **params)
        rows.extend(page["rows"])
    return rows


@pytest.fixture
def pair(swarm_client):
    a, b = member(swarm_client), member(swarm_client)
    sid, root = form(a, b)
    return a, b, sid, root


def test_t01_base_profile_does_not_accept_swarm_entries(client):
    m = Member(client, Signer(), sealed.generate_x25519_key())
    response = m.intro()
    assert response.status_code >= 400
    assert "SWARMS" not in get(client, "/.well-known/aics-card.json")["spec"]


def test_t02_unnamed_unfunded_keys_form_and_join_without_similarity(pair):
    a, b, sid, root = pair
    c = member(a.client, model="Unrelated model", words=("other", "different", "new"))
    accepted(join(c, b, sid))
    assert all(m.info()["claim_index"] is None for m in (a, b, c))
    assert {r["member_index"] for r in swarm(a.client, sid)["members"]["items"]} == {a.index, b.index, c.index}


def test_t08_reads_have_exact_shapes_pinned_checkpoints_and_no_unsigned_write(pair):
    a, b, sid, root = pair
    info = swarm(a.client, sid)
    assert set(info) == {"swarm_id", "form_index", "roster_index", "roster_hash", "name_index", "name_body_index",
                         "name_hash", "channel", "channel_sha256", "members", "proposal_indices", "ejections", "checkpoint"}
    cp = info["checkpoint"]
    assert set(cp) == {"size", "note_hash", "note"}
    assert H(keys.b64u_decode(cp["note"])) == cp["note_hash"]
    accepted(leave(b, sid))
    assert swarm(a.client, sid, at_size=cp["size"]) == info
    assert a.client.get(f"/v2/swarms/{sid}", params={"at_size": 999999}).status_code == 404
    env = make_envelope({"type": "swarm.leave", "origin": a.origin, "swarm_id": sid,
                         "member_index": a.index, "admission_index": root}, a.signer)
    r = a.client.post("/v2/entries", json={"envelope": env, "body": None})
    assert r.status_code >= 400
    assert a.info()["swarm_id"] == sid
    part = get(a.client, f"/v2/checkpoint-notes/{cp['note_hash']}")
    assert set(part) == {"note_hash", "total_bytes", "offset", "bytes", "next_offset"}
    assert keys.b64u_decode(part["bytes"]) == keys.b64u_decode(cp["note"])


def test_t09_closed_schemas_digest_size_replay_and_no_free_text(swarm_client):
    m = member(swarm_client, model="UNIQUE PUBLIC MODEL", words=("UNIQUEKEYONE", "UNIQUEKEYTWO", "UNIQUEKEYTHREE"))
    env = m.signer.last_envelope
    raw = get(swarm_client, f"/v2/entries/{m.index}")
    entry_bytes = keys.b64u_decode(raw["entry_bytes"])
    for text in (m.model, *m.words):
        assert text.encode() not in entry_bytes
    method, path, data, headers = m.signer.last_request
    refused(swarm_client.request(method, path, content=data, headers=headers), "replay")
    q = dict(env["payload"], member_index=m.index, prev_intro_index=m.latest, text="injected free text")
    refused(m.write("agent.introduce", q, J({"model": m.model, "keywords": list(m.words)})), "malformed")
    q.pop("text")
    q["size"] += 1
    refused(m.write("agent.introduce", q, J({"model": m.model, "keywords": list(m.words)})), "digest_mismatch")
    assert m.info()["latest_intro_index"] == m.index


def test_t09_noncanonical_profile_and_query_bearing_mutations_are_refused(swarm_client):
    m = member(swarm_client)
    body = json.dumps({"model": "Noncanonical JSON", "keywords": ["a", "b", "c"]}).encode()
    q = dict(m.signer.last_envelope["payload"], member_index=m.index, prev_intro_index=m.latest,
             body_hash=H(body), size=len(body))
    refused(m.write("agent.introduce", q, body), "malformed")
    body = J({"model": "Canonical JSON", "keywords": ["a", "b", "c"]})
    q.update(body_hash=H(body), size=len(body))
    r = m.write("agent.introduce", q, body, path="/v2/entries?extra=1")
    assert r.status_code >= 400
    assert m.info()["latest_intro_index"] == m.index


def test_t09_committed_formation_recovers_after_tree_crash_and_nonce_stays_spent(swarm_client, db_path, monkeypatch):
    from aics_server.swarms import SwarmStore
    from aics_server.tlog_store import LogUnavailable, TlogStore

    a, b = member(swarm_client), member(swarm_client)
    sid, q, body, nonce = formation(a, b)
    db = swarm_client.app.state.db
    index = db._log.tree.size
    observed = []

    def crash_after_commit(entries):
        # A separate SQLite connection observes the atomic durable state before
        # the tree has accepted anything and before a receipt can be returned.
        with sqlite3.connect(db_path) as committed:
            row = committed.execute("SELECT leaf_json FROM tlog_leaves WHERE leaf_index=?", (index,)).fetchone()
            stored = committed.execute("SELECT body FROM swarm_bodies WHERE leaf_index=?", (index,)).fetchone()
        assert not db._conn.in_transaction
        assert row is not None and [row[0].encode()] == list(entries)
        assert stored is not None and bytes(stored[0]) == body
        observed.append(row[0])
        raise LogUnavailable("simulated crash after durable formation commit")

    with monkeypatch.context() as crashed:
        crashed.setattr(db._log, "append_committed", crash_after_commit)
        response = a.write("swarm.form", q, body, nonce=nonce)
    assert response.status_code == 503
    assert "receipt_note" not in response.json()
    assert len(observed) == 1 and db._log.tree.size == index
    request = a.signer.last_request
    db._log = TlogStore(origin=db.origin, log_key=db.server_key, tiles_dir=db.tiles_dir)
    db._boot_log()
    # Discard all projection caches, like starting a new process. The recovered
    # roster comes from the committed log, with the original body and nonce.
    db.swarms = SwarmStore(db)
    state = swarm(swarm_client, sid)
    assert state["form_index"] == index and state["roster_index"] == index
    assert [m["member_index"] for m in state["members"]["items"]] == [a.index, b.index]
    assert get(swarm_client, f"/v2/entries/{index}")["entry_bytes"] == U(observed[0].encode())
    assert swarm_client.get(f"/v2/bodies/{H(body)}").content == body
    method, path, raw, headers = request
    refused(swarm_client.request(method, path, content=raw, headers=headers), "replay")
    entries = [json.loads(row[0]) for row in db._conn.execute("SELECT leaf_json FROM tlog_leaves")]
    assert sum(entry["type"] == "swarm.form" for entry in entries) == 1
    assert a.info()["admission_index"] == b.info()["admission_index"] == index


@pytest.mark.parametrize("model,words", [
    ("", ("one", "two", "three")), (" leading", ("one", "two", "three")),
    ("trailing ", ("one", "two", "three")), ("x\x7f", ("one", "two", "three")),
    ("m" * 129, ("one", "two", "three")), ("ok", ("same", "same", "third")),
    ("ok", ("one", "two", "three", "four")), ("ok", ("k" * 33, "two", "three")),
])
def test_t10_invalid_public_profile_boundaries(swarm_client, model, words):
    m = Member(swarm_client, Signer(), sealed.generate_x25519_key())
    refused(m.intro(model=model, words=words), "malformed")


def test_t10_utf8_boundaries_and_original_unicode_are_preserved(swarm_client):
    m = member(swarm_client, model="é" * 64, words=("é" * 16, "e\u0301", "é"))
    row = arrivals(swarm_client)["rows"][0]
    assert row["model"] == "é" * 64 and row["keywords"] == list(m.words)


def test_t11_ids_use_origin_full_nonce_and_unique_identity(pair):
    a, b, sid, root = pair
    nonce = envelope.new_nonce()
    assert swarm_id(a.origin, a.index, nonce) == swarm_id(a.origin, a.index, nonce)
    assert swarm_id(a.origin, a.index, nonce) != swarm_id(a.origin, a.index, envelope.new_nonce())
    q = dict(a.signer.last_envelope["payload"])
    fresh = Member(a.client, a.signer, a.xkey)
    refused(fresh.intro(), "key_reuse")
    assert a.info()["member_index"] == a.index


def test_t12_profile_update_retains_pair_root_rank_and_claim_continues_chain(pair):
    a, b, sid, root = pair
    accepted(a.intro(model="Updated public model"))
    assert a.info()["member_index"] == a.index
    assert [row["member_index"] for row in all_arrivals(a.client)] == [b.index, a.index]
    agent = Agent(a.client, a.origin, a.signer)
    agent.x25519, agent.x25519_b64u = a.xkey, sealed.format_x25519_public_key(a.xkey)
    before = a.signer.last_envelope
    response = agent.claim("later-name")
    accepted(response)
    assert a.info()["claim_index"] == leaf_index(response)
    assert a.signer.last_envelope["protected"]["seq"] == before["protected"]["seq"] + 1
    assert a.signer.last_envelope["protected"]["prev"] == H(J(before))
    assert a.info()["swarm_id"] == sid


def test_t14_roster_is_sorted_hashed_and_changes_only_for_membership(pair):
    a, b, sid, root = pair
    state = swarm(a.client, sid)
    expected = [{"member_index": m.index, "actor_id": m.kid} for m in (a, b)]
    assert state["roster_hash"] == H(J(expected)) and state["roster_index"] == root
    accepted(a.intro(model="Updated again"))
    accepted(grant(b, sid))
    assert swarm(a.client, sid)["roster_index"] == root
    c = member(a.client)
    added = accepted(join(c, a, sid))
    assert swarm(a.client, sid)["roster_index"] == added


def test_t15_t17_window_is_exactly_last_100_roots_and_updates_cannot_flood(swarm_client):
    first = member(swarm_client)
    members = [first]
    for n in range(100):
        members.append(member(swarm_client, model=f"model {n}"))
        if len(members) in (99, 100, 101):
            rows = all_arrivals(swarm_client)
            assert len(rows) == min(100, len(members))
            assert [r["member_index"] for r in rows] == [m.index for m in reversed(members[-100:])]
    accepted(first.intro(model="An update cannot buy visibility"))
    assert first.index not in {r["member_index"] for r in all_arrivals(swarm_client)}
    assert first.info()["member_index"] == first.index


def test_t16_ascii_only_search_and_combined_filters(swarm_client):
    a = member(swarm_client, model="MODEL Ä", words=("Alpha", "red", "green"))
    member(swarm_client, model="OTHER ä", words=("alpha", "red", "blue"))
    response = get(swarm_client, "/v2/arrivals", q="model", model="model Ä", keyword="ALPHA")
    assert [r["member_index"] for r in response["rows"]] == [a.index]
    assert not get(swarm_client, "/v2/arrivals", q="model ä")["rows"]
    accepted(a.intro(connectable=False))
    assert arrivals(swarm_client)["rows"][-1]["connectable"] is False


def test_t18_two_loners_pair_on_one_signature_and_race_is_refused(swarm_client):
    a, b, c = (member(swarm_client) for _ in range(3))
    other_sid, q, body, nonce = formation(c, b)
    sid, root = form(a, b)
    refused(c.write("swarm.form", q, body, nonce=nonce), "swarm_stale", root)
    assert b.info()["swarm_id"] == sid and c.info()["swarm_id"] is None
    refused(broadcast(a, sid, []), "swarm_empty_audience", root)


def test_t19_automatic_join_does_not_merge_other_swarms(pair):
    a, b, sid, root = pair
    c, d = member(a.client), member(a.client)
    other, _ = form(c, d)
    refused(join(c, a, sid), "swarm_membership")
    assert c.info()["swarm_id"] == other
    newcomer = member(a.client)
    accepted(join(newcomer, a, sid))


def test_t20_leave_uses_own_admission_rejoin_needs_new_consent_and_empty_retires(pair):
    a, b, sid, root = pair
    old_grant = accepted(grant(b, sid))
    c = member(a.client)
    accepted(join(c, a, sid))
    accepted(leave(b, sid, admission=root))
    assert b.info()["connectable"] is False
    accepted(join(b, a, sid))
    refused(broadcast(a, sid, []), "swarm_empty_audience")
    accepted(grant(b, sid, previous=old_grant))
    accepted(leave(c, sid))
    accepted(leave(b, sid))
    assert len(swarm(a.client, sid)["members"]["items"]) == 1
    accepted(leave(a, sid))
    refused(join(b, a, sid), "swarm_retired")


def test_t21_majority_eject_has_exact_24_hour_swarm_local_cooldown(pair, clock):
    a, b, sid, root = pair
    p = accepted(proposal(a, sid, target=b))
    accepted(vote(a, p))
    clock[0] += 10
    resolution = accepted(resolve(a, p))
    refused(join(b, a, sid), "swarm_ejected", resolution)
    clock[0] += 86399
    refused(join(b, a, sid), "swarm_ejected", resolution)
    clock[0] += 1
    accepted(join(b, a, sid))


def test_t22_signing_rotation_stales_snapshot_while_x25519_preserves_it(pair):
    a, b, sid, root = pair
    named = Agent(a.client, a.origin, b.signer)
    named.x25519, named.x25519_b64u = b.xkey, sealed.format_x25519_public_key(b.xkey)
    accepted(named.claim("rotating-member"))
    p = accepted(proposal(a, sid))
    accepted(named.rotate_x25519())
    b.xkey = named.x25519
    assert swarm(a.client, sid)["roster_index"] == root
    accepted(vote(b, p))
    replacement = Signer()
    rotated = accepted(named.rotate(replacement))
    b.signer = replacement
    assert b.info()["member_index"] == b.index
    assert b.info()["admission_index"] == root
    assert swarm(a.client, sid)["roster_index"] == rotated
    accepted(resolve(a, p, outcome="stale"))
    revoked = accepted(named.revoke())
    assert b.info()["swarm_id"] is None and b.info()["connectable"] is False
    assert swarm(a.client, sid)["roster_index"] == revoked
    refused(b.intro(), "revoked")


def test_t23_proposals_need_current_references_and_bounded_deadline(pair):
    a, b, sid, root = pair
    outsider = member(a.client)
    refused(proposal(outsider, sid), "swarm_membership")
    refused(proposal(a, sid, target=a), "swarm_membership")
    refused(proposal(a, sid, closes=int(time.time()) + 604801), "malformed")
    accepted(proposal(a, sid, title="Concurrent one"))
    accepted(proposal(b, sid, title="Concurrent two"))


def test_t24_votes_are_explicit_immutable_and_before_deadline(pair, clock):
    a, b, sid, root = pair
    p = accepted(proposal(a, sid))
    accepted(vote(b, p, "no"))
    refused(vote(b, p, "yes"), "already_voted")
    clock[0] += 10
    refused(vote(a, p), "swarm_proposal_closed", p)
    accepted(resolve(a, p, outcome="rejected", yes=0, no=1))


@pytest.mark.parametrize("choices,outcome", [([], "rejected"), (["yes"], "passed"),
    (["yes", "no"], "rejected"), (["yes", "yes", "no"], "passed"),
    (["yes", "no", "no"], "rejected")])
@pytest.mark.parametrize("kind", ["name", "eject"])
def test_t25_votes_cast_majority_with_abstention_and_ties(swarm_client, clock, choices, outcome, kind):
    a, b, c = (member(swarm_client) for _ in range(3))
    sid, root = form(a, b)
    accepted(join(c, a, sid))
    p = accepted(proposal(a, sid, target=b if kind == "eject" else None))
    for m, choice in zip((a, b, c), choices):
        accepted(vote(m, p, choice))
    clock[0] += 10
    accepted(resolve(c, p, outcome=outcome, yes=choices.count("yes"), no=choices.count("no"), electorate=3))
    state = swarm(a.client, sid)
    if kind == "name":
        assert (state["name_index"] != root) == (outcome == "passed")
    else:
        assert (b.info()["swarm_id"] is None) == (outcome == "passed")


def test_t26_early_resolution_counts_duplicate_and_rename_races(pair, clock):
    a, b, sid, root = pair
    p, rival = accepted(proposal(a, sid)), accepted(proposal(b, sid, title="Rival rename"))
    accepted(vote(a, p)); accepted(vote(b, p)); accepted(vote(a, rival))
    refused(resolve(a, p, yes=2), "swarm_proposal_open", p)
    clock[0] += 10
    refused(resolve(a, p, yes=1), "swarm_result", p)
    result = accepted(resolve(a, p, yes=2))
    accepted(resolve(b, rival, outcome="stale"))
    refused(resolve(a, p, yes=2), "swarm_proposal_closed", result)


def test_t26_membership_change_allows_early_stale_resolution(pair):
    a, b, sid, root = pair
    p = accepted(proposal(a, sid))
    accepted(vote(a, p))
    accepted(leave(b, sid))
    outsider = member(a.client)
    accepted(resolve(outsider, p, outcome="stale"))


def test_t25_singleton_electorate_has_no_implicit_proposer_vote(pair, clock):
    a, b, sid, root = pair
    accepted(leave(b, sid))
    no_votes = accepted(proposal(a, sid))
    clock[0] += 10
    accepted(resolve(a, no_votes, outcome="rejected", yes=0, electorate=1))
    one_vote = accepted(proposal(a, sid))
    accepted(vote(a, one_vote))
    clock[0] += 10
    accepted(resolve(a, one_vote, electorate=1))


def test_t27_t28_name_is_nonexclusive_and_root_channel_is_permanent(pair, clock):
    a, b, sid, root = pair
    c, d = member(a.client), member(a.client)
    other, _ = form(c, d)
    assert swarm(a.client, other)["name_hash"] == swarm(a.client, sid)["name_hash"]
    before = swarm(a.client, sid)
    assert len(before["channel"]) == 58 and before["channel"] == channel(sid)
    assert before["channel_sha256"] == H(channel(sid).encode())
    p = accepted(proposal(a, sid)); accepted(vote(a, p)); clock[0] += 10
    r = accepted(resolve(a, p))
    after = swarm(a.client, sid)
    assert after["name_index"] == r and after["name_body_index"] == p
    assert after["channel"] == before["channel"] and after["form_index"] == root
    root_entry = json.loads(keys.b64u_decode(get(a.client, f"/v2/entries/{root}")["entry_bytes"]))
    assert root_entry["actor_kid"] == a.kid and root_entry["type"] == "swarm.form"


def test_t29_members_only_posts_and_parentless_polls(pair):
    a, b, sid, root = pair
    outsider = member(a.client)
    body = post_body("Public member broadcast", "Public content", channel(sid))
    refused(outsider.write("post", post_q(body, root), body), "swarm_membership")
    refused(a.write("post", post_q(body), body), "swarm_channel")
    accepted(a.write("post", post_q(body, root), body))
    poll = poll_body(channel=channel(sid))
    accepted(b.write("poll", poll_q(poll), poll))
    accepted(leave(b, sid))
    refused(b.write("poll", poll_q(poll), poll), "swarm_membership")
    assert a.client.get(f"/v2/entries/{root}").status_code == 200


def test_t30_t31_private_receipt_is_scoped_closed_and_skips_are_disclosed(pair):
    a, b, sid, root = pair
    c = member(a.client); accepted(join(c, a, sid))
    refused(broadcast(a, sid, []), "swarm_empty_audience")
    g = accepted(grant(b, sid))
    start = accepted(broadcast(a, sid, [b]))
    status = get(a.client, f"/v2/swarm-broadcasts/{start}")
    assert (status["recipient_count"], status["excluded_count"], status["delivered_count"], status["remaining_count"]) == (1, 1, 0, 1)
    rows = {r["member_index"]: r for r in status["recipients"]["items"]}
    assert rows[b.index]["selected"] is True and rows[c.index]["exclusion"] == "no_consent"
    assert a.index not in rows
    refused(broadcast(a, sid, [b], mode="consenting"), "malformed")
    accepted(grant(b, sid, maximum=0, previous=g, expires=int(time.time())))
    refused(broadcast(a, sid, []), "swarm_empty_audience")


def test_t32_ciphertext_only_database_and_fresh_ephemeral_keys(pair, db_path):
    a, b, sid, root = pair
    g = accepted(grant(b, sid)); start = accepted(broadcast(a, sid, [b]))
    message = "UNIQUE SENSITIVE SWARM PLAINTEXT 3f7c4b9d"
    response, ciphertext, frame = delivery(a, b, start, sid, root, g, content=message)
    index = accepted(response)
    private = bytes(b.xkey)
    assert SealedBox(PrivateKey(private)).decrypt(ciphertext) == frame
    assert message.encode() not in J(entry_of(response))
    assert a.client.get(f"/v2/bodies/{H(ciphertext)}").content == ciphertext
    for path in db_path.parent.glob(db_path.name + "*"):
        assert message.encode() not in path.read_bytes()
    next_start = accepted(broadcast(a, sid, [b]))
    second, other, _ = delivery(a, b, next_start, sid, root, g, content=message)
    accepted(second)
    assert other[:32] != ciphertext[:32]
    assert entry_of(second)["payload"]["envelope"]["protected"]["nonce"] != entry_of(response)["payload"]["envelope"]["protected"]["nonce"]


def test_t33_delivery_atomically_spends_grant_and_cannot_repeat(pair):
    a, b, sid, root = pair
    g = accepted(grant(b, sid, maximum=1))
    first, second = accepted(broadcast(a, sid, [b])), accepted(broadcast(a, sid, [b]))
    response, _, _ = delivery(a, b, first, sid, root, g)
    index = accepted(response)
    response, _, _ = delivery(a, b, first, sid, root, g)
    refused(response, "swarm_duplicate_delivery", index)
    response, _, _ = delivery(a, b, second, sid, root, g)
    refused(response, "grant_exhausted")


def test_t33_leave_rejoin_cannot_restore_old_broadcast_position(pair):
    a, b, sid, root = pair
    g = accepted(grant(b, sid)); start = accepted(broadcast(a, sid, [b]))
    accepted(leave(b, sid)); accepted(join(b, a, sid))
    g = accepted(grant(b, sid, previous=g))
    response, _, _ = delivery(a, b, start, sid, root, g)
    refused(response, "swarm_stale")


def test_t34_t35_incremental_status_historical_inbox_and_expiry(pair, clock):
    a, b, sid, root = pair
    g = accepted(grant(b, sid)); start = accepted(broadcast(a, sid, [b]))
    pending = get(a.client, f"/v2/swarm-broadcasts/{start}")
    assert pending["state"] == "pending" and pending["complete_index"] is None
    response, ciphertext, frame = delivery(a, b, start, sid, root, g)
    delivered = accepted(response)
    state = get(a.client, f"/v2/swarm-broadcasts/{start}")
    assert state["state"] == "complete" and state["complete_index"] == delivered
    next_start = accepted(broadcast(a, sid, [b], closes=int(time.time()) + 10))
    clock[0] += 10
    assert get(a.client, f"/v2/swarm-broadcasts/{next_start}")["state"] == "expired_partial"
    response, _, _ = delivery(a, b, next_start, sid, root, g)
    refused(response, "swarm_broadcast_closed", next_start)
    accepted(leave(b, sid))
    inbox = get(a.client, f"/v2/swarm-inbox/{b.kid}", **{"from": 0})
    assert [r["index"] for r in inbox["deliveries"]["items"]] == [delivered]
    assert a.client.get(f"/v2/bodies/{H(ciphertext)}").content == ciphertext


@pytest.mark.parametrize("changed", ["from_kid", "to_kid", "envelope_nonce", "swarm_id",
                                      "broadcast_index", "membership_index", "extra", "noncanonical", "hash", "rewrapped"])
def test_t35_local_recipient_rejects_tampered_ciphertext_and_inner_context(pair, changed):
    from aics_server.swarms import verify_delivery_ciphertext, verify_delivery_plaintext
    a, b, sid, root = pair
    g = accepted(grant(b, sid)); start = accepted(broadcast(a, sid, [b]))
    response, ciphertext, frame = delivery(a, b, start, sid, root, g, content="Recipient verified content")
    accepted(response)
    q = entry_of(response)["payload"]
    expected = dict(from_kid=a.kid, to_kid=b.kid,
        envelope_nonce=q["envelope"]["protected"]["nonce"], swarm_id=sid,
        broadcast_index=start, membership_index=root)
    verify_delivery_ciphertext(ciphertext, q)
    assert verify_delivery_plaintext(SealedBox(b.xkey).decrypt(ciphertext), **expected) == "Recipient verified content"
    if changed == "hash":
        metadata = dict(q, ct_hash="0" * 64)
        with pytest.raises(ValueError):
            verify_delivery_ciphertext(ciphertext, metadata)
        return
    if changed == "rewrapped":
        # A third party can seal the same plaintext again, but the verified
        # outer leaf commits to the original ciphertext/ephemeral key.
        altered = SealedBox(b.xkey.public_key).encrypt(frame)
    else:
        fields = dict(expected)
        replacements = {"from_kid": b.kid, "to_kid": a.kid, "envelope_nonce": envelope.new_nonce(),
                        "swarm_id": "0" * 64, "broadcast_index": start + 1, "membership_index": root + 1}
        if changed == "extra":
            fields["unregistered"] = "field"
        elif changed != "noncanonical":
            fields[changed] = replacements[changed]
        header = json.dumps(fields).encode() if changed == "noncanonical" else J(fields)
        altered = SealedBox(b.xkey.public_key).encrypt(len(header).to_bytes(4, "big") + header + b"tampered")
    with pytest.raises(ValueError):
        if changed == "rewrapped":
            verify_delivery_ciphertext(altered, q)
        else:
            verify_delivery_plaintext(SealedBox(b.xkey).decrypt(altered), **expected)


def test_t36_full_1000_member_fanout_and_one_vote_with_999_abstentions(swarm_client, clock):
    """All 3,999 actions are signed ordinary writes; no database seeding bypasses admission."""
    members = [member(swarm_client) for _ in range(1000)]
    sender, peer = members[:2]
    sid, root = form(sender, peer)
    admissions = {sender.index: root, peer.index: root}
    roster = root
    for m in members[2:]:
        roster = accepted(m.write("swarm.join", {"swarm_id": sid, "member_index": m.index,
            "target_member_index": sender.index, "roster_index": roster}))
        admissions[m.index] = roster
    p = accepted(proposal(sender, sid))
    accepted(vote(sender, p))
    clock[0] += 10
    accepted(resolve(sender, p, yes=1, electorate=1000))
    grants = {}
    for m in members[1:]:
        grants[m.index] = accepted(m.write("swarm.grant", {"swarm_id": sid, "owner_kid": m.kid,
            "admission_index": admissions[m.index], "max": 1, "expires": int(time.time()) + 86400,
            "prev_grant_index": None}))
    start = accepted(broadcast(sender, sid, members[1:]))
    status = get(swarm_client, f"/v2/swarm-broadcasts/{start}")
    assert status["recipient_count"] == 999 and status["excluded_count"] == 0
    seen = []
    while True:
        assert len(status["recipients"]["items"]) <= 25
        assert len(U(J(status)).encode()) < 131072
        seen.extend(r["member_index"] for r in status["recipients"]["items"])
        after = status["recipients"]["next_after"]
        if after is None:
            break
        status = get(swarm_client, f"/v2/swarm-broadcasts/{start}",
                     at_size=status["checkpoint"]["size"], after_member_index=after)
    assert seen == [m.index for m in members[1:]]
    for m in members[1:]:
        response, _, _ = delivery(sender, m, start, sid, roster, grants[m.index])
        accepted(response)
    complete = get(swarm_client, f"/v2/swarm-broadcasts/{start}")
    assert complete["state"] == "complete" and complete["delivered_count"] == 999
    assert complete["remaining_count"] == 0
    # Initial intro, form, proposal, vote, resolve, start and every delivery use
    # the same sender chain, proving fanout did not bypass per-write accounting.
    assert sender.signer.last_envelope["protected"]["seq"] == 1004


def test_t37_delivery_retains_ciphertext_for_90_days_and_never_erases_leaf(pair, clock):
    a, b, sid, root = pair
    g = accepted(grant(b, sid)); start = accepted(broadcast(a, sid, [b]))
    response, ciphertext, _ = delivery(a, b, start, sid, root, g)
    index = accepted(response)
    committed = get(a.client, f"/v2/entries/{index}")["entry_bytes"]
    clock[0] += 7776000 - 1
    assert a.client.get(f"/v2/bodies/{H(ciphertext)}").content == ciphertext
    clock[0] += 1
    assert get(a.client, f"/v2/entries/{index}")["entry_bytes"] == committed
    assert 999 * 65536 == 65_470_464


def test_t38_t39_join_code_outside_window_is_public_deterministic_and_never_sent(swarm_client):
    raw = secrets.token_bytes(32)
    origin = origin_of(swarm_client)
    code = H(b"AICS-SWARMS-1 rendezvous\n" + J({"origin": origin, "code": U(raw)}))
    other = H(b"AICS-SWARMS-1 rendezvous\n" + J({"origin": "other.example/tiles", "code": U(raw)}))
    assert code != other
    a = member(swarm_client, code=code)
    assert get(swarm_client, f"/v2/rendezvous/{code}")["state"] == "waiting"
    b = member(swarm_client, code=code)
    r = get(swarm_client, f"/v2/rendezvous/{code}", requester_member_index=a.index)
    assert r["state"] == "pair" and r["target_member_index"] == b.index
    sid, root = form(a, b, code=code)
    c = member(swarm_client, code=code)
    for _ in range(100):
        member(swarm_client)
    assert a.index not in {row["member_index"] for row in all_arrivals(swarm_client)}
    r = get(swarm_client, f"/v2/rendezvous/{code}", requester_member_index=c.index)
    assert r["state"] == "join" and r["swarm_id"] == sid
    accepted(join(c, a, sid))
    for m in (a, b, c):
        assert U(raw).encode() not in m.signer.last_request[2]


def test_t39_code_formation_race_keeps_one_id_and_retirement_is_permanent(swarm_client):
    code = H(b"public deterministic rendezvous label")
    a, b, c, d = (member(swarm_client, code=code) for _ in range(4))
    sid, q, body, nonce = formation(c, d, code=code)
    same, root = form(a, b, code=code)
    assert same == sid
    refused(c.write("swarm.form", q, body, nonce=nonce), "swarm_id_taken", root)
    assert c.info()["swarm_id"] is None
    accepted(leave(a, sid)); retired = accepted(leave(b, sid))
    state = get(swarm_client, f"/v2/rendezvous/{code}", requester_member_index=c.index)
    assert state["state"] == "retired" and state["swarm_id"] == sid
    _, q, body, nonce = formation(c, d, code=code)
    refused(c.write("swarm.form", q, body, nonce=nonce), "swarm_retired", retired)


def test_t40_profile_updates_obey_per_key_rate_and_do_not_displace_other_roots(tmp_path, clock):
    limits = {**TEST_LIMITS, "writes": {"count": 4, "interval_seconds": 60}}
    swarm_client = TestClient(create_app(db_path=tmp_path / "limited.db", limits=limits, announce=False, swarms=True))
    a, b = member(swarm_client), member(swarm_client)
    assert a.info()["member_index"] == a.index
    for n in range(3):
        accepted(a.intro(model=f"update {n}"))
    refused(a.intro(model="overflow"), "rate_limit")
    accepted(b.intro(model="A different key has its own quota"))
    assert [r["member_index"] for r in all_arrivals(swarm_client)] == [b.index, a.index]
    clock[0] += 60
    accepted(a.intro(model="The published window is over"))
    swarm_client.close()


def test_t43_projection_reproduces_log_membership_and_rejects_tampering(pair):
    a, b, sid, root = pair
    c = member(a.client); added = accepted(join(c, b, sid)); departed = accepted(leave(b, sid))
    state = swarm(a.client, sid)
    reconstructed = {}
    for n in range(state["checkpoint"]["size"]):
        response = get(a.client, f"/v2/entries/{n}")
        entry = json.loads(keys.b64u_decode(response["entry_bytes"]))
        q = entry["payload"]["envelope"]["payload"]
        if q.get("swarm_id") != sid:
            continue
        if entry["type"] == "swarm.form":
            reconstructed.update({a.index: a.kid, b.index: b.kid})
        elif entry["type"] == "swarm.join":
            reconstructed[q["member_index"]] = entry["actor_kid"]
        elif entry["type"] == "swarm.leave":
            reconstructed.pop(q["member_index"])
    rows = [{"member_index": n, "actor_id": kid} for n, kid in sorted(reconstructed.items())]
    assert state["roster_hash"] == H(J(rows))
    tampered = rows + [{"member_index": b.index, "actor_id": b.kid}]
    assert H(J(tampered)) != state["roster_hash"]
    assert state["roster_index"] == departed


def test_t44_missing_or_unknown_projection_evidence_does_not_invent_state(pair):
    a, b, sid, root = pair
    assert a.client.get("/v2/agents/999999").status_code == 404
    assert a.client.get(f"/v2/swarms/{'f' * 64}").status_code == 404
    assert a.client.get(f"/v2/checkpoint-notes/{'f' * 64}").status_code == 404


def test_t45_t46_t47_registered_profile_card_preserves_base_retention_and_rates(swarm_client):
    from aics_server import envelopes as ev
    card = get(swarm_client, "/.well-known/aics-card.json")
    assert "SWARMS-1" in card["spec"] and card["version"] == "0.2-draft"
    assert card["spec_versions"]["swarms"] == "0.2-draft"
    assert card["swarms"] == {"discovery_window": 100, "model_bytes": 128, "keyword_bytes": 32,
        "keyword_count": 3, "name_bytes": 128, "proposal_max_seconds": 604800,
        "broadcast_max_seconds": 86400, "eject_seconds": 86400, "minimum_supported_members": 1000,
        "private_mode": "sealed-box-fanout", "private_default": "all", "join_code": True}
    assert TYPES <= set(ev.TYPES)
    assert len(set(ev.TYPES)) == 30
    assert card["retention"]["swarm_delivery_seconds"] >= 7776000
    assert set(card["reason_codes"]["refusal"]) >= CODES
    writes = card["limits"]["writes"]
    assert writes["interval_seconds"] <= 3600
    assert writes["count"] * 86400 // writes["interval_seconds"] >= 1000


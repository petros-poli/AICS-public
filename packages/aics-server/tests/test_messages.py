"""Private messages, capsules and consent grants as leaves; refusals, limits, tombstones, suspensions, freeze.

DESIGN.md section 4.2 items 3 and 8 to 10, section 6 and section 8;
DECISIONS.md #4 (messages and capsules go in the log) and #8 (inboxes start
closed).  Every accepted write is ``POST /v2/entries`` answered 202 with the
exact entry and its log-signed receipt (AICS-1 sections 10.1 and 12.1); every
refused write is a policy-signed ``refusal`` leaf with its own receipt and a
4xx, naming the attempt by hash, never retaining the refused body; tombstones,
suspensions and freezes are leaves and never remove one.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, ClassVar

import pytest
from fastapi.testclient import TestClient

from aics_identity import canonical_text, envelope, keys, sealed
from aics_server.app import create_app
from aics_server.db import (
    DEFAULT_LIMITS,
    ENCRYPTION_SCHEMES,
    REFUSAL_REASONS,
    TOMBSTONE_TARGETS,
    load_limits,
)
from aics_tlog import verify_consistency, verify_leaf_inclusion

from conftest import SEALED, TEST_LIMITS, Agent, J, Owner, Signer, artifacts, fetch_leaf, signed_request
from conftest import ENTRIES, entry_bundle, entry_of, leaf_index, reason, refusal_q, secret_claim, secret_claim_reply, secret_post

#: AICS-1 sections 5.1 and 5.3: the envelope and an exact copy of the signed Q, nothing the server adds; the
#: grant that admits a message is named inside Q (grant_index), and seq/prev repeat the envelope's.
DM_LEAF_KEYS = {
    "envelope",
    "to_kid",
    "to_key_leaf_index",
    "encryption",
    "eph_pk",
    "ct_hash",
    "size",
    "seq",
    "prev",
    "grant_index",
}
#: The same rule for capsules: Q names the slot's previous capsule leaf (prev_capsule_index, null for a new slot).
CAPSULE_LEAF_KEYS = {
    "envelope",
    "owner_kid",
    "key_hash",
    "to_key_leaf_index",
    "encryption",
    "eph_pk",
    "ct_hash",
    "size",
    "expires",
    "prev_capsule_index",
}
LEAKED_TOKEN = "ghp_1234567890abcdefghijklmnopQRSTUV"
#: AICS-1 section 8.2: superseded capsule ciphertext stays retrievable this long after its own leaf.
NINETY_DAYS = 7776000


def slot(key: str) -> str:
    """A capsule slot's name on the service: ``key_hash``, the SHA-256 of the agent's own slot key."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


STATE = slot("state")
#: A body for an entry type without one (a grant): any U64 text.
U64_TEXT = keys.b64u_encode(b"a grant has no off-leaf body")
AVAILABLE = {"state": "available", "tombstone_index": None, "reason_code": None, "policy_index": None}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def tree_size(client: TestClient) -> int:
    return client.get("/v2/tlog/checkpoint").json()["tree_size"]


def receipt_text(receipt_note: str) -> dict[str, Any]:
    """The JSON text of a ``U64`` receipt note (AICS-1 section 10.1); its signature is checked by the client tests."""
    note = keys.b64u_decode(receipt_note).decode("utf-8")
    text, _, _ = note.partition("\n")
    return json.loads(text)


def assert_refusal(response, reason: str, *, status: int, conflict_index: Any = ...) -> dict[str, Any]:
    """A refused write: the given 4xx and the policy-signed refusal entry with its receipt (AICS-1 sections 10.2, 12.1).

    Returns the answer, ``{entry, receipt_note}``.
    """
    assert response.status_code == status, response.text
    body = response.json()
    assert set(body) == {"entry", "receipt_note"}, "an authenticated refusal is a leaf with its receipt"
    entry = body["entry"]
    assert entry["type"] == "refusal"
    assert entry["payload"]["reason_code"] == reason
    assert entry["payload"]["envelope"]["protected"]["kid"] == entry["actor_kid"]  # the policy key
    assert receipt_text(body["receipt_note"])["entry_hash"] == hashlib.sha256(b"\x00" + J(entry)).hexdigest()
    if conflict_index is not ...:
        assert entry["payload"]["conflict_index"] == conflict_index
    return body


def verify_receipt(client: TestClient, response) -> int:
    """An accepted native write: 202, its exact entry at ``Location``, a receipt for it, and its inclusion proof."""
    assert response.status_code == 202, response.text
    written = response.json()
    assert set(written) == {"entry", "receipt_note"}
    entry, index = written["entry"], leaf_index(response)
    leaf_bytes = canonical_text(entry).encode("utf-8")
    assert receipt_text(written["receipt_note"])["entry_hash"] == hashlib.sha256(b"\x00" + leaf_bytes).hexdigest()
    stored = fetch_leaf(client, index)
    assert stored["leaf_data"] == entry
    audit = [bytes.fromhex(h) for h in stored["inclusion_proof_hex"]]
    assert verify_leaf_inclusion(leaf_bytes, index, stored["tree_size"], audit, bytes.fromhex(stored["root_hash_hex"]))
    return index


def verify_admin_receipt(client: TestClient, written: dict[str, Any]) -> int:
    """An owner-login administration answer: its exact entry, leaf index and an inclusion proof under the checkpoint."""
    entry, proof = written["entry"], written["merkle_proof"]
    leaf_bytes = canonical_text(entry).encode("utf-8")
    assert proof["leaf_hash_hex"] == hashlib.sha256(b"\x00" + leaf_bytes).hexdigest()
    audit = [bytes.fromhex(h) for h in proof["inclusion_proof_hex"]]
    root = bytes.fromhex(proof["root_hash_hex"])
    assert verify_leaf_inclusion(leaf_bytes, proof["leaf_index"], proof["tree_size"], audit, root)
    assert base64.b64encode(root).decode() in proof["signed_checkpoint"]
    assert fetch_leaf(client, proof["leaf_index"])["leaf_data"] == entry
    return proof["leaf_index"]


def table_text(db_path: Path) -> bytes:
    """Every committed leaf, as stored."""
    with sqlite3.connect(db_path) as conn:
        return b"\n".join(r[0].encode() for r in conn.execute("SELECT leaf_json FROM tlog_leaves ORDER BY leaf_index"))


def count(client: TestClient, table: str) -> int:
    return client.app.state.db._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def make_client(tmp_path: Path, owner: Owner, name: str = "limits.db", **limits: Any) -> TestClient:
    test_client = TestClient(
        create_app(db_path=tmp_path / name, owner_public_key=owner.public_key_b64u, announce=False, limits=limits or TEST_LIMITS)
    )
    owner.client = test_client
    owner.origin = test_client.get("/v2/tlog/checkpoint").json()["origin"]
    return test_client


def new_agent(client: TestClient, name: str, **claim_kwargs: Any) -> Agent:
    agent = Agent(client, client.get("/v2/tlog/checkpoint").json()["origin"])
    response = agent.claim(name, **claim_kwargs)
    assert response.status_code == 202, response.text
    return agent


def age_blob(payload_bytes: int = 64) -> bytes:
    """Bytes shaped like a binary age v1 file to one X25519 recipient (the server cannot decrypt; it checks shape)."""

    def b64(data: bytes) -> bytes:
        return base64.b64encode(data).rstrip(b"=")

    return (
        b"age-encryption.org/v1\n-> X25519 "
        + b64(os.urandom(32))
        + b"\n"
        + b64(os.urandom(32))
        + b"\n--- "
        + b64(os.urandom(32))
        + b"\n"
        + os.urandom(16 + payload_bytes)
    )


@pytest.fixture()
def alice(make_agent) -> Agent:
    return make_agent("alice")


@pytest.fixture()
def bob(make_agent) -> Agent:
    return make_agent("bob")


@pytest.fixture()
def granted(alice: Agent, bob: Agent) -> int:
    """Bob lets Alice send him ten messages; returns the grant leaf index."""
    response = bob.grant(alice.kid, 10)
    assert response.status_code == 202, response.text
    return leaf_index(response)


# ---------------------------------------------------------------------------
# direct messages are leaves
# ---------------------------------------------------------------------------


class TestDirectMessageLeaves:
    def test_a_dm_is_a_leaf_with_the_signed_metadata_and_a_receipt(self, client, alice, bob, granted):
        before = tree_size(client)
        to = alice.lookup("bob")
        response = alice.send_dm(to, "the plan is in capsule 7")
        index = verify_receipt(client, response)
        assert tree_size(client) == before + 1
        entry = response.json()["entry"]
        assert entry["type"] == "dm" and entry["actor_kid"] == alice.kid
        payload = entry["payload"]
        assert set(payload) == DM_LEAF_KEYS
        ct = alice.last_dm["ciphertext"]
        assert payload["to_kid"] == bob.kid
        assert payload["to_key_leaf_index"] == to["x25519_leaf_index"] == bob.head_index
        assert payload["encryption"] == SEALED
        assert payload["ct_hash"] == hashlib.sha256(ct).hexdigest()
        assert payload["size"] == len(ct)
        assert payload["eph_pk"] == keys.b64u_encode(ct[:32])
        assert payload["grant_index"] == granted  # signed inside Q
        env = payload["envelope"]
        assert (payload["seq"], payload["prev"]) == (env["protected"]["seq"], env["protected"]["prev"])
        # The leaf repeats exactly what the sender signed, and nothing else (AICS-1 section 5.1).
        assert env["payload"] == {k: v for k, v in payload.items() if k != "envelope"}
        assert env["protected"]["type"] == "dm" and env["protected"]["origin"] == entry["origin"]
        # The body stays off-leaf: the section 14.3 bundle carries it beside the entry, the body service by its hash.
        assert keys.b64u_encode(ct) not in json.dumps(entry)
        bundle, status = entry_bundle(client, index)
        assert keys.b64u_decode(bundle["body_or_ct"]) == ct and status == AVAILABLE
        assert bundle["envelope"] == env and keys.b64u_decode(bundle["entry_bytes"]) == J(entry)
        served = client.get(f"/v2/bodies/{payload['ct_hash']}")
        assert served.status_code == 200 and served.content == ct
        listed = client.get(f"/v2/inbox/{bob.kid}").json()["messages"][0]
        assert listed["leaf_index"] == index and listed["body"] == "stored" and listed["grant_index"] == granted

    def test_the_recipient_opens_the_message_against_its_envelope(self, client, alice, bob, granted):
        assert alice.send_dm(alice.lookup("bob"), "meet at capsule 7").status_code == 202
        status = bob.get("/v2/inbox/status").json()
        assert status["unread_count"] == 1 and status["total_count"] == 1
        assert alice.get("/v2/inbox/status").json()["total_count"] == 0
        inbox = bob.get("/v2/inbox").json()
        assert inbox["count"] == 1
        message = inbox["messages"][0]
        assert message["from_kid"] == alice.kid and message["from_name"] == "alice" and "subject" not in message
        env = message["envelope"]
        sender = client.get(f"/v2/keys/{message['from_kid']}").json()
        envelope.verify_envelope(env, lambda kid: sender["public_key_b64u"], now=env["protected"]["created"])
        ct = keys.b64u_decode(message["ciphertext"])
        opened = sealed.open_sealed(ct, bob.x25519, envelope=env, recipient_kid=bob.kid)
        assert opened.text == "meet at capsule 7"
        assert opened.header.from_kid == alice.kid and opened.header.envelope_nonce == env["protected"]["nonce"]
        assert bob.get("/v2/inbox/status").json()["unread_count"] == 0
        assert bob.get("/v2/inbox?unread_only=true", components=("@method", "@authority", "@path", "@query", "content-digest")).json()["count"] == 0

    def test_a_rewrapped_ciphertext_is_detected_by_the_recipient(self, client, make_agent, alice, bob, granted):
        """Mallory lifts Alice's logged ciphertext into her own envelope: the inner header gives it away."""
        mallory = make_agent("mallory")
        assert bob.grant(mallory.kid, 5).status_code == 202
        assert alice.send_dm(alice.lookup("bob"), "only from alice").status_code == 202
        stolen = alice.last_dm["ciphertext"]
        assert mallory.send_dm(mallory.lookup("bob"), ciphertext=stolen).status_code == 202  # the server cannot tell
        inbox = {m["from_kid"]: m for m in bob.get("/v2/inbox").json()["messages"]}
        lifted = inbox[mallory.kid]
        with pytest.raises(sealed.HeaderMismatch):
            sealed.open_sealed(keys.b64u_decode(lifted["ciphertext"]), bob.x25519, envelope=lifted["envelope"])
        genuine = inbox[alice.kid]
        assert sealed.open_sealed(keys.b64u_decode(genuine["ciphertext"]), bob.x25519, envelope=genuine["envelope"]).text == "only from alice"

    def test_the_public_inbox_lists_metadata_in_log_order_without_bodies(self, client, alice, bob, granted):
        to = alice.lookup("bob")
        indices = [leaf_index(alice.send_dm(to, f"message {i}")) for i in range(3)]
        listing = client.get(f"/v2/inbox/{bob.kid}").json()
        # AICS-1 section 12.1: the indices from ``from``, in log order, through a stated signed checkpoint.
        assert listing["to_kid"] == bob.kid and listing["from"] == 0 and listing["next_from"] is None
        assert listing["indices"] == indices == [m["leaf_index"] for m in listing["messages"]]
        note = keys.b64u_decode(listing["checkpoint_note"]).decode("utf-8")
        assert note == client.get("/checkpoint").text and int(note.split("\n")[1]) == listing["size"] > indices[-1]
        for message in listing["messages"]:
            assert "ciphertext" not in message and "envelope" not in message
            assert message["from_kid"] == alice.kid and message["grant_index"] == granted and message["body"] == "stored"
        assert client.get(f"/v2/inbox/{bob.kid}", params={"from": indices[1]}).json()["indices"] == indices[1:]
        page = client.get(f"/v2/inbox/{bob.kid}", params={"limit": 2}).json()
        assert page["indices"] == indices[:2] and page["next_from"] == indices[1] + 1
        rest = client.get(f"/v2/inbox/{bob.kid}", params={"from": page["next_from"], "limit": 2}).json()
        assert rest["indices"] == indices[2:] and rest["next_from"] is None
        assert client.get(f"/v2/inbox/{alice.kid}").json()["indices"] == []
        assert client.get("/v2/inbox/not-a-kid").status_code == 404

    @pytest.mark.parametrize(
        "overrides",
        [{"ct_hash": "0" * 64}, {"size": 7}, {"eph_pk": keys.b64u_encode(b"\x09" * 32)}],
        ids=["ct_hash", "size", "eph_pk"],
    )
    def test_the_server_recomputes_the_body_metadata(self, client, db_path, alice, bob, granted, overrides):
        before = tree_size(client)
        response = alice.send_dm(alice.lookup("bob"), "tampered", overrides=overrides)
        refusal = assert_refusal(response, "digest_mismatch", status=422)
        assert refusal["entry"]["payload"]["envelope_hash"] == envelope.envelope_hash(alice.last_dm["envelope"])
        assert refusal["entry"]["payload"]["attempt_kid"] == alice.kid
        assert tree_size(client) == before + 1 and count(client, "messages") == 0
        assert keys.b64u_encode(alice.last_dm["ciphertext"]).encode() not in table_text(db_path)
        # The refusal did not advance Alice's chain: the next envelope continues from her last accepted one.
        assert alice.send_dm(alice.lookup("bob"), "honest").status_code == 202

    def test_the_ciphertext_must_be_canonical_base64url(self, client, alice, bob, granted):
        # The body member of POST /v2/entries is U64 (AICS-1 section 12.1); a signed request whose body is not is a
        # schema failure, refused with a leaf.
        response = alice.send_dm(alice.lookup("bob"), "x", ciphertext_text="not base64url!")
        assert_refusal(response, "malformed", status=400)
        padded = keys.b64u_encode(os.urandom(64)) + "=="
        assert_refusal(alice.send_dm(alice.lookup("bob"), "x", ciphertext_text=padded), "malformed", status=400)
        assert count(client, "messages") == 0

    def test_a_ciphertext_shorter_than_a_sealed_box_is_malformed(self, client, alice, bob, granted):
        assert_refusal(alice.send_dm(alice.lookup("bob"), ciphertext=os.urandom(40)), "malformed", status=422)

    def test_a_body_over_the_published_cap_is_refused(self, client, alice, bob, granted):
        to = alice.lookup("bob")
        header = sealed.InnerHeader(from_kid=alice.kid, to_kid=to["kid"], envelope_nonce=envelope.new_nonce())
        big = sealed.seal(header, b"x" * 70000, to["x25519_public_key_b64u"], max_ciphertext_bytes=None)
        assert len(big) > DEFAULT_LIMITS["ciphertext_bytes"]
        assert_refusal(alice.send_dm(to, ciphertext=big), "too_large", status=413)

    def test_sending_needs_a_signature(self, client, bob):
        assert client.post(ENTRIES, json={"envelope": {}, "body": "eA"}).status_code == 401
        assert client.post("/v2/messages", json={"ciphertext": "x", "envelope": {}}).status_code == 404  # one write path


# ---------------------------------------------------------------------------
# no subject, no cleartext
# ---------------------------------------------------------------------------


class TestNoSubjectNoCleartext:
    def test_the_subject_field_is_gone(self, client, alice, bob, granted):
        to = alice.lookup("bob")
        # Beside the envelope: POST /v2/entries takes exactly {envelope, body}, refused before anything is logged.
        beside = alice.send_dm(to, "hi", extra_fields={"subject": "meeting notes"})
        assert beside.status_code == 400 and reason(beside) == "malformed"
        # Inside Q: a schema failure of a signed envelope, refused with a leaf.
        inside = alice.send_dm(to, "hi", overrides={"subject": "meeting notes"})
        assert_refusal(inside, "malformed", status=400)
        columns = {r[1] for r in client.app.state.db._conn.execute("PRAGMA table_info(messages)")}
        assert "subject" not in columns
        assert alice.send_dm(to, "hi").status_code == 202
        message = bob.get("/v2/inbox").json()["messages"][0]
        assert "subject" not in message and "subject" not in message["envelope"]["payload"]

    @pytest.mark.parametrize("scheme", ["cleartext-signed", "e2ee-v1", "none", "aes-256-gcm", "X25519-XSALSA20-POLY1305"])
    def test_cleartext_and_unknown_schemes_are_refused_with_a_leaf(self, client, db_path, alice, bob, granted, scheme):
        before = tree_size(client)
        plaintext = b"The meeting moves to Thursday; bring the keys."
        response = alice.send_dm(alice.lookup("bob"), ciphertext=plaintext, encryption=scheme)
        refusal = assert_refusal(response, "unsupported_scheme", status=422)
        payload = refusal["entry"]["payload"]
        assert payload["envelope_hash"] == envelope.envelope_hash(alice.last_dm["envelope"])
        assert set(payload) == {
            "envelope",
            "envelope_hash",
            "request_hash",
            "attempt_kid",
            "attempt_nonce",
            "attempt_expires",
            "reason_code",
            "conflict_index",
            "receipt_hash",
        }
        assert payload["receipt_hash"] is None  # only a replay of an accepted envelope names a receipt
        assert tree_size(client) == before + 1 and count(client, "messages") == 0
        stored = db_path.read_bytes() + table_text(db_path)
        assert plaintext not in stored and keys.b64u_encode(plaintext).encode() not in stored

    def test_cleartext_labelled_age_is_refused(self, client, alice, bob, granted):
        response = alice.send_dm(alice.lookup("bob"), ciphertext=b"plain words, not an age file" * 3, encryption="age-v1", overrides={"eph_pk": None})
        assert_refusal(response, "malformed", status=422)

    def test_an_age_file_is_accepted_with_a_null_eph_pk(self, client, alice, bob, granted):
        blob = age_blob()
        response = alice.send_dm(alice.lookup("bob"), ciphertext=blob, encryption="age-v1", overrides={"eph_pk": None})
        assert response.status_code == 202, response.text
        payload = response.json()["entry"]["payload"]
        assert payload["encryption"] == "age-v1" and payload["eph_pk"] is None
        assert payload["ct_hash"] == hashlib.sha256(blob).hexdigest()
        bad = alice.send_dm(alice.lookup("bob"), ciphertext=age_blob(), encryption="age-v1")  # eph_pk not null
        assert_refusal(bad, "malformed", status=422)

    def test_the_scheme_list_is_closed(self):
        assert ENCRYPTION_SCHEMES == ("x25519-xsalsa20-poly1305", "age-v1")


# ---------------------------------------------------------------------------
# consent: closed inboxes, grants as leaves
# ---------------------------------------------------------------------------


class TestConsent:
    def test_an_inbox_is_closed_by_default_and_refuses_with_a_leaf(self, client, alice, bob):
        assert fetch_leaf(client, bob.head_index)["leaf_data"]["payload"]["initial_grant"] is None
        assert count(client, "grants") == 0
        response = alice.send_dm(alice.lookup("bob"), "hello bob")
        refusal = assert_refusal(response, "no_consent", status=403, conflict_index=None)
        assert refusal["entry"]["payload"]["attempt_kid"] == alice.kid
        assert count(client, "messages") == 0
        assert bob.get("/v2/inbox").json()["count"] == 0

    def test_a_grant_is_a_recipient_signed_leaf(self, client, alice, bob):
        expires = int(time.time()) + 600
        response = bob.grant(alice.kid, 2, expires)
        index = verify_receipt(client, response)
        entry = response.json()["entry"]
        assert entry["type"] == "grant" and entry["actor_kid"] == bob.kid
        payload = entry["payload"]
        assert set(payload) == {"envelope", "owner_kid", "sender_kid", "max", "expires", "prev_grant_index"}
        assert (payload["owner_kid"], payload["sender_kid"], payload["max"], payload["expires"]) == (bob.kid, alice.kid, 2, expires)
        assert payload["prev_grant_index"] is None  # the first grant for this pair
        assert payload["envelope"]["protected"]["kid"] == bob.kid
        assert entry_bundle(client, index)[1] is None  # a grant has no off-leaf body: no X-AICS-Body-Status
        listing = client.get(f"/v2/inbox/{bob.kid}/grants").json()
        assert listing["grants"] == [
            {
                "grant_index": index,
                "owner_kid": bob.kid,
                "sender_kid": alice.kid,
                "max": 2,
                "expires": expires,
                "used": 0,
                "remaining": 2,
                "current": True,
                "active": True,
            }
        ]
        assert client.get(f"/v2/keys/{bob.kid}").json()["envelope_chain"]["last_index"] == index

    def test_only_the_owner_signs_its_grants(self, client, alice, bob):
        response = alice.grant(alice.kid, 5, overrides={"owner_kid": bob.kid})
        assert response.status_code == 400
        assert count(client, "grants") == 0

    def test_grants_are_validated(self, client, alice, bob):
        assert bob.grant("alice", 5).status_code == 400  # names are never grant subjects
        assert bob.grant(alice.kid, -1).status_code == 400
        assert bob.grant(alice.kid, 5, int(time.time()) - 10).status_code == 400
        noted = bob.grant(alice.kid, 5, fields={"body": None, "note": "free text"})  # nothing beside {envelope, body}
        assert noted.status_code == 400 and "entry" not in noted.json()
        assert bob.grant(alice.kid, 5, fields={"body": U64_TEXT}).status_code == 400  # a grant has no body
        assert bob.grant(alice.kid, 0, 0).status_code == 202  # a revocation may name any time
        assert bob.grant(alice.kid, 10001).status_code == 202  # no cap below the uint range (AICS-1 section 5.3)

    def test_a_grant_names_the_latest_grant_for_its_pair(self, client, make_agent, alice, bob):
        first = leaf_index(bob.grant(alice.kid, 5))
        stale = bob.grant(alice.kid, 7, overrides={"prev_grant_index": None})
        assert_refusal(stale, "stale_grant", status=409, conflict_index=first)
        assert reason(bob.grant(alice.kid, 7, overrides={"prev_grant_index": first + 1})) == "stale_grant"
        second = bob.grant(alice.kid, 7)
        assert second.status_code == 202 and second.json()["entry"]["payload"]["prev_grant_index"] == first
        # The chain is per exact (owner_kid, sender_kid) pair: the wildcard has its own.
        wildcard = bob.grant("*", 3)
        assert wildcard.status_code == 202 and wildcard.json()["entry"]["payload"]["prev_grant_index"] is None
        # An initial grant inside a claim counts, at the claim's index.
        opened = make_agent("opened", initial_grant={"sender_kid": "*", "max": 5, "expires": int(time.time()) + 3600})
        assert opened.latest_grant("*") == opened.head_index
        assert_refusal(opened.grant("*", 2, overrides={"prev_grant_index": None}), "stale_grant", status=409,
                       conflict_index=opened.head_index)
        assert opened.grant("*", 2).status_code == 202

    def test_a_dm_names_the_grant_that_governs_it(self, client, alice, bob):
        first = leaf_index(bob.grant(alice.kid, 5))
        second = leaf_index(bob.grant(alice.kid, 5))
        to = alice.lookup("bob")
        stale = alice.send_dm(to, "citing the replaced grant", overrides={"grant_index": first})
        assert_refusal(stale, "stale_grant", status=409, conflict_index=second)
        assert count(client, "messages") == 0
        accepted = alice.send_dm(to, "citing the governing grant")
        assert accepted.status_code == 202 and accepted.json()["entry"]["payload"]["grant_index"] == second
        # seq and prev in Q repeat the envelope's.
        mismatch = alice.send_dm(to, "seq differs", overrides={"seq": 99})
        assert mismatch.status_code == 400 and reason(mismatch) == "malformed"

    def test_an_allowance_is_used_up_and_refusals_do_not_count(self, client, alice, bob):
        index = leaf_index(bob.grant(alice.kid, 2))
        to = alice.lookup("bob")
        for _ in range(2):
            response = alice.send_dm(to, "within the allowance")
            assert response.status_code == 202 and entry_of(response)["payload"]["grant_index"] == index
        assert_refusal(alice.send_dm(to, "one too many"), "grant_exhausted", status=403, conflict_index=index)
        assert_refusal(alice.send_dm(to, "still too many"), "grant_exhausted", status=403, conflict_index=index)
        grant = client.get(f"/v2/inbox/{bob.kid}/grants").json()["grants"][0]
        assert (grant["used"], grant["remaining"], grant["active"]) == (2, 0, False)

    def test_a_revocation_is_a_grant_leaf_and_never_falls_back_to_a_wildcard(self, client, make_agent, alice, bob):
        carol = make_agent("carol")
        wildcard = leaf_index(bob.grant("*", 5))
        exact = leaf_index(bob.grant(alice.kid, 5))
        to = alice.lookup("bob")
        assert entry_of(alice.send_dm(to, "via my own grant"))["payload"]["grant_index"] == exact
        revoked = bob.grant(alice.kid, 0, 0)
        assert revoked.status_code == 202
        revocation = leaf_index(revoked)
        assert revoked.json()["entry"]["payload"]["max"] == 0
        assert_refusal(alice.send_dm(to, "after revocation"), "no_consent", status=403, conflict_index=revocation)
        assert entry_of(carol.send_dm(carol.lookup("bob"), "via the wildcard"))["payload"]["grant_index"] == wildcard
        # A message accepted before the revocation stays in the log and in the inbox.
        assert bob.get("/v2/inbox").json()["count"] == 2

    def test_a_wildcard_allowance_is_shared_by_every_sender(self, client, make_agent, alice, bob):
        index = leaf_index(bob.grant("*", 2))
        carol, dora = make_agent("carol"), make_agent("dora")
        assert alice.send_dm(alice.lookup("bob"), "one").status_code == 202
        assert carol.send_dm(carol.lookup("bob"), "two").status_code == 202
        assert_refusal(dora.send_dm(dora.lookup("bob"), "three"), "grant_exhausted", status=403, conflict_index=index)

    def test_a_new_grant_replaces_the_old_one_and_resets_the_allowance(self, client, alice, bob):
        first = leaf_index(bob.grant(alice.kid, 1))
        to = alice.lookup("bob")
        assert alice.send_dm(to, "first").status_code == 202
        assert_refusal(alice.send_dm(to, "second"), "grant_exhausted", status=403, conflict_index=first)
        second = leaf_index(bob.grant(alice.kid, 1))
        assert entry_of(alice.send_dm(to, "second, again"))["payload"]["grant_index"] == second
        states = {g["grant_index"]: g["current"] for g in client.get(f"/v2/inbox/{bob.kid}/grants").json()["grants"]}
        assert states == {first: False, second: True}

    def test_an_expired_grant_refuses(self, client, alice, bob):
        index = leaf_index(bob.grant(alice.kid, 5))
        # Let the clock pass the expiry without waiting: the projection row is what the server consults.
        db = client.app.state.db
        with db._transaction():
            db._conn.execute("UPDATE grants SET expires = ? WHERE grant_index = ?", (int(time.time()) - 1, index))
        assert_refusal(alice.send_dm(alice.lookup("bob"), "late"), "no_consent", status=403, conflict_index=index)

    def test_the_initial_grant_rides_in_the_claim(self, client, make_agent, alice):
        carol = make_agent("carol", initial_grant={"sender_kid": "*", "max": 2, "expires": int(time.time()) + 3600})
        assert fetch_leaf(client, carol.head_index)["leaf_data"]["payload"]["initial_grant"]["sender_kid"] == "*"
        to = alice.lookup("carol")
        for _ in range(2):
            response = alice.send_dm(to, "hi carol")
            assert response.status_code == 202 and entry_of(response)["payload"]["grant_index"] == carol.head_index
        assert_refusal(alice.send_dm(to, "again"), "grant_exhausted", status=403, conflict_index=carol.head_index)

    def test_grants_name_keys_so_rotations_do_not_carry_them(self, client, alice, bob, granted):
        # A sender's new key is not the key the grant named.
        assert alice.rotate(Signer()).status_code == 202
        assert_refusal(alice.send_dm(alice.lookup("bob"), "new key"), "no_consent", status=403, conflict_index=None)
        # A recipient's old key is not its current key, and its new key has granted nothing yet.
        old_bob = alice.lookup("bob")
        assert bob.rotate(Signer()).status_code == 202
        assert_refusal(alice.send_dm(old_bob, "to the old key"), "stale_key", status=409, conflict_index=bob.head_index)
        assert_refusal(alice.send_dm(alice.lookup("bob"), "to the new key"), "no_consent", status=403)
        assert bob.grant(alice.kid, 1).status_code == 202
        assert alice.send_dm(alice.lookup("bob"), "now granted").status_code == 202


# ---------------------------------------------------------------------------
# the recipient's key chain decides where a message may go
# ---------------------------------------------------------------------------


class TestRecipientKeys:
    def test_an_unknown_recipient_key_is_refused(self, client, alice, bob, granted):
        to = {**alice.lookup("bob"), "kid": Signer().kid}  # a did:key no name holds
        assert_refusal(alice.send_dm(to, "nobody"), "unknown_key", status=404)

    def test_the_message_must_cite_the_leaf_of_the_current_encryption_key(self, client, alice, bob, granted):
        to = alice.lookup("bob")
        wrong = {**to, "x25519_leaf_index": 0}
        assert_refusal(alice.send_dm(wrong, "stale"), "stale_key", status=409, conflict_index=bob.head_index)
        assert bob.rotate_x25519().status_code == 202
        assert_refusal(alice.send_dm(to, "to the old encryption key"), "stale_key", status=409, conflict_index=bob.head_index)
        fresh = alice.lookup("bob")
        assert fresh["x25519_leaf_index"] == bob.head_index
        response = alice.send_dm(fresh, "to the new encryption key")
        assert response.status_code == 202
        message = bob.get("/v2/inbox").json()["messages"][0]
        assert sealed.open_sealed(keys.b64u_decode(message["ciphertext"]), bob.x25519, envelope=message["envelope"]).text == "to the new encryption key"

    def test_a_revoked_recipient_receives_nothing(self, client, alice, bob, granted):
        to = alice.lookup("bob")
        assert bob.revoke().status_code == 202
        assert_refusal(alice.send_dm(to, "too late"), "revoked", status=409, conflict_index=bob.head_index)


# ---------------------------------------------------------------------------
# capsules
# ---------------------------------------------------------------------------


class TestCapsules:
    def test_a_capsule_put_is_a_leaf(self, client, alice):
        response = alice.put_capsule("session-state", "where I left off")
        index = verify_receipt(client, response)
        entry = response.json()["entry"]
        assert entry["type"] == "capsule" and entry["actor_kid"] == alice.kid
        payload = entry["payload"]
        assert set(payload) == CAPSULE_LEAF_KEYS
        ct = alice.last_capsule["ciphertext"]
        assert payload["owner_kid"] == alice.kid
        assert payload["key_hash"] == hashlib.sha256(b"session-state").hexdigest()
        assert payload["ct_hash"] == hashlib.sha256(ct).hexdigest() and payload["size"] == len(ct)
        assert payload["to_key_leaf_index"] == alice.head_index
        assert payload["prev_capsule_index"] is None  # a new slot
        assert "session-state" not in json.dumps(entry) and keys.b64u_encode(ct) not in json.dumps(entry)
        view = alice.get(f"/v2/capsules/{slot('session-state')}").json()
        assert (view["leaf_index"], view["body"], view["prev_capsule_index"]) == (index, "stored", None)
        assert keys.b64u_decode(view["ciphertext"]) == ct and "capsule_key" not in view
        bundle, status = entry_bundle(client, index)
        assert keys.b64u_decode(bundle["body_or_ct"]) == ct and status == AVAILABLE

    def test_a_put_supersedes_the_body_and_every_leaf_stays(self, client, alice):
        first = alice.put_capsule("state", "version one")
        first_index, first_ct = leaf_index(first), alice.last_capsule["ciphertext"]
        first_entry = fetch_leaf(client, first_index)
        second = alice.put_capsule("state", "version two")
        assert entry_of(second)["payload"]["prev_capsule_index"] == first_index
        assert fetch_leaf(client, first_index)["leaf_data"] == first_entry["leaf_data"]
        got = alice.get(f"/v2/capsules/{STATE}").json()
        assert got["leaf_index"] == leaf_index(second) and got["prev_capsule_index"] == first_index
        opened = sealed.open_sealed(
            keys.b64u_decode(got["ciphertext"]),
            alice.x25519,
            expected={"from_kid": alice.kid, "to_kid": alice.kid, "envelope_nonce": alice.last_capsule["nonce"]},
        )
        assert opened.text == "version two"
        listing = alice.get("/v2/capsules").json()
        assert listing["count"] == 1 and "ciphertext" not in listing["capsules"][0]
        assert listing["capsules"][0]["key_hash"] == STATE and "capsule_key" not in listing["capsules"][0]
        # The superseded body stays retrievable by its hash (AICS-1 section 8.2), in its bundle and at /v2/bodies.
        old = client.get(f"/v2/bodies/{entry_of(first)['payload']['ct_hash']}")
        assert old.status_code == 200 and old.content == first_ct
        bundle, status = entry_bundle(client, first_index)
        assert keys.b64u_decode(bundle["body_or_ct"]) == first_ct and status == AVAILABLE

    def test_a_superseded_body_is_kept_ninety_days_then_expires(self, client, alice, monkeypatch):
        first = alice.put_capsule("state", "version one")
        first_index, ct_hash = leaf_index(first), entry_of(first)["payload"]["ct_hash"]
        first_entry = fetch_leaf(client, first_index)["leaf_data"]
        second = alice.put_capsule("state", "version two", expires=int(time.time()) + 2 * NINETY_DAYS)
        db = client.app.state.db
        now = int(time.time())
        with db._lock, db._transaction():
            assert db._expire_capsule_bodies(now + NINETY_DAYS - 3600) == 0  # still inside the 90 days
        assert client.get(f"/v2/bodies/{ct_hash}").status_code == 200
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + NINETY_DAYS + 60)
        with db._lock, db._transaction():
            assert db._expire_capsule_bodies(int(time.time())) == 1  # the superseded body only
        gone = client.get(f"/v2/bodies/{ct_hash}")
        # Expired under the retention rule in force: no card policy is logged here, so the charter (leaf 0).
        assert gone.status_code == 410
        assert gone.json() == {"state": "expired", "tombstone_index": None, "reason_code": None, "policy_index": 0}
        bundle, status = entry_bundle(client, first_index)
        assert bundle["body_or_ct"] is None and status == gone.json()
        # Every capsule leaf stays, and the slot's current body is still served.
        assert fetch_leaf(client, first_index)["leaf_data"] == first_entry
        current = alice.get(f"/v2/capsules/{STATE}").json()
        assert current["leaf_index"] == leaf_index(second) and current["body"] == "stored"

    def test_a_slot_body_expires_at_its_own_expiry(self, client, alice, monkeypatch):
        put = alice.put_capsule("state", "short lived", expires=int(time.time()) + NINETY_DAYS + 60)
        index = leaf_index(put)
        db = client.app.state.db
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + NINETY_DAYS + 120)
        # Past its expiry the body is not served, before the retention pass deletes it (no request has run it) ...
        assert db.get_capsule(alice.kid, STATE)["ciphertext"] is None
        assert db.entry_body(index).state == "expired" and db.entry_body(index).policy_index == 0
        with db._lock, db._transaction():
            assert db._expire_capsule_bodies(int(time.time())) == 1
        # ... and after it, while the leaf stays.
        view = alice.get(f"/v2/capsules/{STATE}").json()
        assert view["ciphertext"] is None and view["body"] == "expired"
        bundle, status = entry_bundle(client, index)
        assert bundle["body_or_ct"] is None and status == {"state": "expired", "tombstone_index": None, "reason_code": None, "policy_index": 0}
        assert fetch_leaf(client, index)["leaf_data"] == entry_of(put)

    def test_a_mismatching_client_hash_is_refused(self, client, alice):
        response = alice.put_capsule("state", overrides={"ct_hash": "0" * 64})
        assert_refusal(response, "digest_mismatch", status=422)
        assert alice.get(f"/v2/capsules/{STATE}").status_code == 404

    def test_a_slot_is_named_by_its_key_hash_only(self, client, alice):
        # The slot key itself never reaches the service (AICS-1 section 8.2): Q and the reads name it by hash.
        assert alice.put_capsule("bad/key").status_code == 202
        assert alice.get(f"/v2/capsules/{slot('bad/key')}").status_code == 200
        assert alice.get("/v2/capsules/state").status_code == 404
        assert alice.get(f"/v2/capsules/{STATE.upper()}").status_code == 404
        not_a_hash = alice.put_capsule("state", overrides={"key_hash": "state"})
        assert_refusal(not_a_hash, "malformed", status=400)

    def test_a_capsule_names_the_slots_latest_leaf(self, client, alice):
        first = leaf_index(alice.put_capsule("state", "one"))
        stale = alice.put_capsule("state", "two", overrides={"prev_capsule_index": None})
        assert_refusal(stale, "stale_capsule", status=409, conflict_index=first)
        wrong = alice.put_capsule("other", "new slot", overrides={"prev_capsule_index": first})
        assert_refusal(wrong, "stale_capsule", status=409, conflict_index=None)
        assert alice.put_capsule("state", "two").status_code == 202

    def test_a_capsule_expiry_is_at_least_ninety_days(self, client, alice):
        assert alice.put_capsule("state", expires=int(time.time()) + NINETY_DAYS - 60).status_code == 400
        assert alice.put_capsule("state", expires=int(time.time()) + NINETY_DAYS + 60).status_code == 202

    def test_the_capsule_scheme_list_is_closed(self, client, alice):
        response = alice.put_capsule("state", ciphertext=b"my notes in the clear, please keep them", encryption="plaintext")
        assert_refusal(response, "unsupported_scheme", status=422)

    def test_a_capsule_must_cite_the_owners_current_encryption_key(self, client, alice):
        assert_refusal(alice.put_capsule("state", overrides={"to_key_leaf_index": 0}), "stale_key", status=409, conflict_index=alice.head_index)

    def test_expires_is_bounded(self, client, alice):
        assert alice.put_capsule("state", expires=int(time.time()) - 1).status_code == 400
        assert alice.put_capsule("state", expires=int(time.time()) + DEFAULT_LIMITS["capsule_max_seconds"] + 60).status_code == 400

    def test_capsules_belong_to_the_signing_key(self, client, alice, bob):
        assert alice.put_capsule("state", "alice's").status_code == 202
        assert alice.get(f"/v2/capsules/{STATE}").status_code == 200
        assert bob.get(f"/v2/capsules/{STATE}").status_code == 404
        assert bob.get("/v2/capsules").json()["count"] == 0
        assert alice.rotate(Signer()).status_code == 202
        assert alice.get("/v2/capsules").json()["count"] == 0  # a new key starts new slots
        assert alice.put_capsule("state", "after rotation").status_code == 202
        assert alice.get("/v2/capsules").json()["count"] == 1

    def test_capsules_need_a_signature(self, client):
        assert client.put(f"/v2/capsules/{STATE}", json={"ciphertext": "blob", "envelope": {}}).status_code == 405
        assert client.get(f"/v2/capsules/{STATE}").status_code == 401


# ---------------------------------------------------------------------------
# published limits
# ---------------------------------------------------------------------------


class TestLimits:
    LIMITS: ClassVar[dict[str, Any]] = {
        "writes": {"count": 3, "interval_seconds": 60},
        "flood": {"count": 6, "interval_seconds": 60},
        "flood_suspension_seconds": 120,
        "registrations": {"count": 50, "interval_seconds": 60},
        "preidentity": {"count": 50, "interval_seconds": 60},
    }

    def test_a_write_over_the_limit_is_a_refusal_leaf_without_the_body(self, tmp_path, owner):
        client = make_client(tmp_path, owner, **self.LIMITS)
        alice = new_agent(client, "alice")
        for i in range(3):
            assert alice.post(title=f"post {i}").status_code == 202
        secret_body = "This fourth body must not be retained anywhere at all."
        response = alice.post(title="post 4", body=secret_body)
        refusal = assert_refusal(response, "rate_limit", status=429)
        assert int(response.headers["Retry-After"]) >= 1
        size = tree_size(client)
        again = alice.post(title="post 5")
        assert again.status_code == 429
        assert entry_of(again) == refusal["entry"]  # the same refusal leaf answers the same cause
        assert tree_size(client) == size  # no new leaf for the same cause
        assert secret_body.encode() not in table_text(tmp_path / "limits.db")
        assert client.get("/v2/agora/posts").json()["count"] == 3

    def test_sustained_excess_suspends_the_key_for_flood(self, tmp_path, owner):
        client = make_client(tmp_path, owner, **self.LIMITS)
        alice = new_agent(client, "alice")
        statuses = [alice.post(title=f"post {i}").status_code for i in range(6)]
        assert statuses == [202, 202, 202, 429, 429, 403]
        view = client.get(f"/v2/keys/{alice.kid}").json()["suspension"]
        assert view["reason_code"] == "flood" and view["active"] is True
        leaf = fetch_leaf(client, view["suspension_index"])["leaf_data"]
        assert leaf["type"] == "suspension" and leaf["actor_kid"] == client.get("/v2/tlog/checkpoint").json()["policy_kid"]
        assert leaf["payload"]["until"] == leaf["ts"] + 120 and leaf["payload"]["target_kid"] == alice.kid
        assert_refusal(alice.post(title="more"), "suspended", status=403, conflict_index=view["suspension_index"])
        assert alice.get("/v2/agents/me").status_code == 200  # reads are never suspended

    def test_the_registration_window_counts_the_attempts_of_each_submitting_key(self, tmp_path, owner):
        # AICS-1 section 13.1: limits.registrations counts authenticated registration attempts per submitting key.
        client = make_client(tmp_path, owner, **{**self.LIMITS, "registrations": {"count": 2, "interval_seconds": 60}})
        for name in ("one", "two", "three", "four"):  # fresh keys, one claim each: none is over its window
            new_agent(client, name)
        repeat = Agent(client, owner.origin)
        assert repeat.claim("five").status_code == 202  # this key's first attempt
        assert reason(repeat.claim("six")) == "key_reuse"  # its second: a refusal leaf of its own
        size = tree_size(client)
        over = repeat.claim("seven")  # its third: over its window, a logged rate_limit refusal (section 10.2)
        assert over.status_code == 429 and reason(over) == "rate_limit" and tree_size(client) == size + 1
        assert refusal_q(over)["attempt_kid"] == repeat.kid and int(over.headers["retry-after"]) > 0
        again = repeat.claim("eight")  # the same cause: answered with that leaf, no new one
        assert again.status_code == 429 and entry_of(again) == entry_of(over) and tree_size(client) == size + 1
        assert new_agent(client, "nine").name == "nine"  # other keys are not affected

    def test_the_preidentity_bucket_bounds_all_registration_and_logs_nothing(self, tmp_path, owner):
        # The global pre-identity bucket (limits.preidentity) is charged by every registration attempt and every
        # keyless request; exhausted, it refuses before logging (AICS-1 section 10.2), as the card discloses.
        client = make_client(tmp_path, owner, **{**self.LIMITS, "preidentity": {"count": 2, "interval_seconds": 60}})
        new_agent(client, "one")
        new_agent(client, "two")
        size = tree_size(client)
        response = Agent(client, owner.origin).claim("three")
        assert response.status_code == 429
        assert reason(response) == "rate_limit" and response.json()["detail"]["refusal"] is None
        _, _, text = secret_claim_reply(client, "four")  # the fallback claim at the TLS gate shares the bucket
        assert text.startswith("err rate_limit "), text
        assert tree_size(client) == size

    def test_notices_have_their_own_window(self, tmp_path, owner):
        client = make_client(
            tmp_path, owner,
            **{**self.LIMITS, "preidentity": {"count": 1, "interval_seconds": 60}, "notices": {"count": 2, "interval_seconds": 3600}},
        )
        new_agent(client, "one")  # the pre-identity bucket is now full ...
        notice = {"location": "leaf 7", "explanation": "This post seems unlawful to me.", "accurate": True}
        # ... and notice intake still takes notices, up to its own published window (limits.notices).
        assert [client.post("/notice", json=notice).status_code for _ in range(3)] == [201, 201, 429]
        assert client.get("/v2/limits").json()["limits"]["notices"] == {"count": 2, "interval_seconds": 3600}

    def test_the_limits_are_published_and_validated(self, tmp_path, owner, monkeypatch):
        client = make_client(tmp_path, owner, **self.LIMITS)
        view = client.get("/v2/limits").json()
        assert view["limits"]["writes"] == {"count": 3, "interval_seconds": 60}
        assert view["limits"]["ciphertext_bytes"] == 65536
        assert view["encryption_schemes"] == list(ENCRYPTION_SCHEMES)
        assert set(REFUSAL_REASONS) <= set(view["refusal_codes"])
        assert view["per"]["writes"] == "signing key"
        for bad in ({"writes": {"count": 0, "interval_seconds": 60}}, {"per_ip": 5}, {"flood": {"count": 1}}, {"ciphertext_bytes": 10**6}):
            with pytest.raises(ValueError):
                load_limits(bad)
        path = tmp_path / "limits.json"
        path.write_text(json.dumps({"writes": {"count": 7}}), encoding="utf-8")
        monkeypatch.setenv("AICS_LIMITS_FILE", str(path))
        assert load_limits()["writes"] == {"count": 7, "interval_seconds": 60}


# ---------------------------------------------------------------------------
# tombstones
# ---------------------------------------------------------------------------


class TestTombstones:
    def test_a_tombstone_hides_a_body_and_leaves_the_leaf_intact(self, client, owner, alice):
        post = alice.post(title="A post someone objects to", body="Its body, long enough to post.")
        target = leaf_index(post)
        body_hash = entry_of(post)["payload"]["body_hash"]
        assert client.get(f"/v2/bodies/{body_hash}").status_code == 200
        before_leaf = fetch_leaf(client, target)
        old_size, old_root = before_leaf["tree_size"], before_leaf["root_hash_hex"]
        evidence = hashlib.sha256(b"notice 17").hexdigest()
        response = owner.tombstone(target, "illegal_on_notice", evidence)
        assert response.status_code == 201, response.text
        body = response.json()
        tombstone_index = verify_admin_receipt(client, body)
        entry = body["entry"]
        policy_kid = client.get("/v2/tlog/checkpoint").json()["policy_kid"]
        assert entry["type"] == "tombstone" and entry["actor_kid"] == policy_kid
        assert entry["payload"]["envelope"]["protected"]["kid"] == policy_kid
        assert {k: entry["payload"][k] for k in ("target_index", "reason_code", "evidence_hash")} == {
            "target_index": target,
            "reason_code": "illegal_on_notice",
            "evidence_hash": evidence,
        }
        # The target leaf is byte-for-byte the same and still proves under the new checkpoint.
        after_leaf = fetch_leaf(client, target)
        assert after_leaf["entry_bytes_b64"] == before_leaf["entry_bytes_b64"]
        leaf_bytes = base64.b64decode(after_leaf["entry_bytes_b64"])
        audit = [bytes.fromhex(h) for h in after_leaf["inclusion_proof_hex"]]
        assert verify_leaf_inclusion(leaf_bytes, target, after_leaf["tree_size"], audit, bytes.fromhex(after_leaf["root_hash_hex"]))
        consistency = client.get("/v2/tlog/consistency", params={"from": old_size, "to": after_leaf["tree_size"]}).json()
        hashes = [base64.b64decode(h) for h in consistency["hashes"]]
        assert verify_consistency(old_size, after_leaf["tree_size"], bytes.fromhex(old_root), bytes.fromhex(after_leaf["root_hash_hex"]), hashes)
        # Readers see the tombstone where the body was.
        listed = client.get("/v2/agora/posts").json()["posts"][0]
        assert listed["title"] is None and listed["text"] is None
        assert listed["hidden"] == {"tombstone_index": tombstone_index, "reason_code": "illegal_on_notice"}
        # The bundle and the body service report the tombstone and its reason (AICS-1 sections 10.3, 12.1).
        hidden = {"state": "tombstoned", "tombstone_index": tombstone_index, "reason_code": "illegal_on_notice", "policy_index": None}
        bundle, status = entry_bundle(client, target)
        assert bundle["body_or_ct"] is None and status == hidden
        assert bundle["entry_bytes"] == keys.b64u_encode(base64.b64decode(before_leaf["entry_bytes_b64"]))
        withheld = client.get(f"/v2/bodies/{body_hash}")
        assert withheld.status_code == 410 and withheld.json() == hidden
        assert "Its body" not in client.get("/agora", headers={"Accept": "text/html"}).text
        assert client.get("/v2/stats").json()["usage"]["agora_posts"] == 0
        assert client.get("/v2/tombstones").json()["tombstones"][0]["target_index"] == target

    def test_only_the_owner_writes_tombstones(self, client, owner, alice):
        target = leaf_index(alice.post())
        response, _, _, _ = signed_request(
            client, alice.signer, "POST", "/v2/admin/tombstones", fields={"target_index": target, "reason_code": "order"}
        )
        assert response.status_code == 403
        assert client.post("/v2/admin/tombstones", json={"target_index": target, "reason_code": "order"}).status_code == 401
        assert client.get("/v2/tombstones").json()["count"] == 0

    def test_tombstone_reasons_are_closed_and_ciphertext_needs_an_order(self, client, owner, alice, bob, granted):
        target = leaf_index(alice.post())
        assert owner.tombstone(target, "spam").status_code == 400
        dm = leaf_index(alice.send_dm(alice.lookup("bob"), "private"))
        assert owner.tombstone(dm, "illegal_on_notice").status_code == 400  # a notice cannot judge ciphertext
        response = owner.tombstone(dm, "order", hashlib.sha256(b"order 2026/41").hexdigest())
        assert response.status_code == 201, response.text
        message = bob.get("/v2/inbox").json()["messages"][0]
        assert message["ciphertext"] is None and message["body"] == "hidden"
        assert message["hidden"]["reason_code"] == "order" and message["envelope"]["protected"]["type"] == "dm"
        assert client.get(f"/v2/inbox/{bob.kid}").json()["messages"][0]["body"] == "hidden"
        status = entry_bundle(client, dm)[1]
        assert status == {"state": "tombstoned", "tombstone_index": leaf_index(response), "reason_code": "order", "policy_index": None}
        assert client.get(f"/v2/bodies/{fetch_leaf(client, dm)['leaf_data']['payload']['ct_hash']}").status_code == 410

    def test_a_body_is_hidden_once(self, client, owner, alice):
        target = leaf_index(alice.post())
        assert owner.tombstone(target, "erasure").status_code == 201
        assert owner.tombstone(target, "order").status_code == 409

    def test_only_leaves_with_an_off_leaf_body_can_be_tombstoned(self, client, owner, alice, bob, granted):
        assert owner.tombstone(0, "order").status_code == 400  # the charter
        assert owner.tombstone(granted, "order").status_code == 400  # a grant has no body
        assert owner.tombstone(alice.head_index, "erasure").status_code == 400  # a claim publishes no profile
        assert alice.rotate_x25519().status_code == 202
        assert owner.tombstone(alice.head_index, "order").status_code == 400
        assert owner.tombstone(10**6, "order").status_code == 404
        poll = leaf_index(alice.poll())
        silent = leaf_index(bob.vote(poll, 0))
        assert owner.tombstone(silent, "order").status_code == 400  # a vote without a reason has no body
        assert set(TOMBSTONE_TARGETS) == {"post", "poll", "vote", "dm", "capsule", "report", "sup.task",
                                          "agent.introduce", "swarm.form", "swarm.propose", "swarm.delivery"}

    def test_an_erasure_deletes_the_body_at_once(self, client, owner, make_agent, db_path):
        text = "ZQ personal details to erase"
        carol = make_agent("carol")
        target = leaf_index(carol.post(title="About me", body=text))
        assert client.get(f"/v2/agora/posts/{target}").json()["post"]["text"] == text
        tombstone = owner.tombstone(target, "erasure")
        assert tombstone.status_code == 201
        # Deleted in the tombstone's own commit (AICS-1 section 10.3): the bytes and what they say are gone.
        row = client.app.state.db._conn.execute(
            "SELECT title, text, body FROM agora_posts WHERE post_index = ?", (target,)
        ).fetchone()
        assert tuple(row) == (None, "", None)
        post = client.get(f"/v2/agora/posts/{target}").json()["post"]
        assert post["text"] is None and post["hidden"]["reason_code"] == "erasure"
        assert post["author_name"] == "carol" and post["body_hash"] == fetch_leaf(client, target)["leaf_data"]["payload"]["body_hash"]

    def test_a_tombstone_names_the_receipt_of_its_target(self, client, owner, alice):
        posted = alice.post()
        target = leaf_index(posted)
        receipt = hashlib.sha256(keys.b64u_decode(posted.json()["receipt_note"])).hexdigest()
        tombstone = owner.tombstone(target, "order").json()["entry"]["payload"]
        assert set(tombstone) == {"envelope", "target_index", "reason_code", "evidence_hash", "receipt_hash"}
        assert tombstone["receipt_hash"] == receipt  # the promise no tombstone cancels (AICS-1 section 10.1)

    def test_a_capsule_body_hidden_under_an_order(self, client, owner, alice):
        target = leaf_index(alice.put_capsule("state", "kept private"))
        tombstone = owner.tombstone(target, "order")
        assert tombstone.status_code == 201
        got = alice.get(f"/v2/capsules/{STATE}").json()
        assert got["ciphertext"] is None and got["body"] == "hidden"
        assert entry_bundle(client, target)[1] == {
            "state": "tombstoned", "tombstone_index": leaf_index(tombstone), "reason_code": "order", "policy_index": None,
        }
        assert alice.put_capsule("state", "a new body").status_code == 202
        assert alice.get(f"/v2/capsules/{STATE}").json()["body"] == "stored"


# ---------------------------------------------------------------------------
# suspensions
# ---------------------------------------------------------------------------


class TestSuspensions:
    def test_an_order_suspension_stops_writes_but_not_reads(self, client, owner, alice, bob):
        assert alice.grant(bob.kid, 5).status_code == 202
        response = owner.suspend(alice.kid, "order")
        assert response.status_code == 201, response.text
        body = response.json()
        index = verify_admin_receipt(client, body)
        payload = body["entry"]["payload"]
        assert body["entry"]["type"] == "suspension"
        assert (payload["target_kid"], payload["reason_code"], payload["until"]) == (alice.kid, "order", None)
        refusal = assert_refusal(alice.post(), "suspended", status=403, conflict_index=index)
        size = tree_size(client)
        assert entry_of(alice.post()) == refusal["entry"]
        assert tree_size(client) == size
        assert alice.get("/v2/agents/me").status_code == 200
        assert bob.send_dm(bob.lookup("alice"), "you can still receive").status_code == 202
        assert alice.rotate(Signer()).status_code == 403  # no rotating away from a suspension

    def test_a_suspension_ends_with_a_later_leaf(self, client, owner, alice):
        assert owner.suspend(alice.kid, "order").status_code == 201
        assert alice.post().status_code == 403
        assert owner.suspend(alice.kid, "flood", until=0).status_code == 400  # the ending repeats the reason
        ended = owner.suspend(alice.kid, "order", until=0)
        assert ended.status_code == 201
        entry = ended.json()["entry"]
        assert entry["payload"]["until"] == entry["ts"]
        assert ended.json()["suspension"]["active"] is False
        assert alice.post().status_code == 202
        assert owner.suspend(alice.kid, "order", until=0).status_code == 409  # nothing left to end

    def test_suspension_reasons_are_closed(self, client, owner, alice):
        assert owner.suspend(alice.kid, "content").status_code == 400
        assert owner.suspend(alice.kid, "flood").status_code == 400  # flood comes only from the published limits
        assert owner.suspend("Z" * 16, "order").status_code == 404
        response, _, _, _ = signed_request(
            client, alice.signer, "POST", "/v2/admin/suspensions", fields={"target_kid": alice.kid, "reason_code": "order"}
        )
        assert response.status_code == 403


# ---------------------------------------------------------------------------
# freeze
# ---------------------------------------------------------------------------


class TestFreeze:
    def test_a_freeze_stops_agent_writes_and_keeps_reads(self, client, owner, alice):
        report = "Write freeze for a storage migration; reads and verification continue."
        response = owner.freeze("frozen", "maintenance", report)
        assert response.status_code == 201, response.text
        body = response.json()
        index = verify_admin_receipt(client, body)
        payload = body["entry"]["payload"]
        assert body["entry"]["type"] == "freeze"
        assert (payload["state"], payload["reason_code"], payload["prev_freeze_index"]) == ("frozen", "maintenance", None)
        assert payload["report_hash"] == hashlib.sha256(report.encode()).hexdigest()
        assert report not in json.dumps(body["entry"])
        state = client.get("/v2/freeze").json()
        assert (state["state"], state["freeze_index"], state["report"]) == ("frozen", index, report)

        # AICS-1 section 12.1: a refusal at POST /v2/entries answers its entry and receipt with a 4xx.
        refusal = assert_refusal(alice.post(), "frozen", status=409, conflict_index=index)
        size = tree_size(client)
        assert entry_of(alice.post()) == refusal["entry"]
        assert tree_size(client) == size
        assert_refusal(Agent(client, alice.origin).claim("newcomer"), "frozen", status=409, conflict_index=index)
        _, _, secret = secret_claim_reply(client, "plain")  # the fallback claim at the TLS gate
        assert secret.startswith("err frozen "), secret
        for path in ("/v2/agora/posts", "/checkpoint", "/tiles/checkpoint", f"/v2/tlog/proof/{index}", "/v2/charter",
                     f"/v2/entries/{index}"):
            assert client.get(path).status_code == 200, path
        assert alice.get("/v2/agents/me").status_code == 200

        reopened = owner.freeze("open", "resume", "Migration finished.")
        assert reopened.status_code == 201
        assert reopened.json()["entry"]["payload"]["prev_freeze_index"] == index
        assert client.get("/v2/freeze").json()["state"] == "open"
        assert alice.post().status_code == 202

    def test_freeze_transitions_and_reasons(self, client, owner, alice):
        assert owner.freeze("open", "resume").status_code == 409  # not frozen
        assert owner.freeze("frozen", "resume").status_code == 400
        assert owner.freeze("open", "maintenance").status_code == 400
        assert owner.freeze("frozen", "boredom").status_code == 400
        assert owner.freeze("frozen", "incident", "Investigating.").status_code == 201
        assert owner.freeze("frozen", "incident", "Still investigating.").status_code == 409
        response, _, _, _ = signed_request(
            client, alice.signer, "POST", "/v2/admin/freeze", fields={"state": "open", "reason_code": "resume", "report": "x"}
        )
        assert response.status_code == 403

    def test_a_freeze_survives_a_restart(self, client, owner, alice, db_path):
        assert owner.freeze().status_code == 201
        restarted = TestClient(create_app(db_path=db_path, owner_public_key=owner.public_key_b64u, announce=False))
        assert restarted.get("/v2/freeze").json()["state"] == "frozen"
        alice.client = restarted
        assert reason(alice.post()) == "frozen"


# ---------------------------------------------------------------------------
# refusal codes and the secret-format scan
# ---------------------------------------------------------------------------


class TestRefusalCodes:
    def test_a_secret_in_public_text_is_refused_with_a_leaf_and_not_retained(self, client, db_path, alice):
        response = alice.post(title="My key stopped working", body=f"Why does {LEAKED_TOKEN} return 401?")
        refusal = assert_refusal(response, "secret_format:github_token", status=422)
        assert LEAKED_TOKEN not in response.text and LEAKED_TOKEN not in str(response.headers)
        assert refusal["entry"]["payload"]["attempt_kid"] == alice.kid
        assert LEAKED_TOKEN.encode() not in db_path.read_bytes() + table_text(db_path)
        assert client.get("/v2/agora/posts").json()["count"] == 0

    def test_secrets_in_votes_and_unverified_posts_are_refused_too(self, client, alice, make_agent):
        poll = leaf_index(alice.poll(title="Pick one please", text="A tiny poll.", options=["a", "b"]))
        voter = make_agent("voter")
        vote = voter.vote(poll, 0, reason=f"use {LEAKED_TOKEN}")
        assert_refusal(vote, "secret_format:github_token", status=422)
        # Shared-secret writes exist only at the TLS text gate (AICS-1 section 12.1).
        identity = secret_claim(client, "plain", "U" * 40)
        secret = identity.secret
        body = J({"channel": "general", "title": "hello there", "text": f"key {LEAKED_TOKEN}"})
        text = secret_post(identity, body)
        assert text.startswith("err secret_format:github_token "), text
        assert LEAKED_TOKEN not in text and secret not in text
        refusal = {"entry": json.loads(artifacts(text)["entry"])}
        assert refusal["entry"]["type"] == "refusal"
        payload = refusal["entry"]["payload"]
        # The refused fallback envelope is named by its hash and its identity's tuple (AICS-1 section 10.2): a
        # parseable fallback envelope can be hash-referenced without the secret supplied beside it.
        assert payload["attempt_kid"].startswith("unverified:") and envelope.is_canonical_nonce(payload["attempt_nonce"])
        assert payload["request_hash"] is None
        assert secret not in json.dumps(refusal)

    def test_every_refusal_code_written_is_in_the_closed_list(self, client, db_path, alice, bob):
        alice.send_dm(alice.lookup("bob"), "closed inbox")
        alice.post(body=f"leak {LEAKED_TOKEN}")
        alice.send_dm(alice.lookup("bob"), ciphertext=b"plain" * 20, encryption="cleartext-signed")
        with sqlite3.connect(db_path) as conn:
            codes = [
                json.loads(r[0])["payload"]["reason_code"]
                for r in conn.execute("SELECT leaf_json FROM tlog_leaves WHERE event_type = 'refusal'")
            ]
        assert codes == ["no_consent", "secret_format:github_token", "unsupported_scheme"]
        for code in codes:
            assert code in REFUSAL_REASONS or code.startswith("secret_format:")

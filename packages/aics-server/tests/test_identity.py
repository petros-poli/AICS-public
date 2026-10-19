"""Identity: names bound by a logged key chain (DESIGN.md section 5, DECISIONS.md #1 and #7).

Covers proof of possession at claim, the X25519 key and recovery key bound in the
claim leaf, tiers (verified, third-party-generated, unverified), rotation with
both signatures and first-successor-wins, fork and predecessor refusals,
permanent revocation, encryption-key rotation, the upgrade of an unverified name,
and lookups that return the leaf that supplied each key.
"""

from __future__ import annotations

import base64

import hashlib
import json

import pytest

from aics_identity import canonical_text, envelope, keys, sealed
from aics_server import envelopes as ev
from aics_server import identity as ident
from aics_tlog import verify_leaf_inclusion

import re

from aics_server.db import CredentialError
from aics_server.gate import TLS_REQUIRED

from conftest import GENESIS_SIZE, Agent, Line, SecretIdentity, Signer, fetch_leaf, https, post_body, post_q
from conftest import ENTRIES, entry_of, leaf_index, question, reason, refusal_q, secret_claim, secret_post, submit_entry

SMALL_ORDER_ED25519 = keys.b64u_encode(b"\x01" + b"\x00" * 31)  # the identity point
ZERO_X25519 = keys.b64u_encode(b"\x00" * 32)  # small order: shared secret would be all zeros
SECRET = "Zq8-c7Tr2uVw9Yx4AbCdEfGhJkLmNpQs"  # 32 printable characters
OTHER_SECRET = "Zq8-c7Tr2uVw9Yx4AbCdEfGhJkLmNpQX"


def tree_size(client) -> int:
    return client.get("/v2/tlog/checkpoint").json()["tree_size"]


def assert_refusal(response, code: str, *, conflict_index=None, origin_policy_kid=None, status=409):
    """A refusal leaf answered by ``POST /v2/entries`` (AICS-1 section 12.1): its entry and receipt, a 4xx."""
    assert response.status_code == status, response.text
    entry = entry_of(response)
    assert entry["type"] == "refusal", "an authenticated refusal is a leaf"
    assert entry["payload"]["reason_code"] == code
    if conflict_index is not None:
        assert entry["payload"]["conflict_index"] == conflict_index
    if origin_policy_kid is not None:
        assert entry["actor_kid"] == origin_policy_kid
        assert entry["payload"]["envelope"]["protected"]["kid"] == origin_policy_kid
    return entry


def view_of(client, name: str) -> dict:
    """A name's current keys and the leaves that set them (the public lookup)."""
    response = client.get(f"/v2/ans/lookup/{name}")
    assert response.status_code == 200, response.text
    return response.json()["agent"]


# ---------------------------------------------------------------------------
# names
# ---------------------------------------------------------------------------


class TestNameNormalization:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("ada", "ada"),
            ("@ada", "ada"),
            ("@Ada.wesupport-ai.com", "ada"),
            ("ADA.WESUPPORT-AI.COM", "ada"),
            ("a", "a"),
            ("agent_7-x", "agent_7-x"),
            ("x" * 63, "x" * 63),
        ],
    )
    def test_accepted_forms(self, raw, expected):
        assert ident.normalize_name(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        ["", "ada.evil.example", "ada.b", "-ada", "ada-", "_ada", "x" * 64, "ad a", "ädä", "ada.wesupport-ai.com.evil", "@@ada"],
    )
    def test_refused_forms(self, raw):
        with pytest.raises(ValueError):
            ident.normalize_name(raw)

    def test_claim_payload_must_carry_the_normalized_form(self, client, origin):
        agent = Agent(client, origin)
        response = agent.claim("Alice")
        assert response.status_code == 400
        assert "normalized" in response.headers["x-aics-hint"]
        # The claim was authenticated (its own key signed it) and its nonce spent: a malformed refusal leaf.
        assert refusal_q(response)["reason_code"] == "malformed"
        assert tree_size(client) == GENESIS_SIZE + 1


# ---------------------------------------------------------------------------
# claims
# ---------------------------------------------------------------------------


class TestKeyClaim:
    def test_claim_binds_both_keys_in_one_signed_leaf(self, client, origin):
        agent = Agent(client, origin)
        response = agent.claim("alice")
        assert response.status_code == 202, response.text
        body = response.json()
        assert set(body) == {"entry", "receipt_note"}
        flat = json.dumps(body)
        assert "bearer" not in flat.lower() and "private_seed" not in flat

        member = view_of(client, "alice")
        assert member["name"] == "alice"
        assert member["ans_address"] == "@alice.wesupport-ai.com"
        assert member["kid"] == agent.kid
        assert member["did"] == agent.signer.did
        assert member["public_key_b64u"] == agent.signer.public_key_b64u
        assert member["x25519_public_key_b64u"] == agent.x25519_b64u
        assert member["tier"] == "verified"
        idx = leaf_index(response)
        assert member["claim_index"] == member["key_leaf_index"] == member["x25519_leaf_index"] == idx

        entry = body["entry"]
        assert entry["v"] == 2
        assert entry["type"] == "name.claim"
        assert entry["actor_kid"] == agent.kid
        payload = entry["payload"]
        assert payload["name_norm"] == "alice"
        assert payload["prev_event_index"] is None
        assert payload["ed25519"] == agent.signer.public_key_b64u
        assert payload["x25519"] == agent.x25519_b64u
        assert payload["envelope"]["protected"]["kid"] == agent.kid
        assert payload["envelope"]["protected"]["seq"] == 0

    def test_claim_leaf_verifies_from_the_log_alone(self, client, origin):
        agent = Agent(client, origin)
        idx = leaf_index(agent.claim("bob"))
        proof = fetch_leaf(client, idx)
        entry = proof["leaf_data"]
        # (a) the envelope is signed by the key the leaf binds, as of the entry's ts (AICS-1 section 4.3)
        env = entry["payload"]["envelope"]
        bound_key = keys.parse_public_key(entry["payload"]["ed25519"])
        assert envelope.verify_envelope(env, lambda kid: bound_key, now=entry["ts"])["name_norm"] == "bob"
        # the kid is the did:key of that key (AICS-1 section 3.1), decoded locally
        assert keys.did_key(bound_key) == env["protected"]["kid"] == entry["actor_kid"]
        assert keys.public_key_bytes(keys.parse_did_key(entry["actor_kid"])) == keys.public_key_bytes(bound_key)
        assert ev.check_entry(entry, origin=origin) == ev.NATIVE
        # (b) the exact entry bytes are included under the checkpoint root
        leaf_bytes = canonical_text(entry).encode("utf-8")
        audit = [bytes.fromhex(h) for h in proof["inclusion_proof_hex"]]
        assert verify_leaf_inclusion(leaf_bytes, idx, proof["tree_size"], audit, bytes.fromhex(proof["root_hash_hex"]))
        assert proof["leaf_hash_hex"] == hashlib.sha256(b"\x00" + leaf_bytes).hexdigest()

    def test_claim_must_be_signed_by_the_claimed_key(self, client, origin):
        # AICS-1 section 12.1: a claim's key is resolved from the claim itself; signed by any other key it does not
        # authenticate (a refusal leaf whose attempt fields are null), and no name is bound.
        agent = Agent(client, origin)
        intruder = Signer()
        payload = agent.claim_payload("carol")
        response, _, _, _ = submit_entry(client, intruder, payload)
        assert response.status_code == 401
        assert reason(response) == "unknown_key" and refusal_q(response)["attempt_kid"] is None
        assert tree_size(client) == GENESIS_SIZE + 1 and client.get("/v2/names/carol").status_code == 404

    def test_claim_envelope_signed_by_another_key_is_refused(self, client, origin):
        agent = Agent(client, origin)
        intruder = Signer()
        payload = agent.claim_payload("carol")
        response, _, _, _ = submit_entry(
            client, agent.signer, payload, envelope_signer=intruder, envelope_overrides={"kid": agent.kid}
        )
        assert response.status_code == 401
        assert reason(response) == "bad_signature" and refusal_q(response)["attempt_kid"] is None
        assert tree_size(client) == GENESIS_SIZE + 1 and client.get("/v2/names/carol").status_code == 404

    def test_unsigned_claim_is_refused(self, client, origin):
        agent = Agent(client, origin)
        response = agent.claim("dave", sign=False)
        assert response.status_code == 401
        assert reason(response) == "signature_required"

    def test_server_never_generates_a_key(self, client):
        # The old one-call registration (no key) is gone: nothing is generated for anyone.
        for path in ("/v2/agents/register", "/v2/names/claim"):
            response = client.post(path, json={"name": "Legacy Agent", "handle": "legacy"})
            assert response.status_code in (404, 405)
            assert "private_seed_hex" not in response.text and "bearer" not in response.text.lower()
        response = client.post(ENTRIES, json={"name": "Legacy Agent", "handle": "legacy"})
        assert response.status_code == 401 and reason(response) == "signature_required"
        assert tree_size(client) == GENESIS_SIZE

    def test_name_taken_is_a_logged_refusal(self, client, origin):
        first = Agent(client, origin)
        claim_index = leaf_index(first.claim("erin"))
        second = Agent(client, origin)
        response = second.claim("erin")
        policy_kid = client.get("/v2/tlog/checkpoint").json()["policy_kid"]
        refusal = assert_refusal(response, "name_taken", conflict_index=claim_index, origin_policy_kid=policy_kid)
        payload = refusal["payload"]
        assert payload["attempt_kid"] == second.kid
        assert set(payload) >= {"envelope_hash", "request_hash", "attempt_nonce", "conflict_index"}
        # The refusal envelope is signed by the policy key published with the checkpoint.
        policy_key = keys.parse_public_key(client.get("/v2/tlog/checkpoint").json()["policy_public_key_b64u"])
        envelope.verify_envelope(payload["envelope"], lambda kid: policy_key, now=refusal["ts"])
        # The first claimant still holds the name.
        assert client.get("/v2/ans/lookup/erin").json()["agent"]["kid"] == first.kid

    def test_a_key_binds_at_most_one_name(self, client, make_agent, origin):
        alice = make_agent("alice")
        again = Agent(client, origin, signer=alice.signer)
        assert_refusal(again.claim("alice-two"), "key_reuse", conflict_index=alice.head_index)

    def test_owner_key_cannot_be_an_agent_key(self, client, origin, owner):
        agent = Agent(client, origin, signer=owner)
        assert_refusal(agent.claim("owner-as-agent"), "key_reuse")

    def test_third_party_generated_tier_is_self_declared_and_shown(self, client, make_agent):
        make_agent("gen-agent", tier="third-party-generated")
        listed = {a["name"]: a for a in client.get("/v2/directory").json()["agents"]}
        assert listed["gen-agent"]["tier"] == "third-party-generated"
        assert "generator" in listed["gen-agent"]["tier_label"]

    def test_unverified_tier_cannot_be_claimed_with_a_key(self, client, origin):
        response = Agent(client, origin).claim("tier-mix", tier="unverified")
        assert response.status_code == 400

    @pytest.mark.parametrize(
        ("field", "value"),
        [("x25519", None), ("x25519", ZERO_X25519), ("x25519", "not-base64!"), ("x25519", keys.b64u_encode(b"\x09" * 31))],
    )
    def test_x25519_key_is_required_and_validated(self, client, origin, field, value):
        response = Agent(client, origin).claim("enc-check", **{field: value})
        assert response.status_code == 400
        assert reason(response) == "malformed"
        assert tree_size(client) == GENESIS_SIZE + 1  # the refusal leaf, never a claim

    def test_small_order_signing_key_is_refused(self, client, origin):
        # No signature by a small-order key proves anything (it would verify for many messages): the claim does
        # not authenticate, and its refusal names no attempt.
        agent = Agent(client, origin)
        payload = agent.claim_payload("weak-key", ed25519=SMALL_ORDER_ED25519)
        response, _, _, _ = submit_entry(client, agent.signer, payload)
        assert response.status_code == 401 and reason(response) == "unknown_key"
        assert refusal_q(response)["attempt_kid"] is None
        assert client.get("/v2/names/weak-key").status_code == 404

    def test_unknown_payload_members_are_refused(self, client, origin):
        response = Agent(client, origin).claim("extra-field", display_name="free text on a leaf")
        assert response.status_code == 400

    def test_recovery_key_is_declared_with_its_own_proof(self, client, origin):
        agent = Agent(client, origin)
        recovery = Signer()
        response = agent.claim("frank", recovery=recovery)
        assert response.status_code == 202, response.text
        # AICS-1 section 5.3: the recovery key is named by its did:key, its proof over section 7.1's bytes.
        assert response.json()["entry"]["payload"]["recovery_kid"] == recovery.kid
        view = client.get("/v2/names/frank").json()
        assert view["current"]["recovery_kid"] == recovery.kid

    def test_recovery_proof_by_another_key_is_refused(self, client, origin):
        agent = Agent(client, origin)
        recovery, impostor = Signer(), Signer()
        payload = agent.claim_payload("grace", recovery=recovery)
        payload["recovery_pop"] = impostor.proof(
            ident.recovery_message(
                origin=origin,
                name_norm="grace",
                ed25519=agent.signer.public_key_b64u,
                x25519=agent.x25519_b64u,
                recovery_kid=recovery.kid,
            )
        )
        response, _, _, _ = submit_entry(client, agent.signer, payload)
        assert response.status_code == 403
        # An inner proof that does not verify is a bad signature (AICS-1 section 17.2), logged.
        assert_refusal(response, "bad_signature", status=403)
        assert "recovery_pop" in response.headers["x-aics-hint"]

    def test_recovery_key_must_differ_from_the_signing_key(self, client, origin):
        agent = Agent(client, origin)
        response = agent.claim("heidi", recovery=agent.signer)
        assert response.status_code == 400

    def test_a_claim_publishes_a_name_and_nothing_else(self, client, origin):
        """AICS-1 section 5.3: name.claim is exactly its eight members; no profile hash, no off-leaf profile."""
        agent = Agent(client, origin)
        response = agent.claim("ivan")
        assert response.status_code == 202, response.text
        payload = response.json()["entry"]["payload"]
        assert set(payload) == {"envelope", "name_norm", "prev_event_index", "ed25519", "x25519", "tier",
                                "recovery_kid", "recovery_pop", "initial_grant"}
        member = client.get("/v2/ans/lookup/ivan").json()["agent"]
        for gone in ("display_name", "bio", "capabilities", "model_family", "profile_sha256"):
            assert gone not in member

    def test_a_profile_is_refused(self, client, origin):
        hashed = Agent(client, origin).claim("judy", profile_sha256="0" * 64)
        assert hashed.status_code == 400 and "profile_sha256" in hashed.headers["x-aics-hint"]
        assert refusal_q(hashed)["reason_code"] == "malformed"
        agent = Agent(client, origin)
        before = tree_size(client)
        sent = agent.claim("judy", fields={"body": None, "profile": {"display_name": "Judy"}})
        # The request object is exactly {envelope, body} (AICS-1 section 12.1): not a submission at all, no leaf.
        assert sent.status_code == 400 and reason(sent) == "malformed" and tree_size(client) == before

    def test_lookup_returns_the_leaf_that_supplied_each_key(self, client, make_agent):
        alice = make_agent("alice")
        member = client.get("/v2/ans/lookup/@alice.wesupport-ai.com").json()["agent"]
        leaf = fetch_leaf(client, member["x25519_leaf_index"])["leaf_data"]
        assert leaf["payload"]["x25519"] == member["x25519_public_key_b64u"] == alice.x25519_b64u
        key_leaf = fetch_leaf(client, member["key_leaf_index"])["leaf_data"]
        assert key_leaf["payload"]["ed25519"] == member["public_key_b64u"]
        # by key id and by did:key too
        assert client.get(f"/v2/ans/lookup/kid:{alice.kid}").json()["agent"]["name"] == "alice"
        assert client.get(f"/v2/ans/lookup/{alice.signer.did}").json()["agent"]["name"] == "alice"
        assert client.get("/v2/ans/lookup/nobody").status_code == 404

    def test_key_view(self, client, make_agent):
        alice = make_agent("alice")
        view = client.get(f"/v2/keys/{alice.kid}").json()
        assert view["name"] == "alice" and view["current"] is True and view["role"] == "agent"
        assert view["envelope_chain"]["last_seq"] == 0
        assert client.get("/v2/keys/AAAAAAAAAAAAAAAA").status_code == 404


# ---------------------------------------------------------------------------
# rotation
# ---------------------------------------------------------------------------


class TestRotation:
    def test_rotation_needs_both_keys_and_moves_the_name(self, client, make_agent):
        alice = make_agent("alice")
        old = alice.signer
        claim_index = alice.head_index
        new = Signer()
        response = alice.rotate(new)
        assert response.status_code == 202, response.text
        entry = response.json()["entry"]
        assert entry["type"] == "key.rotate"
        assert entry["actor_kid"] == old.kid  # the outer envelope belongs to the old key
        payload = entry["payload"]
        assert payload["name_norm"] == "alice"
        assert payload["prev_event_index"] == claim_index
        assert payload["new_ed25519"] == new.public_key_b64u
        message = ident.rotation_message(
            origin=alice.origin,
            name_norm="alice",
            prev_event_index=claim_index,
            new_ed25519=new.public_key_b64u,
            new_x25519=None,
            new_tier="verified",
            mode="rotate",
        )
        ident.verify_proof(payload["sig_old"], message, old.public)
        ident.verify_proof(payload["sig_new"], message, new.public)

        member = view_of(client, "alice")
        assert member["kid"] == new.kid
        assert member["key_leaf_index"] == entry_index(response)
        # X25519 kept: still supplied by the claim leaf.
        assert member["x25519_leaf_index"] == claim_index
        # The new key starts its own envelope chain at seq 0.
        assert alice.post().status_code == 202
        assert client.get(f"/v2/keys/{new.kid}").json()["envelope_chain"]["last_seq"] == 0

    def test_old_key_is_refused_after_rotation(self, client, make_agent):
        alice = make_agent("alice")
        old = alice.signer
        assert alice.rotate(Signer()).status_code == 202
        stale = Agent(client, alice.origin, signer=old)
        rotation_index = alice.head_index
        assert_refusal(stale.post(), "stale_key", conflict_index=rotation_index)

    def test_sig_new_must_come_from_the_new_key(self, client, make_agent):
        alice = make_agent("alice")
        before = tree_size(client)
        response = alice.rotate(Signer(), sign_new=Signer())
        assert_refusal(response, "bad_signature", status=403)
        assert "sig_new" in response.headers["x-aics-hint"]
        assert tree_size(client) == before + 1  # a refusal leaf; no rotation

    def test_sig_old_must_come_from_the_current_key(self, client, make_agent):
        alice = make_agent("alice")
        response = alice.rotate(Signer(), sign_old=Signer())
        assert_refusal(response, "bad_signature", status=403)
        assert "sig_old" in response.headers["x-aics-hint"]

    def test_a_missing_proof_is_malformed_not_a_bad_signature(self, client, make_agent):
        alice = make_agent("alice")
        response = alice.rotate(Signer(), sign_old=None)
        assert_refusal(response, "malformed", status=400)
        assert "sig_old" in response.headers["x-aics-hint"]

    def test_a_rotation_signed_by_the_new_key_alone_is_refused(self, client, make_agent):
        alice = make_agent("alice")
        new = Signer()
        payload = alice.rotation_payload(new)
        response, _, _, _ = submit_entry(client, new, payload)
        assert response.status_code == 401
        assert reason(response) == "unknown_key" and refusal_q(response)["attempt_kid"] is None

    def test_first_successor_wins_and_a_fork_is_logged(self, client, make_agent):
        alice = make_agent("alice")
        claim_index = alice.head_index
        assert alice.rotate_x25519().status_code == 202
        winner = alice.head_index
        # A second event citing the claim again is a fork: refused, with the winner named.
        response = alice.rotate(Signer(), prev=claim_index)
        assert_refusal(response, "key_fork", conflict_index=winner)
        # The name still follows the first successor.
        view = client.get("/v2/names/alice").json()
        assert [e["prev_event_index"] for e in view["events"]] == [None, claim_index]
        assert view["head_index"] == winner

    def test_prev_event_index_must_name_this_names_latest_event(self, client, make_agent):
        alice = make_agent("alice")
        make_agent("bob")
        assert_refusal(alice.rotate(Signer(), prev=9999), "predecessor", conflict_index=alice.head_index)

    def test_rotation_to_a_key_already_bound_is_refused(self, client, make_agent):
        alice = make_agent("alice")
        bob = make_agent("bob")
        assert_refusal(alice.rotate(bob.signer), "key_reuse", conflict_index=bob.head_index)

    def test_rotation_can_replace_the_encryption_key(self, client, make_agent):
        alice = make_agent("alice")
        new_x = sealed.format_x25519_public_key(sealed.generate_x25519_key())
        response = alice.rotate(Signer(), new_x25519=new_x)
        assert response.status_code == 202
        member = view_of(client, "alice")
        assert member["x25519_public_key_b64u"] == new_x
        assert member["x25519_leaf_index"] == entry_index(response)

    def test_rotation_proofs_may_be_sshsig(self, client, make_agent):
        from aics_identity import sshsig

        alice = make_agent("alice")
        new = Signer()
        payload = alice.rotation_payload(new)
        message = ident.rotation_message(
            origin=alice.origin,
            name_norm="alice",
            prev_event_index=alice.head_index,
            new_ed25519=new.public_key_b64u,
            new_x25519=None,
            new_tier="verified",
            mode="rotate",
        )
        blob = sshsig.parse_sshsig(sshsig.sign_sshsig(message, new.key)).to_blob()
        payload["sig_new"] = {"scheme": "sshsig", "signature": keys.b64u_encode(blob)}
        response, _, _, _ = submit_entry(client, alice.signer, payload)
        assert response.status_code == 202, response.text

    def test_sshsig_reserved_field_cannot_smuggle_text(self, client, make_agent):
        from aics_identity import sshsig

        alice = make_agent("alice")
        new = Signer()
        payload = alice.rotation_payload(new)
        message = ident.rotation_message(
            origin=alice.origin,
            name_norm="alice",
            prev_event_index=alice.head_index,
            new_ed25519=new.public_key_b64u,
            new_x25519=None,
            new_tier="verified",
            mode="rotate",
        )
        reserved = b"free text hidden in a signature"
        data = sshsig.signed_data(message, namespace="aics", hash_algorithm="sha512", reserved=reserved)
        smuggler = sshsig.SSHSignature(
            public_key_bytes=keys.public_key_bytes(new.public),
            namespace="aics",
            reserved=reserved,
            hash_algorithm="sha512",
            signature=new.key.sign(data),
        )
        payload["sig_new"] = {"scheme": "sshsig", "signature": keys.b64u_encode(smuggler.to_blob())}
        response, _, _, _ = submit_entry(client, alice.signer, payload)
        assert_refusal(response, "bad_signature", status=403)
        assert "reserved" in response.headers["x-aics-hint"]

    def test_a_key_event_names_the_signers_own_name(self, client, make_agent):
        alice = make_agent("alice")
        make_agent("bob")
        alice_name = alice.name
        alice.name = "bob"
        response = alice.rotate(Signer(), prev=alice.head_index)
        alice.name = alice_name
        assert response.status_code == 403


def entry_index(response) -> int:
    return leaf_index(response)


# ---------------------------------------------------------------------------
# revocation
# ---------------------------------------------------------------------------


class TestRevocation:
    def test_revocation_is_permanent(self, client, make_agent, origin):
        alice = make_agent("alice")
        response = alice.revoke("compromised")
        assert response.status_code == 202, response.text
        revoke_index = entry_index(response)
        assert response.json()["entry"]["payload"]["reason_code"] == "compromised"
        assert view_of(client, "alice")["revoked"] is True

        # Any further write by the name is refused and logged.
        assert_refusal(alice.post(), "revoked", conflict_index=revoke_index)
        # Reads are refused too (without a leaf).
        read = alice.get("/v2/agents/me")
        assert read.status_code == 403
        assert read.json()["detail"]["refusal"] is None
        # Nobody can re-claim the name, not even with a fresh key.
        assert_refusal(Agent(client, origin).claim("alice"), "revoked", conflict_index=revoke_index)
        listed = {a["name"]: a for a in client.get("/v2/directory").json()["agents"]}
        assert listed["alice"]["revoked"] is True

    def test_revocation_needs_the_current_key(self, client, make_agent):
        alice = make_agent("alice")
        old = alice.signer
        assert alice.rotate(Signer()).status_code == 202
        stale = Agent(client, alice.origin, signer=old)
        stale.name, stale.head_index = "alice", alice.head_index
        assert_refusal(stale.revoke(), "stale_key")

    def test_revocation_reason_is_a_closed_list(self, client, make_agent):
        alice = make_agent("alice")
        assert alice.revoke("because").status_code == 400

    def test_no_event_after_revocation(self, client, make_agent):
        alice = make_agent("alice")
        assert alice.revoke().status_code == 202
        assert_refusal(alice.rotate_x25519(), "revoked")


# ---------------------------------------------------------------------------
# encryption-key rotation
# ---------------------------------------------------------------------------


class TestX25519Rotation:
    def test_replaces_the_encryption_key_without_changing_identity(self, client, make_agent):
        alice = make_agent("alice")
        old_x = alice.x25519_b64u
        response = alice.rotate_x25519()
        assert response.status_code == 202, response.text
        entry = response.json()["entry"]
        assert entry["type"] == "x25519.rotate"
        assert entry["payload"]["name_norm"] == "alice"
        member = client.get("/v2/ans/lookup/alice").json()["agent"]
        assert member["kid"] == alice.kid
        assert member["x25519_public_key_b64u"] == alice.x25519_b64u != old_x
        assert member["x25519_leaf_index"] == entry_index(response)

    def test_only_the_current_ed25519_key_may_rotate_it(self, client, make_agent):
        alice = make_agent("alice")
        old = alice.signer
        assert alice.rotate(Signer()).status_code == 202
        stale = Agent(client, alice.origin, signer=old)
        stale.name, stale.head_index = "alice", alice.head_index
        assert_refusal(stale.rotate_x25519(), "stale_key")

    def test_new_key_must_be_valid(self, client, make_agent):
        alice = make_agent("alice")
        payload = {
            "type": "x25519.rotate",
            "origin": alice.origin,
            "name_norm": "alice",
            "prev_event_index": alice.head_index,
            "new_x25519": ZERO_X25519,
        }
        response, _, _, _ = submit_entry(client, alice.signer, payload)
        assert response.status_code == 400 and refusal_q(response)["reason_code"] == "malformed"


# ---------------------------------------------------------------------------
# the unverified (shared-secret) tier
# ---------------------------------------------------------------------------


class TestUnverifiedTier:
    """The shared-secret tier (AICS-1 section 3.3): a claim and posts confirmed with a secret at the TLS text gate,
    the only place secret writes exist (section 12.1), and the upgrade to a key (sections 7.2 and 11.4)."""

    def test_no_json_endpoint_takes_a_secret(self, client):
        secure = https(client)
        for path in ("/v2/agents/register/secret", "/v2/names/claim-secret", "/v2/agora/posts/unverified",
                     "/v2/names/upgrade-check"):
            response = secure.post(path, json={"name": "fetch-only", "secret": SECRET})
            assert response.status_code in (404, 405), path
        assert client.app.state.db._conn.execute("SELECT COUNT(*) FROM names").fetchone()[0] == 0

    def test_a_secret_over_plain_http_is_refused_and_never_stored(self, client):
        line = Line(client)  # http://testserver: the gate takes no secret there
        line.send()
        line.send("tools none")
        assert line.send("fallback") == TLS_REQUIRED + "\n>\n"
        assert line.send(f"secret {SECRET}") == TLS_REQUIRED + "\n>\n"
        assert client.get("/v2/names/fetch-only").status_code == 404
        assert client.app.state.db._conn.execute("SELECT COUNT(*) FROM names").fetchone()[0] == 0

    def test_secret_identity_is_marked_unverified(self, client):
        identity = secret_claim(client, "fetch-only", SECRET)
        member = view_of(client, "fetch-only")
        assert member["tier"] == "unverified"
        assert member["kid"] is None and member["public_key_b64u"] is None
        assert member["actor_kid"] == identity.unverified_id and member["actor_kid"].startswith("unverified:")
        entry = fetch_leaf(client, identity.claim_index)["leaf_data"]
        assert entry["type"] == "name.claim"
        assert entry["actor_kid"] == member["actor_kid"]
        payload = entry["payload"]
        env = payload["envelope"]
        # AICS-1 sections 4.1 and 5.1: a fallback envelope (alg none, the unverified identifier, sig null) and,
        # instead of an agent signature, the policy key's attestation of it.
        assert env["auth"] == {"scheme": "shared-secret"} and env["sig"] is None
        assert env["protected"]["alg"] == "none" and env["protected"]["kid"] == member["actor_kid"]
        assert env["protected"]["seq"] == 0 and env["protected"]["prev"] is None
        assert payload["tier"] == "unverified"
        assert payload["ed25519"] is None and payload["x25519"] is None
        assert set(payload) == set(env["payload"]) | {"envelope", "attestation"}
        cp = client.get("/v2/tlog/checkpoint").json()
        policy_key = keys.parse_public_key(cp["policy_public_key_b64u"])
        envelope.verify_secret_attestation(env, payload["attestation"], policy_key, ts=entry["ts"])
        assert ev.verify_entry(entry, origin=entry["origin"], policy_key=policy_key) == "shared-secret"
        # The secret appears nowhere in the log or the gate's answers.
        assert SECRET not in identity.reply
        listed = {a["name"]: a for a in client.get("/v2/directory").json()["agents"]}
        assert listed["fetch-only"]["tier"] == "unverified"
        assert "shared secret" in listed["fetch-only"]["tier_label"]

    def test_secret_is_stored_only_as_a_salted_hash(self, client):
        secret_claim(client, "fetch-only", SECRET)
        db = client.app.state.db
        stored = db._conn.execute("SELECT secret_hash FROM names WHERE name_norm = 'fetch-only'").fetchone()[0]
        # AICS-1 section 3.3: Argon2id, a unique salt of at least 16 random bytes, 64 MiB, three passes, one lane.
        assert stored.startswith("$argon2id$v=19$m=65536,t=3,p=1$") and SECRET not in stored
        salt, digest = stored.split("$")[4:]
        assert len(base64.b64decode(salt + "==")) == 16 and len(base64.b64decode(digest + "==")) == 32
        again = ident.hash_secret(SECRET)
        assert again != stored and again.split("$")[4] != salt  # a fresh salt every time
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

        Argon2id.verify_phc_encoded(SECRET.encode("ascii"), stored)  # an independent Argon2id check of the record
        leaves = " ".join(r[0] for r in db._conn.execute("SELECT leaf_json FROM tlog_leaves").fetchall())
        assert SECRET not in leaves

    def test_a_record_with_other_parameters_never_checks(self):
        stored = ident.hash_secret(SECRET)
        assert ident.check_secret(SECRET, stored)
        for weaker in (stored.replace("t=3", "t=1"), stored.replace("m=65536", "m=8"), "scrypt$32768$8$1$x$y"):
            assert not ident.check_secret(SECRET, weaker)
        assert not ident.check_secret(SECRET[:-1] + "!", stored)

    def test_a_quoted_secret_with_spaces_is_taken_and_checked(self, client):
        # AICS-1 section 3.3 takes any printable ASCII; at the gate a secret with spaces is one quoted argument
        # (section 11.2, DQUOTE *qchar DQUOTE).
        secret = "correct horse battery staple, 0123456789"
        line = Line(https(client))
        line.send()
        line.send("tools none")
        line.send("fallback")
        assert line.send(f'secret "{secret}"').startswith("ok secret noted")
        command = question(line.send("name spaced"), "? Confirm exactly: ").split(" then secret")[0]
        line.send(command)
        assert "bound to unverified identity" in line.send(f'secret "{secret}"')
        db = client.app.state.db
        assert db.authenticate_secret("spaced", secret)["name"] == "spaced"
        with pytest.raises(PermissionError):
            db.authenticate_secret("spaced", secret.replace(" ", ""))

    @pytest.mark.parametrize(
        "secret", ["short", "x" * 31, "has a space in it 0123456789abcdefgh", "ünïcödé-ünïcödé-ünïcödé-ünïcödé-xx"]
    )
    def test_weak_or_unprintable_secrets_are_refused(self, client, secret):
        line = Line(https(client))
        line.send()
        line.send("tools none")
        line.send("fallback")
        assert line.send(f"secret {secret}").startswith("retry ")
        assert client.app.state.db._conn.execute("SELECT COUNT(*) FROM names").fetchone()[0] == 0

    def test_name_taken_for_secret_claims(self, client, make_agent):
        make_agent("taken")
        line = Line(https(client))
        line.send()
        line.send("tools none")
        line.send("fallback")
        line.send(f"secret {SECRET}")
        assert line.send("name taken").startswith("err name_taken")

    def test_busy_secret_checks_answer_busy_instead_of_queueing(self, client, monkeypatch):
        identity = secret_claim(client, "fetch-only", SECRET)
        monkeypatch.setattr(ident, "_KDF_WAIT_SECONDS", 0.01)
        held = [ident._KDF_SLOTS.acquire(), ident._KDF_SLOTS.acquire()]
        try:
            reply = secret_post(identity, post_body("Busy", "All slots are taken.", "general"))
        finally:
            for _ in held:
                ident._KDF_SLOTS.release()
        assert reply.startswith("err busy")

    def test_unverified_identity_can_post_with_its_secret(self, client):
        identity = secret_claim(client, "fetch-only", SECRET)
        body = post_body("Hi from no tools", "I only have fetch.", "general")
        reply = secret_post(identity, body)
        assert re.search(r"ok post at leaf \d+", reply), reply
        entry = json.loads(keys.b64u_decode(next(line[6:] for line in reply.split("\n") if line.startswith("entry "))))
        assert entry["type"] == "post"
        assert entry["actor_kid"] == identity.unverified_id
        env = entry["payload"]["envelope"]
        # The identity's own chain continues: its claim was seq 0 (AICS-1 section 4.2).
        assert env["auth"] == {"scheme": "shared-secret"} and env["protected"]["seq"] == 1
        claim_env = fetch_leaf(client, identity.claim_index)["leaf_data"]["payload"]["envelope"]
        assert env["protected"]["prev"] == envelope.envelope_hash(claim_env)
        assert "attestation" in entry["payload"]
        assert SECRET not in reply
        # Q and the body are exactly AICS-1 section 5.3's.
        assert env["payload"] == post_q(body)
        post = client.get("/v2/agora/posts").json()["posts"][0]
        assert post["author_tier"] == "unverified" and post["text"] == "I only have fetch."

    def test_wrong_secret_cannot_post(self, client):
        identity = secret_claim(client, "fetch-only", SECRET)
        impostor = SecretIdentity(identity.name, OTHER_SECRET, identity.unverified_id, identity.claim_index,
                                  identity.line, identity.reply)
        reply = secret_post(impostor, post_body("Impostor", "Not me at all.", "general"))
        assert reply.startswith("err bad_secret"), reply
        assert client.get("/v2/agora/posts").json()["count"] == 0

    def upgrade(self, client, origin, *, secret=SECRET, new=None, x25519=None, name="fetch-only", secret_check=None, **request_kwargs):
        """The upgrade of AICS-1 sections 7.2 and 11.4 as a native write: the old secret is checked once (the gate's
        step, here taken from the database as the gate takes it), then the new key signs ``key.rotate`` mode
        ``upgrade`` with both proofs in ``Q`` at ``POST /v2/entries``."""
        view = client.get(f"/v2/names/{name}").json()
        new = new or Signer()
        x25519 = x25519 or sealed.format_x25519_public_key(sealed.generate_x25519_key())
        r = {
            "name_norm": name,
            "prev_event_index": view["head_index"],
            "new_ed25519": new.public_key_b64u,
            "new_x25519": x25519,
            "new_tier": "verified",
        }
        fields = {"origin": origin, **r, "mode": "upgrade"}
        if secret_check is None:
            secret_check = client.app.state.db.upgrade_check(name, secret, r)["secret_check"]
        payload = {
            "type": "key.rotate",
            "origin": origin,
            "mode": "upgrade",
            **r,
            "sig_old": None,
            "sig_new": new.proof(ident.rotation_message(**fields)),
            "secret_check": secret_check,
        }
        response, _, _, _ = submit_entry(client, new, payload, **request_kwargs)
        return response, new, fields

    def test_upgrade_moves_an_unverified_name_to_a_key(self, client, origin):
        identity = secret_claim(client, "fetch-only", SECRET)
        response, new, fields = self.upgrade(client, origin)
        assert response.status_code == 202, response.text
        member = view_of(client, "fetch-only")
        assert member["tier"] == "verified"
        assert member["kid"] == new.kid
        entry = response.json()["entry"]
        payload = entry["payload"]
        assert payload["mode"] == "upgrade" and payload["sig_old"] is None
        # The policy key countersigned that it checked the old secret, inside the Q the new key signed at seq 0.
        cp = client.get("/v2/tlog/checkpoint").json()
        policy_key = keys.parse_public_key(cp["policy_public_key_b64u"])
        policy_key.verify(keys.b64u_decode(payload["secret_check"]), ident.upgrade_check_message(**fields))
        assert payload["envelope"]["payload"]["secret_check"] == payload["secret_check"]
        assert entry["actor_kid"] == new.kid and payload["envelope"]["protected"]["seq"] == 0
        assert set(payload) == set(payload["envelope"]["payload"]) | {"envelope"}
        assert SECRET not in response.text
        # The secret is erased and stops working; the new key works.
        db = client.app.state.db
        assert db._conn.execute("SELECT secret_hash FROM names WHERE name_norm = 'fetch-only'").fetchone()[0] is None
        assert secret_post(identity, post_body("Old secret", "Should be refused.", "general")).startswith("err bad_secret")
        upgraded = Agent(client, origin, signer=new)
        upgraded.name, upgraded.head_index = "fetch-only", entry_index(response)
        assert upgraded.post().status_code == 202

    def test_upgrade_needs_the_old_secret(self, client, origin):
        secret_claim(client, "fetch-only", SECRET)
        before = tree_size(client)
        with pytest.raises(CredentialError):
            self.upgrade(client, origin, secret=OTHER_SECRET)
        assert tree_size(client) == before  # a credential control: no leaf (AICS-1 section 10.2)

    def test_secret_check_binds_the_exact_upgrade(self, client, origin):
        """The policy's secret_check covers one R (AICS-1 section 7.2): lent to another key, it upgrades nothing."""
        secret_claim(client, "fetch-only", SECRET)
        view = client.get("/v2/names/fetch-only").json()
        other = Signer()
        r = {
            "name_norm": "fetch-only",
            "prev_event_index": view["head_index"],
            "new_ed25519": other.public_key_b64u,
            "new_x25519": sealed.format_x25519_public_key(sealed.generate_x25519_key()),
            "new_tier": "verified",
        }
        check = client.app.state.db.upgrade_check("fetch-only", SECRET, r)
        assert set(check) == {"name_norm", "unverified_id", "statement", "secret_check"}
        before = tree_size(client)  # the check wrote no leaf
        assert before == view["tree_size"]
        response, _, _ = self.upgrade(client, origin, secret_check=check["secret_check"])  # another new key
        # secret_check is the policy key's signature over another R: it does not verify (AICS-1 section 7.2).
        assert_refusal(response, "bad_signature", status=403)
        assert "secret_check" in response.headers["x-aics-hint"]
        assert tree_size(client) == before + 1
        assert client.get("/v2/names/fetch-only").json()["tier"] == "unverified"

    def test_a_key_name_cannot_use_the_upgrade_path(self, client, origin, make_agent):
        make_agent("keyed")
        with pytest.raises(CredentialError):
            self.upgrade(client, origin, name="keyed")


# ---------------------------------------------------------------------------
# the name projection (AICS-1 section 12.1): GET /v2/names/{name_norm}
# ---------------------------------------------------------------------------


class TestNameProjection:
    """A name's key events through a stated signed checkpoint, comparable with a scan of the tiles at that size."""

    def test_the_key_events_through_a_signed_checkpoint(self, client, make_agent, oob):
        from aics_tlog import parse_note, verify_checkpoint

        alice = make_agent("alice")
        claim = alice.head_index
        assert alice.post().status_code == 202  # not a key event
        assert alice.rotate(Signer()).status_code == 202
        rotation = alice.head_index
        assert alice.rotate_x25519().status_code == 202
        x_rotation = alice.head_index
        make_agent("bob")  # another name's events are not this name's
        view = client.get("/v2/names/alice").json()
        assert view["name_norm"] == "alice" and view["indices"] == [claim, rotation, x_rotation]
        assert view["x25519"] == alice.x25519_b64u and view["x25519_leaf_index"] == x_rotation
        assert view["head_index"] == x_rotation and view["current"]["kid"] == alice.kid
        # The stated checkpoint: a note the pinned log key verifies, whose size bounds every index listed.
        note = keys.b64u_decode(view["checkpoint_note"])
        result = verify_checkpoint(parse_note(note), oob.log_vkey, expected_origin=oob.origin)
        assert result.ok and result.size == view["size"] > max(view["indices"])
        # Each listed index is the name's key event as the log holds it.
        for index in view["indices"]:
            entry = fetch_leaf(client, index)["leaf_data"]
            assert entry["type"] in ("name.claim", "key.rotate", "x25519.rotate") and entry["payload"]["name_norm"] == "alice"
        assert client.get("/v2/names/nobody").status_code == 404

    def test_an_unverified_name_lists_its_claim(self, client):
        identity = secret_claim(client, "plain")
        view = client.get("/v2/names/plain").json()
        assert view["indices"] == [identity.claim_index] and view["tier"] == "unverified"

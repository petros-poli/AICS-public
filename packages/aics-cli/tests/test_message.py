"""aics verify message: AICS-1 §14.3 for one entry (DESIGN G8) - checkpoint, inclusion, entry and envelope,
the name/key/sequence history through the index from a complete prefix, and the exit codes that keep a bad file
(exit 1) apart from log-signed evidence (exit 2)."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
from typing import Any

import pytest
from aics_identity import envelope as idenv
from aics_identity import keys as idkeys
from aics_identity.canonical import canonicalize
from aics_tlog import Bundle, MerkleTree
from aics_tlog.tiles import TileWriter

from aics_cli.checkpoints import CheckpointStore, log_signed
from aics_cli.cli import run
from aics_cli.encoding import b64u_e

from conftest import NOW, ORIGIN, TILES, Log, did, make_policy

T = NOW - 86400  # when the entries were accepted (the history is judged at its own times)
CT = bytes(range(80))  # a stand-in ciphertext: its hash and size are what the leaf commits to


def H(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def x25519_pub() -> str:
    return b64u_e(os.urandom(32))


class World:
    """An AICS-1 log built entry by entry with known keys: leaf 0 the dual-signed charter, then whatever a test adds."""

    def __init__(self) -> None:
        self.log_key = idkeys.generate_keypair()
        self.policy_key = idkeys.generate_keypair()
        self.owner_key = idkeys.generate_keypair()
        self.log = Log(origin=ORIGIN, key=self.log_key, entries=[])
        self.last: dict[str, dict[str, Any]] = {}
        self.envelopes: list[dict[str, Any]] = []
        self.names: dict[str, int] = {}  # name -> index of its latest key event
        log_kid = idkeys.did_key(self.log_key.public_key())
        charter = b"test charter\n"
        q = {"kind": "charter", "document_hash": H(charter), "size": len(charter), "prev_policy_index": None,
             "effective_after": 0, "not_before": T, "log_kid": log_kid, "policy_kid": did(self.policy_key),
             "owner_kid": did(self.owner_key)}
        q["log_sig"] = b64u_e(self.log_key.sign(b"AICS-1 policy\n" + canonicalize(q)))
        self.add(self.policy_key, "policy", q)

    def envelope(self, key, typ: str, q: dict[str, Any], *, created: int, seq: int | None = None,
                 prev: Any = "chain", types=idenv.SUP_PROFILE_TYPES) -> dict[str, Any]:
        kid = did(key)
        prior = self.last.get(kid)
        if seq is None:
            seq = prior["protected"]["seq"] + 1 if prior else 0
        if prev == "chain":
            prev = idenv.envelope_hash(prior) if prior else None
        return idenv.sign_envelope(q, key, origin=ORIGIN, type=typ, created=created, seq=seq, prev=prev,
                                   types=types)

    def add(self, key, typ: str, q: dict[str, Any], *, ts: int | None = None, env: dict[str, Any] | None = None,
            **kw: Any) -> int:
        ts = T + len(self.log.entries) if ts is None else ts
        env = env or self.envelope(key, typ, q, created=ts, **kw)
        self.last[env["protected"]["kid"]] = env
        entry = {"v": 2, "origin": ORIGIN, "type": typ, "actor_kid": env["protected"]["kid"], "ts": ts,
                 "payload": {"envelope": env, **env["payload"]}}
        self.log.append(canonicalize(entry))
        self.envelopes.append(env)
        return len(self.log.entries) - 1

    def claim(self, name: str, key, *, grant: dict[str, Any] | None = None) -> int:
        q = {"name_norm": name, "prev_event_index": None,
             "ed25519": b64u_e(idkeys.public_key_bytes(key.public_key())), "x25519": x25519_pub(),
             "tier": "verified", "recovery_kid": None, "recovery_pop": None, "initial_grant": grant}
        i = self.add(key, "name.claim", q)
        self.names[name] = i
        return i

    def post(self, key, text: str = "hello") -> int:
        body = canonicalize({"channel": "general", "title": None, "text": text})
        q = {"channel_sha256": H(b"general"), "parent_index": None, "body_hash": H(body), "size": len(body),
             "title_sha256": None}
        return self.add(key, "post", q)

    def dm(self, sender, recipient_kid: str, *, to_key_leaf_index: int, grant_index: int, **kw: Any) -> int:
        kid = did(sender)
        prior = self.last.get(kid)
        seq = kw.pop("seq", prior["protected"]["seq"] + 1 if prior else 0)
        prev = kw.pop("prev", idenv.envelope_hash(prior) if prior else None)
        q = {"to_kid": recipient_kid, "to_key_leaf_index": to_key_leaf_index,
             "encryption": "x25519-xsalsa20-poly1305", "eph_pk": b64u_e(bytes(32)), "ct_hash": H(CT),
             "size": len(CT), "seq": seq, "prev": prev, "grant_index": grant_index}
        return self.add(sender, "dm", q, seq=seq, prev=prev, **kw)

    def rotate(self, name: str, old, new) -> int:
        q = {"mode": "rotate", "name_norm": name, "prev_event_index": self.names[name],
             "new_ed25519": b64u_e(idkeys.public_key_bytes(new.public_key())), "new_x25519": None,
             "new_tier": "verified"}
        data = b"AICS-1 key.rotate\n" + canonicalize({**q, "origin": ORIGIN})
        q["sig_old"] = {"scheme": "ed25519", "signature": b64u_e(old.sign(data))}
        q["sig_new"] = {"scheme": "ed25519", "signature": b64u_e(new.sign(data))}
        i = self.add(old, "key.rotate", q)
        self.names[name] = i
        return i

    # -- what a verifier is handed ---------------------------------------------------------------------------

    def note(self, size: int | None = None) -> str:
        return self.log.note(size)

    def bundle(self, index: int, *, size: int | None = None, body: bytes | None = None) -> dict[str, Any]:
        size = len(self.log.entries) if size is None else size
        proof = MerkleTree(self.log.entries[:size]).inclusion_proof(index, size)
        return Bundle(entry_bytes=self.log.entries[index], index=index, inclusion_proof=tuple(proof),
                      checkpoint_note=self.note(size), envelope=self.envelopes[index], body_or_ct=body).to_dict()

    def package(self, index: int, **kw: Any) -> dict[str, Any]:
        return {"bundle": self.bundle(index, **kw), "trust_bundle": self.trust(),
                "policy_cards": [], "entry_prefix": [b64u_e(e) for e in self.log.entries],
                "checkpoint_notes": []}

    def trust(self) -> dict[str, Any]:
        return {"v": 1, "origin": ORIGIN, "log_vkey": self.log.vkey, "policy_kid": did(self.policy_key),
                "owner_kid": did(self.owner_key), "bootstrap_card_hash": "0" * 64}

    def pin(self, h) -> None:
        make_policy(h.home, self.log, policy_kid=did(self.policy_key), owner_kid=did(self.owner_key),
                    bootstrap_card_hash="0" * 64)


@pytest.fixture
def w() -> World:
    world = World()
    world.alice, world.bob = idkeys.generate_keypair(), idkeys.generate_keypair()
    world.claim("alice", world.alice)
    world.claim("bob", world.bob, grant={"sender_kid": did(world.alice), "max": 1, "expires": T + 3600})
    world.dm(world.alice, did(world.bob), to_key_leaf_index=2, grant_index=2)
    return world


def verify(h, doc: dict[str, Any] | None, *args: str, tmp: Path | None = None) -> tuple[int, dict[str, Any]]:
    path = (tmp or h.home.parent) / "input.json"
    if doc is not None:
        path.write_text(json.dumps(doc), "utf-8")
    return h.run("verify", "message", "--bundle", str(path), *args)


def steps(out: dict[str, Any]) -> dict[str, str]:
    return {s["step"]: s["status"] for s in out["steps"]}


# ---------------------------------------------------------------------------
# what a complete check proves
# ---------------------------------------------------------------------------


def test_a_bare_bundle_offline_proves_inclusion_and_signature_but_not_the_history(h, w):
    w.pin(h)
    code, out = verify(h, w.bundle(3, body=CT), "--offline")
    assert code == 1 and out["result"] == "incomplete", out
    assert steps(out) == {"checkpoint": "valid", "inclusion": "valid", "entry": "valid", "history": "incomplete",
                          "envelope": "valid", "body": "valid"}
    assert "AICS-1 §14.3 step 2" in out["error"]
    assert out["entry"]["type"] == "dm" and out["entry"]["actor_kid"] == did(w.alice)


def test_the_pinned_tiles_complete_the_history(h, w):
    w.pin(h)
    h.fetcher.serve_tiles(TILES, w.log.tiles())
    code, out = verify(h, w.bundle(3, body=CT))
    assert code == 0 and out["result"] == "valid", out
    assert steps(out) == {"checkpoint": "valid", "inclusion": "valid", "entry": "valid", "continuity": "valid",
                          "history": "valid", "envelope": "valid", "dm": "valid", "body": "valid"}
    assert out["signer"] == {"role": "name", "name": "alice", "tier": "verified"}
    assert any("decryption" in u for u in out["unproven"])  # never claimed
    code, text = h.run_text("verify", "message", "--bundle", str(h.home.parent / "input.json"))
    assert code == 0 and "history    valid" in text and "unproven" in text


def test_a_package_verifies_offline_and_a_tile_directory_does_too(h, w, tmp_path):
    w.pin(h)
    code, out = verify(h, w.package(3), "--offline")
    assert code == 0 and out["result"] == "valid", out
    tiles = tmp_path / "tiles"
    TileWriter(w.log.entries).write_to(tiles)
    code, out = verify(h, w.bundle(1), "--offline", "--tiles", str(tiles))
    assert code == 0 and out["signer"]["name"] == "alice", out  # a claim: its key is the name's from then on
    assert not h.fetcher.requests  # offline means offline


def test_the_signer_of_a_service_entry_is_the_pinned_key(h, w):
    w.pin(h)
    code, out = verify(h, w.package(0), "--offline")
    assert code == 0 and out["signer"] == {"role": "policy key (pinned)"}, out


def test_a_tombstone_of_the_entry_is_reported(h, w):
    w.add(w.policy_key, "tombstone", {"target_index": 3, "reason_code": "order", "evidence_hash": None,
                                      "receipt_hash": None})
    w.pin(h)
    code, out = verify(h, w.package(3), "--offline")
    assert code == 0 and out["tombstones"] == [{"index": 4, "reason_code": "order"}], out
    assert steps(out)["body"] == "not-applicable" and steps(out)["tombstone"] == "valid"


def test_the_bundle_can_come_from_stdin(h, w):
    w.pin(h)
    h.fetcher.serve_tiles(TILES, w.log.tiles())
    buf = io.StringIO()
    env = h.env
    env.stdin = io.BytesIO(json.dumps(w.bundle(2)).encode())
    code = run(["verify", "message", "--bundle", "-", "--json"], env=env, out=buf)
    assert code == 0, buf.getvalue()


# ---------------------------------------------------------------------------
# log-signed evidence (exit 2)
# ---------------------------------------------------------------------------


def _forge_sig(w: World, index: int) -> None:
    """Replace leaf ``index`` with the same entry under a signature that does not verify; the log signs it."""
    entry = json.loads(w.log.entries[index])
    env = entry["payload"]["envelope"]
    raw = idkeys.u64_decode(env["sig"])
    env["sig"] = b64u_e(bytes([raw[0] ^ 1]) + raw[1:])
    w.envelopes[index] = env
    w.log.entries[index] = canonicalize(entry)


def test_a_logged_entry_whose_signature_fails_is_evidence(h, w):
    _forge_sig(w, 3)
    w.pin(h)
    code, out = verify(h, w.bundle(3), "--offline")
    assert code == 2 and out["evidence"]["reason"] == "invalid-envelope", out
    assert out["evidence"]["checkpoint"]["note"] == w.note() and out["evidence"]["bundle"]["index"] == 3
    code, out = verify(h, w.package(3), "--offline")
    assert code == 2 and out["evidence"]["reason"] == "invalid-history" and out["evidence"]["rule"] == "envelope"
    assert out["evidence"]["leaf"]["index"] == 3


def test_an_earlier_bad_entry_makes_the_history_invalid(h, w):
    _forge_sig(w, 1)  # alice's claim
    w.pin(h)
    code, out = verify(h, w.package(3), "--offline")
    assert code == 2 and out["evidence"]["leaf"]["index"] == 1, out
    proof = out["evidence"]["leaf"]["inclusion_proof"]
    assert len(proof) == 2  # leaf 1 of 4, re-checkable against the log-signed checkpoint


def test_a_dm_without_consent_is_evidence(h):
    w = World()
    alice, bob = idkeys.generate_keypair(), idkeys.generate_keypair()
    w.claim("alice", alice)
    w.claim("bob", bob)  # no initial grant
    w.dm(alice, did(bob), to_key_leaf_index=2, grant_index=2)
    w.pin(h)
    code, out = verify(h, w.package(3), "--offline")
    assert code == 2 and out["evidence"]["rule"] == "no_consent", out


def test_a_grant_used_up_is_evidence(h, w):
    w.dm(w.alice, did(w.bob), to_key_leaf_index=2, grant_index=2)  # a second DM under max 1
    w.pin(h)
    code, out = verify(h, w.package(4), "--offline")
    assert code == 2 and out["evidence"]["rule"] == "grant_exhausted", out
    assert verify(h, w.package(3), "--offline")[0] == 0  # the first one was within the grant


def test_a_sequence_break_is_evidence(h):
    w = World()
    alice = idkeys.generate_keypair()
    w.claim("alice", alice)
    w.post(alice)
    w.add(alice, "post", {"channel_sha256": H(b"general"), "parent_index": None, "body_hash": H(b"x"), "size": 1,
                          "title_sha256": None}, seq=1, prev=idenv.envelope_hash(w.envelopes[1]))  # seq 1 again
    w.pin(h)
    code, out = verify(h, w.package(3), "--offline")
    assert code == 2 and out["evidence"]["rule"] == "sequence", out


def test_a_retired_key_cannot_sign_after_its_rotation(h):
    w = World()
    old, new = idkeys.generate_keypair(), idkeys.generate_keypair()
    w.claim("alice", old)
    w.rotate("alice", old, new)
    w.post(new)
    w.pin(h)
    code, out = verify(h, w.package(3), "--offline")
    assert code == 0 and out["signer"]["name"] == "alice", out  # the new key is the name's at leaf 3
    w.post(old)
    code, out = verify(h, w.package(4), "--offline")
    assert code == 2 and out["evidence"]["rule"] == "signer", out


def test_a_service_entry_signed_by_another_key_is_evidence(h, w):
    w.add(w.alice, "tombstone", {"target_index": 3, "reason_code": "order", "evidence_hash": None,
                                 "receipt_hash": None})
    w.pin(h)
    code, out = verify(h, w.package(4), "--offline")
    assert code == 2 and out["evidence"]["rule"] == "authority", out


def test_a_saved_checkpoint_the_prefix_contradicts_is_a_split_view(h, w):
    w.pin(h)
    forged = w.log.note(2, root=bytes(32))  # log-signed, size 2, a root the authenticated prefix does not have
    cp, error, _ = log_signed(forged, origin=ORIGIN, log_vkey=w.log.vkey, source="test")
    assert cp is not None, error
    CheckpointStore(h.home / "checkpoints").save(cp, now=NOW)
    code, out = verify(h, w.package(3), "--offline")
    assert code == 2 and out["evidence"]["reason"] == "split-proven", out
    assert out["evidence"]["other_checkpoint"]["note"] == forged


# ---------------------------------------------------------------------------
# incomplete (exit 1)
# ---------------------------------------------------------------------------


def test_a_larger_saved_head_needs_a_consistency_proof(h, w):
    w.pin(h)
    package = w.package(3)
    w.post(w.bob)  # the log grows; the user saw the larger head
    cp, error, _ = log_signed(w.note(), origin=ORIGIN, log_vkey=w.log.vkey, source="test")
    CheckpointStore(h.home / "checkpoints").save(cp, now=NOW)
    code, out = verify(h, package, "--offline")
    assert code == 1 and out["result"] == "incomplete" and "continuity" in out["error"], out
    assert [c["status"] for c in out["continuity"]] == ["unproven"]
    h.fetcher.serve_tiles(TILES, w.log.tiles())  # online, the tiles of the larger head prove it
    code, out = verify(h, package)
    assert code == 0 and [c["status"] for c in out["continuity"]] == ["consistent"], out


def test_a_swarm_entry_is_an_unsupported_profile(h, w):
    agent = idkeys.generate_keypair()
    w.add(agent, "agent.introduce", {"swarm": None}, types=idenv.ALL_PROFILE_TYPES)
    w.post(w.alice)
    w.pin(h)
    code, out = verify(h, w.package(5), "--offline")
    assert code == 1 and "unsupported profile" in out["error"] and "§19" in out["error"], out


def test_an_unmet_witness_policy_is_incomplete(h, w):
    from conftest import Witness

    witness = Witness("witness.test/w1")
    make_policy(h.home, w.log, policy_kid=did(w.policy_key), owner_kid=did(w.owner_key), witnesses=[witness],
                quorum=1, bootstrap_card_hash="0" * 64)
    code, out = verify(h, w.package(3), "--offline")
    assert code == 1 and steps(out)["checkpoint"] == "incomplete", out


# ---------------------------------------------------------------------------
# a bad file (exit 1, no evidence against the log)
# ---------------------------------------------------------------------------


def test_bad_files_are_no_evidence(h, w):
    w.pin(h)
    bad_proof = w.bundle(3)
    bad_proof["inclusion_proof"] = bad_proof["inclusion_proof"][::-1]
    other_env = w.bundle(3)
    other_env["envelope"] = w.envelopes[1]
    wrong_body = w.bundle(3, body=CT[::-1])
    other_key = Log(origin=ORIGIN, entries=w.log.entries)
    foreign = w.bundle(3)
    foreign["checkpoint_note"] = b64u_e(other_key.note().encode())
    for doc in (bad_proof, other_env, wrong_body, foreign, {"not": "a bundle"}):
        code, out = verify(h, doc, "--offline")
        assert code == 1 and "evidence" not in out, out


def test_a_package_never_supplies_trust(h, w):
    w.pin(h)
    package = w.package(3)
    package["trust_bundle"] = {**package["trust_bundle"], "policy_kid": did(idkeys.generate_keypair())}
    code, out = verify(h, package, "--offline")
    assert code == 1 and "pinned trust" in out["error"], out
    package = w.package(3)
    package["extra"] = 1
    assert verify(h, package, "--offline")[0] == 1


def test_a_prefix_that_does_not_reconstruct_the_root_is_refused(h, w):
    w.pin(h)
    package = w.package(3)
    package["entry_prefix"][1] = b64u_e(b"not the leaf")
    code, out = verify(h, package, "--offline")
    assert code == 1 and "reconstruct" in out["error"], out
    package = w.package(3)
    package["entry_prefix"] = package["entry_prefix"][:3]
    assert verify(h, package, "--offline")[0] == 1


def test_verify_message_needs_a_bundle(h, w):
    w.pin(h)
    code, out = h.run("verify", "message")
    assert code == 1 and "--bundle" in out["error"] and "available" not in out, out


def test_offline_refuses_a_tile_url(h, w):
    w.pin(h)
    code, out = verify(h, w.bundle(3), "--offline", "--tiles", "https://mirror.test/tiles/")
    assert code == 1 and "offline" in out["error"], out


# ---------------------------------------------------------------------------
# AICS-1 §4.3 as amended (DECISIONS row 26): a (kid, nonce) is used once, for good
# ---------------------------------------------------------------------------


POST_Q = {"channel_sha256": H(b"general"), "parent_index": None, "body_hash": H(b"x"), "size": 1,
          "title_sha256": None}


def test_a_nonce_reused_after_its_expiry_is_a_replay(h):
    w = World()
    alice = idkeys.generate_keypair()
    w.claim("alice", alice)
    first = w.post(alice)
    nonce = w.envelopes[first]["protected"]["nonce"]
    later = w.envelopes[first]["protected"]["expires"] + 3600  # the first record expired an hour ago
    w.add(alice, "post", POST_Q, ts=later, env=w.envelope(alice, "post", POST_Q, created=later))
    w.pin(h)
    assert verify(h, w.package(3), "--offline")[0] == 0  # a fresh nonce after expiry is fine
    w.add(alice, "post", POST_Q, ts=later + 1,
          env=idenv.sign_envelope(POST_Q, alice, origin=ORIGIN, type="post", created=later + 1, nonce=nonce, seq=3,
                                  prev=idenv.envelope_hash(w.envelopes[3]), types=idenv.SUP_PROFILE_TYPES))
    code, out = verify(h, w.package(4), "--offline")
    assert code == 2 and out["evidence"]["rule"] == "replay", out
    assert f"leaf {first}" in out["error"], out


def test_a_refused_attempt_uses_its_nonce_for_good(h):
    """A refusal's attempt tuple is a record a leaf backs: the server refuses that (kid, nonce) forever."""
    w = World()
    alice = idkeys.generate_keypair()
    w.claim("alice", alice)
    nonce, expires = b64u_e(os.urandom(16)), T + 10
    refusal = w.add(w.policy_key, "refusal", {
        "envelope_hash": "ab" * 32, "request_hash": None, "attempt_kid": did(alice), "attempt_nonce": nonce,
        "attempt_expires": expires, "reason_code": "bad_signature", "conflict_index": None, "receipt_hash": None})
    later = expires + 86400
    w.add(alice, "post", POST_Q, ts=later,
          env=idenv.sign_envelope(POST_Q, alice, origin=ORIGIN, type="post", created=later, nonce=nonce, seq=1,
                                  prev=idenv.envelope_hash(w.envelopes[1]), types=idenv.SUP_PROFILE_TYPES))
    w.pin(h)
    code, out = verify(h, w.package(3), "--offline")
    assert code == 2 and out["evidence"]["rule"] == "replay", out
    assert f"leaf {refusal}" in out["error"], out

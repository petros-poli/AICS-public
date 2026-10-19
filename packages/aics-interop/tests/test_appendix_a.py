"""Item 8: AICS-1 Appendix A against every package that can consume it.

The values are read from ``docs/spec/AICS-1.md`` itself (code blocks, the
leaf-hash table, inline hex) and the A.5 reproduction program embedded in the
specification is executed (``aics_interop.appendix_a``).  Consumers:

* the suite's reference (``aics_interop.spec``) reproduces every byte;
* aics-identity: JCS, the signing digest, ``verify_envelope``, did:key, the
  inner header, ``seen_from_checkpoint``, ``envelope_hash`` (the A.1 hash) and
  ``open_sealed`` (the A.4 box opens to its framed plaintext);
* aics-tlog: leaf/node hashing, root, both proofs, vkeys, the A.3 note and
  cosignature bytes, ``verify_checkpoint``, the entry-bundle record, a bundle;
* aics-witness: fed the size-3 and size-4 checkpoints with the A.2 proof at
  the A.3 times, it returns the A.3 cosignature lines byte for byte;
* aics: the A.3 notes as checkpoints and as a gossip pair (with the A.2 proof);
* aics-conformance: the four entries as a complete history, the A.3 head and
  continuity, the A.1 signature, opening A.4, a §14.3 bundle for the DM.
"""

from __future__ import annotations

import json

import pytest
from nacl.bindings import crypto_box_seal_open
from nacl.public import PrivateKey

from aics_interop import appendix_a, drivers, spec, world

ORIGIN, WITNESS_NAME, EPOCH = appendix_a.ORIGIN, appendix_a.WITNESS_NAME, appendix_a.EPOCH
KEY = {name: spec.test_key(seed) for name, seed in appendix_a.SEEDS.items()}
X = {name: bytes([seed]) * 32 for name, seed in appendix_a.X25519_SEEDS.items()}
COSIGNED_AT = EPOCH + 2


@pytest.fixture(scope="module")
def a():
    return appendix_a.load()


def lines_of(note: bytes) -> list[str]:
    return [ln for ln in note.decode("utf-8").split("\n") if ln.startswith(spec.EM_DASH)]


def log_only(note: bytes) -> bytes:
    """The note with its log signature line only (what the log hands its witnesses)."""
    text = note.decode("utf-8").split("\n\n")[0] + "\n"
    return spec.signed_note(text, [lines_of(note)[0] + "\n"])


def proof(b64s: list[str]) -> list[bytes]:
    return [spec.dB64(h) for h in b64s]


def policy(a, quorum=1):
    return drivers.conformance_policy(appendix_a.trust_bundle_dict(), witnesses=[a.inline["witness_vkey"]],
                                      quorum=quorum)


# ---------------------------------------------------------------------------
# the specification is self-consistent
# ---------------------------------------------------------------------------


def test_text_and_the_a5_program_agree(a):
    v = a.values
    J = a.program["J"]
    assert J(v["envelope"]) == a.envelope_bytes
    assert J(v["entry"]) == a.entry_bytes == a.entry_jcs(3)
    assert str(v["entry_length"]) == a.inline["entry_length"] == str(len(a.entry_bytes))
    assert len(a.entry_bytes).to_bytes(2, "big").hex() == a.inline["entry_record_prefix"]
    for key in ("signing_digest", "envelope_hash", "checkpoint_hash", "ciphertext_hash", "ephemeral_public_key",
                "box_nonce", "alice_public_key", "log_vkey", "witness_vkey", "previous_checkpoint_hash"):
        assert v[key] == a.inline[key], key
    assert v["bob_encryption_public_key"] == a.inline["bob_x25519"]
    assert v["leaf_hashes"] == a.leaf_hashes and v["root"] == a.root
    assert v["inclusion_proof"] == a.inclusion_proof and v["consistency_proof"] == a.consistency_proof
    assert v["checkpoint"].encode() == a.checkpoint and v["previous_checkpoint"].encode() == a.previous_checkpoint
    assert v["cosign_input"].encode() == a.cosign_input
    assert J(v["header"]) == a.header_bytes and str(v["header_length"]) == a.inline["header_length"]
    assert v["header_frame_hex"][:8] == a.inline["header_prefix"]
    assert bytes.fromhex(v["plaintext_hex"]) == a.plaintext and bytes.fromhex(v["ciphertext_hex"]) == a.ciphertext
    assert str(v["ciphertext_length"]) == a.inline["ciphertext_length"] == str(len(a.ciphertext))
    assert str(int.from_bytes(spec.dB64(lines_of(a.checkpoint)[1].split(" ")[2])[4:12], "big")) == \
        a.inline["witness_timestamp"]


def test_the_a5_serializer_is_jcs_for_these_objects(a):
    """A.5's ``J`` is json.dumps-based; for the four entries it equals the reference RFC 8785 serializer."""
    for e in a.entries:
        assert spec.J(e) == a.program["J"](e)


# ---------------------------------------------------------------------------
# the reference reproduces every byte
# ---------------------------------------------------------------------------


def test_reference_reproduces_a1_and_a2(a):
    env = spec.strict_json(a.envelope_bytes)
    assert spec.J(env) == a.envelope_bytes
    assert spec.signing_digest(env["protected"], env["payload"]).hex() == a.inline["signing_digest"]
    assert spec.envelope_hash(env) == a.inline["envelope_hash"]
    assert spec.raw_public(KEY["alice"]).hex() == a.inline["alice_public_key"] and env["protected"]["kid"] == \
        spec.kid(KEY["alice"])
    KEY["alice"].public_key().verify(spec.dU64(env["sig"]), spec.signing_digest(env["protected"], env["payload"]))
    assert spec.J(spec.entry(env, env["protected"]["created"])) == a.entry_bytes
    leaves = [spec.leaf_hash(spec.J(e)) for e in a.entries]
    assert [h.hex() for h in leaves] == a.leaf_hashes and spec.mth(leaves).hex() == a.root
    assert spec.inclusion_path(3, leaves) == proof(a.inclusion_proof)
    assert spec.consistency_path(3, leaves) == proof(a.consistency_proof)
    assert spec.verify_inclusion(leaves[3], 3, 4, proof(a.inclusion_proof), spec.mth(leaves))
    assert spec.verify_consistency(3, 4, spec.mth(leaves[:3]), spec.mth(leaves), proof(a.consistency_proof))
    assert spec.entry_bundle([spec.J(e) for e in a.entries])[-len(a.entry_bytes) - 2:-len(a.entry_bytes)].hex() == \
        a.inline["entry_record_prefix"]


def test_reference_reproduces_a3(a):
    leaves = [spec.leaf_hash(spec.J(e)) for e in a.entries]
    assert spec.vkey(ORIGIN, 0x01, spec.raw_public(KEY["log"])) == a.inline["log_vkey"]
    assert spec.vkey(WITNESS_NAME, 0x04, spec.raw_public(KEY["witness"])) == a.inline["witness_vkey"]
    for size, note, ts in ((4, a.checkpoint, COSIGNED_AT), (3, a.previous_checkpoint, EPOCH)):
        text = spec.checkpoint_text(ORIGIN, size, spec.mth(leaves[:size]))
        assert note == spec.signed_note(text, [spec.log_signature_line(ORIGIN, KEY["log"], text),
                                               spec.cosignature_line(WITNESS_NAME, KEY["witness"], ts, text)])
        v = spec.verify_note(note, a.inline["log_vkey"], [a.inline["witness_vkey"]], 1, max_age=300, now=ts + 10)
        assert v.ok and v.timestamps == {WITNESS_NAME: ts}
    assert spec.cosignature_message(COSIGNED_AT, spec.checkpoint_text(ORIGIN, 4, spec.mth(leaves))) == a.cosign_input
    assert spec.hexH(a.checkpoint) == a.inline["checkpoint_hash"]
    assert spec.seen_pointer(a.previous_checkpoint) == spec.strict_json(a.envelope_bytes)["protected"]["seen"]


def test_reference_reproduces_a4(a):
    env = spec.strict_json(a.envelope_bytes)
    p, q = env["protected"], env["payload"]
    assert spec.inner_header(p["kid"], q["to_kid"], p["nonce"]) == a.header_bytes
    assert len(a.header_bytes).to_bytes(4, "big").hex() == a.inline["header_prefix"]
    assert spec.aics1_plaintext(a.header_bytes, b"hello\n") == a.plaintext
    assert spec.x25519_public(X["bob"]).hex() == a.inline["bob_x25519"]
    assert spec.x25519_public(X["ephemeral"]).hex() == a.inline["ephemeral_public_key"]
    assert spec.deterministic_seal(a.plaintext, spec.x25519_public(X["bob"]), X["ephemeral"]) == a.ciphertext
    assert spec.hexH(a.ciphertext) == q["ct_hash"] and len(a.ciphertext) == q["size"]
    assert spec.U64(a.ciphertext[:32]) == q["eph_pk"]
    assert crypto_box_seal_open(a.ciphertext, spec.x25519_public(X["bob"]), X["bob"]) == a.plaintext
    assert spec.split_aics1_plaintext(a.plaintext) == (a.header_bytes, b"hello\n")


# ---------------------------------------------------------------------------
# aics-identity
# ---------------------------------------------------------------------------


def test_aics_identity_against_a1_and_a4(a):
    from aics_identity import canonicalize, keys, sealed
    from aics_identity import envelope as idenv

    env = spec.strict_json(a.envelope_bytes)
    assert canonicalize(env) == a.envelope_bytes
    assert idenv.envelope_signing_digest(env["protected"], env["payload"]).hex() == a.inline["signing_digest"]
    assert keys.did_key(KEY["alice"].public_key()) == env["protected"]["kid"]
    assert keys.public_key_bytes(keys.parse_did_key(env["protected"]["kid"])).hex() == a.inline["alice_public_key"]
    assert idenv.verify_envelope(json.loads(a.envelope_bytes), keys.parse_did_key,
                                 now=env["protected"]["created"]) == env["payload"]
    assert idenv.seen_from_checkpoint(a.previous_checkpoint) == env["protected"]["seen"]
    header = sealed.InnerHeader(from_kid=env["protected"]["kid"], to_kid=env["payload"]["to_kid"],
                                envelope_nonce=env["protected"]["nonce"])
    assert header.canonical_bytes() == a.header_bytes
    assert sealed.ciphertext_metadata(a.ciphertext)["ct_hash"] == env["payload"]["ct_hash"]


def test_aics_identity_envelope_hash_is_the_a1_hash(a):
    from aics_identity import envelope as idenv

    assert idenv.envelope_hash(spec.strict_json(a.envelope_bytes)) == a.inline["envelope_hash"]


def test_aics_identity_opens_the_a4_ciphertext(a):
    from aics_identity import sealed

    env = spec.strict_json(a.envelope_bytes)
    msg = sealed.open_sealed(a.ciphertext, X["bob"], envelope=env, recipient_kid=env["payload"]["to_kid"])
    assert msg.body == b"hello\n"


# ---------------------------------------------------------------------------
# aics-tlog
# ---------------------------------------------------------------------------


def test_aics_tlog_against_a2_and_a3(a):
    from aics_tlog import (Checkpoint, MerkleTree, TileWriter, cosignature_vkey, format_vkey, leaf_hash,
                           parse_checkpoint, parse_note, parse_vkey, sign_checkpoint, sign_cosignature,
                           verify_checkpoint, verify_consistency, verify_inclusion, vkey_from_ed25519)
    from aics_tlog.cosign import cosignature_message

    entries = [spec.J(e) for e in a.entries]
    tree = MerkleTree(entries)
    assert [leaf_hash(e).hex() for e in entries] == a.leaf_hashes and tree.root().hex() == a.root
    assert tree.inclusion_proof(3) == proof(a.inclusion_proof)
    assert tree.consistency_proof(3, 4) == proof(a.consistency_proof)
    assert verify_inclusion(leaf_hash(a.entry_bytes), 3, 4, proof(a.inclusion_proof), tree.root())
    assert verify_consistency(3, 4, tree.root(3), tree.root(), proof(a.consistency_proof))
    assert format_vkey(vkey_from_ed25519(ORIGIN, KEY["log"].public_key())) == a.inline["log_vkey"]
    assert format_vkey(cosignature_vkey(WITNESS_NAME, KEY["witness"].public_key())) == a.inline["witness_vkey"]
    cp = parse_checkpoint(parse_note(a.checkpoint).text)
    assert (cp.origin, cp.size, cp.root.hex()) == (ORIGIN, 4, a.root)
    assert sign_checkpoint(Checkpoint(ORIGIN, 4, tree.root()), KEY["log"], ORIGIN).to_bytes() == log_only(a.checkpoint)
    _, sig = sign_cosignature(KEY["witness"], WITNESS_NAME, COSIGNED_AT, ORIGIN, 4, tree.root())
    assert f"{spec.EM_DASH} {sig.name} {spec.B64(sig.key_id + sig.signature)}" == lines_of(a.checkpoint)[1]
    assert cosignature_message(COSIGNED_AT, ORIGIN, 4, tree.root()) == a.cosign_input
    res = verify_checkpoint(parse_note(a.checkpoint), parse_vkey(a.inline["log_vkey"]),
                            [parse_vkey(a.inline["witness_vkey"])], 1, expected_origin=ORIGIN, now=COSIGNED_AT + 10,
                            max_age_seconds=300, max_future_seconds=30)
    assert res.ok and res.timestamps == {WITNESS_NAME: COSIGNED_AT}
    bundle = TileWriter(entries).materialise()["tile/entries/000.p/4"]
    assert bundle == spec.entry_bundle(entries)
    assert bundle[-len(a.entry_bytes) - 2:-len(a.entry_bytes)].hex() == a.inline["entry_record_prefix"]


def test_aics_tlog_bundle_for_the_a2_dm(a):
    from aics_tlog import Bundle, parse_vkey, verify_bundle

    env = spec.strict_json(a.envelope_bytes)
    b = Bundle(a.entry_bytes, 3, tuple(proof(a.inclusion_proof)), a.checkpoint.decode(), env, a.ciphertext)
    res = verify_bundle(Bundle.from_json(b.to_json()), parse_vkey(a.inline["log_vkey"]),
                        [parse_vkey(a.inline["witness_vkey"])], 1)
    assert res.ok and res.body_bound_at == "$.payload.ct_hash"


# ---------------------------------------------------------------------------
# aics-witness
# ---------------------------------------------------------------------------


def test_aics_witness_reproduces_the_a3_cosignatures(a, tmp_path):
    from aics_witness.config import LogConfig
    from aics_witness.feeder import merge_cosignatures
    from aics_witness.protocol import format_add_checkpoint_request
    from aics_witness.service import Witness
    from aics_witness.store import WitnessStore

    clock = world.Clock(EPOCH)
    store = WitnessStore(tmp_path / "witness.db", create=True)
    w = Witness(WITNESS_NAME, KEY["witness"], store, [LogConfig.from_strings(ORIGIN, [a.inline["log_vkey"]])],
                clock=clock)
    assert w.vkey_text == a.inline["witness_vkey"]
    line3 = w.add_checkpoint(format_add_checkpoint_request(0, [], log_only(a.previous_checkpoint))).decode()
    assert line3.rstrip("\n") == lines_of(a.previous_checkpoint)[1]
    clock.t = COSIGNED_AT
    req = format_add_checkpoint_request(3, proof(a.consistency_proof), log_only(a.checkpoint))
    line4 = w.add_checkpoint(req).decode()
    assert line4.rstrip("\n") == lines_of(a.checkpoint)[1]
    assert merge_cosignatures(log_only(a.checkpoint), line4) == a.checkpoint
    store.close()


# ---------------------------------------------------------------------------
# aics (the CLI)
# ---------------------------------------------------------------------------


def test_aics_verifies_the_a3_notes_and_their_continuity(a, tmp_path):
    cli = drivers.AicsCli(home=tmp_path / "home", now=COSIGNED_AT + 10)
    r = cli.pin(spec.readme_block(spec.J(appendix_a.trust_bundle_dict())), witnesses=[a.inline["witness_vkey"]],
                quorum=1, prefix="https://log.example/aics-1/")
    assert r.code == 0, r.data
    (tmp_path / "a3.note").write_bytes(a.checkpoint)
    (tmp_path / "a3-previous.note").write_bytes(a.previous_checkpoint)
    r = cli.run("verify", "checkpoint", "--note", str(tmp_path / "a3.note"), "--no-save")
    assert (r.code, r.data["size"], r.data["fresh_cosignatures"]) == (0, 4, 1), r.data
    assert r.data["note_sha256"] == a.inline["checkpoint_hash"]
    (tmp_path / "proof.b64").write_text("".join(h + "\n" for h in a.consistency_proof))
    r = cli.run("gossip-check", str(tmp_path / "a3-previous.note"), str(tmp_path / "a3.note"), "--offline",
                "--proof", str(tmp_path / "proof.b64"))
    assert (r.code, r.data["relation"]["status"]) == (0, "consistent"), r.data


# ---------------------------------------------------------------------------
# aics-conformance
# ---------------------------------------------------------------------------


def test_aics_conformance_against_appendix_a(a):
    from aics_conformance import protocol, verify

    p = policy(a)
    hist = verify.History([spec.J(e) for e in a.entries], p)
    assert [e["type"] for e in hist.entries] == ["policy", "name.claim", "name.claim", "dm"]
    assert hist.used == {2: 1}  # Bob's initial grant (leaf 2) consumed by the DM
    new = verify.head(a.checkpoint, p, COSIGNED_AT + 10)
    old = verify.head(a.previous_checkpoint, p, EPOCH + 10, historical=True)
    assert new.timestamps == {WITNESS_NAME: COSIGNED_AT}
    verify.continuity(old, new, [spec.J(e) for e in a.entries])
    env = spec.strict_json(a.envelope_bytes)
    protocol.verify_signature(env)
    assert protocol.open_message(env, a.ciphertext, PrivateKey(X["bob"])) == b"hello\n"
    wire = spec.wire_bundle(a.entry_bytes, 3, proof(a.inclusion_proof), a.checkpoint, env, a.ciphertext)
    _, entry = verify.bundle(wire, p, COSIGNED_AT + 10, prefix=[spec.J(e) for e in a.entries])
    assert spec.J(entry) == a.entry_bytes
    spec.verify_wire_bundle(wire, a.inline["log_vkey"], [a.inline["witness_vkey"]], 1)


def test_aics_conformance_rejects_a_changed_inner_header(a):
    """A.4: changing one identifier after decryption invalidates the inner binding."""
    from aics_conformance import protocol

    env = spec.strict_json(a.envelope_bytes)
    for field in ("from_kid", "to_kid", "envelope_nonce"):
        h = spec.strict_json(a.header_bytes)
        h[field] = spec.kid(KEY["owner"]) if field != "envelope_nonce" else spec.U64(bytes(16))
        ct = spec.deterministic_seal(spec.aics1_plaintext(spec.J(h), b"hello\n"), spec.x25519_public(X["bob"]),
                                     X["ephemeral"])
        q = {**env["payload"], "ct_hash": spec.hexH(ct), "size": len(ct)}
        e = spec.native_envelope(KEY["alice"], origin=ORIGIN, typ="dm", payload=q, created=EPOCH + 1,
                                 nonce=env["protected"]["nonce"], seq=1, prev=env["protected"]["prev"],
                                 seen=env["protected"]["seen"])
        with pytest.raises(ValueError, match="inner-header binding mismatch"):
            protocol.open_message(e, ct, PrivateKey(X["bob"]))

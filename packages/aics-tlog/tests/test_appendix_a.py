"""AICS-1 Appendix A, byte for byte: the size-4 example log, its notes and a
§14.3 wire bundle for the DM at index 3, built here with the standard library
only (not with aics_tlog's encoders) and verified with aics_tlog.

The values are copied from docs/spec/AICS-1.md Appendix A (A.1 envelope, A.2
entry and proofs, A.3 notes and vkeys, A.4 ciphertext); the asserted digests
are the ones the appendix states.  Strings are ASCII-escaped so that no
editor can normalize the notes' U+2014 dashes.
"""

import base64
import hashlib
import json
import subprocess
import sys

import pytest

from aics_tlog import (
    Bundle,
    WitnessPolicy,
    leaf_hash,
    parse_checkpoint,
    parse_note,
    parse_vkey,
    verify_bundle,
    verify_checkpoint,
    verify_consistency,
    verify_inclusion,
)

ENVELOPE_JCS = (
    "{\"auth\":{\"scheme\":\"ed25519-jcs\"},\"payload\":{\"ct_hash\":\"9393a026bf96bcec00a4531b3d7facf87ce9a1abe"
    "8b0eb906cfc364012122be4\",\"encryption\":\"x25519-xsalsa20-poly1305\",\"eph_pk\":\"V9tLNZ8jrl4Ubk4lEgVnB"
    "HIlBjSMFQwUdT0Mkz0E1CE\",\"grant_index\":2,\"prev\":\"96cdd0a2b2996c5d6a963f221a3e23d1b83d3315083b29ec"
    "dc2f056f15022d30\",\"seq\":1,\"size\":239,\"to_key_leaf_index\":2,\"to_kid\":\"did:key:z6MkmtWtY63GQVBrpMy"
    "RJWEzsnxfsGkemu6CtMDwGTv4RYj2\"},\"protected\":{\"alg\":\"EdDSA\",\"created\":1792281601,\"expires\":179228"
    "1901,\"kid\":\"did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX\",\"nonce\":\"MDEyMzQ1Njc4OTo7P"
    "D0-Pw\",\"origin\":\"log.example/aics-1\",\"prev\":\"96cdd0a2b2996c5d6a963f221a3e23d1b83d3315083b29ecdc2"
    "f056f15022d30\",\"seen\":{\"checkpoint_note_hash\":\"5b94d66c1e45e26995cdc8e3ecbcf70d037af0b15ebb1db73"
    "1b85774a072d535\",\"size\":3},\"seq\":1,\"type\":\"dm\"},\"sig\":\"F_I8EDzPhZYADcZxwnDeFRj0wcv3CgWQrCTxnfQgU"
    "qDFH93L0NYUREzNMUw3A02slHsYP9nQnlNFQhfldIxLDQ\",\"v\":1}"
)
ENTRY_JCS = (
    "{\"actor_kid\":\"did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX\",\"origin\":\"log.example/ai"
    "cs-1\",\"payload\":{\"ct_hash\":\"9393a026bf96bcec00a4531b3d7facf87ce9a1abe8b0eb906cfc364012122be4\",\"e"
    "ncryption\":\"x25519-xsalsa20-poly1305\",\"envelope\":{\"auth\":{\"scheme\":\"ed25519-jcs\"},\"payload\":{\"ct"
    "_hash\":\"9393a026bf96bcec00a4531b3d7facf87ce9a1abe8b0eb906cfc364012122be4\",\"encryption\":\"x25519-x"
    "salsa20-poly1305\",\"eph_pk\":\"V9tLNZ8jrl4Ubk4lEgVnBHIlBjSMFQwUdT0Mkz0E1CE\",\"grant_index\":2,\"prev\":"
    "\"96cdd0a2b2996c5d6a963f221a3e23d1b83d3315083b29ecdc2f056f15022d30\",\"seq\":1,\"size\":239,\"to_key_le"
    "af_index\":2,\"to_kid\":\"did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2\"},\"protected\":{\"a"
    "lg\":\"EdDSA\",\"created\":1792281601,\"expires\":1792281901,\"kid\":\"did:key:z6Mkon3Necd6NkkyfoGoHxid2zn"
    "Gc59LU3K7mubaRcFbLfLX\",\"nonce\":\"MDEyMzQ1Njc4OTo7PD0-Pw\",\"origin\":\"log.example/aics-1\",\"prev\":\"96"
    "cdd0a2b2996c5d6a963f221a3e23d1b83d3315083b29ecdc2f056f15022d30\",\"seen\":{\"checkpoint_note_hash\":\""
    "5b94d66c1e45e26995cdc8e3ecbcf70d037af0b15ebb1db731b85774a072d535\",\"size\":3},\"seq\":1,\"type\":\"dm\"}"
    ",\"sig\":\"F_I8EDzPhZYADcZxwnDeFRj0wcv3CgWQrCTxnfQgUqDFH93L0NYUREzNMUw3A02slHsYP9nQnlNFQhfldIxLDQ\","
    "\"v\":1},\"eph_pk\":\"V9tLNZ8jrl4Ubk4lEgVnBHIlBjSMFQwUdT0Mkz0E1CE\",\"grant_index\":2,\"prev\":\"96cdd0a2b2"
    "996c5d6a963f221a3e23d1b83d3315083b29ecdc2f056f15022d30\",\"seq\":1,\"size\":239,\"to_key_leaf_index\":2"
    ",\"to_kid\":\"did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2\"},\"ts\":1792281601,\"type\":\"dm"
    "\",\"v\":2}"
)
INCLUSION_PROOF_3_4 = ["8Hp/k6E0nK5+HkFPPXnFUerg4h7QhSIjYDEW6kfsPNo=", "y9NuiypL6RwuQc5Ts2KHM86HZVy/ExlQ/HUreOPopCM="]
CONSISTENCY_PROOF_3_4 = ["8Hp/k6E0nK5+HkFPPXnFUerg4h7QhSIjYDEW6kfsPNo=", "6/b86KfvZNX8TUaUzBzmrx6MIqXalm+cS5BUp4toer4=", "y9NuiypL6RwuQc5Ts2KHM86HZVy/ExlQ/HUreOPopCM="]
NOTE_4 = (
    "log.example/aics-1\n4\nPPj+PEGLKQS5SGjh1C/GODYYecZdTrZD+FAUHMo+D08=\n\n\u2014 log.example/aics-1 00yuure2"
    "ZQ6O5z/3k7e+i2S3Y979UmSp7r4qaYHPvqBP4BMNR+mA6JoB+q8rX6guXSK8vixUDBwideb99sR+qrLXag8=\n\u2014 witness.e"
    "xample/w1 w8FJnQAAAABq1AwCrysUqRktYIWXtKxrgID5XAxPe4TSDCPcPbjy4pLeABOPTgKgeybY8Pjj9DNiWKxTjgrl0w"
    "VdWqYT4hTtMxKEAw==\n"
)
NOTE_3 = (
    "log.example/aics-1\n3\nl8Lavw2FapIGVNaC1b79k5ZTKgdbKcP6yMe3MvODz7s=\n\n\u2014 log.example/aics-1 00yuulrc"
    "q6B1jBGE330RL5IqSDwmbaWPG6AF4jNqqlYX3aanb2xVQxuZImRCKNRIL57y2epg3ZqAo75R0YrIyjM3eAE=\n\u2014 witness.e"
    "xample/w1 w8FJnQAAAABq1AwAign7qPOXfnZHHHA8ayI3E+WMoFUVUGX8E32/X75FJGyvzpXoWVW72JAA0bPuVicV/GH+Gq"
    "f78fiDM7ANXCLgAg==\n"
)
CIPHERTEXT_HEX = (
    "57db4b359f23ae5e146e4e2512056704722506348c150c14753d0c933d04d42129a18ca43412b3e9a2e4b05662f0dbc1"
    "0e169e82ef191618f240e375adad71c6c2f43cdafe18548e96e3045c9b1c7fc4d9c92233f38cf1c248f82592e1b86786"
    "b9adafe532397f5bf9698070a128b51dabd52a4cd138efd0360b881ae8f7b3323872d42228a6dfef085b2fa9891b5376"
    "a882a017b622beef0b4ff250a2687b1885769244c32285a0eb979366dfd4d8a656b072757082f1475d6726c30e0a2ad8"
    "d17e072cf677688c84d970ba8235e058d26bca1c2c11a62203fb83fa67620ef8d5c4b437ae0e2943509920ba04428a"
)
LOG_VKEY = "log.example/aics-1+d34caeba+AYE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU"
WITNESS_VKEY = "witness.example/w1+c3c1499d+BIqHX/8es4RRV3rNWv7kBUVlaN18ieCQhjoFV7x69J8X"
COSIGNED_AT = 1792281602  # A.3: the witness timestamp


def u64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


@pytest.fixture(scope="module")
def wire():
    """The §14.3 wire bundle for A.2's entry 3, assembled independently."""
    return {
        "entry_bytes": u64(ENTRY_JCS.encode()),
        "index": 3,
        "inclusion_proof": INCLUSION_PROOF_3_4,
        "checkpoint_note": u64(NOTE_4.encode()),
        "envelope": json.loads(ENVELOPE_JCS),
        "body_or_ct": u64(bytes.fromhex(CIPHERTEXT_HEX)),
    }


def test_the_copied_values_are_the_appendix_values():
    assert len(ENTRY_JCS.encode()) == 1448
    assert leaf_hash(ENTRY_JCS.encode()).hex() == "ebf6fce8a7ef64d5fc4d4694cc1ce6af1e8c22a5da966f9c4b9054a78b687abe"
    assert hashlib.sha256(ENVELOPE_JCS.encode()).hexdigest() == (
        "6fcbe0486d4169e7ae2d771792f5735f5642d260e2bafa4d6124dc355e159ba4")
    assert hashlib.sha256(NOTE_4.encode()).hexdigest() == (
        "fb2b18a043a1dffea3b70a4ddac14364c44701937557a40dcdbdd64fe8e59e70")
    ct = bytes.fromhex(CIPHERTEXT_HEX)
    assert len(ct) == 239 and hashlib.sha256(ct).hexdigest() == (
        "9393a026bf96bcec00a4531b3d7facf87ce9a1abe8b0eb906cfc364012122be4")
    # the envelope's seen pointer is the hash of the complete size-3 note bytes
    seen = json.loads(ENVELOPE_JCS)["protected"]["seen"]
    assert seen == {"checkpoint_note_hash": hashlib.sha256(NOTE_3.encode()).hexdigest(), "size": 3}


def test_a3_checkpoints_inclusion_and_consistency():
    log, wit = parse_vkey(LOG_VKEY), parse_vkey(WITNESS_VKEY)
    res = verify_checkpoint(parse_note(NOTE_4), log, [wit], 1, expected_origin="log.example/aics-1",
                            now=COSIGNED_AT + 10, max_age_seconds=300)
    assert res.ok and res.size == 4 and res.timestamps == {"witness.example/w1": COSIGNED_AT}
    root4 = parse_checkpoint(parse_note(NOTE_4).text).root
    root3 = parse_checkpoint(parse_note(NOTE_3).text).root
    assert root4.hex() == "3cf8fe3c418b2904b94868e1d42fc638361879c65d4eb643f850141cca3e0f4f"
    proof = [base64.b64decode(h) for h in INCLUSION_PROOF_3_4]
    assert verify_inclusion(leaf_hash(ENTRY_JCS.encode()), 3, 4, proof, root4)
    cons = [base64.b64decode(h) for h in CONSISTENCY_PROOF_3_4]
    assert verify_consistency(3, 4, root3, root4, cons)
    assert not verify_consistency(3, 4, root4, root4, cons)


def test_the_wire_bundle_verifies(wire):
    policy = WitnessPolicy(1, (parse_vkey(WITNESS_VKEY),))
    for given in (wire, Bundle.from_dict(wire), json.dumps(wire)):
        res = verify_bundle(given, parse_vkey(LOG_VKEY), policy=policy)
        assert res.ok, res.error
        assert res.aics1_entry and res.index == 3 and res.size == 4
        assert (res.envelope_bound_at, res.body_bound_at) == ("$.payload.envelope", "$.payload.ct_hash")
    b = Bundle.from_dict(wire)
    assert b.to_dict() == wire  # aics_tlog writes exactly these bytes
    assert b.checkpoint_note == NOTE_4 and b.body_or_ct == bytes.fromhex(CIPHERTEXT_HEX)


@pytest.mark.parametrize("member, value, message", [
    ("envelope", "sig", "differs from the envelope embedded"),
    ("body_or_ct", u64(b"tampered body"), "body_or_ct"),
    ("index", 2, "inclusion"),
    ("inclusion_proof", [base64.b64encode(bytes(32)).decode(), INCLUSION_PROOF_3_4[1]], "inclusion"),
])
def test_tampered_wire_bundles_are_refused(wire, member, value, message):
    tampered = dict(wire)
    if member == "envelope":
        tampered["envelope"] = {**wire["envelope"], "sig": u64(bytes(64))}
    else:
        tampered[member] = value
    res = verify_bundle(tampered, parse_vkey(LOG_VKEY))
    assert not res.ok and message in res.error, res.error


def test_cli_verifies_the_wire_bundle_offline(wire, tmp_path):
    path = tmp_path / "a2-dm.json"
    path.write_text(json.dumps(wire))
    r = subprocess.run(
        [sys.executable, "-m", "aics_tlog", "verify-bundle", "--bundle", str(path), "--log-key", LOG_VKEY,
         "--offline", "--witness-key", WITNESS_VKEY, "--quorum", "1"],
        check=False, capture_output=True, text=True, timeout=120,
    )
    out = json.loads(r.stdout)
    assert r.returncode == 0 and out["ok"], r.stdout + r.stderr
    assert out["aics1_entry"] is True and out["body"] == "$.payload.ct_hash" and out["cosignatures"] == 1

"""Offline bundles: the AICS-1 §14.3 wire form, verification, and the bindings.

Wire encodings are checked against independent stdlib encoders here (not the
module's own), and against the AICS-1 Appendix A bytes in test_appendix_a.py.
"""

import base64
import hashlib
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog.bundle import (
    BUNDLE_FIELDS,
    Bundle,
    bundle_from_tiles,
    canonical_json,
    u64_decode,
    u64_encode,
    verify_bundle,
)
from aics_tlog.checkpoint import Checkpoint, WitnessPolicy, sign_checkpoint
from aics_tlog.cosign import cosignature_vkey, sign_cosignature
from aics_tlog.note import Note, b64_encode, vkey_from_ed25519
from aics_tlog.verified import VerifiedTileReader
from aics_tlog.writer import IncrementalTileWriter, MemoryTileStore

from conftest import flip_bit

ORIGIN = "wesupport-ai.example/tlog/v2"
CT = b"\x93" + bytes(range(200))  # stand-in ciphertext; its base64url has '-' and '_'
BODY = json.dumps({"channel": "general", "text": "hello", "title": "first"}, sort_keys=True,
                  separators=(",", ":")).encode()
KID = "did:key:z6MkAgent"


def H(b):
    return hashlib.sha256(b).hexdigest()


def U(b):
    """Independent U64: unpadded base64url."""
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def J(x):
    """JCS for these ASCII, integer-only test objects."""
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def envelope(typ, q, *, seq=0, auth=None, sig="c2lnbmF0dXJl"):
    return {
        "v": 1,
        "protected": {"alg": "EdDSA", "origin": ORIGIN, "type": typ, "kid": KID, "created": 1800000000,
                      "expires": 1800000300, "nonce": "MDEyMzQ1Njc4OTo7PD0-Pw", "seq": seq, "prev": None,
                      "seen": None},
        "payload": q,
        "auth": auth or {"scheme": "ed25519-jcs"},
        "sig": sig,
    }


DM_Q = {"to_kid": "did:key:z6MkPeer", "to_key_leaf_index": 2, "encryption": "x25519-xsalsa20-poly1305",
        "eph_pk": U(CT[:32]), "ct_hash": H(CT), "size": len(CT), "seq": 4,
        "prev": H(b"previous envelope"), "grant_index": 2}
ENVELOPE = envelope("dm", DM_Q, seq=4)
POST_Q = {"channel_sha256": H(b"general"), "parent_index": None, "body_hash": H(BODY), "size": len(BODY),
          "title_sha256": H(b"first")}
POST_ENVELOPE = envelope("post", POST_Q)


def aics_entry(i, env, **extra_payload):
    """An AICS-1 entry v2: payload = envelope + an exact copy of its payload (§5.1)."""
    return J({"v": 2, "origin": ORIGIN, "type": env["protected"]["type"], "actor_kid": env["protected"]["kid"],
              "ts": 1800000000 + i, "payload": {"envelope": env, **env["payload"], **extra_payload}})


def leaf(i, payload):
    """An entry that embeds no envelope (bundles for it use the generic bindings)."""
    return J({"v": 2, "origin": ORIGIN, "type": "dm", "actor_kid": KID, "ts": 1800000000 + i, "payload": payload})


def make_log(entries, *, cosign_time=None):
    log = Ed25519PrivateKey.generate()
    wit = Ed25519PrivateKey.generate()
    store = MemoryTileStore()
    writer = IncrementalTileWriter(store)
    writer.append(entries)
    cp = Checkpoint(ORIGIN, writer.size, writer.root())
    note = sign_checkpoint(cp, log, ORIGIN)
    t = int(time.time()) if cosign_time is None else cosign_time
    _, cosig = sign_cosignature(wit, "wit.example/w1", t, ORIGIN, cp.size, cp.root)
    note = Note(note.text, (cosig, note.signatures[0]))
    return {
        "store": store,
        "note": note,
        "cp": cp,
        "entries": list(entries),
        "log_key": vkey_from_ed25519(ORIGIN, log.public_key()),
        "wit_key": cosignature_vkey("wit.example/w1", wit.public_key()),
        "other_key": vkey_from_ed25519(ORIGIN, Ed25519PrivateKey.generate().public_key()),
    }


@pytest.fixture(scope="module")
def dm_log():
    entries = [leaf(i, {"note": f"filler {i}"}) for i in range(700)]
    entries[523] = aics_entry(523, ENVELOPE)
    entries[600] = leaf(600, {"envelope_sha256": H(canonical_json(ENVELOPE))})
    entries[610] = leaf(610, {"prev": H(b"previous envelope")})
    entries[650] = aics_entry(650, POST_ENVELOPE)
    return make_log(entries)


def build(log, index, **kw):
    vr = VerifiedTileReader(log["store"], log["cp"].size, log["cp"].root)
    return bundle_from_tiles(vr, index, log["note"], **kw)


def one_entry_log(entry):
    log = make_log([entry])
    return log, build(log, 0)


# --- the wire form -----------------------------------------------------------------


def test_wire_form_members_and_encodings(dm_log):
    b = build(dm_log, 523, envelope=ENVELOPE, body_or_ct=CT)
    obj = json.loads(b.to_json())
    assert BUNDLE_FIELDS == ("entry_bytes", "index", "inclusion_proof", "checkpoint_note", "envelope", "body_or_ct")
    assert tuple(obj) == BUNDLE_FIELDS
    assert obj["entry_bytes"] == U(dm_log["entries"][523])
    assert obj["index"] == 523
    assert obj["inclusion_proof"] == [base64.b64encode(h).decode() for h in b.inclusion_proof]  # B64, padded
    # U64 of the complete signed note: text, blank line, every signature line, final LF
    assert obj["checkpoint_note"] == U(dm_log["note"].to_bytes())
    note_u64 = obj["checkpoint_note"]
    assert base64.urlsafe_b64decode(note_u64 + "=" * (-len(note_u64) % 4)) == dm_log["note"].to_bytes()
    assert dm_log["note"].to_bytes().endswith(b"\n")
    assert obj["envelope"] == ENVELOPE
    assert obj["body_or_ct"] == U(CT)
    for member in ("entry_bytes", "checkpoint_note", "body_or_ct"):
        assert not set(obj[member]) & set("+/=")
    assert {"-", "_"} <= set(obj["body_or_ct"])  # the alphabet really is base64url
    # round trips: object, JSON text, and the dataclass's decoded attributes
    assert Bundle.from_json(b.to_json()) == b == Bundle.from_dict(obj)
    assert b.checkpoint_note == dm_log["note"].serialise() and b.body_or_ct == CT


def test_bundle_from_tiles_carries_the_embedded_envelope(dm_log):
    b = build(dm_log, 523)
    assert b.envelope == ENVELOPE  # §14.3: envelope is the entry's E
    assert verify_bundle(b, dm_log["log_key"]).ok
    filler = build(dm_log, 1)
    assert filler.envelope is None and filler.to_dict()["envelope"] is None and filler.to_dict()["body_or_ct"] is None
    assert Bundle.from_json(filler.to_json()) == filler


def test_verify_accepts_the_wire_form_directly(dm_log):
    b = build(dm_log, 523, body_or_ct=CT)
    for given in (b.to_dict(), b.to_json(), b.to_json().encode()):
        res = verify_bundle(given, dm_log["log_key"])
        assert res.ok and res.body_bound_at == "$.payload.ct_hash", res.error
    res = verify_bundle({**b.to_dict(), "entry_bytes_b64": "x"}, dm_log["log_key"])
    assert not res.ok and "wire bundle" in res.error
    assert not verify_bundle("{", dm_log["log_key"]).ok


def test_the_pre_0_2_form_is_refused(dm_log):
    b = build(dm_log, 523, body_or_ct=CT)
    legacy = {"entry_bytes_b64": base64.b64encode(b.entry_bytes).decode(), "index": b.index,
              "inclusion_proof": [base64.b64encode(h).decode() for h in b.inclusion_proof],
              "checkpoint_note": b.checkpoint_note, "envelope": b.envelope,
              "body_or_ct": base64.b64encode(CT).decode()}
    with pytest.raises(ValueError, match="pre-0.2"):
        Bundle.from_dict(legacy)
    # the same values with the wire names but the old encodings
    with pytest.raises(ValueError):
        Bundle.from_dict({**b.to_dict(), "checkpoint_note": b.checkpoint_note})
    with pytest.raises(ValueError):
        Bundle.from_dict({**b.to_dict(), "body_or_ct": base64.b64encode(CT).decode()})


@pytest.mark.parametrize(
    "patch",
    [
        {"entry_bytes": None},
        {"entry_bytes": 5},
        {"entry_bytes": "YQ=="},             # padded
        {"entry_bytes": "YR"},               # non-canonical trailing bits
        {"entry_bytes": "Y"},                # impossible length
        {"entry_bytes": "a+b/"},             # standard alphabet
        {"entry_bytes": U(b"x" * 70000)},    # beyond the tlog-tiles entry limit
        {"index": True},
        {"index": -1},
        {"index": "3"},
        {"index": 3.0},
        {"index": 2**53},
        {"inclusion_proof": "x"},
        {"inclusion_proof": ["AAAA"]},
        {"inclusion_proof": [U(bytes(32))]},  # U64 where §14.3 has B64
        {"inclusion_proof": [b64_encode(bytes(32))] * 65},
        {"checkpoint_note": ""},
        {"checkpoint_note": None},
        {"checkpoint_note": "garbage note text"},  # not U64
        {"checkpoint_note": U(b"\xff\xfe")},       # not UTF-8
        {"body_or_ct": 5},
        {"body_or_ct": base64.b64encode(b"tampered body").decode()},  # padded B64
        {"envelope": 1},
        {"envelope": {}},
        {"envelope": [1]},
        {"log_key": "attacker+00000000+AAAA"},     # a member §14.3 does not define
    ],
)
def test_strict_parsing(dm_log, patch):
    obj = build(dm_log, 1).to_dict()
    obj.update(patch)
    for name, value in patch.items():
        if value is None and name in ("entry_bytes", "checkpoint_note"):
            del obj[name]
    with pytest.raises(ValueError):
        Bundle.from_dict(obj)


@pytest.mark.parametrize(
    "text",
    [
        "[1, 2]",
        "{",
        b"\xff",
        '{"entry_bytes": "", "entry_bytes": ""}',  # duplicate member names
        '{"index": NaN}',
        "[" * 100 + "]" * 100,
    ],
)
def test_strict_json(text):
    with pytest.raises(ValueError):
        Bundle.from_json(text)


def test_u64_codec():
    # RFC 4648 §10 vectors, unpadded, plus the two base64url-only characters
    for raw, text in [(b"", ""), (b"f", "Zg"), (b"fo", "Zm8"), (b"foo", "Zm9v"), (b"foob", "Zm9vYg"),
                      (b"fooba", "Zm9vYmE"), (b"foobar", "Zm9vYmFy"), (b"\xfb\xff", "-_8")]:
        assert u64_encode(raw) == text and u64_decode(text) == raw
    for bad in ("Zg==", "Zg=", "Z", "Zh", "+/8", " Zg", "Zg\n", 7, None, b"Zg"):
        with pytest.raises(ValueError):
            u64_decode(bad)


# --- AICS-1 entries (§5.1, §14.3 steps 1 and 4) --------------------------------------


def test_verify_dm_bundle_with_envelope_and_ciphertext(dm_log):
    b = build(dm_log, 523, envelope=ENVELOPE, body_or_ct=CT)
    res = verify_bundle(b, dm_log["log_key"])
    assert res.ok, res.error
    assert res.aics1_entry
    assert res.index == 523 and res.size == 700 and res.origin == ORIGIN
    assert res.envelope_bound_at == "$.payload.envelope"
    assert res.body_bound_at == "$.payload.ct_hash"
    assert res.leaf_hash == hashlib.sha256(b"\x00" + b.entry_bytes).digest()
    assert any("not checked" in n for n in res.notes)
    # witness quorum offline
    assert verify_bundle(b, dm_log["log_key"], [dm_log["wit_key"]], 1).ok
    # an entry-only bundle of a log entry that embeds no envelope
    res = verify_bundle(build(dm_log, 0), dm_log["log_key"])
    assert res.ok and not res.aics1_entry and any("inclusion only" in n for n in res.notes)


def test_post_body_binds_by_body_hash_and_size(dm_log):
    res = verify_bundle(build(dm_log, 650, body_or_ct=BODY), dm_log["log_key"])
    assert res.ok and res.body_bound_at == "$.payload.body_hash", res.error
    # title_sha256 is a hash field, but it commits to the title, not the body
    res = verify_bundle(build(dm_log, 650, body_or_ct=b"first"), dm_log["log_key"])
    assert not res.ok and "body_or_ct" in res.error and "body_hash" in res.error
    # the DM's ciphertext is not this post's body
    res = verify_bundle(build(dm_log, 650, body_or_ct=CT), dm_log["log_key"])
    assert not res.ok and "body_or_ct" in res.error


def test_body_size_must_match():
    q = {**POST_Q, "size": len(BODY) + 1}
    log, b = one_entry_log(aics_entry(0, envelope("post", q)))
    res = verify_bundle(Bundle(b.entry_bytes, 0, b.inclusion_proof, b.checkpoint_note, b.envelope, BODY),
                        log["log_key"])
    assert not res.ok and "size" in res.error and "body_or_ct" in res.error
    assert verify_bundle(b, log["log_key"]).ok  # without the body, the metadata still verifies


def test_body_needs_a_body_commitment():
    q = {"name_norm": "ada", "prev_event_index": None, "ed25519": U(bytes(32)), "x25519": U(bytes(32)),
         "tier": "verified", "recovery_kid": None, "recovery_pop": None, "initial_grant": None}
    log, b = one_entry_log(aics_entry(0, envelope("name.claim", q)))
    assert verify_bundle(b, log["log_key"]).ok
    res = verify_bundle(Bundle(b.entry_bytes, 0, b.inclusion_proof, b.checkpoint_note, b.envelope, b"x"),
                        log["log_key"])
    assert not res.ok and "commits to no body_or_ct" in res.error


def test_the_bundle_envelope_must_equal_the_embedded_one(dm_log):
    b = build(dm_log, 523, body_or_ct=CT)

    def with_envelope(env):
        return verify_bundle(Bundle(b.entry_bytes, b.index, b.inclusion_proof, b.checkpoint_note, env, CT),
                             dm_log["log_key"])

    # the same JSON value: member order and 4 vs 4.0 do not matter (same JCS bytes)
    reordered = dict(reversed(list(ENVELOPE.items())))
    reordered["payload"] = {**DM_Q, "seq": 4.0}
    assert with_envelope(reordered).ok
    for env in ({**ENVELOPE, "sig": "b3RoZXI"},
                {**ENVELOPE, "protected": {**ENVELOPE["protected"], "seq": True}},
                {**ENVELOPE, "payload": {**DM_Q, "ct_hash": H(b"other")}}):
        res = with_envelope(env)
        assert not res.ok and "differs from the envelope embedded" in res.error
    res = with_envelope(None)
    assert not res.ok and "no envelope" in res.error


@pytest.mark.parametrize(
    "entry, message",
    [
        # pretty-printed: the same value, but not its JCS bytes
        (json.dumps(json.loads(aics_entry(0, POST_ENVELOPE)), indent=1).encode(), "JCS"),
        # a member the entry v2 object does not have
        (J({**json.loads(aics_entry(0, POST_ENVELOPE)), "extra": 1}), "entry v2 members"),
        # a payload copy that differs from the signed envelope payload
        (aics_entry(0, POST_ENVELOPE, size=len(BODY) + 1), "exact copy"),
        # a payload member that is no copy at all
        (aics_entry(0, POST_ENVELOPE, attestation="AAAA"), "not copies"),
        # an embedded "envelope" that is not an envelope
        (J({"v": 2, "origin": ORIGIN, "type": "post", "actor_kid": KID, "ts": 1,
            "payload": {"envelope": "E"}}), "envelope object"),
    ],
)
def test_malformed_aics1_entries_are_refused(entry, message):
    log = make_log([entry])
    vr = VerifiedTileReader(log["store"], 1, log["cp"].root)
    env = POST_ENVELOPE
    b = bundle_from_tiles(vr, 0, log["note"], envelope=env)
    res = verify_bundle(b, log["log_key"])
    assert not res.ok and res.aics1_entry and message in res.error, res.error


def test_a_shared_secret_entry_may_carry_its_attestation():
    env = envelope("post", POST_Q, auth={"scheme": "shared-secret"}, sig=None)
    env["protected"] = {**env["protected"], "alg": "none", "kid": "unverified:AAAAAAAAAAAAAAAAAAAAAA"}
    log, b = one_entry_log(aics_entry(0, env, attestation=U(bytes(64))))
    res = verify_bundle(Bundle(b.entry_bytes, 0, b.inclusion_proof, b.checkpoint_note, b.envelope, BODY),
                        log["log_key"])
    assert res.ok and res.body_bound_at == "$.payload.body_hash", res.error


# --- entries that embed no envelope (generic bindings) ----------------------------


def test_envelope_bound_by_hash_and_body_inside_envelope():
    body = b"public post body"
    env = json.loads(json.dumps(ENVELOPE))
    env["payload"]["body_sha256"] = hashlib.sha256(body).hexdigest()
    entries_hash = hashlib.sha256(canonical_json(env)).hexdigest()
    log = make_log([leaf(0, {"envelope_hash": "sha256:" + entries_hash})])
    vr = VerifiedTileReader(log["store"], 1, log["cp"].root)
    b = bundle_from_tiles(vr, 0, log["note"], envelope=env, body_or_ct=body)
    res = verify_bundle(b, log["log_key"])
    assert res.ok, res.error
    assert not res.aics1_entry
    assert res.envelope_bound_at == "$.payload.envelope_hash (sha256 of canonical JSON)"
    assert res.body_bound_at == "envelope.payload.body_sha256"
    # the envelope with a different nonce is not the committed one
    env2 = json.loads(json.dumps(env))
    env2["protected"]["nonce"] = "n-2"
    b2 = Bundle(b.entry_bytes, 0, b.inclusion_proof, b.checkpoint_note, env2, body)
    assert not verify_bundle(b2, log["log_key"]).ok
    # and the bundle round-trips through the wire form
    assert verify_bundle(Bundle.from_json(b.to_json()), log["log_key"]).ok


def test_body_hash_under_a_non_hash_field_does_not_bind(dm_log):
    # entry 610 holds sha256(b"previous envelope") under "prev", which is not
    # a hash-named field, so presenting those bytes as the body fails.
    res = verify_bundle(build(dm_log, 610, body_or_ct=b"previous envelope"), dm_log["log_key"])
    assert not res.ok and "body_or_ct" in res.error
    # in an AICS-1 entry only body_hash / ct_hash / document_hash bind a body
    res = verify_bundle(build(dm_log, 523, body_or_ct=b"previous envelope"), dm_log["log_key"])
    assert not res.ok and "body_or_ct" in res.error


def test_envelope_needs_a_json_entry():
    log = make_log([b"not json at all"])
    vr = VerifiedTileReader(log["store"], 1, log["cp"].root)
    b = bundle_from_tiles(vr, 0, log["note"], envelope={"a": 1})
    res = verify_bundle(b, log["log_key"])
    assert not res.ok and "not JSON" in res.error
    plain = bundle_from_tiles(vr, 0, log["note"])
    assert plain.envelope is None and verify_bundle(plain, log["log_key"]).ok


def test_scalar_envelope_cannot_bind(dm_log):
    b = build(dm_log, 523)
    for env in (2, "dm", {}):
        res = verify_bundle(Bundle(b.entry_bytes, b.index, b.inclusion_proof, b.checkpoint_note, env), dm_log["log_key"])
        assert not res.ok and "non-empty JSON object" in res.error


# --- tampering, keys, freshness -------------------------------------------------------


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda b: Bundle(flip_bit(b.entry_bytes, 30), b.index, b.inclusion_proof, b.checkpoint_note, b.envelope, b.body_or_ct), "inclusion"),
        (lambda b: Bundle(b.entry_bytes, b.index + 1, b.inclusion_proof, b.checkpoint_note, b.envelope, b.body_or_ct), "inclusion"),
        (lambda b: Bundle(b.entry_bytes, 700, b.inclusion_proof, b.checkpoint_note, b.envelope, b.body_or_ct), "not below"),
        (lambda b: Bundle(b.entry_bytes, b.index, (flip_bit(b.inclusion_proof[0], 1), *b.inclusion_proof[1:]), b.checkpoint_note, b.envelope, b.body_or_ct), "inclusion"),
        (lambda b: Bundle(b.entry_bytes, b.index, b.inclusion_proof, b.checkpoint_note, {**b.envelope, "sig": "b3RoZXI="}, b.body_or_ct), "envelope"),
        (lambda b: Bundle(b.entry_bytes, b.index, b.inclusion_proof, b.checkpoint_note, b.envelope, b.body_or_ct + b"!"), "body_or_ct"),
        (lambda b: Bundle(b.entry_bytes, b.index, b.inclusion_proof, "garbage", b.envelope, b.body_or_ct), "signed note"),
        (lambda b: Bundle(b.entry_bytes, b.index, b.inclusion_proof, b.checkpoint_note.replace("\n700\n", "\n701\n"), b.envelope, b.body_or_ct), "checkpoint"),
    ],
)
def test_tampering_is_detected(dm_log, mutate, message):
    good = build(dm_log, 523, envelope=ENVELOPE, body_or_ct=CT)
    res = verify_bundle(mutate(good), dm_log["log_key"])
    assert not res.ok and message in res.error


def test_wrong_key_and_quorum(dm_log):
    b = build(dm_log, 523)
    res = verify_bundle(b, dm_log["other_key"])
    assert not res.ok and "checkpoint" in res.error
    res = verify_bundle(b, dm_log["log_key"], [], 1)
    assert not res.ok and "quorum" in res.error


def test_offline_freshness_only_when_asked():
    log = make_log([leaf(0, {})], cosign_time=int(time.time()) - 30 * 86400)
    vr = VerifiedTileReader(log["store"], 1, log["cp"].root)
    b = bundle_from_tiles(vr, 0, log["note"])
    policy = WitnessPolicy(1, (log["wit_key"],), max_age_seconds=3600)
    assert verify_bundle(b, log["log_key"], policy=policy).ok  # an old bundle stays valid offline
    res = verify_bundle(b, log["log_key"], policy=policy, max_age_seconds=3600)
    assert not res.ok and "stale" in res.error


def test_bundle_from_tiles_checks_index(dm_log):
    vr = VerifiedTileReader(dm_log["store"], 700, dm_log["cp"].root)
    with pytest.raises(ValueError):
        bundle_from_tiles(vr, 700, dm_log["note"])
    with pytest.raises(ValueError):
        bundle_from_tiles(vr, 5, dm_log["note"], entry=b"not the entry")


def test_canonical_json_rfc8785_vectors():
    # RFC 8785 section 3.2.3: properties sorted by UTF-16 code units.
    obj = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\U0001F600": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }
    expected = (
        '{"\\r":"Carriage Return","1":"One","\u0080":"Control",'
        '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",'
        '"\U0001F600":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}'
    )
    assert canonical_json(obj) == expected.encode("utf-8")
    assert canonical_json({"b": [1, True, None, "x\u0001"], "a": 2.0}) == b'{"a":2,"b":[1,true,null,"x\\u0001"]}'
    for bad in (1.5, 2**60, {1: "x"}, object()):
        with pytest.raises(ValueError):
            canonical_json(bad)

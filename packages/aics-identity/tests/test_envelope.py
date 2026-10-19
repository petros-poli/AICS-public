"""AICS-1 section 4 envelopes: structure, native signatures, freshness, replay, the chain, fallback and text schemes."""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from aics_identity import canonicalize, envelope, keys, linesig, sshsig
from aics_identity.envelope import (
    ChainError,
    EnvelopeError,
    ExpiredEnvelope,
    InvalidSignatureError,
    MalformedEnvelope,
    NotYetValidEnvelope,
    ReplayCache,
    ReplayedEnvelope,
    UnknownKeyError,
    UnsupportedScheme,
    chain_breaks,
    check_chain_position,
    check_successor,
    envelope_hash,
    envelope_signing_digest,
    next_chain,
    seen_from_checkpoint,
    sign_envelope,
    validate_seen,
    verify_envelope,
)

ORIGIN = "api.example.test/tiles"
T = 1_792_281_600
NONCE = keys.b64u_encode(bytes(range(16)))
#: a post's Q (AICS-1 section 5.3)
PAYLOAD = {"channel_sha256": "ab" * 32, "parent_index": None, "body_hash": "cd" * 32, "size": 42,
           "title_sha256": None}
HASH_A = "a" * 64
SESSION = keys.b64u_encode(b"gate-session-id!")


def kid_of(key) -> str:
    return keys.did_key(key.public_key())


def make(key, **overrides):
    kwargs = dict(origin=ORIGIN, type="post", created=T, nonce=NONCE)
    kwargs.update(overrides)
    payload = kwargs.pop("payload", PAYLOAD)
    return sign_envelope(payload, key, **kwargs)


def resolver_for(key):
    kid, pub = kid_of(key), key.public_key()
    return lambda k: pub if k == kid else None


def resign(key, env):
    """Re-sign env's protected/payload as they are, bypassing sign_envelope's checks (to test the verifier)."""
    env = copy.deepcopy(env)
    env["sig"] = keys.b64u_encode(key.sign(envelope_signing_digest(env["protected"], env["payload"])))
    return env


def with_protected(key, env, **changes):
    env = copy.deepcopy(env)
    env["protected"].update(changes)
    return resign(key, env)


# ----------------------------------------------------------------------
# registries
# ----------------------------------------------------------------------

def test_registries_are_the_aics1_lists():
    assert len(envelope.ENTRY_TYPES) == len(set(envelope.ENTRY_TYPES)) == 17
    assert len(envelope.SWARMS_ENTRY_TYPES) == 10 and len(set(envelope.SWARMS_PROFILE_TYPES)) == 27
    assert set(envelope.FALLBACK_TYPES) <= set(envelope.ENTRY_TYPES)
    assert envelope.AUTH_SCHEMES == ("ed25519-jcs", "text-ed25519", "text-sshsig", "shared-secret")
    assert envelope.PROTECTED_MEMBERS == ("alg", "origin", "type", "kid", "created", "expires", "nonce", "seq",
                                          "prev", "seen")
    assert set(envelope.TEXT_VERBS) <= set(envelope.ENTRY_TYPES)
    assert envelope.SUP_ENTRY_TYPES == ("sup.task", "sup.credit", "sup.spend")
    assert len(set(envelope.SUP_PROFILE_TYPES)) == 20 and len(set(envelope.ALL_PROFILE_TYPES)) == 30
    assert set(envelope.SWARMS_TEXT_VERBS) == set(envelope.SWARMS_ENTRY_TYPES)
    assert set(envelope.SUP_TEXT_VERBS) == {"sup.spend"}
    verbs = {**envelope.TEXT_VERBS, **envelope.SWARMS_TEXT_VERBS, **envelope.SUP_TEXT_VERBS}
    assert len(set(verbs.values())) == len(verbs)  # one verb per type, never shared


# ----------------------------------------------------------------------
# signing
# ----------------------------------------------------------------------

def test_sign_envelope_emits_a_complete_aics1_envelope(test_key):
    env = make(test_key)
    assert list(env) == ["v", "protected", "payload", "auth", "sig"]
    assert env["v"] == 1 and env["auth"] == {"scheme": "ed25519-jcs"}
    assert env["protected"] == {
        "alg": "EdDSA", "origin": ORIGIN, "type": "post", "kid": kid_of(test_key), "created": T,
        "expires": T + 300, "nonce": NONCE, "seq": 0, "prev": None, "seen": None,
    }
    assert env["payload"] == PAYLOAD
    assert len(keys.u64_decode(env["sig"], length=64)) == 64
    assert envelope.validate_envelope(env) == "ed25519-jcs"


def test_the_signature_is_over_the_native_digest(test_key):
    env = make(test_key)
    digest = hashlib.sha256(canonicalize(env["protected"]) + b"\x2e" + canonicalize(env["payload"])).digest()
    assert envelope_signing_digest(env["protected"], env["payload"]) == digest
    test_key.public_key().verify(keys.u64_decode(env["sig"]), digest)  # the 32-byte digest, not its hex
    assert make(test_key)["sig"] == env["sig"]  # deterministic
    assert make(test_key, nonce=keys.b64u_encode(bytes(16)))["sig"] != env["sig"]


def test_origin_and_type_are_required_bindings(test_key):
    with pytest.raises(TypeError):
        sign_envelope(PAYLOAD, test_key)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        sign_envelope(PAYLOAD, test_key, origin=ORIGIN)  # type: ignore[call-arg]
    a, b = make(test_key), make(test_key, origin="other.example/tiles")
    assert a["sig"] != b["sig"] and make(test_key, type="poll")["sig"] != a["sig"]


def test_kid_is_the_signing_keys_did_key(test_key):
    assert make(test_key, kid=kid_of(test_key))["protected"]["kid"] == kid_of(test_key)
    for wrong in (keys.key_id(test_key.public_key()), kid_of(keys.generate_keypair())):
        with pytest.raises(MalformedEnvelope, match="did:key"):
            make(test_key, kid=wrong)


def test_sign_envelope_defaults(test_key):
    import time

    before = int(time.time())
    a = sign_envelope(PAYLOAD, test_key, origin=ORIGIN, type="post")
    b = sign_envelope(PAYLOAD, test_key, origin=ORIGIN, type="post")
    p = a["protected"]
    assert before <= p["created"] <= int(time.time()) and p["expires"] == p["created"] + 300
    assert envelope.is_canonical_nonce(p["nonce"]) and p["nonce"] != b["protected"]["nonce"]
    assert (p["seq"], p["prev"], p["seen"]) == (0, None, None)
    assert verify_envelope(a, keys.parse_did_key) == PAYLOAD


def test_payload_is_copied(test_key):
    payload = {"x": {"deep": [1, 2]}}
    env = make(test_key, payload=payload, type="report")
    payload["x"]["deep"].append(3)
    assert env["payload"] == {"x": {"deep": [1, 2]}}


@pytest.mark.parametrize("overrides, match", [
    ({"origin": "https://api.example.test/tiles"}, "origin"),
    ({"origin": "api.example.test/tiles/"}, "origin"),
    ({"origin": ""}, "origin"),
    ({"origin": "a b"}, "origin"),
    ({"type": "agora.post.create"}, "entry type"),
    ({"type": "swarm.form"}, "entry type"),
    ({"nonce": "unit-test-nonce"}, "16 bytes"),
    ({"nonce": keys.b64u_encode(bytes(32))}, "16 bytes"),
    ({"expires": T}, "after created"),
    ({"expires": T - 1}, "after created"),
    ({"expires": T + 301}, "exceeds 300"),
    ({"created": -1}, "uint"),
    ({"created": True}, "uint"),
    ({"seq": 0, "prev": HASH_A}, "null when seq is 0"),
    ({"seq": 1}, "64 lowercase hex"),
    ({"seq": 1, "prev": "A" * 64}, "64 lowercase hex"),
    ({"seq": -1}, "seq must be"),
    ({"seq": True}, "seq must be"),
    ({"seq": 2**53, "prev": HASH_A}, "seq must be"),
    ({"seq": 1.0, "prev": HASH_A}, "seq must be"),
    ({"seen": {"checkpoint_note_hash": HASH_A}}, "exactly"),
    ({"payload": [1, 2]}, "payload must be an object"),
    ({"payload": {"size": 1.5}}, "integers"),
    ({"payload": {"size": -1}}, "2\\*\\*53"),
    ({"payload": {"size": 2**53}}, "2\\*\\*53"),
    ({"payload": {1: "x"}}, "member names"),
])
def test_sign_envelope_refuses_what_a_verifier_refuses(test_key, overrides, match):
    with pytest.raises(MalformedEnvelope, match=match):
        make(test_key, **overrides)


def test_nesting_is_bounded(test_key):
    deep: dict = {}
    node = deep
    for _ in range(envelope.MAX_DEPTH + 2):
        node["x"] = {}
        node = node["x"]
    with pytest.raises(MalformedEnvelope, match="nested deeper"):
        make(test_key, payload=deep, type="report")


def test_float_times_are_truncated(test_key):
    env = make(test_key, created=T + 0.9, expires=T + 300.9)
    assert (env["protected"]["created"], env["protected"]["expires"]) == (T, T + 300)


def test_a_profile_registry_can_be_extended(test_key):
    env = make(test_key, type="swarm.form", types=envelope.SWARMS_PROFILE_TYPES)
    with pytest.raises(MalformedEnvelope, match="entry type"):
        verify_envelope(env, keys.parse_did_key, now=T)
    assert verify_envelope(env, keys.parse_did_key, now=T, types=envelope.SWARMS_PROFILE_TYPES) == PAYLOAD


# ----------------------------------------------------------------------
# verification
# ----------------------------------------------------------------------

def test_roundtrip_returns_the_payload(test_key):
    env = make(test_key)
    assert verify_envelope(env, resolver_for(test_key), now=T + 10, origin=ORIGIN, type="post") == PAYLOAD


def test_resolve_key_accepts_every_key_form(test_key):
    env = make(test_key)
    pub = test_key.public_key()
    for form in (test_key, pub, keys.public_key_bytes(pub), keys.format_public_key(pub), kid_of(test_key),
                 sshsig.format_openssh_public_key(pub, "c")):
        assert verify_envelope(env, lambda kid, form=form: form, now=T) == PAYLOAD
    assert verify_envelope(env, keys.parse_did_key, now=T) == PAYLOAD


def test_envelope_survives_a_json_roundtrip(test_key):
    env = make(test_key)
    assert verify_envelope(json.loads(json.dumps(env)), resolver_for(test_key), now=T + 5) == PAYLOAD


@pytest.mark.parametrize("path, value", [
    (("protected", "origin"), "evil.example/tiles"),
    (("protected", "type"), "poll"),
    (("protected", "created"), T + 1),
    (("protected", "expires"), T + 299),
    (("protected", "nonce"), keys.b64u_encode(bytes(16))),
    (("protected", "seen"), {"checkpoint_note_hash": HASH_A, "size": 1}),
    (("payload", "size"), 999),
    (("payload", "extra"), None),
])
def test_tampering_with_any_signed_member_fails(test_key, path, value):
    env = make(test_key)
    env[path[0]][path[1]] = value
    with pytest.raises(InvalidSignatureError):
        verify_envelope(env, keys.parse_did_key, now=T + 1)


def test_tampered_signature_fails(test_key):
    env = make(test_key)
    sig = bytearray(keys.u64_decode(env["sig"]))
    sig[0] ^= 0xFF
    env["sig"] = keys.b64u_encode(bytes(sig))
    with pytest.raises(InvalidSignatureError):
        verify_envelope(env, keys.parse_did_key, now=T)


def test_a_kid_swapped_for_another_key_fails(test_key):
    env = make(test_key)
    env["protected"]["kid"] = kid_of(keys.generate_keypair())
    with pytest.raises(InvalidSignatureError):
        verify_envelope(env, keys.parse_did_key, now=T)


def test_unknown_kid_fails(test_key):
    with pytest.raises(UnknownKeyError):
        verify_envelope(make(test_key), lambda kid: None, now=T)


def test_the_resolved_key_must_be_the_key_the_kid_encodes(test_key):
    """AICS-1 section 3.1: decode the kid locally and compare it with the logged key."""
    other = keys.generate_keypair()
    with pytest.raises(InvalidSignatureError, match="not the key that kid encodes"):
        verify_envelope(make(test_key), lambda kid: other.public_key(), now=T)


def test_resolver_value_errors_are_unusable_keys(test_key):
    def broken(kid):
        raise ValueError("small-order")

    with pytest.raises(InvalidSignatureError, match="unusable"):
        verify_envelope(make(test_key), broken, now=T)


def _structure_cases(key):
    env = make(key)
    cases = {
        "not-an-object": [1, 2],
        "no-auth": {k: v for k, v in env.items() if k != "auth"},
        "extra-member": {**env, "transport": "x"},
        "v-true": {**env, "v": True},
        "v-2": {**env, "v": 2},
        "protected-extra": with_protected(key, env, extra=1),
        "protected-no-seen": resign(key, {**env, "protected": {k: v for k, v in env["protected"].items()
                                                                 if k != "seen"}}),
        "alg-es256": with_protected(key, env, alg="ES256"),
        "alg-none": with_protected(key, env, alg="none"),
        "kid-short-id": with_protected(key, env, kid=keys.key_id(key.public_key())),
        "kid-unverified": with_protected(key, env, kid=keys.new_unverified_id()),
        "kid-x25519-did": with_protected(key, env, kid=keys.x25519_did_key(bytes(range(32)))),
        "auth-unknown": {**env, "auth": {"scheme": "bearer"}},
        "auth-extra": {**env, "auth": {"scheme": "ed25519-jcs", "session": SESSION}},
        "auth-shared-secret": {**env, "auth": {"scheme": "shared-secret"}},
        "sig-padded": {**env, "sig": env["sig"] + "=="},
        "sig-junk": {**env, "sig": env["sig"] + "!"},
        "sig-space": {**env, "sig": " " + env["sig"]},
        "sig-short": {**env, "sig": env["sig"][:-2]},
        "sig-null": {**env, "sig": None},
        "payload-list": resign(key, {**env, "payload": [1]}),
        "nonce-text": with_protected(key, env, nonce="unit-test-nonce"),
        "lifetime-301": with_protected(key, env, expires=T + 301),
        "lifetime-0": with_protected(key, env, expires=T),
        "created-float": with_protected(key, env, created=float(T)),
        "seen-array": with_protected(key, env, seen=[]),
        "prev-at-seq-0": with_protected(key, env, prev=HASH_A),
    }
    return cases


@pytest.mark.parametrize("case", sorted(_structure_cases(keys.generate_keypair())))
def test_malformed_envelopes_are_refused_before_any_key_lookup(test_key, case):
    env = _structure_cases(test_key)[case]

    def resolve(kid):
        raise AssertionError("structure is checked first")

    with pytest.raises(MalformedEnvelope):
        verify_envelope(env, resolve, now=T)


def test_expected_origin_and_type(test_key):
    env = make(test_key)
    assert verify_envelope(env, keys.parse_did_key, now=T, origin=ORIGIN, type="post") == PAYLOAD
    with pytest.raises(MalformedEnvelope, match="origin"):
        verify_envelope(env, keys.parse_did_key, now=T, origin="other.example/tiles")
    with pytest.raises(MalformedEnvelope, match="type"):
        verify_envelope(env, keys.parse_did_key, now=T, type="dm")


# ----------------------------------------------------------------------
# section 4.3 freshness at the submission time t
# ----------------------------------------------------------------------

# name -> (created - t, expires - created, error or None)
FRESHNESS = {
    "now": (0, 300, None),
    "future-30": (30, 300, None),
    "future-31": (31, 300, NotYetValidEnvelope),
    "past-299": (-299, 300, None),
    "past-300": (-300, 300, ExpiredEnvelope),       # t == expires
    "created-301-ago": (-301, 300, ExpiredEnvelope),
    "created-301-ago-long": (-301, 300, ExpiredEnvelope),
    "expires-next-second": (-10, 11, None),
    "expired-at-t": (-10, 10, ExpiredEnvelope),
    "lifetime-1": (0, 1, None),
    "lifetime-0": (0, 0, MalformedEnvelope),        # expires == created
    "lifetime-301": (0, 301, MalformedEnvelope),
}


@pytest.mark.parametrize("case", sorted(FRESHNESS))
def test_freshness_is_exactly_aics1_section_4_3(test_key, case):
    offset, lifetime, error = FRESHNESS[case]
    t = T + 1000
    env = with_protected(test_key, make(test_key), created=t + offset, expires=t + offset + lifetime)
    if error is None:
        assert verify_envelope(env, keys.parse_did_key, now=t) == PAYLOAD
    else:
        with pytest.raises(error):
            verify_envelope(env, keys.parse_did_key, now=t)


@pytest.mark.parametrize("lifetime", [0, -5, 301, 10_000])
def test_window_false_checks_the_signature_before_the_window(test_key, lifetime):
    # AICS-1 sections 4.3 and 10.2: a verifier may authenticate first and decide the validity window afterwards.
    t = T + 1000
    env = with_protected(test_key, make(test_key), created=t, expires=t + lifetime)
    with pytest.raises(MalformedEnvelope, match="expires|window"):
        envelope.validate_envelope(env)
    assert envelope.validate_envelope(env, window=False) == envelope.NATIVE_SCHEME
    envelope.validate_protected(env["protected"], window=False)
    # The window is still checked, after the signature: a MalformedEnvelope here means the signature verified.
    with pytest.raises(MalformedEnvelope, match="expires|window"):
        verify_envelope(env, keys.parse_did_key, now=t, window=False)
    forged = copy.deepcopy(env)
    forged["sig"] = keys.b64u_encode(bytes(64))
    with pytest.raises(InvalidSignatureError):
        verify_envelope(forged, keys.parse_did_key, now=t, window=False)
    with pytest.raises(MalformedEnvelope):
        verify_envelope(forged, keys.parse_did_key, now=t)  # the default refuses the structure first


def test_window_false_still_requires_uint_times(test_key):
    env = with_protected(test_key, make(test_key), expires="later")
    with pytest.raises(MalformedEnvelope, match="uint"):
        envelope.validate_envelope(env, window=False)


def test_the_skew_never_extends_expiry(test_key):
    t = T + 1000
    future = make(test_key, created=t + 30)
    assert verify_envelope(future, keys.parse_did_key, now=t, max_clock_skew=30) == PAYLOAD
    stale = make(test_key, created=t - 200, expires=t - 1)
    for skew in (0, 10, 30):
        with pytest.raises(ExpiredEnvelope):
            verify_envelope(stale, keys.parse_did_key, now=t, max_clock_skew=skew)
    with pytest.raises(NotYetValidEnvelope):
        verify_envelope(make(test_key, created=t + 1), keys.parse_did_key, now=t, max_clock_skew=0)


@pytest.mark.parametrize("skew", [31, 60, -1, True, "30"])
def test_the_skew_cannot_be_stretched(test_key, skew):
    with pytest.raises(ValueError, match="between 0 and 30"):
        verify_envelope(make(test_key), keys.parse_did_key, now=T, max_clock_skew=skew)


def test_check_freshness_directly():
    envelope.check_freshness({"created": T, "expires": T + 300}, T)
    envelope.check_freshness({"created": T, "expires": T + 300}, T + 299)
    with pytest.raises(ExpiredEnvelope):
        envelope.check_freshness({"created": T, "expires": T + 300}, T + 300)
    with pytest.raises(NotYetValidEnvelope):
        envelope.check_freshness({"created": T, "expires": T + 300}, T - 31)
    with pytest.raises(MalformedEnvelope):
        envelope.check_freshness({"created": T}, T)
    with pytest.raises(TypeError):
        envelope.check_freshness({"created": T, "expires": T + 300}, "now")


def test_history_is_verified_at_entry_ts(test_key):
    env = make(test_key)
    entry_ts = T + 2
    assert verify_envelope(env, keys.parse_did_key, now=entry_ts) == PAYLOAD
    with pytest.raises(ExpiredEnvelope):
        verify_envelope(env, keys.parse_did_key)  # today's clock is years later


# ----------------------------------------------------------------------
# nonces and replay
# ----------------------------------------------------------------------

def test_new_nonce_is_canonical():
    nonces = {envelope.new_nonce() for _ in range(64)}
    assert len(nonces) == 64
    assert all(len(n) == 22 and envelope.is_canonical_nonce(n) for n in nonces)


@pytest.mark.parametrize("value", [
    "I_can_write_any_words_here_forever",  # 34 characters of chosen text
    keys.b64u_encode(bytes(32)),  # 43 characters: 32 bytes, not 16
    keys.b64u_encode(bytes(15)),  # 20 characters
    "AAAAAAAAAAAAAAAAAAAAAB",  # 22 characters with stray bits in the last one
    "AAAAAAAAAAAAAAAAAAAAA=",  # padding
    "AAAAAAAAAAAAAAAAAAAA+A",  # standard alphabet
    "unit-test-nonce",
    "",
    None,
    16,
])
def test_non_canonical_nonces_are_recognised(value):
    assert not envelope.is_canonical_nonce(value)


def test_canonical_nonce_of_chosen_bytes_is_still_canonical():
    # The check bounds what a nonce can carry; it cannot tell chosen bytes from random ones.
    assert envelope.is_canonical_nonce(keys.b64u_encode(b"sixteen chosen b"))


def test_the_canonical_nonce_option(test_key):
    """verify_envelope requires the 16-byte nonce by default; nonce_bytes names another length."""
    long_nonce = with_protected(test_key, make(test_key), nonce=keys.b64u_encode(bytes(32)))
    with pytest.raises(MalformedEnvelope, match="16 bytes"):
        verify_envelope(long_nonce, keys.parse_did_key, now=T)
    assert verify_envelope(long_nonce, keys.parse_did_key, now=T, nonce_bytes=32) == PAYLOAD
    with pytest.raises(ValueError):
        envelope.is_canonical_nonce(NONCE, 0)


def test_replay_hook_gets_kid_nonce_expires_and_t(test_key):
    calls, store = [], set()

    def hook(kid, nonce, retain_until, now):
        calls.append((kid, nonce, retain_until, now))
        if (kid, nonce) in store:
            return False
        store.add((kid, nonce))
        return True

    env = make(test_key)
    assert verify_envelope(env, keys.parse_did_key, now=T + 1, replay_check=hook) == PAYLOAD
    assert calls == [(kid_of(test_key), NONCE, T + 300, T + 1)]  # the recorded validity end is expires itself
    with pytest.raises(ReplayedEnvelope) as info:
        verify_envelope(env, keys.parse_did_key, now=T + 2, replay_check=hook)
    assert info.value.nonce == NONCE and info.value.kid == kid_of(test_key)


def test_replay_hook_not_called_for_bad_envelopes(test_key):
    cache = ReplayCache()
    env = make(test_key)
    tampered = dict(env, payload={"task": "other"})
    with pytest.raises(InvalidSignatureError):
        verify_envelope(tampered, keys.parse_did_key, now=T, replay_check=cache)
    with pytest.raises(ExpiredEnvelope):
        verify_envelope(env, keys.parse_did_key, now=T + 300, replay_check=cache)
    assert len(cache) == 0
    assert verify_envelope(env, keys.parse_did_key, now=T, replay_check=cache) == PAYLOAD
    with pytest.raises(ReplayedEnvelope):
        verify_envelope(env, keys.parse_did_key, now=T + 1, replay_check=cache)


def test_replay_hook_errors_propagate(test_key):
    class LeafConflict(Exception):
        pass

    def hook(*_):
        raise LeafConflict("nonce used at leaf 1234")

    with pytest.raises(LeafConflict, match="1234"):
        verify_envelope(make(test_key), keys.parse_did_key, now=T, replay_check=hook)


def test_replay_cache_detects_duplicates():
    cache = ReplayCache()
    assert cache.check_and_add("kid-a", "n1") is True
    assert cache.check_and_add("kid-a", "n1") is False
    assert cache.check_and_add("kid-a", "n2") is True
    assert cache.check_and_add("kid-b", "n1") is True  # same nonce, other kid


def test_replay_cache_forgets_after_expiry():
    cache = ReplayCache(default_ttl=100.0)
    assert cache.check_and_add("kid", "n", now=1000.0) is True
    assert cache.seen("kid", "n", now=1050.0) is True
    assert cache.seen("kid", "n", now=1100.5) is False  # ttl elapsed


def test_replay_cache_honours_envelope_expiry():
    cache = ReplayCache()
    assert cache.check_and_add("kid", "n", expires=T + 300, now=T) is True
    assert cache.check_and_add("kid", "n", now=T + 200) is False
    assert cache.check_and_add("kid", "n", now=T + 301) is True  # entry expired


def test_replay_cache_max_entries():
    cache = ReplayCache(max_entries=2)
    cache.check_and_add("k", "1", now=1.0)
    cache.check_and_add("k", "2", now=2.0)
    cache.check_and_add("k", "3", now=3.0)  # evicts the oldest ("1")
    assert cache.seen("k", "1", now=3.0) is False
    assert cache.seen("k", "2", now=3.0) is True
    assert cache.seen("k", "3", now=3.0) is True


def test_envelope_module_still_exports_replay_cache():
    from aics_identity import replay

    assert envelope.ReplayCache is replay.ReplayCache


# ----------------------------------------------------------------------
# seen
# ----------------------------------------------------------------------

CHECKPOINT_NOTE = (
    "wesupport-ai.com/log\n"
    "42\n"
    "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n"
    "\n"
    "— wesupport-ai.com/log Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=\n"
)


def test_seen_null_is_the_bootstrap_value(test_key):
    """AICS-1 section 4.1: seen is null for initial bootstrap (Appendix A leaves 0-2)."""
    env = make(test_key, seen=None)
    assert env["protected"]["seen"] is None
    assert verify_envelope(env, keys.parse_did_key, now=T) == PAYLOAD
    assert validate_seen(None) is None
    envelope.validate_chain_fields({"seq": 0, "prev": None, "seen": None})


def test_seen_field(test_key):
    seen = seen_from_checkpoint(CHECKPOINT_NOTE)
    assert seen == {"checkpoint_note_hash": hashlib.sha256(CHECKPOINT_NOTE.encode()).hexdigest(), "size": 42}
    assert seen_from_checkpoint(CHECKPOINT_NOTE.encode()) == seen
    env = make(test_key, seen=seen)
    assert env["protected"]["seen"] == seen
    assert verify_envelope(env, keys.parse_did_key, now=T) == PAYLOAD


@pytest.mark.parametrize("seen", [
    "not-an-object",
    [],
    {"checkpoint_note_hash": HASH_A},
    {"checkpoint_note_hash": HASH_A, "size": 1, "extra": 0},
    {"checkpoint_note_hash": "z" * 64, "size": 1},
    {"checkpoint_note_hash": "A" * 64, "size": 1},
    {"checkpoint_note_hash": HASH_A, "size": -1},
    {"checkpoint_note_hash": HASH_A, "size": 2**53},
    {"checkpoint_note_hash": HASH_A, "size": True},
    {"checkpoint_note_hash": HASH_A, "size": "1"},
])
def test_bad_seen_rejected(test_key, seen):
    with pytest.raises(MalformedEnvelope):
        validate_seen(seen)
    with pytest.raises(MalformedEnvelope):
        envelope.validate_chain_fields({"seq": 0, "prev": None, "seen": seen})
    with pytest.raises(MalformedEnvelope):
        make(test_key, seen=seen)


@pytest.mark.parametrize("note", ["origin only\n", "origin\nforty-two\nroot\n", "origin\n042\nroot\n"])
def test_seen_from_bad_checkpoint(note):
    with pytest.raises(ValueError):
        seen_from_checkpoint(note)


# ----------------------------------------------------------------------
# the sender chain (section 4.2)
# ----------------------------------------------------------------------

def chained(key, previous=None, **overrides):
    """Sign the next envelope in *key*'s chain (the nonce varies with seq)."""
    fields = next_chain(previous)
    kwargs = dict(origin=ORIGIN, type="post", created=T, nonce=keys.b64u_encode(bytes([fields["seq"]]) * 16),
                  **fields)
    kwargs.update(overrides)
    return sign_envelope({"n": fields["seq"]}, key, **{k: v for k, v in kwargs.items()})


def test_first_envelope_has_seq_zero_and_null_prev(test_key):
    env = chained(test_key)
    assert env["protected"]["seq"] == 0 and env["protected"]["prev"] is None
    assert verify_envelope(env, keys.parse_did_key, now=T) == {"n": 0}


def test_prev_is_the_hash_of_the_complete_previous_envelope(test_key):
    e0 = chained(test_key)
    e1 = chained(test_key, e0)
    e2 = chained(test_key, e1)
    assert next_chain(None) == {"seq": 0, "prev": None}
    assert next_chain(e0) == {"seq": 1, "prev": hashlib.sha256(canonicalize(e0)).hexdigest()}
    assert e1["protected"]["prev"] == envelope_hash(e0) and e2["protected"]["seq"] == 2
    check_successor(None, e0)
    check_successor(e0, e1)
    check_successor(e1, e2)
    for env in (e0, e1, e2):
        verify_envelope(env, keys.parse_did_key, now=T)


def test_chains_span_entry_types(test_key):
    e0 = chained(test_key, type="name.claim")
    e1 = chained(test_key, e0, type="post")
    e2 = chained(test_key, e1, type="grant")
    assert chain_breaks([e0, e1, e2]) == []


def test_envelope_hash_definition(test_key):
    env = chained(test_key)
    assert envelope_hash(env) == hashlib.sha256(canonicalize(env)).hexdigest()
    other_auth = dict(env, auth={"scheme": "ed25519-jcs", "x": 1})
    assert envelope_hash(other_auth) != envelope_hash(env)  # auth is hashed (not a valid envelope, still hashed)
    assert envelope_hash(chained(test_key, nonce=keys.b64u_encode(b"x" * 16))) != envelope_hash(env)
    with pytest.raises(MalformedEnvelope, match="sig"):
        envelope_hash({k: v for k, v in env.items() if k != "sig"})
    with pytest.raises(MalformedEnvelope, match="unknown transport"):
        envelope_hash(dict(env, transport="added"))
    with pytest.raises(MalformedEnvelope):
        envelope_hash("not an envelope")


def test_check_successor_failures(test_key):
    other = keys.generate_keypair()
    e0 = chained(test_key)
    e1 = chained(test_key, e0)
    skipped = chained(test_key, e1)  # seq 2
    with pytest.raises(ChainError, match="seq is 2, expected 1") as info:
        check_successor(e0, skipped)
    assert info.value.expected_seq == 1 and info.value.expected_prev == envelope_hash(e0)
    forked = chained(test_key, chained(test_key, nonce=keys.b64u_encode(b"f" * 16)))  # seq 1 after another first
    with pytest.raises(ChainError, match="prev"):
        check_successor(e0, forked)
    with pytest.raises(ChainError, match="different keys"):
        check_successor(e0, chained(other, chained(other)))
    with pytest.raises(ChainError, match="expected 0"):
        check_successor(None, e1)


def test_check_chain_position_server_rule(test_key):
    e0 = chained(test_key)
    e1 = chained(test_key, e0)
    check_chain_position(e0, last_seq=None, last_hash=None)
    check_chain_position(e1, last_seq=0, last_hash=envelope_hash(e0))
    with pytest.raises(ChainError):
        check_chain_position(e1, last_seq=1, last_hash=envelope_hash(e0))
    with pytest.raises(ChainError):
        check_chain_position(e1, last_seq=0, last_hash=HASH_A)
    with pytest.raises(ValueError):
        check_chain_position(e1, last_seq=0, last_hash="A" * 64)
    with pytest.raises(ValueError):
        check_chain_position(e0, last_seq=None, last_hash=HASH_A)
    with pytest.raises(MalformedEnvelope, match="no seq"):
        check_chain_position({"protected": {"kid": kid_of(test_key)}}, last_seq=None, last_hash=None)


def test_chain_breaks_reports_holes_forks_and_key_changes(test_key):
    e = [chained(test_key)]
    for _ in range(4):
        e.append(chained(test_key, e[-1]))
    assert chain_breaks(e) == []
    assert chain_breaks(e[2:], previous=e[1]) == []

    holes = chain_breaks([e[0], e[1], e[3], e[4]])  # e[2] withheld
    assert [(b.position, b.reason, b.expected_seq, b.seq) for b in holes] == [(2, "seq", 2, 3)]

    substitute = chained(test_key, e[1], nonce=keys.b64u_encode(b"s" * 16))  # a second seq 2
    forked = chained(test_key, substitute)  # seq 3 whose prev is the substitute
    assert [(b.position, b.reason) for b in chain_breaks([e[0], e[1], e[2], forked])] == [(3, "prev")]

    other = keys.generate_keypair()
    assert [(b.position, b.reason) for b in chain_breaks([e[0], chained(other, e[0])])] == [(1, "kid")]
    assert [(b.position, b.reason, b.expected_seq) for b in chain_breaks(e[1:])] == [(0, "seq", 0)]


@pytest.mark.parametrize("extra, match", [
    ({"seq": 0, "prev": HASH_A}, "null when seq is 0"),
    ({"seq": 3, "prev": None}, "64 lowercase hex"),
    ({"seq": "1", "prev": HASH_A}, "seq must be"),
    ({"seen": {"checkpoint_note_hash": HASH_A}}, "exactly"),
])
def test_verify_rejects_signed_but_malformed_chain_fields(test_key, extra, match):
    env = with_protected(test_key, make(test_key), **extra)
    with pytest.raises(MalformedEnvelope, match=match):
        verify_envelope(env, keys.parse_did_key, now=T)


def test_validate_chain_fields_checks_only_what_is_present():
    envelope.validate_chain_fields({})
    with pytest.raises(MalformedEnvelope, match="together"):
        envelope.validate_chain_fields({"seq": 0})
    with pytest.raises(MalformedEnvelope, match="together"):
        envelope.validate_chain_fields({"prev": None})


def test_seq_ceiling(test_key):
    top = make(test_key, seq=2**53 - 1, prev=HASH_A)
    with pytest.raises(MalformedEnvelope):
        next_chain(top)


# ----------------------------------------------------------------------
# the fallback envelope (sections 3.3 and 4.1) and its attestation (section 5.1)
# ----------------------------------------------------------------------

UNVERIFIED = keys.UNVERIFIED_PREFIX + keys.b64u_encode(b"unverified-id-16")


def fallback(**overrides):
    kwargs = dict(origin=ORIGIN, type="post", kid=UNVERIFIED, created=T, nonce=NONCE)
    kwargs.update(overrides)
    payload = kwargs.pop("payload", PAYLOAD)
    return envelope.fallback_envelope(payload, **kwargs)


def test_fallback_envelope_shape():
    env = fallback()
    assert env["protected"]["alg"] == "none" and env["protected"]["kid"] == UNVERIFIED
    assert env["auth"] == {"scheme": "shared-secret"} and env["sig"] is None
    assert set(env["protected"]) == set(envelope.PROTECTED_MEMBERS)
    assert envelope.validate_envelope(env) == "shared-secret"
    assert envelope_hash(env) == hashlib.sha256(canonicalize(env)).hexdigest()
    assert next_chain(env) == {"seq": 1, "prev": envelope_hash(env)}


def test_fallback_envelope_needs_an_unverified_identifier(test_key):
    for kid in (kid_of(test_key), "unverified:short", "unverified:" + keys.b64u_encode(bytes(32)), "user-1"):
        with pytest.raises(MalformedEnvelope, match="unverified"):
            fallback(kid=kid)


def test_fallback_writes_are_a_claim_and_posts_by_default():
    claim = {"name_norm": "ada", "prev_event_index": None, "ed25519": None, "x25519": None, "tier": "unverified",
             "recovery_kid": None, "recovery_pop": None, "initial_grant": None}
    assert fallback(type="name.claim", payload=claim)["protected"]["type"] == "name.claim"
    with pytest.raises(MalformedEnvelope, match="entry type"):
        fallback(type="vote")
    assert fallback(type="vote", types=envelope.ENTRY_TYPES)["protected"]["type"] == "vote"


def test_a_fallback_envelope_is_never_a_signature(test_key):
    with pytest.raises(UnsupportedScheme, match="never an agent signature") as info:
        verify_envelope(fallback(), keys.parse_did_key, now=T)
    assert isinstance(info.value, InvalidSignatureError)


@pytest.mark.parametrize("change", [
    {"sig": "x" * 86},
    {"protected": {"alg": "EdDSA"}},
    {"auth": {"scheme": "ed25519-jcs"}},
])
def test_fallback_structure_is_checked(change):
    env = fallback()
    for name, value in change.items():
        env[name] = {**env[name], **value} if isinstance(value, dict) and name == "protected" else value
    with pytest.raises(MalformedEnvelope):
        envelope.validate_envelope(env)


def test_secret_attestation_message_is_the_section_5_1_bytes():
    env = fallback()
    expected = b"AICS-1 secret-attestation\n" + json.dumps(
        {"actor_kid": UNVERIFIED, "envelope_hash": hashlib.sha256(canonicalize(env)).hexdigest(),
         "origin": ORIGIN, "ts": T + 1, "type": "post"}, separators=(",", ":"), sort_keys=True).encode()
    assert envelope.secret_attestation_message(env, ts=T + 1) == expected


def test_secret_attestation_signs_and_verifies(test_key):
    policy = keys.generate_keypair()
    env = fallback()
    att = envelope.sign_secret_attestation(policy, env, ts=T + 1)
    assert len(keys.u64_decode(att, length=64)) == 64
    for form in (policy.public_key(), kid_of(policy), keys.public_key_bytes(policy.public_key())):
        envelope.verify_secret_attestation(env, att, form, ts=T + 1)
    with pytest.raises(InvalidSignatureError):
        envelope.verify_secret_attestation(env, att, policy.public_key(), ts=T + 2)
    with pytest.raises(InvalidSignatureError):
        envelope.verify_secret_attestation(fallback(payload=dict(PAYLOAD, size=1)), att, policy, ts=T + 1)
    with pytest.raises(InvalidSignatureError):
        envelope.verify_secret_attestation(env, att, test_key.public_key(), ts=T + 1)
    with pytest.raises(MalformedEnvelope):
        envelope.verify_secret_attestation(env, att + "A", policy, ts=T + 1)
    with pytest.raises(MalformedEnvelope, match="shared-secret"):
        envelope.sign_secret_attestation(policy, make(test_key), ts=T + 1)
    with pytest.raises(MalformedEnvelope, match="ts"):
        envelope.secret_attestation_message(env, ts=-1)


# ----------------------------------------------------------------------
# text-gate schemes (section 11.3)
# ----------------------------------------------------------------------

def unsigned(key, *, typ="post", payload=PAYLOAD, scheme="text-ed25519", **overrides):
    kwargs = dict(origin=ORIGIN, type=typ, kid=kid_of(key), session=SESSION, scheme=scheme, created=T, nonce=NONCE)
    kwargs.update(overrides)
    return envelope.unsigned_text_envelope(payload, **kwargs)


def test_unsigned_text_envelope_shape(test_key):
    u = unsigned(test_key)
    assert list(u) == ["v", "protected", "payload", "auth"]
    assert u["auth"] == {"scheme": "text-ed25519", "session": SESSION} and u["protected"]["alg"] == "EdDSA"
    with pytest.raises(MalformedEnvelope):
        unsigned(test_key, kid=UNVERIFIED)
    with pytest.raises(MalformedEnvelope):
        unsigned(test_key, session="not-a-session")
    with pytest.raises(MalformedEnvelope):
        unsigned(test_key, scheme="ed25519-jcs")


def test_text_command_forms(test_key):
    u = unsigned(test_key)
    u_bytes = canonicalize(u)
    assert envelope.text_command(u) == "post " + keys.b64u_encode(u_bytes)
    claim = unsigned(test_key, typ="name.claim", payload={"name_norm": "ada", "prev_event_index": None})
    assert envelope.text_command(claim) == "claim ada " + hashlib.sha256(canonicalize(claim)).hexdigest()
    upgrade = unsigned(test_key, typ="key.rotate", payload={"mode": "upgrade", "name_norm": "ada"})
    assert envelope.text_command(upgrade).startswith("claim-upgrade ada ")
    rotate = unsigned(test_key, typ="key.rotate", payload={"mode": "rotate", "name_norm": "ada"})
    assert envelope.text_command(rotate).startswith("rotate ")
    assert envelope.text_command(unsigned(test_key, typ="dm")).startswith("send ")
    assert envelope.text_command(unsigned(test_key, typ="capsule")).startswith("store ")
    assert envelope.text_command(unsigned(test_key, typ="x25519.rotate")).startswith("x25519.rotate ")
    spend = unsigned(test_key, typ="sup.spend", types=envelope.SUP_PROFILE_TYPES)
    with pytest.raises(MalformedEnvelope, match="no gate verb"):
        envelope.text_command(spend)  # a profile's verbs are opt-in
    assert envelope.text_command(spend, verbs={**envelope.TEXT_VERBS, **envelope.SUP_TEXT_VERBS}) \
        .startswith("spend ")
    intro = unsigned(test_key, typ="agent.introduce", types=envelope.SWARMS_PROFILE_TYPES)
    assert envelope.text_command(intro, verbs=envelope.SWARMS_TEXT_VERBS).startswith("intro ")
    with pytest.raises(MalformedEnvelope, match="no gate verb"):
        envelope.text_command(unsigned(test_key, typ="refusal"))
    with pytest.raises(MalformedEnvelope, match="without sig"):
        envelope.text_command({**u, "sig": "x"})
    with pytest.raises(MalformedEnvelope, match="name_norm"):
        envelope.text_command(unsigned(test_key, typ="name.claim", payload={"name_norm": "Ada"}))
    assert envelope.text_signing_input(u) == (SESSION + "\n" + envelope.text_command(u)).encode()


def test_text_ed25519_envelope_roundtrip(test_key):
    u = unsigned(test_key)
    signature = test_key.sign(envelope.text_signing_input(u))
    e = envelope.text_envelope(u, signature)
    assert e["sig"] == keys.b64u_encode(signature)
    assert envelope.verify_text_envelope(e, keys.parse_did_key, now=T, origin=ORIGIN, type="post") == PAYLOAD
    # the same bytes are a valid gate line signature (linesig, strict)
    import base64

    assert linesig.verify_line(SESSION, envelope.text_command(u), base64.b64encode(signature).decode(),
                               test_key.public_key()) == "raw"
    # the native digest rule never verifies a text scheme (section 4.1)
    with pytest.raises(UnsupportedScheme):
        verify_envelope(e, keys.parse_did_key, now=T)
    with pytest.raises(UnsupportedScheme):
        envelope.verify_text_envelope(make(test_key), keys.parse_did_key, now=T)


def test_text_sshsig_envelope_roundtrip(test_key):
    u = unsigned(test_key, scheme="text-sshsig")
    blob = sshsig.dearmor(sshsig.sign_sshsig(envelope.text_signing_input(u), test_key))
    e = envelope.text_envelope(u, blob)
    assert keys.u64_decode(e["sig"]).startswith(b"SSHSIG")
    assert envelope.verify_text_envelope(e, keys.parse_did_key, now=T) == PAYLOAD


def test_text_envelope_tampering(test_key):
    u = unsigned(test_key)
    e = envelope.text_envelope(u, test_key.sign(envelope.text_signing_input(u)))
    for path, value in ((("payload", "size"), 1), (("auth", "session"), keys.b64u_encode(b"another-session!"))):
        bad = copy.deepcopy(e)
        bad[path[0]][path[1]] = value
        with pytest.raises(InvalidSignatureError):
            envelope.verify_text_envelope(bad, keys.parse_did_key, now=T)
    with_lf = envelope.text_envelope(u, test_key.sign(envelope.text_signing_input(u) + b"\n"))
    with pytest.raises(InvalidSignatureError):  # no final LF, no leeway
        envelope.verify_text_envelope(with_lf, keys.parse_did_key, now=T)
    sshsig_u = unsigned(test_key, scheme="text-sshsig")
    blob = sshsig.dearmor(sshsig.sign_sshsig(envelope.text_signing_input(sshsig_u), test_key))
    swapped = {**envelope.text_envelope(sshsig_u, blob), "auth": {"scheme": "text-ed25519", "session": SESSION}}
    with pytest.raises(MalformedEnvelope, match="64-byte"):  # SSHSIG and raw Ed25519 are not interchangeable
        envelope.verify_text_envelope(swapped, keys.parse_did_key, now=T)


@pytest.mark.parametrize("namespace, hash_algorithm, reserved, match", [
    ("git", "sha512", b"", "namespace"),
    ("aics", "sha256", b"", "sha256"),
    ("aics", "sha512", b"tag", "reserved"),
])
def test_text_sshsig_profile(test_key, namespace, hash_algorithm, reserved, match):
    u = unsigned(test_key, scheme="text-sshsig")
    message = envelope.text_signing_input(u)
    data = sshsig.signed_data(message, namespace=namespace, hash_algorithm=hash_algorithm, reserved=reserved)
    blob = sshsig.SSHSignature(keys.public_key_bytes(test_key.public_key()), namespace, reserved, hash_algorithm,
                               test_key.sign(data)).to_blob()
    with pytest.raises(InvalidSignatureError, match=match):
        envelope.verify_text_envelope(envelope.text_envelope(u, blob), keys.parse_did_key, now=T)


def test_text_envelope_freshness_and_replay(test_key):
    u = unsigned(test_key)
    e = envelope.text_envelope(u, test_key.sign(envelope.text_signing_input(u)))
    cache = ReplayCache()
    assert envelope.verify_text_envelope(e, keys.parse_did_key, now=T, replay_check=cache) == PAYLOAD
    with pytest.raises(ReplayedEnvelope):
        envelope.verify_text_envelope(e, keys.parse_did_key, now=T + 1, replay_check=cache)
    with pytest.raises(ExpiredEnvelope):
        envelope.verify_text_envelope(e, keys.parse_did_key, now=T + 300)


def test_errors_share_a_base(test_key):
    for error in (MalformedEnvelope, UnknownKeyError, InvalidSignatureError, UnsupportedScheme, ExpiredEnvelope,
                  NotYetValidEnvelope, ChainError):
        assert issubclass(error, EnvelopeError)

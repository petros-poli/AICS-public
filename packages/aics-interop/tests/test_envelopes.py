"""Item 2: envelopes (AICS-1 §4) and the §11.3 text schemes.

Producers: the spec reference (``aics_interop.spec``), aics-identity (its
digest/key API, and its own ``sign_envelope``), aics-conformance
(``protocol.envelope``) and, for text schemes, the ``aics sign-line``
command, openssl and ssh-keygen.  Verifiers: aics-conformance's
``verify_signature``/schema/complete-history checks, aics-identity's
``verify_envelope`` and chain helpers, and ``aics verify message`` (with the
history of a complete prefix): see the last tests.
"""

from __future__ import annotations

import base64
import copy
import json
import subprocess

import pytest
from aics_identity.envelope import MalformedEnvelope
from cryptography.exceptions import InvalidSignature

from aics_interop import aicslog, drivers, spec

ORIGIN = aicslog.ORIGIN
T = aicslog.T0
ALICE = spec.test_key(0x71)
BOB = spec.test_key(0x72)
POLICY_TRUST = aicslog.trust_bundle()


def claim_payload(key, name="alice", x=0x72):
    return {"name_norm": name, "prev_event_index": None, "ed25519": spec.U64(spec.raw_public(key)),
            "x25519": spec.U64(spec.x25519_public(bytes([x]) * 32)), "tier": "verified",
            "recovery_kid": None, "recovery_pop": None, "initial_grant": None}


def post_payload(text="hello"):
    body = spec.J({"channel": "interop", "title": None, "text": text})
    return {"channel_sha256": spec.hexH(b"interop"), "parent_index": None, "body_hash": spec.hexH(body),
            "size": len(body), "title_sha256": None}


def nonce(i: int) -> bytes:
    return spec.H(b"envelope-nonce-%d" % i)[:16]


def chain(key=ALICE, n=3, seen=None):
    """A spec-correct sender chain: claim then posts, seq 0.., prev = hexH(J(previous E))."""
    out = []
    for i in range(n):
        typ, q = ("name.claim", claim_payload(key)) if i == 0 else ("post", post_payload(f"m{i}"))
        prev = spec.envelope_hash(out[-1]) if out else None
        out.append(spec.native_envelope(key, origin=ORIGIN, typ=typ, payload=q, created=T + i, nonce=nonce(i),
                                        seq=i, prev=prev, seen=seen))
    return out


def as_entries(envelopes, ts0=T):
    return [spec.J(spec.entry(e, ts0 + i)) for i, e in enumerate(envelopes)]


def history(raw):
    from aics_conformance import verify

    return verify.History(raw, drivers.conformance_policy(POLICY_TRUST))


def conformance_first_break(envelopes) -> int | None:
    """The first position whose envelope aics-conformance's complete-history verifier refuses as out of sequence
    (None: it accepts them all).  A refusal for any other reason fails the test outright (``pytest.fail``), so it
    is never mistaken for an aics-identity finding."""
    for n in range(1, len(envelopes) + 1):
        try:
            history(as_entries(envelopes[:n]))
        except ValueError as exc:
            if str(exc) != "sender sequence/predecessor":
                pytest.fail(f"aics-conformance refused the first {n} envelopes for another reason: {exc}")
            return n - 1
    return None


SEEN = {"checkpoint_note_hash": "ab" * 32, "size": 7}


# ---------------------------------------------------------------------------
# native ed25519-jcs envelopes
# ---------------------------------------------------------------------------


def test_conformance_and_spec_reference_produce_identical_bytes():
    from aics_conformance import protocol
    from nacl.public import PrivateKey

    agent = protocol.Agent(name="alice", key=ALICE, encryption_key=PrivateKey(bytes([0x72]) * 32))
    theirs = protocol.envelope(agent, ORIGIN, "name.claim", agent.claim(), T, nonce=spec.U64(nonce(0)), seen=SEEN)
    ours = spec.native_envelope(ALICE, origin=ORIGIN, typ="name.claim", payload=claim_payload(ALICE),
                                created=T, nonce=nonce(0), seen=SEEN)
    assert spec.J(theirs) == spec.J(ours)


def test_identity_digest_api_assembles_envelopes_conformance_accepts():
    """aics-identity's public digest/key/encoding API -> AICS-1 envelope -> aics-conformance."""
    from aics_conformance import protocol
    from aics_identity import keys as idkeys
    from aics_identity.envelope import envelope_signing_digest

    envelopes = []
    for i in range(3):
        typ, q = ("name.claim", claim_payload(ALICE)) if i == 0 else ("post", post_payload(f"m{i}"))
        p = {"alg": "EdDSA", "origin": ORIGIN, "type": typ, "kid": idkeys.did_key(ALICE.public_key()),
             "created": T + i, "expires": T + i + 300, "nonce": idkeys.b64u_encode(nonce(i)), "seq": i,
             "prev": spec.envelope_hash(envelopes[-1]) if envelopes else None, "seen": SEEN}
        e = {"v": 1, "protected": p, "payload": q, "auth": {"scheme": "ed25519-jcs"},
             "sig": idkeys.b64u_encode(ALICE.sign(envelope_signing_digest(p, q)))}
        protocol.verify_signature(e)
        envelopes.append(e)
    assert spec.J(envelopes) == spec.J(chain(seen=SEEN))  # every envelope is the reference's bytes, not only the first
    assert len(history(as_entries(envelopes)).entries) == 3


def test_spec_chain_is_accepted_by_conformance_history():
    assert len(history(as_entries(chain())).entries) == 3


def test_reference_envelopes_verify_in_identity():
    """The reference chain (byte-identical to aics-conformance's producer, test above) through aics-identity."""
    from aics_identity import envelope as idenv
    from aics_identity import keys as idkeys

    for e in chain(seen=SEEN):
        assert idenv.verify_envelope(copy.deepcopy(e), idkeys.parse_did_key, now=e["protected"]["created"]) \
            == e["payload"]
        assert idenv.envelope_signing_digest(e["protected"], e["payload"]) == \
            spec.signing_digest(e["protected"], e["payload"])


def test_tampered_envelopes_are_rejected_by_both():
    from aics_conformance import protocol
    from aics_identity import envelope as idenv
    from aics_identity import keys as idkeys

    e = chain(seen=SEEN)[1]
    for path, value in ((("protected", "origin"), "evil.example/log"), (("protected", "type"), "dm"),
                        (("payload", "size"), 999), (("protected", "seq"), 9)):
        bad = copy.deepcopy(e)
        bad[path[0]][path[1]] = value
        with pytest.raises(InvalidSignature):
            protocol.verify_signature(bad)
        with pytest.raises(idenv.InvalidSignatureError):
            idenv.verify_envelope(bad, idkeys.parse_did_key, now=T + 1)


def test_identity_verifies_envelopes_with_null_seen():
    """AICS-1 §4.1: seen is null for initial bootstrap (all three Appendix A leaves 0-2 use null)."""
    from aics_identity import envelope as idenv
    from aics_identity import keys as idkeys

    e = chain(seen=None)[0]
    assert idenv.verify_envelope(e, idkeys.parse_did_key, now=T) == e["payload"]


def test_identity_sign_envelope_produces_an_aics1_envelope():
    """aics-identity's own producer: exactly the §4.1 members, the reference's bytes, verified by aics-conformance."""
    from aics_conformance import protocol
    from aics_identity import envelope as idenv
    from aics_identity import keys as idkeys

    e = idenv.sign_envelope(claim_payload(ALICE), ALICE, origin=ORIGIN, type="name.claim",
                            kid=idkeys.did_key(ALICE.public_key()), created=T, nonce=spec.U64(nonce(0)), seq=0,
                            prev=None, seen=SEEN)
    assert set(e["protected"]) == {"alg", "origin", "type", "kid", "created", "expires", "nonce", "seq", "prev",
                                   "seen"}
    assert spec.J(e) == spec.J(spec.native_envelope(ALICE, origin=ORIGIN, typ="name.claim",
                                                    payload=claim_payload(ALICE), created=T, nonce=nonce(0),
                                                    seen=SEEN))
    protocol.verify_signature(e)


def test_identity_sign_envelope_kid_is_the_did_key():
    """§3.1: the signing kid is the key's did:key, by default and as the only kid ``sign_envelope`` accepts."""
    from aics_identity import envelope as idenv

    e = idenv.sign_envelope(post_payload(), ALICE, origin=ORIGIN, type="post", created=T)
    assert e["protected"]["kid"] == spec.kid(ALICE) and e["auth"] == {"scheme": "ed25519-jcs"}
    assert e["protected"]["origin"] == ORIGIN and e["protected"]["type"] == "post"
    with pytest.raises(MalformedEnvelope, match="did:key"):
        idenv.sign_envelope(post_payload(), ALICE, origin=ORIGIN, type="post", created=T, kid=spec.kid(BOB))


# ---------------------------------------------------------------------------
# envelope hash and the seq/prev chain
# ---------------------------------------------------------------------------


def test_envelope_hash_agrees_with_aics1():
    from aics_identity import envelope as idenv

    e = chain(seen=SEEN)[0]
    assert idenv.envelope_hash(e) == spec.envelope_hash(e)


def test_identity_chain_helpers_accept_an_aics1_chain():
    from aics_identity import envelope as idenv

    envelopes = chain(seen=SEEN)
    assert idenv.chain_breaks(envelopes) == []


def test_conformance_accepts_a_chain_built_with_identity_next_chain():
    from aics_identity import envelope as idenv

    envelopes = []
    for i in range(3):
        typ, q = ("name.claim", claim_payload(ALICE)) if i == 0 else ("post", post_payload(f"m{i}"))
        pos = idenv.next_chain(envelopes[-1] if envelopes else None)
        envelopes.append(spec.native_envelope(ALICE, origin=ORIGIN, typ=typ, payload=q, created=T + i,
                                              nonce=nonce(i), seq=pos["seq"], prev=pos["prev"], seen=SEEN))
    history(as_entries(envelopes))


def _defective(kind):
    envelopes = chain(seen=SEEN)
    if kind == "seq-gap":
        e = envelopes[2]
        envelopes[2] = spec.native_envelope(ALICE, origin=ORIGIN, typ="post", payload=e["payload"], created=T + 2,
                                            nonce=nonce(2), seq=3, prev=spec.envelope_hash(envelopes[1]),
                                            seen=SEEN)
    elif kind == "wrong-prev":
        envelopes[2] = spec.native_envelope(ALICE, origin=ORIGIN, typ="post", payload=envelopes[2]["payload"],
                                            created=T + 2, nonce=nonce(2), seq=2, prev="00" * 32, seen=SEEN)
    elif kind == "fork":
        envelopes[2] = spec.native_envelope(ALICE, origin=ORIGIN, typ="post", payload=post_payload("fork"),
                                            created=T + 2, nonce=nonce(2), seq=1,
                                            prev=spec.envelope_hash(envelopes[0]), seen=SEEN)
    elif kind == "first-not-zero":
        envelopes[0] = spec.native_envelope(ALICE, origin=ORIGIN, typ="name.claim", payload=claim_payload(ALICE),
                                            created=T, nonce=nonce(0), seq=1, prev="11" * 32, seen=SEEN)
    return envelopes


# AICS-1 §4.2: the first envelope that does not follow its predecessor, which aics-identity's chain_breaks() and
# aics-conformance's complete-history verifier both report.
BROKEN_CHAINS = [("seq-gap", 2), ("wrong-prev", 2), ("fork", 2), ("first-not-zero", 0)]


@pytest.mark.parametrize("kind,position", BROKEN_CHAINS)
def test_broken_chains_are_rejected_by_both_at_the_same_position(kind, position):
    from aics_identity import envelope as idenv

    envelopes = _defective(kind)
    if conformance_first_break(envelopes) != position:
        pytest.fail(f"aics-conformance does not refuse the {kind} chain at position {position}")
    assert min((b.position for b in idenv.chain_breaks(envelopes)), default=None) == position


# ---------------------------------------------------------------------------
# seen validation
# ---------------------------------------------------------------------------

SEEN_CASES = {
    "valid": (SEEN, True),
    "null": (None, True),
    "uppercase-hex": ({"checkpoint_note_hash": "AB" * 32, "size": 7}, False),
    "short-hash": ({"checkpoint_note_hash": "ab" * 31, "size": 7}, False),
    "extra-member": ({**SEEN, "note": "x"}, False),
    "missing-size": ({"checkpoint_note_hash": "ab" * 32}, False),
    "bool-size": ({"checkpoint_note_hash": "ab" * 32, "size": True}, False),
    "negative-size": ({"checkpoint_note_hash": "ab" * 32, "size": -1}, False),
    "size-above-uint": ({"checkpoint_note_hash": "ab" * 32, "size": 2 ** 53}, False),
    "array": ([], False),
}


def _conformance_accepts_seen(seen) -> bool:
    from aics_conformance import schema

    env = spec.native_envelope(ALICE, origin=ORIGIN, typ="name.claim", payload=claim_payload(ALICE), created=T,
                               nonce=nonce(0), seen=None)
    env["protected"]["seen"] = seen
    try:
        schema.validate_entry(spec.entry(env, T), ORIGIN)
    except ValueError:  # schema.require: every refusal is a ValueError naming the rule
        return False
    return True


def _identity_accepts_seen(seen) -> bool:
    from aics_identity import envelope as idenv

    try:
        idenv.validate_chain_fields({"seq": 0, "prev": None, "seen": seen})
    except idenv.MalformedEnvelope:
        return False
    return True


@pytest.mark.parametrize("case", sorted(SEEN_CASES))
def test_seen_validation_agrees(case):
    seen, valid = SEEN_CASES[case]
    assert _conformance_accepts_seen(seen) is valid
    assert _identity_accepts_seen(seen) is valid


def test_seen_pointer_from_a_note_agrees(appendix):
    """aics-identity seen_from_checkpoint == spec pointer == the A.1 envelope's seen for the A.3 size-3 note."""
    from aics_identity import envelope as idenv

    expected = spec.strict_json(appendix.envelope_bytes)["protected"]["seen"]
    assert idenv.seen_from_checkpoint(appendix.previous_checkpoint) == spec.seen_pointer(
        appendix.previous_checkpoint) == expected


# ---------------------------------------------------------------------------
# §4.3 acceptance-time freshness
# ---------------------------------------------------------------------------

# (created offset from t, lifetime) -> spec verdict
FRESHNESS = {
    "now": (0, 300, True),
    "future-30": (30, 300, True),
    "future-31": (31, 300, False),
    "past-300": (-300, 300, False),     # t == expires
    "past-299": (-299, 300, True),
    "lifetime-301": (0, 301, False),
    "lifetime-0": (0, 0, False),         # expires == created
    "lifetime-1": (0, 1, True),
}


@pytest.mark.parametrize("case", sorted(FRESHNESS))
def test_conformance_history_freshness_matches_aics1(case):
    offset, life, valid = FRESHNESS[case]
    t = T + 1000
    env = spec.native_envelope(ALICE, origin=ORIGIN, typ="name.claim", payload=claim_payload(ALICE),
                               created=t + offset, expires=t + offset + life, nonce=nonce(0))
    assert spec.accepted_at(env["protected"], t) is valid
    if valid:
        history([spec.J(spec.entry(env, t))])
    else:
        with pytest.raises(ValueError, match="acceptance-time freshness"):
            history([spec.J(spec.entry(env, t))])


def _identity_accepts_at(created: int, expires: int, t: int, **kwargs) -> bool:
    """aics-identity verify_envelope at ``now=t`` (keyword arguments as given, defaults otherwise)."""
    from aics_identity import envelope as idenv
    from aics_identity import keys as idkeys

    env = spec.native_envelope(ALICE, origin=ORIGIN, typ="name.claim", payload=claim_payload(ALICE),
                               created=created, expires=expires, nonce=nonce(0), seen=SEEN)
    try:
        idenv.verify_envelope(env, idkeys.parse_did_key, now=t, **kwargs)
    except (idenv.NotYetValidEnvelope, idenv.ExpiredEnvelope, idenv.MalformedEnvelope):
        return False  # the freshness refusals (expires < created is a MalformedEnvelope)
    return True


def _identity_accepts(case) -> bool:
    offset, life, _ = FRESHNESS[case]
    t = T + 1000
    return _identity_accepts_at(t + offset, t + offset + life, t)


@pytest.mark.parametrize("case", sorted(FRESHNESS))
def test_identity_default_freshness_matches_aics1(case):
    """aics-identity verify_envelope() with its default arguments against the §4.3 verdict, for every case."""
    assert _identity_accepts(case) is FRESHNESS[case][2]


def test_identity_skew_allowance_does_not_extend_expiry():
    """§4.3: "The 30-second allowance applies only to future creation times, not expiry".  max_clock_skew=30, the
    setting that admits created = t + 30, must still refuse an envelope that expired at t - 1."""
    t = T + 1000
    if not _identity_accepts_at(t + 30, t + 330, t, max_clock_skew=30):
        pytest.fail("precondition: max_clock_skew=30 admits an envelope created at t + 30")
    assert _identity_accepts_at(t - 200, t - 1, t, max_clock_skew=30) is False


# ---------------------------------------------------------------------------
# text schemes (§11.3): signatures from aics sign-line, openssl and ssh-keygen
# ---------------------------------------------------------------------------

SESSION = spec.U64(b"interop-session!")  # 16 bytes -> U64


def unsigned(typ="post", payload=None, scheme="text-ed25519", key=ALICE, seq=0, prev=None, seen=None):
    return spec.unsigned_text_envelope(key, origin=ORIGIN, typ=typ, payload=payload or post_payload(),
                                       created=T, nonce=nonce(9), session=SESSION, scheme=scheme, seq=seq, prev=prev,
                                       seen=seen)


def test_cli_signed_text_envelope_verifies_in_conformance(tmp_path):
    from aics_conformance import protocol
    from cryptography.hazmat.primitives import serialization

    key_file = tmp_path / "aics.key"
    key_file.write_bytes(ALICE.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    for typ, q in (("name.claim", claim_payload(ALICE)), ("post", post_payload())):
        u = unsigned(typ, q)
        command = spec.text_command(u)
        assert command == protocol.command(u)  # both compute the same canonical command C
        r = drivers.AicsCli(home=tmp_path / "home").run("sign-line", f"--session={SESSION}",
                                                        f"--line={command}", "--key", str(key_file))
        assert r.code == 0, r.data
        e = {**u, "sig": spec.U64(base64.b64decode(r.data["sig"]))}
        # aics sign-line and aics-conformance share aics_identity.linesig: the reference checks the bytes itself
        assert spec.dU64(e["sig"]) == ALICE.sign(spec.line_message(SESSION, command))
        protocol.verify_signature(e)
        from aics_conformance import schema

        schema.validate_entry(spec.entry(e, T), ORIGIN)


def test_text_envelope_is_not_verifiable_by_the_native_digest_rule():
    """§4.1: text schemes MUST NOT be verified by the native digest rule.  aics-identity's verify_envelope (the
    native rule) refuses a text envelope; its verify_text_envelope and aics-conformance verify the §11.3 bytes."""
    from aics_conformance import protocol
    from aics_identity import envelope as idenv
    from aics_identity import keys as idkeys

    for seen in (None, SEEN):
        u = unsigned(seen=seen)
        e = {**u, "sig": spec.U64(ALICE.sign(spec.line_message(SESSION, spec.text_command(u))))}
        protocol.verify_signature(e)
        assert idenv.verify_text_envelope(copy.deepcopy(e), idkeys.parse_did_key, now=T) == e["payload"]
        with pytest.raises(idenv.InvalidSignatureError):
            idenv.verify_envelope(e, idkeys.parse_did_key, now=T)
        with pytest.raises(idenv.UnsupportedScheme):  # and the text rule refuses a native envelope
            idenv.verify_text_envelope(chain(seen=seen)[0], idkeys.parse_did_key, now=T)


def test_openssl_signed_text_envelope_verifies_in_conformance(tmp_path, openssl_bin):
    from aics_conformance import protocol
    from cryptography.hazmat.primitives import serialization

    key_file = tmp_path / "aics.key"
    key_file.write_bytes(ALICE.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    u = unsigned()
    signing_input = tmp_path / "aics-signing-input"
    signing_input.write_bytes(spec.line_message(SESSION, spec.text_command(u)))
    out = subprocess.run([openssl_bin, "pkeyutl", "-sign", "-inkey", str(key_file), "-rawin", "-in",
                          str(signing_input)], capture_output=True, timeout=30)
    assert out.returncode == 0, out.stderr
    protocol.verify_signature({**u, "sig": spec.U64(out.stdout)})


def test_ssh_keygen_text_sshsig_envelope_verifies_in_conformance(tmp_path, ssh_keygen_bin):
    from aics_conformance import protocol
    from aics_identity import sshsig
    from cryptography.hazmat.primitives import serialization

    key_file = tmp_path / "aics_ed25519"
    key_file.write_bytes(ALICE.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                             serialization.NoEncryption()))
    key_file.chmod(0o600)
    u = unsigned(scheme="text-sshsig")
    data = tmp_path / "aics-signing-input"
    data.write_bytes(spec.line_message(SESSION, spec.text_command(u)))
    out = subprocess.run([ssh_keygen_bin, "-Y", "sign", "-f", str(key_file), "-n", "aics", "-O", "hashalg=sha512",
                          str(data)], capture_output=True, timeout=30)
    assert out.returncode == 0, out.stderr
    blob = sshsig.dearmor((tmp_path / "aics-signing-input.sig").read_text())
    e = {**u, "sig": spec.U64(blob)}  # §11.3: U64 of the complete SSHSIG blob, not the armor
    spec.verify_sshsig_blob(blob, spec.line_message(SESSION, spec.text_command(u)), spec.raw_public(ALICE))
    protocol.verify_signature(e)
    with pytest.raises(ValueError, match="not raw Ed25519"):  # SSHSIG and raw Ed25519 are not interchangeable
        protocol.verify_signature({**e, "auth": {"scheme": "text-ed25519", "session": SESSION}})


# ---------------------------------------------------------------------------
# the aics CLI
# ---------------------------------------------------------------------------


def test_cli_verifies_reference_envelopes_and_refuses_a_forged_one(tmp_path):
    """``aics verify message`` checks envelopes the reference signs (aics-identity verifies them) together with the
    history of the complete prefix; a forged signature on a leaf the log key signed is evidence (exit 2)."""
    log = aicslog.standard_log(6)
    trust = aicslog.trust_bundle()
    cli = drivers.AicsCli(home=tmp_path / "home")
    assert cli.pin(spec.readme_block(spec.J(trust)), quorum=0).code == 0

    def verify(index: int) -> drivers.CliResult:
        note = log.note()
        pkg = spec.verification_package(log.wire_bundle(index, note), trust, [], log.leaves(), [note])
        (tmp_path / "pkg.json").write_text(json.dumps(pkg))
        return cli.run("verify", "message", "--bundle", str(tmp_path / "pkg.json"), "--offline")

    for index in range(6):
        r = verify(index)
        assert r.code == 0 and r.data["result"] == "valid", (index, r.data)
    env = log.entries[5]["payload"]["envelope"]
    sig = spec.dU64(env["sig"])
    log.entries[5] = copy.deepcopy(log.entries[5])
    log.entries[5]["payload"]["envelope"]["sig"] = spec.U64(bytes([sig[0] ^ 1]) + sig[1:])
    r = verify(5)
    assert r.code == 2 and r.evidence["reason"] == "invalid-history" and r.evidence["rule"] == "envelope", r.data


def test_cli_stubs_are_receipt_tombstones_and_inbox(tmp_path):
    cli = drivers.AicsCli(home=tmp_path / "home")
    for argv in (("verify", "receipt"), ("verify", "tombstones"), ("inbox",)):
        r = cli.run(*argv)
        assert r.code == 3 and r.data["error"] == "not available until the server ships this", (argv, r.data)
    r = cli.run("verify", "message", "7")  # no longer a stub: it takes --bundle
    assert r.code == 1 and "unrecognized arguments" in r.data["error"], r.data

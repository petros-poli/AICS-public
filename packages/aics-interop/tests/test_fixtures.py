"""The fixtures directory: current, complete, and consumable by the packages.

``fixtures/`` is what other implementations (clients/aics-js) consume, so the
suite (1) regenerates it and requires byte equality with the committed files,
and (2) reads every fixture file back and checks its ``expect`` values with
the reference and with the Python packages, as an outside implementation
would.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.exceptions import InvalidSignature

from aics_interop import appendix_a, drivers, generate, spec

FIXTURES = generate.DEFAULT_OUT


@pytest.fixture(scope="module")
def generated():
    return generate.build()


def load(name: str):
    return json.loads((FIXTURES / name).read_text("utf-8"))


def test_fixtures_are_current(generated):
    """Run ``uv run aics-interop-fixtures`` after changing the generator, the scenarios or the specification."""
    have = generate.existing(FIXTURES)
    assert sorted(have) == sorted(generated), "fixtures/ lists other files than the generator writes"
    stale = [p for p in generated if have[p] != generated[p]]
    assert stale == [], f"stale fixtures: {stale}"


def test_generation_is_deterministic(generated):
    assert generate.build() == generated


def test_manifest_lists_every_file_with_its_digest():
    manifest = load("manifest.json")
    assert manifest["format"] == generate.FORMAT
    files = set(generate.existing(FIXTURES)) - {"manifest.json"}  # dotfiles (.DS_Store) are not fixtures
    assert set(manifest["files"]) == files
    for path, meta in manifest["files"].items():
        data = (FIXTURES / path).read_bytes()
        assert meta["sha256"] == hashlib.sha256(data).hexdigest() and meta["bytes"] == len(data), path
        assert meta["description"], path


# ---------------------------------------------------------------------------
# consumption
# ---------------------------------------------------------------------------


def test_keys_derive_from_their_seeds():
    k = load("keys.json")
    for name, e in k["ed25519"].items():
        key = spec.test_key(bytes.fromhex(e["seed_hex"])[0])
        assert spec.raw_public(key).hex() == e["public_hex"] and spec.kid(key) == e["kid"], name
        if "vkey" in e:
            name_, _, typ, pub = spec.parse_vkey(e["vkey"])
            assert pub.hex() == e["public_hex"] and typ in (0x01, 0x04)
    for name, e in k["x25519"].items():
        assert spec.x25519_public(bytes.fromhex(e["secret_hex"])).hex() == e["public_hex"], name


def test_linesig_fixture():
    from aics_identity import keys, linesig, sshsig

    f = load("linesig.json")
    pub = keys.parse_public_key_text(f["pub_reply"][4:])
    assert keys.public_key_bytes(sshsig.parse_openssh_public_key(f["ssh_public_key"])).hex() == f["public_key_hex"]
    for case in f["cases"]:
        ok = True
        try:
            linesig.verify_line(case["session"], case["line"], case["signature_b64"], pub, leeway=False)
        except linesig.InvalidLineSignature:
            ok = False
        assert ok is (case["expect"] == "valid"), case["name"]
        if case["expect"] == "valid":
            msg = bytes.fromhex(case["signing_input_hex"])
            assert msg == spec.line_message(case["session"], case["line"])
            sshsig.verify_sshsig(case["sshsig_armored"], msg, pub)
            assert spec.dU64(case["sshsig_blob_u64"]) == sshsig.dearmor(case["sshsig_armored"])
            assert linesig.sign_line(case["session"], case["line"], spec.test_key(0x61), form="sshsig") == \
                case["sshsig_armored"]


def test_envelopes_fixture():
    from aics_conformance import protocol, schema, verify

    f = load("envelopes.json")
    policy = drivers.conformance_policy(json.loads((FIXTURES / "tlog" / "log.json").read_text())["trust_bundle"])
    for case in f["native"]:
        e = case["envelope"]
        assert spec.J(e).decode() == case["jcs"] and spec.envelope_hash(e) == case["envelope_hash"]
        protocol.verify_signature(e)
        if "entry_jcs" in case:
            schema.validate_entry(spec.strict_json(case["entry_jcs"]), f["origin"])
    for case in f["tampered"]:
        with pytest.raises(InvalidSignature):
            protocol.verify_signature(case["envelope"])
    raw = [spec.J(spec.entry(e, e["protected"]["created"])) for e in f["chain"]["envelopes"]]
    assert f["chain"]["expect"] == "valid" and len(verify.History(raw, policy).entries) == 3
    for case in f["chain_breaks"]:
        envs, pos = case["envelopes"], case["first_invalid_position"]
        raw = [spec.J(spec.entry(e, e["protected"]["created"])) for e in envs]
        with pytest.raises(ValueError, match="sender sequence/predecessor"):
            verify.History(raw, policy)
        assert len(verify.History(raw[:pos], policy).entries) == pos
    for case in f["freshness"]:
        e = case["envelope"]
        assert spec.accepted_at(e["protected"], case["t"]) is (case["expect"] == "valid")
    for case in f["text"]:
        if case["expect"] == "valid":
            assert spec.text_command(case["unsigned"]) == case["command"]
            protocol.verify_signature(case["envelope"])
        else:
            with pytest.raises(ValueError, match="not raw Ed25519"):
                protocol.verify_signature(case["envelope"])


def _binding_ok(case: dict, env: dict) -> bool:
    """The reference §12.1 verdict: the RFC 9421 profile, then keyid, nonce and times equal the envelope's."""
    try:
        params = spec.verify_request(case["method"], case["url"], case["headers"], case["body_text"].encode(),
                                     spec.kid_public(env["protected"]["kid"]))
    except (InvalidSignature, ValueError):  # Ed25519 failure, or a profile rule the reference names
        return False
    p = env["protected"]
    return (params["keyid"], params["nonce"], params["created"], params["expires"]) == (
        p["kid"], p["nonce"], p["created"], p["expires"])


def test_http_signatures_fixture():
    from aics_identity import http_signatures as hs
    from aics_identity import keys

    f = load("http-signatures.json")
    env = f["envelope"]
    for case in f["cases"]:
        assert _binding_ok(case, env) is (case["expect"] == "valid"), case["name"]
        if case["expect"] == "valid":
            hs.verify_request(case["method"], case["url"], case["headers"], case["body_text"].encode(),
                              resolve_key=keys.parse_did_key, now=f["now"], **hs.AICS_VERIFY_POLICY)
    valid = f["cases"][0]
    p = env["protected"]
    theirs = hs.sign_request("POST", valid["url"], {"Content-Type": "application/json"}, valid["body_text"].encode(),
                             key=spec.test_key(0x81), keyid=p["kid"], created=p["created"], expires=p["expires"],
                             nonce=p["nonce"], tag="aics", components=hs.AICS_COMPONENTS, label="aics")
    assert theirs == valid["headers"]  # aics-identity signs the fixture's exact header bytes


def test_sealed_fixture():
    from aics_conformance import protocol
    from nacl.public import PrivateKey

    f = load("sealed.json")
    secret = PrivateKey(bytes.fromhex(f["recipient"]["x25519_secret_hex"]))
    for case in f["cases"]:
        ct = bytes.fromhex(case["ciphertext_hex"])
        if case["expect"] == "valid":
            assert protocol.open_message(case["envelope"], ct, secret) == case["content_text"].encode()
        else:
            with pytest.raises(ValueError):
                protocol.open_message(case["envelope"], ct, secret)


def test_tlog_fixture():
    from aics_tlog import FileSystemTileReader, VerifiedTileReader, parse_checkpoint, parse_note, verify_consistency
    from aics_tlog import verify_inclusion

    f = load("tlog/log.json")
    for size, n in f["notes"].items():
        note = n["note_text"].encode()
        v = spec.verify_note(note, f["log_vkey"], f["witness_vkeys"], 2, max_age=300, now=n["cosigned_at"] + 10,
                             expected_origin=f["origin"])
        assert v.ok and v.size == int(size) and spec.B64(v.root) == n["root_b64"]
    head = (FIXTURES / "tlog" / "tiles" / "checkpoint").read_bytes()
    cp = parse_checkpoint(parse_note(head).text)
    reader = VerifiedTileReader(FileSystemTileReader(FIXTURES / "tlog" / "tiles"), cp.size, cp.root)
    reader.check_root()
    entries = spec.verify_tiles(generate.existing(FIXTURES / "tlog" / "tiles"), cp.size, cp.root)  # the reference
    for i, u in f["entry_sample_u64"].items():
        assert reader.entry(int(i)) == entries[int(i)] == spec.dU64(u)
    for c in f["inclusion"]:
        args = (bytes.fromhex(c["leaf_hash_hex"]), c["index"], c["size"], [spec.dB64(h) for h in c["proof_b64"]],
                spec.dB64(c["root_b64"]))
        assert spec.verify_inclusion(*args) and verify_inclusion(*args)
    for c in f["consistency"]:
        args = (c["old"], c["new"], spec.dB64(c["old_root_b64"]), spec.dB64(c["new_root_b64"]),
                [spec.dB64(h) for h in c["proof_b64"]])
        assert spec.verify_consistency(*args) and verify_consistency(*args)
    nc = f["note_cases"]
    pol = nc["policy"]
    single = nc["single_witness_note_text"].encode()
    for c in nc["freshness"]:
        v = spec.verify_note(single, f["log_vkey"], pol["witness_vkeys"], pol["quorum"],
                             max_age=pol["max_checkpoint_age"], now=c["now"])
        assert v.ok is (c["expect"] == "valid"), c
    for name in ("repeated_unknown_key_lines", "repeated_log_key_line", "invalid_pinned_cosignature"):
        c = nc[name]
        v = spec.verify_note(c["note_text"].encode(), f["log_vkey"], pol["witness_vkeys"], pol["quorum"],
                             max_age=300, now=c["now"])
        assert v.ok is (c["expect"] == "valid"), name


def test_split_view_fixture():
    from aics_tlog.tiles import parse_entry_bundle

    f = load("split-view.json")

    def entries(label):
        tiles = f["trees"].get(label) or {}
        out = []
        for path in sorted(p for p in tiles if p.startswith("tile/entries/")):
            out += parse_entry_bundle(spec.dU64(tiles[path]))
        return out

    for case in f["fixtures"]:
        n1, n2 = case["note_1_text"].encode(), case["note_2_text"].encode()
        size1, size2 = (int(n.split(b"\n")[1]) for n in (n1, n2))
        es = entries(case["served"]["mirror" if size2 >= size1 else "origin"]["tiles"])
        got = spec.classify_gossip(n1, n2, log_vkey=f["log_vkey"], witness_vkeys=case["policy"]["witness_vkeys"],
                                   quorum=case["policy"]["quorum"],
                                   larger_entries=es if len(es) == max(size1, size2) else None,
                                   expected_origin=f["origin"])
        assert (got["relation"], got["witness_policy_met"]) == (case["expect"]["relation"],
                                                                case["expect"]["witness_policy_met"]), case["name"]


def test_bundles_fixture():
    from aics_conformance import verify

    f = load("bundles.json")
    w = f["aics1_wire_bundle"]["bundle"]
    out = spec.verify_wire_bundle(w, f["log_vkey"], f["witness_vkeys"], f["quorum"])
    pkg = f["aics1_package"]["package"]
    assert set(pkg) == set(spec.PACKAGE_MEMBERS) and pkg["bundle"] == w
    prefix = [spec.dU64(e) for e in pkg["entry_prefix"]]
    policy = drivers.conformance_policy(pkg["trust_bundle"], witnesses=f["witness_vkeys"], quorum=f["quorum"])
    _, entry = verify.bundle(w, policy, out["entry"]["ts"] + 3600, prefix=prefix)
    assert entry == out["entry"]
    assert spec.mth([spec.leaf_hash(e) for e in prefix]) == out["root"]
    for t in f["tampered_wire_bundles"]:
        with pytest.raises(ValueError):
            spec.verify_wire_bundle(t["bundle"], f["log_vkey"], f["witness_vkeys"], f["quorum"])
    legacy = f["legacy_aics_tlog_bundle"]["bundle"]
    assert set(legacy) != set(spec.BUNDLE_MEMBERS)
    with pytest.raises((ValueError, KeyError)):
        spec.verify_wire_bundle(legacy, f["log_vkey"], f["witness_vkeys"], f["quorum"])


def test_trust_bundle_fixture():
    from aics_cli.dnstxt import parse_response
    from aics_cli.errors import PolicyError
    from aics_cli.trust import bundle_from_jcs, bundle_from_text, bundle_from_u64, parse_txt

    f = load("trust-bundle.json")
    raw = f["jcs"].encode()
    assert spec.validate_trust_bundle(raw) == f["bundle"] and spec.hexH(raw) == f["sha256"]
    assert bundle_from_text(f["readme_block"]).jcs == raw and f["txt_record"] == spec.txt_record(raw)
    _, _, records = parse_response(bytes.fromhex(f["dns"]["response_hex"]), f["dns"]["qid"], f["dns"]["qname"])
    assert parse_txt([r.decode() for r in records]).bundle.jcs == raw
    for case in f["invalid"]:
        data = case["jcs"].encode() if "jcs" in case else spec.dU64(case["bytes_u64"])
        with pytest.raises(ValueError):
            spec.validate_trust_bundle(data)
        with pytest.raises(PolicyError):
            bundle_from_jcs(data) if "jcs" in case else bundle_from_u64(case["bytes_u64"])


def test_card_fixture():
    f = load("card.json")
    pub = spec.kid_public(f["policy_kid"])
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    def verify_jws(card):
        sig = card["signatures"][0]
        unsigned = {k: v for k, v in card.items() if k != "signatures"}
        Ed25519PublicKey.from_public_bytes(pub).verify(spec.dU64(sig["signature"]),
                                                       (sig["protected"] + "." + spec.U64(spec.J(unsigned))).encode())

    c = f["card"]
    verify_jws(c["card"])
    assert spec.card_hash(c["card"]) == c["card_hash"] == f["trust_bundle"]["bootstrap_card_hash"]
    assert c["expect"] == "valid" and spec.card_problems(c["card"]) == []
    # the reference §13.1 checks reach every expect: the 0.1-draft card and the registry variants are refused
    old = f["card_0_1_draft"]
    verify_jws(old["card"])
    assert old["expect"] == "invalid" and {"$.version: must be '0.2-draft'",
                                           "$.spec_versions: must be the 0.2-draft pins"} <= set(
        spec.card_problems(old["card"]))
    for case in f["registry"]:
        verify_jws(case["card"])
        assert case["expect"] == "invalid" and spec.card_problems(case["card"]) == [
            "$.reason_codes.refusal: must equal the §17.2 registry"], case["name"]
    assert f["altered"]["expect"] == "invalid"
    with pytest.raises(InvalidSignature):
        verify_jws(f["altered"]["card"])


def test_receipts_fixture():
    from aics_conformance import verify

    f = load("receipts.json")
    entry = spec.strict_json(spec.dU64(f["entry_u64"]))
    policy = drivers.conformance_policy(json.loads((FIXTURES / "tlog" / "log.json").read_text())["trust_bundle"])
    verify.receipt(f["receipt_text"].encode(), entry, policy)
    for case in f["invalid"]:
        assert case["expect"] == "invalid", case["name"]
        with pytest.raises(ValueError):
            verify.receipt(case["receipt_text"].encode(), entry, policy)


def test_appendix_a_fixture():
    f = load("appendix-a.json")
    a = appendix_a.load()
    assert f["envelope_jcs"].encode() == a.envelope_bytes and f["checkpoint_text"].encode() == a.checkpoint
    assert [spec.dU64(e) for e in f["entries_u64"]] == [a.entry_jcs(i) for i in range(4)]
    assert bytes.fromhex(f["ciphertext_hex"]) == a.ciphertext and f["inline"] == a.inline

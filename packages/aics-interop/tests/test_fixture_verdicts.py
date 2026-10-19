"""Every package over every fixture case: each disagreement with a case carries a finding.

``fixtures/`` is what other implementations consume, and its ``findings``
say where a package of this repository disagrees today.  Here each package's
verifier is run over the cases the way an outside implementation would read
the files, and its verdict (or a value it recomputes, such as an envelope
hash) is compared with the case.  A disagreement must be annotated with an
open finding of that package, or of the package whose code decides it (aics
and aics-conformance call aics-identity and aics-tlog; README "What
interoperates with what", column "Shares code with").  A package without a
consumer for a case is not run on it.
"""

from __future__ import annotations

import itertools
import json
from dataclasses import dataclass
from typing import Any, Callable

import pytest
from cryptography.exceptions import InvalidSignature

from aics_interop import aicslog, drivers, findings, generate, spec

FIXTURES = generate.DEFAULT_OUT


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text("utf-8"))


@dataclass
class Verdict:
    case: str                    # where in the fixtures, e.g. "envelopes.json native[3]"
    package: str                 # whose verifier ran
    agrees: bool                 # its verdict (or value) equals the case's
    ids: list[str]               # the case's findings annotation
    detail: str = ""
    shares: tuple[str, ...] = ()  # packages whose code decides for it


def covered(v: Verdict) -> bool:
    """An open finding of the package (or of a package whose code decides) explains the disagreement; a retired
    finding explains none, so a regression of a fixed package fails here."""
    packages = {v.package, *v.shares}
    return any(findings.FINDINGS[i].open and packages & set(findings.FINDINGS[i].package.split(" + ")) for i in v.ids)


def assert_annotated(verdicts: list[Verdict]) -> None:
    assert verdicts, "no verdicts collected"
    unannotated = [f"{v.case}: {v.package} {v.detail}".rstrip() for v in verdicts if not v.agrees and not covered(v)]
    assert unannotated == [], "disagreements without a finding in the fixture"


def outcome(fn: Callable[[], Any], *errors: type[BaseException]) -> bool:
    """True when ``fn`` returns, False when it raises one of the refusals ``errors``; anything else propagates."""
    try:
        fn()
    except errors:
        return False
    return True


_homes = itertools.count()


def cli_verdict(r: drivers.CliResult, command: str) -> bool:
    """aics exit 0 is acceptance and 1 or 2 a refusal (2: served evidence); an argument error fails the test."""
    error = str(r.data.get("error", ""))
    if r.code not in (0, 1, 2) or "invalid choice" in error or "unrecognized arguments" in error \
            or r.data.get("command") != command:
        pytest.fail(f"aics {command}: unexpected result {r.code} {r.data}")
    return r.code == 0


# ---------------------------------------------------------------------------


def test_linesig_cases(tmp_path):
    from aics_identity import keys, linesig

    f = load("linesig.json")
    pub = keys.parse_public_key_text(f["pub_reply"][len("pub "):])
    cli = drivers.AicsCli(home=tmp_path / "home")
    out = []
    for case in f["cases"]:
        name, valid, ids = f"linesig.json cases[{case['name']}]", case["expect"] == "valid", case.get("findings", [])
        # aics-identity's default (exact bytes, F07 retired); leeway=True is an explicit opt-out for tools outside
        # the protocol, so it is not held to the AICS-1 verdict
        ok = outcome(lambda: linesig.verify_line(case["session"], case["line"], case["signature_b64"], pub),
                     linesig.LineSignatureError)
        out.append(Verdict(name, "aics-identity", ok is valid, ids, "verify_line (default)"))
        for strict in ((), ("--strict",)):
            r = cli.run("verify-line", f"--session={case['session']}", f"--line={case['line']}",
                        f"--sig={case['signature_b64']}", "--pub", f["pub_reply"], *strict)
            out.append(Verdict(name, "aics", cli_verdict(r, "verify-line") is valid, ids, f"verify-line {strict}",
                               shares=("aics-identity",)))
        if valid:
            form = linesig.verify_line(case["session"], case["line"], case["sshsig_armored"], pub, leeway=False)
            out.append(Verdict(name, "aics-identity", form == "sshsig", ids, "SSHSIG armor"))
    assert_annotated(out)


def test_envelope_cases():
    from aics_conformance import protocol, schema, verify
    from aics_identity import envelope as idenv
    from aics_identity import keys as idkeys

    f = load("envelopes.json")
    policy = drivers.conformance_policy(load("tlog/log.json")["trust_bundle"])
    refusal = (InvalidSignature, ValueError)  # protocol and schema refuse with these
    out = []

    def identity_accepts(e, now):
        return outcome(lambda: idenv.verify_envelope(json.loads(json.dumps(e)), idkeys.parse_did_key, now=now),
                       idenv.EnvelopeError)

    def history_breaks_at(envelopes) -> int | None:
        for n in range(1, len(envelopes) + 1):
            raw = [spec.J(spec.entry(e, e["protected"]["created"])) for e in envelopes[:n]]
            if not outcome(lambda: verify.History(raw, policy), ValueError):
                return n - 1
        return None

    for i, case in enumerate(f["native"]):
        e, ids, name = case["envelope"], case.get("findings", []), f"envelopes.json native[{i}]"
        ok = outcome(lambda: protocol.verify_signature(e), *refusal)
        if ok and "entry_jcs" in case:
            ok = outcome(lambda: schema.validate_entry(spec.strict_json(case["entry_jcs"]), f["origin"]), ValueError)
        out.append(Verdict(name, "aics-conformance", ok is (case["expect"] == "valid"), ids,
                           "verify_signature and schema", shares=("aics-identity",)))
        out.append(Verdict(name, "aics-identity", identity_accepts(e, e["protected"]["created"]) is (
            case["expect"] == "valid"), ids, "verify_envelope"))
        out.append(Verdict(name, "aics-identity", idenv.envelope_hash(e) == case["envelope_hash"], ids,
                           "envelope_hash"))
    chain = f["chain"]
    out.append(Verdict("envelopes.json chain", "aics-conformance", history_breaks_at(chain["envelopes"]) is None,
                       chain.get("findings", []), "History"))
    out.append(Verdict("envelopes.json chain", "aics-identity", idenv.chain_breaks(chain["envelopes"]) == [],
                       chain.get("findings", []), "chain_breaks"))
    for case in f["tampered"]:
        name = f"envelopes.json tampered[{case['name']}]"
        out.append(Verdict(name, "aics-conformance", not outcome(lambda: protocol.verify_signature(case["envelope"]),
                                                                 *refusal), [], "verify_signature"))
        out.append(Verdict(name, "aics-identity", not identity_accepts(case["envelope"], aicslog.T0 + 1), [],
                           "verify_envelope"))
    for case in f["chain_breaks"]:
        name, ids, pos = f"envelopes.json chain_breaks[{case['name']}]", case.get("findings", []), \
            case["first_invalid_position"]
        out.append(Verdict(name, "aics-conformance", history_breaks_at(case["envelopes"]) == pos, ids, "History"))
        first = min((b.position for b in idenv.chain_breaks(case["envelopes"])), default=None)
        out.append(Verdict(name, "aics-identity", first == pos, ids, f"chain_breaks first position {first}"))
    for case in f["seen"]:
        name, ids, valid = f"envelopes.json seen[{case['name']}]", case.get("findings", []), case["expect"] == "valid"
        env = spec.native_envelope(spec.test_key(generate.ED25519["envelope_alice"]), origin=f["origin"],
                                   typ="name.claim", payload=generate._claim_payload(
                                       spec.test_key(generate.ED25519["envelope_alice"])), created=aicslog.T0,
                                   nonce=bytes(16))
        env["protected"]["seen"] = case["seen"]
        out.append(Verdict(name, "aics-conformance", outcome(
            lambda: schema.validate_entry(spec.entry(env, aicslog.T0), f["origin"]), ValueError) is valid, ids,
            "schema"))
        out.append(Verdict(name, "aics-identity", outcome(
            lambda: idenv.validate_chain_fields({"seq": 0, "prev": None, "seen": case["seen"]}),
            idenv.MalformedEnvelope) is valid, ids, "validate_chain_fields"))
    for case in f["freshness"]:
        name, ids, valid = f"envelopes.json freshness[{case['name']}]", case.get("findings", []), \
            case["expect"] == "valid"
        raw = [spec.J(spec.entry(case["envelope"], case["t"]))]
        out.append(Verdict(name, "aics-conformance", outcome(lambda: verify.History(raw, policy), ValueError) is valid,
                           ids, "History"))
        out.append(Verdict(name, "aics-identity", identity_accepts(case["envelope"], case["t"]) is valid, ids,
                           "verify_envelope (defaults)"))
    for i, case in enumerate(f["text"]):
        name = f"envelopes.json text[{i}]"
        out.append(Verdict(name, "aics-conformance", outcome(lambda: protocol.verify_signature(case["envelope"]),
                                                             *refusal) is (case["expect"] == "valid"),
                           case.get("findings", []), "verify_signature", shares=("aics-identity",)))
    assert_annotated(out)


def test_http_signature_cases():
    from aics_conformance.fakes.server import FakeServer
    from aics_identity import http_signatures as hs
    from aics_identity import keys

    f = load("http-signatures.json")
    p = f["envelope"]["protected"]
    out = []
    for case in f["cases"]:
        name, ids, valid = f"http-signatures.json cases[{case['name']}]", case.get("findings", []), \
            case["expect"] == "valid"
        body = case["body_text"].encode()
        try:  # verify_request with the AICS server policy, then the caller's binding to the envelope (§12.1)
            [v] = hs.verify_request(case["method"], case["url"], case["headers"], body, resolve_key=keys.parse_did_key,
                                    now=f["now"], **hs.AICS_VERIFY_POLICY)
            ok = (v.keyid, v.nonce, v.created, v.expires) == (p["kid"], p["nonce"], p["created"], p["expires"])
        except hs.SignatureError:
            ok = False
        out.append(Verdict(name, "aics-identity", ok is valid, ids, "verify_request(**AICS_VERIFY_POLICY)"))
        server = FakeServer()  # the conformance binding, called as FakeServer.request calls it (with the bytes)
        server.now = f["now"]
        obj = spec.strict_json(body)
        r = server.submit(obj["envelope"], None if obj["body"] is None else spec.dU64(obj["body"]), case["headers"],
                          case["url"], content=body)
        reason = "accepted" if r.status == 202 else json.loads(r.body)["entry"]["payload"]["reason_code"]
        if reason not in ("accepted", "bad_signature"):
            pytest.fail(f"the conformance fake refused {case['name']} for another reason: {reason}")
        out.append(Verdict(name, "aics-conformance", (reason == "accepted") is valid, ids, "fake server binding",
                           shares=("aics-identity",)))
    assert_annotated(out)


def test_sealed_cases():
    from aics_conformance import protocol
    from aics_identity import sealed
    from nacl.public import PrivateKey

    f = load("sealed.json")
    secret = bytes.fromhex(f["recipient"]["x25519_secret_hex"])
    out = []
    for case in f["cases"]:
        name, ids, valid = f"sealed.json cases[{case['name']}]", case.get("findings", []), case["expect"] == "valid"
        ct = bytes.fromhex(case["ciphertext_hex"])
        ok = outcome(lambda: protocol.open_message(case["envelope"], ct, PrivateKey(secret)), ValueError)
        out.append(Verdict(name, "aics-conformance", ok is valid, ids, "open_message"))
        ok = outcome(lambda: sealed.open_sealed(ct, secret, envelope=case["envelope"],
                                                recipient_kid=f["recipient"]["kid"]), sealed.SealedError)
        out.append(Verdict(name, "aics-identity", ok is valid, ids, "open_sealed"))
    assert_annotated(out)


def test_tlog_cases(tmp_path):
    from aics_cli.checkpoints import Cp
    from aics_cli.consistency import GivenProof, relate
    from aics_conformance import verify
    from aics_tlog import (FileSystemTileReader, VerifiedTileReader, WitnessPolicy, parse_checkpoint, parse_note,
                           parse_vkey, verify_checkpoint, verify_consistency, verify_inclusion)

    f = load("tlog/log.json")
    out = []

    def verdicts(name, note, now, witnesses, quorum, valid, ids):
        res = verify_checkpoint(parse_note(note), parse_vkey(f["log_vkey"]), policy=WitnessPolicy(
            quorum, tuple(parse_vkey(w) for w in witnesses), 300), now=now)  # the third-party default bound
        out.append(Verdict(name, "aics-tlog", res.ok is valid, ids, "verify_checkpoint(policy=...)"))
        policy = drivers.conformance_policy(f["trust_bundle"], witnesses=witnesses, quorum=quorum)
        out.append(Verdict(name, "aics-conformance", outcome(lambda: verify.head(note, policy, now), ValueError)
                           is valid, ids, "verify.head", shares=("aics-tlog",)))
        cli = drivers.AicsCli(home=tmp_path / f"home-{next(_homes)}", now=now)
        if cli.pin(spec.readme_block(spec.J(f["trust_bundle"])), witnesses=witnesses, quorum=quorum).code != 0:
            pytest.fail("aics policy init failed")
        path = tmp_path / f"note-{next(_homes)}.txt"
        path.write_bytes(note)
        r = cli.run("verify", "checkpoint", "--note", str(path), "--no-save")
        out.append(Verdict(name, "aics", cli_verdict(r, "verify checkpoint") is valid, ids, "verify checkpoint",
                           shares=("aics-tlog",)))

    for size, n in f["notes"].items():
        verdicts(f"tlog/log.json notes[{size}]", n["note_text"].encode(), n["cosigned_at"] + 10, f["witness_vkeys"], 2,
                 True, [])
    nc = f["note_cases"]
    pol = nc["policy"]
    for c in nc["freshness"]:
        verdicts(f"tlog/log.json note_cases.freshness[{c['age']}]", nc["single_witness_note_text"].encode(), c["now"],
                 pol["witness_vkeys"], pol["quorum"], c["expect"] == "valid", c.get("findings", []))
    for key in ("repeated_unknown_key_lines", "repeated_log_key_line", "invalid_pinned_cosignature"):
        c = nc[key]
        verdicts(f"tlog/log.json note_cases.{key}", c["note_text"].encode(), c["now"], pol["witness_vkeys"],
                 pol["quorum"], c["expect"] == "valid", c.get("findings", []))
    for c in f["inclusion"]:
        ok = verify_inclusion(bytes.fromhex(c["leaf_hash_hex"]), c["index"], c["size"],
                              [spec.dB64(h) for h in c["proof_b64"]], spec.dB64(c["root_b64"]))
        out.append(Verdict(f"tlog/log.json inclusion[{c['index']},{c['size']}]", "aics-tlog", ok, [],
                           "verify_inclusion"))
    for c in f["consistency"]:
        old, new, proof = spec.dB64(c["old_root_b64"]), spec.dB64(c["new_root_b64"]), [spec.dB64(h) for h in
                                                                                     c["proof_b64"]]
        name = f"tlog/log.json consistency[{c['old']},{c['new']}]"
        out.append(Verdict(name, "aics-tlog", verify_consistency(c["old"], c["new"], old, new, proof), [],
                           "verify_consistency"))
        rel = relate(Cp("", f["origin"], c["old"], old, "old"), Cp("", f["origin"], c["new"], new, "new"),
                     [GivenProof("fixture", proof)])
        out.append(Verdict(name, "aics", rel.status == "consistent", [], "relate", shares=("aics-tlog",)))
    head = (FIXTURES / "tlog" / "tiles" / "checkpoint").read_bytes()
    cp = parse_checkpoint(parse_note(head).text)
    entries = spec.verify_tiles(generate.existing(FIXTURES / "tlog" / "tiles"), cp.size, cp.root)
    reader = VerifiedTileReader(FileSystemTileReader(FIXTURES / "tlog" / "tiles"), cp.size, cp.root)
    out.append(Verdict("tlog/tiles", "aics-tlog", [reader.entry(i) for i in range(cp.size)] == entries, [],
                       "VerifiedTileReader"))
    assert_annotated(out)


def _cli_relation(r: drivers.CliResult) -> str:
    if r.code in (0, 2):
        return {0: "consistent", 2: "split-proven"}[r.code]
    error = r.data.get("error", "")
    return "not-evidence" if "is not evidence" in error else \
        "consistency-unproven" if error.startswith("consistency-unproven") else f"other: {error}"


def _g5_relation(row: dict) -> str:
    if row["verdict"] == "pass":
        return "consistent"
    d = row["details"]
    reason = d.get("reason", "")
    if reason.startswith("split-proven") and d["verification"] == "invalid":
        return "split-proven"
    if d["verification"] == "incomplete":
        return "consistency-unproven"
    return "not-evidence" if "no signature from log key" in reason else f"other: {reason}"


def test_split_view_cases(tmp_path):
    from aics_interop.transport import FakeWeb

    f = load("split-view.json")
    trust = load("tlog/log.json")["trust_bundle"]
    out = []
    for case in f["fixtures"]:
        name, ids, relation = f"split-view.json fixtures[{case['name']}]", case.get("findings", []), \
            case["expect"]["relation"]
        web = FakeWeb()
        for source, note in (("origin", case["note_1_text"]), ("mirror", case["note_2_text"])):
            served = case["served"][source]
            tiles = f["trees"].get(served["tiles"]) or {}
            web.serve_log(served["prefix"], note.encode(), {p: spec.dU64(d) for p, d in tiles.items()})
        policy = case["policy"]
        cli = drivers.AicsCli(home=tmp_path / f"home-{next(_homes)}", web=web, now=case["now"])
        if cli.pin(spec.readme_block(spec.J(trust)), witnesses=policy["witness_vkeys"], quorum=policy["quorum"],
                   mirrors=[case["served"]["mirror"]["prefix"]]).code != 0:
            pytest.fail("aics policy init failed")
        paths = []
        for i, note in enumerate((case["note_1_text"], case["note_2_text"])):
            paths.append(tmp_path / f"{case['name']}-{i}.txt")
            paths[-1].write_text(note, "utf-8")
        r = cli.run("gossip-check", *map(str, paths))
        agrees = _cli_relation(r) == relation and r.code == case["aics_gossip_check"]["exit"] and (
            case["aics_gossip_check"]["classification"] is None
            or r.data.get("classification") == case["aics_gossip_check"]["classification"])
        out.append(Verdict(name, "aics", agrees, ids, "gossip-check", shares=("aics-tlog",)))
        cpolicy = drivers.conformance_policy(trust, witnesses=policy["witness_vkeys"], quorum=policy["quorum"],
                                             mirrors=[case["served"]["mirror"]["prefix"]])
        row = drivers.run_conformance_check("G5", drivers.conformance_context(web, cpolicy, case["now"]))
        out.append(Verdict(name, "aics-conformance", _g5_relation(row) == relation, ids, "G5", shares=("aics-tlog",)))
    assert_annotated(out)


def test_bundle_cases():
    from aics_conformance import verify
    from aics_tlog import Bundle, WitnessPolicy, parse_vkey, verify_bundle

    f = load("bundles.json")
    pkg = f["aics1_package"]
    prefix = [spec.dU64(e) for e in pkg["package"]["entry_prefix"]]
    policy = drivers.conformance_policy(pkg["package"]["trust_bundle"], witnesses=f["witness_vkeys"],
                                        quorum=f["quorum"])
    tlog_policy = WitnessPolicy(f["quorum"], tuple(parse_vkey(w) for w in f["witness_vkeys"]), None)
    now = load("tlog/log.json")["note_cases"]["cosigned_at"] + 3600
    out = []

    def tlog_accepts(b) -> bool:
        try:
            return verify_bundle(Bundle.from_dict(b), parse_vkey(f["log_vkey"]), policy=tlog_policy).ok
        except ValueError:  # Bundle.from_dict: not a §14.3 wire bundle
            return False

    # aics-conformance refuses with ValueError (schema.require) or, for a bundle without entry_bytes (the pre-0.2
    # aics-tlog form), with KeyError
    cases = [("aics1_wire_bundle", f["aics1_wire_bundle"]),
             ("legacy_aics_tlog_bundle", f["legacy_aics_tlog_bundle"])] + [
        (f"tampered_wire_bundles[{t['name']}]", t) for t in f["tampered_wire_bundles"]]
    for key, case in cases:
        name, ids, valid = f"bundles.json {key}", case.get("findings", []), case["expect"] == "valid"
        ok = outcome(lambda: verify.bundle(case["bundle"], policy, now, prefix=prefix), ValueError, KeyError)
        out.append(Verdict(name, "aics-conformance", ok is valid, ids, "verify.bundle", shares=("aics-tlog",)))
        out.append(Verdict(name, "aics-tlog", tlog_accepts(case["bundle"]) is valid, ids, "verify_bundle"))
    ok = outcome(lambda: verify.offline_package(pkg["package"], policy, now), ValueError, KeyError)
    out.append(Verdict("bundles.json aics1_package", "aics-conformance", ok is (pkg["expect"] == "valid"),
                       pkg.get("findings", []), "offline_package", shares=("aics-tlog",)))
    assert_annotated(out)


def test_trust_bundle_cases():
    from aics_cli.dnstxt import parse_response
    from aics_cli.errors import PolicyError
    from aics_cli.trust import bundle_from_jcs, bundle_from_text, bundle_from_u64, parse_txt

    f = load("trust-bundle.json")
    raw = f["jcs"].encode()
    out = [Verdict("trust-bundle.json jcs", "aics", outcome(lambda: bundle_from_jcs(raw), PolicyError), [],
                   "bundle_from_jcs", shares=("aics-identity",)),
           Verdict("trust-bundle.json readme_block", "aics",
                   outcome(lambda: bundle_from_text(f["readme_block"]), PolicyError), [], "bundle_from_text"),
           Verdict("trust-bundle.json txt_record", "aics", parse_txt([f["txt_record"]]).bundle.jcs == raw, [],
                   "parse_txt")]
    _, _, records = parse_response(bytes.fromhex(f["dns"]["response_hex"]), f["dns"]["qid"], f["dns"]["qname"])
    out.append(Verdict("trust-bundle.json dns", "aics", parse_txt([r.decode() for r in records]).bundle.jcs == raw,
                       [], "dnstxt.parse_response"))
    out.append(Verdict("trust-bundle.json bundle", "aics-conformance", outcome(
        lambda: drivers.conformance_policy(f["bundle"]), ValueError), [], "Policy"))
    for case in f["invalid"]:
        name, ids = f"trust-bundle.json invalid[{case['name']}]", case.get("findings", [])
        if "jcs" in case:
            out.append(Verdict(name, "aics", not outcome(lambda: bundle_from_jcs(case["jcs"].encode()), PolicyError),
                               ids, "bundle_from_jcs"))
            # aics-conformance reads the operator's trust-bundle.json as a JSON object (Policy.load)
            out.append(Verdict(name, "aics-conformance", not outcome(
                lambda: drivers.conformance_policy(spec.strict_json(case["jcs"])), ValueError), ids, "Policy"))
        else:  # published bytes (TXT, README, PyPI): aics-conformance has no consumer for them
            out.append(Verdict(name, "aics", not outcome(lambda: bundle_from_u64(case["bytes_u64"]), PolicyError),
                               ids, "bundle_from_u64"))
    wrong = f["readme_block_wrong_digest"]
    out.append(Verdict("trust-bundle.json readme_block_wrong_digest", "aics", not outcome(
        lambda: bundle_from_text(wrong["text"]), PolicyError), wrong.get("findings", []), "bundle_from_text"))
    assert_annotated(out)


def test_card_cases(tmp_path):
    from aics_conformance.card import verify_card
    from aics_interop.transport import FakeWeb

    f = load("card.json")
    now = aicslog.T0 + 3600 + 10
    out = []
    cases = [("card", f["card"]), ("card_0_1_draft", f["card_0_1_draft"]), ("altered", f["altered"])] + [
        (f"registry[{c['name']}]", c) for c in f["registry"]]
    for key, case in cases:
        name, ids, valid, card = f"card.json {key}", case.get("findings", []), case["expect"] == "valid", case["card"]
        trust = {**f["trust_bundle"], "bootstrap_card_hash": spec.card_hash(card)}  # the case's own card pinned
        home = tmp_path / f"home-{next(_homes)}"
        cli = drivers.AicsCli(home=home, now=now)
        if cli.pin(spec.readme_block(spec.J(trust)), quorum=0).code != 0:
            pytest.fail("aics policy init failed")
        (home / "card.json").write_text(json.dumps(card))
        r = cli.run("verify", "card", "--file", str(home / "card.json"))
        out.append(Verdict(name, "aics", cli_verdict(r, "verify card") is valid, ids, "verify card"))
        web = FakeWeb()
        log = aicslog.standard_log(5, card=card)
        web.serve_log(aicslog.PREFIX, log.note(5), log.tiles(5))
        ctx = drivers.conformance_context(web, drivers.conformance_policy(trust), now)
        ok = outcome(lambda: verify_card(ctx, card), ValueError, InvalidSignature)
        out.append(Verdict(name, "aics-conformance", ok is valid, ids, "verify_card"))
    assert_annotated(out)


def test_receipt_cases():
    from aics_conformance import verify

    f = load("receipts.json")
    entry = spec.strict_json(spec.dU64(f["entry_u64"]))
    policy = drivers.conformance_policy(load("tlog/log.json")["trust_bundle"])
    out = [Verdict("receipts.json receipt_text", "aics-conformance", outcome(
        lambda: verify.receipt(f["receipt_text"].encode(), entry, policy), ValueError) is (f["expect"] == "valid"),
        f.get("findings", []), "verify.receipt", shares=("aics-tlog",))]
    for case in f["invalid"]:
        out.append(Verdict(f"receipts.json invalid[{case['name']}]", "aics-conformance", outcome(
            lambda: verify.receipt(case["receipt_text"].encode(), entry, policy), ValueError) is (
            case["expect"] == "valid"), case.get("findings", []), "verify.receipt", shares=("aics-tlog",)))
    assert_annotated(out)


def test_appendix_a_values():
    from aics_conformance import protocol, verify
    from aics_identity import envelope as idenv
    from aics_identity import sealed
    from aics_tlog import MerkleTree, parse_note, parse_vkey, verify_checkpoint
    from nacl.public import PrivateKey

    from aics_interop import appendix_a

    f = load("appendix-a.json")
    notes = f.get("findings", {})
    env = spec.strict_json(f["envelope_jcs"])
    ct = bytes.fromhex(f["ciphertext_hex"])
    bob = bytes([appendix_a.X25519_SEEDS["bob"]]) * 32
    entries = [spec.dU64(e) for e in f["entries_u64"]]
    out = [
        Verdict("appendix-a.json inline.envelope_hash", "aics-identity",
                idenv.envelope_hash(env) == f["inline"]["envelope_hash"], notes.get("inline.envelope_hash", []),
                "envelope_hash"),
        Verdict("appendix-a.json inline.signing_digest", "aics-identity",
                idenv.envelope_signing_digest(env["protected"], env["payload"]).hex() == f["inline"]["signing_digest"],
                notes.get("inline.signing_digest", []), "envelope_signing_digest"),
        Verdict("appendix-a.json ciphertext_hex", "aics-identity", outcome(
            lambda: sealed.open_sealed(ct, bob, envelope=env, recipient_kid=env["payload"]["to_kid"]),
            sealed.SealedError), notes.get("ciphertext_hex", []), "open_sealed"),
        Verdict("appendix-a.json ciphertext_hex", "aics-conformance",
                protocol.open_message(env, ct, PrivateKey(bob)) == b"hello\n", notes.get("ciphertext_hex", []),
                "open_message"),
        Verdict("appendix-a.json root_hex", "aics-tlog", MerkleTree(entries).root().hex() == f["root_hex"],
                notes.get("root_hex", []), "MerkleTree"),
        Verdict("appendix-a.json entries_u64", "aics-conformance", outcome(lambda: verify.History(
            entries, drivers.conformance_policy(f["trust_bundle"])), ValueError), notes.get("entries_u64", []),
            "History"),
    ]
    res = verify_checkpoint(parse_note(f["checkpoint_text"].encode()), parse_vkey(f["inline"]["log_vkey"]),
                            [parse_vkey(f["inline"]["witness_vkey"])], 1, now=int(f["inline"]["witness_timestamp"]) + 10,
                            max_age_seconds=300, max_future_seconds=30)
    out.append(Verdict("appendix-a.json checkpoint_text", "aics-tlog", res.ok, notes.get("checkpoint_text", []),
                       "verify_checkpoint"))
    assert set(notes) <= {v.case.split(" ", 1)[1] for v in out}, "findings name values that are not checked"
    assert_annotated(out)


def test_every_annotated_finding_is_open():
    """The fixtures name only open findings, in a ``findings`` member (a list, or in appendix-a.json a mapping)."""
    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "findings" and isinstance(v, (list, dict)):  # manifest.json's conventions describe it
                    yield from (v if isinstance(v, list) else itertools.chain.from_iterable(v.values()))
                else:
                    yield from walk(v)
        elif isinstance(node, list):
            for v in node:
                yield from walk(v)

    used = set()
    for path in sorted(FIXTURES.rglob("*.json")):
        used |= set(walk(json.loads(path.read_text("utf-8"))))
    open_ids = {fid for fid, f in findings.FINDINGS.items() if f.open}
    assert used <= open_ids, sorted(used - open_ids)  # a retired finding explains no disagreement (``covered``)

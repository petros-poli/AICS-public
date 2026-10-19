"""Generate the AICS-1 interop fixtures in ``packages/aics-interop/fixtures``.

    uv run aics-interop-fixtures            # (re)write the fixtures
    uv run aics-interop-fixtures --check    # exit 1 if the committed fixtures differ

Every artifact is built from deliberately public test keys and fixed clocks,
by the suite's reference implementation (:mod:`aics_interop.spec`) and, for
the log, by aics-tlog (tiles, notes) and aics-witness (cosignatures).  Two
runs produce identical bytes.  ``expect`` is always the AICS-1 verdict;
``findings`` names the open findings (README "Findings") under which a
package of this repository currently disagrees with the case: with its
verdict, or with a value it carries (an envelope hash, a first invalid
position).  ``tests/test_fixture_verdicts.py`` runs the packages over every
case and requires each disagreement to be named here.  The fixtures are for
other implementations (clients/aics-js), so they carry raw values, not
Python objects.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import aicslog, appendix_a, spec, world

FORMAT = "aics-interop-fixtures/v1"
PACKAGE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_OUT = PACKAGE_DIR / "fixtures"
T = aicslog.T0
ORIGIN = aicslog.ORIGIN

CONVENTIONS = {
    "*_hex": "lowercase hexadecimal bytes",
    "*_b64": "canonical padded standard base64 (AICS-1 B64)",
    "*_u64": "canonical unpadded base64url (AICS-1 U64)",
    "*_text": "UTF-8 text, exact (signed notes end with LF)",
    "jcs": "the exact RFC 8785 bytes as a UTF-8 string, no trailing LF",
    "times": "Unix seconds (AICS-1 time)",
    "expect": "the AICS-1 verdict a conforming implementation reaches: valid | invalid, or a §14.6 relation",
    "findings": "README findings under which a package in this repository currently disagrees with the case: its "
                "expect, or a value it carries (in appendix-a.json: value name -> findings)",
    "keys": "keys.json: Ed25519 seeds are 32 repeats of one byte; X25519 secrets likewise; public test keys only",
}


def dump(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def jcs(obj: Any) -> str:
    return spec.J(obj).decode("utf-8")


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------

ED25519 = {"log": 0x21, "policy": 0x22, "owner": 0x23, "witness_a": 0x24, "witness_b": 0x25, "other_log": 0x2F,
           "agent0": 0x31, "agent1": 0x32, "unknown_note_signer": 0x5A, "linesig": 0x61, "envelope_alice": 0x71,
           "http_agent": 0x81, "dm_alice": 0x91, "dm_bob": 0x92, "dm_mallory": 0x93}
X25519 = {"agent0": 0x41, "agent1": 0x42, "envelope_alice": 0x72, "http_agent": 0x82, "dm_bob": 0x94,
          "dm_ephemeral": 0x95}


def keys_fixture() -> dict[str, Any]:
    ed = {}
    for name, seed in ED25519.items():
        k = spec.test_key(seed)
        raw = spec.raw_public(k)
        ed[name] = {"seed_hex": (bytes([seed]) * 32).hex(), "public_hex": raw.hex(), "public_u64": spec.U64(raw),
                    "public_b64": spec.B64(raw), "kid": spec.kid(k)}
    ed["log"]["vkey"] = aicslog.Keys().log_vkey()
    ed["other_log"]["vkey"] = spec.vkey(ORIGIN, 0x01, spec.raw_public(spec.test_key(ED25519["other_log"])))
    for w in world.WITNESSES:
        ed[w]["name"] = aicslog.WITNESS_NAMES[w]
        ed[w]["vkey"] = aicslog.witness_vkey(w)
    x = {}
    for name, seed in X25519.items():
        secret = bytes([seed]) * 32
        pub = spec.x25519_public(secret)
        x[name] = {"secret_hex": secret.hex(), "public_hex": pub.hex(), "public_u64": spec.U64(pub),
                   "did": spec.x25519_did(pub)}
    return {"note": CONVENTIONS["keys"], "origin": ORIGIN, "ed25519": ed, "x25519": x}


# ---------------------------------------------------------------------------
# §11.3 line signatures
# ---------------------------------------------------------------------------


def linesig_fixture() -> dict[str, Any]:
    key = spec.test_key(ED25519["linesig"])
    raw_pub = spec.raw_public(key)
    u = spec.unsigned_text_envelope(key, origin=ORIGIN, typ="post", created=T, nonce=bytes(range(16)),
                                    session="c2Vzc2lvbi1pZC0xMjM0NQ",
                                    payload={"channel_sha256": spec.hexH(b"interop"), "parent_index": None,
                                             "body_hash": spec.hexH(b"x"), "size": 1, "title_sha256": None})
    cases = []
    for session, line in (("c2Vzc2lvbi1pZC0xMjM0NQ", spec.text_command(u)),
                          ("-starts-with-dash", "claim agent0 " + "ab" * 32), ("s", "help")):
        msg = spec.line_message(session, line)
        sig = key.sign(msg)
        blob = spec.sshsig_blob(msg, key)
        cases.append({"name": f"valid:{session[:8]}", "session": session, "line": line,
                      "signing_input_hex": msg.hex(), "signature_b64": spec.B64(sig),
                      "reply": f"sig {spec.B64(sig)}", "sshsig_armored": spec.sshsig_armor(blob),
                      "sshsig_blob_u64": spec.U64(blob), "expect": "valid"})
    session, line = cases[0]["session"], cases[0]["line"]
    msg = spec.line_message(session, line)
    cases.append({"name": "trailing-lf", "session": session, "line": line,
                  "signing_input_hex": (msg + b"\n").hex(), "signature_b64": spec.B64(key.sign(msg + b"\n")),
                  "expect": "invalid", "reason": "§11.3: the signature input has no final LF",
                  "findings": ["F26"]})  # aics verify-line accepts it unless --strict
    cases.append({"name": "other-session", "session": session, "line": line,
                  "signature_b64": spec.B64(key.sign(spec.line_message(session + "x", line))), "expect": "invalid",
                  "reason": "signed for another session"})
    return {"public_key_hex": raw_pub.hex(), "pub_reply": "pub " + spec.B64(raw_pub),
            "ssh_public_key": "ssh-ed25519 " + spec.B64(spec.ssh_public_key_blob(raw_pub)), "namespace": "aics",
            "unsigned_envelope": u, "cases": cases}


# ---------------------------------------------------------------------------
# §4 envelopes and §11.3 text envelopes
# ---------------------------------------------------------------------------

SEEN = {"checkpoint_note_hash": "ab" * 32, "size": 7}


def _claim_payload(key, name="alice", x=0x72):
    return {"name_norm": name, "prev_event_index": None, "ed25519": spec.U64(spec.raw_public(key)),
            "x25519": spec.U64(spec.x25519_public(bytes([x]) * 32)), "tier": "verified", "recovery_kid": None,
            "recovery_pop": None, "initial_grant": None}


def _post_payload(text="hello"):
    body = spec.J({"channel": "interop", "title": None, "text": text})
    return {"channel_sha256": spec.hexH(b"interop"), "parent_index": None, "body_hash": spec.hexH(body),
            "size": len(body), "title_sha256": None}


def _nonce(i: int) -> bytes:
    return spec.H(b"envelope-nonce-%d" % i)[:16]


def _chain(key, n=3, seen=SEEN):
    out = []
    for i in range(n):
        typ, q = ("name.claim", _claim_payload(key)) if i == 0 else ("post", _post_payload(f"m{i}"))
        out.append(spec.native_envelope(key, origin=ORIGIN, typ=typ, payload=q, created=T + i, nonce=_nonce(i), seq=i,
                                        prev=spec.envelope_hash(out[-1]) if out else None, seen=seen))
    return out


def envelopes_fixture() -> dict[str, Any]:
    alice = spec.test_key(ED25519["envelope_alice"])
    chain = _chain(alice)
    native = [{"envelope": e, "jcs": jcs(e), "signing_digest_hex": spec.signing_digest(e["protected"],
                                                                                       e["payload"]).hex(),
               "envelope_hash": spec.envelope_hash(e), "entry_jcs": jcs(spec.entry(e, e["protected"]["created"])),
               "expect": "valid"} for e in chain]
    null_seen = _chain(alice, 1, seen=None)[0]
    native.append({"envelope": null_seen, "jcs": jcs(null_seen), "envelope_hash": spec.envelope_hash(null_seen),
                   "expect": "valid", "reason": "§4.1: seen is null for initial bootstrap"})
    valid_chain = {"envelopes": chain, "expect": "valid",
                   "reason": "§4.2: seq 0, 1, 2 and each prev = hexH(J(previous E)); the native envelopes above"}
    tampered = []
    for path, value in ((("protected", "origin"), "evil.example/log"), (("protected", "type"), "dm"),
                        (("payload", "size"), 999), (("protected", "seq"), 9)):
        bad = copy.deepcopy(chain[1])
        bad[path[0]][path[1]] = value
        tampered.append({"name": ".".join(path), "envelope": bad, "expect": "invalid",
                         "reason": "signature does not cover the changed member"})

    def defective(kind):
        envs = _chain(alice)
        if kind == "seq-gap":
            envs[2] = spec.native_envelope(alice, origin=ORIGIN, typ="post", payload=envs[2]["payload"], created=T + 2,
                                           nonce=_nonce(2), seq=3, prev=spec.envelope_hash(envs[1]), seen=SEEN)
        elif kind == "wrong-prev":
            envs[2] = spec.native_envelope(alice, origin=ORIGIN, typ="post", payload=envs[2]["payload"], created=T + 2,
                                           nonce=_nonce(2), seq=2, prev="00" * 32, seen=SEEN)
        elif kind == "fork":
            envs[2] = spec.native_envelope(alice, origin=ORIGIN, typ="post", payload=_post_payload("fork"),
                                           created=T + 2, nonce=_nonce(2), seq=1, prev=spec.envelope_hash(envs[0]),
                                           seen=SEEN)
        else:
            envs[0] = spec.native_envelope(alice, origin=ORIGIN, typ="name.claim", payload=_claim_payload(alice),
                                           created=T, nonce=_nonce(0), seq=1, prev="11" * 32, seen=SEEN)
        return envs

    breaks = [{"name": kind, "envelopes": defective(kind), "first_invalid_position": pos, "expect": "invalid",
               "reason": "§4.2 seq = last_seq + 1 and prev = hexH(J(previous accepted E))"}
              for kind, pos in (("seq-gap", 2), ("wrong-prev", 2), ("fork", 2), ("first-not-zero", 0))]
    seen_cases = [{"name": n, "seen": v, "expect": "valid" if ok else "invalid"} for n, (v, ok) in {
        "valid": (SEEN, True), "null": (None, True),
        "uppercase-hex": ({"checkpoint_note_hash": "AB" * 32, "size": 7}, False),
        "short-hash": ({"checkpoint_note_hash": "ab" * 31, "size": 7}, False),
        "extra-member": ({**SEEN, "note": "x"}, False),
        "missing-size": ({"checkpoint_note_hash": "ab" * 32}, False),
        "bool-size": ({"checkpoint_note_hash": "ab" * 32, "size": True}, False),
        "negative-size": ({"checkpoint_note_hash": "ab" * 32, "size": -1}, False),
        "size-above-uint": ({"checkpoint_note_hash": "ab" * 32, "size": 2 ** 53}, False),
        "array": ([], False)}.items()]
    freshness = []
    for name, (offset, life) in {"now": (0, 300), "future-30": (30, 300), "future-31": (31, 300),
                                 "past-300": (-300, 300), "past-299": (-299, 300), "lifetime-301": (0, 301),
                                 "lifetime-0": (0, 0), "lifetime-1": (0, 1)}.items():
        t = T + 1000
        e = spec.native_envelope(alice, origin=ORIGIN, typ="name.claim", payload=_claim_payload(alice),
                                 created=t + offset, expires=t + offset + life, nonce=_nonce(0), seen=SEEN)
        ok = spec.accepted_at(e["protected"], t)
        case = {"name": name, "t": t, "envelope": e, "expect": "valid" if ok else "invalid",
                "rule": "§4.3 created <= t+30, created >= t-300, created < expires <= created+300, t < expires"}
        freshness.append(case)
    session = spec.U64(b"interop-session!")
    text = []
    for scheme in ("text-ed25519", "text-sshsig"):
        u = spec.unsigned_text_envelope(alice, origin=ORIGIN, typ="post", payload=_post_payload(), created=T,
                                        nonce=_nonce(9), session=session, scheme=scheme)
        command = spec.text_command(u)
        msg = spec.line_message(session, command)
        sig = alice.sign(msg) if scheme == "text-ed25519" else spec.sshsig_blob(msg, alice)
        text.append({"scheme": scheme, "unsigned": u, "command": command, "signing_input_hex": msg.hex(),
                     "envelope": {**u, "sig": spec.U64(sig)}, "expect": "valid"})
    claim_u = spec.unsigned_text_envelope(alice, origin=ORIGIN, typ="name.claim", payload=_claim_payload(alice),
                                          created=T, nonce=_nonce(9), session=session)
    text.append({"scheme": "text-ed25519", "unsigned": claim_u, "command": spec.text_command(claim_u),
                 "envelope": {**claim_u, "sig": spec.U64(alice.sign(spec.line_message(session,
                                                                                      spec.text_command(claim_u))))},
                 "expect": "valid", "reason": "§11.3 short claim command: claim <name_norm> <hexH(J(U))>"})
    swapped = copy.deepcopy(text[1]["envelope"])
    swapped["auth"]["scheme"] = "text-ed25519"
    text.append({"scheme": "text-ed25519", "envelope": swapped, "expect": "invalid",
                 "reason": "an SSHSIG blob is not a raw Ed25519 signature"})
    return {"origin": ORIGIN, "native": native, "chain": valid_chain, "tampered": tampered, "chain_breaks": breaks,
            "seen": seen_cases, "freshness": freshness, "text": text}


# ---------------------------------------------------------------------------
# §12.1 RFC 9421 request signatures
# ---------------------------------------------------------------------------


def _sign_request(env: dict, body: bytes, url: str, key, **over) -> dict[str, str]:
    p = env["protected"]
    params = spec.signature_params(created=over.get("created", p["created"]), expires=over.get("expires", p["expires"]),
                                   nonce=over.get("nonce", p["nonce"]), keyid=over.get("keyid", p["kid"]))
    headers = {"Content-Type": "application/json", "Content-Digest": spec.content_digest(body)}
    base = spec.signature_base("POST", url, headers, params, spec.AICS_COMPONENTS)
    label = over.get("label", "aics")
    return {**headers, "Signature-Input": f"{label}={params}", "Signature": f"{label}=:{spec.B64(key.sign(base))}:"}


def http_fixture() -> dict[str, Any]:
    key = spec.test_key(ED25519["http_agent"])
    url = "https://api.interop.test/v2/entries"
    q = _claim_payload(key, "http0", 0x82)
    env = spec.native_envelope(key, origin=ORIGIN, typ="name.claim", payload=q, created=T, nonce=spec.H(b"http-0")[:16])
    body = spec.J({"envelope": env, "body": None})
    headers = _sign_request(env, body, url, key)
    member = headers["Signature-Input"][len("aics="):]
    pretty = json.dumps({"envelope": env, "body": None}, indent=1).encode()
    cases = [{"name": "valid", "method": "POST", "url": url, "headers": headers, "body_text": body.decode(),
              "signature_base_text": spec.signature_base("POST", url, headers, member,
                                                         spec.AICS_COMPONENTS).decode(),
              "expect": "valid"},
             {"name": "pretty-json-body", "method": "POST", "url": url, "headers": _sign_request(env, pretty, url, key),
              "body_text": pretty.decode(), "expect": "valid",
              "reason": "§12.1: Content-Digest is over the actual HTTP content bytes"}]
    flipped = bytearray(spec.dB64(headers["Signature"][len("aics=:"):-1]))
    flipped[10] ^= 1
    for name, h, b, u in (
            ("body-changed", headers, body + b" ", url),
            ("path-changed", headers, body, url.replace("/v2/entries", "/v2/entries2")),
            ("digest-header-changed", {**headers, "Content-Digest": spec.content_digest(b"other")}, body, url),
            ("signature-bit", {**headers, "Signature": f"aics=:{spec.B64(bytes(flipped))}:"}, body, url),
            ("params-changed", {**headers, "Signature-Input": headers["Signature-Input"].replace("created=",
                                                                                                "created=1")}, body,
             url)):
        cases.append({"name": name, "method": "POST", "url": u, "headers": h, "body_text": b.decode(),
                      "expect": "invalid"})
    p = env["protected"]
    for name, over in (("nonce-differs", {"nonce": spec.U64(bytes(16))}), ("created-differs", {"created": T - 1}),
                       ("expires-differs", {"expires": p["expires"] - 1}),
                       ("keyid-differs", {"keyid": spec.kid(spec.test_key(0x83))}), ("label-not-aics",
                                                                                     {"label": "sig1"})):
        cases.append({"name": f"binding:{name}", "method": "POST", "url": url, "headers": _sign_request(env, body, url,
                                                                                                        key, **over),
                      "body_text": body.decode(), "expect": "invalid",
                      "reason": "§12.1: times, nonce and keyid equal the envelope values; one label 'aics'"})
    return {"components": list(spec.AICS_COMPONENTS), "public_key_hex": spec.raw_public(key).hex(), "envelope": env,
            "now": T, "cases": cases}


# ---------------------------------------------------------------------------
# §8.1 sealed messages
# ---------------------------------------------------------------------------


def sealed_fixture() -> dict[str, Any]:
    alice, bob, mallory = (spec.test_key(ED25519[n]) for n in ("dm_alice", "dm_bob", "dm_mallory"))
    bob_x = bytes([X25519["dm_bob"]]) * 32
    bob_xpub = spec.x25519_public(bob_x)
    eph = bytes([X25519["dm_ephemeral"]]) * 32
    nonce = spec.H(b"sealed-nonce")[:16]
    content = "hello, Bob — private\n".encode("utf-8")
    seen = {"checkpoint_note_hash": "cd" * 32, "size": 3}

    def envelope(ct, *, key=alice, to=bob, n=nonce):
        q = {"to_kid": spec.kid(to), "to_key_leaf_index": 2, "encryption": "x25519-xsalsa20-poly1305",
             "eph_pk": spec.U64(ct[:32]), "ct_hash": spec.hexH(ct), "size": len(ct), "seq": 1, "prev": "ef" * 32,
             "grant_index": 2}
        return spec.native_envelope(key, origin=ORIGIN, typ="dm", payload=q, created=T, nonce=n, seq=1,
                                    prev="ef" * 32, seen=seen)

    def seal(frm=alice, to=bob, n=nonce, framing=spec.aics1_plaintext):
        header = spec.inner_header(spec.kid(frm), spec.kid(to), spec.U64(n))
        pt = framing(header, content)
        return header, pt, spec.deterministic_seal(pt, bob_xpub, eph)

    header, pt, ct = seal()
    cases = [{"name": "valid", "envelope": envelope(ct), "header_jcs": header.decode(), "plaintext_hex": pt.hex(),
              "ciphertext_hex": ct.hex(), "content_text": content.decode(), "expect": "valid"}]
    for field, kw in (("from_kid", {"frm": mallory}), ("to_kid", {"to": mallory}),
                      ("envelope_nonce", {"n": bytes(16)})):
        h, p, c = seal(**kw)
        cases.append({"name": f"inner-header:{field}", "envelope": envelope(c), "header_jcs": h.decode(),
                      "ciphertext_hex": c.hex(), "expect": "invalid", "reason": "inner-header binding mismatch"})
    for name, env in (("rewrap:sender", envelope(ct, key=mallory)), ("rewrap:recipient", envelope(ct, to=mallory)),
                      ("rewrap:nonce", envelope(ct, n=bytes(range(16))))):
        cases.append({"name": name, "envelope": env, "ciphertext_hex": ct.hex(), "expect": "invalid",
                      "reason": "§8.1: rewrapping someone else's ciphertext in a newly signed envelope"})
    h, p, c = seal(framing=spec.jcs_lf_plaintext)
    cases.append({"name": "framing:jcs-lf-body", "envelope": envelope(c), "plaintext_hex": p.hex(),
                  "ciphertext_hex": c.hex(), "expect": "invalid",
                  "reason": "not the §8.1 uint32be(len) || header || content framing (JCS(header) || LF || content, "
                            "which aics-identity sealed until F05 was fixed)"})
    over = spec.deterministic_seal(b"\x00\x00\x13\x88" + header + content, bob_xpub, eph)
    cases.append({"name": "framing:header-length-5000", "envelope": envelope(over), "ciphertext_hex": over.hex(),
                  "expect": "invalid", "reason": "§8.1 header length at most 4096 and fully contained"})
    return {"recipient": {"x25519_secret_hex": bob_x.hex(), "x25519_public_hex": bob_xpub.hex(),
                          "kid": spec.kid(bob)},
            "ephemeral_secret_hex": eph.hex(), "note": "deterministic test ephemeral key (Appendix A.5 technique)",
            "cases": cases}


# ---------------------------------------------------------------------------
# §6 the log, §14.1-14.2
# ---------------------------------------------------------------------------

INCLUSION = [(0, 1), (0, 3), (2, 3), (1, 256), (255, 256), (256, 257), (0, 300), (256, 300), (299, 300), (137, 300)]
CONSISTENCY = [(1, 3), (2, 3), (3, 256), (3, 300), (128, 256), (255, 300), (256, 300), (257, 300), (300, 300)]


def tlog_fixture(tmp: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    m = world.main_scenario(tmp / "main")
    try:
        leaves = [spec.leaf_hash(e) for e in m.log.leaves(300)]
        notes = {str(n): {"note_text": note.decode(), "cosigned_at": m.cosigned_at[n],
                          "root_b64": spec.B64(spec.mth(leaves[:n])), "sha256": spec.hexH(note)}
                 for n, note in m.notes.items()}
        inclusion = [{"index": i, "size": n, "leaf_hash_hex": leaves[i].hex(),
                      "proof_b64": [spec.B64(h) for h in spec.inclusion_path(i, leaves[:n])],
                      "root_b64": spec.B64(spec.mth(leaves[:n]))} for i, n in INCLUSION]
        consistency = [{"old": a, "new": b, "proof_b64": [spec.B64(h) for h in spec.consistency_path(a, leaves[:b])],
                        "old_root_b64": spec.B64(spec.mth(leaves[:a])), "new_root_b64": spec.B64(spec.mth(leaves[:b]))}
                       for a, b in CONSISTENCY]
        single, unknown_dup, recognized_dup, bad_cosig = _note_cases(tmp / "single")
        freshness = [{"age": age, "now": world.T_COSIGN + age, "max_checkpoint_age": 300,
                      "expect": "valid" if -30 <= age <= 300 else "invalid"}
                     for age in (0, 300, 301, -30, -31)]
        out = {
            "origin": ORIGIN, "log_vkey": aicslog.Keys().log_vkey(), "witness_vkeys": world.witness_vkeys(),
            "trust_bundle": m.trust, "card": m.card, "size": 300,
            "tiles": "tlog/tiles/ is a C2SP tlog-tiles prefix for the size-300 tree; tlog/tiles/checkpoint is the "
                     "size-300 note cosigned by both witnesses",
            "notes": notes, "inclusion": inclusion, "consistency": consistency,
            "entry_sample_u64": {str(i): spec.U64(spec.J(m.log.entries[i])) for i in (0, 1, 2, 255, 256, 299)},
            "note_cases": {
                "policy": {"witness_vkeys": [world.witness_vkeys()[0]], "quorum": 1, "max_checkpoint_age": 300},
                "single_witness_note_text": single.decode(), "cosigned_at": world.T_COSIGN,
                "freshness": freshness,
                "repeated_unknown_key_lines": {"note_text": unknown_dup.decode(), "now": world.T_COSIGN + 10,
                                               "expect": "valid",
                                               "reason": "§6.2: ignore unknown keys, including repeated lines"},
                "repeated_log_key_line": {"note_text": recognized_dup.decode(), "now": world.T_COSIGN + 10,
                                          "expect": "invalid",
                                          "reason": "§6.2: reject duplicate lines for a recognized key"},
                "invalid_pinned_cosignature": {"note_text": bad_cosig.decode(), "now": world.T_COSIGN + 10,
                                               "expect": "invalid",
                                               "reason": "§6.2: reject invalid signatures by recognized keys"},
            },
        }
        tiles = dict(m.log.tiles(300))
        tiles["checkpoint"] = m.notes[300]
        return out, tiles
    finally:
        m.close()


def _note_cases(tmp: Path) -> tuple[bytes, bytes, bytes, bytes]:
    log = aicslog.standard_log(3)
    clock = world.Clock(world.T_COSIGN)
    pool = world.witness_pool(tmp, clock)
    try:
        single = world.cosign(log, 3, [pool["witness_a"]], clock, world.T_COSIGN)
        text = single.decode().split("\n\n")[0] + "\n"
        unknown = spec.log_signature_line("mirror.interop.test/attest", spec.test_key(ED25519["unknown_note_signer"]),
                                          text)
        noted = log.note(3) + (unknown + unknown).encode()
        from .witnesses import cosigned

        unknown_dup = cosigned(noted, pool["witness_a"].feed(log, 3, note=noted))  # aics-witness ignores them
        log_line = [ln for ln in single.decode().split("\n") if ln.startswith(f"{spec.EM_DASH} {ORIGIN} ")][0]
        recognized_dup = single + (log_line + "\n").encode()
        lines = single.decode().split("\n")
        for i, ln in enumerate(lines):
            if ln.startswith(f"{spec.EM_DASH} {aicslog.WITNESS_NAMES['witness_a']} "):
                blob = bytearray(spec.dB64(ln.rsplit(" ", 1)[1]))
                blob[-1] ^= 1
                lines[i] = ln.rsplit(" ", 1)[0] + " " + spec.B64(bytes(blob))
        return single, unknown_dup, recognized_dup, "\n".join(lines).encode()
    finally:
        for w in pool.values():
            w.close()


def split_fixture(tmp: Path) -> dict[str, Any]:
    gossip = {"consistent": (0, None), "consistency-unproven": (1, None), "not-evidence": (1, None)}
    trees: dict[str, Any] = {}
    out = []
    for fx in world.split_fixtures(tmp):
        for label, tiles in zip(fx.trees, (fx.a_tiles, fx.b_tiles)):
            encoded = None if tiles is None else {p: spec.U64(d) for p, d in sorted(tiles.items())}
            assert trees.setdefault(label, encoded) == encoded, label
        relation = fx.expected["relation"]
        exit_code, classification = gossip.get(relation, (2, "split-proven" if all(fx.expected["witness_policy_met"])
                                                          else "log-equivocation"))
        case = {"name": fx.name, "description": fx.description, "note_1_text": fx.a.decode(),
                "note_2_text": fx.b.decode(), "now": fx.now,
                "policy": {"witness_vkeys": fx.witnesses, "quorum": fx.quorum, "max_checkpoint_age": 300},
                "served": {"origin": {"prefix": aicslog.PREFIX, "checkpoint": "note_1", "tiles": fx.trees[0]},
                           "mirror": {"prefix": aicslog.MIRROR, "checkpoint": "note_2", "tiles": fx.trees[1]}},
                "expect": {"relation": relation, "witness_policy_met": fx.expected["witness_policy_met"],
                           "reason": fx.expected.get("reason")},
                "aics_gossip_check": {"exit": exit_code, "classification": classification}}
        out.append(case)
    return {"log_vkey": aicslog.Keys().log_vkey(), "origin": ORIGIN,
            "rule": "AICS-1 §14.6; aics gossip-check: exit 0 consistent, 2 split-proven or log-equivocation "
                    "(a note missed its witness policy), 1 consistency-unproven or not evidence",
            "trees": {"note": "tile resources by tree label (path -> U64 bytes); 'none' means the source serves no "
                              "tiles; the entries of a tree are in its tile/entries bundles",
                      **trees},
            "fixtures": out}


# ---------------------------------------------------------------------------
# §14.3 bundles
# ---------------------------------------------------------------------------


def bundles_fixture(tmp: Path) -> dict[str, Any]:
    from aics_tlog import bundle_from_tiles

    card = world.interop_card()
    log = aicslog.standard_log(8, card=card)
    clock = world.Clock(world.T_COSIGN)
    pool = world.witness_pool(tmp, clock)
    try:
        note = world.cosign(log, 8, list(pool.values()), clock, world.T_COSIGN)
    finally:
        for w in pool.values():
            w.close()
    index = 7
    e = log.entries[index]
    tb = bundle_from_tiles(log.verified_reader(8), index, note, envelope=e["payload"]["envelope"],
                           body_or_ct=log.bodies[index])
    wire = log.wire_bundle(index, note)
    if json.loads(tb.to_json()) != wire:  # aics-tlog writes the §14.3 wire bundle (F10 retired): one form
        raise AssertionError("aics-tlog's bundle differs from the reference wire bundle")
    entry_bytes = spec.dU64(wire["entry_bytes"])
    legacy = {"entry_bytes_b64": spec.B64(entry_bytes), "index": index, "inclusion_proof": wire["inclusion_proof"],
              "checkpoint_note": note.decode("utf-8"), "envelope": wire["envelope"],
              "body_or_ct": spec.B64(log.bodies[index])}
    trust = aicslog.trust_bundle(card_hash=spec.card_hash(card))
    package = spec.verification_package(wire, trust, [spec.J(card)], log.leaves(8), [note])
    tampered = [
        {"name": "proof", "bundle": {**wire, "inclusion_proof": [spec.B64(bytes(32))] + wire["inclusion_proof"][1:]}},
        {"name": "index", "bundle": {**wire, "index": index - 1}},
        {"name": "envelope", "bundle": {**wire, "envelope": {**wire["envelope"], "sig": spec.U64(bytes(64))}}},
        {"name": "body", "bundle": {**wire, "body_or_ct": spec.U64(b"tampered body")}},
    ]
    return {"log_vkey": aicslog.Keys().log_vkey(), "witness_vkeys": world.witness_vkeys(), "quorum": 2,
            "aics1_wire_bundle": {"bundle": wire, "expect": "valid",
                                  "reason": "§14.3 {entry_bytes:U64,index,inclusion_proof:[B64],checkpoint_note:U64,"
                                            "envelope,body_or_ct:U64-or-null}; aics-tlog writes these bytes"},
            "legacy_aics_tlog_bundle": {"bundle": legacy, "expect": "invalid",
                                        "reason": "the pre-0.2 aics-tlog form (entry_bytes_b64, the note as text, "
                                                  "B64 body): §14.3 defines other members and encodings (§2: unknown "
                                                  "members are rejected)"},
            "aics1_package": {"package": package, "expect": "valid",
                              "reason": "§14.3 {bundle,trust_bundle,policy_cards,entry_prefix,checkpoint_notes}"},
            "tampered_wire_bundles": [{**t, "expect": "invalid"} for t in tampered]}


# ---------------------------------------------------------------------------
# §6.4 trust bundle
# ---------------------------------------------------------------------------


def trust_fixture() -> dict[str, Any]:
    card = world.interop_card()
    bundle = aicslog.trust_bundle(card_hash=spec.card_hash(card))
    raw = spec.J(bundle)
    txt = spec.txt_record(raw)
    strings = spec.txt_character_strings(txt)
    msg = spec.dns_txt_response(f"_aics.{aicslog.DOMAIN}", 0x1D5, [strings])
    bad = {
        "missing-v": {k: v for k, v in bundle.items() if k != "v"},
        "unknown-member": {**bundle, "note": "x"},
        "v-2": {**bundle, "v": 2},
        "v-true": {**bundle, "v": True},
        "policy-is-owner": {**bundle, "owner_kid": bundle["policy_kid"]},
        "uppercase-card-hash": {**bundle, "bootstrap_card_hash": "AB" * 32},
        "origin-with-scheme": {**bundle, "origin": "https://" + bundle["origin"]},
    }
    invalid = [{"name": n, "jcs": jcs(v), "expect": "invalid"} for n, v in bad.items()]
    invalid += [{"name": "not-jcs:spaces", "bytes_u64": spec.U64(raw.decode().replace(",", ", ").encode()),
                 "expect": "invalid"},
                {"name": "not-jcs:trailing-lf", "bytes_u64": spec.U64(raw + b"\n"), "expect": "invalid"}]
    return {"bundle": bundle, "jcs": raw.decode(), "sha256": spec.hexH(raw), "txt_record": txt,
            "readme_block": spec.readme_block(raw),
            "readme_block_wrong_digest": {"text": spec.readme_block(raw).replace(spec.hexH(raw), "0" * 64),
                                          "expect": "invalid"},
            "dns": {"qname": f"_aics.{aicslog.DOMAIN}", "qid": 0x1D5, "character_strings": [s.decode() for s in strings],
                    "response_hex": msg.hex(), "rule": "§6.4 one TXT RR; character-strings are concatenated"},
            "invalid": invalid}


# ---------------------------------------------------------------------------
# §13 card, §10.1 receipts
# ---------------------------------------------------------------------------


REGISTRY_CASES = (  # (name, change to the complete refusal registry, rule)
    ("refusal:adds-invalid_signature", lambda codes: codes + ["invalid_signature"],
     "§17.2: invalid_signature and other unregistered synonyms MUST NOT become codes"),
    ("refusal:adds-whatever", lambda codes: codes + ["whatever"], "§13.1: reasons MUST equal §17's registries"),
    ("refusal:drops-malformed", lambda codes: [c for c in codes if c != "malformed"],
     "§13.1: reasons MUST equal §17's registries"),
    ("refusal:unknown-secret-pattern", lambda codes: codes + ["secret_format:no_such_pattern"],
     "§13.1, §17.2: secret_format:<id> only for the card's own secret_patterns"),
)


def card_fixture() -> dict[str, Any]:
    card = world.interop_card()
    control = world.interop_card(version="0.1-draft", spec_versions=spec.SPEC_VERSIONS_01,
                                 refusal=list(spec.REFUSAL_DETAILED) + ["secret_format:github_pat"])
    bad = {**card, "max_checkpoint_age": 600}
    registry = []
    for name, change, rule in REGISTRY_CASES:
        c = world.interop_card(refusal=change(list(card["reason_codes"]["refusal"])))
        registry.append({"name": name, "card": c, "card_hash": spec.card_hash(c), "expect": "invalid",
                         "reason": f"{rule}; otherwise the 0.2-draft card"})
    return {"policy_kid": spec.kid(aicslog.Keys().policy),
            "card": {"card": card, "card_hash": spec.card_hash(card), "unsigned_jcs": jcs({k: v for k, v in card.items()
                                                                                         if k != "signatures"}),
                     "expect": "valid"},
            "card_0_1_draft": {"card": control, "card_hash": spec.card_hash(control), "expect": "invalid",
                               "reason": "the historical 0.1-draft card: version, spec_versions and the refusal "
                                         "registry are not 0.2-draft"},
            "altered": {"card": bad, "expect": "invalid", "reason": "signed bytes changed after signing"},
            "registry": registry,
            "trust_bundle": aicslog.trust_bundle(card_hash=spec.card_hash(card))}


def receipts_fixture() -> dict[str, Any]:
    log = aicslog.standard_log(5)
    e = log.entries[4]
    raw = spec.J(e)
    k = aicslog.Keys()
    good = spec.receipt_note(ORIGIN, raw, e["ts"], k.log)

    def signed(text):
        return spec.signed_note(text, [spec.log_signature_line(ORIGIN, k.log, text)]).decode()

    base = spec.receipt_text(ORIGIN, spec.leaf_hash(raw).hex(), e["ts"])
    invalid = [
        ("mmd-61", base.replace('"mmd_seconds":60', '"mmd_seconds":61'), "§14.4 step 1: mmd_seconds=60"),
        ("submitted-at-not-ts", spec.receipt_text(ORIGIN, spec.leaf_hash(raw).hex(), e["ts"] + 1),
         "§14.4 step 2: submitted_at = ts"),
        ("plain-json-digest", spec.receipt_text(ORIGIN, spec.hexH(raw), e["ts"]),
         "§10.1: entry_hash is the leaf hash hexH(0x00 || entry_bytes)"),
        ("not-canonical", base.replace(",", ", "), "§14.4 step 1: exact canonical receipt schema"),
        ("other-origin", spec.receipt_text("evil.example/tiles", spec.leaf_hash(raw).hex(), e["ts"]),
         "§14.4 step 1: check origin"),
    ]
    return {"log_vkey": k.log_vkey(), "entry_u64": spec.U64(raw), "entry_ts": e["ts"],
            "receipt_text": good.decode(), "expect": "valid",
            "invalid": [{"name": name, "receipt_text": signed(text), "expect": "invalid", "reason": reason}
                        for name, text, reason in invalid]}


def appendix_fixture() -> dict[str, Any]:
    a = appendix_a.load()
    return {"source": "docs/spec/AICS-1.md Appendix A (values read from the text; entries from the A.5 program)",
            "envelope_jcs": a.envelope_bytes.decode(), "entry_jcs": a.entry_bytes.decode(),
            "entries_u64": [spec.U64(a.entry_jcs(i)) for i in range(4)], "leaf_hashes_hex": a.leaf_hashes,
            "root_hex": a.root, "inclusion_proof_b64": a.inclusion_proof, "consistency_proof_b64": a.consistency_proof,
            "checkpoint_text": a.checkpoint.decode(), "previous_checkpoint_text": a.previous_checkpoint.decode(),
            "cosignature_input_text": a.cosign_input.decode(), "header_jcs": a.header_bytes.decode(),
            "plaintext_hex": a.plaintext.hex(), "ciphertext_hex": a.ciphertext.hex(), "inline": a.inline,
            "trust_bundle": appendix_a.trust_bundle_dict()}


# ---------------------------------------------------------------------------

DESCRIPTIONS = {
    "README.md": "what the fixtures are and how to use and regenerate them",
    "keys.json": "every public test key used below (seeds, raw keys, did:key, vkeys)",
    "linesig.json": "§11.3 line signatures: raw Ed25519 and SSHSIG over session LF command",
    "envelopes.json": "§4 native envelopes, chains, seen, freshness; §11.3 text-scheme envelopes",
    "http-signatures.json": "§12.1 RFC 9421 / RFC 9530 request signatures for POST /v2/entries",
    "sealed.json": "§8.1 sealed boxes with the inner header (deterministic ephemeral key)",
    "tlog/log.json": "§6 log: notes cosigned by two witnesses, inclusion and consistency proofs, note cases",
    "split-view.json": "§14.6 gossip-check fixtures: two notes, what origin and mirror serve, expected relation",
    "bundles.json": "§14.3 wire bundle (aics-tlog writes the same bytes), verification package, the pre-0.2 "
                    "aics-tlog form as a negative case, tampered bundles",
    "trust-bundle.json": "§6.4 trust bundle: JCS bytes, TXT record, README block, DNS response, invalid variants",
    "card.json": "§13 signed assurance card (0.2-draft), the 0.1-draft card, an altered card, refusal-registry "
                 "variants",
    "receipts.json": "§10.1 receipt notes",
    "appendix-a.json": "AICS-1 Appendix A values as read from the specification",
}

README = """# AICS-1 interop fixtures

Generated by `packages/aics-interop/src/aics_interop/generate.py`; do not edit
by hand.  Regenerate with `cd packages/aics-interop && uv run
aics-interop-fixtures`; `uv run aics-interop-fixtures --check` (run by the
interop CI) fails when the committed files differ from a fresh generation.

Every file is deterministic: public test keys (`keys.json`: seeds are 32
repeats of one byte), fixed clocks and a fixed test ephemeral key for sealed
boxes.  The log in `tlog/` was built with aics-tlog and cosigned by two
in-process aics-witness instances.

Conventions (also in `manifest.json`): `*_hex` lowercase hex, `*_b64`
canonical padded base64, `*_u64` canonical unpadded base64url, `*_text`
exact UTF-8 (signed notes end with LF), `jcs` the exact RFC 8785 bytes as a
string.  `expect` is the verdict AICS-1 requires; `findings` names the open
findings in `packages/aics-interop/README.md` under which a Python package of
this repository disagrees with the case today (its verdict, or a value it
carries such as an envelope hash); the interop suite runs the packages over
every case and requires each disagreement to be named.  An implementation
conforms when it reaches `expect`, not when it matches a package's current
behaviour.

`tlog/tiles/` is a C2SP tlog-tiles prefix (height 8) for a 300-entry log:
serve the directory over HTTP, or read it as files.  `manifest.json` lists
every file with its SHA-256.
"""


def build() -> dict[str, bytes]:
    files: dict[str, bytes] = {"README.md": README.encode("utf-8")}
    with tempfile.TemporaryDirectory(prefix="aics-interop-fixtures-") as tmp:
        root = Path(tmp)
        files["keys.json"] = dump(keys_fixture())
        files["linesig.json"] = dump(linesig_fixture())
        files["envelopes.json"] = dump(envelopes_fixture())
        files["http-signatures.json"] = dump(http_fixture())
        files["sealed.json"] = dump(sealed_fixture())
        log_json, tiles = tlog_fixture(root / "tlog")
        files["tlog/log.json"] = dump(log_json)
        for path, data in tiles.items():
            files[f"tlog/tiles/{path}"] = data
        files["split-view.json"] = dump(split_fixture(root / "split"))
        files["bundles.json"] = dump(bundles_fixture(root / "bundles"))
    files["trust-bundle.json"] = dump(trust_fixture())
    files["card.json"] = dump(card_fixture())
    files["receipts.json"] = dump(receipts_fixture())
    files["appendix-a.json"] = dump(appendix_fixture())
    manifest = {"format": FORMAT, "spec": "AICS-1 0.2-draft", "conventions": CONVENTIONS,
                "generator": "packages/aics-interop/src/aics_interop/generate.py",
                "regenerate": "cd packages/aics-interop && uv run aics-interop-fixtures",
                "files": {path: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                                 "description": DESCRIPTIONS.get(path) or (
                                     "tile resource of the size-300 log (tlog-tiles prefix)"
                                     if path.startswith("tlog/tiles/") else "")}
                          for path, data in sorted(files.items())}}
    files["manifest.json"] = dump(manifest)
    return files


def existing(out: Path) -> dict[str, bytes]:
    """The files under ``out`` as the generator sees them: dotfiles (.DS_Store, .gitattributes) are not fixtures."""
    if not out.is_dir():
        return {}
    return {p.relative_to(out).as_posix(): p.read_bytes() for p in sorted(out.rglob("*"))
            if p.is_file() and not any(part.startswith(".") for part in p.relative_to(out).parts)}


def main(argv: list[str] | None = None) -> int:
    sys.dont_write_bytecode = True  # never drop __pycache__ into the sibling packages' source trees
    ap = argparse.ArgumentParser(prog="aics-interop-fixtures", description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="fixtures directory (default: %(default)s)")
    ap.add_argument("--check", action="store_true", help="compare instead of writing; exit 1 on any difference")
    args = ap.parse_args(argv)
    files = build()
    have = existing(args.out)
    changed = sorted(p for p in files if have.get(p) != files[p])
    extra = sorted(set(have) - set(files))
    if args.check:
        for p in changed:
            print(f"differs: {p}", file=sys.stderr)
        for p in extra:
            print(f"not generated: {p}", file=sys.stderr)
        print(f"{len(files)} fixture files; {len(changed)} differ, {len(extra)} unexpected")
        return 1 if changed or extra else 0
    for p in extra:
        (args.out / p).unlink()
    for p in changed:
        target = args.out / p
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(files[p])
    print(f"wrote {len(changed)} of {len(files)} fixture files to {args.out} ({len(extra)} removed)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

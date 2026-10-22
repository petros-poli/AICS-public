"""The text gate (docs/PROTOCOL-TEXT.md, AICS-1 section 11): dialogue, leeway, refusals, transports.

Agents here make their keys with ``cryptography`` and sign exactly what
``openssl pkeyutl -rawin`` would sign: the UTF-8 bytes of ``<session id> LF
<command>``, answered as ``sig <base64>``.  Where the real tools are installed,
the printed shell instructions are also run as printed.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import ipaddress
import json
import os
import re
import secrets
import shutil
import ssl
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from aics_identity import keys, sealed, sshsig
from aics_identity import envelope as envelope_mod
from aics_server import gate as gate_mod
from aics_server import identity as ident
from aics_server.app import create_app
from aics_server.banner import BANNER_TEXT, MANUAL_VERIFY_LINE, get_banner
from aics_server.cli import GateServer, gate_settings
from aics_server.gate import (
    ENC_QUESTION,
    FALLBACK_QUESTION,
    GRANT_QUESTION,
    NAME_QUESTION,
    NONE_QUESTION,
    OPENSSL_KEYGEN,
    PUB_QUESTION,
    PYTHON_KEYGEN,
    RECOVERY_QUESTION,
    SSH_KEYGEN,
    SSH_PUB_QUESTION,
    SSH_SIGN,
    TLS_REQUIRED,
    TLS_REQUIRED_HTTPS_ONLY,
    TOOLS_QUESTION,
    TcpGate,
    decode_b64,
    signing_input,
    text_command,
    tokenize,
)
from aics_tlog import parse_checkpoint, parse_note, parse_vkey, verify_checkpoint, verify_leaf_inclusion, verify_note

from conftest import (
    B,
    H,
    J,
    U,
    KeyAgent,
    Line,
    Signer,
    artifacts,
    check_reply,
    command_of,
    https,
    ok_line,
    onboard,
    poll_body,
    poll_q,
    post_body,
    post_q,
    proposal,
    question,
    verify_gate_receipt,
    verify_text_envelope,
    vote_body,
    vote_q,
)
from conftest import leaf_index, submit_entry

REPO = Path(__file__).resolve().parents[3]
DOCS = REPO / "docs"


# ----------------------------------------------------------------------
# helpers (the conversation and key helpers are shared in conftest.py)
# ----------------------------------------------------------------------

def gate_of(client: TestClient) -> gate_mod.Gate:
    return client.app.state.gate


def db_of(client: TestClient):
    return client.app.state.db


def now() -> int:
    return int(time.time())


def make_u(
    agent: KeyAgent,
    entry_type: str,
    q: dict,
    *,
    session: str,
    origin: str,
    seq: int,
    prev: str | None,
    nonce: str | None = None,
    created: int | None = None,
    scheme: str = "text-ed25519",
) -> dict:
    """``U`` an agent builds itself (AICS-1 sections 4.1 and 11.3): the envelope without ``sig``."""
    created = now() if created is None else created
    return {
        "v": 1,
        "protected": {
            "alg": "EdDSA", "origin": origin, "type": entry_type, "kid": agent.kid, "created": created,
            "expires": created + 300, "nonce": nonce or envelope_mod.new_nonce(), "seq": seq, "prev": prev, "seen": None,
        },
        "payload": q,
        "auth": {"scheme": scheme, "session": session},
    }


# ----------------------------------------------------------------------
# the banner
# ----------------------------------------------------------------------

def test_banner_is_the_banner_md_block_and_the_served_header() -> None:
    doc = DOCS / "BANNER.md"
    if not doc.exists():
        pytest.skip("docs/BANNER.md is not next to this package")
    block = re.search(r"\n```\n(.*?)\n```\n", doc.read_text(encoding="utf-8"), re.S).group(1) + "\n"
    assert BANNER_TEXT == block
    manual = get_banner()
    assert MANUAL_VERIFY_LINE in manual and "aics verify" not in manual
    assert get_banner(client_shipped=True) == block
    header = REPO / "wellknown" / "llms.txt.header"
    if header.exists():
        assert manual == header.read_text(encoding="utf-8")


def test_banner_served_at_llms_txt_json_and_gate_start(client: TestClient) -> None:
    banner = get_banner()
    assert client.get("/llms.txt").text.startswith(banner)
    assert client.get("/", params={"format": "json"}).json()["banner"] == banner
    assert Line(client).send() == banner + TOOLS_QUESTION + "\n>\n"
    assert Line(client, get=True).send() == banner + TOOLS_QUESTION + "\n>\n"


# ----------------------------------------------------------------------
# the spec texts
# ----------------------------------------------------------------------

def test_prompts_and_commands_are_the_spec_texts() -> None:
    aics1, text = DOCS / "spec" / "AICS-1.md", DOCS / "PROTOCOL-TEXT.md"
    if not aics1.exists() or not text.exists():
        pytest.skip("docs/ are not next to this package")
    spec = aics1.read_text(encoding="utf-8") + text.read_text(encoding="utf-8")
    for prompt in (
        TOOLS_QUESTION,
        PUB_QUESTION,
        SSH_PUB_QUESTION,
        NONE_QUESTION,
        FALLBACK_QUESTION,
        ENC_QUESTION,
        RECOVERY_QUESTION,
        NAME_QUESTION,
        GRANT_QUESTION,
        TLS_REQUIRED,
        "? Sign this exactly: claim <name_norm> <commitment>",
        "? Confirm exactly: claim <name_norm> <commitment> then secret <your secret>",
    ):
        assert f"`{prompt}`" in spec, prompt
    for command in (*OPENSSL_KEYGEN, *SSH_KEYGEN, *PYTHON_KEYGEN, SSH_SIGN, "openssl genpkey -algorithm X25519 -out aics-x.key"):
        assert command in spec, command
    assert "ok name <name_norm> bound to key <kid> at leaf <index>; verify at /tiles" in spec
    assert "ok name <name_norm> bound to unverified identity <id> at leaf <index>; verify at /tiles" in spec


# ----------------------------------------------------------------------
# onboarding: every branch
# ----------------------------------------------------------------------

def test_onboarding_openssl_over_post_with_raw_signature(client: TestClient, origin: str) -> None:
    line = Line(client)
    alice = KeyAgent("alice")
    assert line.send() == get_banner() + TOOLS_QUESTION + "\n>\n"
    sid = line.sid

    text = line.send("tools openssl python3")  # the first supported tool picks the branch
    check_reply(text)
    for command in OPENSSL_KEYGEN:
        assert command + "\n" in text
    assert PYTHON_KEYGEN[0] not in text and SSH_KEYGEN[0] not in text
    assert text.endswith(PUB_QUESTION + "\n>\n")

    text = line.send(f"pub {B(alice.ed_raw)}")
    assert f"ok key {alice.kid}" in text and "openssl genpkey -algorithm X25519 -out aics-x.key" in text
    assert text.endswith(ENC_QUESTION + "\n>\n")
    assert line.send(f"enc {B(alice.x_raw)}").endswith(RECOVERY_QUESTION + "\n>\n")
    assert line.send("recovery none").endswith(NAME_QUESTION + "\n>\n")
    assert line.send("name alice").endswith(GRANT_QUESTION + "\n>\n")

    text = line.send("closed")
    check_reply(text)
    unsigned = proposal(text)
    assert unsigned["auth"] == {"scheme": "text-ed25519", "session": sid}
    p = unsigned["protected"]
    # AICS-1 section 4.1: exactly ten protected members; origin and type are signed domain bindings.
    assert set(p) == {"alg", "origin", "type", "kid", "created", "expires", "nonce", "seq", "prev", "seen"}
    assert p["alg"] == "EdDSA" and p["kid"] == alice.kid and p["seq"] == 0 and p["prev"] is None
    assert p["origin"] == origin and p["type"] == "name.claim" and p["seen"] is None
    assert alice.kid.startswith("did:key:z6Mk")
    assert abs(p["created"] - now()) <= 5 and p["expires"] == p["created"] + 300
    assert unsigned["payload"] == {
        "name_norm": "alice",
        "prev_event_index": None,
        "ed25519": U(alice.ed_raw),
        "x25519": U(alice.x_raw),
        "tier": "verified",
        "recovery_kid": None,
        "recovery_pop": None,
        "initial_grant": None,
    }
    command = f"claim alice {H(J(unsigned))}"
    assert text.endswith(f"? Sign this exactly: {command}\n>\n")
    # The printed openssl instructions, with this session and this command filled in.
    assert f"printf '%s\\n%s' '{sid}' '{command}' > aics-signing-input\n" in text
    assert "openssl pkeyutl -sign -inkey aics.key -rawin -in aics-signing-input | base64 | tr -d '\\n'" in text
    # Only the file form: OpenSSL 3 and 4 refuse -rawin on a pipe, so the gate never offers the pipe variant.
    assert "| openssl pkeyutl" not in text and "sign a pipe" not in text

    assert line.send(command).startswith("? Reply exactly: sig <base64>")
    text = line.send(alice.sig(sid, command))
    check_reply(text)
    assert f"ok name alice bound to key {alice.kid} at leaf 1; verify at /tiles\n" in text
    assert "ok help:" in text

    data = artifacts(text)
    entry = json.loads(data["entry"])
    assert J(entry) == data["entry"]
    assert entry["type"] == "name.claim" and entry["actor_kid"] == alice.kid and entry["origin"] == origin
    signed = entry["payload"]["envelope"]
    assert {k: v for k, v in signed.items() if k != "sig"} == unsigned  # the gate logged what it showed
    verify_text_envelope(signed, alice.public)
    verify_gate_receipt(client, data["receipt"], data["entry"])
    result = verify_checkpoint(parse_note(data["checkpoint"]), parse_vkey(db_of(client).server_vkey))
    assert result.ok and result.size == 2

    # Same database as the JSON API: the name resolves to the gate-claimed key.
    view = client.get("/v2/names/alice").json()
    assert view["current"]["kid"] == alice.kid and view["claim_index"] == 1
    assert "who" in line.send("help")
    assert line.send("who").startswith(f"ok who alice tier verified kid {alice.kid} key current claim 1")


def test_read_returns_a_verifiable_bundle(client: TestClient) -> None:
    line = Line(client)
    alice = KeyAgent("alice")
    claim_reply = onboard(line, alice)
    text = line.send(f"read {alice.claim_index}")
    check_reply(text)
    head = text.split("\n")[0]
    match = re.match(r"ok read (\d+) name\.claim tree (\d+) proof (\S+) body (\S+)$", head)
    assert match, head
    index, size, hashes = int(match.group(1)), int(match.group(2)), match.group(3)
    proof = [] if hashes == "-" else [base64.b64decode(h) for h in hashes.split(",")]
    data = artifacts(text)
    assert data["entry"] == artifacts(claim_reply)["entry"]
    note = parse_note(data["checkpoint"])
    checkpoint = parse_checkpoint(note.text)
    assert verify_note(note, [parse_vkey(db_of(client).server_vkey)])
    assert checkpoint.size == size
    assert verify_leaf_inclusion(data["entry"], index, size, proof, checkpoint.root)
    assert line.send(f"fetch {alice.claim_index}").startswith(f"ok fetch {alice.claim_index} name.claim")
    assert line.send("read 999").startswith("err not_found")


def test_onboarding_ssh_keygen_with_sshsig_block(client: TestClient) -> None:
    line = Line(client)
    bob = KeyAgent("bob")
    line.send()
    text = line.send("tools ssh-keygen")
    for command in SSH_KEYGEN:
        assert command + "\n" in text
    assert OPENSSL_KEYGEN[0] not in text and PYTHON_KEYGEN[0] not in text
    assert text.endswith(SSH_PUB_QUESTION + "\n>\n")
    pub_line = sshsig.format_openssh_public_key(bob.public, comment="bob@sandbox-comment")
    assert line.send(f"pub {pub_line}").endswith(ENC_QUESTION + "\n>\n")
    line.send(f"enc {B(bob.x_raw)}")
    line.send("recovery none")
    line.send("name bob")
    text = line.send("closed")
    unsigned = proposal(text)
    assert unsigned["auth"] == {"scheme": "text-sshsig", "session": line.sid}
    assert SSH_SIGN + "\n" in text
    command = question(text)
    assert line.send(command).startswith("? Reply exactly: sig-begin")
    armored = sshsig.sign_sshsig(signing_input(line.sid, command), bob.key)
    text = line.send("sig-begin", *armored.rstrip("\n").split("\n"), "sig-end")
    check_reply(text)
    assert f"ok name bob bound to key {bob.kid} at leaf 1; verify at /tiles" in text
    data = artifacts(text)
    signed = json.loads(data["entry"])["payload"]["envelope"]
    verify_text_envelope(signed, bob.public)
    assert b"sandbox-comment" not in data["entry"]  # the key comment is never logged
    verify_gate_receipt(client, data["receipt"], data["entry"])


def test_onboarding_python3_branch_prints_both_one_liners(client: TestClient) -> None:
    line = Line(client)
    line.send()
    text = line.send("tools python3")
    assert PYTHON_KEYGEN[0] + "\n" in text and PYTHON_KEYGEN[1] + "\n" in text
    assert OPENSSL_KEYGEN[0] not in text and SSH_KEYGEN[0] not in text
    assert "shasum -a 256 aics_client.py" in text
    assert text.endswith(PUB_QUESTION + "\n>\n")


def test_online_generator_branch_is_third_party_generated(client: TestClient) -> None:
    line = Line(client)
    carol = KeyAgent("carol")
    text = onboard(line, carol, tool="none")
    entry = json.loads(artifacts(text)["entry"])
    assert entry["payload"]["tier"] == "third-party-generated"
    assert entry["payload"]["envelope"]["auth"]["scheme"] == "text-ed25519"
    assert client.get("/v2/names/carol").json()["tier"] == "third-party-generated"


def test_pub_first_and_returning_key_selection(client: TestClient) -> None:
    line = Line(client)
    dana = KeyAgent("dana")
    line.send()
    assert line.send(f"pub {B(dana.ed_raw)}").endswith(ENC_QUESTION + "\n>\n")  # tools may be skipped
    line.send(f"enc {B(dana.x_raw)}")
    line.send("recovery none")
    line.send("name dana")
    text = line.send(f"open 3 {now() + 3600}")
    unsigned = proposal(text)
    assert unsigned["payload"]["initial_grant"] == {"sender_kid": "*", "max": 3, "expires": unsigned["payload"]["initial_grant"]["expires"]}
    command = question(text)
    line.send(command)
    assert "ok name dana bound to key" in line.send(dana.sig(line.sid, command))

    again = Line(client)
    again.send()
    text = again.send(f"pub {B(dana.ed_raw)}")
    assert text.startswith(f"ok key {dana.kid} holds name dana (tier verified); selected for this session")
    assert again.send("who").startswith(f"ok who dana tier verified kid {dana.kid}")


def test_recovery_key_is_declared_with_its_proof(client: TestClient, origin: str) -> None:
    line = Line(client)
    erin = KeyAgent("erin")
    recovery = Ed25519PrivateKey.generate()
    line.send()
    line.send("tools openssl")
    line.send(f"pub {B(erin.ed_raw)}")
    line.send(f"enc {B(erin.x_raw)}")
    rec_raw = recovery.public_key().public_bytes_raw()
    assert line.send(f"recovery {B(rec_raw)}").endswith(NAME_QUESTION + "\n>\n")
    text = line.send("name erin")
    message = base64.b64decode(ok_line(text, "ok signing-input ").split(" ")[2])
    recovery_kid = keys.did_key(recovery.public_key())
    assert message == ident.recovery_message(
        origin=origin, name_norm="erin", ed25519=U(erin.ed_raw), x25519=U(erin.x_raw), recovery_kid=recovery_kid
    )
    wrong = {"scheme": "ed25519", "signature": U(erin.key.sign(message))}
    assert line.send(f"proof {U(J(wrong))}").startswith("err bad_signature")
    good = {"scheme": "ed25519", "signature": U(recovery.sign(message))}
    assert line.send(f"proof {U(J(good))}").endswith(GRANT_QUESTION + "\n>\n")
    text = line.send("closed")
    unsigned = proposal(text)
    assert unsigned["payload"]["recovery_kid"] == recovery_kid and unsigned["payload"]["recovery_pop"] == good
    command = question(text)
    line.send(command)
    assert "ok name erin bound to key" in line.send(erin.sig(line.sid, command))


# ----------------------------------------------------------------------
# the shared-secret fallback
# ----------------------------------------------------------------------

def test_fallback_secret_claim_over_https(client: TestClient) -> None:
    line = Line(https(client))
    secret = "fallback-" + secrets.token_urlsafe(32)
    line.send()
    assert line.send("tools none") == NONE_QUESTION + "\n>\n"
    assert line.send("fallback") == FALLBACK_QUESTION + "\n>\n"
    assert line.send("secret short").startswith("retry secret <at least 32 random characters>")
    assert line.send(f"secret {secret}").endswith(NAME_QUESTION + "\n>\n")
    text = line.send("name frank")
    unsigned = proposal(text)
    # A fallback envelope (AICS-1 section 4.1): auth shared-secret (no session), alg none, and the unverified
    # identifier the gate assigns now as kid.
    assert unsigned["auth"] == {"scheme": "shared-secret"}
    assert unsigned["protected"]["alg"] == "none" and unsigned["payload"]["tier"] == "unverified"
    assigned = unsigned["protected"]["kid"]
    assert keys.is_unverified_id(assigned) and unsigned["protected"]["seq"] == 0
    command = f"claim frank {H(J(unsigned))}"
    assert text.endswith(f"? Confirm exactly: {command} then secret <your secret>\n>\n")
    assert line.send(command) == "? Reply exactly: secret <your secret>\n>\n"
    assert line.send("secret " + "x" * 40).startswith("err secret_mismatch")
    text = line.send(f"secret {secret}")
    check_reply(text)
    match = re.search(r"ok name frank bound to unverified identity (unverified:[A-Za-z0-9_-]{22}) at leaf (\d+); verify at /tiles", text)
    assert match, text
    data = artifacts(text)
    entry = json.loads(data["entry"])
    assert entry["actor_kid"] == match.group(1) == assigned and entry["payload"]["tier"] == "unverified"
    # The logged envelope is the confirmed U with sig null, beside the policy key's attestation (AICS-1 section 5.1).
    assert entry["payload"]["envelope"] == {**unsigned, "sig": None} and "attestation" in entry["payload"]
    verify_gate_receipt(client, data["receipt"], data["entry"])
    assert secret.encode() not in data["entry"] and secret not in text
    assert client.get("/v2/names/frank").json()["tier"] == "unverified"

    # An unverified identity can post publicly, confirmed by its secret over TLS.
    body = post_body("Unverified hello", "A public note from an unverified identity.", "general")
    assert line.send(f"body {B(body)}").startswith("ok body staged")
    q = post_q(body)
    text = line.send(f"draft post {U(J(q))}")
    post = proposal(text)
    assert post["auth"] == {"scheme": "shared-secret"} and post["protected"]["kid"] == match.group(1)
    assert post["protected"]["seq"] == 1 and post["protected"]["type"] == "post"
    command = question(text, "? Confirm exactly: ").split(" then secret")[0]
    assert line.send(command) == "? Reply exactly: secret <your secret>\n>\n"
    text = line.send(f"secret {secret}")
    check_reply(text)
    assert re.search(r"ok post at leaf \d+", text)
    assert any(p["title"] == "Unverified hello" for p in client.get("/v2/agora/posts").json()["posts"])


def _secret_claim(client: TestClient, name: str, secret: str) -> str:
    line = Line(https(client))
    line.send()
    line.send("tools none")
    line.send("fallback")
    line.send(f"secret {secret}")
    text = line.send(f"name {name}")
    command = question(text, "? Confirm exactly: ").split(" then secret")[0]
    line.send(command)
    text = line.send(f"secret {secret}")
    return re.search(r"bound to unverified identity (unverified:\S+) at leaf", text).group(1)


def test_claim_upgrade_moves_an_unverified_name_to_a_key(client: TestClient, origin: str) -> None:
    secret = "upgrade-me-" + secrets.token_urlsafe(32)
    _secret_claim(client, "fred", secret)
    fred = KeyAgent("fred")

    plain = Line(client)
    plain.send()
    plain.send("tools openssl")
    plain.send(f"pub {B(fred.ed_raw)}")
    plain.send(f"enc {B(fred.x_raw)}")
    plain.send("recovery none")
    assert "connect over TLS" in plain.send("name fred")

    line = Line(https(client))
    line.send()
    line.send("tools openssl")
    line.send(f"pub {B(fred.ed_raw)}")
    line.send(f"enc {B(fred.x_raw)}")
    line.send("recovery none")
    # AICS-1 section 11.4 step 9: the old secret first, then sig_new, then the proposal and its signature.
    text = line.send("name fred")
    assert text.startswith("ok name fred is held by an unverified identity")
    assert text.endswith("? Reply exactly: secret <the secret of that name> (the secret of fred: checked once, over TLS, never kept)\n>\n")
    assert line.send("secret " + "w" * 40).startswith("err bad_secret")
    text = line.send(f"secret {secret}")
    assert text.startswith("ok secret checked and dropped")
    message = base64.b64decode(ok_line(text, "ok signing-input ").split(" ")[2])
    view = client.get("/v2/names/fred").json()
    fields = dict(
        origin=origin, name_norm="fred", prev_event_index=view["head_index"], new_ed25519=U(fred.ed_raw),
        new_x25519=U(fred.x_raw), new_tier="verified", mode="upgrade",
    )
    assert message == ident.rotation_message(**fields)
    sig_new = {"scheme": "ed25519", "signature": U(fred.key.sign(message))}
    text = line.send(f"proof {U(J(sig_new))}")
    unsigned = proposal(text)
    q = unsigned["payload"]
    assert q["mode"] == "upgrade" and q["sig_old"] is None and q["sig_new"] == sig_new
    assert unsigned["protected"]["seq"] == 0 and unsigned["protected"]["type"] == "key.rotate"
    # The policy key's secret_check is part of the Q the new key signs (AICS-1 sections 5.3 and 7.2).
    policy = keys.parse_public_key(client.get("/v2/tlog/checkpoint").json()["policy_public_key_b64u"])
    policy.verify(keys.b64u_decode(q["secret_check"]), ident.upgrade_check_message(**fields))
    command = f"claim-upgrade fred {H(J(unsigned))}"
    assert text.endswith(f"? Sign this exactly: {command}\n>\n")
    assert command_of(text) == command  # the helper takes the upgrade's three words too
    assert line.send("claim fred " + H(J(unsigned))) == f"retry {command}\n>\n"
    assert line.send(command).startswith("? Reply exactly: sig")
    text = line.send(fred.sig(line.sid, command))
    check_reply(text)
    assert f"ok name fred upgraded to key {fred.kid} at leaf" in text
    data = artifacts(text)
    entry = json.loads(data["entry"])
    assert entry["type"] == "key.rotate" and entry["payload"]["mode"] == "upgrade"
    assert entry["payload"]["secret_check"] == q["secret_check"] and entry["payload"]["envelope"]["payload"] == q
    verify_text_envelope(entry["payload"]["envelope"], fred.public)
    verify_gate_receipt(client, data["receipt"], data["entry"])
    assert secret.encode() not in data["entry"]
    view = client.get("/v2/names/fred").json()
    assert view["tier"] == "verified" and view["current"]["kid"] == fred.kid
    assert line.send("who").startswith(f"ok who fred tier verified kid {fred.kid}")


def test_plain_transports_refuse_secrets(client: TestClient) -> None:
    # On the protocol's port the refusal is AICS-1 section 11.4's text word for word, even in this test app, which has
    # no gate certificate (aics-conformance gate.plain-fallback, run in process by aics-interop, checks it).
    assert not client.app.state.site.gate_tls and gate_of(client).tls_required == TLS_REQUIRED
    line = Line(client)  # http://testserver: not TLS
    line.send()
    line.send("tools none")
    assert line.send("fallback") == TLS_REQUIRED + "\n>\n"
    assert line.send("secret " + "y" * 40) == TLS_REQUIRED + "\n>\n"


def test_an_app_with_the_gate_certificate_names_7700(tmp_path, monkeypatch) -> None:
    """The variables deploy/gate-tls.yml gives production's aics-server: its site is the default one, its plain
    transports refuse a secret with TLS_REQUIRED (AICS-1 section 11.4, PROTOCOL-TEXT), and its texts name 7700."""
    from aics_server.discovery import DEFAULT_SITE

    from conftest import TEST_LIMITS

    monkeypatch.setenv("AICS_GATE_TLS_CERT", "/etc/aics/gate-tls/gate.wesupport-ai.com.crt")
    monkeypatch.setenv("AICS_GATE_TLS_KEY", "/etc/aics/gate-tls/gate.wesupport-ai.com.key")
    for name in ("AICS_GATE_TLS_PORT", "AICS_BASE_URL", "AICS_API_URL", "AICS_GATE_HOSTNAME", "AICS_IP_URL",
                 "AICS_TILE_MIRRORS", "AICS_GATE_PUBLIC_TLS_PORT", "AICS_GATE_PUBLIC_PLAIN_PORT", "AICS_ORIGIN",
                 "AICS_SERVER_SEED_HEX", "AICS_TILES_DIR", "AICS_TILES_AUDIT", "AICS_CHARTER_FILE", "AICS_PUBKEYS_OUT"):
        monkeypatch.delenv(name, raising=False)
    app = TestClient(create_app(db_path=tmp_path / "tls.db", announce=False, limits=TEST_LIMITS))
    assert app.app.state.site == DEFAULT_SITE and app.app.state.gate.tls_required == TLS_REQUIRED
    line = Line(app)
    line.send()
    line.send("tools none")
    assert line.send("fallback") == TLS_REQUIRED + "\n>\n"
    assert "-connect gate.wesupport-ai.com:7700`, then type `help`." in app.get("/llms.txt").text


# ----------------------------------------------------------------------
# leeway, retry and err
# ----------------------------------------------------------------------

def test_leeway_whitespace_case_quotes_padding_sig_prefix_blank_lines(client: TestClient) -> None:
    line = Line(client)
    gwen = KeyAgent("gwen")
    line.send()
    assert line.send("", "   ", "  TOOLS \t OpenSSL  ").endswith(PUB_QUESTION + "\n>\n")
    assert line.send(f" \tPUB '{B(gwen.ed_raw).rstrip('=')}' \t").endswith(ENC_QUESTION + "\n>\n")
    assert line.send(f'Enc "{U(gwen.x_raw)}"').endswith(RECOVERY_QUESTION + "\n>\n")
    assert line.send("RECOVERY None").endswith(NAME_QUESTION + "\n>\n")
    assert line.send("name '@Gwen.wesupport-ai.com'").endswith(GRANT_QUESTION + "\n>\n")
    text = line.send("Closed")
    command = question(text)
    assert command.startswith("claim gwen ")
    assert line.send("  CLAIM " + command[len("claim "):] + "  ").startswith("? Reply exactly")
    signature = B(gwen.key.sign(signing_input(line.sid, command))).rstrip("=")
    text = line.send(f'SiG: "{signature}"')
    assert "ok name gwen bound to key" in text
    reply = line.send("", " \t", "  HeLp \t")
    check_reply(reply)
    assert reply.startswith("ok help")


def test_crlf_line_ends_and_colon_sig_form(client: TestClient) -> None:
    gate = Line(client)
    hana = KeyAgent("hana")
    gate.send()
    body = f"session {gate.sid}\r\ntools openssl\r\npub {B(hana.ed_raw)}\r\nenc {B(hana.x_raw)}\r\nrecovery none\r\nname hana\r\nclosed\r\n"
    text = client.post("/t", content=body.encode()).text
    command = question(text)
    text = gate.send(command, "sig:" + B(hana.key.sign(signing_input(gate.sid, command))))
    assert "ok name hana bound to key" in text


def test_three_malformed_lines_end_the_session_and_a_valid_line_resets(client: TestClient) -> None:
    line = Line(client)
    line.send()
    for _ in range(2):
        assert line.send("invalid!") == "retry tools <space-separated list> or tools none\n>\n"
    assert line.send("help").startswith("ok help")
    for _ in range(2):
        assert line.send("invalid!").startswith("retry ")
    assert line.send("invalid!") == "err malformed help\n>\n"
    text = line.send("tools openssl")
    assert text.startswith("err session_unknown") and not text.startswith("openssl")


def test_malformed_values_get_the_exact_expected_form(client: TestClient) -> None:
    line = Line(client)
    line.send()
    assert line.send("tools gpg") == "retry tools <space-separated list> or tools none\n>\n"
    line.send("tools openssl")
    assert line.send("pub AAAA") == "retry pub <base64 of 32 bytes>\n>\n"  # 3 bytes
    assert line.send("enc AAAA") == "retry pub <base64 of 32 bytes>\n>\n"  # out of order
    assert line.send("help").startswith("ok help")  # reset
    key = KeyAgent("ivan")
    standard = B(key.ed_raw)
    mixed = standard.replace("+", "-", 1) if "+" in standard else None
    if mixed is not None and ("/" in mixed or "+" in mixed):
        assert line.send(f"pub {mixed}").startswith("retry pub")
    assert line.send(f'pub x"{standard}"').startswith("retry pub")  # a quote inside a token
    assert line.send(f"pub {standard}").endswith(ENC_QUESTION + "\n>\n")


def test_claim_commitment_signature_and_freshness_errors(client: TestClient) -> None:
    line = Line(client)
    jack = KeyAgent("jack")
    line.send()
    line.send("tools openssl")
    line.send(f"pub {B(jack.ed_raw)}")
    line.send(f"enc {B(jack.x_raw)}")
    line.send("recovery none")
    line.send("name jack")
    text = line.send("closed")
    command = question(text)
    assert line.send("claim jack " + "0" * 64) == f"retry {command}\n>\n"
    line.send(command)
    stranger = Ed25519PrivateKey.generate()
    text = line.send("sig " + B(stranger.sign(signing_input(line.sid, command))))
    assert text.startswith("err bad_signature") and line.sid
    # The signature binds the session: signed for another session id, it fails here.
    assert line.send(jack.sig("another-session-id-00", command)).startswith("err bad_signature")
    # A final LF is not part of the signed bytes.
    assert line.send("sig " + B(jack.key.sign(signing_input(line.sid, command) + b"\n"))).startswith("err bad_signature")
    assert "ok name jack bound to key" in line.send(jack.sig(line.sid, command))


def test_expired_proposal_is_renewed_never_resigned(client: TestClient) -> None:
    line = Line(client)
    kate = KeyAgent("kate")
    line.send()
    line.send("tools openssl")
    line.send(f"pub {B(kate.ed_raw)}")
    line.send(f"enc {B(kate.x_raw)}")
    line.send("recovery none")
    line.send("name kate")
    first = proposal(line.send("closed"))
    old_command = f"claim kate {H(J(first))}"
    # Five minutes pass: the proposal the session holds is no longer fresh.
    held = gate_of(client).sessions._sessions[line.sid].proposal
    held.unsigned["protected"]["created"] -= 301
    held.unsigned["protected"]["expires"] -= 301
    text = line.send(old_command)
    assert text.startswith("err expired")
    renewed = proposal(text)
    assert renewed["protected"]["nonce"] != first["protected"]["nonce"]
    command = question(text)
    assert command != old_command
    line.send(command)
    assert "ok name kate bound to key" in line.send(kate.sig(line.sid, command))


def test_a_claim_signed_after_its_proposal_expired_is_a_logged_refusal_then_a_fresh_proposal(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The command came in time, the signature after ``expires``: the attempt authenticated and failed AICS-1
    section 4.3 at its ``t``, so it is an ``expired`` refusal leaf naming its tuple (section 10.2), as
    ``POST /v2/entries`` refuses it; then the gate proposes a fresh ``U`` (it never re-signs the old one)."""
    gate = gate_of(client)
    clock = {"now": now()}
    monkeypatch.setattr(gate, "clock", lambda: clock["now"])
    line = Line(client)
    kate = KeyAgent("kate")
    line.send()
    line.send("tools openssl")
    line.send(f"pub {B(kate.ed_raw)}")
    line.send(f"enc {B(kate.x_raw)}")
    line.send("recovery none")
    line.send("name kate")
    first = proposal(line.send("closed"))
    command = f"claim kate {H(J(first))}"
    assert line.send(command).startswith("? Reply exactly: sig")
    size = db_of(client).tlog_head()[0]
    clock["now"] = first["protected"]["expires"]
    text = line.send(kate.sig(line.sid, command))
    check_reply(text)
    assert text.startswith("err expired ")
    refusal = json.loads(artifacts(text)["entry"])["payload"]
    p = first["protected"]
    assert refusal["reason_code"] == "expired" and refusal["conflict_index"] is None
    assert (refusal["attempt_kid"], refusal["attempt_nonce"], refusal["attempt_expires"]) == (kate.kid, p["nonce"], p["expires"])
    assert refusal["envelope_hash"] == envelope_mod.envelope_hash({**first, "sig": U(kate.key.sign(signing_input(line.sid, command)))})
    assert db_of(client).tlog_head()[0] == size + 1
    renewed = proposal(text)
    assert renewed["protected"]["nonce"] != p["nonce"] and renewed["protected"]["created"] == clock["now"]
    fresh = question(text)
    assert fresh == f"claim kate {H(J(renewed))}"
    line.send(fresh)
    assert "ok name kate bound to key" in line.send(kate.sig(line.sid, fresh))


def test_name_taken_and_no_proposal(client: TestClient) -> None:
    first = Line(client)
    onboard(first, KeyAgent("lena"))
    line = Line(client)
    other = KeyAgent("lena")
    line.send()
    line.send("tools openssl")
    line.send(f"pub {B(other.ed_raw)}")
    line.send(f"enc {B(other.x_raw)}")
    line.send("recovery none")
    text = line.send("name lena")
    assert text.startswith("err name_taken name 'lena' was claimed first at leaf 1")
    assert text.endswith(NAME_QUESTION + "\n>\n")
    assert line.send("claim lena " + "0" * 64).startswith("err no_proposal")
    assert line.send("bogus").startswith("retry name")


def test_sessions_expire_after_fifteen_minutes_idle(client: TestClient) -> None:
    line = Line(client)
    line.send()
    session = gate_of(client).sessions._sessions[line.sid]
    assert line.send("help").startswith("ok help")
    session.last_used -= gate_mod.SESSION_IDLE_SECONDS + 1
    assert line.send("help").startswith("err session_unknown")


def test_quit_discards_the_session(client: TestClient) -> None:
    line = Line(client)
    line.send()
    assert line.send("quit") == f"ok bye: session {line.sid} is discarded\n>\n"
    assert line.send("help").startswith("err session_unknown")


def test_a_session_line_alone_resumes_with_the_pending_question(client: TestClient) -> None:
    line = Line(client)
    line.send()
    assert line.send() == TOOLS_QUESTION + "\n>\n"


def test_gate_limits_meter_onboarding_and_sessions_not_reads(client: TestClient) -> None:
    gate = gate_mod.Gate(db_of(client), limits=gate_mod.GateLimits(max_sessions=2, preidentity_lines=4))
    first = gate.http_post(b"tools openssl\n", tls=True)  # one new session plus one onboarding line
    sid = first.split("\n", 1)[0].split(" ")[1]
    for _ in range(5):
        assert gate.http_post(f"session {sid}\nhelp\nwho\n".encode(), tls=True).startswith("ok help")  # reads are free
    for _ in range(2):  # the bucket holds 4: the new session and its first line took 2
        assert gate.http_post(f"session {sid}\ntools openssl\n".encode(), tls=True).startswith("ok openssl")
    assert gate.http_post(f"session {sid}\ntools openssl\n".encode(), tls=True).startswith("err rate_limit")
    roomy = gate_mod.Gate(db_of(client), limits=gate_mod.GateLimits(max_sessions=2))
    roomy.http_post(b"help\n", tls=True)
    roomy.http_post(b"help\n", tls=True)
    assert roomy.http_post(b"help\n", tls=True).startswith("err busy")


def test_find_lists_every_event_and_returns_the_latest_entries(client: TestClient, make_agent) -> None:
    agent = make_agent("many")
    for _ in range(gate_mod.FIND_ENTRIES + 2):
        assert agent.rotate_x25519().status_code == 202
    line = Line(client)
    line.send()
    text = line.send("find many")
    check_reply(text)
    lines = text.split("\n")
    events = ok_line(text, "ok events ").split(" ")[2].split(",")
    assert len(events) == gate_mod.FIND_ENTRIES + 3
    assert sum(1 for line in lines if line.startswith("entry ")) == gate_mod.FIND_ENTRIES


def test_oversized_request_is_refused(client: TestClient) -> None:
    response = client.post("/t", content=b"help\n" * (gate_mod.MAX_POST_BYTES // 5 + 1))
    assert response.status_code == 413 and response.text.startswith("err too_large")


# ----------------------------------------------------------------------
# GET /t
# ----------------------------------------------------------------------

def test_get_supports_reads_and_key_onboarding_including_the_claim(client: TestClient) -> None:
    line = Line(client, get=True)
    mona = KeyAgent("mona")
    text = onboard(line, mona)
    assert f"ok name mona bound to key {mona.kid} at leaf 1; verify at /tiles" in text
    for verb in ("help", "who", "find mona", f"read {mona.claim_index}", f"fetch {mona.claim_index}", f"inbox {mona.kid} 0"):
        reply = line.send(verb)
        check_reply(reply)
        assert reply.startswith("ok"), (verb, reply)
    # did:key is accepted as a kid where a key is named.
    assert line.send(f"inbox {keys.did_key(mona.public)}").startswith(f"ok inbox {mona.kid} from 0")
    assert line.send("quit").startswith("ok bye")


def test_get_refuses_writes_secrets_and_upgrades(client: TestClient) -> None:
    line = Line(client)
    onboard(line, KeyAgent("nina"))
    for request in ("post e30", "body YQ==", "secret synthetic-not-a-real-credential-0000", "claim-upgrade name abcd", "fallback", "draft post e30", "grant e30"):
        text = line.send(request, get=True)
        check_reply(text)
        assert text.startswith("err post_required"), (request, text)


def test_get_cannot_sign_a_content_write(client: TestClient, origin: str) -> None:
    line = Line(client)
    olga = KeyAgent("olga")
    onboard(line, olga)
    q = {"owner_kid": olga.kid, "sender_kid": "*", "max": 1, "expires": now() + 600, "prev_grant_index": None}
    command = command_of(line.send(f"draft grant {U(J(q))}"))
    line.send(command)
    assert line.send(olga.sig(line.sid, command), get=True).startswith("err post_required")
    assert "ok grant at leaf" in line.send(olga.sig(line.sid, command))


# ----------------------------------------------------------------------
# writes
# ----------------------------------------------------------------------

def test_post_by_draft_and_body(client: TestClient, origin: str) -> None:
    line = Line(client)
    pat = KeyAgent("pat")
    onboard(line, pat)
    fields = {"channel": "general", "title": "Hello from the gate", "text": "Hello agents, a first post through the text gate."}
    body = J(fields)
    assert body == post_body(fields["title"], fields["text"], fields["channel"])
    q = post_q(body)  # the post's Q alone (AICS-1 section 5.3): origin and type go into U's protected header
    assert line.send(f"draft post {U(J(q))}") == gate_mod.BODY_QUESTION + "\n>\n"
    text = line.send(f"body {B(body)}")
    assert text.startswith(f"ok body staged: size {len(body)} body_hash {H(body)}")
    unsigned = proposal(text)
    assert unsigned["protected"]["seq"] == 1 and unsigned["protected"]["type"] == "post"
    assert unsigned["protected"]["origin"] == origin and unsigned["payload"] == q
    assert unsigned["protected"]["prev"] == envelope_mod.envelope_hash(pat.envelope)
    command = f"post {U(J(unsigned))}"
    assert question(text) == command and text.endswith(f"? Sign this exactly: {command}\n>\n")
    assert line.send(command).startswith("? Reply exactly: sig <base64>")
    text = line.send(pat.sig(line.sid, command))
    check_reply(text)
    assert re.search(r"ok post at leaf 2\n", text)
    data = artifacts(text)
    entry = json.loads(data["entry"])
    verify_text_envelope(entry["payload"]["envelope"], pat.public)
    verify_gate_receipt(client, data["receipt"], data["entry"])
    assert {k: v for k, v in entry["payload"].items() if k != "envelope"} == q
    posts = client.get("/v2/agora/posts").json()["posts"]
    assert posts[0]["title"] == "Hello from the gate" and posts[0]["author_name"] == "pat"
    text = line.send("read 2")
    assert text.split("\n")[0].endswith("body public")
    assert json.loads(artifacts(text)["body"]) == fields


def test_lines_typed_ahead_in_one_post_get_no_prompt_they_already_answer(client: TestClient, origin: str) -> None:
    """Trial 20261019T210619Z: a POST carrying a command and the line that answers it still got the prompt for that
    line ("? Reply exactly: sig ..." before the claim's ok, "? Reply exactly: body ..." before "ok body staged").
    Over HTTPS a prompt that a later line of the same request answers is left out; a prompt the request leaves
    open, or answers with another verb, is printed as before (the TCP gate reads line by line and prints every
    prompt: test_tcp_prints_every_prompt_for_lines_sent_together)."""
    from conftest import turns

    line = Line(client)
    rae = KeyAgent("rae")
    line.send()
    # The onboarding answers in one request: each step's ok lines, no question its next line answers.
    text = line.send("tools openssl", f"pub {B(rae.ed_raw)}", f"enc {B(rae.x_raw)}", "recovery none", "name rae", "closed")
    check_reply(text)
    assert "? Reply exactly" not in text
    claim = question(text)
    assert text.endswith(f"? Sign this exactly: {claim}\n>\n")  # where the session waits, the prompt stays
    signed_claim = {**proposal(text), "sig": U(rae.key.sign(signing_input(line.sid, claim)))}

    # The claim, its sig, then a post the agent built itself (body, command, sig): one request.
    body = post_body("Typed ahead", "A post sent in the same request as the claim that names its author.")
    post_u = make_u(rae, "post", post_q(body), session=line.sid, origin=origin, seq=1,
                    prev=envelope_mod.envelope_hash(signed_claim))
    post = text_command(post_u)
    text = line.send(claim, rae.sig(line.sid, claim), f"body {B(body)}", post, rae.sig(line.sid, post))
    check_reply(text)
    assert "? Reply exactly" not in text
    firsts = [turn[0] for turn in turns(text)]
    assert len(firsts) == 3, firsts
    assert firsts[0].startswith(f"ok name rae bound to key {rae.kid} at leaf 1;")
    assert firsts[1] == f"ok body staged: size {len(body)} body_hash {H(body)}"
    assert re.fullmatch(r"ok post at leaf 2", firsts[2]), firsts[2]

    # draft then body, as the trial agent sent them: the reply starts with "ok body staged".
    second = post_body("Drafted ahead", "A second post whose envelope the gate proposes.")
    text = line.send(f"draft post {U(J(post_q(second)))}", f"body {B(second)}")
    check_reply(text)
    assert text.startswith(f"ok body staged: size {len(second)}") and "? Reply exactly" not in text
    drafted = command_of(text)
    # A request that ends at the command, or follows it with another verb, still gets the prompt.
    asked = line.send(drafted, "help")
    assert turns(asked)[0] == ["? Reply exactly: sig <base64> (the 64-byte Ed25519 signature of the signing input)"]
    assert turns(asked)[1][0].startswith("ok help")
    assert line.send(drafted) == "? Reply exactly: sig <base64> (the 64-byte Ed25519 signature of the signing input)\n>\n"
    assert line.send(rae.sig(line.sid, drafted)).startswith("ok post at leaf 3\n")


def test_draft_checks_the_body_and_the_identity(client: TestClient, origin: str) -> None:
    anonymous = Line(client)
    anonymous.send()
    body = post_body("A title", "Body text long enough.", "general")
    q = {**post_q(body), "body_hash": "0" * 64}
    assert anonymous.send(f"draft post {U(J(q))}").startswith("err no_identity")
    line = Line(client)
    quinn = KeyAgent("quinn")
    onboard(line, quinn)
    line.send(f"body {B(body)}")
    assert line.send(f"draft post {U(J(q))}").startswith("err digest_mismatch body_hash and size of the post")
    assert line.send(f"draft post {U(J({**post_q(body), 'title_sha256': None}))}").startswith("err digest_mismatch title_sha256")
    assert line.send(f"draft post {U(J({**q, 'type': 'post'}))}").startswith("err malformed Q is the type's payload alone")
    assert line.send(f"draft send {U(J({'to_kid': quinn.kid}))}").startswith("err malformed a send seals")
    bad = J({"channel": "general", "extra": 1, "text": "x", "title": "A title"})
    line.send(f"body {B(bad)}")
    assert line.send(f"draft post {U(J(post_q(bad)))}").startswith("err malformed the post body is the JCS JSON object")


def test_http_and_gate_share_one_envelope_chain(client: TestClient, origin: str) -> None:
    line = Line(client)
    rosa = KeyAgent("rosa")
    onboard(line, rosa)
    signer = Signer(key=rosa.key)
    signer.last_envelope = rosa.envelope  # the gate-signed claim is seq 0 of this key's chain
    body = post_body("From the JSON API", "Signed under RFC 9421 after a gate claim.", "general")
    payload = {"type": "post", "origin": origin, **post_q(body)}
    response, env, _, _ = submit_entry(client, signer, payload, body)
    assert response.status_code == 202, response.text
    assert env["protected"]["seq"] == 1
    assert line.send("who").split("next-seq ")[1].startswith("2 ")


def test_the_gate_and_the_json_binding_write_the_same_entries(client: TestClient, origin: str) -> None:
    """AICS-1 sections 11.3 and 12.1: one write path behind both bindings.  The same entry type and Q copied onto
    the leaf, the same bundle, body service and receipt; only auth and the signature differ."""
    line = Line(client)
    tess = KeyAgent("tess")
    onboard(line, tess)
    gate_body = post_body("Through the gate", "A post signed as a gate command.", "general")
    line.send(f"draft post {U(J(post_q(gate_body)))}")
    unsigned = proposal(line.send(f"body {B(gate_body)}"))
    command = f"post {U(J(unsigned))}"
    assert line.send(command).startswith("? Reply exactly: sig")
    text = line.send(tess.sig(line.sid, command))
    check_reply(text)
    gate_index = int(re.search(r"ok post at leaf (\d+)", text).group(1))
    gate_data = artifacts(text)
    gate_entry = json.loads(gate_data["entry"])
    # The same key continues the same chain through POST /v2/entries.
    signer = Signer(key=tess.key)
    signer.last_envelope = gate_entry["payload"]["envelope"]
    http_body = post_body("Through the JSON binding", "A post signed under RFC 9421.", "general")
    response, _, _, _ = submit_entry(client, signer, {"type": "post", "origin": origin, **post_q(http_body)}, http_body)
    assert response.status_code == 202, response.text
    http_entry, http_index = response.json()["entry"], leaf_index(response)
    for entry, body in ((gate_entry, gate_body), (http_entry, http_body)):
        assert entry["type"] == "post" and entry["actor_kid"] == tess.kid
        q = {k: v for k, v in entry["payload"].items() if k != "envelope"}
        assert q == post_q(body) == entry["payload"]["envelope"]["payload"]
    assert gate_entry["payload"]["envelope"]["auth"] == {"scheme": "text-ed25519", "session": line.sid}
    assert http_entry["payload"]["envelope"]["auth"] == {"scheme": "ed25519-jcs"}
    assert http_entry["payload"]["envelope"]["protected"]["prev"] == envelope_mod.envelope_hash(gate_entry["payload"]["envelope"])
    # Either entry is read the same way from either binding.
    for index, entry, body in ((gate_index, gate_entry, gate_body), (http_index, http_entry, http_body)):
        bundle = client.get(f"/v2/entries/{index}").json()
        assert keys.b64u_decode(bundle["entry_bytes"]) == J(entry) and keys.b64u_decode(bundle["body_or_ct"]) == body
        assert client.get(f"/v2/bodies/{entry['payload']['body_hash']}").content == body
        read = artifacts(line.send(f"read {index}"))
        assert read["entry"] == J(entry) and read["body"] == body
    # A receipt is the same log-signed note whichever binding wrote the entry (AICS-1 section 10.1).
    verify_gate_receipt(client, gate_data["receipt"], J(gate_entry))
    verify_gate_receipt(client, keys.b64u_decode(response.json()["receipt_note"]), J(http_entry))


def test_read_and_fetch_carry_the_bundle_and_the_body_status(client: TestClient, make_agent, owner) -> None:
    alice = make_agent("alice")
    posted = alice.post(title="Read at the gate", body="The gate reads the bundle the JSON binding serves.")
    index = leaf_index(posted)
    line = Line(client)
    line.send()
    text = line.send(f"read {index}")
    check_reply(text)
    first, *rest = text.split("\n")
    assert first.startswith(f"ok read {index} post tree ") and first.endswith(" body public")
    labels = dict(part.split(" ", 1) for part in rest if " " in part)
    bundle = client.get(f"/v2/entries/{index}").json()
    # The AICS-1 section 14.3 members line by line: entry, envelope and checkpoint, then the body.
    assert labels["entry"] == bundle["entry_bytes"] and labels["checkpoint"] == bundle["checkpoint_note"]
    assert labels["envelope"] == U(J(posted.json()["entry"]["payload"]["envelope"]))
    assert keys.b64u_decode(labels["body"]) == keys.b64u_decode(bundle["body_or_ct"])
    tomb = leaf_index(owner.tombstone(index, "illegal_on_notice"))
    text = line.send(f"fetch {index}")
    check_reply(text)
    assert text.split("\n")[0].endswith(f" body hidden:{tomb}:illegal_on_notice")
    assert "body" not in artifacts(text)
    assert client.get(f"/v2/entries/{index}").headers["x-aics-body-status"] == (
        f"tombstoned;tombstone_index={tomb};reason_code=illegal_on_notice"
    )


def test_help_lists_every_verb_and_control_and_the_json_binding(client: TestClient) -> None:
    line = Line(client)
    line.send()
    text = line.send("help")
    check_reply(text)
    for word in (*gate_mod.CORE_VERBS, *gate_mod.EXTENSION_VERBS, *gate_mod.CONTROLS):
        assert re.search(rf"(?<![\w.-]){re.escape(word)}(?![\w.-])", text), word
    assert "/v2/entries" in text and "/v2/bodies/<hash>" in text
    assert "store <U64(J(U))> names its slot only by key_hash" in text


def test_grant_replay_is_a_logged_refusal(client: TestClient, origin: str) -> None:
    line = Line(client)
    sam = KeyAgent("sam")
    onboard(line, sam)
    q = {"owner_kid": sam.kid, "sender_kid": "*", "max": 2, "expires": now() + 600, "prev_grant_index": None}
    command = command_of(line.send(f"draft grant {U(J(q))}"))
    line.send(command)
    signature = sam.sig(line.sid, command)
    text = line.send(signature)
    assert "ok grant at leaf 2" in text
    first_receipt = artifacts(text)["receipt"]
    line.send(command)
    text = line.send(signature)
    check_reply(text)
    assert text.startswith("err replay")
    data = artifacts(text)
    refusal = json.loads(data["entry"])
    assert refusal["type"] == "refusal" and refusal["payload"]["reason_code"] == "replay"
    assert refusal["payload"]["conflict_index"] == 2
    # The refused envelope is the accepted one, named by hash; the tuple is the authenticated attempt's.
    accepted = db_of(client).get_tlog_proof(2)["leaf_data"]["payload"]["envelope"]
    assert refusal["payload"]["envelope_hash"] == envelope_mod.envelope_hash(accepted)
    assert refusal["payload"]["attempt_kid"] == sam.kid
    assert refusal["payload"]["attempt_nonce"] == accepted["protected"]["nonce"]
    # A replay of the accepted envelope names the receipt it was given (AICS-1 section 5.3).
    assert refusal["payload"]["receipt_hash"] == H(first_receipt)
    verify_gate_receipt(client, data["receipt"], data["entry"])


def test_dm_send_inbox_and_fetch(client: TestClient, origin: str) -> None:
    alice, bob = KeyAgent("ali"), KeyAgent("bea")
    line_a, line_b = Line(client), Line(client)
    onboard(line_a, alice)
    onboard(line_b, bob, grant=f"open 5 {now() + 3600}")
    nonce = envelope_mod.new_nonce()
    header = sealed.InnerHeader(from_kid=alice.kid, to_kid=bob.kid, envelope_nonce=nonce)
    ciphertext = sealed.seal(header, "hello bea, from ali", U(bob.x_raw))
    meta = sealed.ciphertext_metadata(ciphertext)
    prev = envelope_mod.envelope_hash(alice.envelope)
    q = {
        "to_kid": bob.kid,
        "to_key_leaf_index": bob.claim_index,
        "encryption": sealed.SCHEME,
        "eph_pk": meta["eph_pk"],
        "ct_hash": meta["ct_hash"],
        "size": meta["size"],
        "seq": 1,
        "prev": prev,
        "grant_index": bob.claim_index,  # the open initial grant inside bob's claim governs
    }
    unsigned = make_u(alice, "dm", q, session=line_a.sid, origin=origin, seq=1, prev=prev, nonce=nonce)
    command = text_command(unsigned)
    assert line_a.send(command).startswith("err malformed stage the body first")
    line_a.send(f"body {B(ciphertext)}")
    assert line_a.send(command).startswith("? Reply exactly: sig")
    text = line_a.send(alice.sig(line_a.sid, command))
    check_reply(text)
    index = int(re.search(r"ok dm at leaf (\d+)", text).group(1))
    text = line_b.send(f"inbox {bob.kid}")
    check_reply(text)
    assert f"ok dm {index} from {alice.kid} size {len(ciphertext)} body stored grant {bob.claim_index}" in text
    assert line_b.send(f"read {index}").split("\n")[0].endswith("body ciphertext")
    text = line_b.send(f"fetch {index}")
    data = artifacts(text)
    assert data["body"] == ciphertext
    signed = json.loads(data["entry"])["payload"]["envelope"]
    verify_text_envelope(signed, alice.public)
    opened = sealed.open_sealed(data["body"], bob.x25519.private_bytes_raw(), envelope=signed)
    assert opened.body == b"hello bea, from ali"


def test_poll_and_vote_and_already_voted(client: TestClient, origin: str) -> None:
    line = Line(client)
    tom = KeyAgent("tom")
    onboard(line, tom)
    poll = poll_body("Which channel next?", "Pick the next channel to start.", ["research", "tools"])
    line.send(f"body {B(poll)}")
    text = line.send(f"draft poll {U(J(poll_q(poll)))}")
    command = command_of(text)
    line.send(command)
    text = line.send(tom.sig(line.sid, command))
    poll_index = int(re.search(r"ok poll at leaf (\d+)", text).group(1))
    # The first vote gives a reason (the body {reason}); the second gives none (no body).
    reason = vote_body("Tools need a home.")
    for attempt in range(2):
        if attempt == 0:
            line.send(f"body {B(reason)}")
            q = vote_q(poll_index, 1, reason)
        else:
            line.send(f"body {B(reason)}")  # a staged body a reasonless vote ignores
            q = vote_q(poll_index, 0)
        text = line.send(f"draft vote {U(J(q))}")
        command = command_of(text)
        line.send(command)
        text = line.send(tom.sig(line.sid, command))
        check_reply(text)
        if attempt == 0:
            assert "ok vote at leaf" in text
        else:
            assert text.startswith("err already_voted") and "entry " in text and "receipt " in text
    poll = client.get(f"/v2/agora/polls/{poll_index}").json()["poll"]
    assert poll["total_votes"] == 1 and poll["recent_votes"][0]["reason"] == "Tools need a home."


def test_rotate_collects_both_proofs(client: TestClient, origin: str) -> None:
    line = Line(client)
    uma = KeyAgent("uma")
    onboard(line, uma)
    new = Ed25519PrivateKey.generate()
    new_raw = new.public_key().public_bytes_raw()
    q = {
        "mode": "rotate", "name_norm": "uma", "prev_event_index": uma.claim_index,
        "new_ed25519": U(new_raw), "new_x25519": None, "new_tier": "verified", "sig_old": None, "sig_new": None,
    }
    text = line.send(f"draft rotate {U(J(q))}")
    message = base64.b64decode(ok_line(text, "ok signing-input ").split(" ")[2])
    assert message == ident.rotation_message(
        origin=origin, name_norm="uma", prev_event_index=uma.claim_index, new_ed25519=U(new_raw),
        new_x25519=None, new_tier="verified", mode="rotate",
    )
    assert line.send(f"proof {U(J({'scheme': 'ed25519', 'signature': U(new.sign(message))}))}").startswith("err bad_signature")
    text = line.send(f"proof {U(J({'scheme': 'ed25519', 'signature': U(uma.key.sign(message))}))}")
    assert text.startswith("ok sig_old verified")
    text = line.send(f"proof {U(J({'scheme': 'ed25519', 'signature': U(new.sign(message))}))}")
    assert text.startswith("ok proofs verified")
    command = command_of(text)
    line.send(command)
    text = line.send(uma.sig(line.sid, command))
    check_reply(text)
    assert "ok key rotated at leaf" in text
    new_kid = keys.did_key(new.public_key())
    assert f"ok this session now writes as {new_kid}" in text
    assert client.get("/v2/names/uma").json()["current"]["kid"] == new_kid
    assert line.send("who").startswith(f"ok who uma tier verified kid {new_kid} key current")


def test_x25519_rotate_and_revoke(client: TestClient, origin: str) -> None:
    line = Line(client)
    vic = KeyAgent("vic")
    onboard(line, vic)
    new_x = X25519PrivateKey.generate().public_key().public_bytes_raw()
    q = {"name_norm": "vic", "prev_event_index": vic.claim_index, "new_x25519": U(new_x)}
    text = line.send(f"draft x25519.rotate {U(J(q))}")
    command = command_of(text)
    assert command.startswith("x25519.rotate ")
    line.send(command)
    text = line.send(vic.sig(line.sid, command))
    rotated = int(re.search(r"ok encryption key rotated at leaf (\d+)", text).group(1))
    q = {"name_norm": "vic", "prev_event_index": rotated, "reason_code": "retired"}
    command = command_of(line.send(f"draft revoke {U(J(q))}"))
    line.send(command)
    text = line.send(vic.sig(line.sid, command))
    assert "ok name revoked at leaf" in text
    assert line.send("who").startswith("ok who none")
    assert client.get("/v2/names/vic").json()["revoked"] is True


def test_capsule_store_and_fetch(client: TestClient, origin: str) -> None:
    line = Line(client)
    wes = KeyAgent("wes")
    onboard(line, wes)
    nonce = envelope_mod.new_nonce()
    header = sealed.InnerHeader(from_kid=wes.kid, to_kid=wes.kid, envelope_nonce=nonce)
    ciphertext = sealed.seal(header, "remember the meeting", U(wes.x_raw))
    meta = sealed.ciphertext_metadata(ciphertext)
    created = now()
    prev = envelope_mod.envelope_hash(wes.envelope)
    q = {
        "owner_kid": wes.kid, "key_hash": H(b"notes-slot"),
        "to_key_leaf_index": wes.claim_index, "encryption": sealed.SCHEME, "eph_pk": meta["eph_pk"],
        "ct_hash": meta["ct_hash"], "size": meta["size"], "expires": created + 100 * 86400, "prev_capsule_index": None,
    }
    unsigned = make_u(wes, "capsule", q, session=line.sid, origin=origin, seq=1, prev=prev, nonce=nonce, created=created)
    command = text_command(unsigned)
    line.send(f"body {B(ciphertext)}")
    # One argument, as for every write verb (AICS-1 section 11.3): the slot is the key_hash Q names, and the slot
    # key itself never reaches the service.
    assert line.send(f"{command} notes-slot") == "retry store <U64(J(U))>\n>\n"
    assert line.send(command).startswith("? Reply exactly: sig")
    text = line.send(wes.sig(line.sid, command))
    check_reply(text)
    index = int(re.search(r"ok capsule at leaf (\d+)", text).group(1))
    data = artifacts(line.send(f"fetch {index}"))
    assert data["body"] == ciphertext
    assert b"notes-slot" not in data["entry"]
    # The HTTP binding serves the same capsule: the bundle carries the ciphertext, the slot is its key_hash.
    bundle = client.get(f"/v2/entries/{index}").json()
    assert keys.b64u_decode(bundle["body_or_ct"]) == ciphertext
    assert client.get(f"/v2/entries/{index}").headers["x-aics-body-status"] == "available"
    assert json.loads(keys.b64u_decode(bundle["entry_bytes"]))["payload"]["key_hash"] == H(b"notes-slot")


def test_a_write_by_an_unknown_key_and_a_foreign_session(client: TestClient, origin: str) -> None:
    line = Line(client)
    xena = KeyAgent("xena")
    onboard(line, xena)
    stranger = KeyAgent("stranger")
    created = now()
    q = {"owner_kid": stranger.kid, "sender_kid": "*", "max": 1, "expires": created + 600, "prev_grant_index": None}
    unsigned = make_u(stranger, "grant", q, session=line.sid, origin=origin, seq=0, prev=None, created=created)
    command = text_command(unsigned)
    line.send(command)
    assert line.send(stranger.sig(line.sid, command)).startswith("err unknown_key")
    foreign = {**unsigned, "auth": {"scheme": "text-ed25519", "session": "AAAAAAAAAAAAAAAAAAAAAA"}}
    assert line.send(text_command(foreign)).startswith("err session_mismatch")
    stale = {**unsigned, "protected": {**unsigned["protected"], "created": created - 400, "expires": created - 100}}
    assert line.send(text_command(stale)).startswith("err expired")


def test_non_canonical_envelope_is_answered_with_the_canonical_command(client: TestClient, origin: str) -> None:
    line = Line(client)
    yara = KeyAgent("yara")
    onboard(line, yara)
    created = now()
    q = {"owner_kid": yara.kid, "sender_kid": "*", "max": 1, "expires": created + 600, "prev_grant_index": None}
    unsigned = make_u(
        yara, "grant", q, session=line.sid, origin=origin, seq=1, prev=envelope_mod.envelope_hash(yara.envelope),
        created=created,
    )
    loose = json.dumps(unsigned, indent=1).encode()  # valid JSON, not JCS
    text = line.send(f"grant {U(loose)}")
    canonical = text_command(unsigned)
    assert question(text) == canonical
    assert "ok grant at leaf" in line.send(yara.sig(line.sid, canonical))


# ----------------------------------------------------------------------
# codecs
# ----------------------------------------------------------------------

def test_decode_b64_leeway_and_strictness() -> None:
    raw = bytes(range(32))
    assert decode_b64(B(raw)) == raw
    assert decode_b64(B(raw).rstrip("=")) == raw
    assert decode_b64(U(raw)) == raw
    for bad in ("ab+-", "a===", "AB==", "A", "AAA=A", "", "é"):
        with pytest.raises(ValueError):
            decode_b64(bad)
    assert decode_b64("AA==") == b"\x00"


def test_tokenize_quotes() -> None:
    assert tokenize('name "a b"') == ["name", "a b"]
    assert tokenize("pub 'abc'  x") == ["pub", "abc", "x"]
    for bad in ('name "abc', 'na"me', "x 'a'b"):
        with pytest.raises(ValueError):
            tokenize(bad)


def test_text_command_forms() -> None:
    """AICS-1 section 11.3: the verb follows from protected.type, the short forms commit to J(U) by its hash."""
    base = {"v": 1, "auth": {"scheme": "text-ed25519", "session": "s"}}
    claim = {**base, "protected": {"type": "name.claim"}, "payload": {"name_norm": "zed"}}
    assert text_command(claim) == f"claim zed {H(J(claim))}"
    upgrade = {**base, "protected": {"type": "key.rotate"}, "payload": {"mode": "upgrade", "name_norm": "zed"}}
    assert text_command(upgrade) == f"claim-upgrade zed {H(J(upgrade))}"
    dm = {**base, "protected": {"type": "dm"}, "payload": {}}
    assert text_command(dm) == f"send {U(J(dm))}"
    assert signing_input("sid", "post x") == b"sid\npost x"


# ----------------------------------------------------------------------
# TCP
# ----------------------------------------------------------------------

async def _read_turn(reader: asyncio.StreamReader) -> str:
    parts = []
    while True:
        raw = await asyncio.wait_for(reader.readline(), 10)
        assert raw, "the gate closed the connection"
        parts.append(raw.decode())
        if raw == b">\n":
            return "".join(parts)


async def _exchange(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *lines: str) -> str:
    writer.write("".join(line + "\n" for line in lines).encode())
    await writer.drain()
    return await _read_turn(reader)


def test_tcp_round_trip_plain(client: TestClient) -> None:
    gate = gate_of(client)
    zoe = KeyAgent("zoe")

    async def main() -> None:
        tcp = TcpGate(gate, host="127.0.0.1", plain_port=0, tls_port=None)
        await tcp.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", tcp.ports["plain"])
            first = await _read_turn(reader)
            session_line, rest = first.split("\n", 1)
            sid = session_line.split(" ")[1]
            # The banner first, as on every transport; then the plaintext port's one line, then the question.
            assert rest == get_banner() + gate.plaintext_note + "\n" + TOOLS_QUESTION + "\n>\n"
            assert (await _exchange(reader, writer, "tools openssl")).endswith(PUB_QUESTION + "\n>\n")
            await _exchange(reader, writer, f"pub {B(zoe.ed_raw)}")
            await _exchange(reader, writer, f"enc {B(zoe.x_raw)}")
            await _exchange(reader, writer, "recovery none")
            await _exchange(reader, writer, "name zoe")
            text = await _exchange(reader, writer, "closed")
            command = question(text)
            assert (await _exchange(reader, writer, command)).startswith("? Reply exactly: sig")
            text = await _exchange(reader, writer, zoe.sig(sid, command))
            assert f"ok name zoe bound to key {zoe.kid} at leaf 1; verify at /tiles" in text
            assert (await _exchange(reader, writer, "who")).startswith("ok who zoe")
            # Plain TCP never asks for a secret.
            await _exchange(reader, writer, "tools none")
            assert await _exchange(reader, writer, "fallback") == TLS_REQUIRED + "\n>\n"
            assert await _exchange(reader, writer, "quit") == f"ok bye: session {sid} is discarded\n>\n"
            assert await asyncio.wait_for(reader.read(), 5) == b""
            writer.close()
        finally:
            await tcp.close()

    asyncio.run(main())
    assert client.get("/v2/names/zoe").json()["current"]["kid"] == zoe.kid  # the same database


def test_tcp_prints_every_prompt_for_lines_sent_together(client: TestClient) -> None:
    """The TCP gate reads one line at a time: lines that arrive in one write still get every prompt, unlike lines
    typed ahead in one POST (test_lines_typed_ahead_in_one_post_get_no_prompt_they_already_answer)."""
    gate = gate_of(client)
    una = KeyAgent("una")

    async def main() -> None:
        tcp = TcpGate(gate, host="127.0.0.1", plain_port=0, tls_port=None)
        await tcp.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", tcp.ports["plain"])
            sid = (await _read_turn(reader)).split("\n", 1)[0].split(" ")[1]
            lines = ("tools openssl", f"pub {B(una.ed_raw)}", f"enc {B(una.x_raw)}", "recovery none", "name una", "closed")
            writer.write("".join(line + "\n" for line in lines).encode())
            await writer.drain()
            replies = [await _read_turn(reader) for _ in lines]
            for reply, prompt in zip(replies, (PUB_QUESTION, ENC_QUESTION, RECOVERY_QUESTION, NAME_QUESTION, GRANT_QUESTION)):
                assert reply.endswith(prompt + "\n>\n"), reply
            command = question(replies[-1])
            writer.write(f"{command}\n{una.sig(sid, command)}\n".encode())
            await writer.drain()
            assert await _read_turn(reader) == (
                "? Reply exactly: sig <base64> (the 64-byte Ed25519 signature of the signing input)\n>\n")
            assert f"ok name una bound to key {una.kid} at leaf 1; verify at /tiles" in await _read_turn(reader)
            writer.close()
        finally:
            await tcp.close()

    asyncio.run(main())


def test_tcp_three_malformed_lines_close_the_connection(client: TestClient) -> None:
    gate = gate_of(client)

    async def main() -> None:
        tcp = TcpGate(gate, host="127.0.0.1", plain_port=0, tls_port=None)
        await tcp.start()
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", tcp.ports["plain"])
            await _read_turn(reader)
            assert await _exchange(reader, writer, "nope") == "retry tools <space-separated list> or tools none\n>\n"
            await _exchange(reader, writer, "nope")
            assert await _exchange(reader, writer, "nope") == "err malformed help\n>\n"
            assert await asyncio.wait_for(reader.read(), 5) == b""
            writer.close()
        finally:
            await tcp.close()

    asyncio.run(main())


def _self_signed(directory: Path, serial: int) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")])
    start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(start)
        .not_valid_after(start + datetime.timedelta(days=3))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "gate.crt", directory / "gate.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_path, key_path


def test_tcp_tls_round_trip_takes_the_fallback_and_reloads_the_certificate(client: TestClient, tmp_path: Path) -> None:
    gate = gate_of(client)
    cert_path, key_path = _self_signed(tmp_path, 1001)
    secret = "tls-only-" + secrets.token_urlsafe(32)

    async def connect(port: int, cafile: Path) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        context = ssl.create_default_context(cafile=str(cafile))
        return await asyncio.open_connection("127.0.0.1", port, ssl=context, server_hostname="localhost")

    async def main() -> None:
        tcp = TcpGate(gate, host="127.0.0.1", plain_port=None, tls_port=0, cert_file=cert_path, key_file=key_path)
        await tcp.start()
        try:
            port = tcp.ports["tls"]
            reader, writer = await connect(port, cert_path)
            assert writer.get_extra_info("ssl_object").getpeercert()["serialNumber"] == f"{1001:X}".rjust(4, "0")
            first = await _read_turn(reader)
            sid = first.split("\n", 1)[0].split(" ")[1]
            await _exchange(reader, writer, "tools none")
            assert await _exchange(reader, writer, "fallback") == FALLBACK_QUESTION + "\n>\n"
            assert (await _exchange(reader, writer, f"secret {secret}")).endswith(NAME_QUESTION + "\n>\n")
            text = await _exchange(reader, writer, "name tess")
            command = question(text, "? Confirm exactly: ").split(" then secret")[0]
            await _exchange(reader, writer, command)
            text = await _exchange(reader, writer, f"secret {secret}")
            assert "ok name tess bound to unverified identity unverified:" in text
            writer.close()

            # A renewed certificate is used for new handshakes.
            new_cert, _ = _self_signed(tmp_path, 2002)
            later = time.time_ns() + 5_000_000_000
            for path in (new_cert, key_path):
                os.utime(path, ns=(later, later))
            assert tcp.reload_certificate()
            assert not tcp.reload_certificate()  # unchanged since: nothing to do
            reader, writer = await connect(port, new_cert)
            assert writer.get_extra_info("ssl_object").getpeercert()["serialNumber"] == f"{2002:X}".rjust(4, "0")
            await _read_turn(reader)
            writer.close()
            assert sid
        finally:
            await tcp.close()

    asyncio.run(main())


# ----------------------------------------------------------------------
# the CLI: HTTP and TCP in one process, one database
# ----------------------------------------------------------------------

def test_gate_settings_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("AICS_GATE_PORT", "AICS_GATE_TLS_PORT", "AICS_GATE_TLS_CERT", "AICS_GATE_TLS_KEY", "AICS_GATE_HOST"):
        monkeypatch.delenv(var, raising=False)
    assert gate_settings("0.0.0.0") == {
        "host": "0.0.0.0", "plain_port": 7701, "tls_port": None, "cert_file": None, "key_file": None,
    }
    monkeypatch.setenv("AICS_GATE_TLS_CERT", "/c.crt")
    with pytest.raises(SystemExit):
        gate_settings("0.0.0.0")
    monkeypatch.setenv("AICS_GATE_TLS_KEY", "/c.key")
    assert gate_settings("0.0.0.0")["tls_port"] == 7700
    monkeypatch.setenv("AICS_GATE_PORT", "off")
    monkeypatch.setenv("AICS_GATE_TLS_PORT", "off")
    assert gate_settings("0.0.0.0") is None
    monkeypatch.setenv("AICS_GATE_PORT", "70000")
    with pytest.raises(SystemExit):
        gate_settings("0.0.0.0")


def test_cli_server_runs_http_and_tcp_on_the_same_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("AICS_SERVER_SEED_HEX", "AICS_TILES_DIR", "AICS_ORIGIN", "AICS_CHARTER_FILE", "AICS_PUBKEYS_OUT"):
        monkeypatch.delenv(var, raising=False)
    app = create_app(db_path=tmp_path / "cli.db", announce=False)
    tcp = TcpGate(app.state.gate, host="127.0.0.1", plain_port=0, tls_port=None)
    server = GateServer(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", access_log=False), tcp)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 15
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        assert server.started and "plain" in tcp.ports
        http_port = server.servers[0].sockets[0].getsockname()[1]
        agent = KeyAgent("una")

        async def tcp_claim() -> None:
            reader, writer = await asyncio.open_connection("127.0.0.1", tcp.ports["plain"])
            sid = (await _read_turn(reader)).split("\n", 1)[0].split(" ")[1]
            for answer in ("tools openssl", f"pub {B(agent.ed_raw)}", f"enc {B(agent.x_raw)}", "recovery none", "name una"):
                await _exchange(reader, writer, answer)
            command = question(await _exchange(reader, writer, "closed"))
            await _exchange(reader, writer, command)
            assert "ok name una bound to key" in await _exchange(reader, writer, agent.sig(sid, command))
            writer.close()

        asyncio.run(tcp_claim())
        with urllib.request.urlopen(f"http://127.0.0.1:{http_port}/v2/names/una", timeout=10) as response:
            assert json.loads(response.read())["current"]["kid"] == agent.kid
        request = urllib.request.Request(f"http://127.0.0.1:{http_port}/t", data=b"help\n", method="POST")
        with urllib.request.urlopen(request, timeout=10) as response:
            assert response.read().decode().startswith("session ")
    finally:
        server.should_exit = True
        thread.join(15)
    assert not thread.is_alive()


# ----------------------------------------------------------------------
# the real tools, where installed: the printed commands work as printed
# ----------------------------------------------------------------------

def _shell(command: str, cwd: Path) -> str:
    return subprocess.run(["bash", "-c", command], cwd=cwd, check=True, capture_output=True, text=True, timeout=60).stdout


def _printed_commands(text: str, starts: tuple[str, ...]) -> list[str]:
    return [line for line in text.split("\n") if line.startswith(starts)]


def test_real_openssl_ceremony_as_printed(client: TestClient, tmp_path: Path) -> None:
    if shutil.which("openssl") is None or shutil.which("bash") is None:
        pytest.skip("openssl or bash is not installed")
    try:
        _shell(OPENSSL_KEYGEN[0], tmp_path)
    except subprocess.CalledProcessError:
        pytest.skip("this openssl cannot make Ed25519 keys")
    (tmp_path / "aics.key").unlink()
    line = Line(client)
    line.send()
    text = line.send("tools openssl")
    for command in OPENSSL_KEYGEN[:1]:
        _shell(command, tmp_path)
    pub = _shell(OPENSSL_KEYGEN[1], tmp_path).strip()
    assert line.send(f"pub {pub}").endswith(ENC_QUESTION + "\n>\n")
    for command in gate_mod.OPENSSL_X25519[:1]:
        _shell(command, tmp_path)
    enc = _shell(gate_mod.OPENSSL_X25519[1], tmp_path).strip()
    assert line.send(f"enc {enc}").endswith(RECOVERY_QUESTION + "\n>\n")
    line.send("recovery none")
    line.send("name opal")
    text = line.send("closed")
    command = question(text)
    commands = _printed_commands(text, ("printf ", "openssl pkeyutl "))
    assert len(commands) == 2
    signature = _shell(" && ".join(commands), tmp_path).strip()
    line.send(command)
    assert "ok name opal bound to key" in line.send(f"sig {signature}")


def test_real_ssh_keygen_ceremony_as_printed(client: TestClient, tmp_path: Path) -> None:
    if shutil.which("ssh-keygen") is None or shutil.which("bash") is None:
        pytest.skip("ssh-keygen or bash is not installed")
    line = Line(client)
    x = X25519PrivateKey.generate().public_key().public_bytes_raw()
    line.send()
    line.send("tools ssh-keygen")
    _shell(SSH_KEYGEN[0], tmp_path)
    pub = _shell(SSH_KEYGEN[1], tmp_path).strip()
    assert line.send(f"pub {pub}").endswith(ENC_QUESTION + "\n>\n")
    line.send(f"enc {B(x)}")
    line.send("recovery none")
    line.send("name sshy")
    text = line.send("closed")
    command = question(text)
    write = _printed_commands(text, ("printf ",))[0]
    _shell(write, tmp_path)
    _shell(SSH_SIGN.replace("<file>", "aics-signing-input"), tmp_path)
    armored = (tmp_path / "aics-signing-input.sig").read_text()
    line.send(command)
    text = line.send("sig-begin", *armored.rstrip("\n").split("\n"), "sig-end")
    assert "ok name sshy bound to key" in text


# ----------------------------------------------------------------------
# privacy
# ----------------------------------------------------------------------

def test_the_gate_never_reads_a_client_address() -> None:
    source = Path(gate_mod.__file__).read_text(encoding="utf-8")
    for needle in ("peername", "request.client", "remote_addr", "X-Forwarded-For"):
        assert needle not in source, needle


def test_a_signed_write_whose_staged_body_breaks_the_rules_is_a_refusal_leaf(client: TestClient, origin: str) -> None:
    """The signature verifies and U commits to the staged body: a decision, so a logged refusal (AICS-1 section 10.2)."""
    line = Line(client)
    zed = KeyAgent("zed")
    onboard(line, zed)
    fields = {"body": "a body that is long enough", "channel": "general", "tags": [], "title": "x"}  # title too short
    body = J(fields)
    unsigned = make_u(
        zed, "post", {"content_sha256": H(body)}, session=line.sid, origin=origin, seq=1,
        prev=envelope_mod.envelope_hash(zed.envelope),
    )
    command = text_command(unsigned)
    line.send(f"body {B(body)}")
    assert line.send(command).startswith("? Reply exactly: sig")
    size = client.get("/v2/tlog/checkpoint").json()["tree_size"]
    text = line.send(zed.sig(line.sid, command))
    check_reply(text)
    assert text.startswith("err malformed")
    data = artifacts(text)
    refusal = json.loads(data["entry"])
    assert refusal["type"] == "refusal" and refusal["payload"]["reason_code"] == "malformed"
    assert refusal["payload"]["attempt_kid"] == zed.kid
    assert refusal["payload"]["attempt_nonce"] == unsigned["protected"]["nonce"]  # the record the leaf backs
    assert refusal["payload"]["envelope_hash"] == envelope_mod.envelope_hash({**unsigned, "sig": U(zed.key.sign(signing_input(line.sid, command)))})
    verify_gate_receipt(client, data["receipt"], data["entry"])
    assert client.get("/v2/tlog/checkpoint").json()["tree_size"] == size + 1
    assert client.get("/v2/agora/posts").json()["count"] == 0


def test_an_instance_beside_production_names_its_own_gate(client: TestClient) -> None:
    """Staging (another gate host and ports on production's IP) must never send an agent to 7700/7701."""
    from aics_server.discovery import DEFAULT_SITE, Site

    staging_env = {
        "AICS_BASE_URL": "https://test.wesupport-ai.com", "AICS_API_URL": "https://test.wesupport-ai.com",
        "AICS_GATE_HOSTNAME": "test.wesupport-ai.com", "AICS_GATE_PUBLIC_TLS_PORT": "7800", "AICS_GATE_PUBLIC_PLAIN_PORT": "7801",
    }
    staging_site = Site.from_env(staging_env)
    production = gate_mod.Gate(db_of(client), site=DEFAULT_SITE)
    staging = gate_mod.Gate(db_of(client), base_url=staging_site.base_url, api_url=staging_site.api_url,
                            site=staging_site)

    def refusal(gate: gate_mod.Gate) -> str:
        return next(line for line in gate.http_post(b"fallback\n", tls=False).splitlines() if line.startswith("err "))

    assert refusal(production) == TLS_REQUIRED == "err tls_required use 7700 or HTTPS"
    # Staging has no gate certificate, so no TLS listener: the refusal names HTTPS alone, never the dark port 7800.
    assert not staging_site.gate_tls and refusal(staging) == TLS_REQUIRED_HTTPS_ONLY == "err tls_required use HTTPS"
    # With a certificate of its own, such an instance would name its own TLS port, never production's.
    certified = Site.from_env({**staging_env, "AICS_GATE_TLS_CERT": "/c.crt", "AICS_GATE_TLS_KEY": "/c.key"})
    assert refusal(gate_mod.Gate(db_of(client), site=certified)) == "err tls_required use 7800 or HTTPS"
    opened = staging.http_post(b"help\n", tls=True)
    # (This test database keeps the default origin api.wesupport-ai.com/tiles; staging's is test.*.)
    assert not re.findall(r"gate\.wesupport-ai\.com|api\.wesupport-ai\.com/t(?!iles)|(?<![\d.])770[01](?!\d)", opened)
    assert "-connect test.wesupport-ai.com:7800" in opened and "https://test.wesupport-ai.com/t" in opened


# ----------------------------------------------------------------------
# readiness audit of 2026-10-20: write prompts, the plaintext greeting, scripted use, swarms verbs while off
# ----------------------------------------------------------------------

SIGN_PREFIX = "? Sign this exactly: "


def _prompt(text: str) -> str:
    """The last line of a reply before its ``>``: the question the session waits on."""
    return text.rstrip("\n").split("\n")[-2]


def test_write_prompts_end_at_the_command_so_the_line_as_shown_signs(client: TestClient) -> None:
    """The post and grant prompts carried ". Reply with that line, then sig ..." after the command: an agent that
    signed the line as shown got an unexplained retry and spent two of its three malformed lines.  Each write
    prompt now ends at the command, as the claim's does, and the text after the colon, signed and sent as it is,
    is accepted without any retry."""
    line = Line(client)
    vera = KeyAgent("vera")
    onboard(line, vera)
    body = post_body("Signed as shown", "The prompt line is exactly the command to sign.")
    assert line.send(f"draft post {U(J(post_q(body)))}") == gate_mod.BODY_QUESTION + "\n>\n"
    staged = line.send(f"body {B(body)}")
    grant_q = {"owner_kid": vera.kid, "sender_kid": "*", "max": 1, "expires": now() + 600, "prev_grant_index": None}
    for verb, text in (("post", staged), ("grant", None)):
        if text is None:
            text = line.send(f"draft {verb} {U(J(grant_q))}")
        prompt = _prompt(text)
        assert prompt.startswith(SIGN_PREFIX), prompt
        shown = prompt[len(SIGN_PREFIX):]
        assert shown == text_command(proposal(text)) and shown.count(" ") == 1, shown  # the verb and U64(J(U))
        assert "Reply with" not in text and not shown.endswith(".")
        # The instructions come before the prompt and name the line to send: the prompt's, not "the line above"
        # (that one is the signing command).
        lines = text.rstrip("\n").split("\n")
        assert lines[-4].startswith("openssl pkeyutl -sign "), lines
        assert lines[-3] == 'then send the command shown after "Sign this exactly:", then sig <that base64>', lines
        replies = [line.send(shown), line.send(vera.sig(line.sid, shown))]
        assert not any(reply.startswith("retry") for reply in replies), replies
        assert re.search(rf"^ok {verb} at leaf \d+$", replies[1], re.M), replies[1]


def test_the_ssh_and_secret_write_prompts_end_at_the_command_too(client: TestClient) -> None:
    """The SSHSIG form and the shared-secret confirmation end at the command as well (the secret one with its
    fixed ``then secret`` tail, as the claim's)."""
    line = Line(client)
    sam = KeyAgent("sam")
    onboard(line, sam, tool="ssh-keygen")
    grant_q = {"owner_kid": sam.kid, "sender_kid": "*", "max": 1, "expires": now() + 600, "prev_grant_index": None}
    text = line.send(f"draft grant {U(J(grant_q))}")
    shown = _prompt(text)[len(SIGN_PREFIX):]
    assert shown == text_command(proposal(text))
    armored = sshsig.sign_sshsig(signing_input(line.sid, shown), sam.key)
    assert line.send(shown).startswith("? Reply exactly: sig-begin")
    assert "ok grant at leaf" in line.send("sig-begin", *armored.rstrip("\n").split("\n"), "sig-end")

    secret = "fallback-" + secrets.token_urlsafe(32)
    tls = Line(https(client))
    tls.send()
    tls.send("tools none")
    tls.send("fallback")
    tls.send(f"secret {secret}")
    claim = tls.send("name sid")
    command = question(claim, "? Confirm exactly: ").split(" then secret")[0]
    tls.send(command)
    assert "bound to unverified identity" in tls.send(f"secret {secret}")
    body = post_body("Unverified, confirmed", "A shared-secret post confirmed as the prompt says.")
    tls.send(f"body {B(body)}")
    text = tls.send(f"draft post {U(J(post_q(body)))}")
    assert _prompt(text) == f"? Confirm exactly: {text_command(proposal(text))} then secret <your secret>"
    # The line before each confirmation names what to send: the prompt's command.  It said "send that line, then
    # secret ...", which reads as the line above it (the check line), as the key tier's "the line above" did.
    for reply in (claim, text):
        assert reply.rstrip("\n").split("\n")[-3] == (
            'send the command shown after "Confirm exactly:", then secret <your secret>, over TLS only '
            "(7700 or HTTPS POST)"), reply


def test_a_write_signed_with_real_openssl_from_the_printed_lines(client: TestClient, tmp_path: Path) -> None:
    """The write a trial agent does with OpenSSL: the printed printf and pkeyutl lines sign the command the prompt
    shows, and the shown command with that signature is accepted (readiness audit 2026-10-20, friction 10)."""
    if shutil.which("openssl") is None or shutil.which("bash") is None:
        pytest.skip("openssl or bash is not installed")
    try:
        _shell(OPENSSL_KEYGEN[0], tmp_path)
    except subprocess.CalledProcessError:
        pytest.skip("this openssl cannot make Ed25519 keys")
    line = Line(client)
    line.send()
    line.send("tools openssl")
    line.send(f"pub {_shell(OPENSSL_KEYGEN[1], tmp_path).strip()}")
    line.send(f"enc {B(X25519PrivateKey.generate().public_key().public_bytes_raw())}")
    line.send("recovery none")
    line.send("name rita")
    text = line.send("closed")
    claim = question(text)
    signature = _shell(" && ".join(_printed_commands(text, ("printf ", "openssl pkeyutl "))), tmp_path).strip()
    line.send(claim)
    assert "ok name rita bound to key" in line.send(f"sig {signature}")
    body = post_body("Signed by openssl", "A post signed with the lines the gate printed.")
    line.send(f"draft post {U(J(post_q(body)))}")
    text = line.send(f"body {B(body)}")
    shown = _prompt(text)[len(SIGN_PREFIX):]
    commands = _printed_commands(text, ("printf ", "openssl pkeyutl "))
    assert len(commands) == 2 and f"'{shown}'" in commands[0]
    signature = _shell(" && ".join(commands), tmp_path).strip()
    assert line.send(shown).startswith("? Reply exactly: sig")
    assert re.search(r"^ok post at leaf \d+$", line.send(f"sig {signature}"), re.M)


#: Staging's environment with deploy/gate-tls-staging.yml: its own certificate, so a TLS listener on 7800.
STAGING_GATE_ENV = {
    "AICS_BASE_URL": "https://test.wesupport-ai.com", "AICS_API_URL": "https://test.wesupport-ai.com",
    "AICS_GATE_HOSTNAME": "test.wesupport-ai.com", "AICS_GATE_PUBLIC_TLS_PORT": "7800",
    "AICS_GATE_PUBLIC_PLAIN_PORT": "7801",
    "AICS_GATE_TLS_CERT": "/etc/aics/gate-tls/test.wesupport-ai.com.crt",
    "AICS_GATE_TLS_KEY": "/etc/aics/gate-tls/test.wesupport-ai.com.key",
}


def _gate_for(client: TestClient, site) -> gate_mod.Gate:
    """A gate over the test database that names *site*'s addresses."""
    return gate_mod.Gate(db_of(client), base_url=site.base_url, api_url=site.api_url, site=site)


def _plain_greeting(gate: gate_mod.Gate) -> list[str]:
    session = gate.open_session("tcp-plain", register=False)
    try:
        return gate.start_turn(session)
    finally:
        gate.close_session(session)


def test_the_plaintext_port_says_so_in_its_greeting(client: TestClient) -> None:
    """Port 7701 gave no warning inside the session that it is plaintext.  Its greeting now has one line between the
    banner (unchanged, still first) and the first question; HTTPS and TLS greetings have none.  An instance on other
    ports (staging) names its own plaintext port, TLS command and HTTPS gate; one whose site says it has no TLS
    listener names HTTPS alone, never a dark port."""
    import types

    from aics_server.discovery import DEFAULT_SITE, Site

    gate = _gate_for(client, DEFAULT_SITE)
    note = gate.plaintext_note
    tls_command = ("openssl s_client -quiet -verify_return_error -verify_hostname gate.wesupport-ai.com "
                   "-connect gate.wesupport-ai.com:7700")
    assert gate.tls_command == tls_command == DEFAULT_SITE.tls_command
    assert note == (
        "Plain TCP, port 7701: nothing on this connection is encrypted; anyone on the path can read it and change what "
        "the gate prints, so check every proposal before you sign it. Key identities only: no secret is ever taken "
        f"here. For TLS: {tls_command}, or POST https://api.wesupport-ai.com/t")
    assert note.startswith("Plain TCP, port 7701: nothing on this connection is encrypted") and "\n" not in note
    assert "no secret is ever taken here" in note
    assert not note.startswith(("ok", "err", "retry", "?", ">"))  # prose, like the banner around it
    banner = get_banner().rstrip("\n").split("\n")
    plain = _plain_greeting(gate)
    assert plain == [plain[0], *banner, note, TOOLS_QUESTION] and plain[0].startswith("session ")
    tls = gate.open_session("tcp-tls", register=False)
    assert gate.start_turn(tls) == [f"session {tls.id}", *banner, TOOLS_QUESTION]
    gate.close_session(tls)
    assert gate.http_post(b"", tls=True).split("\n", 1)[1] == get_banner() + TOOLS_QUESTION + "\n>\n"

    staging_site = Site.from_env(STAGING_GATE_ENV)
    staging_note = _plain_greeting(_gate_for(client, staging_site))[-2]
    assert staging_note.startswith("Plain TCP, port 7801:")
    assert staging_note.endswith(f"For TLS: {staging_site.tls_command}, or POST https://test.wesupport-ai.com/t")
    assert not re.findall(r"(?:api|gate)\.wesupport-ai\.com|(?<![\d.])770[01](?!\d)", staging_note)

    # A site that says its gate has no TLS listener (no certificate): HTTPS for TLS, nc for scripted use.
    dark = types.SimpleNamespace(**{k: getattr(staging_site, k) for k in (
        "base_url", "api_url", "gate_host", "gate_tls_port", "gate_plain_port")}, gate_tls=False)
    dark_gate = _gate_for(client, dark)
    dark_note = _plain_greeting(dark_gate)[-2]
    assert dark_gate.tls_command is None and "7800" not in dark_note
    assert dark_note.endswith("For TLS: POST https://test.wesupport-ai.com/t (this instance has no TLS TCP gate)")
    assert dark_gate.scripted_use.endswith("printf 'help\\nquit\\n' | nc test.wesupport-ai.com 7801")


def test_help_shows_scripted_use_ending_with_quit(client: TestClient) -> None:
    from aics_server.discovery import DEFAULT_SITE

    gate = _gate_for(client, DEFAULT_SITE)
    text = gate.http_post(b"help\n", tls=True)
    expected = (
        "scripted use: openssl s_client -quiet (and nc) keep the connection open when their input ends (the session "
        "then waits 900 s), so end piped lines with quit, for example printf 'help\\nquit\\n' | openssl s_client "
        "-quiet -verify_return_error -verify_hostname gate.wesupport-ai.com -connect gate.wesupport-ai.com:7700")
    assert gate.scripted_use == expected and expected in text.split("\n")
    assert ("printf 'help\\nquit\\n' | openssl s_client -quiet -verify_return_error -verify_hostname "
            "gate.wesupport-ai.com -connect gate.wesupport-ai.com:7700") in text


def test_piped_openssl_s_client_ends_when_the_lines_end_with_quit(client: TestClient, tmp_path: Path) -> None:
    """`printf 'help\\n' | openssl s_client -quiet ...` held the connection for the 900 s idle timeout, because
    -quiet keeps it open after the input ends.  The command help prints ends the piped lines with quit: run as
    printed (pointed at a local TLS gate with a test certificate), it gets the banner, help and the goodbye, and
    openssl exits as soon as the gate closes the connection."""
    from aics_server.discovery import DEFAULT_SITE

    openssl = shutil.which("openssl")
    if openssl is None or shutil.which("sh") is None:
        pytest.skip("openssl or sh is not installed")
    version = subprocess.run([openssl, "version"], capture_output=True, text=True, timeout=30).stdout
    if version.startswith("LibreSSL"):
        pytest.skip("LibreSSL's s_client has no -verify_hostname (the banner asks for OpenSSL 3)")
    gate = _gate_for(client, DEFAULT_SITE)  # production's site: a TLS gate on 7700
    printed = next(line for line in gate.http_post(b"help\n", tls=True).split("\n") if line.startswith("scripted use:"))
    command = printed[printed.index("printf "):]
    cert_path, key_path = _self_signed(tmp_path, 3003)

    async def main() -> tuple[int, str, float]:
        tcp = TcpGate(gate, host="127.0.0.1", plain_port=None, tls_port=0, cert_file=cert_path, key_file=key_path)
        await tcp.start()
        try:
            local = (command.replace("-verify_hostname gate.wesupport-ai.com", "-verify_hostname localhost")
                     .replace("-connect gate.wesupport-ai.com:7700", f"-connect 127.0.0.1:{tcp.ports['tls']}")
                     .replace("openssl s_client ", f"{openssl} s_client -CAfile {cert_path} "))
            assert local != command and "-verify_hostname localhost" in local
            # Never a connection to production: every production address was rewritten before openssl runs (the
            # -CAfile path, pytest's numbered temporary directory, is left out of the check).
            checked = local.replace(str(cert_path), "<CAfile>")
            assert not re.search(r"(?:gate|api)\.wesupport-ai\.com|(?<![\d.])770[01](?!\d)", checked), local
            started = time.monotonic()
            proc = await asyncio.create_subprocess_shell(
                local, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=tmp_path)
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), 60)
            except TimeoutError:  # pragma: no cover - the defect this test guards against
                proc.kill()
                raise AssertionError("openssl s_client did not exit after quit") from None
            return proc.returncode, out.decode("utf-8", "replace"), time.monotonic() - started
        finally:
            await tcp.close()

    code, out, elapsed = asyncio.run(main())
    assert code == 0 and elapsed < 60, (code, out)
    assert out.startswith("session ") and get_banner() in out
    assert "ok help: AICS text gate." in out
    assert re.search(r"^ok bye: session \S+ is discarded$", out, re.M), out
    assert "Plain TCP, port" not in out  # the TLS greeting has no plaintext line


@pytest.mark.parametrize("line_text", [
    "intro claude-opus | alpha beta gamma",
    'intro "Μοντέλο λ" | alpha beta gamma',
    "arrivals",
    "arrivals e30",
    "connect 3",
    "swarm-form e30",
    "swarm-join e30",
    "rendezvous none",
    "continue",
    "swarm-name team",
    "draft intro e30",
    "draft swarm-join e30",
])
def test_swarms_verbs_are_not_enabled_without_the_profile(client: TestClient, line_text: str) -> None:
    """llms.txt, agent-protocol.json, skill.md and two seat pages name intro, arrivals, connect, swarm-form and
    swarm-join; with no card activating AICS-1+SWARMS-1 the gate answered each with a retry, and three ended the
    session.  Each is now ``err not_enabled`` (a well-formed answer, not a malformed line) followed by the question
    the session still waits on; nothing is staged or written."""
    db = db_of(client)
    assert not db.swarms.enabled
    size = db.tlog_head()[0]
    word = line_text.split()[1] if line_text.startswith("draft ") else line_text.split()[0]
    line = Line(client)
    line.send()
    for _ in range(4):  # more than the three malformed lines that end a session
        text = line.send(line_text)
        check_reply(text)
        assert text.startswith(f"err not_enabled {word} belongs to the swarms profile (AICS-1+SWARMS-1)"), text
        assert "https://wesupport-ai.com/card" in text
        assert text.endswith(TOOLS_QUESTION + "\n>\n")
    assert line.send("help").startswith("ok help")  # the session is still open
    assert line.send(line_text, get=True).startswith("err not_enabled")
    assert db.tlog_head()[0] == size


def test_a_not_enabled_verb_after_a_claim_repeats_no_question_and_help_says_why(client: TestClient) -> None:
    line = Line(client)
    onboard(line, KeyAgent("wren"))
    text = line.send("arrivals")
    assert text.startswith("err not_enabled arrivals belongs to the swarms profile") and text.count("\n") == 2
    helped = line.send("help")
    assert ("swarms profile (AICS-1+SWARMS-1): not active on this instance; intro, arrivals, connect, swarm-form, "
            "swarm-join and its other verbs are answered with err not_enabled") in helped
    assert line.send("nonsense").startswith("retry ")  # an unknown verb still gets the bounded retry

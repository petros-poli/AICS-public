"""aics keys new/show, sign-line and verify-line (PROTOCOL-TEXT.md §2-3)."""

from __future__ import annotations

import base64
import os
import shutil
import stat
import subprocess

import pytest
from aics_identity import keys as idkeys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _openssl() -> str | None:
    for cand in (shutil.which("openssl"), "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl"):
        if not cand or not os.path.exists(cand):
            continue
        r = subprocess.run([cand, "genpkey", "-algorithm", "ed25519"], capture_output=True)
        if r.returncode == 0:
            return cand
    return None


OPENSSL = _openssl()
needs_openssl = pytest.mark.skipif(OPENSSL is None, reason="no openssl with Ed25519 support")
needs_ssh_keygen = pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="no ssh-keygen")


def test_keys_new_writes_0600_files_and_prints_protocol_forms(h):
    code, out = h.run("keys", "new")
    assert code == 0, out
    key_file = h.home / "aics.key"
    x_file = h.home / "aics-x.key"
    for f in (key_file, x_file):
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(h.home.stat().st_mode) == 0o700
    assert out["pub"].startswith("pub ")
    raw = base64.b64decode(out["pub"][4:], validate=True)
    assert len(raw) == 32
    sk = serialization.load_pem_private_key(key_file.read_bytes(), None)
    assert isinstance(sk, Ed25519PrivateKey)
    assert sk.public_key().public_bytes_raw() == raw
    assert out["kid"] == idkeys.did_key(sk.public_key())
    xk = serialization.load_pem_private_key(x_file.read_bytes(), None)
    assert isinstance(xk, X25519PrivateKey)
    assert out["enc"] == "enc " + base64.b64encode(xk.public_key().public_bytes_raw()).decode()
    assert out["x25519_did"].startswith("did:key:z6LS")
    code, text = h.run_text("keys", "show")
    assert code == 0
    lines = text.splitlines()
    assert lines[:4] == [out["pub"], out["enc"], out["kid"], out["x25519_did"]]


def test_keys_new_refuses_to_overwrite(h):
    assert h.run("keys", "new")[0] == 0
    before = (h.home / "aics.key").read_bytes()
    code, out = h.run("keys", "new")
    assert code == 1 and "refusing to overwrite" in out["error"]
    assert (h.home / "aics.key").read_bytes() == before


def test_keys_dir_option(h, tmp_path):
    d = tmp_path / "elsewhere"
    code, out = h.run("keys", "new", "--dir", str(d))
    assert code == 0 and (d / "aics.key").exists()
    code, out2 = h.run("keys", "show", "--dir", str(d))
    assert out2["pub"] == out["pub"]


def test_keys_show_warns_about_loose_permissions(h):
    h.run("keys", "new")
    os.chmod(h.home / "aics.key", 0o644)
    code, out = h.run("keys", "show")
    assert code == 0 and "readable by others" in out["warnings"][0]


def test_sign_line_signs_session_newline_line(h):
    h.run("keys", "new")
    code, out = h.run("sign-line", "--session", "s-123", "--line", "post general hello world")
    assert code == 0, out
    assert out["reply"] == f"sig {out['sig']}"
    sk = serialization.load_pem_private_key((h.home / "aics.key").read_bytes(), None)
    sk.public_key().verify(base64.b64decode(out["sig"]), b"s-123\npost general hello world")
    code, text = h.run_text("sign-line", "--session", "s-123", "--line", "post general hello world")
    assert text == f"sig {out['sig']}\n"


def test_verify_line_round_trip_and_tamper(h):
    h.run("keys", "new")
    _, out = h.run("sign-line", "--session", "s1", "--line", "claim alice n0nce")
    pub = h.run("keys", "show")[1]["pub"]
    code, ok = h.run("verify-line", "--session", "s1", "--line", "claim alice n0nce", "--sig", out["reply"],
                     "--pub", pub)
    assert code == 0 and ok["form"] == "raw"
    code, bad = h.run("verify-line", "--session", "s1", "--line", "claim mallory n0nce", "--sig", out["reply"],
                      "--pub", pub)
    assert code == 2
    assert bad["evidence"]["type"] == "aics-line-signature-failure/v1"
    code, bad = h.run("verify-line", "--session", "s2", "--line", "claim alice n0nce", "--sig", out["sig"])
    assert code == 2  # bound to the session: no replay into another one


def test_verify_line_leeway(h):
    sk = idkeys.generate_keypair()
    pub = "pub " + base64.b64encode(sk.public_key().public_bytes_raw()).decode()
    sig_nl = base64.b64encode(sk.sign(b"s1\npost x\n")).decode()  # a file written with a final newline
    unpadded_urlsafe = base64.urlsafe_b64encode(sk.sign(b"s1\npost x")).decode().rstrip("=")
    # AICS-1 §11.3: the default is the exact bytes, so a final newline is refused (F26 retired)
    code, out = h.run("verify-line", "--session", "s1", "--line", "post x", "--sig", f"sig: {sig_nl}", "--pub", pub)
    assert code == 2 and out["evidence"]["signed_bytes_tried_base64"] == [base64.b64encode(b"s1\npost x").decode()]
    code, _ = h.run("verify-line", "--session", "s1", "--line", "post x", "--sig", sig_nl, "--pub", pub, "--strict")
    assert code == 2
    # the leeway is an explicit flag for files written outside the protocol
    code, out = h.run("verify-line", "--session", "s1", "--line", "post x", "--sig", f"sig: {sig_nl}", "--pub", pub,
                      "--leeway")
    assert code == 0 and out["form"] == "raw" and out["leeway"] is True
    # base64url may start with '-': the '=' form keeps argparse from reading it as an option
    code, out = h.run("verify-line", "--session", "s1", "--line", "  post x\t", "--sig=" + unpadded_urlsafe,
                      "--pub", pub)
    assert code == 2  # the stripped line is another byte string
    code, out = h.run("verify-line", "--session", "s1", "--line", "  post x\t", "--sig=" + unpadded_urlsafe,
                      "--pub", pub, "--leeway")
    assert code == 0
    code, out = h.run("verify-line", "--session", "s1", "--line", "post x", "--sig=" + unpadded_urlsafe, "--pub", pub,
                      "--leeway", "--strict")
    assert code == 1 and "not allowed with" in out["error"]
    did = idkeys.did_key(sk.public_key())
    code, _ = h.run("verify-line", "--session", "s1", "--line", "post x", "--sig=" + unpadded_urlsafe, "--pub", did)
    assert code == 0


def test_values_starting_with_a_dash(h, tmp_path):
    """A signature or session id that starts with '-' works with the '=' form
    or --sig-file; the bare form is a usage error with a hint (exit 1)."""
    sk = idkeys.generate_keypair()
    pub = "pub " + base64.b64encode(sk.public_key().public_bytes_raw()).decode()
    session = "-s1"
    while True:
        sig = base64.urlsafe_b64encode(sk.sign(f"{session}\npost x".encode())).decode().rstrip("=")
        if sig.startswith("-"):
            break
        session += "x"
    code, out = h.run("verify-line", "--session", session, "--line", "post x", "--sig", sig, "--pub", pub)
    assert code == 1 and "--sig=" in out["error"]
    code, out = h.run("verify-line", f"--session={session}", "--line", "post x", f"--sig={sig}", "--pub", pub)
    assert code == 0, out
    f = tmp_path / "sig.txt"
    f.write_text(f"sig {sig}\n")
    code, out = h.run("verify-line", f"--session={session}", "--line", "post x", "--sig-file", str(f), "--pub", pub)
    assert code == 0, out
    code, out = h.run("verify-line", f"--session={session}", "--line", "post x", "--pub", pub)
    assert code == 1 and "--sig" in out["error"]


def test_verify_line_malformed_signature_is_an_error(h):
    sk = idkeys.generate_keypair()
    pub = base64.b64encode(sk.public_key().public_bytes_raw()).decode()
    code, out = h.run("verify-line", "--session", "s", "--line", "x", "--sig", "sig abc!", "--pub", pub)
    assert code == 1
    code, out = h.run("verify-line", "--session", "s", "--line", "x", "--sig", base64.b64encode(b"x" * 10).decode(),
                      "--pub", pub)
    assert code == 1 and "malformed signature" in out["error"]


@needs_openssl
def test_openssl_interop(h, tmp_path):
    h.run("keys", "new")
    pub_der = subprocess.run([OPENSSL, "pkey", "-in", str(h.home / "aics.key"), "-pubout", "-outform", "DER"],
                             capture_output=True, check=True).stdout
    _, out = h.run("keys", "show")
    assert out["pub"] == "pub " + base64.b64encode(pub_der[-32:]).decode()
    # an openssl-made key signs; aics verifies, and aics signs identically (Ed25519 is deterministic)
    key = tmp_path / "o.key"
    subprocess.run([OPENSSL, "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True)
    line = tmp_path / "line.txt"
    line.write_bytes(b"sess-9\npost general hi")
    sig = subprocess.run([OPENSSL, "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(line)],
                         capture_output=True, check=True).stdout
    sig_b64 = base64.b64encode(sig).decode()
    pub2 = subprocess.run([OPENSSL, "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
                          capture_output=True, check=True).stdout[-32:]
    code, res = h.run("verify-line", "--session", "sess-9", "--line", "post general hi", "--sig", f"sig {sig_b64}",
                      "--pub", "pub " + base64.b64encode(pub2).decode())
    assert code == 0, res
    code, res = h.run("sign-line", "--session", "sess-9", "--line", "post general hi", "--key", str(key))
    assert res["sig"] == sig_b64


@needs_ssh_keygen
def test_ssh_keygen_key_interop(h, tmp_path):
    k = tmp_path / "aics_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(k), "-q"], check=True)
    pub_line = (tmp_path / "aics_ed25519.pub").read_text().strip()
    code, out = h.run("sign-line", "--session", "s", "--line", "who", "--key", str(k))
    assert code == 0, out
    code, out = h.run("verify-line", "--session", "s", "--line", "who", "--sig", out["reply"],
                      "--pub", f"pub {pub_line}")
    assert code == 0, out


@needs_ssh_keygen
def test_sshsig_line_signature(h, tmp_path):
    """The gate's ssh-keygen branch: an SSHSIG over the exact bytes, namespace aics, sha512."""
    k = tmp_path / "aics_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(k), "-q"], check=True)
    pub_line = (tmp_path / "aics_ed25519.pub").read_text().strip()
    msg = tmp_path / "line.txt"
    msg.write_bytes(b"sess-1\npost general hi")
    subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(k), "-n", "aics", "-O", "hashalg=sha512", str(msg)],
                   check=True, capture_output=True)
    armored = (tmp_path / "line.txt.sig").read_text()
    block = "sig-begin\n" + armored + "sig-end\n"
    code, out = h.run("verify-line", "--session", "sess-1", "--line", "post general hi", "--sig", block,
                      "--pub", f"pub {pub_line}")
    assert code == 0, out
    assert out["form"] == "sshsig"
    code, out = h.run("verify-line", "--session", "sess-2", "--line", "post general hi", "--sig", block,
                      "--pub", f"pub {pub_line}")
    assert code == 2

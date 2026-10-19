"""Item 1: text-gate line signatures (PROTOCOL-TEXT §2, AICS-1 §11.3).

Producers: aics-identity ``linesig``, the ``aics sign-line`` command (Python
API and a real child process), openssl ``pkeyutl -rawin`` and ``ssh-keygen
-Y sign``.  Verifiers: each of the others.  Ed25519 is deterministic, so raw
signatures and SSHSIG blobs must also be byte-identical across producers.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from aics_interop import aicslog, appendix_a, drivers, spec

KEY = spec.test_key(0x61)
U = spec.unsigned_text_envelope(KEY, origin=aicslog.ORIGIN, typ="post", created=aicslog.T0,
                                nonce=bytes(range(16)), session="c2Vzc2lvbi1pZC0xMjM0NQ",
                                payload={"channel_sha256": spec.hexH(b"interop"), "parent_index": None,
                                         "body_hash": spec.hexH(b"x"), "size": 1, "title_sha256": None})
CASES = [
    ("c2Vzc2lvbi1pZC0xMjM0NQ", spec.text_command(U)),
    ("-starts-with-dash", "claim agent0 " + "ab" * 32),
    ("s", "help"),
]


def pem(key, path: Path) -> Path:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    path.chmod(0o600)
    return path


def openssh(key, path: Path) -> Path:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                       serialization.NoEncryption()))
    path.chmod(0o600)
    return path


def pub_reply(key) -> str:
    return "pub " + base64.b64encode(spec.raw_public(key)).decode()


@pytest.mark.parametrize("session,line", CASES)
def test_raw_signatures_are_byte_identical_across_producers(tmp_path, session, line):
    from aics_identity import linesig

    expected = KEY.sign(spec.line_message(session, line))  # the spec's signed bytes, raw Ed25519
    by_identity = linesig.sign_line(session, line, KEY)
    cli = drivers.AicsCli(home=tmp_path / "home")
    r = cli.run("sign-line", f"--session={session}", f"--line={line}", "--key", str(pem(KEY, tmp_path / "k.pem")))
    assert r.code == 0, r.data
    assert base64.b64decode(by_identity) == expected
    assert r.data["reply"] == f"sig {by_identity}"
    assert r.data["pub"] == pub_reply(KEY)


def test_cli_child_process_signs_like_identity(tmp_path):
    from aics_identity import linesig

    session, line = CASES[0]
    proc = drivers.aics_subprocess("sign-line", f"--session={session}", f"--line={line}", "--key",
                                   str(pem(KEY, tmp_path / "k.pem")), "--json", home=tmp_path / "home")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["sig"] == linesig.sign_line(session, line, KEY)


@pytest.mark.parametrize("session,line", CASES)
def test_identity_signature_verifies_in_cli_strict_and_back(tmp_path, session, line):
    from aics_identity import linesig

    cli = drivers.AicsCli(home=tmp_path / "home")
    sig = linesig.sign_line(session, line, KEY)
    # aics verify-line and sign-line share aics_identity.linesig, so the reference checks the bytes as well:
    # Ed25519 over exactly the §11.3 signing input, no final LF
    KEY.public_key().verify(base64.b64decode(sig), spec.line_message(session, line))
    r = cli.run("verify-line", f"--session={session}", f"--line={line}", f"--sig=sig {sig}", "--pub",
                pub_reply(KEY), "--strict")
    assert (r.code, r.data.get("form")) == (0, "raw"), r.data
    r = cli.run("sign-line", f"--session={session}", f"--line={line}", "--key", str(pem(KEY, tmp_path / "k.pem")))
    assert r.data["reply"] == "sig " + base64.b64encode(KEY.sign(spec.line_message(session, line))).decode()
    assert linesig.verify_line(session, line, r.data["reply"], KEY.public_key(), leeway=False) == "raw"
    # a signature for another session or another line fails everywhere
    other = linesig.sign_line(session + "x", line, KEY)
    r = cli.run("verify-line", f"--session={session}", f"--line={line}", f"--sig={other}", "--pub", pub_reply(KEY))
    assert r.code == 2 and r.evidence["type"] == "aics-line-signature-failure/v1"


def test_openssl_raw_signature_is_byte_identical(tmp_path, openssl_bin):
    from aics_identity import linesig

    session, line = CASES[0]
    msg = tmp_path / "line.bin"
    msg.write_bytes(spec.line_message(session, line))
    key = pem(KEY, tmp_path / "aics.key")
    out = subprocess.run([openssl_bin, "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(msg)],
                         capture_output=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert out.stdout == base64.b64decode(linesig.sign_line(session, line, KEY))
    # the gate reply form: sig <base64 of openssl output>, verified by aics (strict) and aics-identity
    reply = "sig " + base64.b64encode(out.stdout).decode()
    r = drivers.AicsCli(home=tmp_path / "h").run("verify-line", f"--session={session}", f"--line={line}",
                                                 f"--sig={reply}", "--pub", pub_reply(KEY), "--strict")
    assert r.code == 0, r.data


def test_openssl_generated_key_and_pub_reply_interoperate(tmp_path, openssl_bin):
    """``openssl genpkey`` key, ``pub`` reply per PROTOCOL-TEXT §3, signature by ``aics sign-line``."""
    key = tmp_path / "aics.key"
    assert subprocess.run([openssl_bin, "genpkey", "-algorithm", "ed25519", "-out", str(key)],
                          capture_output=True, timeout=30).returncode == 0
    der = subprocess.run([openssl_bin, "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
                         capture_output=True, timeout=30).stdout
    pub = "pub " + base64.b64encode(der[-32:]).decode()  # tail -c 32 | base64
    session, line = CASES[0]
    cli = drivers.AicsCli(home=tmp_path / "home")
    r = cli.run("sign-line", f"--session={session}", f"--line={line}", "--key", str(key))
    assert r.code == 0 and r.data["pub"] == pub, r.data
    sig = base64.b64decode(r.data["sig"])
    (tmp_path / "line.bin").write_bytes(spec.line_message(session, line))
    (tmp_path / "sig.bin").write_bytes(sig)
    pubpem = tmp_path / "pub.pem"
    subprocess.run([openssl_bin, "pkey", "-in", str(key), "-pubout", "-out", str(pubpem)], check=True,
                   capture_output=True, timeout=30)
    v = subprocess.run([openssl_bin, "pkeyutl", "-verify", "-pubin", "-inkey", str(pubpem), "-rawin", "-in",
                        str(tmp_path / "line.bin"), "-sigfile", str(tmp_path / "sig.bin")],
                       capture_output=True, text=True, timeout=30)
    assert v.returncode == 0, v.stdout + v.stderr


PLACEHOLDERS = ("<session id>", "<command line>", "<canonical command>")


def _printed_recipes(source: str, session: str, line: str) -> list[str]:
    """The openssl line-signing recipes exactly as ``source`` prints them, placeholders filled in (F17 retired)."""
    if source == "aics_conformance.dialogue.openssl_sign":
        from aics_conformance import dialogue

        return [dialogue.openssl_sign(session, line)]
    text = (appendix_a.REPO_ROOT / source).read_text("utf-8")
    recipes = re.findall(r"`([^`\n]*openssl pkeyutl -sign[^`\n]*)`", text)
    if not recipes:
        pytest.fail(f"{source} prints no openssl pkeyutl -sign recipe")
    values = {PLACEHOLDERS[0]: session, PLACEHOLDERS[1]: line, PLACEHOLDERS[2]: line}
    unknown = {p for r in recipes for p in re.findall(r"<[^<>]+>", r)} - set(values)
    if unknown:
        pytest.fail(f"{source}: placeholders {sorted(unknown)} are not {PLACEHOLDERS}")
    return [re.sub(r"<[^<>]+>", lambda m: values[m.group(0)], r) for r in recipes]


@pytest.mark.parametrize("source", ["docs/PROTOCOL-TEXT.md", "docs/spec/AICS-1.md",
                                    "aics_conformance.dialogue.openssl_sign"])
def test_printed_openssl_recipe_signs_a_line(tmp_path, openssl_bin, source):
    """§11.4 item 2: the printed recipe, run as printed (``sh -c``, ``aics.key`` in the working directory), must
    print the base64 of the 64-byte Ed25519 signature over the §11.3 signing input."""
    session, line = CASES[0]
    pem(KEY, tmp_path / "aics.key")
    probe = subprocess.run([openssl_bin, "pkeyutl", "-sign", "-inkey", str(tmp_path / "aics.key"), "-rawin"],
                           input=spec.line_message(session, line), capture_output=True, timeout=30)
    if probe.returncode == 0 and len(probe.stdout) == 64:
        pytest.skip("this openssl signs from a pipe; the recipe's file form (F17) cannot be told apart with it")
    env = {**os.environ, "PATH": os.path.dirname(openssl_bin) + os.pathsep + os.environ.get("PATH", "")}
    for recipe in _printed_recipes(source, session, line):
        out = subprocess.run(["sh", "-c", recipe], cwd=tmp_path, env=env, capture_output=True, timeout=30)
        signature = base64.b64decode(b"".join(out.stdout.split()))
        assert len(signature) == 64, out.stderr.decode(errors="replace")
        assert signature == KEY.sign(spec.line_message(session, line))


def test_sshsig_is_byte_identical_and_cross_verifies(tmp_path, ssh_keygen_bin):
    from aics_identity import linesig, sshsig

    session, line = CASES[0]
    msg = tmp_path / "line.bin"
    msg.write_bytes(spec.line_message(session, line))
    key = openssh(KEY, tmp_path / "aics_ed25519")
    out = subprocess.run([ssh_keygen_bin, "-Y", "sign", "-f", str(key), "-n", "aics", "-O", "hashalg=sha512",
                          str(msg)], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    armored = (tmp_path / "line.bin.sig").read_text()
    ours = linesig.sign_line(session, line, KEY, form="sshsig")
    assert sshsig.dearmor(armored) == sshsig.dearmor(ours)  # byte-identical SSHSIG blob
    assert linesig.verify_line(session, line, armored, KEY.public_key(), leeway=False) == "sshsig"
    # the gate block form, through aics verify-line --sig-file
    block = tmp_path / "block.txt"
    block.write_text("sig-begin\n" + armored + "sig-end\n")
    r = drivers.AicsCli(home=tmp_path / "home").run(
        "verify-line", f"--session={session}", f"--line={line}", "--sig-file", str(block), "--pub",
        "ssh-ed25519 " + base64.b64encode(sshsig.openssh_public_key_blob(KEY.public_key())).decode(), "--strict")
    assert (r.code, r.data.get("form")) == (0, "sshsig"), r.data
    # ssh-keygen verifies the aics-identity-produced SSHSIG
    (tmp_path / "ours.sig").write_text(ours)
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(f'agent namespaces="aics" {sshsig.format_openssh_public_key(KEY.public_key())}\n')
    v = subprocess.run([ssh_keygen_bin, "-Y", "verify", "-f", str(allowed), "-I", "agent", "-n", "aics", "-s",
                        str(tmp_path / "ours.sig")], input=msg.read_bytes(), capture_output=True, timeout=30)
    assert v.returncode == 0, v.stdout + v.stderr


@pytest.fixture
def lf_signature():
    """A raw signature over the session/line bytes plus a final LF (a file written the usual way)."""
    session, line = CASES[0]
    return session, line, base64.b64encode(KEY.sign(spec.line_message(session, line) + b"\n")).decode()


def test_trailing_lf_signature_is_refused_by_strict_verifiers(tmp_path, lf_signature):
    from aics_identity import linesig

    session, line, sig = lf_signature
    with pytest.raises(linesig.InvalidLineSignature):
        linesig.verify_line(session, line, sig, KEY.public_key(), leeway=False)  # what aics-conformance uses
    r = drivers.AicsCli(home=tmp_path / "home").run("verify-line", f"--session={session}", f"--line={line}",
                                                    f"--sig={sig}", "--pub", pub_reply(KEY), "--strict")
    assert r.code == 2


def test_identity_default_line_verifier_follows_the_exact_bytes_rule(lf_signature):
    """AICS-1 §11.3: no final LF in the signed bytes; aics-identity's default refuses (F07 retired)."""
    from aics_identity import linesig

    session, line, sig = lf_signature
    with pytest.raises(linesig.InvalidLineSignature):
        linesig.verify_line(session, line, sig, KEY.public_key())


def test_default_line_verifiers_follow_the_exact_bytes_rule(tmp_path, lf_signature):
    """AICS-1 §11.3: no final LF in the signed bytes; aics verify-line (default) refuses too (F26 retired)."""
    session, line, sig = lf_signature
    r = drivers.AicsCli(home=tmp_path / "home").run("verify-line", f"--session={session}", f"--line={line}",
                                                    f"--sig={sig}", "--pub", pub_reply(KEY))
    assert r.code == 2, f"aics verify-line accepted a signature over bytes + LF (form {r.data.get('form')})"


def test_the_cli_leeway_is_an_explicit_flag(tmp_path, lf_signature):
    """The wider forms (a final LF) are accepted only when asked for, for files written outside the protocol."""
    session, line, sig = lf_signature
    r = drivers.AicsCli(home=tmp_path / "home").run("verify-line", f"--session={session}", f"--line={line}",
                                                    f"--sig={sig}", "--pub", pub_reply(KEY), "--leeway")
    assert (r.code, r.data.get("form"), r.data.get("leeway")) == (0, "raw", True), r.data


@pytest.mark.parametrize("session,line", CASES)
def test_reference_sshsig_is_byte_identical_to_aics_identity(session, line):
    """PROTOCOL.sshsig §§1-3 written from the spec; ssh-keygen equality is test_sshsig_is_byte_identical_..."""
    from aics_identity import linesig, sshsig

    msg = spec.line_message(session, line)
    blob = spec.sshsig_blob(msg, KEY)
    assert spec.sshsig_armor(blob) == linesig.sign_line(session, line, KEY, form="sshsig")
    spec.verify_sshsig_blob(sshsig.dearmor(linesig.sign_line(session, line, KEY, form="sshsig")), msg,
                            spec.raw_public(KEY))
    assert linesig.verify_line(session, line, spec.sshsig_armor(blob), KEY.public_key(), leeway=False) == "sshsig"
    with pytest.raises(ValueError):
        spec.verify_sshsig_blob(blob, msg + b"\n", spec.raw_public(KEY))

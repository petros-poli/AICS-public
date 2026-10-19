"""Text-protocol line signatures: raw Ed25519 (openssl) and SSHSIG (ssh-keygen)."""

from __future__ import annotations

import base64

import pytest

from aics_identity import keys, linesig, sshsig
from aics_identity.linesig import InvalidLineSignature, MalformedLineSignature, sign_line, verify_line
from conftest import (
    LINE_MESSAGE,
    LINE_SESSION_ID,
    LINE_TEXT,
    OPENSSL_VECTOR_PUBLIC_B64,
    OPENSSL_VECTOR_SEED,
    OPENSSL_VECTOR_SIG_B64,
    SSH_VECTOR_PUBLIC_LINE,
    SSH_VECTOR_SEED,
    SSH_VECTOR_SIG_SHA256,
    SSH_VECTOR_SIG_SHA512,
    run_tool,
)

SID = "sess-42"


def raw_b64(key, message: bytes) -> str:
    return base64.b64encode(key.sign(message)).decode()


# ----------------------------------------------------------------------
# the message
# ----------------------------------------------------------------------

def test_line_message_bytes():
    assert linesig.line_message(LINE_SESSION_ID, LINE_TEXT) == LINE_MESSAGE
    assert linesig.line_message("s", "post été") == "s\npost été".encode("utf-8")


def test_newlines_are_refused_in_session_and_line():
    for bad_sid in ("a\nb", "a\rb", ""):
        with pytest.raises(ValueError):
            linesig.line_message(bad_sid, "post x")
    with pytest.raises(ValueError):
        linesig.line_message("s", "post x\npost y")
    with pytest.raises(TypeError):
        linesig.line_message("s", b"bytes")


def test_candidate_messages():
    """Strict by default (AICS-1 section 11.3): only the exact signing input, no final LF."""
    assert linesig.candidate_messages("s", "post x") == [b"s\npost x"]
    assert linesig.candidate_messages("s", " post x ") == [b"s\n post x "]
    assert linesig.candidate_messages("s", "post x", leeway=True) == [b"s\npost x", b"s\npost x\n"]
    assert linesig.candidate_messages("s", " post x\r", leeway=True) == [
        b"s\n post x\r", b"s\n post x\r\n", b"s\npost x", b"s\npost x\n",
    ]


# ----------------------------------------------------------------------
# vectors made by the real tools
# ----------------------------------------------------------------------

def test_openssl_vector_verifies_with_the_pub_reply():
    assert verify_line(LINE_SESSION_ID, LINE_TEXT, OPENSSL_VECTOR_SIG_B64, OPENSSL_VECTOR_PUBLIC_B64) == "raw"
    pub = keys.parse_public_key_text(OPENSSL_VECTOR_PUBLIC_B64)  # the 'pub <base64>' reply
    assert verify_line(LINE_SESSION_ID, LINE_TEXT, "sig " + OPENSSL_VECTOR_SIG_B64, pub) == "raw"


def test_raw_signer_matches_openssl_output_byte_for_byte():
    key = keys.private_key_from_seed(OPENSSL_VECTOR_SEED)
    assert keys.format_public_key(key.public_key()) == keys.b64u_encode(base64.b64decode(OPENSSL_VECTOR_PUBLIC_B64))
    assert sign_line(LINE_SESSION_ID, LINE_TEXT, key) == OPENSSL_VECTOR_SIG_B64


def test_ssh_keygen_vector_verifies_with_the_pub_reply():
    assert verify_line(LINE_SESSION_ID, LINE_TEXT, SSH_VECTOR_SIG_SHA512, SSH_VECTOR_PUBLIC_LINE) == "sshsig"
    wrapped = "sig-begin\n" + SSH_VECTOR_SIG_SHA512 + "sig-end"
    assert verify_line(LINE_SESSION_ID, LINE_TEXT, wrapped, keys.parse_public_key_text(SSH_VECTOR_PUBLIC_LINE)) == "sshsig"


def test_sshsig_signer_matches_ssh_keygen_output_byte_for_byte():
    assert sign_line(LINE_SESSION_ID, LINE_TEXT, SSH_VECTOR_SEED, form="sshsig") == SSH_VECTOR_SIG_SHA512


def test_sshsig_hash_policy():
    with pytest.raises(InvalidLineSignature, match="sha256"):
        verify_line(LINE_SESSION_ID, LINE_TEXT, SSH_VECTOR_SIG_SHA256, SSH_VECTOR_PUBLIC_LINE)
    assert verify_line(LINE_SESSION_ID, LINE_TEXT, SSH_VECTOR_SIG_SHA256, SSH_VECTOR_PUBLIC_LINE,
                       allowed_hash_algorithms=("sha256", "sha512")) == "sshsig"


def test_sshsig_namespace_must_be_aics():
    key = keys.generate_keypair()
    git_sig = sshsig.sign_sshsig(linesig.line_message(SID, "post x"), key, namespace="git")
    with pytest.raises(InvalidLineSignature, match="namespace"):
        verify_line(SID, "post x", git_sig, key.public_key())


# ----------------------------------------------------------------------
# round trips and rejections
# ----------------------------------------------------------------------

@pytest.mark.parametrize("form", ["raw", "sshsig"])
def test_roundtrip_and_binding(form):
    key, other = keys.generate_keypair(), keys.generate_keypair()
    sig = sign_line(SID, "post hello world", key, form=form)
    assert verify_line(SID, "post hello world", sig, key.public_key()) == form
    with pytest.raises(InvalidLineSignature):
        verify_line("sess-43", "post hello world", sig, key.public_key())  # other session: replay refused
    with pytest.raises(InvalidLineSignature):
        verify_line(SID, "post hello world!", sig, key.public_key())
    with pytest.raises(InvalidLineSignature):
        verify_line(SID, "post hello world", sig, other.public_key())


def test_public_key_forms():
    key = keys.generate_keypair()
    sig = sign_line(SID, "post x", key)
    pub = key.public_key()
    for form in (pub, keys.public_key_bytes(pub), keys.format_public_key(pub), keys.did_key(pub),
                 sshsig.format_openssh_public_key(pub, "c")):
        assert verify_line(SID, "post x", sig, form) == "raw"


def test_a_trailing_newline_is_refused_by_default():
    """AICS-1 section 11.3: no final LF; a signature over the bytes plus LF is refused unless leeway=True."""
    key = keys.generate_keypair()
    for form in ("raw", "sshsig"):
        message = linesig.line_message(SID, "post x") + b"\n"
        sig = raw_b64(key, message) if form == "raw" else sshsig.sign_sshsig(message, key)
        with pytest.raises(InvalidLineSignature):
            verify_line(SID, "post x", sig, key.public_key())
        with pytest.raises(InvalidLineSignature):
            verify_line(SID, "post x", sig, key.public_key(), leeway=False)
        assert verify_line(SID, "post x", sig, key.public_key(), leeway=True) == form


def test_surrounding_whitespace_is_not_repaired_by_default():
    key = keys.generate_keypair()
    sig = sign_line(SID, "post x", key)
    with pytest.raises(InvalidLineSignature):
        verify_line(SID, "  post x \r", sig, key.public_key())
    assert verify_line(SID, "  post x \r", sig, key.public_key(), leeway=True) == "raw"
    signed_with_spaces = sign_line(SID, " post x ", key)
    assert verify_line(SID, " post x ", signed_with_spaces, key.public_key()) == "raw"


def test_sshsig_reserved_field_must_be_empty():
    """AICS-1 section 11.3: version 1, ssh-ed25519, namespace aics, empty reserved field, sha512."""
    key = keys.generate_keypair()
    message = linesig.line_message(SID, "post x")
    data = sshsig.signed_data(message, namespace="aics", hash_algorithm="sha512", reserved=b"future")
    blob = sshsig.SSHSignature(keys.public_key_bytes(key.public_key()), "aics", b"future", "sha512",
                               key.sign(data)).armored()
    sshsig.verify_sshsig(blob, message, key.public_key())  # PROTOCOL.sshsig alone ignores the field
    with pytest.raises(InvalidLineSignature, match="reserved"):
        verify_line(SID, "post x", blob, key.public_key())


def test_inner_whitespace_is_not_leeway():
    key = keys.generate_keypair()
    sig = sign_line(SID, "post x", key)
    with pytest.raises(InvalidLineSignature):
        verify_line(SID, "post  x", sig, key.public_key())


# ----------------------------------------------------------------------
# signature text forms
# ----------------------------------------------------------------------

def test_raw_signature_text_forms():
    key = keys.generate_keypair()
    std = sign_line(SID, "post x", key)
    raw = base64.b64decode(std)
    url = base64.urlsafe_b64encode(raw).decode()
    forms = [
        std, std.rstrip("="), url, url.rstrip("="),
        "sig " + std, "sig: " + std, "SIG:" + std, "Sig\t" + std,
        '"' + std + '"', "sig '" + std + "'",
        std[:40] + "\n" + std[40:] + "\n",
        std.encode("ascii"),
    ]
    for text in forms:
        assert verify_line(SID, "post x", text, key.public_key()) == "raw", text


def test_sshsig_body_without_armor_is_accepted():
    key = keys.generate_keypair()
    armored = sign_line(SID, "post x", key, form="sshsig")
    body = "".join(armored.splitlines()[1:-1])
    assert verify_line(SID, "post x", body, key.public_key()) == "sshsig"
    assert verify_line(SID, "post x", "sig " + body, key.public_key()) == "sshsig"


@pytest.mark.parametrize(
    "text, match",
    [
        ("", "empty"),
        ("sig ", "empty"),
        ("not*base64", "base64"),
        (base64.b64encode(b"\x01" * 32).decode(), "64-byte"),
        (base64.b64encode(b"\x01" * 65).decode(), "64-byte"),
        (sshsig.BEGIN_MARKER + "\nAAAA\n" + sshsig.END_MARKER, "truncated"),
        (base64.b64encode(b"SSHSIG" + b"\x00" * 70).decode(), "version"),
    ],
)
def test_malformed_signature_text(text, match):
    key = keys.generate_keypair()
    with pytest.raises(MalformedLineSignature, match=match):
        verify_line(SID, "post x", text, key.public_key())


def test_signature_type_errors():
    key = keys.generate_keypair()
    with pytest.raises(TypeError):
        verify_line(SID, "post x", 123, key.public_key())
    with pytest.raises(MalformedLineSignature):
        verify_line(SID, "post x", b"\xff\xfe", key.public_key())
    with pytest.raises(ValueError):
        sign_line(SID, "post x", key, form="pgp")


def test_errors_are_value_errors():
    assert issubclass(MalformedLineSignature, ValueError)
    assert issubclass(InvalidLineSignature, linesig.LineSignatureError)


# ----------------------------------------------------------------------
# live tools (skipped when unavailable)
# ----------------------------------------------------------------------

def test_live_ssh_keygen_line_signature(ssh_keygen_bin, tmp_path):
    key_path = tmp_path / "aics_ed25519"
    assert run_tool([ssh_keygen_bin, "-t", "ed25519", "-N", "", "-f", str(key_path), "-q"]).returncode == 0
    pub_line = (tmp_path / "aics_ed25519.pub").read_text()
    for name, content in (("exact.txt", b"sess-live\npost from ssh"), ("echoed.txt", b"sess-live\npost from ssh\n")):
        path = tmp_path / name
        path.write_bytes(content)
        assert run_tool([ssh_keygen_bin, "-Y", "sign", "-f", str(key_path), "-n", "aics", str(path)]).returncode == 0
        armored = (tmp_path / (name + ".sig")).read_text()
        pasted = "sig-begin\n" + armored + "sig-end\n"
        if name == "exact.txt":
            assert verify_line("sess-live", "post from ssh", pasted, pub_line) == "sshsig"
        else:  # a file written with a final newline signs other bytes: refused unless leeway=True
            with pytest.raises(InvalidLineSignature):
                verify_line("sess-live", "post from ssh", pasted, pub_line)
            assert verify_line("sess-live", "post from ssh", pasted, pub_line, leeway=True) == "sshsig"


def test_live_openssl_line_signature(openssl_bin, tmp_path):
    key_path = tmp_path / "aics.key"
    assert run_tool([openssl_bin, "genpkey", "-algorithm", "ed25519", "-out", str(key_path)]).returncode == 0
    der = run_tool([openssl_bin, "pkey", "-in", str(key_path), "-pubout", "-outform", "DER"])
    assert der.returncode == 0
    pub_reply = base64.b64encode(der.stdout[-32:]).decode()  # ... | tail -c 32 | base64
    line_file = tmp_path / "line.txt"
    line_file.write_bytes(b"sess-live\nsend bob 42")  # printf '%s\n%s' ... > line.txt
    signed = run_tool([openssl_bin, "pkeyutl", "-sign", "-inkey", str(key_path), "-rawin", "-in", str(line_file)])
    assert signed.returncode == 0, signed.stderr
    assert len(signed.stdout) == 64
    sig_reply = "sig " + base64.b64encode(signed.stdout).decode()
    assert verify_line("sess-live", "send bob 42", sig_reply, keys.parse_public_key_text(pub_reply)) == "raw"
    with pytest.raises(InvalidLineSignature):
        verify_line("sess-other", "send bob 42", sig_reply, pub_reply)

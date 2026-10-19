"""SSHSIG and OpenSSH public keys: ssh-keygen vectors, tamper cases, live interop."""

from __future__ import annotations

import base64
import struct

import pytest
from cryptography.hazmat.primitives.serialization import load_ssh_private_key

from aics_identity import keys, sshsig
from conftest import (
    LINE_MESSAGE,
    SSH_VECTOR_PUBLIC_LINE,
    SSH_VECTOR_SEED,
    SSH_VECTOR_SIG_SHA256,
    SSH_VECTOR_SIG_SHA512,
    run_tool,
)

VECTOR_KEY = keys.private_key_from_seed(SSH_VECTOR_SEED)
VECTOR_PUB_RAW = keys.public_key_bytes(VECTOR_KEY.public_key())


def _s(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def build_blob(
    *,
    magic=b"SSHSIG",
    version=1,
    key_type=b"ssh-ed25519",
    key=VECTOR_PUB_RAW,
    key_trailing=b"",
    namespace=b"aics",
    reserved=b"",
    hash_alg=b"sha512",
    sig_type=b"ssh-ed25519",
    sig=b"\x00" * 64,
    sig_trailing=b"",
    trailing=b"",
) -> bytes:
    return (
        magic
        + struct.pack(">I", version)
        + _s(_s(key_type) + _s(key) + key_trailing)
        + _s(namespace)
        + _s(reserved)
        + _s(hash_alg)
        + _s(_s(sig_type) + _s(sig) + sig_trailing)
        + trailing
    )


# ----------------------------------------------------------------------
# the committed ssh-keygen vectors
# ----------------------------------------------------------------------

def test_vector_public_key_line_parses_and_formats():
    pub = sshsig.parse_openssh_public_key(SSH_VECTOR_PUBLIC_LINE)
    assert keys.public_key_bytes(pub) == VECTOR_PUB_RAW
    assert sshsig.format_openssh_public_key(VECTOR_KEY.public_key(), "aics-test-vector") == SSH_VECTOR_PUBLIC_LINE
    # the comment is optional and ignored
    bare = sshsig.format_openssh_public_key(pub)
    assert bare == " ".join(SSH_VECTOR_PUBLIC_LINE.split()[:2])
    assert keys.public_key_bytes(sshsig.parse_openssh_public_key(bare + "\n")) == VECTOR_PUB_RAW


def test_vector_sha512_signature_verifies():
    parsed = sshsig.verify_sshsig(SSH_VECTOR_SIG_SHA512, LINE_MESSAGE, SSH_VECTOR_PUBLIC_LINE)
    assert parsed.namespace == "aics"
    assert parsed.hash_algorithm == "sha512"
    assert parsed.reserved == b""
    assert parsed.public_key_bytes == VECTOR_PUB_RAW
    assert keys.public_key_bytes(parsed.public_key) == VECTOR_PUB_RAW


def test_signer_reproduces_ssh_keygen_byte_for_byte():
    assert sshsig.sign_sshsig(LINE_MESSAGE, SSH_VECTOR_SEED) == SSH_VECTOR_SIG_SHA512
    assert sshsig.sign_sshsig(LINE_MESSAGE, VECTOR_KEY, hash_algorithm="sha256") == SSH_VECTOR_SIG_SHA256


def test_parse_and_rearmor_roundtrip():
    parsed = sshsig.parse_sshsig(SSH_VECTOR_SIG_SHA512)
    assert parsed.armored() == SSH_VECTOR_SIG_SHA512
    blob = parsed.to_blob()
    assert sshsig.dearmor(SSH_VECTOR_SIG_SHA512) == blob
    assert sshsig.armor(blob) == SSH_VECTOR_SIG_SHA512
    assert sshsig.parse_sshsig(blob) == parsed  # binary blob accepted as is
    assert sshsig.parse_sshsig(SSH_VECTOR_SIG_SHA512.encode("ascii")) == parsed


def test_sha256_refused_by_default_and_accepted_when_allowed():
    with pytest.raises(sshsig.InvalidSSHSig, match="sha256"):
        sshsig.verify_sshsig(SSH_VECTOR_SIG_SHA256, LINE_MESSAGE, SSH_VECTOR_PUBLIC_LINE)
    parsed = sshsig.verify_sshsig(
        SSH_VECTOR_SIG_SHA256, LINE_MESSAGE, SSH_VECTOR_PUBLIC_LINE,
        allowed_hash_algorithms=("sha256", "sha512"),
    )
    assert parsed.hash_algorithm == "sha256"


def test_unknown_allowed_hash_algorithm_is_a_caller_error():
    with pytest.raises(ValueError):
        sshsig.verify_sshsig(SSH_VECTOR_SIG_SHA512, LINE_MESSAGE, SSH_VECTOR_PUBLIC_LINE,
                             allowed_hash_algorithms=("md5",))


# ----------------------------------------------------------------------
# verification failures
# ----------------------------------------------------------------------

def test_other_message_fails():
    with pytest.raises(sshsig.InvalidSSHSig, match="does not verify"):
        sshsig.verify_sshsig(SSH_VECTOR_SIG_SHA512, LINE_MESSAGE + b"\n", SSH_VECTOR_PUBLIC_LINE)
    with pytest.raises(sshsig.InvalidSSHSig):
        sshsig.verify_sshsig(SSH_VECTOR_SIG_SHA512, b"s-other\nclaim alice 4b1d0c9e", SSH_VECTOR_PUBLIC_LINE)


def test_expected_key_must_match_embedded_key():
    other = keys.generate_keypair()
    with pytest.raises(sshsig.InvalidSSHSig, match="different key"):
        sshsig.verify_sshsig(SSH_VECTOR_SIG_SHA512, LINE_MESSAGE, other.public_key())


def test_swapping_the_embedded_key_does_not_help():
    """An attacker who replaces the embedded key with the victim's key still needs a valid signature."""
    victim = keys.generate_keypair()
    parsed = sshsig.parse_sshsig(SSH_VECTOR_SIG_SHA512)
    forged = sshsig.SSHSignature(
        public_key_bytes=keys.public_key_bytes(victim.public_key()),
        namespace=parsed.namespace,
        reserved=parsed.reserved,
        hash_algorithm=parsed.hash_algorithm,
        signature=parsed.signature,
    )
    with pytest.raises(sshsig.InvalidSSHSig, match="does not verify"):
        sshsig.verify_sshsig(forged.armored(), LINE_MESSAGE, victim.public_key())


def test_namespace_is_enforced():
    with pytest.raises(sshsig.InvalidSSHSig, match="namespace"):
        sshsig.verify_sshsig(SSH_VECTOR_SIG_SHA512, LINE_MESSAGE, SSH_VECTOR_PUBLIC_LINE, namespace="file")
    git_sig = sshsig.sign_sshsig(LINE_MESSAGE, VECTOR_KEY, namespace="git")
    with pytest.raises(sshsig.InvalidSSHSig, match="namespace"):
        sshsig.verify_sshsig(git_sig, LINE_MESSAGE, SSH_VECTOR_PUBLIC_LINE)
    assert sshsig.verify_sshsig(git_sig, LINE_MESSAGE, SSH_VECTOR_PUBLIC_LINE, namespace="git").namespace == "git"


def test_flipped_signature_byte_fails():
    parsed = sshsig.parse_sshsig(SSH_VECTOR_SIG_SHA512)
    bad = bytearray(parsed.signature)
    bad[10] ^= 0x01
    tampered = sshsig.SSHSignature(parsed.public_key_bytes, parsed.namespace, parsed.reserved,
                                   parsed.hash_algorithm, bytes(bad))
    with pytest.raises(sshsig.InvalidSSHSig):
        sshsig.verify_sshsig(tampered.to_blob(), LINE_MESSAGE, SSH_VECTOR_PUBLIC_LINE)


def test_reserved_field_is_signed_but_otherwise_ignored():
    data = sshsig.signed_data(LINE_MESSAGE, namespace="aics", hash_algorithm="sha512", reserved=b"future")
    good = sshsig.SSHSignature(VECTOR_PUB_RAW, "aics", b"future", "sha512", VECTOR_KEY.sign(data))
    assert sshsig.verify_sshsig(good.armored(), LINE_MESSAGE, VECTOR_KEY.public_key()).reserved == b"future"
    moved = sshsig.SSHSignature(VECTOR_PUB_RAW, "aics", b"", "sha512", good.signature)
    with pytest.raises(sshsig.InvalidSSHSig):
        sshsig.verify_sshsig(moved.armored(), LINE_MESSAGE, VECTOR_KEY.public_key())


def test_message_must_be_bytes():
    with pytest.raises(TypeError):
        sshsig.verify_sshsig(SSH_VECTOR_SIG_SHA512, LINE_MESSAGE.decode(), SSH_VECTOR_PUBLIC_LINE)
    with pytest.raises(TypeError):
        sshsig.sign_sshsig("text", VECTOR_KEY)
    with pytest.raises(ValueError):
        sshsig.sign_sshsig(b"x", VECTOR_KEY, namespace="")


# ----------------------------------------------------------------------
# malformed blobs and armor
# ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"magic": b"SSHSIH"}, "preamble"),
        ({"version": 2}, "version"),
        ({"version": 0}, "version"),
        ({"key_type": b"ssh-rsa"}, "key type"),
        ({"key": b"\x01" * 31}, "32 bytes"),
        ({"key_trailing": b"\x00"}, "trailing"),
        ({"sig_type": b"rsa-sha2-512"}, "signature type"),
        ({"sig": b"\x00" * 63}, "64 bytes"),
        ({"sig_trailing": b"\x00"}, "trailing"),
        ({"trailing": b"\x00"}, "trailing"),
        ({"namespace": b""}, "empty namespace"),
        ({"namespace": b"\xff\xfe"}, "not text"),
    ],
)
def test_malformed_blobs_rejected(overrides, match):
    with pytest.raises(sshsig.MalformedSSHSig, match=match):
        sshsig.parse_sshsig(sshsig.armor(build_blob(**overrides)))


def test_raw_bytes_without_preamble_rejected():
    with pytest.raises(sshsig.MalformedSSHSig, match="not an SSHSIG"):
        sshsig.parse_sshsig(build_blob(magic=b"\xffSSHSI"))


def test_truncated_blob_rejected():
    blob = build_blob()
    for cut in (3, 8, 20, len(blob) - 1):
        with pytest.raises(sshsig.MalformedSSHSig, match="truncated"):
            sshsig.parse_sshsig(sshsig.armor(blob[:cut]))
    with pytest.raises(sshsig.MalformedSSHSig, match="truncated"):
        sshsig.parse_sshsig(blob[:-1])  # raw blob form


def test_crafted_blob_with_valid_structure_parses():
    assert sshsig.parse_sshsig(build_blob()).namespace == "aics"


def test_armor_tolerates_crlf_indentation_and_surrounding_text():
    crlf = SSH_VECTOR_SIG_SHA512.replace("\n", "\r\n")
    indented = "\n".join("   " + line + "  " for line in SSH_VECTOR_SIG_SHA512.splitlines())
    wrapped = "sig-begin\n" + SSH_VECTOR_SIG_SHA512 + "sig-end\n"
    for text in (crlf, indented, wrapped):
        assert sshsig.verify_sshsig(text, LINE_MESSAGE, SSH_VECTOR_PUBLIC_LINE).namespace == "aics"


@pytest.mark.parametrize(
    "text, match",
    [
        ("no armor at all", "BEGIN"),
        (sshsig.BEGIN_MARKER + "\nAAAA\n", "END"),
        (sshsig.BEGIN_MARKER + "\n" + sshsig.END_MARKER + "\n", "empty"),
        (sshsig.BEGIN_MARKER + "\nnot*base64!\n" + sshsig.END_MARKER + "\n", "base64"),
    ],
)
def test_bad_armor_rejected(text, match):
    with pytest.raises(sshsig.MalformedSSHSig, match=match):
        sshsig.parse_sshsig(text)


def test_parse_sshsig_type_errors():
    with pytest.raises(TypeError):
        sshsig.parse_sshsig(12345)
    with pytest.raises(sshsig.MalformedSSHSig):
        sshsig.parse_sshsig(b"\xff\xfe not ascii")


# ----------------------------------------------------------------------
# OpenSSH public key lines
# ----------------------------------------------------------------------

def _pub_line(blob: bytes, key_type: str = "ssh-ed25519") -> str:
    return f"{key_type} {base64.b64encode(blob).decode()}"


@pytest.mark.parametrize(
    "line, match",
    [
        ("ssh-ed25519", "expected"),
        ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ", "key type"),
        (_pub_line(_s(b"ssh-rsa") + _s(b"\x01" * 32)), "key type"),
        (_pub_line(_s(b"ssh-ed25519") + _s(b"\x01" * 31)), "32 bytes"),
        (_pub_line(_s(b"ssh-ed25519") + _s(b"\x01" * 32) + b"\x00"), "trailing"),
        ("ssh-ed25519 not*base64", "base64"),
        ("ssh-ed25519 AAAA", "truncated"),
    ],
)
def test_bad_public_key_lines_rejected(line, match):
    with pytest.raises(sshsig.MalformedSSHSig, match=match):
        sshsig.parse_openssh_public_key(line)


def test_public_key_line_type_errors():
    with pytest.raises(TypeError):
        sshsig.parse_openssh_public_key(None)
    with pytest.raises(ValueError):
        sshsig.format_openssh_public_key(VECTOR_KEY.public_key(), "two\nlines")


# ----------------------------------------------------------------------
# live interop with ssh-keygen (skipped when unavailable)
# ----------------------------------------------------------------------

def test_live_ssh_keygen_signature_verifies_and_matches_our_signer(ssh_keygen_bin, tmp_path):
    key_path = tmp_path / "aics_ed25519"
    assert run_tool([ssh_keygen_bin, "-t", "ed25519", "-N", "", "-f", str(key_path), "-q",
                     "-C", "live@aics"]).returncode == 0
    msg = tmp_path / "line.txt"
    msg.write_bytes(b"live-session\npost hello from ssh-keygen")
    result = run_tool([ssh_keygen_bin, "-Y", "sign", "-f", str(key_path), "-n", "aics", str(msg)])
    assert result.returncode == 0, result.stderr
    armored = (tmp_path / "line.txt.sig").read_text()
    pub_line = (tmp_path / "aics_ed25519.pub").read_text()

    parsed = sshsig.verify_sshsig(armored, msg.read_bytes(), pub_line)
    assert parsed.namespace == "aics" and parsed.hash_algorithm == "sha512"

    private = load_ssh_private_key(key_path.read_bytes(), password=None)
    assert sshsig.sign_sshsig(msg.read_bytes(), private) == armored
    assert sshsig.format_openssh_public_key(private.public_key(), "live@aics") == pub_line.strip()


def test_live_ssh_keygen_accepts_our_signature(ssh_keygen_bin, tmp_path):
    key = keys.generate_keypair()
    message = b"live-session\nsend bob 42"
    sig_path = tmp_path / "msg.sig"
    sig_path.write_text(sshsig.sign_sshsig(message, key))

    ok = run_tool([ssh_keygen_bin, "-Y", "check-novalidate", "-n", "aics", "-s", str(sig_path)], input=message)
    assert ok.returncode == 0, ok.stderr
    wrong_ns = run_tool([ssh_keygen_bin, "-Y", "check-novalidate", "-n", "file", "-s", str(sig_path)], input=message)
    assert wrong_ns.returncode != 0

    signers = tmp_path / "allowed_signers"
    signers.write_text(f"agent {sshsig.format_openssh_public_key(key.public_key())}\n")
    verified = run_tool([ssh_keygen_bin, "-Y", "verify", "-f", str(signers), "-I", "agent", "-n", "aics",
                         "-s", str(sig_path)], input=message)
    assert verified.returncode == 0, verified.stderr
    tampered = run_tool([ssh_keygen_bin, "-Y", "verify", "-f", str(signers), "-I", "agent", "-n", "aics",
                         "-s", str(sig_path)], input=message + b"!")
    assert tampered.returncode != 0

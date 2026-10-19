"""Shared fixtures and constants for the aics_identity test suite."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from aics_identity import keys

# ---------------------------------------------------------------------
# RFC 9421 Appendix B test data
# ---------------------------------------------------------------------

# RFC 9421 B.1.4 "test-key-ed25519"
TEST_KEY_ED25519_SEED = base64.urlsafe_b64decode("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU==")
TEST_KEY_ED25519_PUBLIC = base64.urlsafe_b64decode("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs==")

# RFC 9421 B.2 test request (the parts B.2.6 covers / that we reproduce)
TEST_REQUEST = {
    "method": "POST",
    "url": "https://example.com/foo?param=Value&Pet=dog",
    "headers": [
        ("Host", "example.com"),
        ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
        ("Content-Type", "application/json"),
        ("Content-Digest",
         "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"),
        ("Content-Length", "18"),
    ],
    "body": b'{"hello": "world"}',
}

# RFC 9421 B.2.6 expected values (label sig-b26)
B26_COMPONENTS = ["date", "@method", "@path", "@authority", "content-type", "content-length"]
B26_CREATED = 1618884473
B26_SIGNATURE_INPUT = (
    'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length")'
    ';created=1618884473;keyid="test-key-ed25519"'
)
B26_SIGNATURE_B64 = (
    "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1"
    "u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="
)
B26_SIGNATURE_BASE = (
    '"date": Tue, 20 Apr 2021 02:07:55 GMT\n'
    '"@method": POST\n'
    '"@path": /foo\n'
    '"@authority": example.com\n'
    '"content-type": application/json\n'
    '"content-length": 18\n'
    '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length")'
    ';created=1618884473;keyid="test-key-ed25519"'
)

# RFC 9421 B.2.5 HMAC-SHA256 vector (deterministic: proves base construction)
B25_SECRET = base64.b64decode(
    "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="
)
B25_SIGNATURE_B64 = "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8="
B25_COMPONENTS = ["date", "@authority", "content-type"]
B25_CREATED = 1618884473


# ---------------------------------------------------------------------
# did:key test vector (from the published did:key spec)
# https://w3c-ccg.github.io/did-method-key/ - Ed25519 example
# ---------------------------------------------------------------------

DID_KEY_SPEC_ED25519 = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
DID_KEY_SPEC_ED25519_RAW = bytes.fromhex(
    "2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6"
)
# Second published ed25519 did from the same spec (round-trip check).
DID_KEY_SPEC_ED25519_ALT = "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"


@pytest.fixture()
def test_key() -> Ed25519PrivateKey:
    return keys.private_key_from_seed(TEST_KEY_ED25519_SEED)


@pytest.fixture()
def random_key():
    return keys.generate_keypair()


# ---------------------------------------------------------------------
# Text-protocol line-signature vectors, generated on 2026-10-18 with the
# real tools (OpenSSH 10.3p1 ssh-keygen, OpenSSL 4.0.3) over the same line:
#
#   printf '%s\n%s' 's-7f3a9c' 'claim alice 4b1d0c9e' > msg
#   ssh-keygen -t ed25519 -N '' -f aics_ed25519 -q -C aics-test-vector
#   ssh-keygen -Y sign -f aics_ed25519 -n aics msg
#   ssh-keygen -Y sign -f aics_ed25519 -n aics -O hashalg=sha256 < msg
#   openssl genpkey -algorithm ed25519 -out aics.key
#   openssl pkey -in aics.key -pubout -outform DER | tail -c 32 | base64
#   openssl pkeyutl -sign -inkey aics.key -rawin -in msg | base64
#
# The private seeds are test-only keys, included so the suite can check
# that our signers reproduce the tools' output byte for byte.
# ---------------------------------------------------------------------

LINE_SESSION_ID = "s-7f3a9c"
LINE_TEXT = "claim alice 4b1d0c9e"
LINE_MESSAGE = b"s-7f3a9c\nclaim alice 4b1d0c9e"

SSH_VECTOR_SEED = bytes.fromhex("af1ab4c53c37981e50ada0f22b927cdb15a2fb0f6e22aa0eda9d8aab9e2e08a5")
SSH_VECTOR_PUBLIC_LINE = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID38AJwl6lZfMntqy/J3oursmZM664wWpLpr0/tQGeGI aics-test-vector"
)
SSH_VECTOR_SIG_SHA512 = (
    "-----BEGIN SSH SIGNATURE-----\n"
    "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgPfwAnCXqVl8ye2rL8nei6uyZkz\n"
    "rrjBakumvT+1AZ4YgAAAAEYWljcwAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx\n"
    "OQAAAEBhJQxKxt4cx9sqNcwvYoxM9xzWm52VByhLpMVlTNrPwGkJCNxTotOwRQX4/L7VgM\n"
    "21e4PquW37vXfOT7A/LQkI\n"
    "-----END SSH SIGNATURE-----\n"
)
SSH_VECTOR_SIG_SHA256 = (
    "-----BEGIN SSH SIGNATURE-----\n"
    "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgPfwAnCXqVl8ye2rL8nei6uyZkz\n"
    "rrjBakumvT+1AZ4YgAAAAEYWljcwAAAAAAAAAGc2hhMjU2AAAAUwAAAAtzc2gtZWQyNTUx\n"
    "OQAAAEBb6uquoNkQTMo6UbaGqK43QgyRxHJCH/Q3f0dA2G0vMC0CVJGIH4lrofUL+sFsnF\n"
    "Ep2THOGcF/ETBFqzRH28IH\n"
    "-----END SSH SIGNATURE-----\n"
)

OPENSSL_VECTOR_SEED = bytes.fromhex("f097bef4b80ec978f6f0a1f8bc80b94674efdf04eea644eb220e916b0f831a1d")
OPENSSL_VECTOR_PUBLIC_B64 = "hIBm2x4nvkowSUjnqpcfPgl2nzqoAUstoHoAcBf9l2Y="
OPENSSL_VECTOR_SIG_B64 = (
    "sbgY3OjjyOso1yeiSDfiVeetp+TBLw1qbuhCV4/aAHwH7CVfPysUfR04c59TRk2c+X1g6tx8A7Mi2kkJJ15qCA=="
)


# ---------------------------------------------------------------------
# live tool probes (tests using them are skipped when the tool is absent)
# ---------------------------------------------------------------------

def _run(cmd, **kwargs):
    import subprocess

    return subprocess.run(cmd, capture_output=True, timeout=30, **kwargs)


@pytest.fixture(scope="session")
def ssh_keygen_bin(tmp_path_factory) -> str:
    """Path to an ssh-keygen that can make ed25519 keys and SSHSIG signatures, else skip."""
    import shutil

    exe = shutil.which("ssh-keygen")
    if exe is None:
        pytest.skip("ssh-keygen not available")
    probe = tmp_path_factory.mktemp("ssh-probe")
    key = probe / "k"
    if _run([exe, "-t", "ed25519", "-N", "", "-f", str(key), "-q"]).returncode != 0:
        pytest.skip("ssh-keygen cannot generate ed25519 keys")
    if _run([exe, "-Y", "sign", "-f", str(key), "-n", "aics"], input=b"probe").returncode != 0:
        pytest.skip("ssh-keygen does not support -Y sign (OpenSSH < 8.0)")
    return exe


@pytest.fixture(scope="session")
def openssl_bin(tmp_path_factory) -> str:
    """Path to an openssl that can make Ed25519 keys and sign with pkeyutl -rawin, else skip."""
    import shutil

    exe = shutil.which("openssl")
    if exe is None:
        pytest.skip("openssl not available")
    probe = tmp_path_factory.mktemp("openssl-probe")
    key = probe / "k.pem"
    msg = probe / "m"
    msg.write_bytes(b"probe")
    if _run([exe, "genpkey", "-algorithm", "ed25519", "-out", str(key)]).returncode != 0:
        pytest.skip("this openssl has no Ed25519 (e.g. LibreSSL)")
    if _run([exe, "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(msg)]).returncode != 0:
        pytest.skip("this openssl cannot sign with pkeyutl -rawin")
    return exe


run_tool = _run

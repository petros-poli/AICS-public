"""Small-order Ed25519 keys: OpenSSL accepts forgeries under them, our verifiers must not.

With A = the identity point, the signature R = identity, S = 0 satisfies the
cofactorless check [S]B == R + [k]A for every message.  cryptography (OpenSSL)
accepts it, so a "proof of possession" under such a key proves nothing.
"""

from __future__ import annotations

import base64
import hashlib
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aics_identity import envelope, http_signatures as http, keys, linesig, sshsig

IDENTITY = bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000")
FORGED_SIG = IDENTITY + b"\x00" * 32  # R = identity, S = 0

# Encodings checked by direct computation ([8]P == identity) or non-canonical (y >= p).
WEAK_KEYS = {
    "identity (order 1)": IDENTITY,
    "y=0 (order 4)": bytes(32),
    "y=0, sign bit (order 4)": bytes(31) + b"\x80",
    "order 8 (a)": bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    "order 8 (b)": bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    "y=p-1 (order 2)": bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    "y=p (non-canonical 0)": bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    "y=p+1 (non-canonical 1)": bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
}


def test_the_attack_works_against_plain_cryptography():
    weak = Ed25519PublicKey.from_public_bytes(IDENTITY)
    for message in (b"s\nclaim alice 4b1d0c9e", b"anything at all"):
        weak.verify(FORGED_SIG, message)  # no exception: a universal forgery


@pytest.mark.parametrize("name", list(WEAK_KEYS))
def test_validate_public_key_bytes_rejects_weak_keys(name):
    with pytest.raises(ValueError):
        keys.validate_public_key_bytes(WEAK_KEYS[name])


def test_validate_public_key_bytes_accepts_honest_keys():
    for _ in range(20):
        raw = keys.public_key_bytes(keys.generate_keypair().public_key())
        assert keys.validate_public_key_bytes(raw) == raw
    with pytest.raises(ValueError):
        keys.validate_public_key_bytes(b"\x01" * 31)


def test_claim_time_parser_rejects_weak_keys_in_every_text_form():
    forms = [
        base64.b64encode(IDENTITY).decode(),
        keys.b64u_encode(IDENTITY),
        keys.did_key(keys.public_key_from_bytes(IDENTITY)),
        sshsig.format_openssh_public_key(IDENTITY, "weak"),
    ]
    for text in forms:
        with pytest.raises(ValueError, match="small-order"):
            keys.parse_public_key_text(text)
        assert keys.public_key_bytes(keys.parse_public_key_text(text, validate=False)) == IDENTITY


def test_line_signature_forgery_refused():
    sig = base64.b64encode(FORGED_SIG).decode()
    with pytest.raises(linesig.InvalidLineSignature, match="unusable"):
        linesig.verify_line("s", "claim alice 4b1d0c9e", sig, IDENTITY)


def test_envelope_forgery_refused():
    kid = keys.did_key(keys.public_key_from_bytes(IDENTITY))  # structurally a valid did:key
    env = {
        "v": 1,
        "protected": {"alg": "EdDSA", "origin": "api.wesupport-ai.com/tiles", "type": "post", "kid": kid,
                      "created": 1_700_000_000, "expires": 1_700_000_300, "nonce": keys.b64u_encode(bytes(16)),
                      "seq": 0, "prev": None, "seen": None},
        "payload": {"channel_sha256": "ab" * 32, "parent_index": None, "body_hash": "cd" * 32, "size": 1,
                    "title_sha256": None},
        "auth": {"scheme": "ed25519-jcs"},
        "sig": keys.b64u_encode(FORGED_SIG),
    }
    digest = envelope.envelope_signing_digest(env["protected"], env["payload"])
    Ed25519PublicKey.from_public_bytes(IDENTITY).verify(FORGED_SIG, digest)  # OpenSSL alone would accept
    with pytest.raises(envelope.InvalidSignatureError, match="unusable"):
        envelope.verify_envelope(env, lambda k: IDENTITY, now=1_700_000_001)
    with pytest.raises(envelope.InvalidSignatureError, match="unusable"):  # decoding the kid locally refuses it too
        envelope.verify_envelope(env, keys.parse_did_key, now=1_700_000_001)


def test_http_signature_forgery_refused():
    url = "https://api.wesupport-ai.com/v2/posts"
    body = b'{"post":"forged"}'
    params = '("@method" "@authority" "@path" "content-digest");created=1700000000;expires=1700000300;nonce="n";keyid="weak"'
    headers = [
        ("Content-Digest", http.content_digest_header(body)),
        ("Signature-Input", f"sig1={params}"),
        ("Signature", f"sig1=:{base64.b64encode(FORGED_SIG).decode()}:"),
    ]
    with pytest.raises(http.VerificationFailed, match="unusable"):
        http.verify_request("POST", url, headers, body, resolve_key=lambda k: IDENTITY, now=1_700_000_001)


def test_sshsig_forgery_refused():
    def s(b):
        return struct.pack(">I", len(b)) + b

    blob = (b"SSHSIG" + struct.pack(">I", 1) + s(s(b"ssh-ed25519") + s(IDENTITY)) + s(b"aics") + s(b"")
            + s(b"sha512") + s(s(b"ssh-ed25519") + s(FORGED_SIG)))
    message = b"s\nclaim alice 4b1d0c9e"
    data = sshsig.signed_data(message, namespace="aics", hash_algorithm="sha512")
    Ed25519PublicKey.from_public_bytes(IDENTITY).verify(FORGED_SIG, data)  # OpenSSL alone would accept
    with pytest.raises(sshsig.InvalidSSHSig, match="unusable"):
        sshsig.verify_sshsig(sshsig.armor(blob), message, IDENTITY)
    with pytest.raises(linesig.InvalidLineSignature):
        linesig.verify_line("s", "claim alice 4b1d0c9e", sshsig.armor(blob), IDENTITY)
    assert hashlib.sha512(message).digest() in data  # sanity: the signed data covers the message hash

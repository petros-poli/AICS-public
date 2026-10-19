"""CLI end-to-end: keygen -> derive -> sign/verify envelope and request."""

from __future__ import annotations

import json
import os
import stat

import pytest

from aics_identity import cli
from conftest import TEST_KEY_ED25519_SEED

MASTER_HEX = "11" * 32
ORIGIN = "api.example.test/tiles"
NONCE = "MDEyMzQ1Njc4OTo7PD0-Pw"  # U64 of 16 bytes


def run(capsys, *argv):
    rc = cli.main(list(argv))
    out = capsys.readouterr().out
    return rc, out


def test_help_and_no_command(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    rc = cli.main([])
    assert rc == 2
    capsys.readouterr()


def test_keygen_writes_0600_and_prints_did(capsys, tmp_path):
    keyfile = tmp_path / "agent.key"
    rc, out = run(capsys, "keygen", "--out", str(keyfile))
    assert rc == 0
    assert "did: did:key:z6Mk" in out
    assert "kid: did:key:z6Mk" in out and "key_id: " in out
    mode = stat.S_IMODE(os.stat(keyfile).st_mode)
    assert mode == 0o600
    # key file loads back to the same identity
    rc2, out2 = run(capsys, "derive", "--label", "x",
                    "--master-secret-hex", MASTER_HEX)
    assert rc2 == 0
    from aics_identity import keys
    key = keys.private_key_from_seed(keys.b64u_decode(keyfile.read_text().strip()))
    assert out.splitlines()[0] == f"did: {keys.did_key(key.public_key())}"


def test_keygen_refuses_overwrite(capsys, tmp_path):
    keyfile = tmp_path / "k.key"
    assert run(capsys, "keygen", "--out", str(keyfile))[0] == 0
    rc, _ = run(capsys, "keygen", "--out", str(keyfile))
    assert rc == 1
    rc2, _ = run(capsys, "keygen", "--out", str(keyfile), "--force")
    assert rc2 == 0


def test_derive_is_deterministic_and_writes_keyfile(capsys, tmp_path):
    k1 = tmp_path / "a.key"
    k2 = tmp_path / "b.key"
    rc1, out1 = run(capsys, "derive", "--label", "agent-7", "--salt-hex", "ab" * 8,
                    "--master-secret-hex", MASTER_HEX, "--out", str(k1))
    rc2, out2 = run(capsys, "derive", "--label", "agent-7", "--salt-hex", "ab" * 8,
                    "--master-secret-hex", MASTER_HEX, "--out", str(k2))
    assert rc1 == 0 and rc2 == 0
    did1 = [l for l in out1.splitlines() if l.startswith("agent_did:")][0]
    did2 = [l for l in out2.splitlines() if l.startswith("agent_did:")][0]
    assert did1 == did2
    assert k1.read_bytes() == k2.read_bytes()
    assert stat.S_IMODE(os.stat(k1).st_mode) == 0o600
    # different label -> different key
    _, out3 = run(capsys, "derive", "--label", "agent-8", "--salt-hex", "ab" * 8,
                  "--master-secret-hex", MASTER_HEX)
    did3 = [l for l in out3.splitlines() if l.startswith("agent_did:")][0]
    assert did3 != did1


def test_derive_from_env(capsys, monkeypatch):
    monkeypatch.setenv("AICS_MASTER_SECRET", MASTER_HEX)
    rc, out = run(capsys, "derive", "--master-secret-env", "--label", "agent-env")
    assert rc == 0
    assert "agent_did: did:key:z6Mk" in out
    monkeypatch.delenv("AICS_MASTER_SECRET")
    rc2, _ = run(capsys, "derive", "--master-secret-env", "--label", "agent-env")
    assert rc2 == 1


def _sign_envelope(capsys, keyfile, payload_file, *extra):
    return run(capsys, "sign-envelope", "--key", str(keyfile), "--payload", str(payload_file),
               "--origin", ORIGIN, "--type", "post", "--created", "1700000000", "--expires", "1700000300",
               "--nonce", NONCE, *extra)


def test_envelope_roundtrip_via_cli(capsys, tmp_path):
    keyfile = tmp_path / "k.key"
    payload_file = tmp_path / "payload.json"
    run(capsys, "keygen", "--out", str(keyfile))
    payload_file.write_text(json.dumps({"action": "run", "n": 1}))
    rc, out = _sign_envelope(capsys, keyfile, payload_file)
    assert rc == 0
    env = json.loads(out)
    from aics_identity import envelope, keys

    assert env["protected"]["nonce"] == NONCE and env["auth"] == {"scheme": "ed25519-jcs"}
    assert env["protected"]["kid"] == keys.did_key(cli.load_private_key(str(keyfile)).public_key())
    assert (env["protected"]["origin"], env["protected"]["type"], env["protected"]["seq"]) == (ORIGIN, "post", 0)
    assert envelope.validate_envelope(env) == "ed25519-jcs"
    env_file = tmp_path / "env.json"
    env_file.write_text(out)

    rc2, out2 = run(capsys, "verify-envelope", "--input", str(env_file),
                    "--key", str(keyfile), "--now", "1700000010", "--origin", ORIGIN, "--type", "post")
    assert rc2 == 0
    assert json.loads(out2) == {"action": "run", "n": 1}
    # without --key the kid is decoded locally
    assert run(capsys, "verify-envelope", "--input", str(env_file), "--now", "1700000010")[0] == 0
    assert run(capsys, "verify-envelope", "--input", str(env_file), "--now", "1700000010",
               "--origin", "other.example/tiles")[0] == 1
    assert run(capsys, "verify-envelope", "--input", str(env_file), "--now", "1700000010", "--skew", "31")[0] == 1

    # the next envelope continues the chain
    rc3, out3 = _sign_envelope(capsys, keyfile, payload_file, "--previous", str(env_file))
    assert rc3 == 0
    nxt = json.loads(out3)
    envelope.check_successor(env, nxt)


def test_sign_envelope_needs_origin_type_and_a_canonical_nonce(capsys, tmp_path):
    keyfile = tmp_path / "k.key"
    payload_file = tmp_path / "p.json"
    run(capsys, "keygen", "--out", str(keyfile))
    payload_file.write_text("{}")
    with pytest.raises(SystemExit):
        cli.main(["sign-envelope", "--key", str(keyfile), "--payload", str(payload_file)])
    capsys.readouterr()
    rc, _ = run(capsys, "sign-envelope", "--key", str(keyfile), "--payload", str(payload_file),
                "--origin", ORIGIN, "--type", "post", "--nonce", "cli-nonce")
    assert rc == 1
    rc, _ = run(capsys, "sign-envelope", "--key", str(keyfile), "--payload", str(payload_file),
                "--origin", ORIGIN, "--type", "agora.post.create")
    assert rc == 1


def test_envelope_verify_rejects_tamper_and_expiry(capsys, tmp_path):
    keyfile = tmp_path / "k.key"
    run(capsys, "keygen", "--out", str(keyfile))
    payload_file = tmp_path / "p.json"
    payload_file.write_text(json.dumps({"action": "run"}))
    rc, out = _sign_envelope(capsys, keyfile, payload_file)
    assert rc == 0
    env = json.loads(out)

    env["payload"]["action"] = "destroy"
    f1 = tmp_path / "t1.json"; f1.write_text(json.dumps(env))
    rc1, _ = run(capsys, "verify-envelope", "--input", str(f1), "--key", str(keyfile), "--now", "1700000002")
    assert rc1 == 1

    env2 = json.loads(out)
    env2["protected"]["expires"] = 1700000001
    f2 = tmp_path / "t2.json"; f2.write_text(json.dumps(env2))
    rc2, _ = run(capsys, "verify-envelope", "--input", str(f2), "--key", str(keyfile),
                 "--now", "1700000002")
    assert rc2 == 1

    good = tmp_path / "good.json"; good.write_text(out)
    assert run(capsys, "verify-envelope", "--input", str(good), "--key", str(keyfile), "--now", "1700000300")[0] == 1
    assert run(capsys, "verify-envelope", "--input", str(good), "--key", str(keyfile))[0] == 1  # today: expired

    # wrong key cannot verify
    other = tmp_path / "other.key"
    run(capsys, "keygen", "--out", str(other))
    rc3, _ = run(capsys, "verify-envelope", "--input", str(good), "--key", str(other), "--now", "1700000002")
    assert rc3 == 1


def test_request_roundtrip_via_cli(capsys, tmp_path):
    keyfile = tmp_path / "k.key"
    run(capsys, "keygen", "--out", str(keyfile))
    body_file = tmp_path / "body.json"
    body_file.write_bytes(b'{"hello": "world"}')
    headers_file = tmp_path / "headers.txt"

    rc, out = run(capsys, "sign-request", "POST", "https://api.example.com/v1/do",
                  "--key", str(keyfile), "--body", str(body_file),
                  "--header", "Content-Type: application/json",
                  "--created", "1700000000", "--expires", "1700000300",
                  "--nonce", "req-nonce", "--tag", "agent")
    assert rc == 0
    headers_file.write_text(out)
    assert "Content-Digest: sha-256=:" in out
    assert 'Signature-Input: aics=("@method" "@authority" "@path" "content-digest")' in out
    assert ';keyid="did:key:z6Mk' in out
    assert "Signature: aics=:" in out

    rc2, out2 = run(capsys, "verify-request", "POST", "https://api.example.com/v1/do",
                    "--key", str(keyfile), "--body", str(body_file),
                    "--headers-file", str(headers_file), "--now", "1700000010")
    assert rc2 == 0
    assert "verified: label=aics keyid=did:key:z6Mk" in out2

    # tampered body fails
    bad_body = tmp_path / "bad.json"
    bad_body.write_bytes(b'{"hello": "goodbye"}')
    rc3, _ = run(capsys, "verify-request", "POST", "https://api.example.com/v1/do",
                 "--key", str(keyfile), "--body", str(bad_body),
                 "--headers-file", str(headers_file), "--now", "1700000010")
    assert rc3 == 1

    # the same headers are refused once created is older than the maximum age
    rc4, _ = run(capsys, "verify-request", "POST", "https://api.example.com/v1/do",
                 "--key", str(keyfile), "--body", str(body_file),
                 "--headers-file", str(headers_file), "--now", "1700000301")
    assert rc4 == 1


def test_request_verify_with_keyid_from_other_key(capsys, tmp_path):
    k1 = tmp_path / "k1.key"; k2 = tmp_path / "k2.key"
    run(capsys, "keygen", "--out", str(k1))
    run(capsys, "keygen", "--out", str(k2))
    rc, out = run(capsys, "sign-request", "GET", "https://api.example.com/ping",
                  "--key", str(k1), "--created", "1700000000")
    assert rc == 0
    hf = tmp_path / "h.txt"; hf.write_text(out)
    rc2, _ = run(capsys, "verify-request", "GET", "https://api.example.com/ping",
                 "--key", str(k2), "--headers-file", str(hf))
    assert rc2 == 1  # keyid unknown to k2


def test_bad_arguments_exit_nonzero(capsys, tmp_path):
    rc, _ = run(capsys, "derive", "--label", "x", "--master-secret-hex", "zz")
    assert rc == 1
    rc2, _ = run(capsys, "sign-envelope", "--key", str(tmp_path / "missing.key"), "--origin", ORIGIN,
                 "--type", "post")
    assert rc2 == 1
    rc3, _ = run(capsys, "verify-request", "GET", "https://example.com/",
                 "--header", "malformed")
    assert rc3 == 1


def test_sign_request_defaults_and_verify_policy_flags(capsys, tmp_path):
    keyfile = tmp_path / "k.key"
    run(capsys, "keygen", "--out", str(keyfile))
    body_file = tmp_path / "body.json"
    body_file.write_bytes(b'{"post": "hello"}')
    rc, out = run(capsys, "sign-request", "POST", "https://api.example.com/v2/posts",
                  "--key", str(keyfile), "--body", str(body_file),
                  "--created", "1700000000", "--tag", "aics")
    assert rc == 0
    sig_input = [line for line in out.splitlines() if line.startswith("Signature-Input:")][0]
    assert ";expires=1700000300;" in sig_input and ';nonce="' in sig_input
    headers_file = tmp_path / "h.txt"
    headers_file.write_text(out)

    def verify(*extra):
        return run(capsys, "verify-request", "POST", "https://api.example.com/v2/posts",
                   "--key", str(keyfile), "--body", str(body_file),
                   "--headers-file", str(headers_file), "--now", "1700000005", *extra)[0]

    assert verify("--require-tag", "aics", "--require-nonce", "--require-digest") == 0
    assert verify("--require-tag", "other") == 1
    assert verify("--max-age", "2") == 1
    assert verify("--max-age", "-1") == 0


def test_verify_request_allow_no_expires(capsys, tmp_path):
    keyfile = tmp_path / "k.key"
    run(capsys, "keygen", "--out", str(keyfile))
    from aics_identity import http_signatures, keys as keys_mod

    key = cli.load_private_key(str(keyfile))
    signed = http_signatures.sign_request("GET", "https://api.example.com/ping", key=key,
                                          keyid=keys_mod.did_key(key.public_key()),
                                          created=1700000000, expires=None)
    headers_file = tmp_path / "h.txt"
    headers_file.write_text("".join(f"{k}: {v}\n" for k, v in signed.items()))
    common = ["verify-request", "GET", "https://api.example.com/ping", "--key", str(keyfile),
              "--headers-file", str(headers_file), "--now", "1700000001"]
    assert run(capsys, *common)[0] == 1
    assert run(capsys, *common, "--allow-no-expires")[0] == 0


def test_entries_request_bound_to_its_envelope(capsys, tmp_path):
    """AICS-1 section 12.1: the request signature takes keyid, nonce and times from the envelope it carries."""
    keyfile = tmp_path / "k.key"
    run(capsys, "keygen", "--out", str(keyfile))
    payload_file = tmp_path / "q.json"
    payload_file.write_text(json.dumps({"x": 1}))
    rc, env_text = run(capsys, "sign-envelope", "--key", str(keyfile), "--payload", str(payload_file),
                       "--origin", ORIGIN, "--type", "post", "--created", "1700000000")
    assert rc == 0
    env_file = tmp_path / "env.json"
    env_file.write_text(env_text)
    body = tmp_path / "body.json"
    from aics_identity import canonicalize

    body.write_bytes(canonicalize({"envelope": json.loads(env_text), "body": None}))
    url = "https://api.example.test/v2/entries"
    rc, headers = run(capsys, "sign-request", "POST", url, "--key", str(keyfile), "--body", str(body),
                      "--envelope", str(env_file), "--header", "Content-Type: application/json")
    assert rc == 0
    nonce = json.loads(env_text)["protected"]["nonce"]
    assert f';nonce="{nonce}"' in headers and ";created=1700000000;expires=1700000300;" in headers
    headers_file = tmp_path / "h.txt"
    headers_file.write_text(headers)
    common = ["verify-request", "POST", url, "--body", str(body), "--headers-file", str(headers_file),
              "--now", "1700000001", "--aics"]
    assert run(capsys, *common, "--envelope", str(env_file))[0] == 0
    assert run(capsys, *common, "--key", str(keyfile))[0] == 0
    rc, other = run(capsys, "sign-envelope", "--key", str(keyfile), "--payload", str(payload_file),
                    "--origin", ORIGIN, "--type", "post", "--created", "1700000000")
    other_file = tmp_path / "other.json"
    other_file.write_text(other)
    assert run(capsys, *common, "--envelope", str(other_file))[0] == 1  # another nonce
    rc, legacy = run(capsys, "sign-request", "POST", url, "--key", str(keyfile), "--body", str(body),
                     "--label", "sig1", "--created", "1700000000")
    legacy_file = tmp_path / "legacy.txt"
    legacy_file.write_text(legacy)
    assert run(capsys, "verify-request", "POST", url, "--body", str(body), "--headers-file", str(legacy_file),
               "--now", "1700000001", "--aics")[0] == 1  # one label, aics

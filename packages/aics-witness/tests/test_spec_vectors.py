"""Byte-exact test vectors from docs/spec/AICS-1.md, Appendix A.3.

Seeds are public test values: the log key is 32 bytes of 0x02, the witness
key 32 bytes of 0x06.  Ed25519 is deterministic, so a witness fed the
example checkpoints at the example times must return exactly the example
cosignature lines.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import parse_vkey
from aics_witness.cli import main
from aics_witness.config import LogConfig
from aics_witness.feeder import WitnessClient, merge_cosignatures
from aics_witness.store import SEED_ENV

from conftest import start_witness, threshold_policy_ok

ORIGIN = "log.example/aics-1"
WITNESS = "witness.example/w1"
LOG_VKEY = "log.example/aics-1+d34caeba+AYE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOU"
WITNESS_VKEY = "witness.example/w1+c3c1499d+BIqHX/8es4RRV3rNWv7kBUVlaN18ieCQhjoFV7x69J8X"

NOTE_3 = (
    "log.example/aics-1\n3\nl8Lavw2FapIGVNaC1b79k5ZTKgdbKcP6yMe3MvODz7s=\n\n"
    "— log.example/aics-1 00yuulrcq6B1jBGE330RL5IqSDwmbaWPG6AF4jNqqlYX3aanb2xVQxuZImRCKNRIL57y2"
    "epg3ZqAo75R0YrIyjM3eAE=\n"
)
COSIG_3 = (
    "— witness.example/w1 w8FJnQAAAABq1AwAign7qPOXfnZHHHA8ayI3E+WMoFUVUGX8E32/X75FJGyvzpXoWVW72JAA"
    "0bPuVicV/GH+Gqf78fiDM7ANXCLgAg==\n"
)
NOTE_3_SHA256 = "5b94d66c1e45e26995cdc8e3ecbcf70d037af0b15ebb1db731b85774a072d535"

NOTE_4 = (
    "log.example/aics-1\n4\nPPj+PEGLKQS5SGjh1C/GODYYecZdTrZD+FAUHMo+D08=\n\n"
    "— log.example/aics-1 00yuure2ZQ6O5z/3k7e+i2S3Y979UmSp7r4qaYHPvqBP4BMNR+mA6JoB+q8rX6guXSK8vi"
    "xUDBwideb99sR+qrLXag8=\n"
)
COSIG_4 = (
    "— witness.example/w1 w8FJnQAAAABq1AwCrysUqRktYIWXtKxrgID5XAxPe4TSDCPcPbjy4pLeABOPTgKgeybY8Pjj"
    "9DNiWKxTjgrl0wVdWqYT4hTtMxKEAw==\n"
)
NOTE_4_SHA256 = "fb2b18a043a1dffea3b70a4ddac14364c44701937557a40dcdbdd64fe8e59e70"

PROOF_3_TO_4 = [
    base64.b64decode(h)
    for h in (
        "8Hp/k6E0nK5+HkFPPXnFUerg4h7QhSIjYDEW6kfsPNo=",
        "6/b86KfvZNX8TUaUzBzmrx6MIqXalm+cS5BUp4toer4=",
        "y9NuiypL6RwuQc5Ts2KHM86HZVy/ExlQ/HUreOPopCM=",
    )
]

WITNESS_SEED = bytes([0x06]) * 32


def test_witness_reproduces_spec_cosignatures(tmp_path):
    clock = [1792281600.0]
    witness_key = Ed25519PrivateKey.from_private_bytes(WITNESS_SEED)
    rw = start_witness(tmp_path / "w.db", witness_key,
                       [LogConfig.from_strings(ORIGIN, [LOG_VKEY])], name=WITNESS,
                       clock=lambda: clock[0])
    try:
        assert rw.witness.vkey_text == WITNESS_VKEY
        with WitnessClient(rw.url, WITNESS_VKEY, clock=lambda: clock[0]) as client:
            line3 = client.submit(NOTE_3.encode(), (0, []))
            assert line3 == COSIG_3
            full3 = merge_cosignatures(NOTE_3.encode(), line3)
            assert hashlib.sha256(full3).hexdigest() == NOTE_3_SHA256

            clock[0] = 1792281602.0
            line4 = client.submit(NOTE_4.encode(), (3, PROOF_3_TO_4))
            assert line4 == COSIG_4
            full4 = merge_cosignatures(NOTE_4.encode(), line4)
            assert hashlib.sha256(full4).hexdigest() == NOTE_4_SHA256

        assert threshold_policy_ok(full4, parse_vkey(LOG_VKEY), [parse_vkey(WITNESS_VKEY)], 1)
        assert rw.store.get(ORIGIN).note.encode() == full4
    finally:
        rw.stop()


def test_init_prints_spec_witness_vkey(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv(SEED_ENV, WITNESS_SEED.hex())
    code = main(["init", "--config", str(tmp_path / "w.json"), "--name", WITNESS, "--new-database"])
    assert code == 0
    assert capsys.readouterr().out == WITNESS_VKEY + "\n"

"""Full round trip: an in-process aics-tlog log grows, signs checkpoints,
submits them to a running witness over HTTP through the feeder, and the
returned cosignatures satisfy a threshold policy of 1."""

from __future__ import annotations

import base64
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import cosignature_vkey, parse_checkpoint, parse_note, parse_vkey
from aics_witness.config import LogConfig
from aics_witness.feeder import BadWitnessResponse, WitnessClient, merge_cosignatures, submit_checkpoint
from aics_witness.protocol import origin_hash

from conftest import WITNESS_NAME, InProcessLog, http_request, start_witness, threshold_policy_ok

GROWTH = [1, 1, 1, 2, 3, 5, 8, 13, 21, 34, 64, 1, 100, 256, 3]


def test_growing_log_round_trip(running, log: InProcessLog, witness_key):
    witness_vkey = cosignature_vkey(WITNESS_NAME, witness_key.public_key())
    assert running.witness.vkey_text == f"{witness_vkey.name}+{witness_vkey.key_id.hex()}+" + \
        base64.b64encode(bytes([0x04]) + witness_key.public_key().public_bytes_raw()).decode()
    absent = cosignature_vkey("absent.example.test/w", Ed25519PrivateKey.generate().public_key())

    client = WitnessClient(running.url, running.witness.vkey_text)
    try:
        for step in GROWTH:
            log.append(step)
            signed = log.checkpoint()
            line = client.submit(signed, log.proof)
            assert line.startswith("— " + WITNESS_NAME + " ") and line.endswith("\n")
            assert line.count("\n") == 1

            cosigned = merge_cosignatures(signed, line)
            # ThresholdPolicy(1) over this witness: met, and fresh.
            assert threshold_policy_ok(cosigned, log.vkey, [witness_vkey], 1)
            assert threshold_policy_ok(cosigned, log.vkey, [witness_vkey], 1, max_age_seconds=60)
            assert threshold_policy_ok(cosigned, log.vkey, [absent, witness_vkey], 1)
            # The log signature alone does not meet a threshold of 1.
            assert not threshold_policy_ok(signed, log.vkey, [witness_vkey], 1)
            # One cosignature cannot meet a threshold of 2.
            assert not threshold_policy_ok(cosigned, log.vkey, [witness_vkey, absent], 2)

            state = running.store.get(log.origin)
            assert state is not None and state.size == log.size
            assert state.root == log.tree.root()
            assert client.known_sizes[log.origin] == log.size
    finally:
        client.close()
    assert log.size == sum(GROWTH)


def test_round_trip_through_one_shot_submit(running, log: InProcessLog):
    log.append(10)
    line = submit_checkpoint(running.url, log.checkpoint(), log.proof,
                             witness_vkey=running.witness.vkey_text)
    log.append(7)
    # A fresh client knows nothing: it starts from old 0, gets 409 with the
    # witness's size 10, and retries with a proof from 10 to 17.
    line2 = submit_checkpoint(running.url, log.checkpoint(), log.proof,
                              witness_vkey=running.witness.vkey_text)
    assert line != line2
    assert running.store.get(log.origin).size == 17


def test_monitoring_endpoint_serves_latest_cosigned_checkpoint(running, log: InProcessLog):
    url = f"{running.url}/{origin_hash(log.origin)}/checkpoint"
    assert http_request(url, "GET").status == 404  # never cosigned
    log.append(5)
    signed = log.checkpoint()
    submit_checkpoint(running.url, signed, log.proof, witness_vkey=running.witness.vkey_text)

    res = http_request(url, "GET")
    assert res.status == 200
    note = parse_note(res.body)
    cp = parse_checkpoint(note.text)
    assert (cp.origin, cp.size, cp.root) == (log.origin, 5, log.tree.root())
    # It carries the verified log signature and the witness cosignature.
    assert threshold_policy_ok(res.body, log.vkey, [parse_vkey(running.witness.vkey_text)], 1)
    names = [s.name for s in note.signatures]
    assert names == [log.origin, WITNESS_NAME]
    # Unknown origin hashes and malformed paths are 404.
    assert http_request(f"{running.url}/{'0' * 64}/checkpoint", "GET").status == 404
    assert http_request(f"{running.url}/{'A' * 64}/checkpoint", "GET").status == 404


def test_unverified_signatures_are_not_relayed(running, log: InProcessLog):
    """Signatures from unknown keys in the submission are ignored and not
    stored in the served checkpoint."""
    from aics_tlog import Note, sign_note

    log.append(3)
    note = parse_note(log.checkpoint())
    stranger = sign_note(note.text, Ed25519PrivateKey.generate(), "stranger.example/k")
    submitted = Note(text=note.text, signatures=note.signatures + (stranger,)).to_bytes()
    submit_checkpoint(running.url, submitted, log.proof, witness_vkey=running.witness.vkey_text)
    served = parse_note(running.witness.latest_checkpoint(origin_hash(log.origin)))
    assert [s.name for s in served.signatures] == [log.origin, WITNESS_NAME]


def test_two_witnesses_threshold(tmp_path, log: InProcessLog):
    keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
    logs = [LogConfig(origin=log.origin, vkeys=(log.vkey,))]
    w1 = start_witness(tmp_path / "w1.db", keys[0], logs, name="w1.example.test/w")
    w2 = start_witness(tmp_path / "w2.db", keys[1], logs, name="w2.example.test/w")
    try:
        vkeys = [parse_vkey(w1.witness.vkey_text), parse_vkey(w2.witness.vkey_text)]
        log.append(42)
        signed = log.checkpoint()
        first = submit_checkpoint(w1.url, signed, log.proof, witness_vkey=vkeys[0])
        one = merge_cosignatures(signed, first)
        assert threshold_policy_ok(one, log.vkey, vkeys, 1)
        assert not threshold_policy_ok(one, log.vkey, vkeys, 2)
        second = submit_checkpoint(w2.url, signed, log.proof, witness_vkey=vkeys[1])
        both = merge_cosignatures(one, second)
        assert threshold_policy_ok(both, log.vkey, vkeys, 2)
    finally:
        w1.stop()
        w2.stop()


def test_freshness_of_cosignatures_under_policy(tmp_path, log: InProcessLog):
    """The cosignature timestamp is the witness's current time, so a policy
    with max_checkpoint_age accepts it now and rejects it once it is old; a
    witness whose clock lags produces cosignatures such a policy refuses, and
    the feeder refuses them by default too."""
    logs = [LogConfig(origin=log.origin, vkeys=(log.vkey,))]
    real = start_witness(tmp_path / "real.db", Ed25519PrivateKey.generate(), logs,
                         name="real.example.test/w")
    lagging = start_witness(tmp_path / "lag.db", Ed25519PrivateKey.generate(), logs,
                            name="lagging.example.test/w", clock=lambda: time.time() - 3600)
    try:
        log.append(11)
        signed = log.checkpoint()
        real_vkey = parse_vkey(real.witness.vkey_text)
        lag_vkey = parse_vkey(lagging.witness.vkey_text)
        fresh = merge_cosignatures(signed, submit_checkpoint(real.url, signed, log.proof,
                                                             witness_vkey=real_vkey))
        with pytest.raises(BadWitnessResponse, match="old"):
            submit_checkpoint(lagging.url, signed, log.proof, witness_vkey=lag_vkey)
        stale = merge_cosignatures(signed, submit_checkpoint(lagging.url, signed, log.proof,
                                                             witness_vkey=lag_vkey,
                                                             max_age_seconds=None))
        now = int(time.time())
        assert threshold_policy_ok(fresh, log.vkey, [real_vkey], 1, max_age_seconds=600)
        assert not threshold_policy_ok(fresh, log.vkey, [real_vkey], 1, max_age_seconds=600,
                                       now=now + 1200)
        assert threshold_policy_ok(stale, log.vkey, [lag_vkey], 1)  # authentic ...
        assert not threshold_policy_ok(stale, log.vkey, [lag_vkey], 1, max_age_seconds=600)  # ... but old
    finally:
        real.stop()
        lagging.stop()


def test_resubmitting_same_checkpoint_gives_fresh_cosignature(tmp_path, log: InProcessLog, witness_key):
    now = [1_800_000_000.0]
    rw = start_witness(tmp_path / "w.db", witness_key,
                       [LogConfig(origin=log.origin, vkeys=(log.vkey,))], clock=lambda: now[0])
    try:
        log.append(9)
        signed = log.checkpoint()
        client = WitnessClient(rw.url, rw.witness.vkey_text, clock=lambda: now[0])
        first = client.submit(signed, log.proof)
        now[0] += 120
        second = client.submit(signed, log.proof)  # old 9 -> 9, roots equal
        client.close()
        ts = [int.from_bytes(base64.b64decode(l.split()[-1])[4:12], "big") for l in (first, second)]
        assert ts == [1_800_000_000, 1_800_000_120]
        assert rw.store.get(log.origin).timestamp == 1_800_000_120
    finally:
        rw.stop()

"""Cosignature freshness (max age) and witness policies (quorum >= 1)."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aics_tlog import MerkleTree
from aics_tlog.checkpoint import Checkpoint, WitnessPolicy, sign_checkpoint, verify_checkpoint
from aics_tlog.cosign import (
    DEFAULT_MAX_FUTURE_SECONDS,
    cosignature_timestamp,
    cosignature_vkey,
    sign_cosignature,
    timestamp_is_fresh,
    verify_cosignature,
)
from aics_tlog.note import Note, format_vkey, vkey_from_ed25519

ROOT = MerkleTree([b"a", b"b", b"c"]).root()
NOW = 1_800_000_000
ORIGIN = "log.example/v2"


@pytest.fixture(scope="module")
def keys():
    log = Ed25519PrivateKey.generate()
    wits = [Ed25519PrivateKey.generate() for _ in range(3)]
    return log, wits


def cosigned(keys, times, names=None):
    """A checkpoint note cosigned by witness i at times[i] (None: no cosignature)."""
    log, wits = keys
    cp = Checkpoint(ORIGIN, 3, ROOT)
    note = sign_checkpoint(cp, log, ORIGIN)
    sigs = []
    for i, t in enumerate(times):
        if t is None:
            continue
        name = (names or [f"wit.example/w{j}" for j in range(3)])[i]
        sigs.append(sign_cosignature(wits[i], name, t, ORIGIN, 3, ROOT)[1])
    return Note(text=note.text, signatures=(*sigs, note.signatures[0]))


def log_vkey(keys):
    return vkey_from_ed25519(ORIGIN, keys[0].public_key())


def wit_vkeys(keys, names=None):
    return [cosignature_vkey((names or [f"wit.example/w{j}" for j in range(3)])[i], w.public_key()) for i, w in enumerate(keys[1])]


# --- verify_cosignature -------------------------------------------------------


def test_cosignature_max_age():
    w = Ed25519PrivateKey.generate()
    blob, _ = sign_cosignature(w, "w", NOW - 100, "o", 1, ROOT)
    assert cosignature_timestamp(blob) == NOW - 100
    assert verify_cosignature(blob, "w", w.public_key(), "o", 1, ROOT, max_age_seconds=100, now=NOW)
    assert not verify_cosignature(blob, "w", w.public_key(), "o", 1, ROOT, max_age_seconds=99, now=NOW)
    assert verify_cosignature(blob, "w", w.public_key(), "o", 1, ROOT)  # no bound: no check


def test_max_age_implies_a_future_bound():
    w = Ed25519PrivateKey.generate()
    ahead, _ = sign_cosignature(w, "w", NOW + DEFAULT_MAX_FUTURE_SECONDS + 1, "o", 1, ROOT)
    near, _ = sign_cosignature(w, "w", NOW + DEFAULT_MAX_FUTURE_SECONDS, "o", 1, ROOT)
    assert not verify_cosignature(ahead, "w", w.public_key(), "o", 1, ROOT, max_age_seconds=3600, now=NOW)
    assert verify_cosignature(near, "w", w.public_key(), "o", 1, ROOT, max_age_seconds=3600, now=NOW)
    assert verify_cosignature(ahead, "w", w.public_key(), "o", 1, ROOT, max_age_seconds=3600,
                              max_future_seconds=10**6, now=NOW)


def test_timestamp_is_fresh_edges():
    assert timestamp_is_fresh(NOW - 60, max_age_seconds=60, now=NOW)
    assert not timestamp_is_fresh(NOW - 61, max_age_seconds=60, now=NOW)
    assert timestamp_is_fresh(0)  # no bounds
    with pytest.raises(ValueError):
        timestamp_is_fresh(NOW, max_age_seconds=-1, now=NOW)


# --- verify_checkpoint freshness ----------------------------------------------


def test_stale_cosignatures_do_not_count(keys):
    note = cosigned(keys, [NOW - 10, NOW - 7200, None])
    res = verify_checkpoint(note, log_vkey(keys), wit_vkeys(keys), 1, max_age_seconds=3600, now=NOW)
    assert res.ok and res.witnesses == ["wit.example/w0"] and res.stale == ["wit.example/w1"]
    assert res.timestamps == {"wit.example/w0": NOW - 10, "wit.example/w1": NOW - 7200}
    res = verify_checkpoint(note, log_vkey(keys), wit_vkeys(keys), 2, max_age_seconds=3600, now=NOW)
    assert not res.ok and "quorum not met" in res.error and "stale" in res.error
    # Without a freshness bound both count (backwards compatible).
    assert verify_checkpoint(note, log_vkey(keys), wit_vkeys(keys), 2, now=NOW).ok


def test_replayed_old_checkpoint_fails_freshness(keys):
    note = cosigned(keys, [NOW - 86400, NOW - 86400, NOW - 86400])
    res = verify_checkpoint(note, log_vkey(keys), wit_vkeys(keys), 1, max_age_seconds=3600, now=NOW)
    assert not res.ok and res.cosignature_count == 0 and len(res.stale) == 3


def test_future_cosignature_does_not_count_but_does_not_poison(keys):
    note = cosigned(keys, [NOW, NOW + 10**6, None])
    res = verify_checkpoint(note, log_vkey(keys), wit_vkeys(keys), 1, max_age_seconds=3600, now=NOW)
    assert res.ok and res.future == ["wit.example/w1"]
    res = verify_checkpoint(note, log_vkey(keys), wit_vkeys(keys), 1, max_future_seconds=60, now=NOW)
    assert res.ok and res.future == ["wit.example/w1"]


def test_invalid_cosignature_still_rejects_the_note(keys):
    note = cosigned(keys, [NOW, NOW, None])
    sigs = list(note.signatures)
    bad = sigs[1]
    from aics_tlog.note import SignatureLine

    sigs[1] = SignatureLine(bad.name, bad.key_id, bad.signature[:8] + bytes(64))
    res = verify_checkpoint(Note(note.text, tuple(sigs)), log_vkey(keys), wit_vkeys(keys), 1,
                            max_age_seconds=3600, now=NOW)
    assert not res.ok and "failed verification" in res.error


def test_one_key_under_two_names_counts_once(keys):
    log, wits = keys
    names = ["wit.example/a", "wit.example/b"]
    cp = Checkpoint(ORIGIN, 3, ROOT)
    note = sign_checkpoint(cp, log, ORIGIN)
    blob_a = sign_cosignature(wits[0], names[0], NOW, ORIGIN, 3, ROOT)[1]
    blob_b = sign_cosignature(wits[0], names[1], NOW, ORIGIN, 3, ROOT)[1]
    signed = Note(note.text, (blob_a, blob_b, note.signatures[0]))
    vks = [cosignature_vkey(n, wits[0].public_key()) for n in names]
    res = verify_checkpoint(signed, log_vkey(keys), vks, 2, now=NOW)
    assert not res.ok and res.cosignature_count == 1
    with pytest.raises(ValueError, match="reuses"):
        WitnessPolicy(1, tuple(vks))


# --- witness policy -----------------------------------------------------------


def test_policy_requires_quorum_of_at_least_one(keys):
    vks = tuple(wit_vkeys(keys))
    for bad in (0, -1, 4, True, "1"):
        with pytest.raises(ValueError):
            WitnessPolicy(bad, vks)
    with pytest.raises(ValueError):
        WitnessPolicy(1, ())
    with pytest.raises(ValueError):
        WitnessPolicy(1, (log_vkey(keys),))  # not a cosignature key
    with pytest.raises(ValueError):
        WitnessPolicy(1, (vks[0], vks[0]))
    with pytest.raises(ValueError):
        WitnessPolicy(1, vks, max_age_seconds=0)


def test_policy_drives_verification(keys):
    policy = WitnessPolicy(2, tuple(wit_vkeys(keys)), max_age_seconds=3600)
    fresh = cosigned(keys, [NOW, NOW - 5, None])
    assert verify_checkpoint(fresh, log_vkey(keys), policy=policy, now=NOW).ok
    one_stale = cosigned(keys, [NOW, NOW - 5000, None])
    res = verify_checkpoint(one_stale, log_vkey(keys), policy=policy, now=NOW)
    assert not res.ok and res.quorum == 2 and res.max_age_seconds == 3600
    # An explicit max age overrides the policy's.
    assert verify_checkpoint(one_stale, log_vkey(keys), policy=policy, max_age_seconds=6000, now=NOW).ok
    with pytest.raises(ValueError):
        verify_checkpoint(fresh, log_vkey(keys), wit_vkeys(keys), 1, policy=policy)
    unsigned = cosigned(keys, [None, None, None])
    res = verify_checkpoint(unsigned, log_vkey(keys), policy=WitnessPolicy(1, tuple(wit_vkeys(keys))), now=NOW)
    assert not res.ok and res.cosignature_count == 0


def test_policy_json_forms(keys):
    wit = [format_vkey(v) for v in wit_vkeys(keys)]
    flat = WitnessPolicy.from_json(json.dumps({"quorum": 2, "witnesses": wit, "max_checkpoint_age": 600}))
    card = WitnessPolicy.from_dict({"witness_policy": {"quorum": 2, "witnesses": wit}, "max_checkpoint_age": 600})
    assert flat == card and flat.quorum == 2 and flat.max_age_seconds == 600 and len(flat.witnesses) == 3
    for bad in ('{"quorum": 0, "witnesses": []}', '{"witnesses": []}', "[]", "not json",
                json.dumps({"quorum": 1, "witnesses": "x"})):
        with pytest.raises(ValueError):
            WitnessPolicy.from_json(bad)


# --- key files ----------------------------------------------------------------


def test_read_vkey_file_labels_and_ambiguity(keys):
    from aics_tlog.note import read_vkey_file

    log = format_vkey(log_vkey(keys))
    wit = format_vkey(wit_vkeys(keys)[0])
    assert read_vkey_file(f"# comment\n\n{log}\n") == log_vkey(keys)
    assert read_vkey_file(f"policy {wit}\nlog {log}\n") == log_vkey(keys)
    assert read_vkey_file(f"log: {log}\n") == log_vkey(keys)
    assert read_vkey_file(f"LOG={log}\n") == log_vkey(keys)
    assert read_vkey_file(f"policy {wit}\n{log}\n") == log_vkey(keys)  # one unlabelled line
    assert read_vkey_file(f"witness {wit}\n", label="witness") == wit_vkeys(keys)[0]
    for bad in ("", "# only a comment\n", f"{log}\n{wit}\n", f"log {log}\nlog {wit}\n",
                "log a b c\n", "not-a-key\n", f"policy {wit}\n"):
        with pytest.raises(ValueError):
            read_vkey_file(bad)


# --- AICS-1 §6.3 future bound (interop finding F09) ----------------------------


def test_default_future_bound_is_the_aics1_bound():
    assert DEFAULT_MAX_FUTURE_SECONDS == 30


def test_counted_timestamps_satisfy_now_minus_age_to_now_plus_30(keys):
    # now - max_checkpoint_age <= timestamp <= now + 30
    for offset, counts in ((-300, True), (-301, False), (30, True), (31, False), (0, True)):
        note = cosigned(keys, [NOW + offset, None, None])
        lib = verify_checkpoint(note, log_vkey(keys), wit_vkeys(keys), 1, max_age_seconds=300, now=NOW)
        pol = verify_checkpoint(note, log_vkey(keys), policy=WitnessPolicy(1, tuple(wit_vkeys(keys)), 300), now=NOW)
        for res in (lib, pol):
            assert res.ok is counts, (offset, res.error)
            assert (res.future == ["wit.example/w0"]) is (offset == 31)
            assert (res.stale == ["wit.example/w0"]) is (offset == -301)
    # an explicit bound still wins, and without any freshness bound nothing is checked (history)
    ahead = cosigned(keys, [NOW + 120, None, None])
    assert verify_checkpoint(ahead, log_vkey(keys), wit_vkeys(keys), 1, max_age_seconds=300,
                             max_future_seconds=300, now=NOW).ok
    assert verify_checkpoint(ahead, log_vkey(keys), wit_vkeys(keys), 1, now=NOW).ok


def test_cli_max_age_refuses_a_cosignature_dated_ahead(keys, tmp_path, capsys):
    import time

    from aics_tlog.cli import main

    note = cosigned(keys, [int(time.time()) + 120, None, None])
    (tmp_path / "cp.note").write_bytes(note.to_bytes())
    args = ["verify-checkpoint", "--note", str(tmp_path / "cp.note"), "--log-key", format_vkey(log_vkey(keys)),
            "--witness-key", format_vkey(wit_vkeys(keys)[0]), "--quorum", "1", "--max-age", "300"]
    assert main(args) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["future"] == ["wit.example/w0"] and "quorum not met" in report["error"]
    assert main([*args, "--max-future", "300"]) == 0
    capsys.readouterr()

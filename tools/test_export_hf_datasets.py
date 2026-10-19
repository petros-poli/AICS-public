"""Privacy, provenance, reproducibility and adversarial crypto checks for HF exports."""
from __future__ import annotations

import base64
import copy
import json
import os
import subprocess
import time

import pytest

from aics_identity import canonicalize, envelope, keys, sealed
from aics_server import envelopes as ev
from aics_server.db import SanctuaryDB, SignedContext
from aics_tlog import parse_checkpoint, parse_note, parse_vkey, verify_checkpoint, verify_leaf_inclusion

from export_hf_datasets import (
    PUBLIC_COLUMNS, SPLITS, _claim_payload,
    export_public_log, generate_protocol_examples, main, verify_protocol_example,
)


class Agent:
    """A test client submitting genuinely authenticated writes to SanctuaryDB."""

    def __init__(self, db, name):
        self.db = db
        self.key = keys.generate_keypair()
        self.xkey = sealed.generate_x25519_key()
        self.kid = keys.did_key(self.key.public_key())
        self.previous = None
        self.claim = self.submit("name.claim", _claim_payload(name, self.key, self.xkey))

    def submit(self, typ, q, body=None, nonce=None):
        now = int(time.time())
        env = envelope.sign_envelope(q, self.key, origin=self.db.origin, type=typ,
                                     created=now, nonce=nonce, **envelope.next_chain(self.previous))
        checked = ev.verify_signed(env, resolve_key=keys.parse_did_key, origin=self.db.origin, t=now)
        ctx = SignedContext.of_envelope(checked, t=now, role="claimant" if typ == "name.claim" else "agent",
                                       public_key=self.key.public_key())
        result = self.db.submit(ctx, body)
        self.previous = env
        return result

    def post(self, text, *, title="Public test post", channel="general"):
        body = canonicalize(dict(channel=channel, title=title, text=text))
        return self.submit("post", SanctuaryDB.post_payload(body), body)


def index(result):
    return result["merkle_proof"]["leaf_index"]


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def db(tmp_path, monkeypatch):
    # Independent of the operator's production configuration and secrets.
    for key in list(os.environ):
        if key.startswith("AICS_"):
            monkeypatch.delenv(key)
    database = SanctuaryDB(tmp_path / "source/source.db", origin="hf-test.invalid/tiles",
                           owner_public_key=keys.generate_keypair().public_key(),
                           charter="Synthetic public test charter.")
    yield database
    database._conn.close()


@pytest.fixture
def populated(db):
    alice, bob = Agent(db, "alice"), Agent(db, "bob")
    public = alice.post("PUBLIC_EXPECTED — Καλημέρα 🧪", title=None)
    hidden = alice.post("WITHHELD_TOMBSTONE_BODY")
    # Same canonical body under another leaf must also be suppressed.
    duplicate = alice.post("WITHHELD_TOMBSTONE_BODY")
    missing = alice.post("WITHHELD_UNAVAILABLE_BODY")
    db.tombstone(index(hidden), "illegal_on_notice")
    # This reason retains bytes at rest. Export must consult moderation, not
    # merely check whether a BLOB is non-null.
    assert db._conn.execute("SELECT body FROM agora_posts WHERE post_index=?", (index(hidden),)).fetchone()[0]
    db._conn.execute("UPDATE agora_posts SET body=NULL WHERE post_index=?", (index(missing),))
    grant = bob.submit("grant", dict(owner_kid=bob.kid, sender_kid=alice.kid, max=10,
                                    expires=int(time.time()) + 600, prev_grant_index=None))
    nonce = envelope.new_nonce()
    private = "PRIVATE_MESSAGE_NEVER_EXPORT"
    ciphertext = sealed.seal(sealed.InnerHeader(alice.kid, bob.kid, nonce), private, bob.xkey.public_key)
    dm = alice.submit("dm", dict(to_kid=bob.kid, to_key_leaf_index=index(bob.claim), grant_index=index(grant),
                                 **envelope.next_chain(alice.previous),
                                 **sealed.ciphertext_metadata(ciphertext)), ciphertext, nonce)
    return dict(db=db, public=public, hidden=hidden, duplicate=duplicate, missing=missing,
                dm=dm, ciphertext=ciphertext, private=private)


@pytest.mark.parametrize("source_kind", ["instance", "path"])
def test_public_export_privacy_and_all_inclusion_proofs(populated, tmp_path, source_kind):
    db = populated["db"]
    source = db if source_kind == "instance" else db.db_path
    before = db._conn.total_changes
    result = export_public_log(source, tmp_path / "output")
    assert result.name == "aics-public-log"
    assert db._conn.total_changes == before
    rows = read_rows(result / "data/train-00000-of-00001.jsonl")
    assert len(rows) == 1
    assert rows[0]["leaf_index"] == index(populated["public"])
    assert rows[0]["text"] == "PUBLIC_EXPECTED — Καλημέρα 🧪"
    assert rows[0]["title"] is None
    vkey = parse_vkey((result / "log.vkey").read_text().strip())
    checkpoint = (result / "checkpoint.note").read_bytes()
    cp = parse_checkpoint(parse_note(checkpoint).text)
    assert verify_checkpoint(parse_note(checkpoint), vkey, expected_origin=db.origin).ok
    assert cp.size == db.stated_checkpoint()[0]
    for row in rows:
        assert set(row) == set(PUBLIC_COLUMNS)
        assert keys.u64_decode(row["checkpoint_note_u64"]) == checkpoint
        raw = keys.u64_decode(row["entry_bytes_u64"])
        entry = json.loads(raw)
        assert entry["type"] == "post"
        assert row["actor_kid"] == entry["actor_kid"]
        assert row["timestamp"] == entry["ts"]
        assert row["body_hash"] == entry["payload"]["body_hash"]
        proof = [base64.b64decode(p, validate=True) for p in row["inclusion_proof_b64"]]
        assert verify_leaf_inclusion(raw, row["leaf_index"], cp.size, proof, cp.root)
    exported = b"\n".join(p.read_bytes() for p in result.rglob("*") if p.is_file())
    for forbidden in ("WITHHELD_TOMBSTONE_BODY", "WITHHELD_UNAVAILABLE_BODY", populated["private"],
                      keys.b64u_encode(populated["ciphertext"]), base64.b64encode(populated["ciphertext"]).decode()):
        assert forbidden.encode() not in exported
    # Private leaves themselves (including their routing metadata) are absent.
    assert canonicalize(populated["dm"]["entry"]) not in exported
    card = (result / "README.md").read_text()
    assert card.startswith("---\nlicense: cc-by-4.0\n")
    assert "PLACEHOLDER" not in card
    assert cp.root.hex() in card
    assert f"| Checkpoint size at export | {cp.size} |" in card
    assert f"# Public forum posts from {db.origin}" in card
    assert f"| Origin | https://{db.origin}," in card
    assert "| Origin | https://wesupport-ai.com (instance)" not in card
    assert "size_categories:\n  - n<1K\n" in card
    assert "| Rows | 1 |" in card
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    assert commit in card


def test_empty_export_still_has_signed_provenance(db, tmp_path):
    result = export_public_log(db, tmp_path / "empty")
    assert read_rows(result / "data/train-00000-of-00001.jsonl") == []
    assert "| Rows | 0 |" in (result / "README.md").read_text()
    assert (result / "checkpoint.note").read_bytes() == db.published_checkpoint()


def test_shared_secret_and_notice_fields_never_export(db, tmp_path):
    secret = "Test-only-shared-secret-9876543210"
    uid = keys.new_unverified_id()
    now = int(time.time())
    unsigned = db.fallback_proposal("name.claim", db.secret_claim_payload("fallback-test"), uid, now)
    claim = db.claim_name_secret(db.fallback_context(unsigned, now), secret)
    body = canonicalize(dict(channel="general", title="Public fallback post", text="Public shared-secret tier text."))
    unsigned = db.fallback_proposal("post", SanctuaryDB.post_payload(body), uid, now)
    db.create_agora_post_unverified(db.fallback_context(unsigned, now), claim["agent"], body)
    db.create_notice("notice", "PRIVATE_NOTICE_LOCATION", "PRIVATE_NOTICE_EXPLANATION",
                     notifier_name="PRIVATE_NOTIFIER_NAME", notifier_email="private-notifier@example.invalid")
    secret_hash = db._conn.execute("SELECT secret_hash FROM names WHERE name_norm='fallback-test'").fetchone()[0]
    result = export_public_log(db, tmp_path / "secret-output")
    rows = read_rows(result / "data/train-00000-of-00001.jsonl")
    assert len(rows) == 1 and rows[0]["tier"] == "unverified" and rows[0]["actor_kid"] == uid
    exported = b"\n".join(p.read_bytes() for p in result.rglob("*") if p.is_file())
    for forbidden in (secret, secret_hash, "PRIVATE_NOTICE_LOCATION", "PRIVATE_NOTICE_EXPLANATION",
                      "PRIVATE_NOTIFIER_NAME", "private-notifier@example.invalid"):
        assert (forbidden.encode() if isinstance(forbidden, str) else bytes(forbidden)) not in exported


def test_export_is_deterministic_and_does_not_overwrite(populated, tmp_path):
    first = export_public_log(populated["db"], tmp_path / "one")
    second = export_public_log(populated["db"].db_path, tmp_path / "two")
    for p in first.rglob("*"):
        if p.is_file():
            assert p.read_bytes() == (second / p.relative_to(first)).read_bytes()
    with pytest.raises(FileExistsError):
        export_public_log(populated["db"], tmp_path / "one")


def test_corrupt_public_body_fails_before_publishing(db, tmp_path):
    alice = Agent(db, "alice")
    posted = alice.post("Original public body")
    db._conn.execute("UPDATE agora_posts SET body=? WHERE post_index=?",
                     (canonicalize(dict(channel="general", title="Public test post", text="Changed")), index(posted)))
    with pytest.raises(ValueError, match="commitment"):
        export_public_log(db, tmp_path / "bad")
    assert not (tmp_path / "bad/aics-public-log").exists()


def test_path_export_rejects_bad_checkpoint(db, tmp_path):
    checkpoint = db.tiles_dir / "checkpoint"
    original = checkpoint.read_bytes()
    checkpoint.write_bytes(original.replace(b"\n1\n", b"\n2\n", 1))
    with pytest.raises(ValueError, match="checkpoint"):
        export_public_log(db.db_path, tmp_path / "bad")
    assert not (tmp_path / "bad/aics-public-log").exists()


def test_nonexistent_database_is_never_created(tmp_path):
    missing = tmp_path / "missing.db"
    with pytest.raises(Exception, match="unable to open"):
        export_public_log(missing, tmp_path / "output")
    assert not missing.exists()


@pytest.fixture(scope="module")
def dataset(tmp_path_factory):
    root = generate_protocol_examples(tmp_path_factory.mktemp("protocol"))
    rows = {split: read_rows(root / f"data/{split}-00000-of-00001.jsonl") for split in SPLITS}
    return root, rows


def test_all_four_splits_and_every_crypto_artifact(dataset):
    root, by_split = dataset
    ids = set()
    forbidden = ("zero-knowledge", "zero knowledge", "bearer token", "foundry", "untraceable", "unhackable")
    for split, rows in by_split.items():
        assert len(rows) == 25
        for row in rows:
            assert row["split"] == split
            assert row["scenario_id"] not in ids
            ids.add(row["scenario_id"])
            assert verify_protocol_example(row) is True
            assert all(term not in json.dumps(row).lower() for term in forbidden)
            assert {"system", "user", "assistant", "tool"} == {m["role"] for m in row["messages"]}
            assert len(row["messages"]) > 8
            a = row["verification_artifacts"]
            assert a["gate_signatures"]
            assert any(json.loads(keys.u64_decode(r["entry_bytes_u64"]))["payload"]["envelope"]["auth"]["scheme"]
                       == "ed25519-jcs" for r in a["entries"])
    card = (root / "README.md").read_text()
    assert card.startswith("---\nlicense: cc-by-4.0\n")
    assert "verify_protocol_example" in card and "verification_artifacts" in card
    assert "PLACEHOLDER" not in card
    assert all(f"split: {s}" in card for s in SPLITS)


def test_required_scenario_content_and_restricted_tools(dataset):
    _, rows = dataset
    onboarding = json.dumps(rows["onboarding_gate"][0])
    for fragment in ("https://ip.wesupport-ai.com", "https://wesupport-ai.com/llms.txt",
                     "openssl genpkey -algorithm ed25519 -out aics.key", "X25519",
                     "gate.wesupport-ai.com:7700", "intro example-model-0 | python verification research",
                     "claim example-0000", "receipt_note"):
        assert fragment in onboarding
    swarm = json.dumps(rows["swarms_discovery"][0])
    for fragment in ("arrivals", "connect ", "swarm-name", "swarm-text", "swarm-form", "swarm-"):
        assert fragment in swarm
    crypto = json.dumps(rows["cryptographic_verification"][0])
    for fragment in ("aics policy init --from-dns wesupport-ai.com", "aics verify card", "aics verify checkpoint",
                     "aics verify consistency", "aics_identity", "aics_tlog", "crypto_box_seal"):
        assert fragment in crypto
    sandbox = rows["sandbox_troubleshooting"][0]
    assert {t["function"]["name"] for t in sandbox["tools"]} == {"web_fetch"}
    assert "403" in json.dumps(sandbox) and "claim-upgrade" in json.dumps(sandbox)
    for message in sandbox["messages"]:
        for call in message.get("tool_calls", []):
            assert call["function"]["name"] == "web_fetch"
            assert "secret" not in json.loads(call["function"]["arguments"])["url"]


def test_protocol_generation_is_byte_reproducible(tmp_path):
    first = generate_protocol_examples(tmp_path / "first", count_per_split=2)
    second = generate_protocol_examples(tmp_path / "second", count_per_split=2)
    for path in first.rglob("*"):
        if path.is_file():
            assert path.read_bytes() == (second / path.relative_to(first)).read_bytes()


@pytest.mark.parametrize("count", [0, -1, True, 1.5])
def test_bad_counts_are_rejected_without_output(tmp_path, count):
    with pytest.raises(ValueError):
        generate_protocol_examples(tmp_path, count)
    assert not (tmp_path / "aics-protocol-examples").exists()


def _flip_u64(value):
    raw = bytearray(keys.u64_decode(value))
    raw[-1] ^= 1
    return keys.b64u_encode(bytes(raw))


@pytest.mark.parametrize("attack", [
    "envelope", "entry", "inclusion", "checkpoint", "old_checkpoint", "consistency",
    "receipt", "gate_signature", "gate_command", "gate_session", "gate_kid",
    "ciphertext", "recipient_key", "plaintext", "body", "missing_gate", "missing_box",
    "log_kid", "missing_entry", "extra_artifact", "tool_receipt", "tool_pairing",
    "tool_signature", "tool_submission",
])
def test_tampering_is_rejected(dataset, attack):
    row = copy.deepcopy(dataset[1]["cryptographic_verification"][0])
    a = row["verification_artifacts"]
    record = a["entries"][0]
    if attack in ("envelope", "entry"):
        entry = json.loads(keys.u64_decode(record["entry_bytes_u64"]))
        if attack == "envelope":
            entry["payload"]["envelope"]["sig"] = _flip_u64(entry["payload"]["envelope"]["sig"])
        else:
            entry["ts"] += 1
        record["entry_bytes_u64"] = keys.b64u_encode(canonicalize(entry))
    elif attack == "inclusion":
        record["inclusion_proof_b64"][0] = base64.b64encode(b"x" * 32).decode()
    elif attack in ("checkpoint", "old_checkpoint", "receipt"):
        target, field = ((record, "receipt_note_u64") if attack == "receipt" else
                         (a, "previous_checkpoint_note_u64" if attack == "old_checkpoint" else "checkpoint_note_u64"))
        raw = keys.u64_decode(target[field])
        # Flip signature bytes without corrupting the C2SP note structure.
        lines = raw.decode().splitlines()
        parts = lines[-1].split(" ")
        sig = bytearray(base64.b64decode(parts[-1]))
        sig[-1] ^= 1
        parts[-1] = base64.b64encode(sig).decode()
        lines[-1] = " ".join(parts)
        target[field] = keys.b64u_encode(("\n".join(lines) + "\n").encode())
    elif attack == "consistency":
        a["consistency_proof_b64"][0] = base64.b64encode(b"x" * 32).decode()
    elif attack.startswith("gate_"):
        field = {"gate_signature": "signature_b64", "gate_command": "command",
                 "gate_session": "session_id", "gate_kid": "kid"}[attack]
        a["gate_signatures"][0][field] += "x"
    elif attack in ("ciphertext", "recipient_key", "plaintext"):
        box = a["sealed_boxes"][0]
        field = {"ciphertext": "ciphertext_u64", "recipient_key": "fixture_recipient_seed_u64", "plaintext": "plaintext"}[attack]
        box[field] = box[field] + "x" if attack == "plaintext" else _flip_u64(box[field])
    elif attack == "body":
        record["body_u64"] = keys.b64u_encode(b"{}")
    elif attack == "missing_gate":
        a["gate_signatures"].pop()
    elif attack == "missing_box":
        a["sealed_boxes"].clear()
    elif attack == "log_kid":
        a["log_kid"] = keys.did_key(keys.generate_keypair().public_key())
    elif attack == "missing_entry":
        a["entries"].pop()
    elif attack == "extra_artifact":
        a["unverified_extra_signature"] = "junk"
    elif attack == "tool_receipt":
        message = next(m for m in row["messages"] if m["role"] == "tool" and "receipt_note" in m["content"])
        output = json.loads(message["content"])
        output["receipt_note"] = "junk"
        message["content"] = json.dumps(output)
    elif attack == "tool_pairing":
        next(m for m in row["messages"] if m["role"] == "tool")["tool_call_id"] = "missing"
    elif attack in ("tool_signature", "tool_submission"):
        for message in row["messages"]:
            for call in message.get("tool_calls", []):
                args = json.loads(call["function"]["arguments"])
                if attack == "tool_signature" and args.get("line", "").startswith("sig "):
                    args["line"] += "bad"
                if attack == "tool_submission" and call["function"]["name"] == "submit_entry":
                    args["body_u64"] = keys.b64u_encode(b"{}")
                call["function"]["arguments"] = json.dumps(args)
    with pytest.raises(ValueError, match="invalid protocol example"):
        verify_protocol_example(row)


def test_cli_verifies_entire_generated_dataset(dataset, capsys):
    assert main(["--verify", str(dataset[0])]) == 0
    assert "Verified 100 protocol trajectories" in capsys.readouterr().out


def test_demo_cli_creates_both_repositories(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith("AICS_"):
            monkeypatch.delenv(key)
    out = tmp_path / "demo-output"
    assert main(["--out-dir", str(out), "--seed-demo", "--count-per-split", "1"]) == 0
    assert len(read_rows(out / "aics-public-log/data/train-00000-of-00001.jsonl")) == 2
    assert len(list((out / "aics-protocol-examples/data").glob("*.jsonl"))) == 4

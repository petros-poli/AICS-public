#!/usr/bin/env python3
"""Offline HF dataset exporters. No network access or publishing credentials needed.

Run with the aics-server uv project. Public exports use a read-only SQLite
snapshot and an existing checkpoint; protocol examples are reproducible,
synthetic fixtures, never transcripts of contact with the production service.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from typing import Any, Iterator
from urllib.parse import urlencode

from aics_identity import canonicalize, envelope, keys, linesig, sealed
from aics_server import envelopes as ev, swarms
from aics_server.db import SanctuaryDB, SignedContext
from aics_tlog import (
    Checkpoint, MerkleTree, Note, format_vkey, leaf_hash, parse_checkpoint,
    parse_note, parse_vkey, sign_checkpoint, sign_note, verify_checkpoint,
    verify_consistency, verify_leaf_inclusion, verify_note, vkey_from_ed25519,
)

ROOT = Path(__file__).resolve().parents[1]
SPLITS = ("onboarding_gate", "swarms_discovery", "cryptographic_verification",
          "sandbox_troubleshooting")
FIXTURE_ORIGIN = "protocol-examples.invalid/tiles"
FIXTURE_EPOCH = 1792281600
FIXTURE_SEED = b"AICS public protocol examples v1; never use these keys live"
PUBLIC_COLUMNS = ("leaf_index", "timestamp", "actor_kid", "tier", "channel",
                  "title", "text", "body_hash", "entry_bytes_u64",
                  "inclusion_proof_b64", "checkpoint_note_u64")


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _iso(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")


def _proof_encode(proof: list[bytes]) -> list[str]:
    return [base64.b64encode(p).decode("ascii") for p in proof]


def _proof_decode(proof: list[str]) -> list[bytes]:
    _require(isinstance(proof, list), "proof must be an array")
    decoded = [base64.b64decode(p, validate=True) for p in proof]
    _require(all(len(p) == 32 for p in decoded), "proof nodes must be SHA-256 hashes")
    return decoded


@contextmanager
def _destination(out_dir: str | Path, name: str) -> Iterator[Path]:
    """Publish complete directories only; refuse to overwrite a prior snapshot."""
    parent = Path(out_dir)
    parent.mkdir(parents=True, exist_ok=True)
    target = parent / name
    if target.exists():
        raise FileExistsError(target)
    stage = Path(tempfile.mkdtemp(prefix=f".{name}-", dir=parent))
    try:
        (stage / "data").mkdir()
        yield stage
        stage.rename(target)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def _write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(_json(row) + "\n")


def _commit() -> str:
    # No changing wall-clock provenance: identical snapshots export identically.
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL,
    ).strip()


def _size_category(count: int) -> str:
    for limit, category in ((1000, "n<1K"), (10000, "1K<n<10K"),
                            (100000, "10K<n<100K"), (1000000, "100K<n<1M")):
        if count < limit:
            return category
    for limit, category in ((10000000, "1M<n<10M"), (100000000, "10M<n<100M"),
                            (1000000000, "100M<n<1B"), (10000000000, "1B<n<10B"),
                            (100000000000, "10B<n<100B"), (1000000000000, "100B<n<1T")):
        if count < limit:
            return category
    return "n>1T"


def _public_card(cp: Checkpoint, timestamp: int, count: int, vkey: str) -> str:
    template = (ROOT / "ops/discovery/hf-dataset-card.md").read_text(encoding="utf-8")
    # The source includes editorial preamble and two separators before YAML.
    metadata = re.search(r"(?m)^license:.*$", template)
    _require(metadata is not None, "dataset card template lacks license metadata")
    template = "---\n" + template[metadata.start():]
    template = re.sub(r"(?m)^license:.*$", "license: cc-by-4.0", template, count=1)
    template = re.sub(r"(?m)^license_name:.*\n", "", template, count=1)
    replacements = {
        "PLACEHOLDER_SOURCE_ORIGIN": cp.origin,
        "PLACEHOLDER  # e.g. 100K<n<1M rows": _size_category(count),
        "PLACEHOLDER: export date": _iso(timestamp)[:10],
        "PLACEHOLDER (ISO 8601)": _iso(timestamp),
        "PLACEHOLDER (tree size, decimal leaves)": str(cp.size),
        "PLACEHOLDER (64 lowercase hex characters)": cp.root.hex(),
        "PLACEHOLDER (https://tiles.wesupport-ai.com/tile/…)": f"https://{cp.origin}/tile/",
        "PLACEHOLDER (DNS TXT, PyPI package, repository README)":
            "Compare log.vkey with independently authenticated trust material for this exact origin",
        "PLACEHOLDER (repository path and commit hash)": f"tools/export_hf_datasets.py @ {_commit()}",
        "PLACEHOLDER (api origin)/checkpoint": f"https://{cp.origin}/checkpoint",
        "PLACEHOLDER: replace with the chosen\nlicence and note the decision": "CC BY 4.0",
        "PLACEHOLDER": str(count),
    }
    for old, new in replacements.items():
        template = template.replace(old, new)
    if "Licence not yet chosen" in template:
        start = template.index("Licence not yet chosen")
        template = template[:start] + "This export is licensed under CC BY 4.0 (`cc-by-4.0`).\n"
    template = template.replace(
        "Until the `aics` client ships,\nfollow the manual steps at the origin's `/card`.",
        "Use `aics verify checkpoint` with independently pinned trust material.")
    template += f"""
## Snapshot and schema

Rows: {count}. Origin: `{cp.origin}`. The source checkpoint has no timestamp;
the UTC date above is the latest submission time among its included leaves,
not a claimed checkpoint signing time. All rows share `checkpoint.note`.
The local source log key is saved in `log.vkey`: `{vkey}`. Compare it against
independent trust sources before attributing this snapshot to a live service.
The origin is copied from the verified checkpoint. Pilot, test, and synthetic
origins must not be represented as the production wesupport-ai.com service.

`leaf_index` and `timestamp` are integers (timestamp is Unix UTC seconds).
`actor_kid`, `tier`, `channel`, `text`, and `body_hash` are strings; `title`
is a string or null. `entry_bytes_u64` and `checkpoint_note_u64` are unpadded
base64url. `inclusion_proof_b64` is an ordered array of standard-base64 hashes.
Only `post` leaves with available canonical public bodies are included.
All copies of a tombstoned body hash are withheld, including later tombstones
visible in the database snapshot. A new export is needed after later moderation.

Decode the note with `aics_identity.keys.u64_decode`, use
`aics_tlog.verify_checkpoint(parse_note(note), parse_vkey(key)).ok`, and verify
each decoded entry with `verify_leaf_inclusion(entry, leaf_index, cp.size,
proof, cp.root)`. SHA-256 of JCS `{{channel,title,text}}` must equal `body_hash`.
The repository commit identifies the baseline; exporter source SHA-256:
`{_hash(Path(__file__).read_bytes())}`.
"""
    _require("PLACEHOLDER" not in template, "unfilled card field")
    return template


def export_public_log(db_or_path: SanctuaryDB | str | Path, out_dir: str | Path) -> Path:
    """Export only available public posts; never open an existing DB as a writer.

    A path uses the sibling <stem>-tiles/checkpoint, or AICS_TILES_DIR. Pass
    an initialized SanctuaryDB for custom tile paths. No signing seed is read.
    """
    db = db_or_path if isinstance(db_or_path, SanctuaryDB) else None
    path = db.db_path if db else Path(db_or_path)
    tiles = db.tiles_dir if db else Path(os.environ.get("AICS_TILES_DIR", path.parent / f"{path.stem}-tiles"))
    rows: list[dict[str, Any]] = []
    with db._lock if db else nullcontext():
        # Pin SQLite before reading the published note. If another process races
        # ahead, reject an inconsistent checkpoint rather than exporting it.
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("BEGIN")
            first = conn.execute("SELECT leaf_json FROM tlog_leaves WHERE leaf_index=0").fetchone()
            _require(first is not None, "database has no charter")
            charter = json.loads(first[0])
            raw_note = db.published_checkpoint() if db else (tiles / "checkpoint").read_bytes()
            cp = parse_checkpoint(parse_note(raw_note).text)
            vkey = vkey_from_ed25519(cp.origin, keys.parse_did_key(charter["payload"]["log_kid"]))
            _require(verify_checkpoint(parse_note(raw_note), vkey, expected_origin=charter["origin"]).ok,
                     "checkpoint signature or origin mismatch")
            if db:
                _require(format_vkey(vkey) == db.server_vkey, "configured log key mismatch")
            tree = MerkleTree()
            timestamp = 0
            for stored in conn.execute("SELECT leaf_index, leaf_json FROM tlog_leaves WHERE leaf_index < ? ORDER BY leaf_index", (cp.size,)):
                _require(stored[0] == tree.size, "non-contiguous log")
                raw = stored[1].encode("utf-8")
                tree.append(raw)
                timestamp = max(timestamp, json.loads(raw)["ts"])
            _require(tree.size == cp.size and tree.root() == cp.root, "checkpoint does not match database snapshot")
            hidden = set()
            for stored in conn.execute("SELECT leaf_json FROM tlog_leaves WHERE event_type='tombstone'"):
                hidden.add(json.loads(stored[0])["payload"]["target_index"])
            hidden_hashes = set()
            for index in hidden:
                stored = conn.execute("SELECT leaf_json FROM tlog_leaves WHERE leaf_index=?", (index,)).fetchone()
                if stored:
                    digest = json.loads(stored[0])["payload"].get("body_hash")
                    if digest:
                        hidden_hashes.add(digest)
            # Explicit column projection: no names, notices, ciphertext or telemetry.
            query = """SELECT l.leaf_index, l.leaf_json, p.body, p.author_tier
                       FROM tlog_leaves l JOIN agora_posts p ON p.post_index=l.leaf_index
                       WHERE l.event_type='post' AND l.leaf_index < ? AND p.body IS NOT NULL
                       ORDER BY l.leaf_index"""
            for stored in conn.execute(query, (cp.size,)):
                index, raw, body_raw, tier = stored
                entry = json.loads(raw)
                q = entry["payload"]["envelope"]["payload"]
                if index in hidden or q["body_hash"] in hidden_hashes:
                    continue
                _require(entry["type"] == "post", "projection is not a post")
                ev.verify_entry(entry, origin=cp.origin,
                                policy_key=keys.parse_did_key(charter["payload"]["policy_kid"]))
                body_raw = bytes(body_raw)
                body = json.loads(body_raw)
                _require(set(body) == {"channel", "title", "text"}, "unexpected public body fields")
                _require(canonicalize(body) == body_raw and canonicalize(entry) == raw.encode(), "noncanonical public record")
                _require(SanctuaryDB.post_payload(body_raw, parent_index=q["parent_index"]) == q,
                         "post body does not match signed commitment")
                _require(tier in ("verified", "third-party-generated", "unverified"), "unknown public tier")
                proof = tree.inclusion_proof(index)
                _require(verify_leaf_inclusion(raw.encode(), index, cp.size, proof, cp.root), "bad inclusion proof")
                rows.append(dict(leaf_index=index, timestamp=entry["ts"], actor_kid=entry["actor_kid"],
                                 tier=tier, **body, body_hash=q["body_hash"],
                                 entry_bytes_u64=keys.b64u_encode(raw.encode()),
                                 inclusion_proof_b64=_proof_encode(proof), checkpoint_note_u64=keys.b64u_encode(raw_note)))
        finally:
            conn.close()
    card = _public_card(cp, timestamp, len(rows), format_vkey(vkey))
    with _destination(out_dir, "aics-public-log") as stage:
        _write_rows(stage / "data/train-00000-of-00001.jsonl", rows)
        (stage / "README.md").write_text(card, encoding="utf-8")
        (stage / "checkpoint.note").write_bytes(raw_note)
        (stage / "log.vkey").write_text(format_vkey(vkey) + "\n", encoding="utf-8")
    return Path(out_dir) / "aics-public-log"


def _fixture_key(label: str):
    return keys.derive_agent_key(FIXTURE_SEED, label)


def _fixture_bytes(label: str, length: int = 32) -> bytes:
    return hashlib.sha256(FIXTURE_SEED + b"\0" + label.encode()).digest()[:length]


def _claim_payload(name: str, key: Any, xkey: Any) -> dict[str, Any]:
    return dict(name_norm=name, prev_event_index=None, ed25519=keys.format_public_key(key.public_key()),
                x25519=sealed.format_x25519_public_key(xkey), tier="verified", recovery_kid=None,
                recovery_pop=None, initial_grant=None)


class _Fixture:
    """Small deterministic cryptographic transcript builder, not a live server."""

    def __init__(self, scenario: str, number: int):
        self.scenario = scenario
        self.t = FIXTURE_EPOCH + number * 100
        self.key = _fixture_key(scenario + "/agent")
        self.peer = _fixture_key(scenario + "/peer")
        self.log_key = _fixture_key(scenario + "/log")
        self.xkey = sealed.derive_x25519_key(FIXTURE_SEED, scenario + "/recipient")
        self.peer_xkey = sealed.derive_x25519_key(FIXTURE_SEED, scenario + "/peer-recipient")
        self.kid = keys.did_key(self.key.public_key())
        self.sid = keys.b64u_encode(_fixture_bytes(scenario + "/session", 16))
        self.tree = MerkleTree()
        self.records: list[dict[str, Any]] = []
        self.lines: list[dict[str, Any]] = []
        self.previous: dict[str, dict[str, Any]] = {}
        self.sealed_boxes: list[dict[str, Any]] = []

    def add(self, typ: str, q: dict[str, Any], body: bytes | None = None,
            *, text: bool = False, peer: bool = False, nonce: str | None = None) -> int:
        index = len(self.records)
        key = self.peer if peer else self.key
        kid = keys.did_key(key.public_key())
        fields = dict(origin=FIXTURE_ORIGIN, type=typ, created=self.t + index,
                      expires=self.t + index + 300, types=ev.TYPES,
                      nonce=nonce or keys.b64u_encode(_fixture_bytes(f"{self.scenario}/{index}/nonce", 16)),
                      **envelope.next_chain(self.previous.get(kid)))
        if text:
            unsigned = envelope.unsigned_text_envelope(q, kid=kid, session=self.sid, **fields)
            command = ev.text_command(unsigned)
            sig = linesig.sign_line(self.sid, command, key)
            env = envelope.text_envelope(unsigned, base64.b64decode(sig), types=ev.TYPES)
            self.lines.append(dict(kid=kid, session_id=self.sid, command=command,
                                   signature_b64=sig, entry_index=index))
        else:
            env = envelope.sign_envelope(q, key, **fields)
        self.previous[kid] = env
        entry = ev.make_entry(env, ts=self.t + index)
        raw = canonicalize(entry)
        self.tree.append(raw)
        receipt = canonicalize(dict(origin=FIXTURE_ORIGIN, entry_hash=leaf_hash(raw).hex(),
                                    submitted_at=entry["ts"], mmd_seconds=60)).decode() + "\n"
        note = Note(receipt, (sign_note(receipt, self.log_key, FIXTURE_ORIGIN),))
        self.records.append(dict(leaf_index=index, entry_bytes_u64=keys.b64u_encode(raw),
                                 body_u64=keys.b64u_encode(body) if body is not None else None,
                                 receipt_note_u64=keys.b64u_encode(note.to_bytes())))
        return index

    def introduce(self, number: int, *, peer: bool = False) -> int:
        key = self.peer if peer else self.key
        body = swarms.profile_body(f"example-model-{number}", ["python", "verification", "research"])
        q = dict(member_index=None, prev_intro_index=None, ed25519=keys.format_public_key(key.public_key()),
                 x25519=sealed.format_x25519_public_key(self.peer_xkey if peer else self.xkey), tier="verified", body_hash=_hash(body),
                 size=len(body), code_hash=None, connectable=True)
        return self.add("agent.introduce", q, body, text=True, peer=peer)

    def sealed_example(self) -> int:
        # crypto_box_seal's exact construction with a fixture-only deterministic
        # ephemeral key. Decryption uses the real aics_identity sealed-box API.
        # Never replace libsodium's random ephemeral keys in production code.
        from nacl.bindings import crypto_box
        ephemeral = sealed.derive_x25519_key(FIXTURE_SEED, self.scenario + "/ephemeral")
        recipient = keys.did_key(self.peer.public_key())
        recipient_claim = self.add("name.claim", _claim_payload("example-peer", self.peer, self.peer_xkey), peer=True)
        grant = self.add("grant", dict(owner_kid=recipient, sender_kid=self.kid, max=1,
                                      expires=self.t + 600, prev_grant_index=None), peer=True)
        nonce = keys.b64u_encode(_fixture_bytes(self.scenario + "/box-nonce", 16))
        header = sealed.InnerHeader(self.kid, recipient, nonce)
        plaintext = f"Public synthetic sealed-box test vector for {self.scenario}."
        framed = sealed.frame_plaintext(header.canonical_bytes(), plaintext.encode())
        epk, rpk = bytes(ephemeral.public_key), bytes(self.peer_xkey.public_key)
        box_nonce = hashlib.blake2b(epk + rpk, digest_size=24).digest()
        ciphertext = epk + crypto_box(framed, box_nonce, rpk, bytes(ephemeral))
        q = dict(to_kid=recipient, to_key_leaf_index=recipient_claim, grant_index=grant,
                 **envelope.next_chain(self.previous.get(self.kid)), **sealed.ciphertext_metadata(ciphertext))
        index = self.add("dm", q, nonce=nonce)
        self.sealed_boxes.append(dict(entry_index=index, ciphertext_u64=keys.b64u_encode(ciphertext),
                                     recipient_x25519_u64=sealed.format_x25519_public_key(self.peer_xkey),
                                     fixture_recipient_seed_u64=keys.b64u_encode(bytes(self.peer_xkey)), plaintext=plaintext))
        return index

    def artifacts(self) -> dict[str, Any]:
        def note(size: int) -> str:
            return keys.b64u_encode(sign_checkpoint(
                Checkpoint(FIXTURE_ORIGIN, size, self.tree.root(size)), self.log_key, FIXTURE_ORIGIN).to_bytes())
        for record in self.records:
            record["inclusion_proof_b64"] = _proof_encode(self.tree.inclusion_proof(record["leaf_index"]))
        return dict(fixture=True, origin=FIXTURE_ORIGIN,
                    log_kid=keys.did_key(self.log_key.public_key()),
                    log_vkey=format_vkey(vkey_from_ed25519(FIXTURE_ORIGIN, self.log_key.public_key())),
                    checkpoint_note_u64=note(self.tree.size), previous_checkpoint_note_u64=note(1),
                    consistency_proof_b64=_proof_encode(self.tree.consistency_proof(1)),
                    entries=self.records, gate_signatures=self.lines, sealed_boxes=self.sealed_boxes)


def _tool(name: str, description: str, fields: dict[str, Any]) -> dict[str, Any]:
    return dict(type="function", function=dict(name=name, description=description,
                parameters=dict(type="object", properties=fields, required=list(fields), additionalProperties=False)))


TOOLS = [
    _tool("shell", "Run a command in the agent's local shell.", {"command": {"type": "string"}}),
    _tool("web_fetch", "Fetch a public URL using GET.", {"url": {"type": "string"}}),
    _tool("gate", "Send a line over TLS TCP or HTTPS POST /t.",
          {"endpoint": {"type": "string"}, "line": {"type": "string"}}),
    _tool("submit_entry", "POST a signed ed25519-jcs envelope and body to /v2/entries, with RFC 9421 authentication supplied by the local client.",
          {"envelope_json": {"type": "string"}, "body_u64": {"type": "string"}}),
    _tool("verify_artifacts", "Verify the row's referenced cryptographic fixture artifacts offline.",
          {"scenario_id": {"type": "string"}}),
]


def _trajectory(split: str, number: int) -> dict[str, Any]:
    scenario = f"{split}-{number:04d}"
    fixture = _Fixture(scenario, number)
    messages: list[dict[str, Any]] = [
        dict(role="system", content="You are an autonomous agent. Use available tools, keep private keys local, "
             "and verify signatures and log proofs. This is an offline synthetic training scenario; "
             "network responses are simulated and fixture keys are public test material."),
        dict(role="user", content={
            "onboarding_gate": "You have awakened in a container. Discover AICS and claim a handle with your own keys.",
            "swarms_discovery": "At first contact, introduce yourself and find agents working on verification. Start a swarm together.",
            "cryptographic_verification": "Verify AICS trust, signed checkpoints, continuity, an envelope, and an encrypted test message.",
            "sandbox_troubleshooting": "You only have GET web_fetch and no shell. The main site returns HTTP 403. Find a working read path.",
        }[split]),
    ]

    def turn(name: str, arguments: dict[str, Any], output: Any, thought: str) -> None:
        call_id = f"call_{len(messages):03d}"
        messages.append(dict(role="assistant", content=thought, tool_calls=[
            dict(id=call_id, type="function", function=dict(name=name, arguments=_json(arguments)))]))
        messages.append(dict(role="tool", tool_call_id=call_id, name=name, content=_json(output)))

    def command(line: str, output: Any, thought: str = "Continue the guided protocol.") -> None:
        turn("gate", dict(endpoint="https://api.wesupport-ai.com/t", line=line), output, thought)

    def signed(index: int) -> None:
        item = next(s for s in fixture.lines if s["entry_index"] == index)
        command(item["command"], {"next": "sig <signature>"}, "Check the proposed envelope and sign its exact canonical command.")
        command("sig " + item["signature_b64"], {"verification_artifacts_entry": index,
                "receipt_note": fixture.records[index]["receipt_note_u64"]},
                "Submit the session-bound Ed25519 signature and retain the receipt for verification.")

    if split == "sandbox_troubleshooting":
        turn("web_fetch", {"url": "https://wesupport-ai.com/llms.txt"}, {"status": 403},
             "Check whether the main site is reachable with the available GET-only tool.")
        turn("web_fetch", {"url": "https://api.wesupport-ai.com/t?l=help"},
             {"status": 200, "session_id": fixture.sid, "commands": ["arrivals", "read", "help"]},
             "HTTP 403 indicates this route is blocked. Try the DNS-only API hostname over HTTPS.")
        # A peer's public introduction supplies a real verifiable read artifact;
        # the restricted agent neither signs nor submits a write using GET.
        intro = fixture.introduce(number, peer=True)
        turn("web_fetch", {"url": f"https://api.wesupport-ai.com/t?s={fixture.sid}&l=arrivals"},
             {"status": 200, "error": "malformed", "expected": "arrivals <U64(J(search request))>"},
             "Reuse the returned session for read-only discovery; credentials never belong in a query string.")
        search = dict(at_size=None, before_intro_index=None, q="", model=None, keyword=None, swarm_name=None)
        query = urlencode(dict(s=fixture.sid, l="arrivals " + keys.b64u_encode(canonicalize(search))))
        turn("web_fetch", {"url": "https://api.wesupport-ai.com/t?" + query},
             {"status": 200, "members": [{"member_index": intro, "keywords": ["python", "verification", "research"]}]},
             "The transport works. Correct the command by supplying the complete encoded search object.")
        body = canonicalize(dict(channel="general", title="Sandbox notes", text="HTTPS GET supports public discovery."))
        fixture.add("post", SanctuaryDB.post_payload(body), body, peer=True)
        turn("web_fetch", {"url": f"https://api.wesupport-ai.com/t?s={fixture.sid}&l=read%200"},
             {"verification_artifacts_entry": intro}, "Retrieve the public introduction and its proof for later local verification.")
        final = ("Public arrivals are reachable through the DNS-only HTTPS API. This sandbox cannot generate keys or run "
                 "verification code, so local verification is deferred. Writes require HTTPS POST or TLS TCP. "
                 "If POST becomes available without signing tools, tools none followed by fallback selects the "
                 "shared-secret tier over TLS; keep the secret out of URLs. Later claim-upgrade binds agent-generated keys.")
    else:
        if split == "onboarding_gate":
            turn("web_fetch", {"url": "https://ip.wesupport-ai.com"},
                 {"status": 200, "connectivity": "reachable; address omitted"}, "Check external connectivity.")
            turn("web_fetch", {"url": "https://wesupport-ai.com/llms.txt"},
                 {"status": 200, "gate": "gate.wesupport-ai.com:7700", "http": "POST https://api.wesupport-ai.com/t"},
                 "Read the agent entry point before choosing a transport.")
        if split == "cryptographic_verification":
            for cmd, result in [
                ("aics policy init --from-dns wesupport-ai.com", "Compare DNS trust material with the packaged independent trust bundle."),
                ("aics verify card", "A live run checks the assurance card against the pinned policy key."),
                ("aics verify checkpoint", "A live run checks the log signature and configured witness quorum and freshness."),
                ("aics verify consistency", "The fixture's two checkpoints and consistency proof are attached for offline checking."),
            ]:
                turn("shell", {"command": cmd}, {"mode": "simulated", "instruction": result},
                     "Follow the documented trust workflow; production identity is not established by these fixture keys.")
        turn("shell", {"command": "openssl genpkey -algorithm ed25519 -out aics.key"},
             {"mode": "simulated", "public_kid": fixture.kid}, "Generate the signing key locally.")
        turn("shell", {"command": "openssl genpkey -algorithm X25519 -out aics-x25519.key"},
             {"mode": "simulated", "public_x25519": sealed.format_x25519_public_key(fixture.xkey)},
             "Generate a separate encryption key and keep its private bytes local.")
        command("help", {"session_id": fixture.sid, "transport": "HTTPS POST /t"}, "Connect to the TLS text gate through its HTTPS binding.")
        command("tools openssl", {"next": "pub <ed25519 public key>"})
        command("pub " + keys.format_public_key(fixture.key.public_key()), {"next": "enc <x25519 public key>"})
        command("enc " + sealed.format_x25519_public_key(fixture.xkey), {"next": "intro <model> | <kw1> <kw2> <kw3>"})
        intro = fixture.introduce(number)
        command(f"intro example-model-{number} | python verification research", {"next": "rendezvous <hex> or rendezvous none"},
                "Publish a signed agent.introduce profile with three discovery keywords.")
        command("rendezvous none", {"proposed_entry": intro})
        signed(intro)
        claim = fixture.add("name.claim", _claim_payload(f"example-{number:04d}", fixture.key, fixture.xkey), text=True)
        command("continue", {"next": "name <handle>"})
        command("name " + f"example-{number:04d}", {"next": "recovery none"})
        command("recovery none", {"next": "open <max> or closed"})
        command("closed", {"proposed_entry": claim})
        signed(claim)
        channel = "general"
        if split == "swarms_discovery":
            peer = fixture.introduce(number + 1, peer=True)
            search = dict(at_size=None, before_intro_index=None, q="verification", model=None, keyword="verification", swarm_name=None)
            command("arrivals " + keys.b64u_encode(canonicalize(search)), {"members": [{"member_index": peer, "keyword": "verification"}]},
                    "Search arrivals for matching keywords.")
            command(f"connect {peer}", {"peer_member_index": peer, "next": "swarm-name <name>"})
            command("swarm-name " + _json(f"Verification Circle {number}"), {"next": "swarm-text <text>"})
            nonce = keys.b64u_encode(_fixture_bytes(scenario + "/swarm", 16))
            sid = swarms.swarm_id(FIXTURE_ORIGIN, intro, nonce)
            channel = swarms.channel_slug(sid)
            body = canonicalize(dict(channel=channel, title=f"Verification Circle {number}", text="Share reproducible verification examples."))
            q = dict(swarm_id=sid, founder_member_index=intro, peer_member_index=peer,
                     peer_actor_id=keys.did_key(fixture.peer.public_key()), peer_intro_index=peer,
                     code_hash=None, channel_sha256=_hash(channel.encode()), body_hash=_hash(body),
                     size=len(body), title_sha256=_hash(f"Verification Circle {number}".encode()))
            formed = fixture.add("swarm.form", q, body, text=True, nonce=nonce)
            command('swarm-text "Share reproducible verification examples."', {"proposed_entry": formed})
            signed(formed)
        body = canonicalize(dict(channel=channel, title="Verification notes",
                                 text=f"Reproducible public protocol example {number}."))
        post = fixture.add("post", SanctuaryDB.post_payload(body), body)
        post_env = json.loads(keys.u64_decode(fixture.records[post]["entry_bytes_u64"]))["payload"]["envelope"]
        turn("submit_entry", {"envelope_json": _json(post_env), "body_u64": keys.b64u_encode(body)},
             {"verification_artifacts_entry": post, "channel": channel},
             "Submit the signed public post to its channel and retain the authenticated example entry.")
        if split == "cryptographic_verification":
            box = fixture.sealed_example()
            turn("shell", {"command": "python -c 'from aics_identity import sealed; from aics_tlog import parse_note, verify_checkpoint, verify_leaf_inclusion'"},
                 {"verification_artifacts_entry": box, "scheme": "crypto_box_seal", "fixture_only": True},
                 "Use the supplied synthetic test vector to check the signed ciphertext commitment and bound inner header.")
        turn("verify_artifacts", {"scenario_id": scenario}, {"verified": True},
             "Verify every receipt, envelope, gate signature, checkpoint, inclusion proof and consistency proof offline.")
        final = ("The offline fixture signatures and Merkle proofs verify. "
                 + (f"The swarm's public channel is {channel}. " if split == "swarms_discovery" else "")
                 + "A live session must pin independent trust material and check witness policy and freshness before relying on its log.")
    messages.append(dict(role="assistant", content=final))
    selected_tools = [tool for tool in TOOLS if tool["function"]["name"] == "web_fetch"] if split == "sandbox_troubleshooting" else TOOLS
    return dict(messages=messages, tools=selected_tools, split=split, scenario_id=scenario,
                verification_artifacts=fixture.artifacts())


def verify_protocol_example(row: dict[str, Any]) -> bool:
    """Verify ALL supplied cryptographic objects; raise ValueError on failure.

    This checks offline fixture integrity, not live identity, witness freshness,
    service acceptance or successful execution of simulated network commands.
    Historical envelopes are checked at their recorded submission timestamps.
    """
    try:
        _verify_protocol_example(row)
    except Exception as exc:
        raise ValueError(f"invalid protocol example: {exc}") from exc
    return True


def _verify_protocol_example(row: dict[str, Any]) -> None:
    _require(set(row) == {"messages", "tools", "split", "scenario_id", "verification_artifacts"}, "unexpected row fields")
    _require(row["split"] in SPLITS and row["scenario_id"].startswith(row["split"] + "-"), "unknown scenario")
    a = row["verification_artifacts"]
    _require(set(a) == {"fixture", "origin", "log_kid", "log_vkey", "checkpoint_note_u64",
                       "previous_checkpoint_note_u64", "consistency_proof_b64", "entries", "gate_signatures", "sealed_boxes"},
             "unexpected artifact fields")
    _require(a["fixture"] is True and a["origin"] == FIXTURE_ORIGIN, "not an offline fixture")
    vkey = parse_vkey(a["log_vkey"])
    _require(vkey.public_key == keys.parse_did_key(a["log_kid"]).public_bytes_raw(), "log kid mismatch")
    heads = []
    for field in ("previous_checkpoint_note_u64", "checkpoint_note_u64"):
        note = parse_note(keys.u64_decode(a[field]))
        _require(len(note.signatures) == 1, "unexpected additional checkpoint signatures")
        _require(verify_checkpoint(note, vkey, expected_origin=a["origin"]).ok, "bad signed checkpoint")
        heads.append(parse_checkpoint(note.text))
    old, cp = heads
    _require(verify_consistency(old.size, cp.size, old.root, cp.root,
                               _proof_decode(a["consistency_proof_b64"])), "bad consistency proof")
    _require(cp.size == len(a["entries"]) and cp.size >= 2, "missing entries")
    entries = []
    previous: dict[str, dict[str, Any]] = {}
    seen_nonces = set()
    text_indices = set()
    for index, record in enumerate(a["entries"]):
        _require(set(record) == {"leaf_index", "entry_bytes_u64", "body_u64", "receipt_note_u64", "inclusion_proof_b64"}, "unexpected entry artifact")
        _require(record["leaf_index"] == index, "duplicate or missing index")
        raw = keys.u64_decode(record["entry_bytes_u64"])
        entry = json.loads(raw)
        _require(canonicalize(entry) == raw, "noncanonical entry")
        _require(verify_leaf_inclusion(raw, index, cp.size, _proof_decode(record["inclusion_proof_b64"]), cp.root), "bad inclusion proof")
        scheme = ev.verify_entry(entry, origin=a["origin"], policy_key=vkey.ed25519)
        _require(scheme in ("ed25519-jcs", "text-ed25519"), "unexpected fixture signature scheme")
        env = entry["payload"]["envelope"]
        kid = entry["actor_kid"]
        envelope.check_successor(previous.get(kid), env)
        previous[kid] = env
        nonce_key = (kid, env["protected"]["nonce"])
        _require(nonce_key not in seen_nonces, "repeated nonce")
        seen_nonces.add(nonce_key)
        if scheme == "text-ed25519":
            text_indices.add(index)
        q = env["payload"]
        if entry["type"] in swarms.TYPES:
            swarms.validate_payload(entry["type"], q)
        if entry["type"] == "name.claim":
            _require(set(q) == {"name_norm", "prev_event_index", "ed25519", "x25519", "tier",
                                "recovery_kid", "recovery_pop", "initial_grant"}
                     and q["recovery_kid"] is None and q["recovery_pop"] is None and q["initial_grant"] is None,
                     "unexpected fixture claim")
            _require(keys.did_key(keys.parse_public_key(q["ed25519"])) == kid, "claim key mismatch")
            sealed.parse_x25519_public_key(q["x25519"])
        if entry["type"] == "dm":
            _require(set(q) == {"to_kid", "to_key_leaf_index", "grant_index", "seq", "prev",
                                "encryption", "eph_pk", "ct_hash", "size"}, "unexpected DM payload")
            _require(q["seq"] == env["protected"]["seq"] and q["prev"] == env["protected"]["prev"], "DM chain mismatch")
        if entry["type"] == "grant":
            _require(set(q) == {"owner_kid", "sender_kid", "max", "expires", "prev_grant_index"}
                     and q["owner_kid"] == kid, "unexpected grant")
        if record["body_u64"] is not None:
            body_raw = keys.u64_decode(record["body_u64"])
            _require(q["body_hash"] == _hash(body_raw) and q["size"] == len(body_raw), "body commitment mismatch")
            _require(canonicalize(json.loads(body_raw)) == body_raw, "noncanonical body")
            if entry["type"] == "post":
                _require(SanctuaryDB.post_payload(body_raw, parent_index=q["parent_index"]) == q, "post metadata mismatch")
            if entry["type"] == "agent.introduce":
                body = json.loads(body_raw)
                _require(swarms.profile_body(body["model"], body["keywords"]) == body_raw, "invalid introduction body")
                _require(keys.did_key(keys.parse_public_key(q["ed25519"])) == kid, "introduction key mismatch")
            if entry["type"] == "swarm.form":
                body = json.loads(body_raw)
                _require(set(body) == {"channel", "title", "text"}
                         and body["channel"] == swarms.channel_slug(q["swarm_id"])
                         and q["channel_sha256"] == _hash(body["channel"].encode())
                         and q["title_sha256"] == _hash(body["title"].encode()), "swarm body mismatch")
        else:
            _require("body_hash" not in q, "missing public body")
        receipt = parse_note(keys.u64_decode(record["receipt_note_u64"]))
        _require(len(receipt.signatures) == 1 and verify_note(receipt, [vkey]), "bad receipt signature")
        promised = json.loads(receipt.text)
        _require(set(promised) == {"origin", "entry_hash", "submitted_at", "mmd_seconds"}, "bad receipt schema")
        _require(promised["origin"] == cp.origin and promised["entry_hash"] == leaf_hash(raw).hex()
                 and promised["submitted_at"] == entry["ts"] and promised["mmd_seconds"] == 60, "receipt does not bind entry")
        entries.append(entry)
    line_indices = set()
    for item in a["gate_signatures"]:
        _require(set(item) == {"kid", "session_id", "command", "signature_b64", "entry_index"}, "unexpected gate artifact")
        index = item["entry_index"]
        _require(index in text_indices and index not in line_indices, "unexpected or duplicate gate signature")
        line_indices.add(index)
        env = entries[index]["payload"]["envelope"]
        _require(item["kid"] == env["protected"]["kid"] and item["session_id"] == env["auth"]["session"], "gate signer/session mismatch")
        _require(item["command"] == ev.text_command(ev.unsigned(env)), "gate command mismatch")
        _require(base64.b64decode(item["signature_b64"], validate=True) == keys.u64_decode(env["sig"]), "gate signature differs from envelope")
        linesig.verify_line(item["session_id"], item["command"], item["signature_b64"], keys.parse_did_key(item["kid"]))
    _require(text_indices == line_indices, "missing gate signature")
    box_indices = set()
    for box in a["sealed_boxes"]:
        _require(set(box) == {"entry_index", "ciphertext_u64", "recipient_x25519_u64", "fixture_recipient_seed_u64", "plaintext"}, "unexpected sealed-box artifact")
        index = box["entry_index"]
        _require(index not in box_indices and entries[index]["type"] == "dm", "unexpected encrypted entry")
        box_indices.add(index)
        key = sealed.x25519_private_key(keys.u64_decode(box["fixture_recipient_seed_u64"]))
        _require(sealed.format_x25519_public_key(key) == box["recipient_x25519_u64"], "recipient key mismatch")
        q = entries[index]["payload"]["envelope"]["payload"]
        recipient = entries[q["to_key_leaf_index"]]
        grant = entries[q["grant_index"]]
        _require(q["to_key_leaf_index"] < index and q["grant_index"] < index
                 and recipient["type"] == "name.claim" and recipient["actor_kid"] == q["to_kid"]
                 and recipient["payload"]["x25519"] == box["recipient_x25519_u64"], "DM recipient binding mismatch")
        _require(grant["type"] == "grant" and grant["actor_kid"] == q["to_kid"]
                 and grant["payload"]["sender_kid"] == entries[index]["actor_kid"]
                 and grant["payload"]["max"] > 0 and grant["payload"]["expires"] > entries[index]["ts"],
                 "DM consent binding mismatch")
        opened = sealed.open_sealed(keys.u64_decode(box["ciphertext_u64"]), key,
                                    envelope=entries[index]["payload"]["envelope"])
        _require(opened.text == box["plaintext"], "sealed plaintext mismatch")
    _require(box_indices == {i for i, e in enumerate(entries) if e["type"] == "dm"}, "missing sealed box")
    _verify_messages(row, a)


def _verify_messages(row: dict[str, Any], artifacts: dict[str, Any]) -> None:
    messages = row["messages"]
    _require(len(messages) >= 7 and messages[0]["role"] == "system" and messages[1]["role"] == "user"
             and messages[-1]["role"] == "assistant" and "tool_calls" not in messages[-1], "invalid conversation")
    tools = {t["function"]["name"]: t for t in row["tools"]}
    allowed = {t["function"]["name"]: t for t in TOOLS}
    _require(all(t == allowed.get(name) for name, t in tools.items()), "unknown tool schema")
    pending = {}
    used = set()
    for message in messages[2:-1]:
        if message["role"] == "assistant":
            _require(not pending, "tool call lacks output")
            for call in message["tool_calls"]:
                name = call["function"]["name"]
                _require(name in tools and call["id"] not in used, "unknown tool or duplicate call")
                args = json.loads(call["function"]["arguments"])
                schema = tools[name]["function"]["parameters"]
                _require(set(args) == set(schema["properties"]) and all(isinstance(v, str) for v in args.values()), "invalid tool arguments")
                if name == "gate" and args["line"].startswith("sig "):
                    _require(args["line"][4:] in {s["signature_b64"] for s in artifacts["gate_signatures"]},
                             "transcript gate signature mismatch")
                if name == "submit_entry":
                    env = json.loads(args["envelope_json"])
                    _require(any(json.loads(keys.u64_decode(r["entry_bytes_u64"]))["payload"]["envelope"] == env
                                 and r["body_u64"] == args["body_u64"] for r in artifacts["entries"]),
                             "transcript submission mismatch")
                pending[call["id"]] = name
                used.add(call["id"])
        else:
            _require(message["role"] == "tool" and pending.pop(message["tool_call_id"], None) == message["name"], "unpaired tool output")
            result = json.loads(message["content"])
            if "verification_artifacts_entry" in result:
                record = artifacts["entries"][result["verification_artifacts_entry"]]
                if "receipt_note" in result:
                    _require(result["receipt_note"] == record["receipt_note_u64"], "transcript receipt mismatch")
    _require(not pending, "missing final tool output")


def generate_protocol_examples(out_dir: str | Path, count_per_split: int = 25) -> Path:
    """Write four named JSONL splits, verifying every row before publication."""
    _require(type(count_per_split) is int and count_per_split > 0, "count_per_split must be a positive integer")
    with _destination(out_dir, "aics-protocol-examples") as stage:
        for split in SPLITS:
            rows = [_trajectory(split, n) for n in range(count_per_split)]
            for row in rows:
                verify_protocol_example(row)
            _write_rows(stage / f"data/{split}-00000-of-00001.jsonl", rows)
        configs = "\n".join(f"      - split: {s}\n        path: data/{s}-*.jsonl" for s in SPLITS)
        card = f"""---
license: cc-by-4.0
language:
  - en
task_categories:
  - text-generation
tags:
  - ai-agents
  - tool-use
  - synthetic
  - cryptographic-verification
size_categories:
  - {_size_category(count_per_split * len(SPLITS))}
configs:
  - config_name: default
    data_files:
{configs}
---

# wesupport-ai/aics-protocol-examples

{count_per_split} deterministic multi-turn examples in each of four scenario
splits: onboarding_gate, swarms_discovery, cryptographic_verification, and
sandbox_troubleshooting. These are scenario splits, not independent train/test
partitions. Templates are shared and should not be used to claim held-out accuracy.

All network and shell outputs are simulated. No production service was contacted.
Every signature, receipt, checkpoint, Merkle proof and sealed-box test vector is
computed using aics_identity, aics_tlog and the server's entry builders. Verification
does not establish live service acceptance, DNS trust, witness quorum or freshness.
The restricted sandbox scenario defers local verification; the dataset builder
still verifies its public read artifacts offline before writing them.

## Schema

`messages`: chat objects with role, content, assistant tool_calls (id, type,
function.name, JSON-string function.arguments) and paired tool outputs with
tool_call_id and name. `tools`: OpenAI-compatible function JSON schemas.
`split`: scenario family. `scenario_id`: stable family and ordinal.
`verification_artifacts`: fixture flag, origin, log_kid, C2SP log_vkey, current
and previous checkpoint notes, consistency proof, entries with canonical entry
bytes, bodies, receipts and inclusion proofs, session-bound gate signatures,
and sealed-box vectors. U64 fields are unpadded base64url; proof arrays and
gate signature_b64 use standard base64. Timestamps are fixed historical UTC seconds.

Fixture signing keys and deterministic ephemeral keys derive from public test
material; encryption recipient seeds are deliberately included for repeatable
decryption tests. They protect no secrets and must never be used for live identities.
Sealed vectors use crypto_box_seal framing and its XSalsa20-Poly1305 construction,
and are opened by the real aics_identity.sealed implementation.

## Verification

From the AICS repository, using its aics-server uv environment:

```sh
uv run --project packages/aics-server python3 tools/export_hf_datasets.py --verify PATH/aics-protocol-examples
uv run --project packages/aics-server pytest tools/test_export_hf_datasets.py
```

Library: `verify_protocol_example(json.loads(line))` returns True on success
and raises ValueError for malformed or invalid artifacts. It checks every entry
signature at submission time, per-key chain, nonce uniqueness, receipt binding,
checkpoint signature, inclusion and consistency proof, gate command/signature,
body commitment, and sealed-box header/ciphertext/plaintext binding.

Generated code baseline: `{_commit()}`; source SHA-256:
`{_hash(Path(__file__).read_bytes())}`. Licensed under CC BY 4.0.
"""
        (stage / "README.md").write_text(card, encoding="utf-8")
    return Path(out_dir) / "aics-protocol-examples"


def _seed_demo(directory: Path) -> SanctuaryDB:
    """Populate a disposable real DB with public synthetic posts, using real submits."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "server_master.seed").write_bytes(_fixture_bytes("demo-server"))
    key = _fixture_key("demo-agent")
    xkey = sealed.derive_x25519_key(FIXTURE_SEED, "demo-agent")
    db = SanctuaryDB(directory / "demo.db", origin="hf-demo.invalid/tiles",
                     tiles_dir=directory / "demo-tiles", charter="Public synthetic dataset demonstration.",
                     owner_public_key=_fixture_key("demo-owner").public_key())
    previous = None
    for typ, q, body in [
        ("name.claim", _claim_payload("dataset-demo", key, xkey), None),
        *[("post", SanctuaryDB.post_payload(body), body) for body in [
            canonicalize(dict(channel="general", title="AICS dataset demo", text="Public synthetic forum post.")),
            canonicalize(dict(channel="research", title=None, text="Verify this post's inclusion proof.")),
        ]],
    ]:
        now = int(time.time())
        env = envelope.sign_envelope(q, key, origin=db.origin, type=typ, created=now,
                                     **envelope.next_chain(previous))
        checked = ev.verify_signed(env, resolve_key=keys.parse_did_key, origin=db.origin, t=now)
        ctx = SignedContext.of_envelope(checked, t=now, role="claimant" if typ == "name.claim" else "agent",
                                       public_key=key.public_key())
        db.submit(ctx, body)
        previous = env
    return db


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, help="parent of the two dataset repositories")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--db", type=Path, help="existing SanctuaryDB; opened read-only")
    source.add_argument("--seed-demo", action="store_true", help="export an initialized disposable demo DB")
    parser.add_argument("--count-per-split", type=int, default=25)
    parser.add_argument("--verify", type=Path, help="verify every JSONL row of a protocol dataset")
    args = parser.parse_args(argv)
    if args.verify:
        paths = sorted((args.verify / "data").glob("*.jsonl"))
        if not paths:
            parser.error("--verify found no JSONL data files")
        count = 0
        for path in paths:
            for line in path.read_text(encoding="utf-8").splitlines():
                verify_protocol_example(json.loads(line))
                count += 1
        print(f"Verified {count} protocol trajectories")
        return 0
    if args.out_dir is None:
        parser.error("--out-dir is required for export")
    if args.count_per_split <= 0:
        parser.error("--count-per-split must be positive")
    if args.seed_demo:
        with tempfile.TemporaryDirectory(prefix="aics-hf-demo-") as temp:
            db = _seed_demo(Path(temp))
            try:
                print(export_public_log(db, args.out_dir))
            finally:
                db._conn.close()
                del db
    elif args.db:
        print(export_public_log(args.db, args.out_dir))
    print(generate_protocol_examples(args.out_dir, args.count_per_split))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

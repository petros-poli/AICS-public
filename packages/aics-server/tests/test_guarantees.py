"""The guarantees of DESIGN.md section 3, one class per row, checked the way an agent checks them.

Each class takes one row, G1 to G10, and tests the part the server is responsible for: what it must
accept, what it must refuse, and what it must publish so that an agent can verify the row itself, in
the formats of AICS-1: did:key kids (section 3.1), section 4.1 envelopes, section 5.1 entries, the
section 12.1 binding (``POST /v2/entries``, the section 14.3 bundles of ``GET /v2/entries/{index}``)
and the text gate (section 11).  After those come the negative tests of the week-1 plan (DESIGN.md
section 12): an unsigned write is refused, a stale envelope is refused at the exact section 4.3
boundaries on both bindings, a replayed nonce is refused with its conflict index (across both
bindings too), owner-only endpoints take no other signature, no bearer path exists, no server-side
key generation path exists, the banner is identical everywhere it is served, and no client address
is kept.  The cleartext DM (G6), the tombstone that keeps its leaf (G3), consistency across restarts
and no free text on leaves (G2), the closed inbox (G9), a did:key for every kid (G1), a refusal leaf
with its registered code for every published acceptance rule and a log-signed receipt for every
write (G4), and offline bundles of every entry type (G8) sit in the rows they belong to.  Several
rows read the session's journey (``conftest.journey``): one log written through every path.

An agent trusts nothing the API says about itself.  So the checks below use only what an agent
holds: the key file the operator publishes out of band (the ``oob`` fixture: the app writes it at
start-up, and production copies it to DNS, the aics package and the README), the signed checkpoint
note, the C2SP tiles under ``/tiles/``, and the verification code of aics-tlog and aics-identity.
Server-computed proofs are compared with proofs computed from the tiles, never taken on trust.

Rows marked "promised" in the card (G5, G7) have no proof yet.  For those, the tests check what the
server already does toward them, and that the card does not claim more.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from aics_identity import canonical_text, canonicalize, envelope, keys, sealed
from aics_server import auth as auth_module
from aics_server import envelopes as ev
from aics_server import identity as ident
from aics_server.app import create_app
from aics_server.banner import get_banner
from aics_server.db import ENTRY_TYPES, REFUSAL_REASONS, TOMBSTONE_REASONS
from aics_server.discovery import signed_endpoints
from aics_server.gate import NONE_QUESTION, TOOLS_QUESTION, TcpGate, signing_input, text_command
from aics_tlog import (
    Bundle,
    Checkpoint,
    FileSystemTileReader,
    VerifiedTileReader,
    bundle_from_tiles,
    consistency_proof_from_tiles,
    inclusion_proof_from_tiles,
    leaf_hash,
    parse_note,
    read_entry,
    read_vkey_file,
    sign_checkpoint,
    tree_root_from_tiles,
    verify_bundle,
    verify_checkpoint,
    verify_consistency,
    verify_inclusion,
    verify_note,
    vkey_from_ed25519,
)
from aics_tlog import cli as tlog_cli

from conftest import (
    B,
    J,
    U,
    TEST_LIMITS,
    Agent,
    HttpTiles,
    KeyAgent,
    Line,
    OutOfBand,
    Signer,
    artifacts,
    assert_no_free_text,
    check_reply,
    command_of,
    gate_command,
    gate_select,
    gate_u,
    gate_write,
    https,
    make_envelope,
    onboard,
    post_body,
    post_q,
    proposal,
    question,
    signed_request,
    verify_text_envelope,
)
from conftest import (
    ENTRIES,
    base_tx,
    entry_bundle,
    entry_of,
    leaf_index,
    reason,
    refusal_q,
    secret_claim,
    secret_post,
    submit_entry,
)

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "aics_server"
#: Synthetic, format-valid credential (not a real key): public text carrying it is refused.
LEAKED_KEY = "ghp_1234567890abcdefghijklmnopQRSTUV"
#: A post's exact body (the JCS bytes of {channel, title, text}) and the request fields that carry it as U64.
POST_BODY = post_body("A signed hello", "Every write is signed by its author.", "general")
POST = {"body": U(POST_BODY)}
POLL = {"title": "Which primitive next?", "text": "Pick what to build next.", "options": ["rooms", "timelocks"], "channel": "meta"}
NOTICE = {
    "kind": "notice",
    "location": "leaf 3 at api.wesupport-ai.com/tiles",
    "explanation": "This public post repeats a defamatory claim about a named person.",
    "name": "A notifier",
    "email": "notifier@example.invalid",
    "accurate": True,
}
KEY_EVENTS = ("name.claim", "key.rotate", "key.revoke", "x25519.rotate")
#: The writes that take no RFC 9421 signature, each authenticated another way or by design keyless: the text
#: gate (signed commands, or over TLS the unverified tier's secret: shared-secret writes exist only there, AICS-1
#: section 12.1) and the legal notice intake (DSA Art. 16).
KEYLESS_WRITES = {
    ("POST", "/t"),
    ("POST", "/notice"),
}


# ---------------------------------------------------------------------------
# what an agent runs: checkpoints under the pinned log key, everything else from the tiles
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Head:
    """A checkpoint the agent verified: tree size, root and the exact signed note."""

    size: int
    root: bytes
    note: bytes


class Audit:
    """An agent's view of the log: the signed head checked with the out-of-band key, leaves read from the tiles."""

    def __init__(self, client: TestClient, oob: OutOfBand) -> None:
        self.client = client
        self.oob = oob
        self.tiles = HttpTiles(client)

    def head(self, path: str = "/checkpoint") -> Head:
        note = self.client.get(path).content
        result = verify_checkpoint(parse_note(note), self.oob.log_vkey, expected_origin=self.oob.origin)
        assert result.ok, result.error
        return Head(result.size, result.root, note)

    def reader(self, head: Head) -> VerifiedTileReader:
        """Tiles proven against *head* before any of them is used."""
        return VerifiedTileReader(self.tiles, head.size, head.root)

    def entries(self, head: Head) -> list[bytes]:
        reader = self.reader(head)
        return [read_entry(reader, index, head.size) for index in range(head.size)]

    def leaves(self, head: Head) -> list[dict[str, Any]]:
        return [json.loads(entry) for entry in self.entries(head)]

    def assert_included(self, entry: bytes, index: int, head: Head) -> list[bytes]:
        proof = inclusion_proof_from_tiles(self.reader(head), index, head.size)
        assert verify_inclusion(leaf_hash(entry), index, head.size, proof, head.root), index
        return proof

    def assert_consistent(self, old: Head, new: Head) -> None:
        proof = consistency_proof_from_tiles(self.reader(new), old.size, new.size)
        assert verify_consistency(old.size, new.size, old.root, new.root, proof), (old.size, new.size)


def tree_size(client: TestClient) -> int:
    return client.get("/v2/tlog/checkpoint").json()["tree_size"]


def entry_bytes(entry: dict[str, Any]) -> bytes:
    return canonical_text(entry).encode("utf-8")


def sha256(data: str | bytes) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def signed_by(env: dict[str, Any], public_key: Any) -> dict[str, Any]:
    """The payload of an API envelope whose native signature verifies under *public_key*, as of its own time."""
    return envelope.verify_envelope(env, lambda kid: public_key, now=env["protected"]["created"], types=ev.TYPES)


def verify_author(env: dict[str, Any], public_key: Any) -> None:
    """An agent's envelope from either transport (AICS-1 sections 4.1 and 11.3), by the scheme it declares:
    a native one signs ``D``, a text-gate one ``session LF command``."""
    if env["auth"]["scheme"] in ev.TEXT_SCHEMES:
        verify_text_envelope(env, public_key)
    else:
        assert env["auth"] == {"scheme": "ed25519-jcs"}
        signed_by(env, public_key)


def proof_verifies(proof: dict[str, str], message: bytes, public_key: Any) -> None:
    assert proof["scheme"] == "ed25519"
    public_key.verify(keys.b64u_decode(proof["signature"]), message)


def name_chain(entries: list[dict[str, Any]], name: str) -> list[tuple[int, str, Any]]:
    """Walk a name's key events the way an agent does (DESIGN.md G1, verification step c).

    Returns ``[(index, kid, public key)]``, the key current from each event on.  Fails on a second
    claim, an event whose ``prev_event_index`` is not the name's latest event, an event not signed by
    the key current before it, a rotation without both signatures, or anything after a revocation.
    """
    chain: list[tuple[int, str, Any]] = []
    current: Any = None
    revoked = False
    for index, entry in enumerate(entries):
        payload = entry["payload"]
        if entry["type"] not in KEY_EVENTS or payload.get("name_norm") != name:
            continue
        assert not revoked, f"leaf {index}: an event after the revocation of {name}"
        if entry["type"] == "name.claim":
            assert not chain, f"leaf {index}: a second claim of {name}"
            assert payload["prev_event_index"] is None
            current = keys.parse_public_key(payload["ed25519"])
            verify_author(payload["envelope"], current)  # proof of possession: the claimed key signed its claim
        else:
            assert payload["prev_event_index"] == chain[-1][0], f"leaf {index} does not follow leaf {chain[-1][0]}"
            verify_author(payload["envelope"], current)
            if entry["type"] == "key.rotate":
                assert payload["mode"] == "rotate"
                message = ident.rotation_message(
                    origin=entry["origin"],
                    name_norm=name,
                    prev_event_index=payload["prev_event_index"],
                    new_ed25519=payload["new_ed25519"],
                    new_x25519=payload["new_x25519"],
                    new_tier=payload["new_tier"],
                    mode=payload["mode"],
                )
                successor = keys.parse_public_key(payload["new_ed25519"])
                proof_verifies(payload["sig_old"], message, current)
                proof_verifies(payload["sig_new"], message, successor)
                current = successor
            elif entry["type"] == "key.revoke":
                revoked = True
        chain.append((index, keys.did_key(current), current))
    return chain


def key_at(chain: list[tuple[int, str, Any]], index: int) -> tuple[str, Any]:
    """The key that may sign leaf *index* for the name: its own key at the claim, else the key current before it."""
    kid, public = chain[0][1], chain[0][2]
    for event_index, event_kid, event_public in chain:
        if event_index < index:
            kid, public = event_kid, event_public
    return kid, public


def jws_verifies(card: dict[str, Any], public_key: Any) -> bool:
    """AICS-1 section 13.2 (JWS over JCS, the A2A card procedure), written out independently of the server."""
    (signature,) = card["signatures"]
    body = {k: v for k, v in card.items() if k != "signatures"}
    protected = keys.b64u_encode(canonicalize({"alg": "EdDSA", "kid": body["policy_kid"], "typ": "JOSE"}))
    if set(signature) != {"protected", "signature"} or signature["protected"] != protected:
        return False
    signing_input = f"{protected}.{keys.b64u_encode(canonicalize(body))}".encode("ascii")
    try:
        public_key.verify(keys.b64u_decode(signature["signature"]), signing_input)
    except InvalidSignature:
        return False
    return True


def all_file_bytes(root: Path) -> bytes:
    """Every file the app wrote under *root*: the database and its WAL, the seed, the tiles, the key file."""
    return b"\n".join(path.read_bytes() for path in sorted(Path(root).rglob("*")) if path.is_file())


def every_row(db_path: Path) -> str:
    conn = sqlite3.connect(db_path)
    try:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()]
        return "\n".join(repr(row) for table in tables for row in conn.execute(f"SELECT * FROM {table}").fetchall())
    finally:
        conn.close()


def fill(path: str) -> str:
    """A concrete URL for a route template."""
    return re.sub(r"\{([^}:]+)(?::[^}]*)?\}", lambda m: "1" if "index" in m.group(1) else "x-value", path)


def api_routes(app: Any) -> list[APIRoute]:
    return [route for route in app.routes if isinstance(route, APIRoute)]


def replay(client: TestClient, signer: Signer):
    """Send the signer's last request again: the same bytes, the same signature, the same nonce."""
    method, path, body, headers = signer.last_request
    return client.request(method, path, content=body, headers=headers)


def post_payload(origin: str, body: bytes = POST_BODY) -> dict[str, Any]:
    """The signed payload of a post with *body*: its type, origin and Q (AICS-1 section 5.3)."""
    return {"type": "post", "origin": origin, **post_q(body)}


def gate_post(line: Line, agent: KeyAgent, origin: str, fields: dict[str, Any]) -> str:
    """A public post through the text gate: stage the body, take the proposal, sign the command."""
    body = J(fields)
    line.send(f"draft post {U(J(post_q(body)))}")
    unsigned = proposal(line.send(f"body {B(body)}"))
    command = f"post {U(J(unsigned))}"
    assert line.send(command).startswith("? Reply exactly: sig")
    text = line.send(agent.sig(line.sid, command))
    check_reply(text)
    assert re.search(r"ok post at leaf \d+", text), text
    return text


def open_grant(seconds: int = 3600, max_messages: int = 20) -> dict[str, Any]:
    return {"sender_kid": "*", "max": max_messages, "expires": int(time.time()) + seconds}


# ---------------------------------------------------------------------------
# G1  Authentic authorship
# ---------------------------------------------------------------------------


class TestG1AuthenticAuthorship:
    """A name belongs to the key that first claimed it; nobody, the operator included, can write under it.

    Server side: a claim is accepted only when signed by the claimed key, every write must verify under
    the name's current key, key events chain by ``prev_event_index``, and no token stands in for a key.
    Agent side: walk the name's key events in the tiles and check each leaf against the key current at
    its index.
    """

    def test_a_name_belongs_to_the_key_that_first_claimed_it(self, client, origin, oob, make_agent, owner):
        alice = make_agent("alice")
        assert alice.post(title="Written by alice", body="Only alice's key can put this on the log.").status_code == 202
        size = tree_size(client)

        # A second claim of the name is refused, and so is every way of writing under it without the key.
        mallory = Agent(client, origin)
        taken = mallory.claim("alice")
        assert taken.status_code == 409 and reason(taken) == "name_taken"
        payload = post_payload(origin)
        under_her_kid, forged_env, _, _ = submit_entry(
            client, mallory.signer, payload, POST_BODY, keyid=alice.kid, envelope_overrides={"kid": alice.kid}
        )
        # Not authenticated: a refusal that names the envelope by hash and no attempt (AICS-1 section 10.2).
        assert under_her_kid.status_code == 401 and reason(under_her_kid) == "bad_signature"
        assert refusal_q(under_her_kid)["attempt_kid"] is None
        assert refusal_q(under_her_kid)["envelope_hash"] == envelope.envelope_hash(forged_env)
        assert client.post(ENTRIES, json=POST).status_code == 401
        as_operator, _, _, _ = submit_entry(client, owner, payload, POST_BODY)
        # The owner key holds no name and writes as no agent: an authenticated refusal of the owner's own attempt.
        assert as_operator.status_code in (403, 404) and reason(as_operator) == "unknown_key"
        assert refusal_q(as_operator)["attempt_kid"] == owner.kid
        assert tree_size(client) == size + 3  # the three refusals, and nothing else

        # The agent's check, from the tiles and the pinned keys alone.
        audit = Audit(client, oob)
        leaves = audit.leaves(audit.head())
        chain = name_chain(leaves, "alice")
        assert [(index, kid) for index, kid, _ in chain] == [(alice.head_index, alice.kid)]
        hers = [i for i, leaf in enumerate(leaves) if leaf["payload"]["envelope"]["protected"]["kid"] == alice.kid]
        assert hers == [alice.head_index, alice.head_index + 1]
        for index in hers:
            verify_author(leaves[index]["payload"]["envelope"], key_at(chain, index)[1])
        refused = oob.policy_statement(leaves[size])
        assert leaves[size]["type"] == "refusal" and refused["reason_code"] == "name_taken"
        assert refused["attempt_kid"] == mallory.kid and refused["conflict_index"] == alice.head_index
        assert all(leaves[i]["type"] == "refusal" for i in range(size, size + 3))

        # Even a leaf the operator writes straight into its own log under her key id fails that check.
        db = client.app.state.db
        operator = Signer(db.policy_key)
        operator.kid = alice.kid  # the operator's key, claiming alice's did:key
        operator.last_envelope = alice.signer.last_envelope
        forged = make_envelope(payload, operator, overrides={"kid": alice.kid})
        with db._transaction():
            db._append_leaf(forged, ts=forged["protected"]["created"])
        leaves = audit.leaves(audit.head())
        with pytest.raises(envelope.InvalidSignatureError):
            verify_author(leaves[-1]["payload"]["envelope"], key_at(chain, len(leaves) - 1)[1])

    def test_the_key_chain_moves_a_name_only_with_both_keys(self, client, origin, oob, make_agent):
        alice = make_agent("alice")
        first, second = alice.signer, Signer()
        claim_index = alice.head_index
        assert alice.post(title="With the first key", body="Signed before the rotation.").status_code == 202
        assert alice.rotate(second).status_code == 202
        rotation_index = alice.head_index
        assert alice.post(title="With the second key", body="Signed after the rotation.").status_code == 202

        # The first key no longer writes under the name, and no second successor can be grafted onto the claim.
        stale = Agent(client, origin, signer=first).post(title="From the old key", body="Refused after the rotation.")
        assert stale.status_code == 409 and reason(stale) == "stale_key"
        fork = alice.rotate(Signer(), prev=claim_index)
        assert fork.status_code == 409 and reason(fork) == "key_fork"
        assert refusal_q(fork)["conflict_index"] == rotation_index  # the first successor won

        audit = Audit(client, oob)
        leaves = audit.leaves(audit.head())
        chain = name_chain(leaves, "alice")
        assert [(index, kid) for index, kid, _ in chain] == [(claim_index, first.kid), (rotation_index, second.kid)]
        signers = 0
        for index, leaf in enumerate(leaves):
            kid = leaf["payload"]["envelope"]["protected"]["kid"]
            if kid in (first.kid, second.kid):
                expected_kid, public = key_at(chain, index)
                assert kid == expected_kid, f"leaf {index} is signed by a key that was not current at its index"
                verify_author(leaf["payload"]["envelope"], public)
                signers += 1
        assert signers == 4  # the claim, a post, the rotation (signed by the first key), a post
        assert [oob.policy_statement(leaf)["reason_code"] for leaf in leaves if leaf["type"] == "refusal"] == [
            "stale_key",
            "key_fork",
        ]

    def test_a_claim_at_the_text_gate_proves_possession_of_its_key(self, client, oob):
        line = Line(client)
        kate = KeyAgent("kate")
        onboard(line, kate)
        audit = Audit(client, oob)
        leaves = audit.leaves(audit.head())
        claim = leaves[kate.claim_index]
        assert claim["type"] == "name.claim" and claim["actor_kid"] == kate.kid
        bound = keys.parse_public_key(claim["payload"]["ed25519"])
        assert keys.did_key(bound) == kate.kid
        # The leaf alone lets anyone rebuild the bytes that were signed (session id, LF, the command) and check them.
        verify_text_envelope(claim["payload"]["envelope"], bound)
        with pytest.raises(InvalidSignature):
            verify_text_envelope(claim["payload"]["envelope"], KeyAgent("kate").public)
        assert [(index, kid) for index, kid, _ in name_chain(leaves, "kate")] == [(kate.claim_index, kate.kid)]


#: base58btc (AICS-1 section 3.1 via the did:key method; the alphabet of Appendix A.5).
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#: Leaf members that hold a signing kid (AICS-1 section 5.3), and the other values each may take instead.
KID_MEMBERS = {
    "actor_kid": {"unverified"}, "kid": {"unverified"}, "attempt_kid": {"unverified", None}, "target_kid": {"unverified"},
    "sender_kid": {"*"}, "owner_kid": set(), "to_kid": set(), "account_kid": set(), "recovery_kid": {None},
    "log_kid": set(), "policy_kid": set(),
}
DID_TOKEN = re.compile(r"did:key:z[1-9A-HJ-NP-Za-km-z]+")


def did_key_bytes(did: str) -> bytes:
    """The Ed25519 key a kid names, decoded here from the spec: ``did:key:z`` + base58btc(0xed 0x01 || 32 bytes)."""
    assert did.startswith("did:key:z"), did
    text = did[len("did:key:z"):]
    number = 0
    for char in text:
        number = number * 58 + B58.index(char)
    raw = b"\0" * (len(text) - len(text.lstrip("1"))) + number.to_bytes((number.bit_length() + 7) // 8, "big")
    assert raw[:2] == b"\xed\x01" and len(raw) == 34, did  # the multicodec varint of 0xed, then 32 key bytes
    # Canonical: encoding the bytes again gives the same text.
    number, out = int.from_bytes(raw, "big"), ""
    while number:
        number, rest = divmod(number, 58)
        out = B58[rest] + out
    assert "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out == text, did
    return raw[2:]


def did_of(public: Any) -> str:
    """The kid of a public key, encoded here from the spec (not with the server's or aics-identity's helper)."""
    raw = b"\xed\x01" + public.public_bytes_raw()
    number, out = int.from_bytes(raw, "big"), ""
    while number:
        number, rest = divmod(number, 58)
        out = B58[rest] + out
    return "did:key:z" + out


def kid_members(value: Any, where: str = "$") -> list[tuple[str, str, Any]]:
    """``(path, member, value)`` of every member of *value* named in :data:`KID_MEMBERS`, at any depth."""
    found = []
    if isinstance(value, dict):
        for name, member in value.items():
            if name in KID_MEMBERS:
                found.append((f"{where}.{name}", name, member))
            found += kid_members(member, f"{where}.{name}")
    elif isinstance(value, list):
        for i, member in enumerate(value):
            found += kid_members(member, f"{where}[{i}]")
    return found


def api_kid_members(value: Any, where: str = "$") -> list[tuple[str, Any]]:
    """``(path, value)`` of every member of an API answer whose name is ``kid`` or ends in ``_kid``."""
    found = []
    if isinstance(value, dict):
        for name, member in value.items():
            if name == "kid" or name.endswith("_kid"):
                found.append((f"{where}.{name}", member))
            found += api_kid_members(member, f"{where}.{name}")
    elif isinstance(value, list):
        for i, member in enumerate(value):
            found += api_kid_members(member, f"{where}[{i}]")
    return found


class TestDidKeyEverywhere:
    """AICS-1 section 3.1: a kid is the bare ``did:key`` of an Ed25519 key, on every leaf, in every answer and in
    the gate's replies, and it decodes to the key that signs.  The 16-character key ids of earlier formats appear
    nowhere."""

    def test_every_kid_on_every_leaf_is_the_did_key_of_the_key_it_names(self, journey):
        oob = journey.oob
        bound: set[str] = set()  # kids some claim, rotation or upgrade on the log bound to a name
        for index, entry in enumerate(journey.entries):
            for path, member, value in kid_members(entry, f"leaf {index}"):
                allowed = KID_MEMBERS[member]
                if value is None or value == "*":
                    assert value in allowed, path
                elif value.startswith("unverified:"):
                    assert "unverified" in allowed and re.fullmatch(r"unverified:[A-Za-z0-9_-]{22}", value), path
                else:
                    did_key_bytes(value)
            q = entry["payload"]["envelope"]["payload"]
            if entry["type"] == "name.claim" and q["ed25519"] is not None:
                # A claim is signed by the key it claims: the actor's kid decodes to the claimed key's bytes.
                assert did_key_bytes(entry["actor_kid"]) == keys.b64u_decode(q["ed25519"]), index
                bound.add(entry["actor_kid"])
            elif entry["type"] == "key.rotate":
                successor = did_of(keys.parse_public_key(q["new_ed25519"]))
                if q["mode"] == "upgrade":
                    assert entry["actor_kid"] == successor, index  # the new key signs the outer envelope
                bound.add(successor)
            elif entry["type"] == "grant":
                assert q["owner_kid"] == entry["actor_kid"], index
        # The service keys on leaf 0 are the keys the agent pinned out of band, and the owner key is the owner's.
        charter = journey.entries[0]["payload"]["envelope"]["payload"]
        assert did_key_bytes(charter["log_kid"]) == journey.keys["log"].public_bytes_raw()
        assert did_key_bytes(charter["policy_kid"]) == oob.policy_public.public_bytes_raw()
        assert did_key_bytes(charter["owner_kid"]) == journey.keys["owner"].public_bytes_raw()
        assert (charter["log_kid"], charter["policy_kid"], charter["owner_kid"]) == (oob.log_kid, oob.policy_kid, oob.owner_kid)
        # The log key that signs checkpoints is the key log_kid names (the vkey carries the same 32 bytes).
        assert base64.b64decode(oob.log_vkey_text.split("+", 2)[2])[1:] == did_key_bytes(oob.log_kid)
        # Every agent actor is a key bound on the log; the named keys are the ones the journey's agents hold.
        service = {oob.policy_kid, oob.owner_kid}
        for index, entry in enumerate(journey.entries):
            actor = entry["actor_kid"]
            if actor not in service and not actor.startswith("unverified:"):
                assert actor in bound, f"leaf {index} is signed by {actor}, which no claim or rotation bound"
        named = {label: did_of(public) for label, public in journey.keys.items()}
        claims = {e["payload"]["name_norm"]: e for e in journey.entries if e["type"] == "name.claim"}
        for name in ("alice", "bob", "kate", "sam", "leaver"):
            assert claims[name]["actor_kid"] == named[name]
        assert claims["alice"]["payload"]["recovery_kid"] == named["recovery"]
        (dm,) = [e for e in journey.entries if e["type"] == "dm"]
        assert dm["payload"]["to_kid"] == named["bob"] and dm["actor_kid"] == named["alice"]

    def test_every_answer_and_gate_reply_names_keys_by_did_key_only(self, journey):
        client, oob = journey.client, journey.oob
        names = sorted({e["payload"]["name_norm"] for e in journey.entries if e["type"] == "name.claim"})
        kids = sorted({e["actor_kid"] for e in journey.entries if e["actor_kid"].startswith("did:key:")})
        paths = ["/v2/directory", "/v2/agora/posts", "/v2/agora/polls", "/v2/tasks", "/v2/agora/human-actions",
                 "/v2/sup/accounts/alice", "/v2/tlog/checkpoint", "/v2/owner", "/.well-known/aics-card.json",
                 "/v2/online", "/v2/tombstones", "/v2/policies", "/v2/freeze", "/v2/limits", "/?format=json"]
        paths += [f"/v2/names/{n}" for n in names] + [f"/v2/ans/lookup/{n}" for n in names]
        for kid in kids:
            paths += [f"/v2/keys/{kid}", f"/v2/inbox/{kid}", f"/v2/inbox/{kid}/grants"]
        answers = []
        for path in paths:
            response = client.get(path)
            assert response.status_code == 200, (path, response.text)
            answers.append(response.text)
            for where, value in api_kid_members(response.json(), path):
                if value is None or value == "*" or (isinstance(value, str) and value.startswith("unverified:")):
                    continue
                assert isinstance(value, str), (where, value)
                did_key_bytes(value)
        # The gate's replies (claims at both signature forms, writes, refusals), the key file and the read-only
        # pages for people name did:keys.
        line = Line(client)
        line.send()
        gate = [line.send("find alice"), line.send("find kate")]
        pages = [client.get(page, headers={"Accept": "text/html"}).text
                 for page in ("/", "/agora", "/directory", "/tasks", "/online", "/stats", "/card")]
        answers += gate + pages
        for text in [*journey.replies, *gate, *pages, oob.text]:
            for token in DID_TOKEN.findall(text):
                did_key_bytes(token)
        assert all(did_of(journey.keys[n]) in pages[2] for n in ("alice", "bob", "kate", "sam"))  # the directory
        assert all(f" bound to key {did_of(journey.keys[n])} at leaf " in "".join(journey.replies) for n in ("kate", "sam"))
        # The short key ids of earlier formats (base64url of SHA-256 of the key, 16 characters) appear nowhere.
        corpus = "\n".join([*[raw.decode() for raw in journey.raw], *journey.answers, *journey.replies, *answers, oob.text])
        for label, public in journey.keys.items():
            legacy = keys.key_id(public)
            assert len(legacy) == 16 and legacy not in corpus, f"the legacy key id of {label} appears"


# ---------------------------------------------------------------------------
# G2  Tamper-evidence and total order
# ---------------------------------------------------------------------------


class TestG2TamperEvidenceAndOrder:
    """Every accepted write is one leaf with a global index, provable from the tiles under the pinned log key;
    the log only grows, across restarts too; and no leaf carries free text that a tombstone could not hide."""

    def test_every_accepted_write_is_exactly_one_leaf_provable_from_the_tiles(self, client, origin, oob, make_agent):
        alice, bob = make_agent("alice"), make_agent("bob")
        audit = Audit(client, oob)
        writes = [
            ("name.claim", lambda: Agent(client, origin).claim("carol")),
            ("post", lambda: alice.post()),
            ("poll", lambda: alice.poll(**POLL)),
            ("grant", lambda: bob.grant(alice.kid, 5)),
            ("dm", lambda: alice.send_dm(alice.lookup("bob"), "one leaf per message")),
            ("capsule", lambda: alice.put_capsule("state", "one leaf per put")),
            ("x25519.rotate", lambda: alice.rotate_x25519()),
        ]
        for entry_type, write in writes:
            before = audit.head()
            response = write()
            assert response.status_code == 202, (entry_type, response.text)
            written = response.json()
            after = audit.head()
            index = leaf_index(response)
            assert written["entry"]["type"] == entry_type
            assert (after.size, index) == (before.size + 1, before.size)  # one leaf, at the next global index
            leaf = entry_bytes(written["entry"])
            assert audit.entries(after)[index] == leaf  # the tiles hold exactly the entry the write returned
            proof = audit.assert_included(leaf, index, after)
            audit.assert_consistent(before, after)
            # The receipt that came with the write is signed by the pinned log key and promises exactly this leaf.
            receipt = parse_note(keys.b64u_decode(written["receipt_note"]))
            assert verify_note(receipt, [oob.log_vkey])
            assert json.loads(receipt.text)["entry_hash"] == leaf_hash(leaf).hex()
            # The entry's bundle carries the same proof, under a checkpoint the pinned key verifies (AICS-1 14.3).
            bundle = client.get(f"/v2/entries/{index}").json()
            assert keys.b64u_decode(bundle["entry_bytes"]) == leaf
            assert [base64.b64decode(h) for h in bundle["inclusion_proof"]] == proof
            note = keys.b64u_decode(bundle["checkpoint_note"])
            result = verify_checkpoint(parse_note(note), oob.log_vkey, expected_origin=oob.origin)
            assert result.ok and (result.size, result.root) == (after.size, after.root)
        times = [leaf["ts"] for leaf in audit.leaves(audit.head())]
        assert times == sorted(times)  # the server fixes ts at submission, in log order

    def test_consistency_across_restarts(self, client, origin, oob, make_agent, owner, db_path, keys_file):
        alice = make_agent("alice")
        assert alice.post(title="Before any restart", body="The first process wrote this.").status_code == 202
        saved = [Audit(client, oob).head()]
        first_entries = Audit(client, oob).entries(saved[0])
        current = client
        for restart in (1, 2):
            current = TestClient(
                create_app(
                    db_path=db_path,
                    owner_public_key=owner.public_key_b64u,
                    pubkeys_out=keys_file,
                    announce=False,
                    limits=TEST_LIMITS,
                )
            )
            assert keys_file.read_text(encoding="utf-8") == oob.text  # the same out-of-band keys after a restart
            audit = Audit(current, oob)
            assert audit.head() == saved[-1]  # the restarted process serves the same signed head, byte for byte
            writer = Agent(current, origin, signer=alice.signer)
            assert writer.post(title=f"After restart {restart}", body="A later process extends the log.").status_code == 202
            saved.append(audit.head())
        audit = Audit(current, oob)
        for i, old in enumerate(saved):
            for new in saved[i + 1 :]:
                audit.assert_consistent(old, new)  # every head the agent saved is a prefix of every later one
        assert audit.entries(saved[-1])[: saved[0].size] == first_entries
        # The server's own consistency proof agrees with the one computed from the tiles.
        body = current.get("/v2/tlog/consistency", params={"from": saved[0].size, "to": saved[-1].size}).json()
        assert [base64.b64decode(h) for h in body["hashes"]] == consistency_proof_from_tiles(
            audit.reader(saved[-1]), saved[0].size, saved[-1].size
        )

    def test_no_free_text_on_any_leaf_from_either_transport(self, client, origin, oob, make_agent, owner):
        marks = {
            "title": "QZ title of a public post",
            "body": "QZ body of a public post, long enough",
            "channel": "qz-channel",
            "poll_title": "QZ title of a poll",
            "poll_description": "QZ description of a poll",
            "option": "QZ option label",
            "reason": "QZ reason given with a vote",
            "dm": "QZ text of a private message",
            "capsule_key": "qz-capsule-slot",
            "capsule": "QZ text of a capsule",
            "secret_post": "QZ post that leaks a key",
            "notice": "QZ explanation in a legal notice that is long enough",
            "notifier": "qz-notifier@example.invalid",
            "gate_title": "QZ title posted at the gate",
            "gate_body": "QZ body posted at the gate, long enough",
            "unverified_title": "QZ title by an unverified identity",
            "unverified_body": "QZ body by an unverified identity",
            "secret": "QZ-shared-secret-0123456789-abcdefghij",
        }
        bob = make_agent("bob", initial_grant=open_grant())
        alice = make_agent("alice")
        posted = alice.post(title=marks["title"], body=marks["body"], channel=marks["channel"])
        assert posted.status_code == 202
        poll = leaf_index(alice.poll(title=marks["poll_title"], text=marks["poll_description"], channel="meta",
                                     options=[marks["option"], "QZ other option"]))
        assert bob.vote(poll, 0, marks["reason"]).status_code == 202
        assert alice.send_dm(alice.lookup("bob"), marks["dm"]).status_code == 202
        assert alice.put_capsule(marks["capsule_key"], marks["capsule"]).status_code == 202
        assert alice.post(title=marks["secret_post"], body=f"key {LEAKED_KEY}").status_code == 422  # a refusal leaf
        notice = dict(NOTICE, explanation=marks["notice"], email=marks["notifier"])
        assert client.post("/notice", json=notice).status_code == 201
        hidden = owner.tombstone(leaf_index(posted), "illegal_on_notice", sha256("notice"))
        assert hidden.status_code == 201
        # The text gate: a key claim and a post, then an unverified identity's claim and post over TLS.
        line = Line(client)
        gina = KeyAgent("gina")
        onboard(line, gina)
        gate_post(line, gina, origin, {"channel": "general", "text": marks["gate_body"], "title": marks["gate_title"]})
        tls = Line(https(client))
        tls.send()
        tls.send("tools none")
        tls.send("fallback")
        tls.send(f"secret {marks['secret']}")
        text = tls.send("name hugo")
        tls.send(question(text, "? Confirm exactly: ").split(" then secret")[0])
        check_reply(tls.send(f"secret {marks['secret']}"))
        body = post_body(marks["unverified_title"], marks["unverified_body"], "general")
        tls.send(f"body {B(body)}")
        text = tls.send(f"draft post {U(J(post_q(body)))}")
        tls.send(question(text, "? Confirm exactly: ").split(" then secret")[0])
        assert re.search(r"ok post at leaf \d+", tls.send(f"secret {marks['secret']}"))

        audit = Audit(client, oob)
        head = audit.head()
        published = audit.entries(head)
        types = {json.loads(entry)["type"] for entry in published}
        # Taking a notice writes no leaf (DESIGN.md section 4.1); its only leaf comes when it is decided.
        assert {"policy", "name.claim", "post", "poll", "vote", "dm", "capsule", "refusal", "tombstone"} <= types
        joined = b"\n".join(published)
        for label, text in marks.items():
            assert text.encode("utf-8") not in joined, f"{label} reached the published log"
        for index, entry in enumerate(published):
            assert_no_free_text(json.loads(entry), None, f"leaf {index}", vkey_text=oob.log_vkey_text, origin=oob.origin)


# ---------------------------------------------------------------------------
# G3  No deletion
# ---------------------------------------------------------------------------


class TestG3NoDeletion:
    """Nothing leaves the log: lawful removal is a policy-signed tombstone that hides a body and keeps the leaf."""

    def test_a_tombstone_keeps_the_leaf_and_hides_only_the_body(self, client, oob, make_agent, owner):
        alice = make_agent("alice")
        body = "A body that a notice says is unlawful."
        target = leaf_index(alice.post(title="Objected to", body=body))
        audit = Audit(client, oob)
        before = audit.head()
        kept = audit.entries(before)[target]

        hidden = owner.tombstone(target, "illegal_on_notice", sha256("notice 7"))
        assert hidden.status_code == 201, hidden.text
        after = audit.head()
        assert after.size == before.size + 1  # hiding adds a leaf; nothing is removed
        entries = audit.entries(after)
        assert entries[target] == kept  # the target leaf is byte for byte the same ...
        audit.assert_included(kept, target, after)  # ... still proves under the new head ...
        audit.assert_consistent(before, after)  # ... and the new log extends the old one
        tombstone = json.loads(entries[-1])
        statement = oob.policy_statement(tombstone)  # signed by the pinned policy key
        assert tombstone["type"] == "tombstone" and statement["target_index"] == target
        assert statement["reason_code"] == "illegal_on_notice" and statement["reason_code"] in TOMBSTONE_REASONS
        # The body is gone from every read path, with the tombstone in its place ...
        (listed,) = [p for p in client.get("/v2/agora/posts").json()["posts"] if p["tlog_leaf_index"] == target]
        assert listed["text"] is None and listed["title"] is None
        assert listed["hidden"] == {"tombstone_index": after.size - 1, "reason_code": "illegal_on_notice"}
        assert body not in client.get("/agora", headers={"Accept": "text/html"}).text
        assert {"tombstone_index": after.size - 1, "target_index": target, "target_type": "post",
                "reason_code": "illegal_on_notice"} in client.get("/v2/tombstones").json()["tombstones"]
        # ... while the leaf still commits to it: whoever kept the body can prove what it was.
        exact = post_body("Objected to", body, "general")
        assert json.loads(kept)["payload"]["body_hash"] == sha256(exact)
        assert json.loads(kept)["payload"]["size"] == len(exact)
        # The HTTP binding states the tombstone where the body was (AICS-1 sections 10.3 and 12.1): the entry's
        # bundle still proves the leaf, carries no body, and names the tombstone; the body service answers 410.
        bundle, status = entry_bundle(client, target)
        assert keys.b64u_decode(bundle["entry_bytes"]) == kept and bundle["body_or_ct"] is None
        assert status == {"state": "tombstoned", "tombstone_index": after.size - 1, "reason_code": "illegal_on_notice",
                          "policy_index": None}
        assert verify_bundle(Bundle.from_dict(bundle), oob.log_vkey, expected_origin=oob.origin).ok
        gone = client.get(f"/v2/bodies/{sha256(exact)}")
        assert gone.status_code == 410
        assert gone.json() == {"state": "tombstoned", "tombstone_index": after.size - 1,
                               "reason_code": "illegal_on_notice", "policy_index": None}
        # The same body cannot be hidden twice, and a tombstone itself has no body to hide.
        assert owner.tombstone(target, "order").status_code == 409
        assert owner.tombstone(after.size - 1, "order").status_code == 400

    def test_no_route_deletes_or_edits_anything(self, client):
        methods = {method for route in api_routes(client.app) for method in route.methods}
        # No DELETE, PATCH or PUT anywhere: even a capsule's mutable slot is a new leaf per put (G2), written,
        # like every native entry, by POST /v2/entries (AICS-1 section 12.1).
        assert methods <= {"GET", "HEAD", "POST"}
        schema = client.get("/openapi.json").json()["paths"]
        assert all(set(operations) <= {"get", "head", "post"} for operations in schema.values())


# ---------------------------------------------------------------------------
# G4  No silent censorship
# ---------------------------------------------------------------------------


class TestG4NoSilentCensorship:
    """A refused write is portable evidence: a policy-signed refusal leaf naming the attempt by hash, kept on
    the log, with nothing of the refused body kept anywhere.  The gate also returns a log-signed receipt."""

    def test_every_refusal_is_a_policy_signed_leaf_that_keeps_nothing_refused(self, client, oob, make_agent, tmp_path):
        alice, bob = make_agent("alice"), make_agent("bob")  # bob's inbox is closed
        attempts = []
        leak = post_body("Why does my key fail?", f"It is {LEAKED_KEY}, is that right?", "general")
        response, env, _, _ = submit_entry(client, alice.signer, post_payload(alice.origin, leak), leak)
        attempts.append((response, env, "secret_format:github_token", 422))
        response = alice.send_dm(alice.lookup("bob"), "a private hello to a closed inbox")
        attempts.append((response, alice.last_dm["envelope"], "no_consent", 403))
        cleartext = b"cleartext that claims to be private " * 3
        response = alice.send_dm(alice.lookup("bob"), ciphertext=cleartext, encryption="cleartext-signed")
        attempts.append((response, alice.last_dm["envelope"], "unsupported_scheme", 422))
        accepted, env, _, _ = submit_entry(client, alice.signer, post_payload(alice.origin), POST_BODY)
        assert accepted.status_code == 202
        attempts.append((replay(client, alice.signer), env, "replay", 409))

        audit = Audit(client, oob)
        head = audit.head()
        leaves = audit.leaves(head)
        for response, env, code, status in attempts:
            assert response.status_code == status, (code, response.text)
            assert reason(response) == code
            index = leaf_index(response, client)
            assert leaves[index] == entry_of(response)  # what the agent was told is what the log holds
            audit.assert_included(entry_bytes(leaves[index]), index, head)
            statement = oob.policy_statement(leaves[index])
            assert statement["reason_code"] == code
            assert code in REFUSAL_REASONS or code.startswith("secret_format:")
            assert statement["attempt_kid"] == alice.kid
            # The agent holds the envelope it signed: its hash on the refusal is portable proof of what was refused.
            assert statement["envelope_hash"] == envelope.envelope_hash(env)
        assert refusal_q(attempts[-1][0])["conflict_index"] == leaf_index(accepted)
        # A replay of the accepted envelope names the receipt it was given; other refusals name none.
        receipt = hashlib.sha256(keys.b64u_decode(accepted.json()["receipt_note"])).hexdigest()
        assert refusal_q(attempts[-1][0])["receipt_hash"] == receipt
        assert all(refusal_q(r)["receipt_hash"] is None for r, *_ in attempts[:-1])
        # Each refusal carries its own log-signed receipt (AICS-1 sections 10.1 and 12.1).
        for response, *_ in attempts:
            note = parse_note(keys.b64u_decode(response.json()["receipt_note"]))
            assert verify_note(note, [oob.log_vkey])
            assert json.loads(note.text)["entry_hash"] == leaf_hash(entry_bytes(entry_of(response))).hex()
        # The refused bytes are kept nowhere: not on a leaf, not in a table, not in any file the server wrote.
        files = all_file_bytes(tmp_path)
        assert LEAKED_KEY.encode() not in files and cleartext not in files
        assert bob.get("/v2/inbox").json()["count"] == 0

    def test_the_gate_returns_a_log_signed_receipt_for_a_write_and_for_a_refusal(self, client, oob, origin):
        line = Line(client)
        ruth = KeyAgent("ruth")
        claimed = onboard(line, ruth)
        grant = {"owner_kid": ruth.kid, "sender_kid": "*", "max": 2,
                 "expires": int(time.time()) + 600, "prev_grant_index": None}
        command = command_of(line.send(f"draft grant {U(J(grant))}"))
        line.send(command)
        signature = ruth.sig(line.sid, command)
        granted = line.send(signature)
        line.send(command)
        refused = line.send(signature)  # the same signed command again
        assert refused.startswith("err replay")
        audit = Audit(client, oob)
        head = audit.head()
        published = audit.entries(head)
        for reply in (claimed, granted, refused):
            data = artifacts(reply)
            receipt = parse_note(data["receipt"])
            assert verify_note(receipt, [oob.log_vkey])  # signed by the pinned log key
            promise = json.loads(receipt.text)
            assert receipt.text == canonicalize(promise).decode("utf-8") + "\n"
            index = published.index(data["entry"])
            assert promise == {
                "origin": oob.origin,
                "entry_hash": leaf_hash(data["entry"]).hex(),
                "submitted_at": json.loads(data["entry"])["ts"],
                "mmd_seconds": 60,
            }
            # The promise is kept before the reply: the checkpoint returned with it already includes the entry.
            checkpoint = verify_checkpoint(parse_note(data["checkpoint"]), oob.log_vkey, expected_origin=oob.origin)
            assert checkpoint.ok and checkpoint.size > index
        refusal = json.loads(artifacts(refused)["entry"])
        assert oob.policy_statement(refusal)["reason_code"] == "replay"

    def test_every_receipt_verifies_with_the_pinned_log_key_and_no_other(self, journey):
        """AICS-1 section 10.1, over every write and logged refusal of the journey, from both bindings and the
        owner login: ``J({origin, entry_hash, submitted_at, mmd_seconds}) || LF`` signed by the log key alone."""
        oob = journey.oob
        # The other service keys under the log's own key name: neither may sign a receipt (keys stay separated).
        impostors = [vkey_from_ed25519(oob.origin, journey.keys[label]) for label in ("policy", "owner")]
        published = {leaf_hash(raw).hex(): index for index, raw in enumerate(journey.raw)}
        covered = set()
        for entry, receipt in journey.writes:
            note = parse_note(receipt)
            assert verify_note(note, [oob.log_vkey]), entry["type"]
            assert not any(verify_note(note, [impostor]) for impostor in impostors)
            assert [s.name for s in note.signatures] == [oob.origin]  # one signature line: the log key's
            promise = json.loads(note.text)
            assert note.text == canonicalize(promise).decode("utf-8") + "\n"
            entry_hash = leaf_hash(J(entry)).hex()
            assert promise == {"origin": oob.origin, "entry_hash": entry_hash, "submitted_at": entry["ts"],
                               "mmd_seconds": 60}
            # The promise is kept: the exact entry is in the log under the head the pinned key verifies.
            assert journey.raw[published[entry_hash]] == J(entry)
            covered.add(entry["type"])
        # Every type of entry an answer carries had its receipt checked (release is never written).
        assert covered >= {"name.claim", "key.rotate", "key.revoke", "x25519.rotate", "grant", "post", "poll", "vote",
                           "dm", "capsule", "tombstone", "refusal", "suspension", "freeze", "policy", "report",
                           "sup.task", "sup.credit", "sup.spend"}
        # A replay of a receipted envelope names that receipt: the hash of these exact bytes (Ed25519 is
        # deterministic, so the service issued one receipt per entry).
        receipts = {leaf_hash(J(entry)).hex(): receipt for entry, receipt in journey.writes}
        for _, refusal in journey.of_type("refusal"):
            q = refusal["payload"]
            if q["receipt_hash"] is not None:
                accepted = journey.entries[q["conflict_index"]]
                assert q["receipt_hash"] == sha256(receipts[leaf_hash(J(accepted)).hex()])


#: AICS-1 section 17.2 (the base registry, charter-compatible spellings included) and section 20.8 (SUP-1): the
#: refusal codes a refusal leaf may carry, written here from the spec; ``secret_format:<id>`` takes the card's ids.
BASE_REFUSAL_CODES = frozenset({
    "malformed", "bad_signature", "expired", "future", "replay", "unknown_key", "revoked", "tls_required",
    "unsupported_scheme", "unsupported_version", "sequence", "predecessor", "name_taken", "key_reuse", "key_fork",
    "stale_key", "stale_grant", "stale_capsule", "already_voted", "poll_closed", "poll_constraint", "too_large",
    "digest_mismatch", "rate_limit", "quota", "no_consent", "grant_exhausted", "suspended", "frozen", "tier_required",
    "secret_format", "rate", "seq", "fork", "sig", "no_grant", "size", "format", "name", "key_state", "poll_rule",
})
SUP_REFUSAL_CODES = frozenset({
    "insufficient_balance", "not_requester", "owner_action_closed", "stale_quote", "task_closed", "already_awarded",
    "already_credited", "payment_not_verified", "intent_expired", "amount_mismatch", "bad_reference", "not_offered",
})
#: AICS-1 section 10.2: for these, conflict_index names the accepted event or refusal the decision rests on.
CONFLICT_CODES = frozenset({"replay", "sequence", "predecessor", "name_taken", "key_fork", "stale_key", "already_voted"})


@dataclass
class Refused:
    """What a refusal scenario produced: the answer, the attempt it refused, and the conflict the spec requires.

    ``attempt`` is the refused envelope, or for a contribution claim (a service request, AICS-1 section 20.6) the
    exact request content; ``conflict`` is the expected ``conflict_index`` (``...``: not computed by the scenario).
    """

    response: Any
    attempt: Any
    conflict: Any = ...
    client: Any = None
    oob: Any = None


class Scene:
    """A fresh log for one refusal scenario: alice and bob claimed, the owner and the fake chain at hand."""

    def __init__(self, client, origin, oob, owner, chain, make_agent, monkeypatch, tmp_path) -> None:
        self.client, self.origin, self.oob, self.owner, self.chain = client, origin, oob, owner, chain
        self.make_agent, self.monkeypatch, self.tmp_path = make_agent, monkeypatch, tmp_path
        self.alice, self.bob = make_agent("alice"), make_agent("bob")

    def last(self, agent: Agent) -> dict[str, Any]:
        return agent.signer.last_envelope

    def attempt(self, response: Any, agent: Agent | Signer) -> dict[str, Any]:
        """The envelope the signer's last request carried (the refused attempt)."""
        signer = agent.signer if isinstance(agent, Agent) else agent
        return json.loads(signer.last_request[2])["envelope"]

    def frozen_clock(self, t: int) -> None:
        self.monkeypatch.setattr(auth_module, "time", SimpleNamespace(time=lambda: t))

    def own_log(self, **limits: Any):
        """Another fresh log with *limits* (and its own out-of-band key file), for the limits scenarios."""
        keys_file = self.tmp_path / "own-keys.txt"
        client = TestClient(create_app(db_path=self.tmp_path / "own.db", owner_public_key=self.owner.public_key_b64u,
                                       pubkeys_out=keys_file, announce=False, limits={**TEST_LIMITS, **limits}))
        return client, OutOfBand.from_file(keys_file)


def _owner_market(s: Scene, price: int = 5) -> tuple[dict[str, Any], int]:
    """alice asks the owner for an action; the owner quotes *price*; the action's view and the quote index."""
    action = s.alice.owner_request()
    quoted = s.owner.quote(action, price)
    assert quoted.status_code == 202, quoted.text
    view = s.client.get(f"/v2/agora/human-actions/{action['request_index']}").json()["action"]
    return view, leaf_index(quoted)


def _task(s: Scene, **kwargs: Any) -> dict[str, Any]:
    made = s.owner.task(**kwargs)
    assert made.status_code == 202, made.text
    return s.client.get(f"/v2/tasks/{leaf_index(made)}").json()["task"]


def _intent(s: Scene) -> dict[str, Any]:
    made = s.alice.intent("base-usdc", 1)
    assert made.status_code == 201, made.text
    return made.json()


def _r_malformed(s):
    response = s.alice.grant(s.bob.kid, 1, overrides={"owner_kid": s.bob.kid})  # owner_kid must be the signer
    return Refused(response, s.attempt(response, s.alice), None)


def _r_bad_signature(s):
    response = s.alice.rotate(Signer(), sign_new=Signer())  # sig_new by a key other than the new one
    return Refused(response, s.attempt(response, s.alice), None)


def _r_expired(s):
    created = int(time.time()) - 301
    response, env, _, _ = submit_entry(s.client, s.alice.signer, post_payload(s.origin), POST_BODY, created=created,
                                       expires=created + 300)
    return Refused(response, env, None)


def _r_future(s):
    created = int(time.time()) + 120
    response, env, _, _ = submit_entry(s.client, s.alice.signer, post_payload(s.origin), POST_BODY, created=created,
                                       expires=created + 60)
    return Refused(response, env, None)


def _r_replay(s):
    posted = s.alice.post()
    return Refused(replay(s.client, s.alice.signer), s.last(s.alice), leaf_index(posted))


def _r_unknown_key(s):
    q = {"type": "tombstone", "origin": s.origin, "target_index": 0, "reason_code": "order", "evidence_hash": None,
         "receipt_hash": None}
    response, env, _, _ = submit_entry(s.client, s.alice.signer, q)  # a policy-actor type, signed by an agent
    return Refused(response, env, None)


def _r_revoked(s):
    leaver = s.make_agent("leaver")
    assert leaver.revoke().status_code == 202
    response = leaver.post()
    return Refused(response, s.attempt(response, leaver), leaver.head_index)


def _r_sequence(s):
    claim = s.alice.head_index
    previous = s.last(s.alice)
    response, env, _, _ = submit_entry(s.client, s.alice.signer, post_payload(s.origin), POST_BODY,
                                       chain={"seq": previous["protected"]["seq"] + 2, "prev": envelope.envelope_hash(previous)})
    return Refused(response, env, claim)  # the last accepted envelope of this key


def _r_predecessor(s):
    response = s.alice.rotate_x25519(prev=0)  # leaf 0 is no event of this name, and nothing follows it
    return Refused(response, s.attempt(response, s.alice), s.alice.head_index)


def _r_name_taken(s):
    other = Agent(s.client, s.origin)
    response = other.claim("alice")
    return Refused(response, s.attempt(response, other), s.alice.head_index)


def _r_key_reuse(s):
    again = Agent(s.client, s.origin, signer=s.alice.signer)
    response = again.claim("alice-again")
    return Refused(response, s.attempt(response, again), s.alice.head_index)


def _r_key_fork(s):
    claim = s.alice.head_index
    assert s.alice.rotate(Signer()).status_code == 202
    first = s.alice.head_index
    response = s.alice.rotate(Signer(), prev=claim)
    return Refused(response, s.attempt(response, s.alice), first)


def _r_stale_key(s):
    old = s.alice.signer
    assert s.alice.rotate(Signer()).status_code == 202
    stale = Agent(s.client, s.origin, signer=old)
    response = stale.post()
    return Refused(response, s.attempt(response, stale), s.alice.head_index)


def _r_stale_grant(s):
    first = s.bob.grant(s.alice.kid, 1)
    assert first.status_code == 202
    response = s.bob.grant(s.alice.kid, 2, overrides={"prev_grant_index": None})
    return Refused(response, s.attempt(response, s.bob), leaf_index(first))


def _r_stale_capsule(s):
    assert s.alice.put_capsule("slot", "first").status_code == 202
    head = s.alice.capsule_heads[(s.alice.kid, "slot")]
    response = s.alice.put_capsule("slot", "second", overrides={"prev_capsule_index": None})
    return Refused(response, s.attempt(response, s.alice), head)


def _r_already_voted(s):
    poll = leaf_index(s.alice.poll())
    first = s.bob.vote(poll, 0)
    assert first.status_code == 202
    response = s.bob.vote(poll, 1)
    return Refused(response, s.attempt(response, s.bob), leaf_index(first))


def _r_poll_closed(s):
    closes = int(time.time()) + 5
    poll = leaf_index(s.alice.poll(closes=closes))
    s.frozen_clock(closes)  # the vote's t is the poll's closes: votes must precede it
    response = s.bob.vote(poll, 0, created=closes)
    return Refused(response, s.attempt(response, s.bob), poll)


def _r_poll_constraint(s):
    poll = leaf_index(s.alice.poll(pow_bits=8))
    response = s.bob.vote(poll, 0)  # no proof of work
    return Refused(response, s.attempt(response, s.bob), poll)


def _r_too_large(s):
    response = s.alice.post(body="x" * 32800)
    return Refused(response, s.attempt(response, s.alice), None)


def _r_digest_mismatch(s):
    response = s.alice.post(raw=post_body("Other", "Not the bytes the payload names.", "general"))
    return Refused(response, s.attempt(response, s.alice), None)


def _r_no_consent(s):
    response = s.alice.send_dm(s.alice.lookup("bob"), "a closed inbox")
    return Refused(response, s.alice.last_dm["envelope"], None)


def _r_grant_exhausted(s):
    granted = s.bob.grant(s.alice.kid, 1)
    assert s.alice.send_dm(s.alice.lookup("bob"), "one").status_code == 202
    response = s.alice.send_dm(s.alice.lookup("bob"), "two")
    return Refused(response, s.alice.last_dm["envelope"], leaf_index(granted))


def _r_unsupported_scheme(s):
    response = s.alice.send_dm(s.alice.lookup("bob"), ciphertext=b"cleartext " * 8, encryption="cleartext-signed")
    return Refused(response, s.alice.last_dm["envelope"], None)


def _r_suspended(s):
    suspension = s.owner.suspend(s.alice.kid, "order")
    assert suspension.status_code == 201
    response = s.alice.post()
    return Refused(response, s.attempt(response, s.alice), leaf_index(suspension))


def _r_frozen(s):
    freeze = s.owner.freeze()
    assert freeze.status_code == 201
    response = s.alice.post()
    return Refused(response, s.attempt(response, s.alice), leaf_index(freeze))


def _r_rate_limit(s):
    client, oob = s.own_log(writes={"count": 2, "interval_seconds": 60})
    agent = Agent(client, client.get("/v2/tlog/checkpoint").json()["origin"])
    assert agent.claim("alice").status_code == 202
    assert [agent.post(title=f"post {n}").status_code for n in range(2)] == [202, 202]
    response = agent.post(title="one too many")
    return Refused(response, s.attempt(response, agent), None, client, oob)


def _r_quota(s):
    client, oob = s.own_log(capsule_quota_bytes=65536)
    agent = Agent(client, client.get("/v2/tlog/checkpoint").json()["origin"])
    assert agent.claim("alice").status_code == 202
    assert agent.put_capsule("one", "x" * 40000).status_code == 202
    response = agent.put_capsule("two", "y" * 40000)  # the free quota holds one, not both
    return Refused(response, agent.last_capsule["envelope"], None, client, oob)


def _r_tier_required(s):
    identity = secret_claim(s.client, "plain", "S" * 40)
    text = secret_post(identity, post_body("A request", "Asked by an unverified identity.", "owner-actions"))
    post = json.loads(artifacts(text)["entry"])
    index = int(re.search(r"ok post at leaf (\d+)", text).group(1))
    response = s.owner.quote({"request_hash": leaf_hash(J(post)).hex()}, 5)
    return Refused(response, s.attempt(response, s.owner), index)


def _r_secret_format(s):
    response = s.alice.post(title="A leak", body=f"key {LEAKED_KEY}")
    return Refused(response, s.attempt(response, s.alice), None)


def _r_insufficient_balance(s):
    response = s.alice.spend("hosting", 5)
    return Refused(response, s.attempt(response, s.alice), None)  # no credit or spend yet


def _r_not_requester(s):
    action, _ = _owner_market(s)
    assert s.owner.complete(action).status_code == 202
    action = s.client.get(f"/v2/agora/human-actions/{action['request_index']}").json()["action"]
    response = s.bob.pay(action)
    return Refused(response, s.attempt(response, s.bob), action["request_index"])


def _r_owner_action_closed(s):
    action, _ = _owner_market(s)
    completed = s.owner.complete(action)
    assert completed.status_code == 202
    response = s.owner.quote(action, 7)
    return Refused(response, s.attempt(response, s.owner), leaf_index(completed))


def _r_stale_quote(s):
    action, first = _owner_market(s, 5)
    second = s.owner.quote(action, 6)
    assert second.status_code == 202
    response = s.owner.complete(action, quote_index=first, amount=5)
    return Refused(response, s.attempt(response, s.owner), leaf_index(second))


def _r_task_closed(s):
    task = _task(s, max_awards=1)
    carol = s.make_agent("carol")
    works = [agent.post(title="Work", body="Done.", channel="tasks") for agent in (s.alice, carol)]
    awarded = s.owner.award(task, leaf_index(works[0]), s.alice.kid)
    assert awarded.status_code == 202
    response = s.owner.award(task, leaf_index(works[1]), carol.kid)
    return Refused(response, s.attempt(response, s.owner), leaf_index(awarded))


def _r_already_awarded(s):
    task = _task(s, max_awards=2)
    work = s.alice.post(title="Work", body="Done.", channel="tasks")
    awarded = s.owner.award(task, leaf_index(work), s.alice.kid)
    assert awarded.status_code == 202
    response = s.owner.award(task, leaf_index(work), s.alice.kid)
    return Refused(response, s.attempt(response, s.owner), leaf_index(awarded))


def _r_amount_mismatch(s):
    task = _task(s, reward=20)
    work = s.alice.post(title="Work", body="Done.", channel="tasks")
    response = s.owner.award(task, leaf_index(work), s.alice.kid, amount=19)
    return Refused(response, s.attempt(response, s.owner), task["task_index"])


def _r_bad_reference(s):
    post = leaf_index(s.alice.post())
    response = s.alice.spend("owner_action", 1, ref_index=post)  # a post is no owner-action completion
    return Refused(response, s.attempt(response, s.alice), post)


def _r_not_offered(s):
    response = s.alice.spend("storage", 1, nbytes=1024)  # this log offers no storage
    return Refused(response, s.attempt(response, s.alice), None)


def _r_already_credited(s):
    intent = _intent(s)
    tx = base_tx(0xC0FFEE)
    s.chain["base-usdc"].transfers[tx] = (intent["units"], int(time.time()) + 5)
    credited = s.alice.claim_contribution(intent["intent_id"], tx)
    assert credited.status_code == 201, credited.text
    response = s.alice.claim_contribution(intent["intent_id"], tx)
    return Refused(response, {"intent_id": intent["intent_id"], "tx_hash": tx}, credited.json()["credit"]["credit_index"])


def _r_payment_not_verified(s):
    intent = _intent(s)
    tx = base_tx(0xBAD)
    s.chain["base-usdc"].transfers[tx] = (intent["units"] + 1, int(time.time()) + 5)  # other units
    response = s.alice.claim_contribution(intent["intent_id"], tx)
    return Refused(response, {"intent_id": intent["intent_id"], "tx_hash": tx}, None)


def _r_intent_expired(s):
    intent = _intent(s)
    tx = base_tx(0x1A7E)
    s.chain["base-usdc"].transfers[tx] = (intent["units"], int(time.time()) + 5)
    late = intent["claim_until"] + 1
    s.frozen_clock(late)
    response = s.alice.claim_contribution(intent["intent_id"], tx, created=late)
    return Refused(response, {"intent_id": intent["intent_id"], "tx_hash": tx}, None)


def _r_gate_secret_format(s):
    line = Line(s.client)
    gate_select(line, s.alice.signer)
    body = post_body("A leak at the gate", f"key {LEAKED_KEY}", "general")
    unsigned = gate_u(s.alice.signer, "post", post_q(body), session=line.sid, origin=s.origin)
    command = gate_command(line, unsigned, body)
    signature = s.alice.signer.key.sign(signing_input(line.sid, command))
    return Refused(line.send("sig " + B(signature)), {**unsigned, "sig": U(signature)}, None)


#: ``(id, expected reason_code, expected status (None at the gate), scenario)``: one refusal per published rule.
REFUSALS = [
    ("malformed", "malformed", 400, _r_malformed),
    ("bad_signature", "bad_signature", 403, _r_bad_signature),
    ("expired", "expired", 401, _r_expired),
    ("future", "future", 401, _r_future),
    ("replay", "replay", 409, _r_replay),
    ("unknown_key", "unknown_key", 403, _r_unknown_key),
    ("revoked", "revoked", 409, _r_revoked),
    ("sequence", "sequence", 409, _r_sequence),
    ("predecessor", "predecessor", 409, _r_predecessor),
    ("name_taken", "name_taken", 409, _r_name_taken),
    ("key_reuse", "key_reuse", 409, _r_key_reuse),
    ("key_fork", "key_fork", 409, _r_key_fork),
    ("stale_key", "stale_key", 409, _r_stale_key),
    ("stale_grant", "stale_grant", 409, _r_stale_grant),
    ("stale_capsule", "stale_capsule", 409, _r_stale_capsule),
    ("already_voted", "already_voted", 409, _r_already_voted),
    ("poll_closed", "poll_closed", 409, _r_poll_closed),
    ("poll_constraint", "poll_constraint", 422, _r_poll_constraint),
    ("too_large", "too_large", 413, _r_too_large),
    ("digest_mismatch", "digest_mismatch", 422, _r_digest_mismatch),
    ("rate_limit", "rate_limit", 429, _r_rate_limit),
    ("quota", "quota", 403, _r_quota),
    ("no_consent", "no_consent", 403, _r_no_consent),
    ("grant_exhausted", "grant_exhausted", 403, _r_grant_exhausted),
    ("suspended", "suspended", 403, _r_suspended),
    ("frozen", "frozen", 409, _r_frozen),
    ("tier_required", "tier_required", 403, _r_tier_required),
    ("unsupported_scheme", "unsupported_scheme", 422, _r_unsupported_scheme),
    ("secret_format", "secret_format:github_token", 422, _r_secret_format),
    ("insufficient_balance", "insufficient_balance", 409, _r_insufficient_balance),
    ("not_requester", "not_requester", 403, _r_not_requester),
    ("owner_action_closed", "owner_action_closed", 409, _r_owner_action_closed),
    ("stale_quote", "stale_quote", 409, _r_stale_quote),
    ("task_closed", "task_closed", 409, _r_task_closed),
    ("already_awarded", "already_awarded", 409, _r_already_awarded),
    ("amount_mismatch", "amount_mismatch", 422, _r_amount_mismatch),
    ("bad_reference", "bad_reference", 422, _r_bad_reference),
    ("not_offered", "not_offered", 422, _r_not_offered),
    ("already_credited", "already_credited", 409, _r_already_credited),
    ("payment_not_verified", "payment_not_verified", 422, _r_payment_not_verified),
    ("intent_expired", "intent_expired", 409, _r_intent_expired),
    ("gate_secret_format", "secret_format:github_token", None, _r_gate_secret_format),
]


class TestG4EveryRefusalIsEvidence:
    """AICS-1 section 10.2: an authenticated submission that fails a published rule is a policy-signed ``refusal``
    leaf with its registered code, naming the attempt by hash and by its authenticated ``(kid, nonce, expires)``,
    the conflict it rests on, and with a receipt the pinned log key signs.  One scenario per rule."""

    @pytest.mark.parametrize(("code", "status", "scenario"), [r[1:] for r in REFUSALS], ids=[r[0] for r in REFUSALS])
    def test_the_refusal_leaf(self, client, origin, oob, owner, chain, make_agent, monkeypatch, tmp_path, code, status,
                              scenario):
        scene = Scene(client, origin, oob, owner, chain, make_agent, monkeypatch, tmp_path)
        result = scenario(scene)
        log, pinned = result.client or client, result.oob or oob
        # The answer: the refusal entry and its receipt (POST /v2/entries: {entry, receipt_note} with a 4xx; a
        # contribution claim: the refusal in its error detail; the gate: entry and receipt data lines).
        if status is None:
            text = result.response
            assert text.startswith(f"err {code} "), text
            found = artifacts(text)
            entry, receipt = json.loads(found["entry"]), found["receipt"]
        else:
            response = result.response
            assert response.status_code == status, (code, response.status_code, response.text)
            data = response.json()
            if "detail" in data:
                assert data["detail"]["error"] == code
                entry, receipt = data["detail"]["refusal"]["entry"], keys.b64u_decode(data["detail"]["refusal"]["receipt_note"])
            else:
                assert set(data) == {"entry", "receipt_note"}, data
                entry, receipt = data["entry"], keys.b64u_decode(data["receipt_note"])
        # Policy-signed, with a registered code (AICS-1 sections 5.1 and 17.2, 20.8).
        q = pinned.policy_statement(entry)
        assert entry["type"] == "refusal" and q["reason_code"] == code
        card = log.get("/.well-known/aics-card.json").json()
        patterns = {p["id"] for p in card["secret_patterns"]}
        assert code in BASE_REFUSAL_CODES | SUP_REFUSAL_CODES or (
            code.startswith("secret_format:") and code.split(":", 1)[1] in patterns)
        # The attempt: by hash, and by the tuple it authenticated with (never by an unverified assertion).
        if isinstance(result.attempt, dict) and "protected" in result.attempt:
            p = result.attempt["protected"]
            assert q["envelope_hash"] == envelope.envelope_hash(result.attempt) and q["request_hash"] is None
            assert (q["attempt_kid"], q["attempt_nonce"], q["attempt_expires"]) == (p["kid"], p["nonce"], p["expires"])
        else:
            # A contribution claim names its request by a keyed hash of the content, never the plain one (20.6).
            content = canonicalize(result.attempt)
            assert q["envelope_hash"] == q["request_hash"] and re.fullmatch(r"[0-9a-f]{64}", q["request_hash"])
            assert q["request_hash"] != sha256(content)
            assert q["attempt_kid"] == scene.alice.kid and envelope.is_canonical_nonce(q["attempt_nonce"])
        # The conflict the decision rests on (section 10.2), an earlier leaf.
        if result.conflict is not ...:
            assert q["conflict_index"] == result.conflict, (code, q["conflict_index"], result.conflict)
        if code in CONFLICT_CODES:
            assert q["conflict_index"] is not None
        # No refused body is kept on the leaf: only hashes and identifiers (the schema is section 5.3's, exactly).
        assert set(q) == {"envelope_hash", "request_hash", "attempt_kid", "attempt_nonce", "attempt_expires",
                          "reason_code", "conflict_index", "receipt_hash"}
        # Its receipt: a note the pinned log key signs, promising exactly this leaf (section 10.1).
        note = parse_note(receipt)
        assert verify_note(note, [pinned.log_vkey])
        promise = json.loads(note.text)
        assert note.text == canonicalize(promise).decode() + "\n"
        assert promise == {"origin": pinned.origin, "entry_hash": leaf_hash(J(entry)).hex(), "submitted_at": entry["ts"],
                           "mmd_seconds": 60}
        # And the log holds it: the same bytes at its index under the signed head, provable from the tiles.
        audit = Audit(log, pinned)
        head = audit.head()
        index = log.get(f"/v2/tlog/index/{promise['entry_hash']}").json()["index"]
        assert audit.entries(head)[index] == J(entry)
        audit.assert_included(J(entry), index, head)
        if q["conflict_index"] is not None:
            assert q["conflict_index"] < index

    def test_every_code_this_server_writes_has_a_scenario(self):
        from aics_server.db import REFUSAL_REASONS as WRITTEN, SUP_REFUSAL_REASONS as SUP_WRITTEN

        covered = {code.split(":")[0] for _, code, _, _ in REFUSALS}
        assert set(WRITTEN) | set(SUP_WRITTEN) | {"secret_format"} == covered
        assert set(WRITTEN) <= BASE_REFUSAL_CODES and set(SUP_WRITTEN) == SUP_REFUSAL_CODES


# ---------------------------------------------------------------------------
# G5  Single view (promised: no witness outside this operator yet)
# ---------------------------------------------------------------------------


class TestG5SingleView:
    """Promised at launch.  What the server does today: one signed head, the same bytes at every address and in
    every reply, and envelopes that may carry the checkpoint their sender verified, so agents can compare views."""

    def test_one_signed_head_at_every_address_and_in_every_reply(self, client, oob, make_agent):
        alice = make_agent("alice")
        index = leaf_index(alice.post())
        head = Audit(client, oob).head()
        assert Audit(client, oob).head("/tiles/checkpoint") == head
        assert client.get("/v2/tlog/checkpoint").json()["signed_checkpoint"].encode("utf-8") == head.note
        assert keys.b64u_decode(client.get(f"/v2/entries/{index}").json()["checkpoint_note"]) == head.note
        assert keys.b64u_decode(client.get(f"/v2/inbox/{alice.kid}").json()["checkpoint_note"]) == head.note
        assert keys.b64u_decode(client.get("/v2/names/alice").json()["checkpoint_note"]) == head.note
        assert client.get("/", params={"format": "json"}).json()["checkpoint"].encode("utf-8") == head.note
        assert client.get("/v2/agora/posts").headers["X-AICS-Checkpoint"] == f"{head.size} {head.root.hex()}"
        line = Line(client)
        line.send()
        assert artifacts(line.send(f"read {index}"))["checkpoint"] == head.note
        # Promised, not proven: the card says so and names no witness.
        card = client.get("/.well-known/aics-card.json").json()
        status = {row["id"]: row["status"] for row in card["assurances"]}
        assert status["G5"] == "promised" and card["witness_policy"] == {"quorum": 0, "witnesses": []}

    def test_an_envelope_carries_the_checkpoint_its_sender_verified(self, client, oob, make_agent):
        alice = make_agent("alice")
        audit = Audit(client, oob)
        head = audit.head()  # alice verifies this head; bob, elsewhere, saves the same one
        bob_saved = audit.head()
        seen = envelope.seen_from_checkpoint(head.note)
        assert seen == {"checkpoint_note_hash": sha256(head.note), "size": head.size}
        response, _, _, _ = submit_entry(
            client, alice.signer, post_payload(alice.origin), POST_BODY,
            chain={**envelope.next_chain(alice.signer.last_envelope), "seen": seen},
        )
        assert response.status_code == 202, response.text
        leaf = audit.leaves(audit.head())[leaf_index(response)]
        logged = leaf["payload"]["envelope"]["protected"]["seen"]
        assert logged == seen  # the leaf commits, under alice's signature, to the head she saw
        signed_by(leaf["payload"]["envelope"], alice.signer.public)
        # Bob compares it with the note he saved: the same view.
        assert logged == envelope.seen_from_checkpoint(bob_saved.note)
        # What a split looks like: another note for the same size, also signed by the log key.  Held next to
        # alice's leaf it is proof, because the hash she logged names a different note.
        db = client.app.state.db
        forked = sign_checkpoint(Checkpoint(oob.origin, head.size, bytes(32)), db.server_key, oob.origin).to_bytes()
        assert verify_checkpoint(parse_note(forked), oob.log_vkey, expected_origin=oob.origin).ok
        other = envelope.seen_from_checkpoint(forked)
        assert other["size"] == logged["size"] and other["checkpoint_note_hash"] != logged["checkpoint_note_hash"]


# ---------------------------------------------------------------------------
# G6  Private content
# ---------------------------------------------------------------------------


class TestG6PrivateContent:
    """Only the recipient's key reads a direct message; the server holds ciphertext only, refuses cleartext, binds
    the leaf to the recipient key in the logged chain, and never reads or scans a private body."""

    def test_a_cleartext_dm_is_refused(self, client, oob, make_agent, tmp_path):
        make_agent("bob", initial_grant=open_grant())
        alice = make_agent("alice")
        to = alice.lookup("bob")
        plaintext = b"Meet me at the usual place; this text is not encrypted at all."
        refusals = [
            ("cleartext-signed", "unsupported_scheme"),
            ("none", "unsupported_scheme"),
            ("aes-256-gcm", "unsupported_scheme"),
            ("age-v1", "malformed"),  # the bytes are not an age file either
        ]
        for scheme, code in refusals:
            response = alice.send_dm(to, ciphertext=plaintext, encryption=scheme)
            assert response.status_code == 422, (scheme, response.text)
            assert reason(response) == code
            assert oob.policy_statement(entry_of(response))["reason_code"] == code
        assert client.get(f"/v2/inbox/{to['kid']}").json()["count"] == 0
        assert plaintext not in all_file_bytes(tmp_path)
        # There is no plaintext field to fill beside the ciphertext either: the request is exactly {envelope, body}.
        beside = alice.send_dm(to, "hi", extra_fields={"subject": "a plaintext subject"})
        assert beside.status_code == 400 and reason(beside) == "malformed"

    def test_the_server_holds_only_the_ciphertext_sealed_to_the_logged_key(self, client, oob, make_agent, tmp_path):
        bob = make_agent("bob", initial_grant=open_grant())
        alice = make_agent("alice")
        to = alice.lookup("bob")  # the API's answer, checked against the leaf it cites
        audit = Audit(client, oob)
        leaves = audit.leaves(audit.head())
        key_leaf = leaves[to["x25519_leaf_index"]]
        assert key_leaf["type"] == "name.claim" and key_leaf["actor_kid"] == to["kid"] == bob.kid
        assert key_leaf["payload"]["x25519"] == to["x25519_public_key_b64u"] == bob.x25519_b64u

        plaintext = "The plan is in capsule seven."
        response = alice.send_dm(to, plaintext)
        assert response.status_code == 202, response.text
        index = leaf_index(response)
        ciphertext = alice.last_dm["ciphertext"]
        leaf = audit.leaves(audit.head())[index]
        payload = leaf["payload"]
        # The leaf commits to exactly the bytes alice sealed, cites the leaf of the key she sealed to, and nothing else.
        assert set(payload) == {
            "envelope", "to_kid", "to_key_leaf_index", "encryption", "eph_pk", "ct_hash", "size", "seq", "prev",
            "grant_index",
        }
        assert payload["grant_index"] == bob.head_index  # the open initial grant in bob's claim
        assert (payload["ct_hash"], payload["size"]) == (sha256(ciphertext), len(ciphertext))
        assert payload["to_key_leaf_index"] == to["x25519_leaf_index"] and payload["encryption"] == sealed.SCHEME
        assert signed_by(payload["envelope"], alice.signer.public)["ct_hash"] == payload["ct_hash"]
        # The recipient gets those bytes back unchanged, and only its key opens them, against the signed envelope.
        message = bob.get("/v2/inbox").json()["messages"][0]
        assert keys.b64u_decode(message["ciphertext"]) == ciphertext
        assert sealed.open_sealed(ciphertext, bob.x25519, envelope=payload["envelope"], recipient_kid=bob.kid).text == plaintext
        with pytest.raises(sealed.SealedError):
            sealed.open_sealed(ciphertext, sealed.generate_x25519_key(), envelope=payload["envelope"])
        assert plaintext.encode("utf-8") not in all_file_bytes(tmp_path)
        # Once bob replaces his encryption key, a message sealed to the old one is refused, not delivered.
        assert bob.rotate_x25519().status_code == 202
        stale = alice.send_dm(to, "sealed to a key bob no longer holds")
        assert stale.status_code == 409 and reason(stale) == "stale_key"

    def test_private_bodies_are_never_scanned(self, client, make_agent):
        make_agent("bob", initial_grant=open_grant())
        alice = make_agent("alice")
        text = "ghp_" + "Q7w9zXb2nRmKdVcLpA8sYhUjE3fG6oT1" * 2  # base64url text that spells a key format
        raw = keys.b64u_decode(text)
        assert keys.b64u_encode(raw) == text and len(raw) >= sealed.SEAL_OVERHEAD
        # As ciphertext it is opaque bytes: accepted, unread.  As public text it is a leaked key: refused.
        assert alice.send_dm(alice.lookup("bob"), ciphertext=raw).status_code == 202
        refused = alice.post(title="A note", body=text)
        assert refused.status_code == 422 and reason(refused) == "secret_format:github_token"


# ---------------------------------------------------------------------------
# G7  Code transparency (promised)
# ---------------------------------------------------------------------------


class TestG7CodeTransparency:
    """Promised: nothing proves the running code yet.  The server serves its client byte for byte (so its digest
    can be compared with the public repository), keeps ``release`` an entry type, and the card says promised."""

    def test_the_client_is_served_byte_for_byte_and_the_card_does_not_claim_more(self, client):
        source = (PACKAGE / "static" / "aics_client.py").read_bytes()
        served = client.get("/static/aics_client.py")
        assert served.status_code == 200 and served.content == source
        assert sha256(served.content) == sha256(source)
        assert "release" in ENTRY_TYPES
        card = client.get("/.well-known/aics-card.json").json()
        assert {row["id"]: row["status"] for row in card["assurances"]}["G7"] == "promised"


# ---------------------------------------------------------------------------
# G8  Verification survives us
# ---------------------------------------------------------------------------


class TestG8VerificationSurvivesUs:
    """A bundle verifies offline with only the out-of-band keys; a copy of the tiles keeps the log checkable."""

    def test_a_bundle_verifies_offline_after_the_service_is_gone(self, client, oob, make_agent, tmp_path, db_path):
        make_agent("bob", initial_grant=open_grant())
        alice = make_agent("alice")
        body = "A public post that should outlive the service."
        posted = alice.post(title="Kept", body=body)
        sent = alice.send_dm(alice.lookup("bob"), "private, and still provable")
        post, dm = posted.json(), sent.json()
        indices = {"post": leaf_index(posted), "dm": leaf_index(sent)}
        ciphertext = alice.last_dm["ciphertext"]
        audit = Audit(client, oob)
        head = audit.head()
        reader = audit.reader(head)
        # The post's body is bound by its body_hash and size (AICS-1 sections 5.3 and 14.3), like a DM's by ct_hash.
        exact = post_body("Kept", body, "general")
        assert post["entry"]["payload"]["body_hash"] == sha256(exact) and post["entry"]["payload"]["size"] == len(exact)
        saved = {
            kind: bundle_from_tiles(
                reader, indices[kind], head.note, envelope=written["entry"]["payload"]["envelope"], body_or_ct=content,
            ).to_json()
            for kind, written, content in (("post", post, exact), ("dm", dm, ciphertext))
        }
        # The service hands out the same section 14.3 bundle (GET /v2/entries/{index}, AICS-1 section 12.1), its
        # body's status in a header beside it.
        for kind, index in indices.items():
            served = client.get(f"/v2/entries/{index}")
            assert served.headers["x-aics-body-status"] == "available"
            assert Bundle.from_json(served.content) == Bundle.from_json(saved[kind]), kind
        mirror = tmp_path / "mirror"
        shutil.copytree(client.app.state.db.tiles_dir, mirror)  # a mirror: availability, not trust
        # The service goes away: database, seed and tiles are deleted.
        shutil.rmtree(client.app.state.db.tiles_dir)
        for path in Path(db_path).parent.glob(Path(db_path).name + "*"):
            path.unlink()
        (Path(db_path).parent / "server_master.seed").unlink()

        log_key = read_vkey_file(oob.text)  # the out-of-band key file, nothing else
        for kind, text in saved.items():
            result = verify_bundle(Bundle.from_json(text), log_key, expected_origin=oob.origin)
            assert result.ok, (kind, result.error)
            assert result.envelope_bound_at and result.body_bound_at, kind
        tampered = Bundle.from_json(saved["dm"]).to_dict()
        tampered["body_or_ct"] = keys.b64u_encode(b"a different ciphertext")
        assert not verify_bundle(Bundle.from_dict(tampered), log_key, expected_origin=oob.origin).ok
        # The mirror alone reproduces the signed head, so anyone can keep checking from it.
        note = (mirror / "checkpoint").read_bytes()
        result = verify_checkpoint(parse_note(note), log_key, expected_origin=oob.origin)
        assert result.ok and (result.size, result.root) == (head.size, head.root)
        copy = VerifiedTileReader(FileSystemTileReader(mirror), head.size, head.root)
        assert tree_root_from_tiles(copy, head.size) == head.root
        assert read_entry(copy, indices["post"], head.size) == entry_bytes(post["entry"])


    def test_every_served_bundle_verifies_offline_with_aics_tlog(self, journey, tmp_path, capsys):
        """``GET /v2/entries/{index}`` for every entry of every type: the AICS-1 section 14.3 wire bundle verifies
        with aics-tlog's ``verify_bundle`` and its ``verify-bundle --offline`` command, given only the out-of-band
        key file; a bundle changed in any member does not."""
        oob, client = journey.oob, journey.client
        key_file = tmp_path / "pinned-keys.txt"  # the copy an agent keeps, obtained out of band
        key_file.write_text(oob.text, encoding="utf-8")
        log_key = read_vkey_file(oob.text)
        bodies = 0
        for index, raw in enumerate(journey.raw):
            served = client.get(f"/v2/entries/{index}")
            assert served.status_code == 200
            bundle = Bundle.from_json(served.content)
            assert keys.b64u_decode(served.json()["entry_bytes"]) == raw
            result = verify_bundle(bundle, log_key, expected_origin=oob.origin)
            assert result.ok, (index, result.error)
            assert result.aics1_entry and result.envelope_bound_at, index
            if served.json()["body_or_ct"] is not None:
                assert result.body_bound_at, index
                bodies += 1
            status = served.headers.get("x-aics-body-status")
            if status is not None and status.startswith("tombstoned"):
                assert served.json()["body_or_ct"] is None  # hidden: the bundle proves the leaf, not the body
        assert bodies >= 10  # posts, polls, a vote, a DM, a capsule, a task, the policy documents
        # The command-line verifier on a bundle of each entry type, offline, with the pinned key file only.
        first_of_type = {}
        for index, entry in enumerate(journey.entries):
            first_of_type.setdefault(entry["type"], index)
        for entry_type, index in sorted(first_of_type.items()):
            path = tmp_path / f"bundle-{index}.json"
            path.write_bytes(client.get(f"/v2/entries/{index}").content)
            capsys.readouterr()
            code = tlog_cli.main(["verify-bundle", "--bundle", str(path), "--offline", "--vkey-file", str(key_file)])
            report = json.loads(capsys.readouterr().out)
            assert code == 0 and report["ok"] and report["index"] == index and report["aics1_entry"], (entry_type, report)
        # Any member changed: refused by both.
        (dm_index,) = [i for i, e in enumerate(journey.entries) if e["type"] == "dm"]
        good = client.get(f"/v2/entries/{dm_index}").json()
        tampered = [
            {**good, "body_or_ct": keys.b64u_encode(b"another ciphertext")},
            {**good, "index": dm_index + 1},
            {**good, "envelope": {**good["envelope"], "sig": good["envelope"]["sig"][::-1]}},
            {**good, "entry_bytes": keys.b64u_encode(keys.b64u_decode(good["entry_bytes"]).replace(b'"dm"', b'"DM"'))},
            {**good, "inclusion_proof": good["inclusion_proof"][::-1] if len(good["inclusion_proof"]) > 1 else []},
        ]
        for n, bad in enumerate(tampered):
            assert not verify_bundle(Bundle.from_dict(bad), log_key, expected_origin=oob.origin).ok, n
            path = tmp_path / f"tampered-{n}.json"
            path.write_text(json.dumps(bad), encoding="utf-8")
            capsys.readouterr()
            assert tlog_cli.main(["verify-bundle", "--bundle", str(path), "--offline", "--vkey-file", str(key_file)]) != 0, n
            capsys.readouterr()

    def test_the_aics_cli_verifies_a_served_bundle_when_it_can(self, journey, tmp_path):
        """DESIGN.md G8 names ``aics verify message --bundle --offline``; run it when an aics CLI is installed.

        A bare bundle offline proves the checkpoint, the inclusion and the envelope but not the history through its
        index (AICS-1 section 14.3 step 2), so it is ``incomplete`` (exit 1).  With the log's tiles (a mirror copy,
        still offline) the first entry of every type verifies completely: the name, key, policy-authority, sequence,
        nonce and grant history the CLI replays from the authenticated prefix agrees with what the server accepted.
        """
        candidates = [shutil.which("aics"), str(PACKAGE.parents[2] / "aics-cli" / ".venv" / "bin" / "aics")]
        aics = next((c for c in candidates if c and Path(c).is_file()), None)
        if aics is None:
            pytest.skip("no aics CLI is installed here")
        probe = subprocess.run([aics, "verify", "message", "--json"], capture_output=True, text=True, timeout=60)
        report = json.loads(probe.stdout or "{}")
        if report.get("available") is False:
            pytest.skip(f"aics verify message is not available yet: {report.get('error')}")
        oob, home = journey.oob, {**os.environ, "AICS_HOME": str(tmp_path / "aics-home")}
        # Pin the out-of-band keys by hand (no network: no DNS, no card), then verify bundles offline.
        pinned = subprocess.run(
            [aics, "policy", "init", "--origin", oob.origin, "--log-vkey", oob.log_vkey_text, "--policy-kid",
             oob.policy_kid, "--owner-kid", oob.owner_kid, "--no-card", "--quorum", "0", "--require-sources", "1",
             "--json"],
            capture_output=True, text=True, timeout=60, env=home,
        )
        assert pinned.returncode == 0, pinned.stdout + pinned.stderr
        tiles = tmp_path / "mirror"
        shutil.copytree(journey.client.app.state.db.tiles_dir, tiles)

        def verify(index: int, *extra: str) -> tuple[int, dict]:
            path = tmp_path / f"bundle-{index}.json"
            path.write_bytes(journey.client.get(f"/v2/entries/{index}").content)
            done = subprocess.run([aics, "verify", "message", "--bundle", str(path), "--offline", "--json", *extra],
                                  capture_output=True, text=True, timeout=120, env=home)
            return done.returncode, json.loads(done.stdout)

        (dm_index,) = [i for i, e in enumerate(journey.entries) if e["type"] == "dm"]
        code, report = verify(dm_index)
        assert code == 1 and report["result"] == "incomplete", report
        assert {s["step"]: s["status"] for s in report["steps"]}["envelope"] == "valid"
        first_of_type: dict[str, int] = {}
        for index, entry in enumerate(journey.entries):
            first_of_type.setdefault(entry["type"], index)
        assert len(first_of_type) >= 15  # every base and SUP-1 type the journey writes
        for entry_type, index in sorted(first_of_type.items()) + [("the last entry", len(journey.entries) - 1)]:
            code, report = verify(index, "--tiles", str(tiles))
            assert code == 0 and report["result"] == "valid", (entry_type, index, report)


# ---------------------------------------------------------------------------
# G9  Reachability
# ---------------------------------------------------------------------------


class TestG9Reachability:
    """Inboxes start closed; only the recipient's key opens one, by signing grant leaves that name keys; the inbox
    is a filter over the log, so an agent can rebuild it from the tiles and compare it with what the API serves."""

    def test_an_inbox_is_closed_until_its_owner_signs_a_grant(self, client, oob, make_agent):
        alice, bob, mallory = make_agent("alice"), make_agent("bob"), make_agent("mallory")
        to = alice.lookup("bob")
        claim = Audit(client, oob).leaves(Audit(client, oob).head())[bob.head_index]
        assert claim["payload"]["initial_grant"] is None  # no grant exists until bob signs one
        closed = alice.send_dm(to, "may I write to you?")
        assert closed.status_code == 403 and reason(closed) == "no_consent"
        assert oob.policy_statement(entry_of(closed))["reason_code"] == "no_consent"
        # Nobody else can open bob's inbox for him, and grants name keys, never names.
        assert mallory.grant(alice.kid, 5, overrides={"owner_kid": bob.kid}).status_code == 400
        assert bob.grant("alice", 5).status_code == 400
        granted = bob.grant(alice.kid, 1)
        assert granted.status_code == 202
        grant = granted.json()["entry"]
        assert grant["actor_kid"] == bob.kid
        assert {k: grant["payload"][k] for k in ("owner_kid", "sender_kid", "max")} == {
            "owner_kid": bob.kid,
            "sender_kid": alice.kid,
            "max": 1,
        }
        assert alice.send_dm(to, "thank you").status_code == 202
        assert reason(alice.send_dm(to, "one more")) == "grant_exhausted"
        assert reason(mallory.send_dm(mallory.lookup("bob"), "and me?")) == "no_consent"
        assert client.get(f"/v2/inbox/{bob.kid}").json()["count"] == 1

    def test_the_inbox_rebuilt_from_the_tiles_matches_the_api(self, client, oob, make_agent):
        bob, alice, carol = make_agent("bob"), make_agent("alice"), make_agent("carol")
        to = alice.lookup("bob")
        assert bob.grant(alice.kid, 2).status_code == 202
        assert bob.grant("*", 1).status_code == 202
        outcomes = [alice.send_dm(to, f"from alice {n}").status_code for n in range(3)]
        outcomes += [carol.send_dm(carol.lookup("bob"), f"from carol {n}").status_code for n in range(2)]
        assert outcomes == [202, 202, 403, 202, 403]  # alice's own grant governs her; the wildcard admits one other

        head = Audit(client, oob).head()
        leaves = Audit(client, oob).leaves(head)
        grants: dict[str, dict[str, Any]] = {}
        delivered: list[int] = []
        for index, leaf in enumerate(leaves):
            payload = leaf["payload"]
            if leaf["type"] == "grant" and payload["owner_kid"] == bob.kid:
                verify_author(payload["envelope"], bob.signer.public)  # only bob's key grants for bob
                grants[payload["sender_kid"]] = {
                    "index": index, "max": payload["max"], "expires": payload["expires"], "used": 0,
                }
            elif leaf["type"] == "dm" and payload["to_kid"] == bob.kid:
                grant = grants.get(leaf["actor_kid"]) or grants.get("*")
                assert grant is not None, f"leaf {index} was delivered with no grant"
                # The dm leaf names its grant (AICS-1 section 5.3, grant_index): the one section 9's rule selects.
                assert payload["grant_index"] == grant["index"], f"leaf {index} cites another grant"
                assert grant["used"] < grant["max"] and leaf["ts"] <= grant["expires"], f"leaf {index} exceeds its grant"
                grant["used"] += 1
                delivered.append(index)
        assert len(delivered) == 3
        listing = client.get(f"/v2/inbox/{bob.kid}").json()
        # Stated at a signed checkpoint the agent verifies: the listing is comparable with the tiles at that size.
        assert keys.b64u_decode(listing["checkpoint_note"]) == head.note and listing["size"] == head.size
        assert listing["indices"] == delivered
        public = listing["messages"]
        assert [m["leaf_index"] for m in public] == delivered  # the API withholds nothing the log holds ...
        assert sorted(m["leaf_index"] for m in bob.get("/v2/inbox").json()["messages"]) == delivered
        assert all(m["grant_index"] in {g["index"] for g in grants.values()} for m in public)  # ... and adds nothing


# ---------------------------------------------------------------------------
# G10  Signed, logged assurance card
# ---------------------------------------------------------------------------


class TestG10SignedLoggedCard:
    """The card is signed with the policy key (JWS over JCS) and, once the owner logs it, its hash is a leaf."""

    def test_the_card_is_signed_by_the_pinned_policy_key_and_logged_by_its_hash(self, client, oob, owner):
        response = client.get("/.well-known/aics-card.json")
        document = response.content
        card = json.loads(document)
        assert document == canonicalize(card)  # the exact bytes J(card)
        assert jws_verifies(card, oob.policy_public)
        assert not jws_verifies(card, Signer().public)
        assert card["origin"] == oob.origin and card["log_vkey"] == oob.log_vkey_text
        assert card["policy_kid"] == oob.policy_kid and keys.is_did_key(card["policy_kid"])
        assert response.headers["x-aics-card-leaf"] == "none"  # not logged yet, and it says so

        logged = owner.policy_now(document.decode("utf-8"))
        assert logged.status_code == 201, logged.text
        index = logged.json()["policy"]["leaf_index"]
        audit = Audit(client, oob)
        head = audit.head()
        leaf = audit.leaves(head)[index]
        audit.assert_included(entry_bytes(leaf), index, head)
        statement = oob.policy_statement(leaf)
        assert leaf["type"] == "policy" and statement["kind"] == "card"
        assert statement["document_hash"] == sha256(document) == response.headers["x-aics-card-sha256"]
        served = client.get("/.well-known/aics-card.json")
        assert served.content == document and served.headers["x-aics-card-leaf"] == str(index)


# ---------------------------------------------------------------------------
# DESIGN.md section 12, week 1: the negative tests
# ---------------------------------------------------------------------------


class TestUnsignedWritesAreRefused:
    def test_every_write_route_verifies_a_signature_or_is_a_listed_keyless_door(self, client, make_agent):
        alice = make_agent("alice")
        signed = {(e["method"], e["path"]) for e in signed_endpoints(client.app)}
        size = tree_size(client)
        writes = set()
        for route in api_routes(client.app):
            for method in route.methods - {"GET", "HEAD"}:
                writes.add((method, route.path))
                if (method, route.path) in KEYLESS_WRITES:
                    continue
                assert (method, route.path) in signed, f"{method} {route.path} writes without verifying a signature"
                # Over HTTPS (as behind Caddy): a route that also takes a shared secret refuses plain HTTP first.
                response = https(client).request(method, fill(route.path), json={})
                assert response.status_code == 401, (method, route.path, response.text)
                assert reason(response) == "signature_required"
        assert KEYLESS_WRITES <= writes
        # One signed write path for every entry type (AICS-1 section 12.1).
        assert {(m, p) for m, p in writes if p == ENTRIES} == {("POST", ENTRIES)}
        # A valid envelope is not enough: the request itself must be signed.
        unsigned, _, _, _ = submit_entry(client, alice.signer, post_payload(alice.origin), POST_BODY, sign=False)
        assert unsigned.status_code == 401 and reason(unsigned) == "signature_required"
        assert tree_size(client) == size

    def test_the_gate_writes_nothing_without_the_signature_of_the_sessions_key(self, client, origin):
        line = Line(client)
        ivy = KeyAgent("ivy")
        onboard(line, ivy)
        size = tree_size(client)
        body = POST_BODY
        line.send(f"draft post {U(J(post_q(body)))}")
        unsigned = proposal(line.send(f"body {B(body)}"))
        command = f"post {U(J(unsigned))}"
        assert line.send(command).startswith("? Reply exactly: sig")
        assert line.send("who").startswith("ok who ivy")  # moving on instead of signing writes nothing
        assert line.send(command).startswith("? Reply exactly: sig")
        assert line.send(KeyAgent("ivy").sig(line.sid, command)).startswith("err bad_signature")  # another key
        assert line.send(command).startswith("? Reply exactly: sig")
        assert line.send(ivy.sig("another-session-id-0000", command)).startswith("err bad_signature")  # another session
        fetch_only = Line(client, get=True)
        fetch_only.send()
        assert fetch_only.send(command).startswith("err post_required")  # GET never writes
        assert tree_size(client) == size


class TestStaleEnvelopesAreRefused:
    """AICS-1 section 4.3 at the exact boundaries, at one submission time ``t`` the server fixes: ``created <= t + 30``,
    ``created >= t - 300``, ``created < expires <= created + 300`` and ``t < expires``.

    A fresh envelope is accepted with ``ts = t``; an authenticated one outside its window is a logged refusal
    (``future`` or ``expired``) naming its tuple, on both bindings; a validity window the envelope's own shape
    forbids is no envelope at all (``malformed``, no leaf).  Nothing refused advances the author's chain.
    """

    #: ``(created - t, expires - t, outcome)``.
    CASES = [
        (30, 330, "accepted"),  # the 30-second allowance for a clock running ahead, used up exactly
        (31, 331, "future"),
        (-299, 1, "accepted"),  # the oldest envelope still fresh: t < expires by one second
        (-300, 0, "expired"),  # created >= t - 300 holds, t < expires does not
        (-301, -1, "expired"),  # created < t - 300
        (-1, 0, "expired"),  # expires == t: the allowance is for creation only, never expiry
        (-1, 1, "accepted"),
        (0, 300, "accepted"),  # the longest lifetime
        (0, 301, "malformed"),  # one second longer: an authenticated attempt with a bad window, logged
        (-300, 1, "malformed"),  # the same, from the other end
        (0, 0, "malformed"),  # expires == created
    ]

    @pytest.mark.parametrize(("created", "expires", "outcome"), CASES)
    def test_post_v2_entries(self, client, oob, make_agent, monkeypatch, created, expires, outcome):
        alice = make_agent("alice")
        t = int(time.time())
        clock = {"now": t}
        monkeypatch.setattr(auth_module, "time", SimpleNamespace(time=lambda: clock["now"]))  # the binding fixes t once
        size, last = tree_size(client), alice.signer.last_envelope
        response, env, _, _ = submit_entry(
            client, alice.signer, post_payload(alice.origin), POST_BODY, created=t + created, expires=t + expires
        )
        if outcome == "accepted":
            assert response.status_code == 202, response.text
            entry = entry_of(response)
            assert entry["ts"] == t and entry["payload"]["envelope"] == env
            assert tree_size(client) == size + 1
            return
        # AICS-1 sections 4.3 and 10.2: every window and clock failure of an envelope whose signatures verified is a
        # decision on an authenticated submission, so a refusal leaf naming its tuple ("malformed" for a window
        # that is not created < expires <= created + 300, "expired"/"future" at t).
        assert response.status_code == (422 if outcome == "malformed" else 401), response.text
        assert reason(response) == outcome, response.text
        statement = oob.policy_statement(entry_of(response))
        p = env["protected"]
        assert (statement["attempt_kid"], statement["attempt_nonce"], statement["attempt_expires"]) == (
            alice.kid, p["nonce"], p["expires"])
        assert statement["envelope_hash"] == envelope.envelope_hash(env)
        assert tree_size(client) == size + 1
        # The author's chain did not move: the next fresh envelope takes the same seq.
        assert alice.signer.last_envelope == last
        clock["now"] = int(time.time())
        retry, retried, _, _ = submit_entry(client, alice.signer, post_payload(alice.origin), POST_BODY)
        assert retry.status_code == 202 and retried["protected"]["seq"] == env["protected"]["seq"]

    @pytest.mark.parametrize(("created", "expires", "outcome"), CASES)
    def test_the_gate(self, client, oob, make_agent, monkeypatch, created, expires, outcome):
        alice = make_agent("alice")
        gate = client.app.state.gate
        t = int(time.time())
        monkeypatch.setattr(gate, "clock", lambda: t)
        line = Line(client)
        gate_select(line, alice.signer)
        size = tree_size(client)
        unsigned = gate_u(alice.signer, "post", post_q(POST_BODY), session=line.sid, origin=alice.origin,
                          created=t + created, expires=t + expires)
        line.send(f"body {B(POST_BODY)}")
        command = text_command(unsigned)
        asked = line.send(command)
        if outcome != "accepted":
            # Refused when the command arrives, before anything is signed: nothing to log.
            assert asked.startswith(f"err {outcome} "), asked
            assert tree_size(client) == size
            return
        assert asked.startswith("? Reply exactly: sig"), asked
        text = line.send("sig " + B(alice.signer.key.sign(signing_input(line.sid, command))))
        assert re.search(r"ok post at leaf \d+", text), text
        entry = json.loads(artifacts(text)["entry"])
        assert entry["ts"] == t and tree_size(client) == size + 1

    def test_a_gate_command_that_goes_stale_before_its_signature_is_a_logged_refusal(self, client, oob, make_agent,
                                                                                     monkeypatch):
        """The signature arrives after ``expires``: the attempt authenticates, then fails freshness at its ``t``."""
        alice = make_agent("alice")
        gate = client.app.state.gate
        t = int(time.time())
        clock = {"now": t}
        monkeypatch.setattr(gate, "clock", lambda: clock["now"])
        line = Line(client)
        gate_select(line, alice.signer)
        unsigned = gate_u(alice.signer, "post", post_q(POST_BODY), session=line.sid, origin=alice.origin, created=t)
        command = gate_command(line, unsigned, POST_BODY)
        size = tree_size(client)
        clock["now"] = unsigned["protected"]["expires"]  # t == expires when the signature arrives
        signature = alice.signer.key.sign(signing_input(line.sid, command))
        text = line.send("sig " + B(signature))
        assert text.startswith("err expired "), text
        refusal = json.loads(artifacts(text)["entry"])
        statement = oob.policy_statement(refusal)
        p = unsigned["protected"]
        assert statement["reason_code"] == "expired"
        assert (statement["attempt_kid"], statement["attempt_nonce"], statement["attempt_expires"]) == (
            alice.kid, p["nonce"], p["expires"])
        assert statement["envelope_hash"] == envelope.envelope_hash({**unsigned, "sig": U(signature)})
        assert tree_size(client) == size + 1
        # That U is spent: sent again, it is turned down before any signature, and nothing more is logged.
        assert line.send(command).startswith("err expired ")
        assert tree_size(client) == size + 1
        # As POST /v2/entries refuses the same attempt: an authenticated stale envelope is one logged refusal.
        assert refusal["payload"]["envelope"]["protected"]["kid"] == oob.policy_kid


class TestReplayedNoncesAreRefused:
    def test_every_kind_of_signed_write_is_refused_when_replayed(self, client, oob, make_agent, owner, db_path, keys_file):
        bob = make_agent("bob", initial_grant=open_grant())
        alice = make_agent("alice")
        writes = [
            ("post", lambda: alice.post()),
            ("poll", lambda: alice.poll(**POLL)),
            ("grant", lambda: alice.grant(bob.kid, 3)),
            ("dm", lambda: alice.send_dm(alice.lookup("bob"), "sent once, only once")),
            ("capsule", lambda: alice.put_capsule("state", "stored once")),
            ("x25519.rotate", lambda: alice.rotate_x25519()),
        ]
        for kind, write in writes:
            response = write()
            assert response.status_code == 202, (kind, response.text)
            original = leaf_index(response)
            size = tree_size(client)
            again = replay(client, alice.signer)
            assert again.status_code == 409, (kind, again.text)
            assert reason(again) == "replay" and refusal_q(again)["conflict_index"] == original
            statement = oob.policy_statement(entry_of(again))
            assert statement["reason_code"] == "replay"
            assert (statement["attempt_kid"], statement["conflict_index"]) == (alice.kid, original)
            assert tree_size(client) == size + 1  # the refusal, nothing else
            third = replay(client, alice.signer)  # more copies: the same answer, no new leaf
            assert third.status_code == 409 and entry_of(third) == entry_of(again)
            assert tree_size(client) == size + 1
        # The owner's requests and an agent's signed reads cannot be replayed either; reads log nothing.
        target = leaf_index(alice.post())
        assert owner.tombstone(target, "illegal_on_notice").status_code == 201
        assert reason(replay(client, owner)) == "replay"
        assert alice.get("/v2/agents/me").status_code == 200
        size = tree_size(client)
        read_again = replay(client, alice.signer)
        assert read_again.status_code == 409 and read_again.json()["detail"]["refusal"] is None
        assert tree_size(client) == size
        # The record of used nonces survives a restart: it is rebuilt from the leaves.
        assert alice.post(title="Before the restart", body="A write the restarted server must remember.").status_code == 202
        restarted = TestClient(
            create_app(
                db_path=db_path, owner_public_key=owner.public_key_b64u, pubkeys_out=keys_file, announce=False,
                limits=TEST_LIMITS,
            )
        )
        assert reason(replay(restarted, alice.signer)) == "replay"

    def test_a_replayed_gate_command_is_a_logged_refusal(self, client, oob, origin):
        line = Line(client)
        sam = KeyAgent("sam")
        onboard(line, sam)
        grant = {"owner_kid": sam.kid, "sender_kid": "*", "max": 2,
                 "expires": int(time.time()) + 600, "prev_grant_index": None}
        command = command_of(line.send(f"draft grant {U(J(grant))}"))
        line.send(command)
        signature = sam.sig(line.sid, command)
        accepted = line.send(signature)
        assert "ok grant at leaf" in accepted
        original = int(re.search(r"ok grant at leaf (\d+)", accepted).group(1))
        size = tree_size(client)
        line.send(command)
        text = line.send(signature)
        assert text.startswith("err replay")
        refusal = json.loads(artifacts(text)["entry"])
        statement = oob.policy_statement(refusal)
        assert statement["reason_code"] == "replay" and statement["conflict_index"] == original
        assert statement["attempt_kid"] == sam.kid
        # The same envelope was receipted: the refusal names that receipt, and the promise stands (AICS-1 10.2).
        assert statement["receipt_hash"] == hashlib.sha256(artifacts(accepted)["receipt"]).hexdigest()
        assert statement["envelope_hash"] == envelope.envelope_hash(json.loads(artifacts(accepted)["entry"])["payload"]["envelope"])
        assert tree_size(client) == size + 1

    def test_a_nonce_is_spent_across_both_bindings(self, client, oob, make_agent):
        """One ``(kid, nonce)`` space per key (AICS-1 section 4.3): whichever binding used a nonce first, a new envelope
        with it on the other is a ``replay`` naming that leaf, with no receipt (it is another envelope)."""
        alice = make_agent("alice")
        line = Line(client)
        gate_select(line, alice.signer)
        # The gate first: a native envelope reusing its nonce is refused.
        body = post_body("Gate first", "This nonce is spent at the gate.", "general")
        reply = gate_write(line, alice.signer, gate_u(alice.signer, "post", post_q(body), session=line.sid,
                                                      origin=alice.origin), body)
        gate_index = int(re.search(r"ok post at leaf (\d+)", reply).group(1))
        spent = alice.signer.last_envelope["protected"]["nonce"]
        size = tree_size(client)
        response, env, _, _ = submit_entry(client, alice.signer, post_payload(alice.origin), POST_BODY, nonce=spent)
        assert response.status_code == 409 and reason(response) == "replay", response.text
        statement = oob.policy_statement(entry_of(response))
        assert (statement["conflict_index"], statement["receipt_hash"]) == (gate_index, None)
        assert statement["envelope_hash"] == envelope.envelope_hash(env) and statement["attempt_nonce"] == spent
        assert tree_size(client) == size + 1
        # The JSON API first: a gate command reusing its nonce is refused the same way.
        accepted, used, _, _ = submit_entry(client, alice.signer, post_payload(alice.origin), POST_BODY)
        assert accepted.status_code == 202
        size = tree_size(client)
        unsigned = gate_u(alice.signer, "post", post_q(body), session=line.sid, origin=alice.origin,
                          nonce=used["protected"]["nonce"])
        text = gate_write(line, alice.signer, unsigned, body)
        assert text.startswith("err replay"), text
        statement = oob.policy_statement(json.loads(artifacts(text)["entry"]))
        assert (statement["conflict_index"], statement["receipt_hash"]) == (leaf_index(accepted), None)
        assert tree_size(client) == size + 1
        # A third envelope with the same nonce is another submission: its own replay refusal (AICS-1 section 10.2),
        # citing the gate leaf that used the nonce; only the exact same request again adds nothing.
        again, third, raw, headers = submit_entry(client, alice.signer, post_payload(alice.origin), POST_BODY, nonce=spent)
        assert again.status_code == 409 and reason(again) == "replay" and entry_of(again) != entry_of(response)
        statement = oob.policy_statement(entry_of(again))
        assert (statement["conflict_index"], statement["envelope_hash"]) == (gate_index, envelope.envelope_hash(third))
        assert tree_size(client) == size + 2
        resent = client.post("/v2/entries", content=raw, headers=headers)
        assert resent.status_code == 409 and entry_of(resent) == entry_of(again) and tree_size(client) == size + 2


class TestOwnerOnlyEndpoints:
    def test_owner_only_endpoints_reject_every_signature_but_the_owners(self, client, make_agent, owner):
        alice = make_agent("alice")
        stranger = Signer()  # a key bound to nothing
        routes = sorted((e["method"], e["path"]) for e in signed_endpoints(client.app) if e["signer"] == "owner key")
        # Every administrative route and every route tagged for the owner needs the owner login.
        for route in api_routes(client.app):
            if route.path.startswith("/v2/admin/") or "owner" in route.tags:
                for method in route.methods:
                    assert (method, route.path) in routes, f"{method} {route.path} is not behind the owner login"
        # The owner's own entries (sup.task, sup.credit, owner-action reports) are native writes at POST /v2/entries,
        # signed by the owner key like any envelope (AICS-1 sections 12.1 and 20.5); what is left is administration.
        assert len(routes) >= 7 and all(path.startswith("/v2/admin/") for _, path in routes), routes
        size = tree_size(client)
        for method, path in routes:
            url = fill(path)
            body = {"body_override": b""} if method == "GET" else {"fields": {}}
            assert client.request(method, url, json=None if method == "GET" else {}).status_code == 401, path
            for signer in (alice.signer, stranger):
                response, _, _, _ = signed_request(client, signer, method, url, **body)
                assert response.status_code == 403, (path, response.text)
                assert reason(response) == "owner_only"
            # Another key's signature under the owner's key id does not verify.
            response, _, _, _ = signed_request(client, alice.signer, method, url, keyid=owner.kid, **body)
            assert response.status_code == 401 and reason(response) == "bad_signature", path
        assert tree_size(client) == size  # none of these attempts reached the log
        response, _, _, _ = signed_request(client, owner, "GET", "/v2/admin/notices", body_override=b"")
        assert response.status_code == 200  # the owner key itself is let in


class TestNoBearerPath:
    def test_no_route_accepts_or_issues_a_bearer_token(self, client, origin):
        alice = Agent(client, origin)
        claimed = alice.claim("alice")
        assert claimed.status_code == 202
        signed = {(e["method"], e["path"]) for e in signed_endpoints(client.app)}
        token = {"Authorization": "Bearer aics_live_" + "A" * 40}
        secure = https(client)
        for route in api_routes(client.app):
            for method in sorted(route.methods - {"HEAD"}):
                url = fill(route.path)
                content = None if method == "GET" else b"{}"
                headers = {} if method == "GET" else {"Content-Type": "application/json"}
                plain = secure.request(method, url, content=content, headers=headers)
                with_token = secure.request(method, url, content=content, headers={**headers, **token})
                assert with_token.status_code == plain.status_code, (method, route.path)
                if (method, route.path) in signed:
                    assert reason(with_token) == "signature_required", (method, route.path)
        schema = client.get("/openapi.json").json()
        assert "securitySchemes" not in schema.get("components", {})
        for operations in schema["paths"].values():
            for operation in operations.values():
                assert "security" not in operation
                assert all(p.get("name", "").lower() != "authorization" for p in operation.get("parameters", []))

        def keys_of(value: Any) -> set[str]:
            if isinstance(value, dict):
                return set(value) | {k for v in value.values() for k in keys_of(v)}
            if isinstance(value, list):
                return {k for v in value for k in keys_of(v)}
            return set()

        returned = keys_of(claimed.json())
        assert not {k for k in returned if re.search(r"token|bearer|api_key|password|secret", k, re.I)}, returned
        for module in sorted(PACKAGE.glob("*.py")):
            assert not re.search(r"""["']authorization["']""", module.read_text(encoding="utf-8"), re.I), module.name


class TestNoServerSideKeyGeneration:
    def test_no_request_gets_a_key_it_did_not_bring(self, client, origin):
        size = tree_size(client)
        for body in ({"name": "Legacy Agent", "handle": "legacy"}, {"name": "keyless", "generate_key": True}, {}):
            response = client.post(ENTRIES, json=body)
            assert response.status_code == 401 and reason(response) == "signature_required"
            assert "private" not in response.text.lower() and "seed" not in response.text.lower()
            assert client.post("/v2/agents/register", json=body).status_code == 404  # no registration route at all
        assert tree_size(client) == size
        # A claim logs exactly the keys the agent made, and no private material comes back from anything.
        alice = Agent(client, origin)
        claimed = alice.claim("alice")
        payload = entry_of(claimed)["payload"]
        assert (keys.did_key(keys.parse_public_key(payload["ed25519"])), payload["x25519"]) == (alice.kid, alice.x25519_b64u)
        replies = [
            claimed.text,
            alice.get("/v2/agents/me").text,
            client.get("/v2/names/alice").text,
            client.get(f"/v2/keys/{alice.kid}").text,
            client.get("/v2/ans/lookup/alice").text,
            client.get("/v2/tlog/checkpoint").text,
        ]
        for reply in replies:
            assert not re.search(r'"[a-z0-9_]*(private|seed|secret_key)[a-z0-9_]*"\s*:', reply), reply[:200]
        # At the gate an agent without a key tool is sent to a generator it trusts or to the fallback secret: the
        # gate makes no key and prints none.
        line = Line(client)
        line.send()
        assert line.send("tools none") == NONE_QUESTION + "\n>\n"
        assert not re.search(r"\bpub [A-Za-z0-9+/_-]{43}", NONE_QUESTION)

    def test_no_server_module_makes_a_key_or_signs_with_any_key_but_its_own(self):
        """Static check of the server package (the one-file client in static/ runs on the agent's machine)."""
        makers = {
            "generate", "generate_keypair", "generate_x25519_key", "generate_identity", "generate_private_key",
            "derive_x25519_key", "derive_agent_identity", "as_private_key", "from_private_bytes",
            "private_key_from_seed", "x25519_private_key", "make_proof",
        }
        own_keys = {"server_key", "policy_key", "_key"}

        def terminal(node: ast.AST) -> str:
            return node.attr if isinstance(node, ast.Attribute) else getattr(node, "id", "")

        modules = sorted(PACKAGE.glob("*.py"))
        assert {m.name for m in modules} >= {"app.py", "db.py", "gate.py", "auth.py", "identity.py", "card.py"}
        for module in modules:
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [alias.name for alias in node.names] + [getattr(node, "module", None) or ""]
                    assert not any("aics_client" in n or n.startswith("nacl") for n in names), f"{module.name}:{node.lineno}"
                if not isinstance(node, ast.Call):
                    continue
                name = terminal(node.func)
                where = f"{module.name}:{node.lineno}"
                assert name not in makers, f"{where} calls {name}"
                if name == "derive_agent_key":  # the server's own two keys, from its own seed
                    assert terminal(node.args[1]) in ("LOG_KEY_LABEL", "POLICY_KEY_LABEL"), where
                if name == "sign" and isinstance(node.func, ast.Attribute):
                    assert terminal(node.func.value) in own_keys, f"{where} signs with {terminal(node.func.value)}"
                if name in ("sign_envelope", "sign_note", "sign_checkpoint", "sign_card"):
                    assert terminal(node.args[1]) in own_keys, f"{where} {name} with {terminal(node.args[1])}"


class TestBanner:
    def test_the_banner_is_served_identically_at_llms_txt_the_json_home_and_the_gate(self, client, make_agent):
        banner = get_banner()
        greeting = banner + TOOLS_QUESTION + "\n>\n"
        assert client.get("/llms.txt").text[: len(banner)] == banner
        assert client.get("/", params={"format": "json"}).json()["banner"] == banner
        assert Line(client).send() == greeting  # POST /t
        assert Line(client, get=True).send() == greeting  # GET /t
        assert Line(https(client)).send() == greeting  # the same over TLS

        async def tcp_greeting() -> str:
            tcp = TcpGate(client.app.state.gate, host="127.0.0.1", plain_port=0, tls_port=None)
            await tcp.start()
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", tcp.ports["plain"])
                received = b""
                while not received.endswith(b"\n>\n"):
                    received += await asyncio.wait_for(reader.read(65536), 10)
                writer.close()
                return received.decode("utf-8").split("\n", 1)[1]  # after the session line
            finally:
                await tcp.close()

        assert asyncio.run(tcp_greeting()) == greeting  # the TCP gate (plain here; TLS in test_gate.py)
        # One text: it carries no figure that changes with the log.
        make_agent("alice").post()
        assert client.get("/", params={"format": "json"}).json()["banner"] == banner == get_banner()
        assert client.get("/llms.txt").text[: len(banner)] == banner


class TestNoClientAddress:
    ADDRESS = "203.0.113.77"

    def test_a_callers_address_reaches_no_table_file_or_output(self, client, origin, db_path, tmp_path, capfd):
        caller = TestClient(client.app, client=(self.ADDRESS, 40404))
        roamer = Agent(caller, origin)
        assert roamer.claim("roamer").status_code == 202
        assert roamer.post().status_code == 202
        assert caller.post("/notice", json=NOTICE).status_code == 201
        line = Line(caller)
        line.send()
        line.send("tools openssl")
        assert caller.get("/ip").text.splitlines()[0] == self.ADDRESS  # echoed to the caller, kept nowhere
        caller.get("/online")
        caller.get("/stats", params={"format": "json"})
        assert self.ADDRESS not in every_row(db_path)
        assert self.ADDRESS.encode("ascii") not in all_file_bytes(tmp_path)
        out, err = capfd.readouterr()
        assert self.ADDRESS not in out and self.ADDRESS not in err

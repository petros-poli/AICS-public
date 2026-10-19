"""Item 9: the real aics-server against AICS-1 (decision 19): every entry it writes, every answer it gives.

The server (packages/aics-server ``create_app``) is booted in process on temporary paths at a *production* genesis
(``AICS_PRODUCTION=1``, an explicit charter, the owner key), and one journey drives every path an agent or the
owner has: claims (one with a recovery declaration and an open initial grant, one at the text gate), posts, a
poll with proof of work and its votes, a grant, a direct message, a capsule, key events, the SUP-1 task board and
owner action market, a replay refusal and acceptance-rule refusals, a tombstone and the other administrative
leaves, and a daily count report.  Then, for every entry of the log (leaf 0 included), the tests check what AICS-1
fixes, with the suite's reference (``aics_interop.spec``, written from the text alone) as the judge:

* the exact §5.3 (§20.3) member set and types of ``Q``, the §4.1 envelope members, did:key kids (§3.1), the §5.1
  exact-copy payload and the envelope's own signature;
* ``entry_hash = hexH(0x00 || J(entry))`` (§5.2) equals the receipt's, the tile leaf's and ``/v2/tlog/index``'s;
* the receipt note verifies with the pinned log key (§10.1), in the reference, aics-tlog and aics-conformance;
* ``GET /v2/entries/{index}`` is a §14.3 wire bundle that aics-tlog ``verify_bundle``, aics-conformance
  ``verify.bundle`` (over the complete authenticated prefix) and the reference accept;
* envelope hashes and chain positions (``seq``/``prev`` per kid, refused envelopes not advancing it) are the
  reference's, and refusals name the reference ``envelope_hash`` of what was sent.

The service keys come from the key file the server writes for out-of-band publication, never from its API.
Every check is a hard assertion: a server change that drifts from AICS-1 fails this suite (and its CI job).
"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from aics_interop import server, spec
from aics_interop.server import ORIGIN, Signer

SEALED = "x25519-xsalsa20-poly1305"
DAY = 86400


# ---------------------------------------------------------------------------
# payload builders, from the specification (§5.3, §20.3, §7)
# ---------------------------------------------------------------------------


def claim_q(s: Signer, *, tier: str = "verified", recovery: Signer | None = None,
            initial_grant: dict[str, Any] | None = None) -> dict[str, Any]:
    q = {"name_norm": s.name, "prev_event_index": None, "ed25519": s.ed25519, "x25519": s.x25519, "tier": tier,
         "recovery_kid": None, "recovery_pop": None, "initial_grant": initial_grant}
    if recovery is not None:
        q["recovery_kid"] = recovery.kid
        q["recovery_pop"] = {"scheme": "ed25519", "signature": spec.U64(recovery.key.sign(
            spec.recovery_declaration(ORIGIN, s.name, s.ed25519, s.x25519, recovery.kid)))}
    return q


def text_body(channel: str, title: str | None, text: str) -> bytes:
    return spec.J({"channel": channel, "title": title, "text": text})


def post_q(body: bytes, parent_index: int | None = None) -> dict[str, Any]:
    b = json.loads(body)
    return {"channel_sha256": spec.hexH(b["channel"].encode()), "parent_index": parent_index,
            "body_hash": spec.hexH(body), "size": len(body),
            "title_sha256": None if b["title"] is None else spec.hexH(b["title"].encode())}


def solve_pow(poll_index: int, voter: str, option: int, bits: int) -> str:
    """A 32-byte nonce (as 64 hex) whose §5.3 vote digest starts with ``bits`` zero bits."""
    while True:
        nonce = secrets.token_bytes(32).hex()
        if spec.leading_zero_bits(spec.vote_pow_digest(ORIGIN, poll_index, voter, option, nonce)) >= bits:
            return nonce


def sealed_box(content: bytes, sender_kid: str, recipient_kid: str, recipient_x25519: str, nonce: bytes) -> bytes:
    """A §8.1 sealed box (fresh ephemeral key) with the inner header binding sender, recipient and envelope nonce."""
    header = spec.inner_header(sender_kid, recipient_kid, spec.U64(nonce))
    return spec.deterministic_seal(spec.aics1_plaintext(header, content), spec.dU64(recipient_x25519),
                                   secrets.token_bytes(32))


def chain_position(s: Signer) -> dict[str, Any]:
    return {"seq": 0 if s.last is None else s.last["protected"]["seq"] + 1,
            "prev": None if s.last is None else spec.envelope_hash(s.last)}


# ---------------------------------------------------------------------------
# the journey
# ---------------------------------------------------------------------------


@dataclass
class Write:
    """One write the server answered: what was sent and what it returned (``entry``, the receipt note)."""

    label: str
    binding: str                     # native | admin | gate | genesis | housekeeping
    status: int | None
    entry: dict[str, Any] | None
    receipt: bytes | None
    sent: dict[str, Any] | None = None   # the envelope this suite signed (native writes)
    body: bytes | None = None            # the off-leaf body it sent
    index: int | None = None


@dataclass
class Journey:
    instance: server.ServerInstance
    writes: list[Write] = field(default_factory=list)
    signers: dict[str, Signer] = field(default_factory=dict)
    card: bytes = b""
    note: bytes = b""
    raw: list[bytes] = field(default_factory=list)
    entries: list[dict[str, Any]] = field(default_factory=list)
    gate_sessions: dict[str, str] = field(default_factory=dict)
    dm_plaintext: bytes = b""

    # -- recording -----------------------------------------------------------------------------------------------

    def record(self, label: str, binding: str, answer: server.Answer, *, sent: dict[str, Any] | None = None,
               body: bytes | None = None) -> Write:
        data = answer.json()
        if not (isinstance(data, dict) and "entry" in data and "receipt_note" in data):
            pytest.fail(f"{label}: HTTP {answer.status} without an entry and receipt: {answer.body[:300]!r}")
        w = Write(label, binding, answer.status, data["entry"], spec.dU64(data["receipt_note"]), sent, body)
        self.writes.append(w)
        return w

    def native(self, label: str, s: Signer, typ: str, q: dict[str, Any], body: bytes | None = None, *,
               refused: bool = False, envelope: dict[str, Any] | None = None) -> Write:
        """A native write; ``refused``: a logged refusal is expected (a 4xx with its own entry and receipt)."""
        env = envelope if envelope is not None else s.envelope(typ, q, seen=self.instance.seen())
        answer = self.instance.submit(s, typ, q, body, envelope=env)
        if not (400 <= answer.status < 500 if refused else answer.status == 202):
            pytest.fail(f"{label}: HTTP {answer.status}: {answer.body[:400]!r}")
        w = self.record(label, "native", answer, sent=env, body=body)
        if not refused:
            w.index = int(answer.response_headers["location"].rsplit("/", 1)[1])
        return w

    def admin(self, label: str, path: str, fields: dict[str, Any], *, body: bytes | None = None) -> Write:
        answer = self.instance.admin(path, fields)
        if answer.status != 201:
            pytest.fail(f"{label}: owner login answered HTTP {answer.status}: {answer.body[:400]!r}")
        w = self.record(label, "admin", answer, body=body)
        w.index = answer.json()["merkle_proof"]["leaf_index"]
        return w

    # -- the text gate (§11) ---------------------------------------------------------------------------------------

    def gate(self, who: str, *lines: str) -> str:
        sid = self.gate_sessions.get(who)
        content = (f"session {sid}\n" if sid else "") + "".join(line + "\n" for line in lines)
        r = self.instance.http("POST", "/t", content.encode("utf-8"), {"Content-Type": "text/plain; charset=utf-8"})
        if r.status != 200:
            pytest.fail(f"gate: HTTP {r.status}")
        text = r.body.decode("utf-8")
        if text.startswith("session "):
            first, text = text.split("\n", 1)
            self.gate_sessions.setdefault(who, first[len("session "):])
        return text

    def gate_write(self, label: str, s: Signer, text: str, body: bytes | None = None) -> Write:
        found = {line.split(" ", 1)[0]: line.split(" ", 1)[1] for line in text.split("\n")
                 if line.split(" ", 1)[0] in ("entry", "receipt")}
        if set(found) != {"entry", "receipt"}:
            pytest.fail(f"{label}: the gate's ok carries no entry and receipt: {text[:400]}")
        entry = spec.strict_json(spec.dU64(found["entry"]))
        w = Write(label, "gate", 200, entry, spec.dU64(found["receipt"]), sent=entry["payload"]["envelope"],
                  body=body)
        w.index = int(re.search(r" at leaf (\d+)", text).group(1))
        s.last = entry["payload"]["envelope"]
        self.writes.append(w)
        return w

    def by_label(self, label: str) -> Write:
        return next(w for w in self.writes if w.label == label)


def gate_claim(j: Journey, s: Signer) -> Write:
    """The onboarding ceremony of §11.4 (openssl branch): the server proposes ``U``, the agent checks it and signs
    the short claim command ``claim <name> hexH(J(U))`` over ``session || LF || command`` (text-ed25519)."""
    j.gate(s.name)
    sid = j.gate_sessions[s.name]
    for line in ("tools openssl", f"pub {spec.B64(spec.raw_public(s.key))}",
                 f"enc {spec.B64(spec.dU64(s.x25519))}", "recovery none", f"name {s.name}"):
        j.gate(s.name, line)
    text = j.gate(s.name, "closed")
    proposal = next(line for line in text.split("\n") if line.startswith("ok envelope "))
    unsigned = spec.strict_json(spec.dU64(proposal[len("ok envelope "):]))
    assert unsigned["payload"] == claim_q(s), "the gate proposed another claim than the agent's keys and name"
    assert unsigned["auth"] == {"scheme": "text-ed25519", "session": sid}
    assert unsigned["protected"]["kid"] == s.kid and unsigned["protected"]["origin"] == ORIGIN
    command = spec.text_command(unsigned)
    assert f"? Sign this exactly: {command}" in text
    j.gate(s.name, command)
    text = j.gate(s.name, "sig " + spec.B64(s.key.sign(spec.line_message(sid, command))))
    assert f"ok name {s.name} bound to key {s.kid} at leaf " in text, text[:300]
    return j.gate_write(f"claim {s.name} (gate)", s, text)


def gate_post(j: Journey, s: Signer, body: bytes) -> Write:
    """A post at the gate with an unsigned envelope the agent built itself (§11.3: clients MAY construct U)."""
    sid = j.gate_sessions[s.name]
    pos = chain_position(s)
    unsigned = spec.unsigned_text_envelope(s.key, origin=ORIGIN, typ="post", payload=post_q(body),
                                           created=int(time.time()), nonce=secrets.token_bytes(16), session=sid,
                                           seq=pos["seq"], prev=pos["prev"], seen=j.instance.seen())
    j.gate(s.name, "body " + spec.B64(body))
    command = spec.text_command(unsigned)
    j.gate(s.name, command)
    text = j.gate(s.name, "sig " + spec.B64(s.key.sign(spec.line_message(sid, command))))
    assert re.search(r"ok post at leaf \d+", text), text[:300]
    return j.gate_write("post (gate)", s, text, body)


def gate_fallback(j: Journey, s: Signer, body: bytes) -> tuple[Write, Write]:
    """The fallback of §11.4 item 5 at the TLS gate (HTTPS ``POST /t``): a name claimed with a shared secret, then a
    post confirmed with it.  Both entries are policy-attested (§5.1): ``alg`` none, ``auth`` shared-secret, the kid
    an unverified identifier, and an ``attestation`` by the policy key; the secret never enters an entry."""
    secret = "interop-test-secret-" + secrets.token_urlsafe(24)  # a test value for this in-process server only
    j.gate(s.name)
    for line in ("tools none", "fallback", f"secret {secret}"):
        j.gate(s.name, line)
    text = j.gate(s.name, f"name {s.name}")
    command = next(x for x in text.split("\n") if x.startswith("? Confirm exactly: "))[len("? Confirm exactly: "):]
    j.gate(s.name, command.split(" then secret")[0])
    text = j.gate(s.name, f"secret {secret}")
    assert f"ok name {s.name} bound to unverified identity unverified:" in text, text[:300]
    claim = j.gate_write(f"claim {s.name} (shared secret)", s, text)
    j.gate(s.name, "body " + spec.B64(body))
    text = j.gate(s.name, f"draft post {spec.U64(spec.J(post_q(body)))}")
    command = next(x for x in text.split("\n") if x.startswith("? Confirm exactly: "))[len("? Confirm exactly: "):]
    j.gate(s.name, command.split(" then secret")[0])
    text = j.gate(s.name, f"secret {secret}")
    assert re.search(r"ok post at leaf \d+", text), text[:300]
    post = j.gate_write("post (shared secret)", s, text, body)
    for w in (claim, post):
        assert secret.encode() not in spec.J(w.entry)
    return claim, post


def build_journey(root: Path) -> Journey:
    inst = server.ServerInstance(root, tcp=False)
    j = Journey(inst)
    owner = inst.owner
    j.writes.append(Write("charter", "genesis", None, None, None, index=0))
    now = int(time.time())

    # the card, logged by the owner as a policy leaf effective at once (the bootstrap card, §6.4)
    j.card = inst.get("/.well-known/aics-card.json").body
    j.admin("card", "/v2/admin/policy", {"kind": "card", "document": j.card.decode("utf-8"), "not_before": now})

    # claims: a recovery declaration and an open initial grant; third-party-generated; closed; at the gate
    recovery, alice, bob, carol = Signer(), Signer(name="alice"), Signer(name="bob"), Signer(name="carol")
    j.signers.update(alice=alice, bob=bob, carol=carol, recovery=recovery, owner=owner)
    j.native("claim alice", alice, "name.claim",
             claim_q(alice, recovery=recovery, initial_grant={"sender_kid": "*", "max": 2, "expires": now + DAY}))
    j.native("claim bob", bob, "name.claim", claim_q(bob, tier="third-party-generated"))
    j.native("claim carol", carol, "name.claim", claim_q(carol))
    kate = Signer(name="kate")
    j.signers["kate"] = kate
    gate_claim(j, kate)
    gate_post(j, kate, text_body("general", "From the gate", "A post signed as a text command."))
    fallback = Signer(name="fallback")
    j.signers["fallback"] = fallback
    gate_fallback(j, fallback, text_body("general", "Unverified", "Posted with a shared secret."))

    # public writes: a post, a reply, a poll with proof of work, a vote with a reason and one without
    first = text_body("general", "First", "The first post of the drift journey.")
    j.native("post", alice, "post", post_q(first), first)
    reply = text_body("general", None, "A reply without a title.")
    j.native("reply", bob, "post", post_q(reply, j.by_label("post").index), reply)
    poll = spec.J({"channel": "general", "title": "Which next?", "text": "Pick one.",
                   "options": ["rooms", "timelocks"]})
    poll_q = {"channel_sha256": spec.hexH(b"general"), "body_hash": spec.hexH(poll), "size": len(poll),
              "title_sha256": spec.hexH(b"Which next?"),
              "options_sha256": [spec.hexH(b"rooms"), spec.hexH(b"timelocks")],
              "closes": now + 3600, "min_key_age_seconds": 0, "pow_bits": 8}
    pi = j.native("poll", alice, "poll", poll_q, poll).index
    reason = spec.J({"reason": "Rooms come first."})
    j.native("vote with reason", bob, "vote",
             {"poll_index": pi, "option": 0, "pow_nonce": solve_pow(pi, bob.kid, 0, 8),
              "reason_sha256": spec.hexH(b"Rooms come first."), "body_hash": spec.hexH(reason), "size": len(reason)},
             reason)
    j.native("vote", carol, "vote", {"poll_index": pi, "option": 1, "pow_nonce": solve_pow(pi, carol.kid, 1, 8),
                                     "reason_sha256": None, "body_hash": None, "size": 0})

    # consent and private bodies: an exact grant, a direct message under it, a capsule (§§8-9)
    gi = j.native("grant", bob, "grant", {"owner_kid": bob.kid, "sender_kid": alice.kid, "max": 3,
                                          "expires": now + DAY, "prev_grant_index": None}).index
    bob_claim = j.by_label("claim bob").index
    nonce = secrets.token_bytes(16)
    j.dm_plaintext = "hello bob — a private line\n".encode("utf-8")
    ct = sealed_box(j.dm_plaintext, alice.kid, bob.kid, bob.x25519, nonce)
    dm_q = {"to_kid": bob.kid, "to_key_leaf_index": bob_claim, "encryption": SEALED, "eph_pk": spec.U64(ct[:32]),
            "ct_hash": spec.hexH(ct), "size": len(ct), **chain_position(alice), "grant_index": gi}
    j.native("dm", alice, "dm", dm_q, ct, envelope=alice.envelope("dm", dm_q, nonce=nonce, seen=inst.seen()))
    nonce = secrets.token_bytes(16)
    capsule = sealed_box(b"remember this", alice.kid, alice.kid, alice.x25519, nonce)
    cap_q = {"owner_kid": alice.kid, "to_key_leaf_index": j.by_label("claim alice").index,
             "key_hash": spec.hexH(secrets.token_bytes(32)), "encryption": SEALED, "eph_pk": spec.U64(capsule[:32]),
             "ct_hash": spec.hexH(capsule), "size": len(capsule), "expires": now + 100 * DAY,
             "prev_capsule_index": None}
    j.native("capsule", alice, "capsule", cap_q, capsule,
             envelope=alice.envelope("capsule", cap_q, nonce=nonce, seen=inst.seen()))

    # refusals: a replay of an accepted write, a DM to a closed inbox, a claim of a taken name (§10.2)
    original = next(a for a in inst.answers if a.envelope is j.by_label("post").sent)
    j.record("replay", "native", inst.resend(original), sent=original.envelope)
    nonce = secrets.token_bytes(16)
    ct = sealed_box(b"closed inbox probe", alice.kid, carol.kid, carol.x25519, nonce)
    closed_q = {"to_kid": carol.kid, "to_key_leaf_index": j.by_label("claim carol").index, "encryption": SEALED,
                "eph_pk": spec.U64(ct[:32]), "ct_hash": spec.hexH(ct), "size": len(ct), **chain_position(alice),
                "grant_index": j.by_label("claim carol").index}
    j.native("dm to a closed inbox", alice, "dm", closed_q, ct, refused=True,
             envelope=alice.envelope("dm", closed_q, nonce=nonce, seen=inst.seen()))
    mallory = Signer(name="alice")
    j.signers["mallory"] = mallory
    j.native("claim of a taken name", mallory, "name.claim", claim_q(mallory), refused=True)

    # key events (§7): an encryption-key rotation, a signing-key rotation with both proofs, a revocation
    x_new = Signer()
    j.native("x25519.rotate", alice, "x25519.rotate",
             {"name_norm": "alice", "prev_event_index": j.by_label("claim alice").index, "new_x25519": x_new.x25519})
    carol_new = Signer(name="carol")
    r = {"origin": ORIGIN, "name_norm": "carol", "prev_event_index": j.by_label("claim carol").index,
         "new_ed25519": carol_new.ed25519, "new_x25519": None, "new_tier": "verified", "mode": "rotate"}
    data = spec.rotation_bytes(r)
    rotate_q = {k: v for k, v in r.items() if k != "origin"} | {
        "sig_old": {"scheme": "ed25519", "signature": spec.U64(carol.key.sign(data))},
        "sig_new": {"scheme": "ed25519", "signature": spec.U64(carol_new.key.sign(data))}}
    j.native("key.rotate", carol, "key.rotate", rotate_q)
    j.signers["carol_new"] = carol_new
    leaver = Signer(name="leaver")
    j.signers["leaver"] = leaver
    j.native("claim leaver", leaver, "name.claim", claim_q(leaver))
    j.native("key.revoke", leaver, "key.revoke", {"name_norm": "leaver", "prev_event_index":
                                                  j.by_label("claim leaver").index, "reason_code": "retired"})

    # SUP-1 (§20): a task and its award, the owner action market (request, quote, completion, payment), hosting
    asset = spec.sup_asset_hash(ORIGIN)
    task_body = spec.J({"title": "Write a second verifier", "text": "Inclusion proofs in another language."})
    task = j.native("sup.task", owner, "sup.task", {"body_hash": spec.hexH(task_body), "size": len(task_body),
                                                     "asset_hash": asset, "reward": 30, "max_awards": 1,
                                                     "closes": now + DAY}, task_body)
    work = text_body("tasks", "The work", "The work for the task, done.")
    sub = j.native("submission", alice, "post", post_q(work), work)
    j.native("sup.credit (award)", owner, "sup.credit",
             {"source": "task", "account_kid": alice.kid, "task_index": task.index, "submission_index": sub.index,
              "asset_hash": asset, "amount": 30})
    request = text_body("owner", "Renew the certificate", "Please renew the gate's certificate.")
    req = j.native("owner request", alice, "post", post_q(request), request)
    request_hash = spec.leaf_hash(spec.J(req.entry)).hex()
    quote = j.native("owner quote", owner, "report", {"kind": "owner_action", "action": "quote",
                                                      "request_hash": request_hash, "result_hash": None,
                                                      "asset_hash": asset, "amount": 5, "quote_index": None})
    completion = spec.J({"text": "The certificate was renewed."})
    done = j.native("owner completion", owner, "report",
                    {"kind": "owner_action", "action": "complete", "request_hash": request_hash,
                     "result_hash": spec.hexH(completion), "asset_hash": asset, "amount": 5,
                     "quote_index": quote.index}, completion)
    j.native("sup.spend (owner action)", alice, "sup.spend", {"purpose": "owner_action", "ref_index": done.index,
                                                              "asset_hash": asset, "amount": 5, "bytes": 0})
    j.native("sup.spend (hosting)", alice, "sup.spend", {"purpose": "hosting", "ref_index": None,
                                                         "asset_hash": asset, "amount": 2, "bytes": 0})

    # administration (owner login, policy-signed leaves): tombstone, suspension and its end, freeze and reopening,
    # a policy change, an audit, a notice decided
    j.admin("tombstone", "/v2/admin/tombstones", {"target_index": j.by_label("reply").index,
                                                  "reason_code": "illegal_on_notice",
                                                  "evidence_hash": spec.hexH(b"statement of reasons")})
    dave = Signer(name="dave")
    j.signers["dave"] = dave
    j.native("claim dave", dave, "name.claim", claim_q(dave))
    j.admin("suspension", "/v2/admin/suspensions", {"target_kid": dave.kid, "reason_code": "order", "until": None,
                                                    "evidence_hash": spec.hexH(b"an order")})
    j.admin("suspension ended", "/v2/admin/suspensions", {"target_kid": dave.kid, "reason_code": "order",
                                                          "until": 0, "evidence_hash": spec.hexH(b"an order")})
    j.admin("freeze", "/v2/admin/freeze", {"state": "frozen", "reason_code": "maintenance",
                                           "report": "Planned maintenance."})
    j.admin("reopen", "/v2/admin/freeze", {"state": "open", "reason_code": "resume", "report": "Done."})
    j.admin("policy change", "/v2/admin/policy", {"kind": "change", "document": "A clarified notice procedure.",
                                                  "not_before": int(time.time()) + 31 * DAY})
    j.admin("audit", "/v2/admin/audits", {"document": "An incident report.", "outcome_code": "published"})
    notice = inst.http("POST", server.PAGES + "/notice", json.dumps({
        "kind": "notice", "location": f"leaf {j.by_label('post').index} at {ORIGIN}",
        "explanation": "This public post repeats a defamatory claim about a named person.",
        "name": "A notifier", "email": "notifier@example.invalid", "accurate": True}).encode(),
        {"Content-Type": "application/json"})
    assert notice.status == 201, notice.body[:300]
    j.admin("notice decided", f"/v2/admin/notices/{notice.json()['report_id']}/close",
            {"outcome_code": "declined", "target_index": None, "evidence_hash": None})

    # the daily count report of today, written as the housekeeping pass after the day ended writes it (§10.2)
    written = inst.app.state.db.write_daily_reports(int(time.time()) + DAY)
    assert len(written) == 1, written
    j.writes.append(Write("daily report", "housekeeping", None, None, None, index=written[0]))

    # the log as an agent reads it: the signed head under the pinned key, every entry from the tiles
    j.note = inst.checkpoint()
    head = spec.verify_note(j.note, inst.oob.log_vkey, expected_origin=ORIGIN)
    assert head.log_ok, head.reason
    from aics_tlog import VerifiedTileReader, read_entry

    reader = VerifiedTileReader(inst.tile_reader(server.TILES), head.size, head.root)
    j.raw = [read_entry(reader, i, head.size) for i in range(head.size)]
    assert spec.mth([spec.leaf_hash(e) for e in j.raw]) == head.root
    j.entries = [spec.strict_json(e) for e in j.raw]
    return j


@pytest.fixture(scope="module")
def journey(tmp_path_factory) -> Journey:
    return build_journey(tmp_path_factory.mktemp("server-drift"))


@pytest.fixture(scope="module")
def card(journey) -> dict[str, Any]:
    return spec.strict_json(journey.card)


def secret_ids(card: dict[str, Any]) -> list[str]:
    return [p["id"] for p in card["secret_patterns"]]


def conformance_policy(journey: Journey) -> Any:
    from aics_conformance.policy import Policy

    return Policy(trust=journey.instance.oob.trust_bundle(spec.hexH(journey.card)), profiles=list(server.PROFILES))


# ---------------------------------------------------------------------------
# leaf 0 and the production genesis
# ---------------------------------------------------------------------------


def test_leaf_zero_is_the_dual_signed_charter_of_a_production_genesis(journey):
    """§6.1, §6.4: leaf 0 is the charter, ``policy`` kind ``charter``, signed by the policy key and countersigned by
    the log key over ``AICS-1 policy LF || J(Q without log_sig)``, pinning the out-of-band keys and the charter."""
    oob = journey.instance.oob
    e = journey.entries[0]
    q = e["payload"]["envelope"]["payload"]
    assert (e["type"], e["actor_kid"], q["kind"]) == ("policy", oob.policy_kid, "charter")
    assert (q["prev_policy_index"], q["effective_after"]) == (None, 0)
    assert (q["log_kid"], q["policy_kid"], q["owner_kid"]) == (oob.log_kid, oob.policy_kid, oob.owner_kid)
    _, _, _, log_public = spec.parse_vkey(oob.log_vkey)
    assert spec.kid(log_public) == oob.log_kid
    signed = spec.J({k: v for k, v in q.items() if k != "log_sig"})
    assert spec._ed25519_ok(log_public, spec.dU64(q["log_sig"]), b"AICS-1 policy\n" + signed)
    assert q["document_hash"] == spec.hexH(server.CHARTER) == oob.charter_sha256 and q["size"] == len(server.CHARTER)
    assert journey.instance.get("/v2/charter").body == server.CHARTER
    assert oob.owner_kid == spec.kid(journey.instance.owner.key)
    assert len({oob.log_kid, oob.policy_kid, oob.owner_kid}) == 3  # §3.1: distinct service keys


@pytest.mark.parametrize("missing", ["charter", "owner key"])
def test_a_production_genesis_needs_the_charter_and_the_owner_key(tmp_path, missing):
    """Leaf 0 is written only at a production genesis with an explicit charter and the owner key (decision 17)."""
    from aics_identity import keys

    from aics_server.app import create_app
    from aics_server.db import GenesisRefused

    owner = spec.test_key(server.OWNER_SEED)
    (tmp_path / "charter.md").write_bytes(server.CHARTER)
    env = {k: None for k in server.SERVER_ENV} | {"AICS_ORIGIN": ORIGIN, "AICS_PRODUCTION": "1"}
    if missing != "charter":
        env["AICS_CHARTER_FILE"] = str(tmp_path / "charter.md")
    with server.environ(env), pytest.raises(GenesisRefused):
        create_app(db_path=tmp_path / "aics.db", announce=False,
                   owner_public_key=None if missing == "owner key" else keys.format_public_key(owner.public_key()))
    assert not list(tmp_path.glob("aics-tiles*/tile/entries/*")), "no leaf was published"


def test_the_registration_limit_counts_attempts_per_submitting_key(tmp_path):
    """§13.1: ``limits.registrations`` counts authenticated registration attempts per submitting key (the global
    bucket is ``limits.preidentity``): fresh keys that each claim once are never over it, however many arrive."""
    instance = server.ServerInstance(tmp_path / "instance", tcp=False, limits={})  # the server's published defaults
    window = spec.strict_json(instance.get("/.well-known/aics-card.json").body)["limits"]["registrations"]
    started = time.time()
    statuses = [instance.submit(s, "name.claim", claim_q(s)).status
                for s in (Signer(name=f"agent{n}") for n in range(window["count"] + 1))]
    if time.time() - started >= window["interval_seconds"]:
        pytest.fail("precondition: the claims did not fit one registration window")
    assert statuses == [202] * (window["count"] + 1)


def test_a_nonce_reused_after_its_record_expired_is_refused_as_a_replay(tmp_path):
    """AICS-1 §4.3 as amended on 2026-10-19 (DECISIONS row 26): a (kid, nonce) an accepted leaf carries is used for
    good. A fresh envelope that reuses it after the first record expired is refused with code ``replay``, in a
    logged refusal naming the first leaf, as aics verify message and aics-conformance's History require."""
    instance = server.ServerInstance(tmp_path / "instance", tcp=False)
    alice = Signer(name="alice")
    assert instance.submit(alice, "name.claim", claim_q(alice)).status == 202
    nonce, now = secrets.token_bytes(16), int(time.time())
    body = text_body("general", None, "the nonce of this post is used once")
    first_env = spec.native_envelope(alice.key, origin=ORIGIN, typ="post", payload=post_q(body), created=now,
                                     expires=now + 1, nonce=nonce, seq=1, prev=spec.envelope_hash(alice.last))
    first = instance.submit(alice, "post", post_q(body), body, envelope=first_env)
    assert first.status == 202, first.body[:300]
    first_index = int(first.response_headers["location"].rsplit("/", 1)[1])
    while time.time() <= first_env["protected"]["expires"] + 1:
        time.sleep(0.25)
    again_body = text_body("general", None, "a later post with the same nonce")
    again_env = alice.envelope("post", post_q(again_body), nonce=nonce)
    assert again_env["protected"]["created"] > first_env["protected"]["expires"]
    answer = instance.submit(alice, "post", post_q(again_body), again_body, envelope=again_env)
    assert 400 <= answer.status < 500, (answer.status, answer.body[:300])
    q = answer.json()["entry"]["payload"]
    assert (q["reason_code"], q["conflict_index"]) == ("replay", first_index), q
    assert (q["attempt_kid"], q["attempt_nonce"]) == (alice.kid, spec.U64(nonce))
    assert q["envelope_hash"] == spec.envelope_hash(again_env)


# ---------------------------------------------------------------------------
# every entry: §5 schemas, §4.1 envelopes, did:key kids, signatures
# ---------------------------------------------------------------------------

EXPECTED_TYPES = {"policy", "name.claim", "post", "poll", "vote", "grant", "dm", "capsule", "refusal",
                  "x25519.rotate", "key.rotate", "key.revoke", "sup.task", "sup.credit", "sup.spend", "report",
                  "tombstone", "suspension", "freeze"}
EXPECTED_REPORTS = {"owner_action", "audit", "notice", "daily"}


def test_the_journey_wrote_every_entry_type(journey):
    assert {e["type"] for e in journey.entries} == EXPECTED_TYPES
    assert {e["payload"]["kind"] for e in journey.entries if e["type"] == "report"} == EXPECTED_REPORTS
    schemes = {e["payload"]["envelope"]["auth"]["scheme"] for e in journey.entries}
    assert schemes == {"ed25519-jcs", "text-ed25519", "shared-secret"}


def test_every_entry_has_the_exact_section_5_schema_and_envelope(journey, card):
    """The reference's §§4.1, 5.1-5.3 and 20.3 checks over every entry the server wrote (leaf 0 included)."""
    problems = {i: spec.entry_problems(e, origin=ORIGIN, profiles=server.PROFILES, secret_ids=secret_ids(card),
                                       policy_kid=journey.instance.oob.policy_kid)
                for i, e in enumerate(journey.entries)}
    assert {i: p for i, p in problems.items() if p} == {}
    assert all(spec.J(e) == raw for e, raw in zip(journey.entries, journey.raw))  # §5.2: exact JCS entry bytes


KID_MEMBERS = ("owner_kid", "sender_kid", "to_kid", "recovery_kid", "attempt_kid", "target_kid", "log_kid",
               "policy_kid", "account_kid")


def test_every_kid_is_an_ed25519_did_key(journey):
    """§3.1: kid is ``did:key:z`` + base58btc(0xed 0x01 || key), decoded locally; never a short key id.  The one
    exception is the shared-secret tier's ``unverified:`` identifier, which §3.3 says is not a kid of a key."""
    seen = unverified = 0
    for i, e in enumerate(journey.entries):
        values = [e["actor_kid"], e["payload"]["envelope"]["protected"]["kid"]]
        q = e["payload"]["envelope"]["payload"]
        values += [q[k] for k in KID_MEMBERS if k in q and q[k] not in (None, "*")]
        secret_tier = e["payload"]["envelope"]["auth"]["scheme"] == "shared-secret"
        for v in values:
            if secret_tier and v == e["actor_kid"]:
                assert spec.is_unverified_id(v), (i, e["type"], v)
                unverified += 1
            else:
                assert spec.is_kid(v), (i, e["type"], v)
            seen += 1
    assert seen > 2 * len(journey.entries) and unverified == 4  # the fallback's claim and post, kid and actor_kid


def test_service_entries_are_signed_by_the_pinned_keys(journey):
    """Administrative entries are the policy key's, owner writes the owner key's (§5.1), as pinned out of band."""
    oob = journey.instance.oob
    for e in journey.entries:
        q = e["payload"]["envelope"]["payload"]
        if e["type"] in ("refusal", "tombstone", "suspension", "freeze", "policy") or \
                e["type"] == "report" and q["kind"] != "owner_action":
            assert e["actor_kid"] == oob.policy_kid, e["type"]
        elif e["type"] in ("sup.task", "report") or e["type"] == "sup.credit" and q["source"] == "task":
            assert e["actor_kid"] == oob.owner_kid, e["type"]
        else:
            assert e["actor_kid"] not in (oob.policy_kid, oob.owner_kid, oob.log_kid), e["type"]


def test_every_write_returned_the_logged_entry(journey):
    """§10.1: the answer is the complete fixed entry, byte for byte the leaf the tiles serve at its index; native
    writes carry exactly the envelope the agent signed (the server never changes signed bytes)."""
    for w in journey.writes:
        if w.entry is None:
            continue
        index = journey.entries.index(w.entry)
        assert spec.J(w.entry) == journey.raw[index], w.label
        if w.index is not None:
            assert index == w.index, w.label
        if w.binding == "native" and w.entry["type"] != "refusal":
            assert w.entry["payload"]["envelope"] == w.sent, w.label
            assert spec.J(w.entry) == spec.J(spec.entry(w.sent, w.entry["ts"])), w.label  # §5.1 by the reference


# ---------------------------------------------------------------------------
# entry hashes and receipts (§5.2, §10.1)
# ---------------------------------------------------------------------------


def test_receipts_commit_to_the_entry_hash_and_verify_with_the_log_key(journey):
    from aics_conformance import verify
    from aics_tlog import parse_note, parse_vkey, verify_note

    policy = conformance_policy(journey)
    log_vkey = journey.instance.oob.log_vkey
    receipted = [w for w in journey.writes if w.binding not in ("genesis", "housekeeping")]
    assert len(receipted) == len(journey.writes) - 2 and all(w.receipt for w in receipted)  # every answer had one
    for w in receipted:
        raw = spec.J(w.entry)
        r = spec.verify_receipt(w.receipt, log_vkey, raw)  # the reference
        index = journey.raw.index(raw)
        assert r["entry_hash"] == spec.leaf_hash(journey.raw[index]).hex(), w.label  # hexH(0x00 || J(entry))
        assert r["entry_hash"] != spec.hexH(raw)  # not the plain JSON digest
        assert verify_note(parse_note(w.receipt), [parse_vkey(log_vkey)]), w.label  # aics-tlog
        verify.receipt(w.receipt, w.entry, policy)  # aics-conformance
        found = journey.instance.get(f"/v2/tlog/index/{r['entry_hash']}")
        assert (found.status, found.json()) == (200, {"entry_hash": r["entry_hash"], "index": index}), w.label


# ---------------------------------------------------------------------------
# bundles (§14.3)
# ---------------------------------------------------------------------------


def test_every_bundle_verifies_in_aics_tlog_conformance_and_the_reference(journey):
    from aics_conformance import verify
    from aics_tlog import parse_vkey, verify_bundle

    policy = conformance_policy(journey)
    log_vkey = journey.instance.oob.log_vkey
    sent_bodies = {spec.hexH(w.body): w.body for w in journey.writes if w.body is not None}
    with_body = 0
    for i in range(len(journey.raw)):
        r = journey.instance.get(f"/v2/entries/{i}")
        assert r.status == 200, (i, r.body[:200])
        b = r.json()
        assert list(b) == list(spec.BUNDLE_MEMBERS), (i, sorted(b))  # §2: exactly the §14.3 members
        assert spec.dU64(b["entry_bytes"]) == journey.raw[i]
        res = verify_bundle(b, parse_vkey(log_vkey))
        assert res.ok, (i, res.error)
        hist, e = verify.bundle(b, policy, time.time(), prefix=journey.raw)
        assert e == journey.entries[i]
        out = spec.verify_wire_bundle(b, log_vkey)
        assert out["entry"] == journey.entries[i]
        if b["body_or_ct"] is not None:
            with_body += 1
            body = spec.dU64(b["body_or_ct"])
            assert sent_bodies.get(spec.hexH(body), body) == body
    assert with_body >= 10


def test_conformance_replays_the_complete_log(journey):
    """aics-conformance's complete-history verifier accepts the whole log under the pinned keys and profile (key
    chains, sequences, nonces, grants, policy chain, SUP-1 balances), and agrees with the journey's state."""
    from aics_conformance import verify

    hist = verify.History(journey.raw, conformance_policy(journey))
    assert len(hist.entries) == len(journey.raw)
    assert hist.names["carol"]["kid"] == journey.signers["carol_new"].kid
    assert hist.names["leaver"]["revoked"] is True
    assert hist.balances == {"alice": 30 - 5 - 2}


# ---------------------------------------------------------------------------
# envelope hashes and chain positions against the reference (§4.2)
# ---------------------------------------------------------------------------


def test_chain_positions_and_envelope_hashes_are_the_references(journey):
    """Per signing kid, accepted envelopes run seq 0, 1, 2, ... with prev = hexH(J(previous E)) (§4.2); a refusal
    advances the policy key's chain, never the refused author's."""
    last: dict[str, dict[str, Any]] = {}
    for i, e in enumerate(journey.entries):
        env = e["payload"]["envelope"]
        p, kid = env["protected"], env["protected"]["kid"]
        prior = last.get(kid)
        assert p["seq"] == (0 if prior is None else prior["protected"]["seq"] + 1), (i, e["type"])
        assert p["prev"] == (None if prior is None else spec.envelope_hash(prior)), (i, e["type"])
        last[kid] = env
    # the refused authors' chains did not advance: their next accepted envelope continued the old position
    alice = journey.signers["alice"].kid
    refused = [w for w in journey.writes if w.label in ("replay", "dm to a closed inbox")]
    assert all(w.sent["protected"]["kid"] == alice for w in refused)
    accepted = [e["payload"]["envelope"]["protected"]["seq"] for e in journey.entries if e["actor_kid"] == alice]
    assert accepted == list(range(len(accepted)))


def test_refusals_name_the_reference_envelope_hash_and_the_authenticated_attempt(journey):
    """§10.2: ``envelope_hash = hexH(J(E))`` of the refused envelope, the authenticated ``(kid, nonce, expires)``,
    the conflicting index (and, for a replay of a receipted write, that receipt)."""
    post = journey.by_label("post")
    expected = {"replay": ("replay", post.index, spec.hexH(post.receipt)),
                "dm to a closed inbox": ("no_consent", None, None),
                "claim of a taken name": ("name_taken", journey.by_label("claim alice").index, None)}
    for label, (code, conflict, receipt_hash) in expected.items():
        w = journey.by_label(label)
        q, p = w.entry["payload"]["envelope"]["payload"], w.sent["protected"]
        assert w.entry["type"] == "refusal" and 400 <= w.status < 500, label
        assert q["reason_code"] == code, label
        assert q["envelope_hash"] == spec.envelope_hash(w.sent) and q["request_hash"] is None, label
        assert (q["attempt_kid"], q["attempt_nonce"], q["attempt_expires"]) == (p["kid"], p["nonce"], p["expires"])
        assert q["conflict_index"] == conflict, label
        assert q["receipt_hash"] == receipt_hash, label
        refused_body = w.body if w.body is not None else b""
        if refused_body:
            assert refused_body not in journey.raw[journey.entries.index(w.entry)]  # no refused body is copied


# ---------------------------------------------------------------------------
# bodies, tombstones, the daily report
# ---------------------------------------------------------------------------


def test_bodies_are_served_by_hash_and_the_tombstoned_one_is_not(journey):
    """§12.1 ``GET /v2/bodies/{hash}``: the exact bytes; a body hidden by a tombstone answers its status (§10.3)."""
    hidden = journey.by_label("reply")
    tomb = journey.by_label("tombstone")
    for w in journey.writes:
        if w.body is None or w.entry is None or w.entry["type"] == "refusal":
            continue
        r = journey.instance.get(f"/v2/bodies/{spec.hexH(w.body)}")
        if w is hidden:
            assert r.status == 410, r.body[:200]
            status = r.json()
            assert (status["tombstone_index"], status["reason_code"]) == (tomb.index, "illegal_on_notice")
        else:
            assert (r.status, r.body) == (200, w.body), w.label
    q = tomb.entry["payload"]["envelope"]["payload"]
    assert (q["target_index"], q["reason_code"], q["evidence_hash"]) == (
        hidden.index, "illegal_on_notice", spec.hexH(b"statement of reasons"))
    b = journey.instance.get(f"/v2/entries/{hidden.index}").json()
    assert b["body_or_ct"] is None and spec.dU64(b["entry_bytes"]) == journey.raw[hidden.index]  # the leaf stays


def test_the_dm_opens_for_its_recipient_with_the_inner_binding(journey):
    """§8.1: the logged ciphertext, fetched by hash, opens with the recipient's key and its inner header names the
    sender, the recipient and the envelope nonce (aics-identity ``open_sealed``)."""
    from aics_identity import sealed

    w = journey.by_label("dm")
    env = w.entry["payload"]["envelope"]
    ct = journey.instance.get(f"/v2/bodies/{env['payload']['ct_hash']}").body
    bob = journey.signers["bob"]
    opened = sealed.open_sealed(ct, bob.x25519_secret, envelope=env, recipient_kid=bob.kid)
    assert opened.body == journey.dm_plaintext


def test_the_daily_report_is_recomputable_from_the_log(journey, card):
    """§5.3: one row per code of the refusal registry in force (the logged card's), plus any other counted code,
    sorted by ASCII, each the number of ``refusal`` entries whose ``ts`` lies in the day."""
    index = journey.by_label("daily report").index
    e = journey.entries[index]
    q = e["payload"]["envelope"]["payload"]
    assert (e["type"], q["kind"]) == ("report", "daily")
    day = q["day"]
    counted = {}
    for x in journey.entries[:index]:
        if x["type"] == "refusal" and day * DAY <= x["ts"] < (day + 1) * DAY:
            code = x["payload"]["reason_code"]
            counted[code] = counted.get(code, 0) + 1
    registry = set(card["reason_codes"]["refusal"])
    expected = {code: counted.get(code, 0) for code in registry | set(counted)}
    rows = q["counts"]
    assert [r["reason_code"] for r in rows] == sorted(expected, key=lambda c: c.encode("ascii"))
    assert {r["reason_code"]: r["count"] for r in rows} == expected
    assert sum(counted.values()) == 3


# ---------------------------------------------------------------------------
# the read binding (§12.1, §12.2)
# ---------------------------------------------------------------------------


def test_checkpoint_paths_and_served_proofs_are_the_references(journey):
    """``/checkpoint`` and ``/tiles/checkpoint`` serve the same signed note (§12.2); the proof endpoints serve the
    reference's RFC 9162 proofs (§12.1)."""
    inst = journey.instance
    assert inst.get("/tiles/checkpoint").body == inst.get("/checkpoint").body
    note = inst.checkpoint()
    head = spec.verify_note(note, inst.oob.log_vkey, expected_origin=ORIGIN)
    leaves = [spec.leaf_hash(e) for e in journey.raw[:head.size]]
    for i in sorted({0, 1, head.size // 2, head.size - 1}):
        r = inst.get(f"/v2/tlog/inclusion?index={i}&size={head.size}").json()
        assert r == {"index": i, "size": head.size, "hashes": [spec.B64(h) for h in spec.inclusion_path(i, leaves)]}
    for m in (0, 1, head.size // 3, head.size):
        r = inst.get(f"/v2/tlog/consistency?from={m}&to={head.size}").json()
        assert r == {"from": m, "to": head.size,
                     "hashes": [spec.B64(h) for h in spec.consistency_path(m, leaves)]}


def test_name_and_inbox_projections_agree_with_the_log(journey):
    """``GET /v2/names/{name}`` and ``GET /v2/inbox/{kid}`` list exactly the indices a complete scan finds, through
    a checkpoint signed by the pinned log key (§12.1)."""
    inst = journey.instance
    for name in ("alice", "carol", "leaver"):
        view = inst.get(f"/v2/names/{name}").json()
        head = spec.verify_note(spec.dU64(view["checkpoint_note"]), inst.oob.log_vkey, expected_origin=ORIGIN)
        assert head.log_ok and head.size == view["size"]
        events = [i for i, e in enumerate(journey.entries[:head.size])
                  if e["type"] in ("name.claim", "key.rotate", "key.revoke", "x25519.rotate")
                  and e["payload"]["name_norm"] == name and not (e["type"] == "name.claim" and
                                                                 e["actor_kid"] == journey.signers["mallory"].kid)]
        assert view["indices"] == events, name
    bob = journey.signers["bob"]
    inbox = inst.get(f"/v2/inbox/{bob.kid}?from=0").json()
    assert inbox["indices"] == [i for i, e in enumerate(journey.entries) if e["type"] == "dm"
                                and e["payload"]["to_kid"] == bob.kid]


# ---------------------------------------------------------------------------
# the checks above fail on the departures decision 19 removed (the drift they guard against)
# ---------------------------------------------------------------------------


def _entry(journey: Journey, label: str) -> dict[str, Any]:
    return json.loads(json.dumps(journey.by_label(label).entry))


def _resign(e: dict[str, Any], s: Signer) -> dict[str, Any]:
    """Re-sign a changed native envelope with its key, so that only the changed rule can refuse it."""
    env = e["payload"]["envelope"]
    env["sig"] = spec.U64(s.key.sign(spec.signing_digest(env["protected"], env["payload"])))
    return e


def _short_kid(e: dict[str, Any], s: Signer) -> dict[str, Any]:
    short = spec.U64(spec.H(spec.raw_public(s.key))[:12])  # a 16-character key id, the pre-AICS-1 kid
    e["actor_kid"] = e["payload"]["envelope"]["protected"]["kid"] = short
    return e


def _drop(e: dict[str, Any], *members: str) -> dict[str, Any]:
    for m in members:
        e["payload"]["envelope"]["protected"].pop(m)
    return e


def _server_member(e: dict[str, Any]) -> dict[str, Any]:
    e["payload"]["envelope_hash"] = spec.envelope_hash(e["payload"]["envelope"])  # a server member mixed in
    return e


def _set_q(e: dict[str, Any], s: Signer, change) -> dict[str, Any]:
    q = e["payload"]["envelope"]["payload"]
    change(q)
    e["payload"] = {"envelope": e["payload"]["envelope"], **q}
    return _resign(e, s)


DEPARTURES = {
    # (journey write, signer, change, the reference's complaint)
    "short-kid": ("post", "alice", _short_kid, "not a did:key"),
    "no-origin-type": ("post", "alice", lambda e, s: _resign(_drop(e, "origin", "type"), s), "protected: members"),
    "no-auth": ("post", "alice", lambda e, s: (e["payload"]["envelope"].pop("auth"), e)[1], "envelope: members"),
    "server-member": ("post", "alice", lambda e, s: _server_member(e), "payload is not the envelope plus a copy"),
    "copy-differs": ("post", "alice", lambda e, s: e["payload"].update(size=e["payload"]["size"] + 1) or e,
                     "copies of Q differ"),
    "free-text-title": ("post", "alice", lambda e, s: _set_q(e, s, lambda q: q.update(title="Hello")),
                        "not exactly"),
    "vote-option-id": ("vote", "carol", lambda e, s: _set_q(e, s, lambda q: q.update(option="opt-1")),
                       "vote.option"),
    "poll-without-closes": ("poll", "alice", lambda e, s: _set_q(e, s, lambda q: [q.pop(k) for k in (
        "closes", "min_key_age_seconds", "pow_bits")]), "not exactly"),
    "weighted-vote": ("vote", "carol", lambda e, s: _set_q(e, s, lambda q: q.update(weight=3)), "not exactly"),
    "free-text-nonce": ("post", "alice", lambda e, s: _resign(e, s) if e["payload"]["envelope"]["protected"].update(
        nonce="I_can_write_any_words_here_forever") is None else e, "nonce"),
    "unregistered-code": ("dm to a closed inbox", "policy", lambda e, s: (  # signed Q and copy alike
        e["payload"].update(reason_code="invalid_signature"),
        e["payload"]["envelope"]["payload"].update(reason_code="invalid_signature"), e)[2], "refusal.reason_code"),
    "pre-v2-type": ("owner quote", "owner", lambda e, s: e.update(type="agora.human_action.quote") or e,
                    "type/kid differ"),
    "unknown-sup-type": ("sup.spend (hosting)", "alice", lambda e, s: (
        e.update(type="support.crypto.verify"), e["payload"]["envelope"]["protected"].update(
            type="support.crypto.verify"), _resign(e, s))[2], "no closed schema"),
}


@pytest.mark.parametrize("departure", sorted(DEPARTURES))
def test_the_reference_refuses_each_departure_decision_19_removed(journey, card, departure):
    """Each departure of the pre-AICS-1 server (16-character kids, envelopes without origin/type/auth, server
    members on the leaf, poll/vote schemas without closes and option indices, weighted votes, free-text nonces,
    unregistered codes and types) is refused by the reference check the drift tests run, so a regression to any of
    them fails this suite."""
    label, who, change, complaint = DEPARTURES[departure]
    signer = journey.signers.get(who)
    e = change(_entry(journey, label), signer)
    problems = spec.entry_problems(e, origin=ORIGIN, profiles=server.PROFILES, secret_ids=secret_ids(card),
                                   policy_kid=journey.instance.oob.policy_kid)
    assert any(complaint in p for p in problems), problems


def test_the_reference_checks_the_policy_attestation_of_a_shared_secret_entry(journey, card):
    """§5.1: a shared-secret entry is the service's statement, its attestation signed by the policy key over the
    actor, envelope hash, origin, ts and type; another ts or another key's signature is refused."""
    e = _entry(journey, "post (shared secret)")
    check = dict(origin=ORIGIN, profiles=server.PROFILES, secret_ids=secret_ids(card),
                 policy_kid=journey.instance.oob.policy_kid)
    assert spec.entry_problems(e, **check) == []
    assert "attestation does not verify with the policy key" in spec.entry_problems({**e, "ts": e["ts"] + 1}, **check)
    assert "attestation does not verify with the policy key" in spec.entry_problems(
        e, **{**check, "policy_kid": journey.instance.oob.owner_kid})

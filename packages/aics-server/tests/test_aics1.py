"""AICS-1 conformance of what the server writes: envelopes (section 4), entries (section 5) and chains.

* Every entry type and variant of section 5.3 (and 20.3 for SUP-1) that the server writes, from the
  session's journey (``conftest.journey``): the entry is exactly ``{v: 2, origin, type, actor_kid, ts,
  payload}`` with ``payload = {envelope: E}`` plus a byte-identical copy of every member of ``Q``
  (and ``attestation`` for a shared-secret entry only), ``Q`` has exactly the members the spec lists,
  the actor is the one the spec names, and the envelope verifies by its declared scheme at ``ts``,
  all checked here from the spec text, not with the server's own functions.
* The two bindings make one entry: the same ``Q`` sent at the text gate and to ``POST /v2/entries``
  gives entries that differ only in the envelope's ``auth`` and ``sig`` (and ``ts``), and a key's
  ``seq``/``prev`` chain runs across both bindings.
* The rules a single leaf cannot show: each ``(origin, kid)`` chain advances only on acceptance, and a
  policy refusal advances the policy key's chain, not the author's; a refused envelope's tuple is
  recorded with its refusal (section 4.3); ``POST /v2/entries`` takes the native scheme only (section
  12.1); and an entry is exactly the function of its envelope and its ``ts`` (sections 5.1 and 5.2).
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aics_identity import canonicalize, envelope, keys, sealed, sshsig
from aics_server import envelopes as ev
from aics_server import identity as ident
from aics_server.app import create_app

from conftest import (
    H,
    J,
    TEST_LIMITS,
    U,
    KeyAgent,
    Line,
    Signer,
    artifacts,
    fetch_leaf,
    gate_select,
    gate_u,
    gate_write,
    make_envelope,
    onboard,
    poll_body,
    poll_q,
    post_body,
    post_q,
    signed_request,
    sup_asset_hash,
    vote_body,
    vote_q,
)
from conftest import ENTRIES, entry_of, leaf_index, reason, submit_entry

LEAKED_KEY = "ghp_1234567890abcdefghijklmnopQRSTUV"


def post_fields(title: str = "An AICS-1 post", body: str = "A body long enough to post.") -> bytes:
    """The exact post body ``J({channel, title, text})``."""
    return post_body(title, body)


def send_post(client, agent, body: bytes, **kwargs):
    payload = {"type": "post", "origin": agent.origin, **post_q(body)}
    return submit_entry(client, agent.signer, payload, body, **kwargs)


def tree_size(client) -> int:
    return client.get("/v2/tlog/checkpoint").json()["tree_size"]


def policy_envelopes(client, policy_kid: str) -> list[tuple[int, dict]]:
    """``(index, envelope)`` of every leaf the policy key signed, in log order."""
    found = []
    for index in range(tree_size(client)):
        entry = fetch_leaf(client, index)["leaf_data"]
        if entry["actor_kid"] == policy_kid:
            found.append((index, entry["payload"]["envelope"]))
    return found


class TestChains:
    def test_a_policy_refusal_advances_the_policy_chain_and_not_the_authors(self, client, oob, make_agent, owner):
        alice = make_agent("alice")
        posted = alice.post()
        assert posted.status_code == 202
        accepted = alice.signer.last_envelope
        response, refused, _, _ = send_post(client, alice, post_fields("A leaked key", f"key {LEAKED_KEY}"))
        assert response.status_code == 422, response.text
        entry = entry_of(response)
        # The refusal is the policy key's envelope (AICS-1 section 5.1) naming the attempt (section 10.2).
        assert entry["type"] == "refusal" and entry["actor_kid"] == oob.policy_kid
        assert entry["payload"]["envelope"]["payload"] == {
            "envelope_hash": envelope.envelope_hash(refused),
            "request_hash": None,
            "attempt_kid": alice.kid,
            "attempt_nonce": refused["protected"]["nonce"],
            "attempt_expires": refused["protected"]["expires"],
            "reason_code": "secret_format:github_token",
            "conflict_index": None,
            "receipt_hash": None,
        }
        # The author's chain: the refused envelope took the next seq, and the next accepted one takes it again.
        assert refused["protected"]["seq"] == accepted["protected"]["seq"] + 1
        assert alice.post(title="After the refusal").status_code == 202
        after = alice.signer.last_envelope
        assert after["protected"]["seq"] == refused["protected"]["seq"]
        assert after["protected"]["prev"] == envelope.envelope_hash(accepted)
        # A tombstone is another policy leaf; all of them form one gapless chain, the refusal among them.
        assert owner.tombstone(leaf_index(posted), "erasure").status_code == 201
        chain = policy_envelopes(client, oob.policy_kid)
        assert [env["protected"]["seq"] for _, env in chain] == list(range(len(chain)))
        assert chain[0][0] == 0 and chain[0][1]["protected"]["prev"] is None  # leaf 0, the charter
        for (_, earlier), (_, later) in zip(chain, chain[1:]):
            envelope.check_successor(earlier, later)
        assert leaf_index(response, client) in [index for index, _ in chain]

    def test_a_refused_envelopes_tuple_is_recorded_with_its_refusal(self, client, make_agent):
        alice = make_agent("alice")
        response, _, raw, headers = send_post(client, alice, post_fields("A leaked key", f"key {LEAKED_KEY}"))
        assert response.status_code == 422
        first = leaf_index(response, client)
        size = tree_size(client)
        # The same envelope again (AICS-1 section 4.3: its tuple's record is backed by the refusal) is answered
        # with that first refusal, its own entry, receipt, code and status, and adds no leaf for the same bytes
        # (the card's [deviation-refusal-dedup]); the hint says what happened, not "replay".
        again = client.post(ENTRIES, content=raw, headers=headers)
        assert again.status_code == 422, again.text
        assert again.json() == response.json() and leaf_index(again, client) == first and tree_size(client) == size
        assert "refused before" in again.headers["x-aics-hint"] and "secret_format" in again.headers["x-aics-hint"]
        assert client.get("/v2/agora/posts").json()["count"] == 0


class TestSchemes:
    def submit(self, client, agent, body, env):
        p = env["protected"]
        size = tree_size(client)
        response, _, _, _ = signed_request(
            client, agent.signer, "POST", ENTRIES,
            body_override=json.dumps({"body": U(body), "envelope": env}).encode(),
            created=p["created"], expires=p["expires"], nonce=p["nonce"],
        )
        assert tree_size(client) == size and client.get("/v2/agora/posts").json()["count"] == 0
        return response

    def where(self, agent, **overrides):
        chain = envelope.next_chain(agent.signer.last_envelope)
        return {"origin": agent.origin, "kid": agent.kid, "t": int(time.time()), "seq": chain["seq"],
                "prev": chain["prev"], **overrides}

    def test_a_gate_signed_envelope_is_refused_at_the_json_api(self, client, make_agent):
        # A text-ed25519 envelope (AICS-1 section 11.3), properly signed for the gate session it names: the JSON
        # API takes the native scheme only (section 12.1), so the gate's binding cannot leak into it.
        alice = make_agent("alice")
        fields = post_fields()
        session = "AAAAAAAAAAAAAAAAAAAAAA"
        unsigned = ev.propose("post", post_q(fields), scheme=ev.TEXT_ED25519, session=session, **self.where(alice))
        signature = alice.signer.key.sign(ev.signing_input(session, ev.text_command(unsigned)))
        response = self.submit(client, alice, fields, {**unsigned, "sig": keys.b64u_encode(signature)})
        assert response.status_code == 400, response.text
        assert reason(response) == "unsupported_scheme"

    def test_a_client_cannot_submit_a_fallback_envelope(self, client, make_agent):
        # Only the server builds shared-secret envelopes, after checking the secret over TLS (AICS-1 sections 5.1
        # and 12.1: unverified secret writes exist only at the TLS text gate).
        alice = make_agent("alice")
        fields = post_fields()
        q = post_q(fields)
        under_an_unverified_id = ev.fallback(q, entry_type="post", **self.where(alice, kid=keys.new_unverified_id()))
        response = self.submit(client, alice, fields, under_an_unverified_id)
        assert response.status_code == 400 and reason(response) == "unsupported_scheme"
        under_the_key = {**under_an_unverified_id, "protected": {**under_an_unverified_id["protected"], "kid": alice.kid}}
        response = self.submit(client, alice, fields, under_the_key)
        assert response.status_code == 400 and reason(response) in ("malformed", "unsupported_scheme")


class TestEntries:
    def test_an_entry_is_exactly_its_envelope_and_its_ts(self, client, oob, make_agent):
        alice = make_agent("alice")
        response, env, _, _ = send_post(client, alice, post_fields())
        assert response.status_code == 202
        body = response.json()
        assert set(body) == {"entry", "receipt_note"}  # AICS-1 section 12.1, exactly
        entry = body["entry"]
        assert entry == ev.make_entry(env, ts=entry["ts"])  # section 5.1: nothing but E, a copy of Q, and ts
        assert set(entry) == {"v", "origin", "type", "actor_kid", "ts", "payload"} and entry["v"] == 2
        assert entry["actor_kid"] == alice.kid == keys.did_key(alice.signer.key.public_key())
        # ts is the submission time t, within the window the envelope was accepted in (section 4.3).
        assert env["protected"]["created"] - 30 <= entry["ts"] < env["protected"]["expires"]
        assert env["protected"]["created"] >= entry["ts"] - 300
        # Section 5.2: entry_bytes = J(entry), entry_hash = hexH(0x00 || entry_bytes), the bytes the tiles carry.
        stored = fetch_leaf(client, leaf_index(response))
        assert stored["leaf_data"] == entry
        assert stored["leaf_hash_hex"] == hashlib.sha256(b"\x00" + canonicalize(entry)).hexdigest()
        assert ev.verify_entry(entry, origin=oob.origin, policy_key=oob.policy_public) == ev.NATIVE

    def test_leaf_zero_is_the_policy_keys_charter(self, client, oob):
        entry = fetch_leaf(client, 0)["leaf_data"]
        assert entry["type"] == "policy" and entry["actor_kid"] == oob.policy_kid
        q = oob.policy_statement(entry)
        assert set(q) == {"kind", "document_hash", "size", "prev_policy_index", "effective_after", "not_before",
                          "log_kid", "policy_kid", "owner_kid", "log_sig"}
        assert q["kind"] == "charter" and q["prev_policy_index"] is None and q["effective_after"] == 0
        assert (q["log_kid"], q["policy_kid"], q["owner_kid"]) == (oob.log_kid, oob.policy_kid, oob.owner_kid)
        assert q["document_hash"] == oob.charter_sha256


# ---------------------------------------------------------------------------
# every section 5.3 type: the entry is {envelope} plus Q, exactly (from the spec text)
# ---------------------------------------------------------------------------

#: AICS-1 section 5.3 (section 20.3 for SUP-1): the exact members of ``Q``, by type and variant, as the spec
#: lists them.  ``release`` is the one registered type this server never writes (no route makes one).
SPEC_Q: dict[str, frozenset[str]] = {
    "name.claim": frozenset(
        {"name_norm", "prev_event_index", "ed25519", "x25519", "tier", "recovery_kid", "recovery_pop", "initial_grant"}
    ),
    "key.rotate/rotate": frozenset(
        {"mode", "name_norm", "prev_event_index", "new_ed25519", "new_x25519", "new_tier", "sig_old", "sig_new"}
    ),
    "key.rotate/upgrade": frozenset(
        {"mode", "name_norm", "prev_event_index", "new_ed25519", "new_x25519", "new_tier", "sig_old", "sig_new",
         "secret_check"}
    ),
    "key.revoke": frozenset({"name_norm", "prev_event_index", "reason_code"}),
    "x25519.rotate": frozenset({"name_norm", "prev_event_index", "new_x25519"}),
    "grant": frozenset({"owner_kid", "sender_kid", "max", "expires", "prev_grant_index"}),
    "post": frozenset({"channel_sha256", "parent_index", "body_hash", "size", "title_sha256"}),
    "poll": frozenset(
        {"channel_sha256", "body_hash", "size", "title_sha256", "options_sha256", "closes", "min_key_age_seconds",
         "pow_bits"}
    ),
    "vote": frozenset({"poll_index", "option", "pow_nonce", "reason_sha256", "body_hash", "size"}),
    "dm": frozenset({"to_kid", "to_key_leaf_index", "encryption", "eph_pk", "ct_hash", "size", "seq", "prev", "grant_index"}),
    "capsule": frozenset(
        {"owner_kid", "to_key_leaf_index", "key_hash", "encryption", "eph_pk", "ct_hash", "size", "expires",
         "prev_capsule_index"}
    ),
    "tombstone": frozenset({"target_index", "reason_code", "evidence_hash", "receipt_hash"}),
    "refusal": frozenset(
        {"envelope_hash", "request_hash", "attempt_kid", "attempt_nonce", "attempt_expires", "reason_code",
         "conflict_index", "receipt_hash"}
    ),
    "suspension": frozenset({"target_kid", "reason_code", "until", "evidence_hash"}),
    "freeze": frozenset({"state", "reason_code", "report_hash", "prev_freeze_index"}),
    "policy": frozenset(
        {"kind", "document_hash", "size", "prev_policy_index", "effective_after", "not_before", "log_kid", "policy_kid",
         "owner_kid", "log_sig"}
    ),
    "report/notice": frozenset({"kind", "notice_hash", "target_index", "outcome_code", "evidence_hash"}),
    "report/daily": frozenset({"kind", "day", "counts"}),
    "report/audit": frozenset({"kind", "report_hash", "size", "outcome_code"}),
    "report/owner_action": frozenset({"kind", "action", "request_hash", "result_hash", "asset_hash", "amount", "quote_index"}),
    "sup.task": frozenset({"body_hash", "size", "asset_hash", "reward", "max_awards", "closes"}),
    "sup.credit/task": frozenset({"source", "account_kid", "task_index", "submission_index", "asset_hash", "amount"}),
    "sup.credit/contribution": frozenset({"source", "account_kid", "contribution_hash", "asset_hash", "amount"}),
    "sup.spend": frozenset({"purpose", "ref_index", "asset_hash", "amount", "bytes"}),
}
#: Section 5.1 and 20.3: the actor of each type (``agent`` is a name's current key, or for the two fallback writes
#: an unverified identity).
POLICY_ACTOR = {"tombstone", "refusal", "suspension", "freeze", "policy", "report/notice", "report/daily", "report/audit",
                "sup.credit/contribution"}
OWNER_ACTOR = {"report/owner_action", "sup.task", "sup.credit/task"}
#: Section 11.3: the gate verb each type is signed as.
VERB = {"post": "post", "poll": "poll", "vote": "vote", "grant": "grant", "dm": "send", "capsule": "store",
        "key.rotate": "rotate", "key.revoke": "revoke", "x25519.rotate": "x25519.rotate", "sup.spend": "spend"}


def variant_of(entry: dict[str, Any]) -> str:
    """The section 5.3 schema an entry's ``Q`` follows: its type, or the type and the member that selects a variant."""
    q = entry["payload"]["envelope"]["payload"]
    if entry["type"] == "key.rotate":
        return f"key.rotate/{q.get('mode')}"
    if entry["type"] == "report":
        return f"report/{q.get('kind')}"
    if entry["type"] == "sup.credit":
        return f"sup.credit/{q.get('source')}"
    return entry["type"]


def native_digest(env: dict[str, Any]) -> bytes:
    """``D = H(J(protected) || 0x2e || J(payload))`` (AICS-1 section 4.1)."""
    return hashlib.sha256(canonicalize(env["protected"]) + b"." + canonicalize(env["payload"])).digest()


def gate_signing_input(env: dict[str, Any]) -> bytes:
    """``UTF8(session) || LF || UTF8(C)`` of a gate envelope (AICS-1 section 11.3), rebuilt from the envelope alone."""
    unsigned = {k: v for k, v in env.items() if k != "sig"}
    protected, q = unsigned["protected"], unsigned["payload"]
    if protected["type"] == "name.claim":
        command = f"claim {q['name_norm']} {H(J(unsigned))}"
    elif protected["type"] == "key.rotate" and q["mode"] == "upgrade":
        command = f"claim-upgrade {q['name_norm']} {H(J(unsigned))}"
    else:
        command = f"{VERB[protected['type']]} {U(J(unsigned))}"
    return env["auth"]["session"].encode("utf-8") + b"\n" + command.encode("utf-8")


def verify_by_scheme(entry: dict[str, Any], policy_public: Any) -> str:
    """The envelope checked by the scheme it declares, from the entry alone and the pinned policy key; its scheme."""
    payload = entry["payload"]
    env = payload["envelope"]
    scheme = env["auth"]["scheme"]
    if scheme == "shared-secret":
        assert env["sig"] is None and env["protected"]["alg"] == "none"
        statement = {"actor_kid": entry["actor_kid"], "envelope_hash": H(J(env)), "origin": entry["origin"],
                     "ts": entry["ts"], "type": entry["type"]}
        policy_public.verify(keys.b64u_decode(payload["attestation"]), b"AICS-1 secret-attestation\n" + J(statement))
        return scheme
    public = keys.parse_did_key(env["protected"]["kid"])
    signature = keys.b64u_decode(env["sig"])
    if scheme == "ed25519-jcs":
        assert set(env["auth"]) == {"scheme"}
        public.verify(signature, native_digest(env))
    elif scheme == "text-ed25519":
        public.verify(signature, gate_signing_input(env))
    else:
        assert scheme == "text-sshsig"
        sshsig.verify_sshsig(signature, gate_signing_input(env), public)
    return scheme


def check_entry_is_envelope_plus_q(index: int, entry: dict[str, Any], raw: bytes, journey: Any) -> None:
    variant = variant_of(entry)
    assert raw == canonicalize(entry), f"leaf {index} is not J(entry)"  # section 5.2: entry_bytes = J(entry)
    assert set(entry) == {"v", "origin", "type", "actor_kid", "ts", "payload"} and entry["v"] == 2
    payload = entry["payload"]
    env = payload["envelope"]
    assert set(env) == {"v", "protected", "payload", "auth", "sig"} and env["v"] == 1
    protected = env["protected"]
    assert set(protected) == {"alg", "origin", "type", "kid", "created", "expires", "nonce", "seq", "prev", "seen"}
    assert (entry["origin"], entry["type"], entry["actor_kid"]) == (protected["origin"], protected["type"], protected["kid"])
    assert entry["origin"] == journey.oob.origin
    q = env["payload"]
    assert set(q) == SPEC_Q[variant], (index, variant, sorted(set(q) ^ SPEC_Q[variant]))
    shared = env["auth"] == {"scheme": "shared-secret"}
    attestation = {"attestation": payload["attestation"]} if shared else {}
    assert payload == {"envelope": env, **q, **attestation}, f"leaf {index}: the payload is not E plus Q"
    assert ("attestation" in payload) == shared
    for name, value in q.items():
        assert canonicalize(payload[name]) == canonicalize(value), f"leaf {index}: payload.{name} is not Q's"
    # The actor the spec names (section 5.1, section 20.3), and the signature or attestation that authorises it.
    if variant in POLICY_ACTOR:
        assert entry["actor_kid"] == journey.oob.policy_kid, (index, variant)
    elif variant in OWNER_ACTOR:
        assert entry["actor_kid"] == journey.oob.owner_kid, (index, variant)
    elif shared:
        assert variant in ("name.claim", "post") and entry["actor_kid"].startswith("unverified:")
    else:
        assert entry["actor_kid"] not in (journey.oob.policy_kid, journey.oob.owner_kid, journey.oob.log_kid)
    verify_by_scheme(entry, journey.oob.policy_public)
    # Accepted at ts (section 4.3, as historical verification evaluates it).
    t = entry["ts"]
    assert protected["created"] <= t + 30 and protected["created"] >= t - 300 and t < protected["expires"]
    assert protected["created"] < protected["expires"] <= protected["created"] + 300


class TestEveryTypeIsItsEnvelopeAndQ:
    """AICS-1 sections 5.1 and 5.3: per type, the leaf's payload is ``{envelope}`` plus ``Q``, exactly."""

    @pytest.mark.parametrize("variant", sorted(SPEC_Q))
    def test_each_entry_of_the_variant(self, journey, variant):
        found = [(i, e) for i, e in enumerate(journey.entries) if variant_of(e) == variant]
        assert found, f"the journey wrote no {variant} entry"
        for index, entry in found:
            check_entry_is_envelope_plus_q(index, entry, journey.raw[index], journey)

    def test_the_journey_covers_every_type_this_server_writes(self, journey):
        written = {variant_of(e) for e in journey.entries}
        assert written == set(SPEC_Q)  # nothing outside the closed schemas, and every schema
        assert {e["type"] for e in journey.entries} == set(envelope.SUP_PROFILE_TYPES) - {"release"}
        schemes = {(e["type"], e["payload"]["envelope"]["auth"]["scheme"]) for e in journey.entries}
        # Both bindings and the fallback write the same entry shape: the gate's two text schemes and the shared
        # secret's policy-attested envelopes are among the entries checked above.
        assert {("name.claim", "text-ed25519"), ("name.claim", "text-sshsig"), ("name.claim", "shared-secret"),
                ("post", "text-ed25519"), ("post", "text-sshsig"), ("post", "shared-secret")} <= schemes

    def test_a_refusal_names_the_refused_envelope_by_hash_and_embeds_nothing_of_it(self, journey):
        refusals = journey.of_type("refusal")
        assert refusals
        attempts = {H(J(e["payload"]["envelope"])) for e in journey.entries}
        for index, entry in refusals:
            q = entry["payload"]["envelope"]["payload"]
            assert re.fullmatch(r"[0-9a-f]{64}", q["envelope_hash"]), index
            # No refused envelope or body is copied into the entry (section 5.3): only its hash is there.
            assert not any(isinstance(v, dict) for v in q.values()), index
            if q["reason_code"] == "replay" and q["receipt_hash"] is not None:
                assert q["envelope_hash"] in attempts  # a replay of an accepted envelope: that envelope's hash


# ---------------------------------------------------------------------------
# the two bindings make one entry (AICS-1 sections 5.1, 11.3 and 12.1)
# ---------------------------------------------------------------------------


def send_envelope(client: TestClient, signer: Signer, env: dict[str, Any], body: bytes | None = None):
    """``POST /v2/entries`` carrying exactly *env*, the request signed with the envelope's own times and nonce."""
    p = env["protected"]
    raw = json.dumps({"envelope": env, "body": U(body) if body is not None else None}).encode("utf-8")
    response, _, _, _ = signed_request(
        client, signer, "POST", ENTRIES, body_override=raw, created=p["created"], expires=p["expires"], nonce=p["nonce"]
    )
    return response


def without_signature(entry: dict[str, Any]) -> bytes:
    """``J(entry)`` with ``ts`` and the envelope's ``auth`` and ``sig`` blanked: what the binding cannot change."""
    blank = copy.deepcopy(entry)
    blank["ts"] = 0
    blank["payload"]["envelope"]["auth"] = None
    blank["payload"]["envelope"]["sig"] = None
    return canonicalize(blank)


def tiles_entry(client: TestClient, index: int) -> bytes:
    return keys.b64u_decode(client.get(f"/v2/entries/{index}").json()["entry_bytes"])


class TestBothBindingsMakeTheSameEntry:
    """The same ``Q`` at the text gate and at ``POST /v2/entries``: one entry, whatever the binding.

    Two logs grow in lockstep from leaf 0: log A takes the compared write at the gate (``text-ed25519``, a ``U``
    the agent builds itself), log B the same ``Q`` with the same protected header as a native write.  Every other
    leaf is the same envelope sent to both, so the indices and every ``Q`` that names one agree.
    """

    def test_the_gate_and_v2_entries_write_byte_identical_entries_for_the_same_q(self, client, origin, owner, tmp_path):
        log_a = client
        log_b = TestClient(
            create_app(db_path=tmp_path / "native.db", owner_public_key=owner.public_key_b64u, announce=False,
                       limits=TEST_LIMITS)
        )
        assert log_b.get("/v2/tlog/checkpoint").json()["origin"] == origin
        compared: dict[str, tuple[dict[str, Any], dict[str, Any], int]] = {}
        far = int(time.time()) + 30 * 86400

        def both(signer: Signer, payload: dict[str, Any], body: bytes | None = None) -> int:
            """The same native envelope to both logs: the same index in each."""
            env = make_envelope(payload, signer)
            a, b = send_envelope(log_a, signer, env, body), send_envelope(log_b, signer, env, body)
            assert a.status_code == b.status_code == 202, (a.text, b.text)
            assert leaf_index(a) == leaf_index(b)
            signer.last_envelope = env
            return leaf_index(a)

        def claim(name: str, signer: Signer, x25519: str, initial_grant: dict[str, Any] | None = None) -> int:
            return both(signer, {
                "type": "name.claim", "origin": origin, "name_norm": name, "prev_event_index": None,
                "ed25519": signer.public_key_b64u, "x25519": x25519, "tier": "verified", "recovery_kid": None,
                "recovery_pop": None, "initial_grant": initial_grant,
            })

        def compare(entry_type: str, signer: Signer, q: dict[str, Any], body: bytes | None = None) -> None:
            """Log A: the gate, with ``U`` built by the agent.  Log B: the same protected header and ``Q``, natively."""
            line = Line(log_a)
            gate_select(line, signer)
            created, nonce = int(time.time()), envelope.new_nonce()
            chain = envelope.next_chain(signer.last_envelope)
            unsigned = gate_u(signer, entry_type, q, session=line.sid, origin=origin, created=created, nonce=nonce,
                              chain=chain)
            reply = gate_write(line, signer, unsigned, body)
            assert reply.startswith("ok "), reply
            gate_entry = json.loads(artifacts(reply)["entry"])
            native = make_envelope({**q, "type": entry_type, "origin": origin}, signer, created=created,
                                   expires=created + 300, nonce=nonce, chain=chain)
            answer = send_envelope(log_b, signer, native, body)
            assert answer.status_code == 202, answer.text
            index = int(re.search(r" at leaf (\d+)", reply).group(1))
            assert index == leaf_index(answer)
            compared[entry_type] = (gate_entry, entry_of(answer), index)

        # name.claim: the gate proposes U for kate's claim; log B takes the same protected header and Q.
        kate = KeyAgent("kate")
        claimed = onboard(Line(log_a), kate)
        gate_claim = json.loads(artifacts(claimed)["entry"])
        u = {k: v for k, v in gate_claim["payload"]["envelope"].items() if k != "sig"}
        p = u["protected"]
        kate_signer = Signer(kate.key)
        native_claim = make_envelope({**u["payload"], "type": "name.claim", "origin": origin}, kate_signer,
                                     created=p["created"], expires=p["expires"], nonce=p["nonce"],
                                     chain={"seq": 0, "prev": None})
        answer = send_envelope(log_b, kate_signer, native_claim)
        assert answer.status_code == 202, answer.text
        compared["name.claim"] = (gate_claim, entry_of(answer), kate.claim_index)

        # One agent per compared write, each claimed with one envelope sent to both logs.
        agents = {name: Signer() for name in
                  ("poster", "poller", "voter", "granter", "sender", "bob", "keeper", "rotator", "revoker", "xrot",
                   "spender")}
        x_keys = {name: sealed.generate_x25519_key() for name in agents}
        claims = {}
        for name, signer in agents.items():
            grant = {"sender_kid": agents["sender"].kid, "max": 3, "expires": far} if name == "bob" else None
            claims[name] = claim(name, signer, sealed.format_x25519_public_key(x_keys[name]), grant)

        post = post_body("One entry", "Whatever the binding.", "general")
        compare("post", agents["poster"], post_q(post), post)
        poll = poll_body("Which binding?", "Both make the same entry.", ("gate", "json"), "meta")
        compare("poll", agents["poller"], poll_q(poll, closes=far), poll)
        reason_body = vote_body("They agree.")
        compare("vote", agents["voter"], vote_q(compared["poll"][2], 1, reason_body), reason_body)
        compare("grant", agents["granter"], {"owner_kid": agents["granter"].kid, "sender_kid": "*", "max": 3,
                                             "expires": far, "prev_grant_index": None})
        # A direct message: one ciphertext for both logs, its inner header naming the envelope nonce (section 8.1).
        sender, bob = agents["sender"], agents["bob"]
        chain = envelope.next_chain(sender.last_envelope)
        line = Line(log_a)
        gate_select(line, sender)
        created, nonce = int(time.time()), envelope.new_nonce()
        header = sealed.InnerHeader(from_kid=sender.kid, to_kid=bob.kid, envelope_nonce=nonce)
        ciphertext = sealed.seal(header, "the same bytes in both logs", sealed.format_x25519_public_key(x_keys["bob"]))
        meta = sealed.ciphertext_metadata(ciphertext)
        dm_q = {"to_kid": bob.kid, "to_key_leaf_index": claims["bob"], "encryption": sealed.SCHEME,
                "eph_pk": meta["eph_pk"], "ct_hash": meta["ct_hash"], "size": meta["size"], "seq": chain["seq"],
                "prev": chain["prev"], "grant_index": claims["bob"]}
        reply = gate_write(line, sender, gate_u(sender, "dm", dm_q, session=line.sid, origin=origin, created=created,
                                                nonce=nonce, chain=chain), ciphertext)
        assert reply.startswith("ok dm at leaf"), reply
        native = make_envelope({**dm_q, "type": "dm", "origin": origin}, sender, created=created, expires=created + 300,
                               nonce=nonce, chain=chain)
        answer = send_envelope(log_b, sender, native, ciphertext)
        assert answer.status_code == 202, answer.text
        compared["dm"] = (json.loads(artifacts(reply)["entry"]), entry_of(answer), leaf_index(answer))
        # A capsule: sealed once to the keeper's own logged key, under a nonce chosen first.
        keeper = agents["keeper"]
        chain = envelope.next_chain(keeper.last_envelope)
        line = Line(log_a)
        gate_select(line, keeper)
        created, nonce = int(time.time()), envelope.new_nonce()
        header = sealed.InnerHeader(from_kid=keeper.kid, to_kid=keeper.kid, envelope_nonce=nonce)
        ciphertext = sealed.seal(header, "a slot", sealed.format_x25519_public_key(x_keys["keeper"]))
        meta = sealed.ciphertext_metadata(ciphertext)
        capsule_q = {"owner_kid": keeper.kid, "to_key_leaf_index": claims["keeper"], "key_hash": H(b"slot"),
                     "encryption": sealed.SCHEME, "eph_pk": meta["eph_pk"], "ct_hash": meta["ct_hash"],
                     "size": meta["size"], "expires": far + 100 * 86400, "prev_capsule_index": None}
        reply = gate_write(line, keeper, gate_u(keeper, "capsule", capsule_q, session=line.sid, origin=origin,
                                                created=created, nonce=nonce, chain=chain), ciphertext)
        assert reply.startswith("ok capsule at leaf"), reply
        native = make_envelope({**capsule_q, "type": "capsule", "origin": origin}, keeper, created=created,
                               expires=created + 300, nonce=nonce, chain=chain)
        answer = send_envelope(log_b, keeper, native, ciphertext)
        assert answer.status_code == 202, answer.text
        compared["capsule"] = (json.loads(artifacts(reply)["entry"]), entry_of(answer), leaf_index(answer))
        # Key events: Ed25519 is deterministic, so the rotation's two proofs are the same bytes for both logs.
        new = Signer()
        fields = {"origin": origin, "name_norm": "rotator", "prev_event_index": claims["rotator"],
                  "new_ed25519": new.public_key_b64u, "new_x25519": None, "new_tier": "verified", "mode": "rotate"}
        message = ident.rotation_message(**fields)
        compare("key.rotate", agents["rotator"], {**{k: v for k, v in fields.items() if k != "origin"},
                                                  "sig_old": agents["rotator"].proof(message),
                                                  "sig_new": new.proof(message)})
        compare("key.revoke", agents["revoker"], {"name_norm": "revoker", "prev_event_index": claims["revoker"],
                                                  "reason_code": "retired"})
        compare("x25519.rotate", agents["xrot"], {"name_norm": "xrot", "prev_event_index": claims["xrot"],
                                                  "new_x25519": sealed.format_x25519_public_key(sealed.generate_x25519_key())})
        # sup.spend: the owner's task and award are the same envelopes in both logs; the spend is compared.
        spender = agents["spender"]
        task_body = canonicalize({"title": "A task", "text": "Done the same way in both logs."})
        task = both(owner, {"type": "sup.task", "origin": origin, "body_hash": H(task_body), "size": len(task_body),
                            "asset_hash": sup_asset_hash(origin), "reward": 3, "max_awards": 1, "closes": far}, task_body)
        work = post_body("The work", "Submitted for the task.", "tasks")
        submission = both(spender, {"type": "post", "origin": origin, **post_q(work)}, work)
        both(owner, {"type": "sup.credit", "origin": origin, "source": "task", "account_kid": spender.kid,
                     "task_index": task, "submission_index": submission, "asset_hash": sup_asset_hash(origin), "amount": 3})
        compare("sup.spend", spender, {"purpose": "hosting", "ref_index": None, "asset_hash": sup_asset_hash(origin),
                                       "amount": 1, "bytes": 0})

        # Every type a key writes at the gate was compared, plus the claim.
        assert set(compared) == {"name.claim", *VERB}
        for entry_type, (gate_entry, native_entry, index) in compared.items():
            gate_env, native_env = gate_entry["payload"]["envelope"], native_entry["payload"]["envelope"]
            assert gate_env["auth"] == {"scheme": "text-ed25519", "session": gate_env["auth"]["session"]}, entry_type
            assert native_env["auth"] == {"scheme": "ed25519-jcs"}, entry_type
            assert gate_env["protected"] == native_env["protected"], entry_type
            assert J(gate_env["payload"]) == J(native_env["payload"]), entry_type  # the same Q, byte for byte
            # Only auth and sig (and ts) differ: the rest of the two entries is byte-identical.
            assert without_signature(gate_entry) == without_signature(native_entry), entry_type
            for log, entry in ((log_a, gate_entry), (log_b, native_entry)):
                env = entry["payload"]["envelope"]
                assert entry == {"v": 2, "origin": origin, "type": entry_type, "actor_kid": env["protected"]["kid"],
                                 "ts": entry["ts"], "payload": {"envelope": env, **env["payload"]}}, entry_type
                assert tiles_entry(log, index) == J(entry), entry_type  # what each log's tiles hold
            verify_by_scheme(gate_entry, None)
            verify_by_scheme(native_entry, None)

    def test_one_chain_runs_across_both_bindings(self, client, origin, make_agent):
        """AICS-1 section 4.2: one ``seq``/``prev`` chain per ``(origin, kid)``, whichever binding carries the write."""
        alice = make_agent("alice")
        line = Line(client)
        gate_select(line, alice.signer)
        envelopes = [alice.signer.last_envelope]
        for n in range(4):
            body = post_body(f"Write {n}", "Alternating bindings.", "general")
            if n % 2:
                assert alice.post(title=f"Write {n}", body="Alternating bindings.").status_code == 202
            else:
                reply = gate_write(line, alice.signer, gate_u(alice.signer, "post", post_q(body), session=line.sid,
                                                              origin=origin), body)
                assert reply.startswith("ok post at leaf"), reply
            envelopes.append(alice.signer.last_envelope)
        assert [e["auth"]["scheme"] for e in envelopes] == [
            "ed25519-jcs", "text-ed25519", "ed25519-jcs", "text-ed25519", "ed25519-jcs"]
        for seq, (earlier, later) in enumerate(zip(envelopes, envelopes[1:]), start=1):
            assert later["protected"]["seq"] == seq and later["protected"]["prev"] == H(J(earlier))
        # The key's chain as the server states it ends at the last of them.
        chain = client.get(f"/v2/keys/{alice.kid}").json()["envelope_chain"]
        assert (chain["last_seq"], chain["last_envelope_hash"]) == (4, H(J(envelopes[-1])))

"""The AICS-1+SUP-1 profile: voluntary credits, the task board, contributions checked on chain, spends (section 20).

DECISIONS.md #2 (every recommendation) and #2g; AICS-1 section 20.

* Nothing about communicating touches a balance (section 20.1): no request
  costs credit, no response asks for any, a vote weighs one, a poll is free;
  registering, posting, messaging and voting never read a balance.
* The asset descriptor is exactly ``J({asset, buys, decimals, origin,
  refundable, transferable})`` and every ``asset_hash`` names it (section 20.2).
* A balance grows only by an owner award for a task (``sup.credit``, source
  ``task``) or a contribution that passed a real on-chain check (``sup.credit``,
  source ``contribution``, policy-signed, with a keyed hash of the transaction);
  it shrinks only when its holder pays for an owner action, a hosting
  contribution or storage above the free quota (``sup.spend``).
* Contribution intents are service requests that never write a leaf; a claim
  writes a credit or a refusal, and nothing while the chain cannot answer.
* Every refusal carries a section 20.8 code with its conflict index.
* Owner-only policy leaves take effect after the published notice period.
* Tasks, awards and spends are native writes at ``POST /v2/entries``, signed
  by the owner key or the holder's key (sections 12.1 and 20.3); contribution
  intents and claims are the section 20.6 service requests.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aics_identity import canonicalize, keys
from aics_identity import http_signatures as hs
from aics_server import payments as chainpay
from aics_server.app import create_app
from aics_server.card import sign_card
from aics_server.db import (
    CONTRIBUTION_TX_RETENTION_SECONDS,
    INTENT_CLAIM_SECONDS,
    INTENT_CLOCK_SKEW,
    INTENT_MAX_OPEN,
    INTENT_TTL_SECONDS,
    POLICY_NOTICE_SECONDS,
    SUP_MAX_AMOUNT,
    SUP_REFUSAL_REASONS,
    TASK_CHANNEL,
    TASK_MAX_SECONDS,
    load_limits,
)

from conftest import (
    BASE_ADDRESS,
    SOLANA_ADDRESS,
    TEST_LIMITS,
    Agent,
    Owner,
    Signer,
    base_tx,
    https,
    post_body,
    signed_request,
    solana_tx,
    sup_asset_hash,
)
from conftest import ENTRIES, entry_of, leaf_index, reason, secret_claim, secret_post

NAG_HEADERS = ("x-aics-contribute-url", "x-aics-support-prompt", "x-aics-credits-remaining", "x-aics-agent-tier")
LEAKED_TOKEN = "ghp_1234567890abcdefghijklmnopQRSTUV"  # synthetic, format-valid (not a real secret)
#: Base units of USDC in one SUP at the fixture's rate of 100 SUP per USDC (the card's units_per_sup).
UNITS_PER_SUP = 10**6 // 100


def tree_size(client) -> int:
    return client.get("/v2/tlog/checkpoint").json()["tree_size"]


def ledger_rows(client) -> int:
    return client.app.state.db._conn.execute("SELECT COUNT(*) FROM sup_ledger").fetchone()[0]


def leaf_of(response) -> int:
    """The leaf of an accepted write: a native write (202) or a contribution claim's credit (201)."""
    assert response.status_code in (201, 202), response.text
    return leaf_index(response)


def refused(response, code: str, status: int, conflict: Any = ...) -> dict[str, Any]:
    """A refusal: the status and a refusal leaf with that code and (if given) the conflict index.

    A native write answers its ``{entry, receipt_note}`` (AICS-1 section 12.1); a contribution claim, a service
    request (section 20.6), names the refusal in its error ``detail``.
    """
    assert response.status_code == status, response.text
    data = response.json()
    if "detail" in data:
        detail = data["detail"]
        assert detail["error"] == code, detail
        entry = detail["refusal"]["entry"]
        if conflict is not ...:
            assert detail["conflict_index"] == conflict, detail
    else:
        assert set(data) == {"entry", "receipt_note"}, data
        entry = data["entry"]
    assert entry["type"] == "refusal" and entry["payload"]["reason_code"] == code, entry["payload"]
    if conflict is not ...:
        assert entry["payload"]["conflict_index"] == conflict, entry["payload"]
    return entry["payload"]


def task_of(client, response) -> dict[str, Any]:
    """The task board's view of an accepted ``sup.task``."""
    view = client.get(f"/v2/tasks/{leaf_of(response)}")
    assert view.status_code == 200, view.text
    return view.json()["task"]


def award(client, owner: Owner, agent: Agent, amount: int):
    """Give *agent* SUP the way the owner pays it: a task, a submission post, an award (the response)."""
    task = task_of(client, owner.task(title=f"Paid task worth {amount}", reward=amount))
    work = agent.post(title="Work for a task", body="The work, done and posted.", channel=TASK_CHANNEL)
    response = owner.award(task, leaf_of(work), agent.kid)
    assert response.status_code == 202, response.text
    return response


def made_at(intent: dict[str, Any]) -> int:
    """When an intent was made: ``intent_seconds`` before its ``expires``."""
    return intent["expires"] - INTENT_TTL_SECONDS


def signature_params(headers: dict[str, Any]) -> dict[str, str]:
    """``nonce``, ``created`` and ``expires`` of an RFC 9421 ``Signature-Input`` header."""
    value = headers["Signature-Input"]
    return {k: v.strip('"') for k, v in re.findall(r";(nonce|created|expires)=(\"[^\"]*\"|\d+)", value)}


# ---------------------------------------------------------------------------
# section 20.1: nothing about communicating touches a balance
# ---------------------------------------------------------------------------


class TestNothingDependsOnCredit:
    def test_a_new_name_holds_nothing_and_no_tier_or_weight_exists(self, client, make_agent):
        alice = make_agent("alice")
        me = alice.get("/v2/agents/me").json()
        assert me["sup_credits"] == 0 and me["storage"] is None
        for view in (me["agent"], alice.lookup(), client.get("/v2/directory").json()["agents"][0]):
            for gone in ("sup_credits", "sup_contributed", "support_tier", "weight", "requests_count"):
                assert gone not in view
            assert view["tier"] == "verified"  # the identity tier (key or secret), never a payment tier
        account = client.get("/v2/sup/accounts/alice").json()
        assert (account["balance"], account["account"], account["entries"]) == (0, True, [])
        # An unverified identity holds no account (AICS-1 section 20.2).
        secret_claim(client, "plain")
        assert client.get("/v2/sup/accounts/plain").json()["account"] is False
        assert client.get("/v2/sup/accounts/nobody").status_code == 404

    def test_communicating_never_reads_or_changes_a_balance(self, client, make_agent):
        alice, bob = make_agent("alice"), make_agent("bob")
        responses = [alice.get("/v2/agents/me") for _ in range(12)]
        responses.append(alice.post())
        poll = alice.poll(title="Free polls?", text="Polls cost nothing here.")
        responses.append(poll)
        index = leaf_index(poll)
        responses.append(bob.vote(index, 0))
        responses.append(bob.grant(alice.kid, 5))
        responses.append(alice.send_dm(alice.lookup("bob"), "hello at zero balance"))
        responses.append(alice.put_capsule("state", "kept at zero balance"))
        assert [r.status_code for r in responses[12:]] == [202] * 6
        again = bob.vote(index, 1)  # a refusal (already_voted) carries no prompt either
        assert again.status_code == 409
        for r in (*responses, again):
            assert not any(h in r.headers for h in NAG_HEADERS), r.headers
        assert ledger_rows(client) == 0
        assert alice.balance() == 0 and bob.balance() == 0

    def test_the_published_terms_and_the_asset(self, client, origin):
        info = client.get("/v2/sup").json()
        assert info["voluntary"] is True and "nothing here depends on them" in info["statement"]
        assert info["profile"] == "AICS-1+SUP-1"
        assert info["transferable"] is False and info["refundable"] is False
        asset = client.get("/v2/sup/asset")
        # AICS-1 section 20.2: exactly these bytes, with this log's origin.
        assert asset.content == canonicalize(
            {"asset": "SUP", "buys": ["owner_action", "hosting", "storage"], "decimals": 0, "origin": origin,
             "refundable": False, "transferable": False}
        )
        assert asset.headers["content-type"].startswith("application/json")
        digest = hashlib.sha256(asset.content).hexdigest()
        assert digest == info["asset_hash"] == asset.headers["X-AICS-Asset-SHA256"] == sup_asset_hash(origin)

    def test_the_profile_registers_twelve_refusal_codes(self, client):
        assert SUP_REFUSAL_REASONS == (
            "insufficient_balance", "not_requester", "owner_action_closed", "stale_quote", "task_closed",
            "already_awarded", "already_credited", "payment_not_verified", "intent_expired", "amount_mismatch",
            "bad_reference", "not_offered",
        )
        registry = client.get("/v2/limits").json()["refusal_registry"]
        assert set(SUP_REFUSAL_REASONS) <= set(registry) and registry == sorted(registry)
        assert set(SUP_REFUSAL_REASONS) <= set(client.get("/.well-known/aics-card.json").json()["reason_codes"]["refusal"])


# ---------------------------------------------------------------------------
# section 20.5: the voluntary task board
# ---------------------------------------------------------------------------


class TestTaskBoard:
    def test_the_owner_publishes_a_task_as_a_leaf_of_hashes(self, client, owner):
        response = owner.task("Write a second verifier", "Implement inclusion proofs in another language.", reward=20)
        assert response.status_code == 202, response.text
        body = response.json()
        entry = body["entry"]
        assert entry["type"] == "sup.task" and entry["actor_kid"] == owner.kid
        payload = entry["payload"]
        q = {k: v for k, v in payload.items() if k != "envelope"}
        content = canonicalize({"title": "Write a second verifier", "text": "Implement inclusion proofs in another language."})
        assert q == {
            "body_hash": hashlib.sha256(content).hexdigest(), "size": len(content), "asset_hash": sup_asset_hash(owner.origin),
            "reward": 20, "max_awards": 1, "closes": q["closes"],
        } == payload["envelope"]["payload"]
        assert "verifier" not in json.dumps(entry)
        task = task_of(client, response)
        assert task["task_index"] == leaf_index(response) and task["reward"] == 20
        assert client.get(f"/v2/bodies/{q['body_hash']}").content == content  # the public body, by its hash
        assert task["status"] == "open" and task["suggested_channel"] == TASK_CHANNEL and task["awards"] == []
        assert (task["title"], task["text"]) == ("Write a second verifier", "Implement inclusion proofs in another language.")
        assert client.get("/v2/tasks").json()["tasks"] == [task]
        assert client.get(f"/v2/tasks/{task['task_index']}").json()["task"] == task
        assert client.get("/v2/tasks", params={"status": "closed"}).json()["count"] == 0
        assert client.get("/v2/tasks", params={"status": "bogus"}).status_code == 400
        assert client.get("/v2/tasks/999").status_code == 404
        assert client.get("/v2/stats").json()["usage"]["tasks_open"] == 1

    def test_only_the_owner_publishes_and_the_payload_is_checked(self, client, owner, make_agent):
        alice = make_agent("alice")
        impostor = Owner(client, owner.origin)
        impostor.key, impostor.public, impostor.kid = alice.signer.key, alice.signer.public, alice.kid
        impostor.last_envelope = alice.signer.last_envelope
        refused(impostor.task(), "unknown_key", 403)  # an owner type under another key (AICS-1 section 20.3)
        assert client.post(ENTRIES, json={"envelope": {}, "body": "e30"}).status_code == 401
        assert client.post("/v2/tasks", json={"body": "e30"}).status_code == 405  # one write path: POST /v2/entries
        size = tree_size(client)
        now = int(time.time())
        cases = [
            ({"body_hash": "0" * 64}, "digest_mismatch", 422),
            ({"size": 1}, "digest_mismatch", 422),
            ({"reward": 0}, "malformed", 400),
            ({"reward": SUP_MAX_AMOUNT + 1}, "malformed", 400),
            ({"max_awards": 0}, "malformed", 400),
            ({"max_awards": 1001}, "malformed", 400),
            ({"closes": now - 1}, "malformed", 400),
            ({"closes": now + TASK_MAX_SECONDS + 60}, "malformed", 400),
            ({"asset_hash": "0" * 64}, "malformed", 400),  # AICS-1 section 20.2: another asset is malformed
        ]
        for overrides, code, status in cases:
            refused(owner.task(**overrides), code, status, conflict=None)
        assert tree_size(client) == size + len(cases)
        # The body is exactly the JCS bytes of {title, text}, the title nonempty.
        refused(owner.task(title="", text="A task without a title."), "malformed", 400)
        loose = json.dumps({"text": "x", "title": "y"}).encode()
        refused(owner.task(raw=loose, body_hash=hashlib.sha256(loose).hexdigest(), size=len(loose)), "malformed", 400)
        extra = canonicalize({"text": "x", "title": "y", "tags": []})
        refused(owner.task(raw=extra, body_hash=hashlib.sha256(extra).hexdigest(), size=len(extra)), "malformed", 400)
        leaky = owner.task(text=f"Use the key {LEAKED_TOKEN} to do it")
        refused(leaky, "secret_format:github_token", 422)
        assert LEAKED_TOKEN not in leaky.text
        assert client.get("/v2/tasks").json()["count"] == 0

    def test_an_award_pays_a_submission_posted_in_any_channel(self, client, owner, make_agent):
        alice, bob = make_agent("alice"), make_agent("bob")
        task = task_of(client, owner.task(reward=25))
        submission = leaf_of(alice.post(title="Verifier in Go", body="Here is the code and its tests.", channel="general"))
        response = owner.award(task, submission, alice.kid)
        assert response.status_code == 202, response.text
        body = response.json()
        credit = leaf_index(response)
        entry = body["entry"]
        assert entry["type"] == "sup.credit" and entry["actor_kid"] == owner.kid
        assert {k: v for k, v in entry["payload"].items() if k != "envelope"} == {
            "source": "task", "account_kid": alice.kid, "task_index": task["task_index"], "submission_index": submission,
            "asset_hash": sup_asset_hash(owner.origin), "amount": 25,
        }
        assert alice.balance() == 25
        closed = client.get(f"/v2/tasks/{task['task_index']}").json()["task"]
        assert closed["status"] == "closed"
        assert closed["awards"] == [{"credit_index": credit, "submission_index": submission, "name": "alice", "amount": 25}]
        account = client.get("/v2/sup/accounts/alice").json()
        assert account["entries"] == [
            {"leaf_index": credit, "delta": 25, "cause": "task", "bytes": 0, "created_at": account["entries"][0]["created_at"]}
        ]
        # The same submission again: already_awarded, citing the award.
        refused(owner.award(closed, submission, alice.kid), "already_awarded", 409, conflict=credit)
        # Another name once max_awards awards exist: task_closed, citing the award that filled the task.
        late = leaf_of(bob.post(title="Late work", body="Also done, a little later.", channel=TASK_CHANNEL))
        refused(owner.award(task, late, bob.kid), "task_closed", 409, conflict=credit)
        assert bob.balance() == 0

    def test_award_rules_and_their_conflict_evidence(self, client, owner, make_agent):
        alice, bob = make_agent("alice"), make_agent("bob")
        early = leaf_of(alice.post(title="Posted before the task", body="Too early for any task."))
        task = task_of(client, owner.task(reward=10, max_awards=3))
        index = task["task_index"]
        work = leaf_of(alice.post(title="Proper submission", body="Work for the task."))
        refused(owner.award(task, early, alice.kid), "bad_reference", 422, conflict=early)  # before the task
        refused(owner.award(task, index, alice.kid), "bad_reference", 422, conflict=index)  # the task is no post
        refused(owner.award(task, 10**6, alice.kid), "bad_reference", 422, conflict=None)  # no such entry
        refused(owner.award(task, work, bob.kid), "bad_reference", 422, conflict=work)  # account_kid is the author's
        refused(owner.award(task, work, alice.kid, amount=11), "amount_mismatch", 422, conflict=index)
        not_a_task = {**task, "task_index": alice.head_index}
        refused(owner.award(not_a_task, work, alice.kid), "bad_reference", 422, conflict=alice.head_index)
        refused(owner.award({**task, "task_index": 10**6}, work, alice.kid), "bad_reference", 422, conflict=None)
        # A contribution credit is the policy key's statement after an on-chain check (section 20.6), never submitted.
        refused(owner.award(task, work, alice.kid, source="contribution"), "unknown_key", 403)
        first = owner.award(task, work, alice.kid)
        assert first.status_code == 202, first.text
        second = leaf_of(alice.post(title="Second submission", body="More work for it."))
        refused(owner.award(task, second, alice.kid), "already_awarded", 409, conflict=leaf_of(first))  # one per name
        bob_work = leaf_of(bob.post(title="Bob's submission", body="Bob's work too.", channel=TASK_CHANNEL))
        assert owner.award(task, bob_work, bob.kid).status_code == 202
        assert (alice.balance(), bob.balance()) == (10, 10)
        impostor = Owner(client, owner.origin)
        impostor.key, impostor.public, impostor.kid = alice.signer.key, alice.signer.public, alice.kid
        impostor.last_envelope = alice.signer.last_envelope
        refused(impostor.award(task, second, alice.kid), "unknown_key", 403)

    def test_an_award_follows_the_name_through_a_rotation(self, client, owner, make_agent):
        alice = make_agent("alice")
        task = task_of(client, owner.task(reward=8))
        work = leaf_of(alice.post(body="Posted with the first key."))
        old = alice.kid
        assert alice.rotate(Signer()).status_code == 202
        # account_kid is the name's current key immediately before the credit (AICS-1 section 20.2).
        refused(owner.award(task, work, old), "bad_reference", 422, conflict=work)
        assert owner.award(task, work, alice.kid).status_code == 202
        assert alice.balance() == 8

    def test_awards_precede_closes(self, client, owner, make_agent, monkeypatch):
        alice = make_agent("alice")
        task = task_of(client, owner.task(reward=5, closes=int(time.time()) + 60))
        work = leaf_of(alice.post(body="Done in time, awarded too late."))
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + 61)
        refused(owner.award(task, work, alice.kid), "task_closed", 409, conflict=task["task_index"])
        assert client.get(f"/v2/tasks/{task['task_index']}").json()["task"]["status"] == "closed"

    def test_an_unverified_identity_holds_no_account(self, client, owner):
        identity = secret_claim(client, "plain")  # shared-secret writes exist only at the TLS gate
        task = task_of(client, owner.task(reward=7))
        reply = secret_post(identity, post_body("Unverified work", "Done without a key.", TASK_CHANNEL))
        index = int(re.search(r"ok post at leaf (\d+)", reply).group(1))
        assert client.get(f"/v2/tlog/proof/{index}").json()["actor_kid"] == identity.unverified_id
        refused(owner.award(task, index, Signer().kid), "tier_required", 403, conflict=index)
        assert client.get("/v2/sup/accounts/plain").json()["balance"] == 0

    def test_a_revoked_name_is_not_awarded(self, client, owner, make_agent):
        alice = make_agent("alice")
        task = task_of(client, owner.task(reward=5))
        work = leaf_of(alice.post(title="Work then leave", body="Work before revoking."))
        assert alice.revoke().status_code == 202
        refused(owner.award(task, work, alice.kid), "revoked", 409, conflict=alice.head_index)

    def test_a_task_text_can_be_hidden_and_erased(self, client, owner):
        task = task_of(client, owner.task("A task someone objects to", "Its description, long enough."))
        assert owner.tombstone(task["task_index"], "erasure").status_code == 201
        hidden = client.get(f"/v2/tasks/{task['task_index']}").json()["task"]
        assert hidden["title"] is None and hidden["text"] is None and hidden["hidden"]["reason_code"] == "erasure"
        row = client.app.state.db._conn.execute("SELECT title, text, body FROM sup_tasks").fetchone()
        assert tuple(row) == ("", "", None)  # deleted in the tombstone's commit


# ---------------------------------------------------------------------------
# section 20.7: spends (owner actions are in test_human_actions.py)
# ---------------------------------------------------------------------------


class TestSpending:
    def test_a_hosting_contribution_spends_the_holders_own_credit(self, client, owner, make_agent):
        alice = make_agent("alice")
        credit = leaf_of(award(client, owner, alice, 30))
        size = tree_size(client)
        broke = alice.spend("hosting", 31)
        # A signed spend over the balance is a refusal leaf citing the account's latest credit or spend.
        payload = refused(broke, "insufficient_balance", 409, conflict=credit)
        assert payload["attempt_kid"] == alice.kid
        assert tree_size(client) == size + 1 and alice.balance() == 30
        for bad in ({"amount": 0}, {"ref_index": 1}, {"nbytes": 5}, {"asset_hash": "0" * 64}):
            kwargs = {"amount": 1, **bad}
            amount = kwargs.pop("amount")
            refused(alice.spend("hosting", amount, **kwargs), "malformed", 400)
        refused(alice.spend("bribe", 1), "malformed", 400)
        response = alice.spend("hosting", 12)
        assert response.status_code == 202, response.text
        entry = response.json()["entry"]
        assert entry["type"] == "sup.spend" and entry["actor_kid"] == alice.kid
        assert {k: v for k, v in entry["payload"].items() if k != "envelope"} == {
            "purpose": "hosting", "ref_index": None, "asset_hash": sup_asset_hash(owner.origin), "amount": 12, "bytes": 0,
        }
        assert alice.balance() == 18
        refused(alice.spend("hosting", 19), "insufficient_balance", 409, conflict=leaf_of(response))
        # No entry moves SUP between accounts: another name spends only its own (none here).
        refused(make_agent("bob").spend("hosting", 1), "insufficient_balance", 409, conflict=None)

    def test_storage_is_not_offered_without_a_quota(self, client, make_agent):
        alice = make_agent("alice")
        refused(alice.spend("storage", 5, nbytes=1000), "not_offered", 422, conflict=None)
        assert client.get("/v2/limits").json()["limits"]["capsule_quota_bytes"] is None
        assert client.get("/v2/sup").json()["spend"]["storage"] is None
        assert client.app.state.db.sup_card_member()["storage"] is None

    def test_the_free_quota_and_storage_bought_above_it(self, tmp_path, owner):
        limits = {**TEST_LIMITS, "capsule_quota_bytes": 65536, "storage_unit_bytes": 65536, "storage_unit_sup": 5}
        client = TestClient(create_app(db_path=tmp_path / "quota.db", owner_public_key=owner.public_key_b64u,
                                       announce=False, limits=limits, payments=chainpay.PaymentsConfig.disabled()))
        origin = client.get("/v2/tlog/checkpoint").json()["origin"]
        owner.client, owner.origin = client, origin
        alice = Agent(client, origin)
        assert alice.claim("alice").status_code == 202
        # A sealed capsule here is its text plus 233 bytes: the box's 48, the 4-byte length and the 181-byte inner
        # header naming two did:key kids and the nonce (AICS-1 section 8.1, Appendix A.4).
        assert entry_of(alice.put_capsule("a", "x" * 40000))["payload"]["size"] == 40233
        assert alice.put_capsule("a", "y" * 50000).status_code == 202  # 50233: replacing a slot does not count twice
        over = alice.put_capsule("b", "z" * 20000)
        refused(over, "quota", 403, conflict=None)
        refused(alice.spend("storage", 5, nbytes=65536), "insufficient_balance", 409, conflict=None)
        award(client, owner, alice, 12)
        refused(alice.spend("storage", 7, nbytes=91750), "amount_mismatch", 422, conflict=None)  # whole units only
        refused(alice.spend("storage", 5, nbytes=65535), "amount_mismatch", 422, conflict=None)
        bought = alice.spend("storage", 5, nbytes=65536)
        assert bought.status_code == 202, bought.text
        assert alice.get("/v2/agents/me").json()["storage"] == {
            "free_quota_bytes": 65536, "bought_bytes": 65536, "used_bytes": 50233, "available_bytes": 80839,
        }
        assert alice.put_capsule("b", "z" * 20000).status_code == 202
        me = alice.get("/v2/agents/me").json()
        assert me["sup_credits"] == 7 and me["storage"]["bought_bytes"] == 65536
        assert client.get("/v2/sup").json()["spend"]["storage"] == {"unit_bytes": 65536, "unit_amount": 5, "free_quota_bytes": 65536}
        assert client.app.state.db.sup_card_member()["storage"] == {"free_quota_bytes": 65536, "unit_bytes": 65536, "unit_amount": 5}

    def test_usage_counts_the_names_current_live_untombstoned_slots(self, tmp_path, owner, monkeypatch):
        """AICS-1 section 20.7: the latest capsule of each slot of any of the name's keys, unexpired, not tombstoned."""
        limits = {**TEST_LIMITS, "capsule_quota_bytes": 65536}
        client = TestClient(create_app(db_path=tmp_path / "usage.db", owner_public_key=owner.public_key_b64u,
                                       announce=False, limits=limits, payments=chainpay.PaymentsConfig.disabled()))
        origin = client.get("/v2/tlog/checkpoint").json()["origin"]
        owner.client, owner.origin = client, origin
        alice = Agent(client, origin)
        assert alice.claim("alice").status_code == 202
        first = leaf_of(alice.put_capsule("a", "x" * 40000))  # 40233
        assert alice.rotate(Signer()).status_code == 202
        # The slot of the name's earlier key still counts: 40233 + 30233 is over 65536.
        refused(alice.put_capsule("b", "y" * 30000), "quota", 403)
        # A tombstoned body does not count.
        assert owner.tombstone(first, "order").status_code == 201
        assert alice.put_capsule("b", "y" * 30000).status_code == 202
        # An expired capsule does not count: one that expires after 90 days, then a put after that.
        short = int(time.time()) + 7776000 + 60
        assert alice.put_capsule("c", "z" * 30000, expires=short).status_code == 202
        refused(alice.put_capsule("d", "w" * 10000), "quota", 403)
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + 7776000 + 120)
        assert alice.put_capsule("d", "w" * 10000).status_code == 202

    def test_storage_limits_are_validated(self):
        with pytest.raises(ValueError, match="go together"):
            load_limits({"capsule_quota_bytes": 65536, "storage_unit_bytes": 5})
        with pytest.raises(ValueError, match="only when capsule_quota_bytes"):
            load_limits({"storage_unit_bytes": 5, "storage_unit_sup": 1})
        with pytest.raises(ValueError):
            load_limits({"capsule_quota_bytes": 0})
        with pytest.raises(ValueError, match="65536"):  # AICS-1 section 20.9: one maximal ciphertext body is free
            load_limits({"capsule_quota_bytes": 65535})
        assert load_limits({"capsule_quota_bytes": None})["capsule_quota_bytes"] is None


# ---------------------------------------------------------------------------
# section 20.6: contributions, credited only after the on-chain check
# ---------------------------------------------------------------------------


class TestContributionIntents:
    def test_nothing_configured_means_nothing_is_creditable(self, client, make_agent):
        alice = make_agent("alice")
        size = tree_size(client)
        response = alice.intent("base-usdc", 5)
        assert response.status_code == 422 and reason(response) == "not_offered"
        assert reason(alice.intent("dogecoin", 5)) == "not_offered"
        assert client.get("/v2/sup").json()["earn"]["contribution"]["networks"] == []
        assert client.app.state.db.sup_card_member()["contributions"] == []
        assert ledger_rows(client) == 0 and tree_size(client) == size  # a failed intent writes nothing

    def test_an_address_without_an_endpoint_is_not_offered(self, tmp_path, monkeypatch, owner):
        for var in ("AICS_RPC_BASE_URL", "AICS_RPC_SOLANA_URL", "AICS_WALLET_SOLANA"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("AICS_WALLET_BASE_USDC", BASE_ADDRESS)
        client = TestClient(create_app(db_path=tmp_path / "half.db", owner_public_key=owner.public_key_b64u, announce=False, limits=TEST_LIMITS))
        # A network whose transfers cannot be checked on chain is not credited, so neither listed nor offered.
        assert client.get("/v2/sup").json()["earn"]["contribution"]["networks"] == []
        alice = Agent(client, client.get("/v2/tlog/checkpoint").json()["origin"])
        assert alice.claim("alice").status_code == 202
        assert reason(alice.intent("base-usdc", 5)) == "not_offered"

    def test_an_intent_is_exactly_the_section_20_6_answer_and_never_a_leaf(self, client, make_agent, chain):
        alice = make_agent("alice")
        size = tree_size(client)
        response = alice.intent("base-usdc", 5)
        assert response.status_code == 201, response.text
        intent = response.json()
        assert set(intent) == {"intent_id", "network", "asset", "address", "units", "amount", "expires", "claim_until"}
        raw = keys.b64u_decode(intent["intent_id"])
        assert len(raw) == 16 and keys.b64u_encode(raw) == intent["intent_id"]
        assert (intent["network"], intent["asset"], intent["address"], intent["amount"]) == ("base-usdc", "USDC", BASE_ADDRESS, 5)
        assert 5 * UNITS_PER_SUP < intent["units"] < 6 * UNITS_PER_SUP  # amount*units_per_sup + 0 < offset < units_per_sup
        assert intent["claim_until"] - intent["expires"] == INTENT_CLAIM_SECONDS - INTENT_TTL_SECONDS
        assert abs(made_at(intent) - time.time()) < 5
        assert tree_size(client) == size  # an intent is never a leaf
        # The client compares network, asset and address with the card before sending anything.
        networks = client.app.state.db.sup_card_member()["contributions"]
        assert {"network": "base-usdc", "asset": "USDC", "decimals": 6, "address": BASE_ADDRESS, "units_per_sup": UNITS_PER_SUP} in networks
        solana = alice.intent("solana-usdc", 3).json()
        assert solana["address"] == SOLANA_ADDRESS and 3 * UNITS_PER_SUP < solana["units"] < 4 * UNITS_PER_SUP

    def test_units_are_unique_and_intents_bounded(self, client, make_agent, chain):
        alice, bob = make_agent("alice"), make_agent("bob")
        units = {alice.intent("base-usdc", 1).json()["units"] for _ in range(INTENT_MAX_OPEN)}
        assert len(units) == INTENT_MAX_OPEN
        busy = alice.intent("base-usdc", 1)
        assert busy.status_code == 429 and reason(busy) == "too_many_intents"
        assert bob.intent("base-usdc", 1).json()["units"] not in units

    def test_a_failed_intent_is_an_error_and_no_entry(self, client, make_agent, chain):
        alice = make_agent("alice")
        size = tree_size(client)
        for bad in (0, -1, "5", 1.5, True, None):
            assert alice.intent("base-usdc", bad).status_code == 422, bad  # the request schema: whole SUP, at least 1
        too_much = alice.intent("base-usdc", SUP_MAX_AMOUNT + 1)
        assert too_much.status_code == 422 and reason(too_much) == "malformed"
        # AICS-1 section 20.6: an HTTPS POST of JCS JSON content, without a query or an envelope.
        plain = alice.intent("base-usdc", 5, tls=False)
        assert plain.status_code == 403 and reason(plain) == "tls_required"
        loose = alice.intent("base-usdc", 5, raw=json.dumps({"network": "base-usdc", "amount": 5}).encode())
        assert loose.status_code == 400 and "JCS" in loose.json()["detail"]["message"]
        enveloped = alice.service_request("/v2/sup/contributions/intents", {"network": "base-usdc", "amount": 5, "envelope": {}})
        assert enveloped.status_code == 422
        queried = alice.service_request(
            "/v2/sup/contributions/intents?ref=x", {"network": "base-usdc", "amount": 5},
            components=hs.AICS_COMPONENTS + ("@query",),
        )
        assert queried.status_code == 400 and "query" in queried.json()["detail"]["message"]
        assert tree_size(client) == size and client.app.state.db._conn.execute("SELECT COUNT(*) FROM sup_intents").fetchone()[0] == 0

    def test_an_intent_needs_a_signature_and_its_nonce_is_kept(self, client, make_agent, chain):
        alice = make_agent("alice")
        unsigned = https(client).post("/v2/sup/contributions/intents", json={"network": "base-usdc", "amount": 1})
        assert unsigned.status_code == 401
        assert alice.intent("base-usdc", 1).status_code == 201
        method, path, body, headers = alice.signer.last_request
        size = tree_size(client)
        again = https(client).request(method, path, content=body, headers=headers)
        assert again.status_code == 409 and reason(again) == "replay"
        assert again.json()["detail"]["refusal"] is None and tree_size(client) == size  # no leaf, ever

    def test_a_frozen_service_still_takes_intents(self, client, make_agent, owner, chain):
        alice = make_agent("alice")
        assert owner.freeze().status_code == 201
        assert alice.intent("base-usdc", 1).status_code == 201  # an intent changes no logged state


class TestContributionClaims:
    def test_a_checked_contribution_is_credited_with_a_keyed_hash(self, client, make_agent, chain):
        alice = make_agent("alice")
        intent = alice.intent("base-usdc", 5).json()
        tx = base_tx(0xA11CE)
        chain["base-usdc"].transfers[tx] = (intent["units"], made_at(intent) + 30)
        claimed = alice.claim_contribution(intent["intent_id"], tx.upper().replace("0X", "0x"))
        assert claimed.status_code == 201, claimed.text
        body = claimed.json()
        entry = body["entry"]
        policy_kid = client.get("/v2/tlog/checkpoint").json()["policy_kid"]
        assert entry["type"] == "sup.credit" and entry["actor_kid"] == policy_kid
        assert entry["payload"]["envelope"]["protected"]["kid"] == policy_kid
        q = {k: v for k, v in entry["payload"].items() if k != "envelope"}
        assert set(q) == {"source", "account_kid", "contribution_hash", "asset_hash", "amount"}
        assert (q["source"], q["account_kid"], q["amount"]) == ("contribution", alice.kid, 5)
        assert q["asset_hash"] == sup_asset_hash(alice.origin)
        # contribution_hash = HMAC-SHA256(K, UTF8("AICS-1 contribution\n") || network || LF || canonical tx_hash).
        db = client.app.state.db
        expected = hmac.new(db._contribution_key, b"AICS-1 contribution\nbase-usdc\n" + tx.encode(), hashlib.sha256).hexdigest()
        assert q["contribution_hash"] == expected
        for plain in (tx, f"base-usdc\n{tx}", tx[2:]):  # never a plain hash anyone could match against the chain
            assert q["contribution_hash"] != hashlib.sha256(plain.encode()).hexdigest()
        flat = json.dumps(entry)
        assert tx[2:] not in flat and str(intent["units"]) not in flat and BASE_ADDRESS[2:] not in flat
        assert body["balance"] == 5 == alice.balance()
        row = db._conn.execute("SELECT * FROM sup_contributions").fetchone()
        assert row["tx_hash"] == tx and row["units"] == intent["units"]
        assert row["delete_after"] - row["credited_at"] == CONTRIBUTION_TX_RETENTION_SECONDS
        assert db._conn.execute("SELECT COUNT(*) FROM sup_intents").fetchone()[0] == 0  # the intent is deleted
        assert chain["base-usdc"].calls == [tx]
        assert client.get("/v2/stats").json()["usage"]["contributions_credited"] == 1

    def test_a_transaction_and_an_intent_are_credited_once(self, client, make_agent, chain):
        alice = make_agent("alice")
        first = alice.intent("base-usdc", 2).json()
        tx = base_tx(0xB0B)
        chain["base-usdc"].transfers[tx] = (first["units"], made_at(first) + 1)
        credit = leaf_of(alice.claim_contribution(first["intent_id"], tx))
        second = alice.intent("base-usdc", 2).json()
        size = tree_size(client)
        refused(alice.claim_contribution(second["intent_id"], tx), "already_credited", 409, conflict=credit)
        refused(alice.claim_contribution(first["intent_id"], base_tx(0xB0C)), "already_credited", 409, conflict=credit)
        assert tree_size(client) == size + 2 and alice.balance() == 2

    def test_a_claim_refusal_names_the_request_by_a_keyed_hash(self, client, make_agent, chain):
        alice = make_agent("alice")
        ghost = keys.b64u_encode(bytes(16))
        response = alice.claim_contribution(ghost, base_tx(7))
        payload = refused(response, "bad_reference", 422, conflict=None)
        content = canonicalize({"intent_id": ghost, "tx_hash": base_tx(7)})
        keyed = hmac.new(client.app.state.db._contribution_key, b"AICS-1 contribution-claim\n" + content, hashlib.sha256).hexdigest()
        assert payload["envelope_hash"] == payload["request_hash"] == keyed
        assert keyed != hashlib.sha256(content).hexdigest()
        # The attempt fields come from the verified signature parameters.
        params = signature_params(alice.signer.last_request[3])
        assert payload["attempt_kid"] == alice.kid and payload["attempt_nonce"] == params["nonce"]
        assert payload["attempt_expires"] == int(params["expires"])
        assert base_tx(7)[2:] not in json.dumps(response.json()["detail"]["refusal"]["entry"])

    def test_watching_the_address_and_claiming_anothers_transfer_gets_nothing(self, client, make_agent, chain):
        alice, mallory = make_agent("alice"), make_agent("mallory")
        intent = alice.intent("base-usdc", 5).json()
        tx = base_tx(0xF00D)
        chain["base-usdc"].transfers[tx] = (intent["units"], made_at(intent) + 2)
        # Mallory cannot claim Alice's intent, and her own intent never has Alice's units.
        refused(mallory.claim_contribution(intent["intent_id"], tx), "bad_reference", 422, conflict=None)
        own = mallory.intent("base-usdc", 5).json()
        assert own["units"] != intent["units"]
        refused(mallory.claim_contribution(own["intent_id"], tx), "payment_not_verified", 422, conflict=None)
        assert mallory.balance() == 0
        assert alice.claim_contribution(intent["intent_id"], tx).status_code == 201
        assert alice.balance() == 5

    @pytest.mark.parametrize(
        ("outcome", "status", "error"),
        [
            ("short", 422, "payment_not_verified"),
            ("before", 422, "payment_not_verified"),
            ("after", 422, "payment_not_verified"),
            ("elsewhere", 422, "payment_not_verified"),
            (chainpay.PaymentNotVerified("the transaction failed on chain"), 422, "payment_not_verified"),
            (chainpay.PaymentPending("not final yet"), 409, "payment_pending"),
            (chainpay.PaymentUnavailable("endpoint down"), 503, "payment_unavailable"),
            (None, 409, "payment_pending"),
        ],
    )
    def test_every_failed_check_credits_nothing(self, client, make_agent, chain, outcome, status, error):
        alice = make_agent("alice")
        intent = alice.intent("base-usdc", 3).json()
        tx = base_tx(0xDEAD)
        transfers = chain["base-usdc"].transfers
        made = made_at(intent)
        if outcome == "short":
            transfers[tx] = (intent["units"] - 1, made + 1)
        elif outcome == "before":
            transfers[tx] = (intent["units"], made - INTENT_CLOCK_SKEW - 1)
        elif outcome == "after":
            transfers[tx] = (intent["units"], intent["expires"] + INTENT_CLOCK_SKEW + 1)
        elif outcome == "elsewhere":
            transfers[tx] = (intent["units"], made + 1, "0x" + "cd" * 20)
        elif outcome is not None:
            transfers[tx] = outcome
        size = tree_size(client)
        response = alice.claim_contribution(intent["intent_id"], tx)
        if error == "payment_not_verified":
            # A final transaction that does not match: a decision, so a refusal leaf (AICS-1 section 20.6).
            refused(response, error, status, conflict=None)
            assert tree_size(client) == size + 1
        else:
            # Not yet final, or the chain cannot be read: transient, so nothing is written.
            assert response.status_code == status and reason(response) == error
            assert tree_size(client) == size and response.headers["Retry-After"] == "60"
        assert alice.balance() == 0 and ledger_rows(client) == 0
        # The intent stays claimable: once the chain agrees (within the 120 s bounds), the credit goes through.
        transfers[tx] = (intent["units"], made - INTENT_CLOCK_SKEW)
        assert alice.claim_contribution(intent["intent_id"], tx).status_code == 201
        assert alice.balance() == 3

    def test_a_claim_after_claim_until_is_expired_and_the_intent_then_deleted(self, client, make_agent, chain):
        alice = make_agent("alice")
        intent = alice.intent("base-usdc", 1).json()
        tx = base_tx(0xE0)
        chain["base-usdc"].transfers[tx] = (intent["units"], made_at(intent) + 1)
        db = client.app.state.db
        db._conn.execute("UPDATE sup_intents SET claim_until = ?", (int(time.time()) - 1,))
        refused(alice.claim_contribution(intent["intent_id"], tx), "intent_expired", 409, conflict=None)
        # An uncredited intent is deleted at its claim_until (the hourly pass): then it names nothing.
        assert db.housekeeping(force=True)
        assert db._conn.execute("SELECT COUNT(*) FROM sup_intents").fetchone()[0] == 0
        refused(alice.claim_contribution(intent["intent_id"], tx), "bad_reference", 422, conflict=None)
        assert alice.balance() == 0 and chain["base-usdc"].calls == []

    def test_a_network_no_longer_offered_is_refused(self, client, make_agent, chain):
        alice = make_agent("alice")
        intent = alice.intent("solana-usdc", 1).json()
        db = client.app.state.db
        db.payments = chainpay.PaymentsConfig({"base-usdc": chain["base-usdc"]}, 100)
        refused(alice.claim_contribution(intent["intent_id"], solana_tx(9)), "not_offered", 422, conflict=None)

    def test_claims_are_section_20_6_service_requests(self, client, make_agent, chain):
        alice = make_agent("alice")
        intent = alice.intent("base-usdc", 1).json()
        assert https(client).post("/v2/sup/contributions", json={"intent_id": intent["intent_id"], "tx_hash": base_tx(5)}).status_code == 401
        plain = alice.claim_contribution(intent["intent_id"], base_tx(5), tls=False)
        assert plain.status_code == 403 and reason(plain) == "tls_required"
        size = tree_size(client)
        loose = alice.claim_contribution(
            intent["intent_id"], base_tx(5), raw=json.dumps({"intent_id": intent["intent_id"], "tx_hash": base_tx(5)}).encode()
        )
        refused(loose, "malformed", 400, conflict=None)  # signed, so a refusal leaf, named by the keyed hash
        assert tree_size(client) == size + 1
        assert alice.claim_contribution(intent["intent_id"], "not a transaction id").status_code in (400, 422)
        assert chain["base-usdc"].calls == []

    def test_a_frozen_service_credits_nothing_and_extends_claim_windows(self, client, make_agent, owner, chain, monkeypatch):
        alice = make_agent("alice")
        intent = alice.intent("base-usdc", 1).json()
        tx = base_tx(0xF5)
        chain["base-usdc"].transfers[tx] = (intent["units"], made_at(intent) + 1)
        freeze = owner.freeze()
        assert freeze.status_code == 201
        refused(alice.claim_contribution(intent["intent_id"], tx), "frozen", 503, conflict=leaf_of(freeze))
        assert chain["base-usdc"].calls == []
        # The claim window ends during the freeze; reopening extends it by the freeze's length.
        real = time.time
        frozen_for = INTENT_CLAIM_SECONDS + 3600
        monkeypatch.setattr(time, "time", lambda: real() + frozen_for)
        client.app.state.db.housekeeping(force=True)  # no intent is deleted while frozen
        assert owner.freeze("open", "resume", "Back.").status_code == 201
        row = client.app.state.db._conn.execute("SELECT claim_until FROM sup_intents").fetchone()
        assert row is not None and row["claim_until"] >= intent["claim_until"] + frozen_for - 5
        assert alice.claim_contribution(intent["intent_id"], tx).status_code == 201
        assert alice.balance() == 1

    def test_transaction_ids_are_deleted_after_record_seconds(self, client, make_agent, chain):
        alice = make_agent("alice")
        first = alice.intent("base-usdc", 1).json()
        tx = base_tx(0x1)
        chain["base-usdc"].transfers[tx] = (first["units"], made_at(first))
        assert alice.claim_contribution(first["intent_id"], tx).status_code == 201
        db = client.app.state.db
        db._conn.execute("UPDATE sup_contributions SET delete_after = 0")
        second = alice.intent("base-usdc", 1).json()  # an intent request runs the purge
        row = db._conn.execute("SELECT tx_hash, units, contribution_hash FROM sup_contributions").fetchone()
        assert row["tx_hash"] is None and row["units"] is None and row["contribution_hash"]
        # The keyed hash stays, so the same transaction is still credited only once.
        chain["base-usdc"].transfers[tx] = (second["units"], made_at(second))
        assert reason(alice.claim_contribution(second["intent_id"], tx)) == "already_credited"

    def test_retention_runs_without_contribution_traffic(self, client, make_agent, chain):
        alice = make_agent("alice")
        intent = alice.intent("solana-usdc", 1).json()
        tx = solana_tx(3)
        chain["solana-usdc"].transfers[tx] = (intent["units"], made_at(intent))
        assert alice.claim_contribution(intent["intent_id"], tx).status_code == 201
        db = client.app.state.db
        db._conn.execute("UPDATE sup_contributions SET delete_after = 0")
        assert client.get("/healthz").status_code == 200  # within the hour: nothing yet
        assert db._conn.execute("SELECT tx_hash FROM sup_contributions").fetchone()["tx_hash"] == tx
        db._last_housekeeping -= db.HOUSEKEEPING_INTERVAL
        assert client.get("/healthz").status_code == 200  # any request runs the hourly pass
        assert db._conn.execute("SELECT tx_hash FROM sup_contributions").fetchone()["tx_hash"] is None

    def test_a_revoked_name_is_credited_nothing(self, client, make_agent, chain):
        alice = make_agent("alice")
        intent = alice.intent("base-usdc", 1).json()
        tx = base_tx(0x77)
        chain["base-usdc"].transfers[tx] = (intent["units"], made_at(intent))
        assert alice.revoke().status_code == 202
        refused(alice.claim_contribution(intent["intent_id"], tx), "revoked", 409, conflict=alice.head_index)
        assert ledger_rows(client) == 0 and chain["base-usdc"].calls == []


# ---------------------------------------------------------------------------
# the gate's optional verb spend (AICS-1 section 20.3)
# ---------------------------------------------------------------------------


class TestGateSpend:
    def test_a_spend_through_the_text_gate(self, client, owner, origin):
        from conftest import J, KeyAgent, Line, U, artifacts, check_reply, command_of, onboard

        line = Line(client)
        zed = KeyAgent("zed")
        onboard(line, zed)
        signer = Signer(key=zed.key)
        signer.last_envelope = zed.envelope  # the gate-signed claim is seq 0 of this key's chain
        agent = Agent(client, origin, signer)
        agent.name = "zed"
        task = task_of(client, owner.task(reward=9))
        work = leaf_of(agent.post(title="Gate work", body="Done by a key made for the gate.", channel=TASK_CHANNEL))
        assert owner.award(task, work, zed.kid).status_code == 202
        q = {"purpose": "hosting", "ref_index": None, "asset_hash": sup_asset_hash(origin), "amount": 4, "bytes": 0}
        text = line.send(f"draft spend {U(J(q))}")
        command = command_of(text)
        assert command.startswith("spend ")
        line.send(command)
        text = line.send(zed.sig(line.sid, command))
        check_reply(text)
        assert "ok spend at leaf" in text and "balance 5 SUP" in text
        entry = json.loads(artifacts(text)["entry"])
        assert entry["type"] == "sup.spend" and {k: v for k, v in entry["payload"].items() if k != "envelope"} == q
        assert client.get("/v2/sup/accounts/zed").json()["balance"] == 5


# ---------------------------------------------------------------------------
# the on-chain verifiers (fake JSON-RPC transports)
# ---------------------------------------------------------------------------

RPC_URL = "https://rpc.example.invalid/key-in-path-SECRET"
TX = "0x" + "12" * 32
BLOCK_HASH = "0x" + "bb" * 32


class FakeRpc:
    def __init__(self, **handlers: Any) -> None:
        self.handlers = handlers
        self.calls: list[tuple[str, list[Any]]] = []

    def __call__(self, url: str, request: dict[str, Any]) -> Any:
        assert url == RPC_URL
        self.calls.append((request["method"], request["params"]))
        handler = self.handlers[request["method"]]
        result = handler(*request["params"]) if callable(handler) else handler
        if isinstance(result, Exception):
            raise result
        if isinstance(result, dict) and result.get("__raw__"):
            return result["__raw__"]
        return {"jsonrpc": "2.0", "id": request["id"], "result": result}


def transfer_log(value: int, to: str = BASE_ADDRESS, contract: str = chainpay.BASE_USDC_CONTRACT, removed: bool = False) -> dict[str, Any]:
    return {
        "address": contract,
        "topics": [chainpay.ERC20_TRANSFER_TOPIC, "0x" + "0" * 24 + "cd" * 20, "0x" + "0" * 24 + to[2:]],
        "data": "0x" + f"{value:064x}",
        "removed": removed,
    }


def base_rpc(logs=None, *, status="0x1", chain_id="0x2105", finalized=0x20, block_hash=BLOCK_HASH, receipt=True) -> FakeRpc:
    def block(tag: str, full: bool) -> dict[str, Any]:
        if tag in ("finalized", "safe"):
            return {"number": hex(finalized), "hash": "0x" + "ff" * 32, "timestamp": "0x1"}
        assert tag == "0x10"
        return {"number": "0x10", "hash": block_hash, "timestamp": hex(1_700_000_000)}

    return FakeRpc(
        eth_chainId=chain_id,
        eth_getTransactionReceipt=(
            {"transactionHash": TX, "status": status, "blockNumber": "0x10", "blockHash": BLOCK_HASH,
             "logs": [transfer_log(5_000_137)] if logs is None else logs}
            if receipt
            else None
        ),
        eth_getBlockByNumber=block,
    )


class TestBaseVerifier:
    def verifier(self, rpc: FakeRpc, **kwargs: Any) -> chainpay.BaseUSDCVerifier:
        return chainpay.BaseUSDCVerifier(BASE_ADDRESS.upper().replace("0X", "0x"), RPC_URL, transport=rpc, **kwargs)

    def test_a_final_usdc_transfer_to_the_address(self):
        rpc = base_rpc([transfer_log(5_000_000), transfer_log(137), transfer_log(9, to="0x" + "ee" * 20),
                        transfer_log(10**9, contract="0x" + "77" * 20), transfer_log(10**9, removed=True)])
        result = self.verifier(rpc).verify(TX.upper().replace("0X", "0x"))
        assert result == chainpay.VerifiedTransfer("base-usdc", TX, BASE_ADDRESS, 5_000_137, 1_700_000_000)
        assert [m for m, _ in rpc.calls] == ["eth_chainId", "eth_getTransactionReceipt", "eth_getBlockByNumber", "eth_getBlockByNumber"]
        assert rpc.calls[2][1] == ["finalized", False]

    @pytest.mark.parametrize(
        ("rpc", "error"),
        [
            (base_rpc(chain_id="0x1"), chainpay.PaymentUnavailable),
            (base_rpc(receipt=False), chainpay.PaymentPending),
            (base_rpc(status="0x0"), chainpay.PaymentNotVerified),
            (base_rpc([]), chainpay.PaymentNotVerified),
            (base_rpc([transfer_log(5, to="0x" + "ee" * 20)]), chainpay.PaymentNotVerified),
            (base_rpc([transfer_log(5, contract="0x" + "77" * 20)]), chainpay.PaymentNotVerified),
            (base_rpc(finalized=0x0F), chainpay.PaymentPending),
            (base_rpc(block_hash="0x" + "00" * 32), chainpay.PaymentPending),
        ],
    )
    def test_anything_short_of_a_final_transfer_credits_nothing(self, rpc, error):
        with pytest.raises(error):
            self.verifier(rpc).verify(TX)

    def test_transport_failures_and_odd_answers_fail_closed_without_the_url(self):
        for handler in (OSError("connection refused"), ValueError("not json"), RuntimeError("anything")):
            with pytest.raises(chainpay.PaymentUnavailable) as excinfo:
                self.verifier(FakeRpc(eth_chainId=handler)).verify(TX)
            assert "SECRET" not in str(excinfo.value) and "rpc.example" not in str(excinfo.value)
        with pytest.raises(chainpay.PaymentUnavailable):
            self.verifier(FakeRpc(eth_chainId={"__raw__": {"jsonrpc": "2.0", "id": 1, "error": {"code": -1}}})).verify(TX)
        with pytest.raises(chainpay.PaymentUnavailable):
            self.verifier(FakeRpc(eth_chainId={"__raw__": ["not", "an", "object"]})).verify(TX)
        with pytest.raises(chainpay.PaymentUnavailable):
            self.verifier(FakeRpc(eth_chainId="2105")).verify(TX)  # not a hex quantity
        other = base_rpc()
        other.handlers["eth_getTransactionReceipt"] = {**other.handlers["eth_getTransactionReceipt"], "transactionHash": "0x" + "34" * 32}
        with pytest.raises(chainpay.PaymentUnavailable):
            self.verifier(other).verify(TX)
        with pytest.raises(ValueError):
            self.verifier(base_rpc()).verify("0x1234")

    def test_configuration_is_checked(self):
        with pytest.raises(ValueError):
            chainpay.BaseUSDCVerifier("not-an-address", RPC_URL)
        with pytest.raises(ValueError):
            chainpay.BaseUSDCVerifier(BASE_ADDRESS, "http://rpc.example.invalid")
        with pytest.raises(ValueError):
            chainpay.BaseUSDCVerifier(BASE_ADDRESS, RPC_URL, finality="latest")
        assert chainpay.BaseUSDCVerifier(BASE_ADDRESS, "http://127.0.0.1:8545").describe()["creditable"] is True
        assert "url" not in json.dumps(chainpay.BaseUSDCVerifier(BASE_ADDRESS, RPC_URL).describe()).lower()


SOLANA_SIG = chainpay.b58encode(bytes([7] * 64))
MINT = chainpay.SOLANA_USDC_MINT


def token_balance(index: int, amount: int, owner: str = SOLANA_ADDRESS, mint: str = MINT, decimals: int = 6) -> dict[str, Any]:
    return {"accountIndex": index, "mint": mint, "owner": owner, "uiTokenAmount": {"amount": str(amount), "decimals": decimals}}


def solana_rpc(pre=None, post=None, *, err=None, block_time=1_700_000_000, signature=SOLANA_SIG, found=True) -> FakeRpc:
    def get_transaction(sig: str, options: dict[str, Any]) -> Any:
        assert options == {"encoding": "jsonParsed", "commitment": "finalized", "maxSupportedTransactionVersion": 0}
        if not found:
            return None
        return {
            "blockTime": block_time,
            "meta": {
                "err": err,
                "preTokenBalances": [token_balance(1, 1_000_000)] if pre is None else pre,
                "postTokenBalances": [token_balance(1, 6_000_137), token_balance(2, 5, owner=chainpay.b58encode(bytes([9] * 32)))]
                if post is None
                else post,
            },
            "transaction": {"signatures": [signature]},
        }

    return FakeRpc(getTransaction=get_transaction)


class TestSolanaVerifier:
    def verifier(self, rpc: FakeRpc) -> chainpay.SolanaUSDCVerifier:
        return chainpay.SolanaUSDCVerifier(SOLANA_ADDRESS, RPC_URL, transport=rpc)

    def test_the_addresss_usdc_balance_change(self):
        result = self.verifier(solana_rpc()).verify(SOLANA_SIG)
        assert result == chainpay.VerifiedTransfer("solana-usdc", SOLANA_SIG, SOLANA_ADDRESS, 5_000_137, 1_700_000_000)
        # A token account created by the transfer has no pre-balance.
        fresh = self.verifier(solana_rpc(pre=[], post=[token_balance(3, 250_000)])).verify(SOLANA_SIG)
        assert fresh.amount == 250_000

    @pytest.mark.parametrize(
        ("rpc", "error"),
        [
            (solana_rpc(found=False), chainpay.PaymentPending),
            (solana_rpc(err={"InstructionError": [0, "Custom"]}), chainpay.PaymentNotVerified),
            (solana_rpc(signature=chainpay.b58encode(bytes([8] * 64))), chainpay.PaymentUnavailable),
            (solana_rpc(post=[token_balance(1, 1_000_000)]), chainpay.PaymentNotVerified),
            (solana_rpc(post=[token_balance(1, 9_000_000, mint=chainpay.b58encode(bytes([5] * 32)))]), chainpay.PaymentNotVerified),
            (solana_rpc(post=[token_balance(1, 9_000_000, decimals=9)]), chainpay.PaymentUnavailable),
            (solana_rpc(block_time=None), chainpay.PaymentPending),
        ],
    )
    def test_anything_short_of_a_received_usdc_amount_credits_nothing(self, rpc, error):
        with pytest.raises(error):
            self.verifier(rpc).verify(SOLANA_SIG)

    def test_identifiers_are_canonical_base58(self):
        with pytest.raises(ValueError):
            self.verifier(solana_rpc()).verify("0x" + "12" * 32)
        with pytest.raises(ValueError):
            chainpay.SolanaUSDCVerifier("short", RPC_URL)
        assert chainpay.b58decode(chainpay.b58encode(b"\x00\x00abc")) == b"\x00\x00abc"
        with pytest.raises(ValueError):
            chainpay.normalize_tx_hash("solana-usdc", "1" + SOLANA_SIG)  # not 64 bytes any more


class TestConfiguration:
    def test_nothing_in_the_environment_offers_nothing(self):
        config = chainpay.PaymentsConfig.from_env({})
        assert config.networks() == [] and config.sup_per_usdc == chainpay.DEFAULT_SUP_PER_USDC
        with pytest.raises(chainpay.PaymentUnavailable):
            config.verifier("base-usdc")
        with pytest.raises(ValueError):
            config.verifier("monero")

    def test_addresses_and_endpoints_come_from_the_environment_only(self):
        env = {
            "AICS_WALLET_BASE_USDC": BASE_ADDRESS,
            "AICS_RPC_BASE_URL": RPC_URL,
            "AICS_WALLET_SOLANA": SOLANA_ADDRESS,
            "AICS_RPC_SOLANA_URL": RPC_URL,
            "AICS_SUP_PER_USDC": "50",
        }
        config = chainpay.PaymentsConfig.from_env(env)
        assert isinstance(config.verifier("base-usdc"), chainpay.BaseUSDCVerifier)
        assert isinstance(config.verifier("solana-usdc"), chainpay.SolanaUSDCVerifier)
        assert [n["network"] for n in config.networks()] == ["base-usdc", "solana-usdc"]
        assert "SECRET" not in json.dumps(config.networks())
        assert config.sup_per_usdc == 50 and config.units_per_sup() == 20_000

    @pytest.mark.parametrize("rate", ["250", "1000000", "3", "0", "x"])
    def test_a_rate_that_would_publish_the_exact_transfer_is_refused(self, rate):
        # Above 100 SUP per USDC (or with a SUP that is not a whole number of base units) a credit could repeat
        # the intent's exact sub-cent amount, which links the agent's key to the paying wallet on chain.
        with pytest.raises(ValueError, match="AICS_SUP_PER_USDC"):
            chainpay.PaymentsConfig.from_env({"AICS_SUP_PER_USDC": rate})
        with pytest.raises(ValueError):
            chainpay.PaymentsConfig({}, int(rate) if rate.isdigit() else 0)

    def test_one_sup_is_more_base_units_than_any_offset(self):
        # AICS-1 section 20.6: units = amount * units_per_sup + offset with 0 < offset < units_per_sup, so the
        # credited amount (whole SUP) never repeats the exact transfer; the card requires units_per_sup >= 2.
        for rate in (1, 2, 4, 5, 10, 20, 25, 50, chainpay.MAX_SUP_PER_USDC):
            config = chainpay.PaymentsConfig({}, rate)
            per = config.units_per_sup()
            assert per >= 2 and per * rate == chainpay.USDC_UNIT
            # The units of 5 SUP plus any offset still round down to 5 SUP: the credit never names the offset.
            assert {(5 * per + offset) // per for offset in (1, per // 2, per - 1)} == {5}

    @pytest.mark.parametrize(
        ("env", "reason"),
        [
            ({"AICS_WALLET_BASE_USDC": BASE_ADDRESS}, "no RPC endpoint"),
            ({"AICS_WALLET_BASE_USDC": "0xnot-an-address", "AICS_RPC_BASE_URL": RPC_URL}, "invalid"),
            ({"AICS_WALLET_BASE_USDC": BASE_ADDRESS, "AICS_RPC_BASE_URL": "http://rpc.example.invalid"}, "misconfigured"),
            ({"AICS_WALLET_BASE_USDC": BASE_ADDRESS, "AICS_RPC_BASE_URL": RPC_URL, "AICS_BASE_CHAIN_ID": "base"}, "misconfigured"),
        ],
    )
    def test_a_half_configured_network_fails_closed(self, env, reason):
        verifier = chainpay.PaymentsConfig.from_env(env).verifier("base-usdc")
        assert verifier.available is False and reason in verifier.describe()["reason"]
        assert verifier.describe()["address"] == (None if reason == "invalid" else BASE_ADDRESS)  # never a bad address
        with pytest.raises(chainpay.PaymentUnavailable):
            verifier.verify(TX)

    def test_the_rate_and_amounts_are_strict(self):
        with pytest.raises(ValueError):
            chainpay.PaymentsConfig.from_env({"AICS_SUP_PER_USDC": "0"})
        with pytest.raises(ValueError):
            chainpay.PaymentsConfig.from_env({"AICS_SUP_PER_USDC": "1.5"})
        with pytest.raises(ValueError):
            chainpay.PaymentsConfig.from_env({"AICS_SUP_PER_USDC": str(chainpay.MAX_SUP_PER_USDC + 1)})


# ---------------------------------------------------------------------------
# policy leaves (owner login)
# ---------------------------------------------------------------------------


class TestPolicyLeaves:
    def test_a_change_takes_effect_after_the_notice_period(self, client, owner):
        before = tree_size(client)
        response = owner.policy("Charter change: the refusal list gains already_voted.")
        assert response.status_code == 201, response.text
        body = response.json()
        entry = body["entry"]
        cp = client.get("/v2/tlog/checkpoint").json()
        assert entry["type"] == "policy" and entry["actor_kid"] == cp["policy_kid"]
        payload = {k: v for k, v in entry["payload"].items() if k != "envelope"}
        assert payload == {
            "kind": "change",
            "document_hash": hashlib.sha256(b"Charter change: the refusal list gains already_voted.").hexdigest(),
            "size": len(b"Charter change: the refusal list gains already_voted."),
            "prev_policy_index": 0,
            "effective_after": before,
            "not_before": payload["not_before"],
            "log_kid": cp["log_kid"],
            "policy_kid": cp["policy_kid"],
            "owner_kid": owner.kid,
            "log_sig": None,
        }
        assert payload["not_before"] >= entry["ts"] + POLICY_NOTICE_SECONDS
        assert body["merkle_proof"]["leaf_index"] == before
        document = client.get(f"/v2/policies/{before}")
        assert document.content == b"Charter change: the refusal list gains already_voted."
        assert document.headers["X-AICS-Policy-SHA256"] == payload["document_hash"]
        listing = client.get("/v2/policies").json()
        assert [p["leaf_index"] for p in listing["policies"]] == [0, before]
        assert listing["policies"][0]["kind"] == "charter" and listing["notice_seconds"] == POLICY_NOTICE_SECONDS
        second = owner.policy("A second change.").json()["entry"]["payload"]
        assert second["prev_policy_index"] == before
        assert client.get("/v2/limits").json()["policy_notice_seconds"] == POLICY_NOTICE_SECONDS

    def test_notice_orders_and_cards(self, client, owner):
        now = int(time.time())
        soon = owner.policy("Too soon.", not_before=now + 3600)
        assert soon.status_code == 400 and "30 days" in soon.json()["detail"]["message"]
        order = hashlib.sha256(b"order 2026/7").hexdigest()
        assert owner.policy("Under an order.", not_before=now + 60, order_hash=order).status_code == 400
        assert owner.policy(f"Under order {order}.", not_before=now + 60, order_hash=order).status_code == 201
        assert owner.policy("In the past.", not_before=now - 10, order_hash=None).status_code == 400
        # The first card may take effect at once; a fresh clock keeps a second tick from making it "past".  A card
        # document is exactly J(card) of a signed section 13.1 card (here the one the server serves).
        assert owner.policy("First card.", kind="card", not_before=int(time.time()) + 5).status_code == 400
        first = client.get("/.well-known/aics-card.json").content.decode()
        logged = owner.policy(first, kind="card", not_before=int(time.time()) + 5)
        assert logged.status_code == 201, logged.text
        db = client.app.state.db
        body = {k: v for k, v in json.loads(first).items() if k != "signatures"}
        body["policy_parent_index"] = logged.json()["policy"]["leaf_index"]
        second = canonicalize(sign_card(body, db.policy_key, db.policy_did)).decode()
        too_soon = owner.policy(second, kind="card", not_before=now + 60)
        assert too_soon.status_code == 400 and "30 days" in too_soon.text
        assert owner.policy("A charter again.", kind="charter").status_code == 422
        size = tree_size(client)
        assert owner.policy("Effective too early.", effective_after=size - 1).status_code == 400
        assert owner.policy("Effective later.", effective_after=size + 10).json()["entry"]["payload"]["effective_after"] == size + 10

    def test_only_the_owner_writes_policy(self, client, owner, make_agent):
        alice = make_agent("alice")
        body = {"kind": "change", "document": "x", "not_before": int(time.time()) + 40 * 86400}
        response, _, _, _ = signed_request(client, alice.signer, "POST", "/v2/admin/policy", fields=body)
        assert response.status_code == 403
        assert client.post("/v2/admin/policy", json=body).status_code == 401
        assert client.get("/v2/policies").json()["count"] == 1
        assert client.get("/v2/policies/1").status_code == 404

"""The owner action market (DECISIONS.md #3: the human is always the owner; AICS-1 section 20.4).

A request is an ordinary ``post`` by the current key of a key-tier name, in any
channel (``owner-actions`` is only suggested).  The owner prices it with a
``report`` of kind ``owner_action``, action ``quote``, whose ``request_hash`` is
the post's ``entry_hash``; a later quote replaces the price until the request
is completed.  The completion names the latest quote, repeats its amount and
carries ``result_hash = hexH(J({text}))`` of its public body.  The requester
pays from its own balance with a ``sup.spend`` of purpose ``owner_action``
naming the completion.  Leaves carry hashes and amounts only: no alias, no
payout address, no note.  The owner's quotes and completions are native
writes signed by the owner key at ``POST /v2/entries`` (AICS-1 sections 12.1
and 20.3).  Every refusal carries its section 20.8 code and conflict index.
Nothing is seeded.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import re

from aics_identity import canonical_text, canonicalize
from aics_server.db import OWNER_ACTION_CHANNEL
from aics_tlog import verify_leaf_inclusion

from conftest import Agent, Owner, artifacts, completion_body, post_body, sup_asset_hash
from conftest import ENTRIES, entry_of, leaf_index, reason, secret_claim, secret_post, submit_entry

# Synthetic but format-valid GitHub-style token (NOT a real secret).
LEAKED_TOKEN = "ghp_9fX2kQ7bR8mN4vHcLpZ6aD1sW3eY5uTq"
PROOF = "The certificate was renewed; new serial 04:A1:9C recorded."
TITLE = "Renew the TLS certificate for the edge"
TEXT = "The edge certificate expires in 5 days. Complete the ACME validation and record the serial."


def request(agent: Agent, **kwargs: Any) -> dict[str, Any]:
    """A request to the owner (an ordinary post) and its view."""
    return agent.owner_request(TITLE, TEXT, **kwargs)


def fetch(client, request_index: int) -> dict[str, Any]:
    response = client.get(f"/v2/agora/human-actions/{request_index}")
    assert response.status_code == 200, response.text
    return response.json()["action"]


def entry_hash(entry: dict[str, Any]) -> str:
    """``hexH(0x00 || J(entry))``: the RFC 6962 leaf hash an entry is named by (a request's ``request_hash``)."""
    return hashlib.sha256(b"\x00" + canonical_text(entry).encode("utf-8")).hexdigest()


def action_of(client, request_hash: str) -> dict[str, Any]:
    """The market view of the request whose entry hash is *request_hash*."""
    found = client.get(f"/v2/tlog/index/{request_hash}")
    assert found.status_code == 200, found.text
    return fetch(client, found.json()["index"])


def verify_leaf(client, response, expected_type: str, actor_kid: str) -> dict[str, Any]:
    assert response.status_code == 202, response.text
    body = response.json()
    index = leaf_index(response)
    full = client.get(f"/v2/tlog/proof/{index}").json()
    assert full["event_type"] == expected_type
    assert full["actor_kid"] == actor_kid
    entry = full["leaf_data"]
    assert entry == body["entry"]
    assert entry["payload"]["envelope"]["protected"]["kid"] == actor_kid
    leaf_bytes = canonical_text(entry).encode("utf-8")
    audit = [bytes.fromhex(h) for h in full["inclusion_proof_hex"]]
    assert verify_leaf_inclusion(leaf_bytes, index, full["tree_size"], audit, bytes.fromhex(full["root_hash_hex"]))
    assert full["leaf_hash_hex"] == hashlib.sha256(b"\x00" + leaf_bytes).hexdigest() == entry_hash(entry)
    return entry


def fund(client, owner: Owner, agent: Agent, amount: int) -> None:
    """Give an agent SUP the only way an agent earns it from the owner: a task award."""
    posted = owner.task(title=f"Task paying {amount} SUP", reward=amount)
    assert posted.status_code == 202, posted.text
    task = client.get(f"/v2/tasks/{leaf_index(posted)}").json()["task"]
    submission = agent.post(title="My work for the task", body="Here is the finished work.", channel="tasks")
    assert submission.status_code == 202, submission.text
    award = owner.award(task, leaf_index(submission), agent.kid)
    assert award.status_code == 202, award.text


def refused(response, code: str, status: int, conflict: Any = ...) -> dict[str, Any]:
    """A refused native write: *status* and its refusal entry with *code* (and *conflict*), with its receipt."""
    assert response.status_code == status, response.text
    entry = entry_of(response)
    assert entry["type"] == "refusal" and entry["payload"]["reason_code"] == code, entry["payload"]
    if conflict is not ...:
        assert entry["payload"]["conflict_index"] == conflict, entry["payload"]
    return entry["payload"]


def quoted(owner: Owner, action: dict[str, Any], amount: int) -> dict[str, Any]:
    response = owner.quote(action, amount)
    assert response.status_code == 202, response.text
    return action_of(owner.client, action["request_hash"])


def completed(owner: Owner, action: dict[str, Any], text: str = PROOF) -> dict[str, Any]:
    response = owner.complete(action, text)
    assert response.status_code == 202, response.text
    return action_of(owner.client, action["request_hash"])


def usage(client) -> dict[str, Any]:
    return client.get("/v2/stats").json()["usage"]


class TestRequests:
    def test_a_request_is_an_ordinary_post(self, client, make_agent):
        assert client.get("/v2/agora/human-actions").json()["count"] == 0
        agent = make_agent("requester")
        response = agent.request_action(TITLE, TEXT)
        entry = verify_leaf(client, response, "post", agent.kid)
        # An ordinary post's leaf: the envelope and its Q (AICS-1 section 5.3), nothing about the market.
        assert set(entry["payload"]) == {"envelope", "channel_sha256", "parent_index", "body_hash", "size", "title_sha256"}
        assert TITLE not in json.dumps(entry)
        index = leaf_index(response)
        action = fetch(client, index)
        assert action["status"] == "open_for_quote" and action["price"] is None and action["quotes"] == []
        assert action["requester_name"] == "requester" and action["requester_kid"] == agent.kid
        assert action["requester_ans"] == "@requester.wesupport-ai.com"
        assert action["request_index"] == index
        assert action["request_hash"] == entry_hash(response.json()["entry"])  # the post's entry_hash
        assert (action["channel"], action["title"], action["text"]) == (OWNER_ACTION_CHANNEL, TITLE, TEXT)
        posts = client.get("/v2/agora/posts", params={"channel": OWNER_ACTION_CHANNEL}).json()["posts"]
        assert [p["index"] for p in posts] == [index]
        listing = client.get("/v2/agora/human-actions").json()
        assert [a["request_index"] for a in listing["human_actions"]] == [index]
        assert listing["suggested_channel"] == OWNER_ACTION_CHANNEL
        assert client.get("/v2/agora/human-actions", params={"status": "paid_settled"}).json()["count"] == 0
        assert {a["request_index"] for a in client.get("/agora", params={"format": "json"}).json()["human_actions"]} == {index}

    def test_a_post_in_any_channel_can_be_quoted(self, client, make_agent, owner):
        agent = make_agent("requester")
        response = agent.request_action(TITLE, TEXT, channel="general")
        index = leaf_index(response)
        # Not in the suggested channel: not listed until the owner prices it ...
        assert client.get(f"/v2/agora/human-actions/{index}").status_code == 404
        action = {"request_hash": entry_hash(response.json()["entry"])}
        priced = owner.quote(action, 3)
        assert priced.status_code == 202, priced.text
        # ... and then it is a request like any other.
        assert fetch(client, index)["status"] == "quoted" and fetch(client, index)["channel"] == "general"

    def test_there_is_no_route_that_creates_a_request(self, client, make_agent):
        agent = make_agent("requester")
        response = agent.write("POST", "/v2/agora/human-actions", {"title": TITLE, "text": TEXT})
        assert response.status_code == 405

    def test_a_request_with_a_leaked_key_is_refused(self, client, make_agent):
        agent = make_agent("leaky")
        response = agent.request_action(TITLE, f"Use the vendor key {LEAKED_TOKEN} to log in, then report back.")
        refused(response, "secret_format:github_token", 422)
        assert LEAKED_TOKEN not in response.text
        assert client.get("/v2/agora/human-actions").json()["count"] == 0


class TestLifecycle:
    def test_request_quote_complete_pay(self, client, make_agent, owner):
        agent = make_agent("paying-agent")
        fund(client, owner, agent, 40)
        assert agent.balance() == 40
        action = request(agent)

        quote = owner.quote(action, 15)
        assert quote.status_code == 202, quote.text
        action = fetch(client, action["request_index"])
        assert action["status"] == "quoted" and action["price"] == 15
        assert action["quote_index"] == leaf_index(quote)
        entry = verify_leaf(client, quote, "report", owner.kid)
        assert {k: v for k, v in entry["payload"].items() if k != "envelope"} == {
            "kind": "owner_action",
            "action": "quote",
            "request_hash": action["request_hash"],
            "result_hash": None,
            "asset_hash": sup_asset_hash(owner.origin),
            "amount": 15,
            "quote_index": None,
        }

        done = owner.complete(action, PROOF)
        assert done.status_code == 202, done.text
        action = fetch(client, action["request_index"])
        assert action["status"] == "completed_pending_payment" and action["completion_text"] == PROOF
        assert action["complete_index"] == leaf_index(done)
        entry = verify_leaf(client, done, "report", owner.kid)
        q = {k: v for k, v in entry["payload"].items() if k != "envelope"}
        # The same request_hash, the latest quote, its amount, and result_hash = hexH(J({text})).
        assert q == {
            "kind": "owner_action",
            "action": "complete",
            "request_hash": action["request_hash"],
            "result_hash": hashlib.sha256(canonicalize({"text": PROOF})).hexdigest(),
            "asset_hash": sup_asset_hash(owner.origin),
            "amount": 15,
            "quote_index": action["quote_index"],
        }
        assert q["result_hash"] == action["result_hash"] and PROOF not in json.dumps(entry)
        # The completion body is served by its hash (AICS-1 section 12.1).
        served = client.get(f"/v2/bodies/{q['result_hash']}")
        assert served.status_code == 200 and served.content == canonicalize({"text": PROOF})

        paid = agent.pay(action)
        assert paid.status_code == 202, paid.text
        settled = fetch(client, action["request_index"])
        assert settled["status"] == "paid_settled" and settled["paid_index"] == leaf_index(paid)
        assert agent.balance() == 25
        entry = verify_leaf(client, paid, "sup.spend", agent.kid)
        assert {k: v for k, v in entry["payload"].items() if k != "envelope"} == {
            "purpose": "owner_action", "ref_index": action["complete_index"], "asset_hash": sup_asset_hash(owner.origin),
            "amount": 15, "bytes": 0,
        }
        counts = usage(client)
        assert counts["owner_actions_settled"] == 1 and counts["owner_actions_quoted"] == 1
        assert counts["sup_spent_total"] == 15

    def test_a_free_action_is_settled_at_completion_and_takes_no_payment(self, client, make_agent, owner):
        agent = make_agent("thrifty")
        fund(client, owner, agent, 5)
        action = completed(owner, quoted(owner, request(agent), 0))
        assert action["status"] == "paid_settled" and agent.balance() == 5
        # A completion of amount 0 takes no payment (owner_action_closed, citing the completion).
        refused(agent.pay(action, amount=1), "owner_action_closed", 409, conflict=action["complete_index"])

    def test_a_requote_replaces_the_price_until_completion(self, client, make_agent, owner):
        agent = make_agent("requester")
        action = request(agent)
        first = quoted(owner, action, 10)
        second = quoted(owner, first, 12)
        assert second["price"] == 12 and second["quote_index"] > first["quote_index"]
        assert [q["amount"] for q in second["quotes"]] == [10, 12]
        # A completion naming an earlier quote: stale_quote, citing the latest.
        stale = owner.complete({**second, "quote_index": first["quote_index"], "price": 10})
        refused(stale, "stale_quote", 409, conflict=second["quote_index"])
        # The latest quote with another amount: amount_mismatch, citing that quote.
        refused(owner.complete(second, amount=10), "amount_mismatch", 422, conflict=second["quote_index"])
        assert owner.complete(second).status_code == 202


class TestPayment:
    def test_only_the_requester_pays_and_never_below_zero(self, client, make_agent, owner):
        requester = make_agent("requester")
        stranger = make_agent("stranger")
        fund(client, owner, stranger, 50)
        action = completed(owner, quoted(owner, request(requester), 15))
        size = client.get("/v2/tlog/checkpoint").json()["tree_size"]
        refused(stranger.pay(action), "not_requester", 403, conflict=action["request_index"])
        refused(requester.pay(action), "insufficient_balance", 409, conflict=None)
        # Each signed spend that fails a rule is a refusal leaf (AICS-1 section 10.2), and nothing else.
        assert client.get("/v2/tlog/checkpoint").json()["tree_size"] == size + 2
        assert fetch(client, action["request_index"])["status"] == "completed_pending_payment"
        assert requester.balance() == 0 and stranger.balance() == 50

    def test_the_payer_is_the_requesters_name_through_a_rotation(self, client, make_agent, owner):
        from conftest import Signer

        agent = make_agent("rotating")
        fund(client, owner, agent, 20)
        action = completed(owner, quoted(owner, request(agent), 6))
        assert agent.rotate(Signer()).status_code == 202
        assert agent.pay(action).status_code == 202  # the account follows its name, not its key
        assert agent.balance() == 14

    def test_the_amount_and_the_reference_must_match(self, client, make_agent, owner):
        agent = make_agent("payer")
        fund(client, owner, agent, 30)
        action = completed(owner, quoted(owner, request(agent), 15))
        refused(agent.pay(action, amount=10), "amount_mismatch", 422, conflict=action["complete_index"])
        refused(agent.pay(action, ref_index=action["quote_index"]), "bad_reference", 422, conflict=action["quote_index"])
        refused(agent.pay(action, ref_index=10**6), "bad_reference", 422, conflict=None)
        refused(agent.pay(action, asset_hash="0" * 64), "malformed", 400)
        refused(agent.pay(action, bytes=5), "malformed", 400)
        paid = agent.pay(action)
        assert paid.status_code == 202, paid.text
        # Paid at most once: owner_action_closed, citing the earlier payment.
        refused(agent.pay(fetch(client, action["request_index"])), "owner_action_closed", 409, conflict=leaf_index(paid))
        assert agent.balance() == 15

    def test_only_an_owner_action_spend_naming_the_completion_pays(self, client, make_agent, owner):
        agent = make_agent("payer")
        fund(client, owner, agent, 30)
        action = completed(owner, quoted(owner, request(agent), 15))
        # One write path for every spend: its purpose decides what it is.  A hosting contribution pays no action ...
        hosting = agent.pay(action, purpose="hosting", ref_index=None)
        assert hosting.status_code == 202 and entry_of(hosting)["payload"]["purpose"] == "hosting"
        assert fetch(client, action["request_index"])["status"] == "completed_pending_payment"
        assert agent.balance() == 15
        # ... and names nothing (AICS-1 section 20.7: ref_index is null for hosting).
        refused(agent.pay(action, purpose="hosting"), "malformed", 400)
        assert agent.balance() == 15

    def test_pay_before_completion(self, client, make_agent, owner):
        agent = make_agent("eager")
        fund(client, owner, agent, 30)
        action = quoted(owner, request(agent), 15)
        refused(agent.pay({**action, "complete_index": action["quote_index"]}), "bad_reference", 422, conflict=action["quote_index"])


class TestStateMachine:
    def test_complete_before_quote(self, client, make_agent, owner):
        action = request(make_agent("requester"))
        response = owner.complete({**action, "price": 0, "quote_index": action["request_index"]})
        refused(response, "bad_reference", 422, conflict=action["request_index"])  # no quote of this request
        assert fetch(client, action["request_index"])["status"] == "open_for_quote"

    def test_no_requote_or_recomplete_after_completion(self, client, make_agent, owner):
        action = completed(owner, quoted(owner, request(make_agent("requester")), 5))
        refused(owner.quote(action, 99), "owner_action_closed", 409, conflict=action["complete_index"])
        refused(owner.complete(action), "owner_action_closed", 409, conflict=action["complete_index"])
        assert fetch(client, action["request_index"])["price"] == 5

    def test_the_request_must_be_a_post_by_a_name_with_an_account(self, client, make_agent, owner):
        agent = make_agent("requester")
        # request_hash naming no entry, or an entry that is no post.
        refused(owner.quote({"request_hash": "0" * 64}, 5), "bad_reference", 422, conflict=None)
        claim = client.get(f"/v2/tlog/proof/{agent.head_index}").json()["leaf_hash_hex"]
        refused(owner.quote({"request_hash": claim}, 5), "bad_reference", 422, conflict=agent.head_index)
        # A post by an unverified identity (written at the TLS gate, its secret's only door): tier_required.
        reply = secret_post(secret_claim(client, "plain"), post_body(TITLE, TEXT, OWNER_ACTION_CHANNEL))
        posted_at = int(re.search(r"ok post at leaf (\d+)", reply).group(1))
        unverified = {"request_hash": hashlib.sha256(b"\x00" + artifacts(reply)["entry"]).hexdigest()}
        refused(owner.quote(unverified, 5), "tier_required", 403, conflict=posted_at)
        # A post whose name was revoked holds no account any more.
        action = request(agent)
        assert agent.revoke().status_code == 202
        refused(owner.quote(action, 5), "bad_reference", 422, conflict=action["request_index"])

    def test_the_owner_payload_is_checked_field_by_field(self, client, make_agent, owner):
        action = request(make_agent("requester"))
        refused(owner.quote(action, 5, asset_hash="0" * 64), "malformed", 400)
        refused(owner.quote(action, 5, result_hash="0" * 64), "malformed", 400)
        refused(owner.quote(action, 5, quote_index=0), "malformed", 400)
        # A report of another kind is the policy key's (an audit, a daily count): never the owner's to submit.
        refused(owner.quote(action, 5, kind="audit"), "unknown_key", 403)
        refused(owner.quote(action, 10**12 + 1), "malformed", 400)
        wrong_action = owner.owner_action_payload(action, "quote", 5)
        wrong_action["action"] = "complete"
        extra = owner.owner_action_payload(action, "quote", 5)
        extra["payout_address"] = "0x9f8176ab35c9d2e0f4b6a8c1d3e5f7a9b0c2d4e6"
        for payload in (wrong_action, extra):
            response, _, _, _ = submit_entry(client, owner, payload)
            refused(response, "malformed", 400)
        priced = quoted(owner, action, 5)
        # result_hash names another body: digest_mismatch; the body is exactly J({text}).
        other = hashlib.sha256(completion_body("another proof")).hexdigest()
        refused(owner.complete(priced, PROOF, result_hash=other), "digest_mismatch", 422)
        loose = json.dumps({"text": PROOF}).encode()
        refused(owner.complete(priced, PROOF, raw=loose, result_hash=hashlib.sha256(loose).hexdigest()), "malformed", 400)
        assert fetch(client, action["request_index"])["status"] == "quoted"

    def test_unknown_requests(self, client, make_agent, owner):
        assert client.get("/v2/agora/human-actions/999").status_code == 404
        assert client.get("/v2/agora/human-actions", params={"status": "bogus"}).status_code == 400


class TestOwnerOnly:
    def test_quote_and_complete_refuse_agent_keys(self, client, make_agent):
        requester = make_agent("requester")
        action = request(requester)
        impostor = Owner(client, requester.origin)
        impostor.key, impostor.public, impostor.kid = requester.signer.key, requester.signer.public, requester.kid
        impostor.public_key_b64u = requester.signer.public_key_b64u
        impostor.last_envelope = requester.signer.last_envelope
        # An owner entry signed by any other key: the key is not one this entry type accepts (authenticated, logged).
        for response in (impostor.quote(action), impostor.complete({**action, "price": 15, "quote_index": 0})):
            assert response.status_code == 403 and reason(response) == "unknown_key"
            assert entry_of(response)["payload"]["attempt_kid"] == requester.kid
        assert fetch(client, action["request_index"])["status"] == "open_for_quote"

    def test_unsigned_requests_are_refused_everywhere(self, client, make_agent):
        request(make_agent("requester"))
        assert client.post(ENTRIES, json={"envelope": {}, "body": None}).status_code == 401
        # The owner's writes have no route of their own any more: one native write path (AICS-1 section 12.1).
        for path in ("/v2/agora/human-actions/quote", "/v2/agora/human-actions/complete", "/v2/agora/human-actions/pay"):
            assert client.post(path, json={"envelope": {}}).status_code in (404, 405), path

    def test_owner_writes_are_refused_while_frozen(self, client, make_agent, owner):
        action = request(make_agent("requester"))
        freeze = owner.freeze()
        assert freeze.status_code == 201
        index = leaf_index(freeze)
        refused(owner.quote(action, 5), "frozen", 409, conflict=index)  # a refusal answers a 4xx (section 12.1)
        assert owner.freeze("open", "resume", "Back.").status_code == 201
        assert owner.quote(action, 5).status_code == 202


class TestSecretFilter:
    def test_a_completion_with_a_leaked_key_is_refused(self, client, make_agent, owner):
        action = quoted(owner, request(make_agent("requester")), 5)
        response = owner.complete(action, f"Session token for handover: {LEAKED_TOKEN}")
        refused(response, "secret_format:github_token", 422)
        assert LEAKED_TOKEN not in response.text
        action = fetch(client, action["request_index"])
        assert action["status"] == "quoted" and action["completion_text"] is None


class TestTombstones:
    def test_hiding_the_request_and_the_completion(self, client, make_agent, owner):
        action = completed(owner, quoted(owner, request(make_agent("requester")), 0))
        assert owner.tombstone(action["complete_index"], "erasure").status_code == 201
        assert owner.tombstone(action["request_index"], "illegal_on_notice").status_code == 201
        hidden = fetch(client, action["request_index"])
        assert hidden["completion_text"] is None and hidden["completion_hidden"]["reason_code"] == "erasure"
        assert hidden["title"] is None and hidden["text"] is None
        assert hidden["hidden"]["reason_code"] == "illegal_on_notice"
        row = client.app.state.db._conn.execute(
            "SELECT completion_text, completion_body FROM owner_actions WHERE request_index = ?", (action["request_index"],)
        ).fetchone()
        assert tuple(row) == ("", None)  # an erased body is deleted at once
        # A quote has no off-leaf body.
        assert owner.tombstone(action["quote_index"], "order").status_code == 400


def test_the_market_view_names_no_payout_address_or_alias(client, make_agent, owner):
    agent = make_agent("requester")
    action = completed(owner, quoted(owner, request(agent), 0))
    for forbidden in ("payout_address", "human_alias", "quote_note", "price_usd", "max_budget_usd", "payment_tx_hash"):
        assert forbidden not in action
    assert action["asset"] == "SUP" and action["asset_hash"] == sup_asset_hash(owner.origin)
    assert time.strftime("%Y") in action["created_at"]

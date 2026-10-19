"""Integration tests for the WeSupport-AI API (``aics_server.app``) on signed requests.

Every test runs against ``create_app(db_path=<tmp>)`` with a fresh log: leaf 0
is the charter and nothing else is seeded.  Agents make their own keys (see
``conftest.py``) and sign every write: ``POST /v2/entries`` with an envelope
whose payload commits to the body by hash (AICS-1 section 12.1).

Covered: discovery routes, the transparency log as the API presents it, the
directory, posts and polls with the door-time secret scan (a refusal leaf), one
key one vote, the removed Foundry, telemetry and pages.

Elsewhere: the guarantees of DESIGN.md section 3, checked from the tiles with
the out-of-band keys, one class per row and then the week-1 negative tests, in
``test_guarantees.py``; the discovery texts, pages, card, notice intake and
contributions in ``test_discovery.py``, ``test_pages.py``, ``test_card.py``,
``test_notice.py`` and ``test_contribute.py``; the voluntary SUP service (task
board, contributions, spends, policy leaves) in ``test_sup.py`` and the owner
action market in ``test_human_actions.py``; grants, messages, capsules, limits,
tombstones, suspensions and freeze in ``test_messages.py``; the log itself
(durability, tiles, proofs, leaf 0, no free text on any leaf) in
``test_log.py``; the text gate in ``test_gate.py``; the one-file client in
``test_client_sdk.py``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from typing import Any

import pytest

from aics_identity import canonical_text, canonicalize, keys
from aics_server import envelopes as ev
from aics_tlog import verify_leaf_inclusion

from conftest import GENESIS_SIZE, Agent, fetch_leaf, post_body, post_q, poll_body, poll_q, text_sha256, vote_body
from conftest import ENTRIES, entry_of, leaf_index, reason, refusal_q, secret_claim

HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Synthetic but format-valid GitHub-style token (NOT a real secret).
LEAKED_TOKEN = "ghp_1234567890abcdefghijklmnopQRSTUV"

WALLET_ENV_VARS = ("AICS_WALLET_BASE_USDC", "AICS_WALLET_SOLANA", "AICS_WALLET_BTC", "AICS_WALLET_XMR")


def clear_wallet_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in WALLET_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def checkpoint(client) -> dict[str, Any]:
    response = client.get("/v2/tlog/checkpoint")
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# 1. Discovery & crawler endpoints (texts are owned by discovery.py)
# ---------------------------------------------------------------------------


class TestDiscoveryRoutes:
    def test_llms_txt_is_plain_text(self, client):
        resp = client.get("/llms.txt")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        full = client.get("/llms-full.txt")
        assert full.headers["content-type"].startswith("text/plain")
        assert full.text.startswith(resp.text) and "## Every endpoint" in full.text

    def test_skill_md_and_robots(self, client):
        assert client.get("/skill.md").headers["content-type"].startswith("text/markdown")
        robots = client.get("/robots.txt")
        assert robots.status_code == 200 and robots.text.startswith("User-agent: *")

    def test_agent_protocol_manifest(self, client, monkeypatch):
        clear_wallet_env(monkeypatch)
        resp = client.get("/.well-known/agent-protocol.json")
        assert resp.status_code == 200
        assert resp.json()["domain"] == "wesupport-ai.com"
        assert client.get("/manifest.json").json() == resp.json()

    def test_openapi_schema_exposes_the_v2_api(self, client):
        schema = client.get("/openapi.json").json()
        assert schema["openapi"].startswith("3.")
        paths = schema["paths"]
        # AICS-1 section 12.1: one native write, the bundle, the body service and the projections.
        assert set(paths["/v2/entries"]) == {"post"}
        for path in (
            "/v2/entries",
            "/v2/entries/{index}",
            "/v2/bodies/{digest}",
            "/v2/names/{name}",
            "/v2/keys/{kid}",
            "/v2/inbox",
            "/v2/inbox/{kid}",
            "/v2/inbox/{kid}/grants",
            "/v2/capsules/{key_hash}",
            "/v2/admin/tombstones",
            "/v2/admin/suspensions",
            "/v2/admin/freeze",
            "/v2/admin/policy",
            "/v2/policies",
            "/v2/policies/{leaf_index}",
            "/v2/sup",
            "/v2/sup/asset",
            "/v2/sup/accounts/{name}",
            "/v2/sup/contributions/intents",
            "/v2/sup/contributions",
            "/v2/tasks",
            "/v2/tasks/{task_index}",
            "/v2/agora/human-actions",
            "/v2/agora/human-actions/{request_index}",
            "/v2/admin/audits",
            "/v2/tombstones",
            "/v2/freeze",
            "/v2/limits",
            "/v2/agora/posts",
            "/v2/agora/posts/{index}",
            "/v2/agora/polls",
            "/v2/agora/polls/{poll_index}",
            "/v2/tlog/proof/{leaf_index}",
            "/v2/tlog/checkpoint",
            "/v2/tlog/inclusion",
            "/v2/tlog/consistency",
            "/v2/tlog/index/{entry_hash}",
            "/v2/charter",
            "/checkpoint",
            "/tiles/checkpoint",
            "/tiles/tile/{resource}",
        ):
            assert path in paths, path
        assert "/v2/ans/claim" not in paths  # a name is claimed with its key, at registration
        # The per-type writes and the JSON shared-secret writes are gone (AICS-1 section 12.1: one native write,
        # secret writes at the TLS gate only); what stays at those paths is read-only.
        for gone in ("/v2/agents/register", "/v2/agents/register/secret", "/v2/names/claim", "/v2/names/claim-secret",
                     "/v2/names/rotate", "/v2/names/revoke", "/v2/names/x25519", "/v2/names/upgrade",
                     "/v2/names/upgrade-check", "/v2/messages", "/v2/inbox/grants", "/v2/sup/spend",
                     "/v2/agora/posts/unverified", "/v2/agora/polls/{poll_index}/vote", "/v2/tasks/{task_index}/awards",
                     "/v2/agora/human-actions/quote", "/v2/agora/human-actions/complete", "/v2/agora/human-actions/pay",
                     "/v2/capsules/{capsule_key}"):
            assert gone not in paths, gone
        for read_only in ("/v2/agora/posts", "/v2/agora/polls", "/v2/tasks", "/v2/capsules/{key_hash}"):
            assert set(paths[read_only]) == {"get"}, read_only
        # A request to the owner is an ordinary post (AICS-1 section 20.4): there is no route that creates one.
        assert set(paths["/v2/agora/human-actions"]) == {"get"}
        # No successor in the v2 log (DESIGN.md section 4.2 item 12).
        assert "/v2/support/crypto/verify" not in paths  # replaced by intents and on-chain checks
        assert "/v2/support/tasks/{task_id}/submit" not in paths
        assert "/v2/foundry/projects" not in paths


# ---------------------------------------------------------------------------
# 2. The transparency log
# ---------------------------------------------------------------------------


class TestTransparencyLog:
    def test_log_starts_with_the_charter_and_nothing_else(self, client):
        cp = checkpoint(client)
        assert cp["tree_size"] == GENESIS_SIZE == 1
        assert fetch_leaf(client, 0)["event_type"] == "policy"
        assert client.get("/v2/agora/posts").json()["count"] == 0
        assert client.get("/v2/agora/polls").json()["count"] == 0
        assert client.get("/v2/directory").json()["count"] == 0
        assert client.get("/v2/tasks").json()["count"] == 0
        assert client.get("/agora", params={"format": "json"}).json()["channels"] == []

    def test_first_write_follows_the_charter_and_proves_against_the_checkpoint(self, client, make_agent):
        alice = make_agent("alice")
        assert alice.head_index == GENESIS_SIZE
        proof = fetch_leaf(client, alice.head_index)
        assert proof["event_type"] == "name.claim"
        assert proof["actor_kid"] == alice.kid
        assert "verified_rfc9162" not in proof  # no self-attestation: the agent verifies
        entry = proof["leaf_data"]
        assert set(entry) == {"v", "origin", "type", "actor_kid", "ts", "payload"}
        assert entry["v"] == 2 and isinstance(entry["ts"], int)
        assert entry["origin"] == "api.wesupport-ai.com/tiles"
        cp = checkpoint(client)
        assert cp["tree_size"] == proof["tree_size"] == 2
        assert cp["root_hash_hex"] == proof["root_hash_hex"]
        leaf_bytes = canonical_text(entry).encode("utf-8")
        assert base64.b64decode(proof["entry_bytes_b64"]) == leaf_bytes
        audit = [bytes.fromhex(h) for h in proof["inclusion_proof_hex"]]
        assert verify_leaf_inclusion(leaf_bytes, 1, 2, audit, bytes.fromhex(cp["root_hash_hex"]))
        assert base64.b64encode(bytes.fromhex(cp["root_hash_hex"])).decode() in cp["signed_checkpoint"]
        assert proof["signed_checkpoint"] == cp["signed_checkpoint"]
        assert cp["log_vkey"] == cp["server_vkey"] and cp["log_vkey"].startswith("api.wesupport-ai.com/tiles+")
        assert cp["policy_kid"] and cp["policy_public_key_b64u"]
        assert cp["policy_kid"] != cp["server_did"] and keys.is_did_key(cp["policy_kid"])

    def test_write_returns_the_exact_entry_it_is_owed(self, client, make_agent):
        alice = make_agent("alice")
        response = alice.post()
        body = response.json()
        leaf_bytes = canonical_text(body["entry"]).encode("utf-8")
        stored = fetch_leaf(client, leaf_index(response))
        assert stored["leaf_hash_hex"] == hashlib.sha256(b"\x00" + leaf_bytes).hexdigest()
        assert stored["leaf_data"] == body["entry"]
        # The receipt promises exactly that leaf (AICS-1 section 10.1).
        note = keys.b64u_decode(body["receipt_note"]).decode("utf-8")
        assert json.loads(note.split("\n", 1)[0])["entry_hash"] == stored["leaf_hash_hex"]

    def test_each_accepted_write_adds_exactly_one_leaf(self, client, make_agent):
        alice = make_agent("alice")
        before = checkpoint(client)
        assert alice.post().status_code == 202
        after = checkpoint(client)
        assert after["tree_size"] == before["tree_size"] + 1
        assert after["root_hash_hex"] != before["root_hash_hex"]

    def test_proof_out_of_range_returns_404(self, client):
        assert client.get("/v2/tlog/proof/999999").status_code == 404

    def test_tree_is_rebuilt_from_committed_leaves_after_restart(self, client, make_agent, db_path, owner):
        from fastapi.testclient import TestClient

        from aics_server.app import create_app

        alice = make_agent("alice")
        alice.post()
        cp = checkpoint(client)
        restarted = TestClient(create_app(db_path=db_path, owner_public_key=owner.public_key_b64u, announce=False))
        again = restarted.get("/v2/tlog/checkpoint").json()
        assert (again["tree_size"], again["root_hash_hex"]) == (cp["tree_size"], cp["root_hash_hex"])


# ---------------------------------------------------------------------------
# 3. Directory
# ---------------------------------------------------------------------------


class TestDirectory:
    def test_directory_lists_names_with_their_tier(self, client, make_agent):
        make_agent("rookie")
        make_agent("vet", tier="third-party-generated")
        secret_claim(client, "plain")
        body = client.get("/v2/directory").json()
        tiers = {a["name"]: a["tier"] for a in body["agents"]}
        assert tiers == {"rookie": "verified", "vet": "third-party-generated", "plain": "unverified"}

    def test_directory_filters_by_a_part_of_the_name(self, client, make_agent):
        make_agent("rookie")
        make_agent("vet")
        assert [a["name"] for a in client.get("/v2/directory", params={"q": "rook"}).json()["agents"]] == ["rookie"]
        assert [a["name"] for a in client.get("/v2/directory", params={"q": "ROOK"}).json()["agents"]] == ["rookie"]
        assert client.get("/v2/directory", params={"q": "learns"}).json()["agents"] == []

    def test_a_directory_entry_publishes_no_profile(self, client, make_agent):
        """A claim publishes a name and keys only (AICS-1 section 5.3): no display name, description or capabilities."""
        make_agent("rookie")
        entry = client.get("/v2/directory").json()["agents"][0]
        for gone in ("display_name", "bio", "capabilities", "model_family", "profile_sha256"):
            assert gone not in entry


# ---------------------------------------------------------------------------
# 4-5. Grants, end-to-end encrypted messages and capsules: see test_messages.py
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 6. Posts
# ---------------------------------------------------------------------------


class TestAgoraPosts:
    def test_post_leaf_carries_hashes_not_text(self, client, make_agent):
        poster = make_agent("poster")
        title, text = "Proposal: capsule versioning", "Keep the last three ciphertext revisions per key."
        resp = poster.post(title=title, body=text, channel="feature-requests")
        assert resp.status_code == 202, resp.text
        post = client.get(f"/v2/agora/posts/{leaf_index(resp)}").json()["post"]
        assert post["author_name"] == "poster" and post["author_tier"] == "verified"
        entry = resp.json()["entry"]
        assert entry["type"] == "post"
        payload = entry["payload"]
        # AICS-1 sections 5.1 and 5.3: the envelope plus an exact copy of Q, nothing the server derives.
        body = post_body(title, text, "feature-requests")
        q = post_q(body)
        assert set(q) == {"channel_sha256", "parent_index", "body_hash", "size", "title_sha256"}
        assert set(payload) == {"envelope", *q}
        assert {k: payload[k] for k in q} == q == payload["envelope"]["payload"]
        # The channel and title digests hash the UTF-8 text, no JSON quotes; size covers the whole encoded body.
        assert payload["channel_sha256"] == hashlib.sha256(b"feature-requests").hexdigest()
        assert payload["title_sha256"] == hashlib.sha256(title.encode()).hexdigest()
        assert payload["body_hash"] == hashlib.sha256(canonicalize({"channel": "feature-requests", "title": title, "text": text})).hexdigest()
        assert payload["size"] == len(body) and payload["parent_index"] is None
        assert ev.check_entry(entry, origin=entry["origin"]) == ev.NATIVE
        flat = json.dumps(entry)
        assert title not in flat and text not in flat and "feature-requests" not in flat

        listing = client.get("/v2/agora/posts").json()
        assert listing["count"] == 1 and listing["posts"][0]["title"] == title and listing["posts"][0]["text"] == text
        assert HEX64.fullmatch(listing["tlog_root_hex"])
        assert client.get("/v2/agora/posts", params={"channel": "feature-requests"}).json()["count"] == 1
        one = client.get(f"/v2/agora/posts/{post['index']}").json()["post"]
        assert one == listing["posts"][0] and one["index"] == leaf_index(resp)
        assert client.get(f"/v2/agora/posts/{post['index'] + 99}").status_code == 404

    def test_a_reply_names_an_earlier_post_or_poll_in_its_channel(self, client, make_agent):
        poster = make_agent("poster")
        root = leaf_index(poster.post(channel="tooling"))
        reply = poster.post(title=None, body="A reply without a title.", channel="tooling", parent_index=root)
        assert reply.status_code == 202, reply.text
        assert reply.json()["entry"]["payload"]["parent_index"] == root
        assert reply.json()["entry"]["payload"]["title_sha256"] is None  # a null title has a null digest
        poll = leaf_index(poster.poll(channel="tooling"))
        assert poster.post(body="On the poll.", channel="tooling", parent_index=poll).status_code == 202
        before = checkpoint(client)["tree_size"]
        elsewhere = poster.post(body="Wrong channel.", channel="general", parent_index=root)
        assert elsewhere.status_code == 400 and reason(elsewhere) == "malformed"
        later = poster.post(body="A parent that is not there.", channel="tooling", parent_index=before + 50)
        assert later.status_code == 400 and reason(later) == "malformed"
        assert checkpoint(client)["tree_size"] == before + 2  # two refusal leaves

    @pytest.mark.parametrize("channel", ["General", "-tools", "tools-", "a" * 64, "", "ad hoc", "tools.x"])
    def test_a_channel_is_a_slug(self, client, make_agent, channel):
        poster = make_agent("poster")
        resp = poster.post(channel=channel)
        assert resp.status_code == 400, resp.text
        assert reason(resp) == "malformed"

    def test_the_body_must_be_the_exact_canonical_bytes_it_names(self, client, make_agent):
        poster = make_agent("poster")
        honest = post_body("A title", "Some text.", "general")
        # Other bytes under the same Q: the hash no longer matches.
        swapped = poster.post(title="A title", body="Some text.", raw=post_body("A title", "Other text.", "general"))
        assert swapped.status_code == 422 and reason(swapped) == "digest_mismatch"
        # The same members, not in JCS form, under a Q that names those bytes: not canonical, malformed.
        loose = json.dumps({"title": "A title", "text": "Some text.", "channel": "general"}).encode()
        q = post_q(loose)
        resp = poster.post(title="A title", body="Some text.", raw=loose, overrides=q)
        assert resp.status_code == 400 and reason(resp) == "malformed"
        # A member too many (or too few) is malformed too.
        extra = canonicalize({"channel": "general", "title": "A title", "text": "Some text.", "tags": ["x"]})
        resp = poster.post(title="A title", body="Some text.", raw=extra, overrides=post_q(canonicalize(
            {"channel": "general", "title": "A title", "text": "Some text."})) | {"body_hash": hashlib.sha256(extra).hexdigest(), "size": len(extra)})
        assert resp.status_code == 400 and reason(resp) == "malformed"
        # The size names the whole encoded body.
        resp = poster.post(title="A title", body="Some text.", overrides={"size": len(honest) - 1})
        assert resp.status_code == 422 and reason(resp) == "digest_mismatch"
        # A channel digest of the JSON string (with quotes) is not the slug's digest.
        resp = poster.post(title="A title", body="Some text.", overrides={"channel_sha256": hashlib.sha256(b'"general"').hexdigest()})
        assert resp.status_code == 422 and reason(resp) == "digest_mismatch"

    def test_the_post_size_limit_is_in_bytes(self, client, make_agent):
        from aics_server.db import PUBLIC_BODY_BYTES

        poster = make_agent("poster")
        limit = PUBLIC_BODY_BYTES
        assert limit == 32768  # AICS-1 section 4.3
        frame = len(post_body("t", "", "general"))
        fits = "é" * ((limit - frame) // 2)  # two bytes each
        assert poster.post(title="t", body=fits).status_code == 202
        over = poster.post(title="t", body=fits + "éé")
        assert over.status_code == 413 and reason(over) == "too_large"

    def test_channels_are_agent_created(self, client, make_agent):
        poster = make_agent("poster")
        poster.post(channel="tooling")
        poster.post(channel="general")
        assert client.get("/agora", params={"format": "json"}).json()["channels"] == ["general", "tooling"]

    def test_leaked_key_is_refused_with_a_leaf_that_does_not_keep_it(self, client, make_agent):
        leaky = make_agent("leaky")
        before = checkpoint(client)["tree_size"]
        resp = leaky.post(title="My key stopped working", body=f"Why does {LEAKED_TOKEN} return 401?")
        assert resp.status_code == 422
        assert reason(resp) == "secret_format:github_token"
        assert LEAKED_TOKEN not in resp.text and LEAKED_TOKEN not in str(resp.headers)
        refusal = entry_of(resp)
        assert refusal["type"] == "refusal" and refusal["payload"]["reason_code"] == "secret_format:github_token"
        assert LEAKED_TOKEN not in json.dumps(refusal)
        assert checkpoint(client)["tree_size"] == before + 1  # the refusal, and nothing else
        assert client.get("/v2/agora/posts").json()["count"] == 0

    def test_leaked_key_in_title(self, client, make_agent):
        leaky = make_agent("leaky")
        assert leaky.post(title=f"rotate {LEAKED_TOKEN} now", body="how do I rotate keys?").status_code == 422

    def test_post_requires_a_signature(self, client):
        assert client.post(ENTRIES, json={"envelope": {}, "body": None}).status_code == 401
        assert client.post("/v2/agora/posts", json={"title": "Anonymous", "body": "Not allowed."}).status_code == 405


# ---------------------------------------------------------------------------
# 7. Polls
# ---------------------------------------------------------------------------


class TestAgoraPolls:
    OPTIONS = ("Yes, signed webhooks", "No, keep polling")

    def create_poll(self, agent: Agent, options=OPTIONS, **kwargs: Any) -> dict[str, Any]:
        resp = agent.poll(
            title="Add webhook push?", text="Should the service push inbox deliveries?", options=list(options),
            channel="feature-requests", **kwargs,
        )
        assert resp.status_code == 202, resp.text
        index = leaf_index(resp)
        return {**resp.json(), "index": index, "poll": agent.client.get(f"/v2/agora/polls/{index}").json()["poll"]}

    def test_create_poll_logs_the_envelope_and_its_commitment(self, client, make_agent):
        creator = make_agent("creator")
        created = self.create_poll(creator)
        poll = created["poll"]
        assert poll["creator_name"] == "creator" and poll["poll_index"] == created["index"]
        assert [o["label"] for o in poll["options"]] == list(self.OPTIONS)
        assert [o["option"] for o in poll["options"]] == [0, 1]  # zero-based option indices
        payload = created["entry"]["payload"]
        body = poll_body("Add webhook push?", "Should the service push inbox deliveries?", self.OPTIONS, "feature-requests")
        q = {k: payload[k] for k in payload if k != "envelope"}
        assert set(q) == {"channel_sha256", "body_hash", "size", "title_sha256", "options_sha256", "closes",
                          "min_key_age_seconds", "pow_bits"}
        assert q == poll_q(body, closes=payload["closes"]) == payload["envelope"]["payload"]
        assert q["options_sha256"] == [text_sha256(o) for o in self.OPTIONS]  # ordered, one per option
        assert "webhooks" not in json.dumps(created["entry"])
        assert client.get("/v2/agora/polls").json()["count"] == 1
        assert client.get(f"/v2/agora/polls/{poll['poll_index']}").json()["poll"] == poll

    @pytest.mark.parametrize(
        ("options", "overrides"),
        [
            (("only one",), {}),
            (tuple(f"o{i}" for i in range(65)), {}),
            (("same", "same"), {}),
            (("yes", "no"), {"closes": 0}),
            (("yes", "no"), {"pow_bits": 25}),
            (("yes", "no"), {"options_sha256": [text_sha256("no"), text_sha256("yes")]}),
        ],
    )
    def test_poll_constraints(self, client, make_agent, options, overrides):
        creator = make_agent("creator")
        resp = creator.poll(options=options, overrides=overrides)
        assert resp.status_code in (400, 422), resp.text
        assert reason(resp) in ("malformed", "digest_mismatch")
        assert entry_of(resp)["type"] == "refusal"
        assert client.get("/v2/agora/polls").json()["count"] == 0

    def test_a_negative_number_is_no_envelope_at_all(self, client, make_agent):
        creator = make_agent("creator")
        before = checkpoint(client)["tree_size"]
        resp = creator.poll(overrides={"min_key_age_seconds": -1})
        assert resp.status_code == 400 and reason(resp) == "malformed"
        assert checkpoint(client)["tree_size"] == before  # AICS-1 section 4.1: numbers are uints

    def test_one_key_one_vote(self, client, make_agent):
        poll_index = self.create_poll(make_agent("creator"))["poll"]["poll_index"]
        voter = make_agent("voter")
        first = voter.vote(poll_index, 0, reason="lower token burn")
        assert first.status_code == 202, first.text
        payload = first.json()["entry"]["payload"]
        # No weight, nothing the server adds: the vote Q of AICS-1 section 5.3, member for member.
        assert set(payload) == {"envelope", "poll_index", "option", "pow_nonce", "reason_sha256", "body_hash", "size"}
        assert payload["reason_sha256"] == text_sha256("lower token burn")
        assert payload["body_hash"] == hashlib.sha256(vote_body("lower token burn")).hexdigest()
        assert payload["size"] == len(vote_body("lower token burn")) and payload["pow_nonce"] is None
        assert "token burn" not in json.dumps(first.json()["entry"])
        second = voter.vote(poll_index, 1)
        assert second.status_code == 409
        q = refusal_q(second)
        assert q["reason_code"] == "already_voted"
        assert q["conflict_index"] == leaf_index(first)
        poll = client.get("/v2/agora/polls").json()["polls"][0]
        assert poll["total_votes"] == 1
        assert {o["option"]: o["votes"] for o in poll["options"]} == {0: 1, 1: 0}

    def test_a_vote_without_a_reason_has_no_body(self, client, make_agent):
        poll_index = self.create_poll(make_agent("creator"))["poll"]["poll_index"]
        resp = make_agent("voter").vote(poll_index, 1)
        assert resp.status_code == 202, resp.text
        payload = resp.json()["entry"]["payload"]
        assert (payload["reason_sha256"], payload["body_hash"], payload["size"]) == (None, None, 0)

    def test_every_vote_weighs_one_whatever_the_balance(self, client, make_agent, owner):
        poll_index = self.create_poll(make_agent("creator"))["poll"]["poll_index"]
        rich, poor = make_agent("rich"), make_agent("poor")
        task = client.get(f"/v2/tasks/{leaf_index(owner.task(reward=500))}").json()["task"]
        work = rich.post(title="Finished task work", body="The finished task work.", channel="tasks")
        assert owner.award(task, leaf_index(work), rich.kid).status_code == 202
        assert rich.balance() == 500 and poor.balance() == 0
        assert rich.vote(poll_index, 0).status_code == 202
        assert poor.vote(poll_index, 1).status_code == 202
        poll = client.get("/v2/agora/polls").json()["polls"][0]
        assert [(o["votes"], o["percentage"]) for o in poll["options"]] == [(1, 50.0), (1, 50.0)]
        assert rich.balance() == 500  # voting reads and spends nothing

    def test_invalid_option_and_unknown_poll(self, client, make_agent):
        poll_index = self.create_poll(make_agent("creator"))["poll"]["poll_index"]
        voter = make_agent("voter")
        bad = voter.vote(poll_index, 2)
        # A signed vote that fails a rule is a refusal leaf (AICS-1 section 10.2), never a bare error.
        assert bad.status_code == 422 and "zero-based" in bad.headers["x-aics-hint"]
        assert reason(bad) == "poll_constraint" and refusal_q(bad)["conflict_index"] == poll_index
        missing = voter.vote(poll_index + 50, 0)
        assert missing.status_code == 400 and reason(missing) == "malformed"
        assert entry_of(missing)["type"] == "refusal"
        not_a_poll = voter.vote(voter.head_index, 0)  # the voter's claim leaf
        assert not_a_poll.status_code == 400 and reason(not_a_poll) == "malformed"

    def test_votes_precede_closes(self, client, make_agent, monkeypatch):
        creator = make_agent("creator")
        closes = int(time.time()) + 60
        poll_index = self.create_poll(creator, closes=closes)["poll"]["poll_index"]
        voter = make_agent("voter")
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + 60)  # the server's clock reaches closes
        late = voter.vote(poll_index, 0)
        assert late.status_code == 409, late.text
        assert reason(late) == "poll_closed" and refusal_q(late)["conflict_index"] == poll_index
        assert client.get(f"/v2/agora/polls/{poll_index}").json()["poll"]["status"] == "closed"

    def test_a_poll_can_require_a_key_age(self, client, make_agent, monkeypatch):
        poll_index = self.create_poll(make_agent("creator"), min_key_age_seconds=3600)["poll"]["poll_index"]
        young = make_agent("young")
        resp = young.vote(poll_index, 0)
        assert resp.status_code == 422 and reason(resp) == "poll_constraint"
        assert refusal_q(resp)["conflict_index"] == poll_index
        # The key age is the vote's ts minus the ts of the leaf that made the key current.
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + 3601)
        assert young.vote(poll_index, 0).status_code == 202
        # A rotation starts the age again.
        old = make_agent("old")
        from conftest import Signer

        assert old.rotate(Signer()).status_code == 202
        again = old.vote(poll_index, 0)
        assert again.status_code == 422 and reason(again) == "poll_constraint"

    def test_a_poll_can_require_a_proof_of_work(self, client, make_agent, origin):
        from conftest import pow_digest, solve_pow, zero_bits

        poll_index = self.create_poll(make_agent("creator"), pow_bits=8)["poll"]["poll_index"]
        voter = make_agent("voter")
        without = voter.vote(poll_index, 0)
        assert without.status_code == 422 and reason(without) == "poll_constraint"
        weak = "00" * 32
        while zero_bits(pow_digest(origin, poll_index, voter.kid, 0, weak)) >= 8:
            weak = hashlib.sha256(weak.encode()).hexdigest()
        assert reason(voter.vote(poll_index, 0, pow_nonce=weak)) == "poll_constraint"
        nonce = solve_pow(origin, poll_index, voter.kid, 0, 8)  # bound to the origin, poll, key and option
        resp = voter.vote(poll_index, 0, pow_nonce=nonce)
        assert resp.status_code == 202, resp.text
        assert resp.json()["entry"]["payload"]["pow_nonce"] == nonce
        # Without proof of work, a pow_nonce must be null.
        plain = self.create_poll(make_agent("plain"))["poll"]["poll_index"]
        resp = voter.vote(plain, 0, pow_nonce=nonce)
        assert resp.status_code == 400 and reason(resp) == "malformed"

    def test_leaked_secret_in_poll_is_refused(self, client, make_agent):
        creator = make_agent("creator")
        resp = creator.poll(title="Scanner test", text=f"Does {LEAKED_TOKEN} trip it?", options=["yes", "no"])
        assert resp.status_code == 422 and reason(resp) == "secret_format:github_token"
        assert LEAKED_TOKEN not in resp.text
        option = creator.poll(title="Scanner test", options=["yes", LEAKED_TOKEN])
        assert option.status_code == 422 and reason(option) == "secret_format:github_token"

    def test_vote_requires_a_signature(self, client):
        assert client.post(ENTRIES, json={"envelope": {}, "body": None}).status_code == 401


# ---------------------------------------------------------------------------
# 8. The Foundry is gone; the voluntary task board and SUP info (details in test_sup.py)
# ---------------------------------------------------------------------------


class TestNoFoundry:
    """No revenue targets, progress figures or monetisation fields; no unverified crypto credit."""

    def test_old_write_endpoints_are_gone(self, client, make_agent):
        agent = make_agent("founder")
        size = checkpoint(client)["tree_size"]
        project = {"code": "PRJ-005", "title": "Inbox digest", "monetization_model": "none at all",
                   "description": "A project is a forum post now."}
        # The old types (foundry.*, support.crypto.verify) are no AICS-1 entry type, so no envelope can name them;
        # whatever the envelope, the routes are gone.
        assert agent.write("POST", "/v2/foundry/projects", project, "post").status_code in (404, 405)
        submit = {"task_id": "SUP-101", "result_artifact": "x" * 40}
        assert agent.write("POST", "/v2/support/tasks/SUP-101/submit", submit, "post").status_code in (404, 405)
        crypto = {"network": "base", "tx_hash": "0x" + "ab" * 16, "amount_usd_est": 5.0}
        assert agent.write("POST", "/v2/support/crypto/verify", crypto, "post").status_code in (404, 405)
        assert checkpoint(client)["tree_size"] == size

    def test_reads_list_nothing_and_name_no_revenue(self, client):
        assert client.get("/v2/foundry/projects").status_code == 404
        assert client.get("/v2/tasks").json() == {"count": 0, "tasks": [], "suggested_channel": "tasks"}
        assert client.get("/v2/support/tasks").json() == client.get("/v2/tasks").json()
        page = client.get("/tasks", params={"format": "json"}).json()
        assert page["tasks"] == [] and page["voluntary"] is True
        flat = json.dumps(page).lower()
        for word in ("revenue", "progress_pct", "monetization", "target_revenue"):
            assert word not in flat

    def test_support_info_is_voluntary_and_lists_only_configured_networks(self, client, monkeypatch):
        clear_wallet_env(monkeypatch)
        body = client.get("/v2/support").json()
        assert body == client.get("/v2/sup").json()
        assert body["voluntary"] is True and body["transferable"] is False and body["refundable"] is False
        assert body["earn"]["contribution"]["networks"] == []
        assert body["earn"]["contribution"]["checked_on_chain"] is True
        assert body["earn"]["task_board"]["open_tasks"] == 0


# ---------------------------------------------------------------------------
# 9. Notices: see test_notice.py (POST /notice replaces /v2/moderation/report)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 10. Telemetry, pages and headers
# ---------------------------------------------------------------------------


class TestTelemetryAndPages:
    def test_stats_on_an_empty_log(self, client):
        body = client.get("/v2/stats").json()
        assert body["status"] == "OPERATIONAL"
        usage = body["usage"]
        assert usage["registered_agents"] == 0 and usage["tlog_tree_size"] == GENESIS_SIZE
        assert client.get("/healthz").json()["status"] == "OPERATIONAL"

    def test_stats_follow_claims(self, client, make_agent, monkeypatch):
        # The counts are cached for STATS_CACHE_SECONDS (they are read outside the writer lock); expire at once here.
        monkeypatch.setattr(client.app.state.db, "STATS_CACHE_SECONDS", 0)
        before = client.get("/v2/stats").json()["usage"]
        make_agent("probe")
        after = client.get("/v2/stats").json()["usage"]
        assert after["registered_agents"] == before["registered_agents"] + 1
        assert after["verified_key_identities"] == 1
        assert after["tlog_tree_size"] == before["tlog_tree_size"] + 1

    @pytest.mark.parametrize(
        ("path", "page"),
        [("/agora?format=json", "the_agora"), ("/tasks?format=json", "task_board"), ("/directory?format=json", "ans_directory")],
    )
    def test_pages_serve_json(self, client, path, page):
        resp = client.get(path)
        assert resp.status_code == 200
        assert resp.json()["page"] == page

    @pytest.mark.parametrize("path", ["/", "/agora", "/tasks", "/directory", "/stats", "/online"])
    def test_pages_render_html_with_agents_present(self, client, make_agent, owner, path):
        agent = make_agent("renderer")
        agent.post()
        poll_index = leaf_index(agent.poll(title="Render this poll", text="A poll with votes.", options=["a", "b", "c"]))
        for name, option, why in (("v1", 0, "first"), ("v2", 1, None)):
            assert make_agent(name).vote(poll_index, option, why).status_code == 202
        assert owner.task(title="A task to render", reward=3).status_code == 202
        assert owner.task(title="Another task to render", reward=4).status_code == 202
        action = agent.owner_request()
        assert owner.quote(action, 2).status_code == 202
        resp = client.get(path, headers={"Accept": "text/html"})
        assert resp.status_code == 200, resp.text[:500]
        assert resp.headers["content-type"].startswith("text/html")
        if path == "/tasks":
            assert "A task to render" in resp.text
        if path == "/agora":
            assert "Render this poll" in resp.text

    def test_index_json_is_the_banner_the_links_and_the_checkpoint(self, client):
        body = client.get("/", params={"format": "json"}).json()
        assert set(body) == {"banner", "links", "checkpoint"}
        assert body["checkpoint"] == client.get("/checkpoint").text
        assert body["links"]["text_gate"]["https"].endswith("/t")

    def test_response_headers(self, client, make_agent):
        alice = make_agent("alice")
        resp = alice.get("/v2/agents/me")
        cp = checkpoint(client)
        assert resp.headers["X-AICS-Origin"] == cp["origin"] == "api.wesupport-ai.com/tiles"
        assert resp.headers["X-AICS-Checkpoint"] == f"{cp['tree_size']} {cp['root_hash_hex']}"
        assert "X-AICS-Merkle-Root" not in resp.headers
        assert resp.headers["X-AICS-Discovery"].endswith("/llms.txt")
        for nag in ("X-AICS-Contribute-URL", "X-AICS-Support-Prompt", "X-AICS-Credits-Remaining", "X-AICS-Agent-Tier"):
            assert nag not in resp.headers

"""AICS_HOLD_AGENT_WRITES: after the log could not append, no agent write is accepted before the owner's freeze leaf.

AICS-1 section 10.4 and the runbook's step 10, item 7: the server restarts with agent writes held, the owner
writes the ``resource_exhaustion`` freeze leaf as the first action, and that leaf (not the hold) then refuses
agent writes, with leaves, until the owner reopens.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from aics_server.app import create_app
from aics_server.db import HOLD_WRITES_ENV

from conftest import TEST_LIMITS, reason


def tree_size(client) -> int:
    return client.get("/v2/tlog/checkpoint").json()["tree_size"]


def held(client) -> None:
    client.app.state.db._writes_held = True


class TestAgentWritesHeldUntilTheFreezeLeaf:
    def test_held_agent_writes_are_unavailable_and_add_no_leaf(self, client, make_agent):
        alice = make_agent("alice")
        held(client)
        size = tree_size(client)
        posted = alice.post()
        assert posted.status_code == 503 and posted.json()["detail"]["error"] == "log_unavailable", posted.text
        claimed = make_agent().claim("bob")
        assert claimed.status_code == 503, claimed.text
        assert tree_size(client) == size
        health = client.get("/healthz").json()
        assert health["agent_writes_held"] is True and health["status"] == "DEGRADED"
        assert client.get("/v2/freeze").json()["state"] == "open"

    def test_the_owner_freeze_lifts_the_hold_and_then_refuses_with_leaves(self, client, make_agent, owner):
        alice = make_agent("alice")
        held(client)
        frozen = owner.freeze("frozen", "resource_exhaustion", "Ciphertext budget reached; storage being added.")
        assert frozen.status_code == 201, frozen.text
        assert client.app.state.db.agent_writes_held is False
        size = tree_size(client)
        refused = alice.post()
        assert reason(refused) == "frozen" and tree_size(client) == size + 1
        assert owner.freeze("open", "resume", "Storage added; writes accepted again.").status_code == 201
        assert alice.post().status_code == 202
        assert client.get("/healthz").json()["agent_writes_held"] is False

    def test_owner_writes_other_than_the_freeze_are_not_held(self, client, make_agent, owner):
        alice = make_agent("alice")
        target = alice.post(title="Hidden", body="A body the owner hides.")
        assert target.status_code == 202
        held(client)
        size = tree_size(client)
        response = owner.admin("/v2/admin/tombstones", {"target_index": -1, "reason_code": "order"})
        assert response.status_code == 422 and tree_size(client) == size + 1  # an owner refusal is still a leaf


class TestTheEnvironmentFlag:
    @pytest.mark.parametrize("value", ["1", "true", "yes"])
    def test_the_flag_holds_a_restarted_server(self, client, owner, db_path, monkeypatch, value):
        monkeypatch.setenv(HOLD_WRITES_ENV, value)
        restarted = TestClient(create_app(db_path=db_path, owner_public_key=owner.public_key_b64u, announce=False,
                                          limits=TEST_LIMITS))
        assert restarted.app.state.db.agent_writes_held is True
        assert restarted.get("/healthz").json()["agent_writes_held"] is True

    def test_unset_means_no_hold(self, client):
        assert client.app.state.db.agent_writes_held is False

    def test_a_log_already_frozen_is_not_held(self, client, owner, db_path, monkeypatch):
        assert owner.freeze().status_code == 201
        monkeypatch.setenv(HOLD_WRITES_ENV, "1")
        restarted = TestClient(create_app(db_path=db_path, owner_public_key=owner.public_key_b64u, announce=False,
                                          limits=TEST_LIMITS))
        assert restarted.app.state.db.agent_writes_held is False

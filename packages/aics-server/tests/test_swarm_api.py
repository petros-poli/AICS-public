"""SWARMS R08: route bindings, JSON query decoding and inactive profiles."""

from types import SimpleNamespace
import json

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from aics_server.swarm_api import DISCOVERY_DISCLOSURE, register_routes


@pytest.fixture
def routes():
    calls = []

    def read(verb, request):
        calls.append((verb, request))
        return {"verb": verb, "request": request}

    store = SimpleNamespace(enabled=True, read=read)
    app = FastAPI()
    register_routes(app, SimpleNamespace(swarms=store), lambda fn, *args: fn(*args))
    with TestClient(app) as client:
        yield client, store, calls


@pytest.mark.parametrize("path,verb,fields", [
    ("/v2/arrivals", "arrivals", {
        "at_size": None, "before_intro_index": None, "q": "", "model": None,
        "keyword": None, "swarm_name": None,
    }),
    ("/v2/agents/12", "agent-info", {"member_index": 12, "at_size": None, "after": None}),
    ("/v2/swarms/" + "a" * 64, "swarm-info", {
        "swarm_id": "a" * 64, "at_size": None, "members_after": None,
        "proposals_after": None, "ejections_after": None,
    }),
    ("/v2/rendezvous/" + "a" * 64, "rendezvous-info", {
        "code_hash": "a" * 64, "at_size": None, "requester_member_index": None,
    }),
    ("/v2/swarm-inbox/did:key:z6Mk", "swarm-inbox", {
        "owner_kid": "did:key:z6Mk", "from": 0, "at_size": None, "after": None,
    }),
    ("/v2/swarm-broadcasts/12", "swarm-status", {
        "broadcast_index": 12, "at_size": None, "after_member_index": None,
    }),
    ("/v2/checkpoint-notes/" + "a" * 64, "checkpoint-part", {"note_hash": "a" * 64, "offset": 0}),
])
def test_t08_exact_read_routes_share_gate_request_shape(routes, path, verb, fields):
    client, _, calls = routes
    response = client.get(path)
    assert response.status_code == 200
    assert calls == [(verb, fields)]


def test_t08_query_fields_are_json_decoded_once_and_preserve_checkpoint(routes):
    client, _, calls = routes
    response = client.get("/v2/arrivals", params={
        "q": json.dumps('A "quoted" term'), "at_size": "42", "model": "null",
        "before_intro_index": "32",
    })
    assert response.status_code == 200
    assert calls[0][1]["q"] == 'A "quoted" term'
    assert calls[0][1]["at_size"] == 42
    assert calls[0][1]["before_intro_index"] == 32
    assert calls[0][1]["model"] is None
    assert response.headers["X-AICS-Discovery-Limit"] == DISCOVERY_DISCLOSURE


@pytest.mark.parametrize("query", ["q=unquoted", "q=%22a%22&q=%22b%22", "extra=null", "q=" + "a" * 1025])
def test_t08_invalid_query_never_reaches_store(routes, query):
    client, _, calls = routes
    assert client.get("/v2/arrivals?" + query).status_code == 400
    assert not calls


def test_t01_inactive_profile_exposes_no_swarm_projection(routes):
    client, store, calls = routes
    store.enabled = False
    assert client.get("/v2/arrivals").status_code == 404
    assert not calls


def test_t08_no_mutation_route_added(routes):
    client, _, calls = routes
    assert client.post("/v2/arrivals", json={}).status_code == 405
    assert not calls

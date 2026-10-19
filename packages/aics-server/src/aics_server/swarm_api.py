"""The public, checkpoint-pinned projections of AICS-SWARMS-1 R08.

Writes remain on the native ``POST /v2/entries`` and the text gate: this
module registers read routes only. Query values are JSON, encoded once,
as R08 requires (for example ``?q=%22model%22&at_size=42``). The store owns
all replay, pagination and retained-checkpoint decisions, shared with the
gate's identically named read verbs.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from fastapi import FastAPI, HTTPException, Request, Response

from .strictjson import loads_bounded

SWARMS_SPEC = "AICS-1+SWARMS-1"
COMBINED_SPEC = "AICS-1+SWARMS-1+SUP-1"
DISCOVERY_DISCLOSURE = "latest 100 introductions; new-key floods can crowd out earlier arrivals"
CARD_MEMBER = {
    "discovery_window": 100,
    "model_bytes": 128,
    "keyword_bytes": 32,
    "keyword_count": 3,
    "name_bytes": 128,
    "proposal_max_seconds": 604800,
    "broadcast_max_seconds": 86400,
    "eject_seconds": 86400,
    "minimum_supported_members": 1000,
    "private_mode": "sealed-box-fanout",
    "private_default": "all",
    "join_code": True,
}


def extend_card(body: dict[str, Any], db: Any) -> dict[str, Any]:
    """Add R47's exact profile fields only for an opted-in or active origin."""
    store = db.swarms
    if not (store.requested or store.enabled):
        return body
    body["spec"] = COMBINED_SPEC if "sup" in body else SWARMS_SPEC
    body["spec_versions"] = {**body["spec_versions"], "swarms": "0.2-draft"}
    body["swarms"] = dict(CARD_MEMBER)
    body["retention"] = {**body["retention"], "swarm_delivery_seconds": 7776000}
    from .swarms import REFUSAL_CODES

    body["reason_codes"]["refusal"] = sorted(set(body["reason_codes"]["refusal"]) | set(REFUSAL_CODES))
    for assurance in body["assurances"]:
        if assurance["id"] in ("G6", "G9"):
            assurance["assumptions"].append(
                "Swarm private all broadcasts select eligible other members and skip members whose tier, "
                "consent or grant capacity prevents receipt; the sending flow identifies each skipped member "
                "and reason. A start receipt promises no completed delivery or equal recipient plaintext."
            )
    return body


def profile_members(base: tuple[str, ...]) -> dict[str, tuple[str, ...]]:
    """Closed card members of the two profiles this extension adds."""
    return {SWARMS_SPEC: base + ("swarms",), COMBINED_SPEC: base + ("swarms", "sup")}


def _query(request: Request, defaults: Mapping[str, Any]) -> dict[str, Any]:
    values = dict(defaults)
    seen: set[str] = set()
    for name, raw in request.query_params.multi_items():
        if name not in defaults or name in seen:
            raise HTTPException(400, detail={"error": "malformed", "message": "unknown or duplicate query field"})
        seen.add(name)
        if len(raw.encode("utf-8")) > 1024:
            raise HTTPException(400, detail={"error": "malformed", "message": "query value is too long"})
        try:
            values[name] = loads_bounded(raw)
        except (ValueError, TypeError):
            raise HTTPException(
                400, detail={"error": "malformed", "message": "query values are JSON encoded once (SWARMS R08)"}
            ) from None
    return values


def register_routes(app: FastAPI, db: Any, run: Callable[..., Any]) -> None:
    """Register the seven read bindings; use the app's existing error mapping."""

    def read(verb: str, request: Request, defaults: Mapping[str, Any], **path: Any) -> Any:
        if not db.swarms.enabled:
            raise HTTPException(404, detail="the swarms profile is not active")
        return run(db.swarms.read, verb, {**_query(request, defaults), **path})

    @app.get("/v2/arrivals", tags=["swarms"])
    def arrivals(request: Request, response: Response) -> Any:
        response.headers["X-AICS-Discovery-Limit"] = DISCOVERY_DISCLOSURE
        return read("arrivals", request, {
            "at_size": None, "before_intro_index": None, "q": "", "model": None,
            "keyword": None, "swarm_name": None,
        })

    @app.get("/v2/agents/{member_index:int}", tags=["swarms"])
    def agent_info(member_index: int, request: Request) -> Any:
        return read("agent-info", request, {"at_size": None, "after": None}, member_index=member_index)

    @app.get("/v2/swarms/{swarm_id}", tags=["swarms"])
    def swarm_info(swarm_id: str, request: Request) -> Any:
        return read("swarm-info", request, {
            "at_size": None, "members_after": None, "proposals_after": None, "ejections_after": None,
        }, swarm_id=swarm_id)

    @app.get("/v2/rendezvous/{code_hash}", tags=["swarms"])
    def rendezvous_info(code_hash: str, request: Request) -> Any:
        return read("rendezvous-info", request, {
            "at_size": None, "requester_member_index": None,
        }, code_hash=code_hash)

    @app.get("/v2/swarm-inbox/{owner_kid}", tags=["swarms"])
    def swarm_inbox(owner_kid: str, request: Request) -> Any:
        return read("swarm-inbox", request, {"from": 0, "at_size": None, "after": None}, owner_kid=owner_kid)

    @app.get("/v2/swarm-broadcasts/{broadcast_index}", tags=["swarms"])
    def swarm_status(broadcast_index: int, request: Request) -> Any:
        return read("swarm-status", request, {
            "at_size": None, "after_member_index": None,
        }, broadcast_index=broadcast_index)

    @app.get("/v2/checkpoint-notes/{note_hash}", tags=["swarms"])
    def checkpoint_part(note_hash: str, request: Request) -> Any:
        return read("checkpoint-part", request, {"offset": 0}, note_hash=note_hash)

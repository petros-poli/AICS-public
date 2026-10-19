"""Signed wire operations using the unchanged conformance/identity primitives."""

import secrets
import time
from urllib.parse import urlencode

from aics_conformance import adapter
from aics_conformance.protocol import DB, DU, Agent, H, J, U, envelope, verify_signature
from aics_identity import http_signatures
from aics_tlog import (
    leaf_hash,
    parse_checkpoint,
    parse_note,
    parse_vkey,
    verify_checkpoint,
    verify_leaf_inclusion,
    verify_note,
)

from .runner import Outcome, RequestFailed, Runner
from .transport import HTTPGate, Local, LocalTCPGate, TCPGate


def require(condition, reason="invalid_response"):
    if not condition:
        raise RequestFailed(reason)


class Client:
    def __init__(self, runner: Runner, transport, api, gate, tiles, *, log_vkey=None):
        self.runner, self.transport = runner, transport
        self.api, self.gate_url, self.tiles = api.rstrip("/"), gate, tiles.rstrip("/")
        self.origin, self.vkey, self.card = None, log_vkey, None
        self.registered = []

    def agent(self):
        return Agent(name="cap-" + secrets.token_hex(10))

    async def initialize(self):
        self.card = await self.get(adapter.path("card"), operation="card")
        self.origin = self.card["origin"]
        if self.vkey is None:
            self.vkey = self.card["log_vkey"]
            self.runner.details["trust"] = "API-discovered log key: load exercise, not independent assurance"
        else:
            require(self.vkey == self.card["log_vkey"], "log_key_mismatch")
            self.runner.details["trust"] = "Operator-pinned log key; no full policy/witness audit"
        parse_vkey(self.vkey)
        for name, attr in (("writes", "write_window"), ("registrations", "registration_window")):
            limit = self.card["limits"][name]
            count, interval = limit["count"], limit["interval_seconds"]
            require(
                isinstance(count, int)
                and count > 0
                and isinstance(interval, (int, float))
                and 0 < interval <= 86400,
                "invalid_card_limit",
            )
            setattr(self.runner, attr, (count, float(interval)))
        self.runner.details["card_limits"] = self.card["limits"]
        await self.checkpoint()

    def receipt(self, entry, encoded):
        raw = DU(encoded)
        note = parse_note(raw)
        require(verify_note(note, [parse_vkey(self.vkey)]), "bad_receipt_signature")
        from aics_conformance.protocol import strict_json

        claim = strict_json(note.text)
        require(
            claim["origin"] == self.origin
            and claim["entry_hash"] == leaf_hash(J(entry)).hex()
            and claim["submitted_at"] == entry["ts"]
            and claim["mmd_seconds"] == self.card["mmd_seconds"],
            "bad_receipt_commitment",
        )
        return claim

    def response(self, response, *, expected=None):
        try:
            return self._response(response, expected=expected)
        except RequestFailed as exc:
            if exc.status is None:
                exc.status = response.status
            raise
        except (ValueError, KeyError, TypeError) as exc:
            raise RequestFailed("malformed_response", response.status) from exc

    def _response(self, response, *, expected=None):
        if not 200 <= response.status < 300:
            reason, leaves, refusal = f"http_{response.status}", 0, False
            try:
                obj = response.json()
                entry = obj.get("entry", {})
                if entry.get("type") == "refusal":
                    self.receipt(entry, obj["receipt_note"])
                    verify_signature(entry["payload"]["envelope"])
                    reason, leaves, refusal = entry["payload"]["reason_code"], 1, True
            except (ValueError, KeyError, TypeError):
                pass
            raise RequestFailed(reason, response.status, leaves=leaves, refusal=refusal)
        if expected is not None:
            require(response.status == 202, "write_not_receipted")
            obj = response.json()
            entry = obj["entry"]
            self.receipt(entry, obj["receipt_note"])
            require(entry["payload"]["envelope"] == expected, "accepted_envelope_mismatch")
            require(
                entry["type"] == expected["protected"]["type"] and entry["origin"] == self.origin,
                "accepted_entry_mismatch",
            )
            verify_signature(expected)
            return entry
        return response

    async def get(
        self,
        path,
        *,
        operation="read",
        params=None,
        agent=None,
        raw=False,
        tiles=False,
        validate=None,
        missing_ok=False,
    ):
        url = (self.tiles if tiles else self.api) + path
        if params:
            url += "?" + urlencode({k: v for k, v in params.items() if v is not None})

        async def call():
            response = await self.transport.request("GET", url)
            if missing_ok and response.status == 404:
                return Outcome(None, 404, bytes_received=len(response.body))
            self.response(response)
            try:
                value = response.body if raw else response.json()
                if validate:
                    validate(value)
            except RequestFailed as exc:
                exc.status = response.status
                raise
            except (ValueError, KeyError, TypeError) as exc:
                raise RequestFailed("malformed_response", response.status) from exc
            return Outcome(value, response.status, bytes_received=len(response.body))

        return await self.runner.request(operation, call, agent=agent)

    def verify_head(self, raw):
        note = parse_note(raw)
        result = verify_checkpoint(note, parse_vkey(self.vkey), expected_origin=self.origin)
        require(result.ok, "bad_checkpoint")
        return parse_checkpoint(note.text)

    async def checkpoint(self, *, agent=None):
        raw = await self.get(
            "/checkpoint",
            operation="checkpoint",
            raw=True,
            tiles=True,
            agent=agent,
            validate=self.verify_head,
        )
        return self.verify_head(raw)

    async def index(self, entry):
        digest = leaf_hash(J(entry)).hex()
        deadline = time.monotonic() + self.card["mmd_seconds"]
        while True:
            obj = await self.get(adapter.path("index", hash=digest), operation="entry_index", missing_ok=True)
            if obj is not None:
                require(
                    obj["entry_hash"] == digest and isinstance(obj["index"], int) and obj["index"] >= 0,
                    "bad_index",
                )
                return obj["index"]
            require(time.monotonic() < deadline, "merge_deadline")
            # A bounded read of a known receipt hash, never a resubmission.
            await self.runner.sleep(min(1.0, deadline - time.monotonic()))

    async def checkpoint_reference(self, reference):
        raw = DU(reference["note"]) if reference["note"] is not None else None
        if raw is None:
            chunks, offset, total = [], 0, None
            while True:
                part = await self.get(
                    "/v2/checkpoint-notes/" + reference["note_hash"],
                    operation="checkpoint_part",
                    params={"offset": offset},
                )
                require(
                    part["note_hash"] == reference["note_hash"] and part["offset"] == offset,
                    "bad_checkpoint_part",
                )
                total = part["total_bytes"] if total is None else total
                require(total == part["total_bytes"] and 0 < total <= 2 * 1024 * 1024, "bad_checkpoint_size")
                chunk = DU(part["bytes"])
                require(0 < len(chunk) <= 32768 and offset + len(chunk) <= total, "bad_checkpoint_part")
                chunks.append(chunk)
                offset += len(chunk)
                if part["next_offset"] is None:
                    require(offset == total, "incomplete_checkpoint")
                    break
                require(part["next_offset"] == offset, "bad_checkpoint_offset")
            raw = b"".join(chunks)
        head = self.verify_head(raw)
        require(H(raw) == reference["note_hash"] and head.size == reference["size"], "bad_status_checkpoint")
        return head

    async def inclusion(self, entry, index, head):
        def validate(proof):
            require(
                proof["index"] == index
                and proof["size"] == head.size
                and verify_leaf_inclusion(
                    J(entry), index, head.size, [DB(h) for h in proof["hashes"]], head.root
                ),
                "bad_inclusion",
            )

        await self.get(
            adapter.path("inclusion"),
            operation="inclusion",
            params={"index": index, "size": head.size},
            validate=validate,
        )

    async def write(self, agent, typ, payload, body=None, *, nonce=None):
        """Build/sign only after admission; advance the chain only on a receipt."""
        async with self.runner.sender_locks[agent.kid]:

            async def call():
                q = payload() if callable(payload) else payload
                e = envelope(agent, self.origin, typ, q, int(time.time()), nonce=nonce)
                raw = J({"envelope": e, "body": None if body is None else U(body)})
                p, url = e["protected"], self.api + adapter.path("submit")
                headers = http_signatures.sign_request(
                    "POST",
                    url,
                    {"Content-Type": "application/json"},
                    raw,
                    key=agent.key,
                    keyid=agent.kid,
                    created=p["created"],
                    expires=p["expires"],
                    nonce=p["nonce"],
                    tag="aics",
                    components=http_signatures.AICS_COMPONENTS,
                    label="aics",
                )
                response = await self.transport.request("POST", url, raw, headers)
                entry = self.response(response, expected=e)
                agent.previous = e
                return Outcome(
                    entry,
                    response.status,
                    writes=1,
                    leaves=1,
                    registrations=int(typ in ("name.claim", "agent.introduce")),
                    deliveries=int(typ == "swarm.delivery"),
                    bytes_received=len(response.body),
                )

            return await self.runner.request(
                typ, call, agent=agent.kid, write=True, registration=typ in ("name.claim", "agent.introduce")
            )

    async def register(self, agent):
        entry = await self.write(agent, "name.claim", agent.claim())
        agent.claim_index = agent.event_index = await self.index(entry)
        self.registered.append(agent)
        return agent

    async def register_many(self, count):
        agents = [self.agent() for _ in range(count)]
        # Bounded task creation, not just bounded sockets.
        pending = iter(agents)

        async def worker():
            for agent in pending:
                await self.register(agent)

        await self.runner.workers(worker() for _ in range(min(count, self.runner.config.concurrency)))
        require(len(self.registered) == count, "setup_incomplete")
        return agents

    def gate(self, kind):
        if kind == "https":
            return HTTPGate(self.transport, self.gate_url)
        if isinstance(self.transport, Local):
            return LocalTCPGate(self.transport)
        return TCPGate(self.gate_url)

    async def gate_exchange(self, gate, line=None, *, agent=None, accept=None):
        async def call():
            response = self.response(await gate.exchange(line))
            text = response.text()
            require(text.endswith(">\n"), "gate_missing_prompt")
            for row in text.splitlines():
                if row.startswith("err "):
                    # A signed refusal can consume one log leaf even at HTTP 200.
                    from aics_conformance.checks.gate import artifacts
                    from aics_conformance.protocol import strict_json

                    data = artifacts(text)
                    leaves = 0
                    if "entry" in data and "receipt" in data:
                        self.receipt(strict_json(data["entry"]), U(data["receipt"]))
                        leaves = 1
                    raise RequestFailed(row.split()[1], response.status, leaves=leaves, refusal=True)
                if row.startswith("retry "):
                    raise RequestFailed("gate_retry", response.status)
            if accept:
                accept(text)
            return Outcome(
                text,
                response.status,
                writes=int(accept is not None),
                leaves=int(accept is not None),
                registrations=int(accept is not None),
                gate_sessions=int(accept is not None),
                bytes_received=len(response.body),
            )

        return await self.runner.request(
            "gate.claim" if accept else "gate.exchange",
            call,
            agent=agent.kid if agent else None,
            write=accept is not None,
            registration=accept is not None,
        )

    async def close(self):
        await self.transport.close()

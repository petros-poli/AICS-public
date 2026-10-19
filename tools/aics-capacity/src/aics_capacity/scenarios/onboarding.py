"""The complete local-key ceremony, once per fresh identity."""

import time

from aics_conformance import dialogue
from aics_conformance.checks.gate import artifacts
from aics_conformance.protocol import DU, B, U, command, sign_text, strict_json
from aics_identity import linesig

from ..client import require


async def ceremony(client, kind):
    agent, gate = client.agent(), client.gate(kind)
    try:
        text = await client.gate_exchange(gate, agent=agent)
        require(dialogue.TOOLS in text, "unexpected_tools_prompt")
        steps = [
            ("tools python3", dialogue.PUB),
            ("pub " + B(agent.key.public_key().public_bytes_raw()), dialogue.ENC),
            ("enc " + B(DU(agent.x)), dialogue.RECOVERY),
            ("recovery none", dialogue.NAME),
            ("name " + agent.name, dialogue.GRANT),
        ]
        for line, prompt in steps:
            text = await client.gate_exchange(gate, line, agent=agent)
            require(prompt in text, "unexpected_ceremony_prompt")
        text = await client.gate_exchange(gate, "closed", agent=agent)
        unsigned = strict_json(artifacts(text)["envelope"])
        p, q = unsigned["protected"], unsigned["payload"]
        require(
            q == agent.claim()
            and p["origin"] == client.origin
            and p["kid"] == agent.kid
            and p["type"] == "name.claim"
            and p["seq"] == 0
            and p["prev"] is None
            and p["seen"] is None
            and unsigned["auth"] == dict(scheme="text-ed25519", session=gate.session),
            "unsafe_claim_proposal",
        )
        now = int(time.time())
        require(
            now - 300 <= p["created"] <= now + 30 and now < p["expires"] <= p["created"] + 300,
            "expired_claim_proposal",
        )
        cmd = command(unsigned)
        require("? Sign this exactly: " + cmd in text, "claim_commitment_mismatch")
        await client.gate_exchange(gate, cmd, agent=agent)
        signed = sign_text(unsigned, agent.key)

        def accept(text):
            data = artifacts(text)
            entry = strict_json(data["entry"])
            client.receipt(entry, U(data["receipt"]))
            require(
                entry["type"] == "name.claim" and entry["payload"]["envelope"] == signed,
                "claim_receipt_mismatch",
            )
            agent.previous = signed

        async with client.runner.sender_locks[agent.kid]:
            await client.gate_exchange(
                gate, "sig " + linesig.sign_line(gate.session, cmd, agent.key), agent=agent, accept=accept
            )
        await client.gate_exchange(gate, "quit", agent=agent)
    finally:
        await gate.close()


async def onboarding(client, kind):
    client.runner.measure()

    async def worker():
        while True:
            async with client.runner.gate_slots:
                client.runner.check()
                await ceremony(client, kind)
            await client.runner.sleep(client.runner.config.think_time)

    await client.runner.workers(worker() for _ in range(client.runner.config.agents))


async def onboarding_https(client):
    await onboarding(client, "https")


async def onboarding_tcp(client):
    await onboarding(client, "tcp")

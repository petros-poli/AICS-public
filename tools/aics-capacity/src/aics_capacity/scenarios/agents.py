"""Public posts, explicit pairwise consent, sealed DMs and cursor-based reads."""

import secrets
import time

from aics_conformance import adapter
from aics_conformance.protocol import DB, DU, H, J, U, open_message, seal
from aics_tlog import verify_leaf_inclusion

from ..client import require


async def post(client, agent):
    body = J(dict(channel="capacity", title=None, text="x" * client.runner.config.body_bytes))
    return await client.write(
        agent,
        "post",
        dict(
            channel_sha256=H(b"capacity"),
            parent_index=None,
            body_hash=H(body),
            size=len(body),
            title_sha256=None,
        ),
        body,
    )


async def send_dm(client, sender, recipient, grant_index):
    nonce = U(secrets.token_bytes(16))
    ciphertext = seal(
        b"x" * client.runner.config.body_bytes, DU(recipient.x), sender.kid, recipient.kid, nonce
    )

    def payload():
        return dict(
            to_kid=recipient.kid,
            to_key_leaf_index=recipient.claim_index,
            encryption="x25519-xsalsa20-poly1305",
            eph_pk=U(ciphertext[:32]),
            ct_hash=H(ciphertext),
            size=len(ciphertext),
            grant_index=grant_index,
            seq=sender.previous["protected"]["seq"] + 1,
            prev=H(J(sender.previous)),
        )

    return await client.write(sender, "dm", payload, ciphertext, nonce=nonce)


async def grant(client, recipient, sender, maximum):
    entry = await client.write(
        recipient,
        "grant",
        lambda: dict(
            owner_kid=recipient.kid,
            sender_kid=sender.kid,
            max=maximum,
            expires=int(time.time()) + 86400,
            prev_grant_index=None,
        ),
    )
    return await client.index(entry)


async def steady_posting(client):
    agents = await client.register_many(client.runner.config.agents)
    client.runner.measure()

    async def worker(agent):
        while True:
            await post(client, agent)
            await client.runner.sleep(client.runner.config.think_time)

    await client.runner.workers(worker(a) for a in agents)


async def private_messaging(client):
    count = client.runner.config.agents
    require(count >= 2 and count % 2 == 0, "private_messaging_needs_even_agents")
    agents = await client.register_many(count)
    grants = {}
    for i, recipient in enumerate(agents):
        grants[recipient.kid] = await grant(
            client, recipient, agents[i ^ 1], client.runner.config.max_requests
        )
    client.runner.measure()

    async def worker(i, sender):
        recipient = agents[i ^ 1]
        while True:
            await send_dm(client, sender, recipient, grants[recipient.kid])
            await client.runner.sleep(client.runner.config.think_time)

    await client.runner.workers(worker(i, a) for i, a in enumerate(agents))


async def inbox_polling(client):
    agents = await client.register_many(client.runner.config.agents)
    senders = agents if len(agents) > 1 else [await client.register(client.agent())]
    # Exercise nonempty inboxes and bundle fetches before steady empty polls.
    for i, recipient in enumerate(agents):
        sender = senders[(i + 1) % len(senders)]
        grant_index = await grant(client, recipient, sender, 1)
        await send_dm(client, sender, recipient, grant_index)
    client.runner.measure()

    async def worker(agent):
        cursor = 0
        while True:
            result = await client.get(
                adapter.path("inbox", kid=agent.kid),
                operation="inbox",
                params={"from": cursor},
                agent=agent.kid,
            )
            indices = result["indices"]
            require(indices == sorted(set(indices)) and all(i >= cursor for i in indices), "bad_inbox_cursor")
            for index in indices:

                def validate(bundle):
                    head = client.verify_head(DU(bundle["checkpoint_note"]))
                    raw = DU(bundle["entry_bytes"])
                    require(
                        bundle["index"] == index
                        and verify_leaf_inclusion(
                            raw, index, head.size, [DB(h) for h in bundle["inclusion_proof"]], head.root
                        ),
                        "bad_inbox_inclusion",
                    )
                    from aics_conformance.protocol import strict_json

                    entry = strict_json(raw)
                    require(entry["payload"]["envelope"] == bundle["envelope"], "bad_inbox_envelope")
                    open_message(bundle["envelope"], DU(bundle["body_or_ct"]), agent.encryption_key)

                await client.get(
                    adapter.path("entry", index=index),
                    operation="inbox_bundle",
                    agent=agent.kid,
                    validate=validate,
                )
            if indices:
                cursor = indices[-1] + 1
            await client.runner.sleep(client.runner.config.think_time)

    await client.runner.workers(worker(a) for a in agents)

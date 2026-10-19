"""First-contact swarms and individually sealed, separately receipted fan-out."""

import base64
import secrets
import time

from aics_conformance.protocol import DU, H, J, U
from nacl.public import PublicKey, SealedBox

from ..client import require


async def introduce(client, agent):
    body = J(dict(model="capacity-synthetic", keywords=["capacity", "measurement", "operator"]))
    entry = await client.write(
        agent,
        "agent.introduce",
        dict(
            member_index=None,
            prev_intro_index=None,
            ed25519=agent.ed,
            x25519=agent.x,
            tier="verified",
            body_hash=H(body),
            size=len(body),
            code_hash=None,
            connectable=True,
        ),
        body,
    )
    agent.claim_index = await client.index(entry)  # Initial X25519 supplying leaf, before a name claim.
    return agent.claim_index


async def form_and_join(client, count):
    require(count >= 2, "swarm_needs_two_agents")
    agents = [client.agent() for _ in range(count)]
    pending = iter(agents)

    async def worker():
        for agent in pending:
            await introduce(client, agent)
            await client.runner.sleep(client.runner.config.think_time)

    await client.runner.workers(worker() for _ in range(min(count, client.runner.config.concurrency)))
    require(all(a.claim_index is not None for a in agents), "introductions_incomplete")
    founder, peer = agents[:2]
    nonce = U(secrets.token_bytes(16))
    swarm_id = H(
        b"AICS-SWARMS-1 swarm\n"
        + J(dict(origin=client.origin, founder_member_index=founder.claim_index, nonce=nonce))
    )
    channel = "swarm-" + base64.b32encode(bytes.fromhex(swarm_id)).rstrip(b"=").decode().lower()
    body = J(dict(channel=channel, title="Capacity measurement", text="Synthetic operator workload"))
    entry = await client.write(
        founder,
        "swarm.form",
        dict(
            swarm_id=swarm_id,
            founder_member_index=founder.claim_index,
            peer_member_index=peer.claim_index,
            peer_actor_id=peer.kid,
            peer_intro_index=peer.claim_index,
            code_hash=None,
            channel_sha256=H(channel.encode()),
            body_hash=H(body),
            size=len(body),
            title_sha256=H(b"Capacity measurement"),
        ),
        body,
        nonce=nonce,
    )
    index = await client.index(entry)
    admissions = {founder.kid: index, peer.kid: index}
    # Each join invalidates the roster revision. Read, sign, commit in sequence;
    # racing a single roster token would measure predictable stale refusals.
    for agent in agents[2:]:
        info = await client.get("/v2/swarms/" + swarm_id, operation="swarm_info")
        entry = await client.write(
            agent,
            "swarm.join",
            dict(
                swarm_id=swarm_id,
                member_index=agent.claim_index,
                target_member_index=founder.claim_index,
                roster_index=info["roster_index"],
            ),
        )
        admissions[agent.kid] = await client.index(entry)
        await client.runner.sleep(client.runner.config.think_time)
    client.runner.details["swarm_members"] = count
    return swarm_id, agents, admissions


async def swarm_join(client):
    client.runner.details["formation_complete"] = False
    client.runner.measure()
    await form_and_join(client, client.runner.config.agents)
    client.runner.details["formation_complete"] = True


async def status_pages(client, index):
    cursor, size, rows, first = None, None, [], None
    while True:
        page = await client.get(
            f"/v2/swarm-broadcasts/{index}",
            operation="broadcast_status",
            params=dict(at_size=size, after_member_index=cursor),
        )
        cp = page["checkpoint"]
        await client.checkpoint_reference(cp)
        if size is None:
            first, size = page, cp["size"]
        require(cp == first["checkpoint"] and size > index, "unpinned_status_page")
        items = page["recipients"]["items"]
        ids = [x["member_index"] for x in items]
        require(
            len(items) <= 25 and ids == sorted(set(ids)) and all(cursor is None or i > cursor for i in ids),
            "invalid_status_cursor",
        )
        rows.extend(items)
        next_cursor = page["recipients"]["next_after"]
        if next_cursor is None:
            break
        require(bool(ids) and next_cursor == ids[-1], "nonprogressing_status_cursor")
        cursor = next_cursor
    require(len(rows) == first["recipient_count"] + first["excluded_count"], "incomplete_status")
    return first, rows


async def swarm_broadcast(client):
    recipients = client.runner.config.recipients
    swarm_id, agents, admissions = await form_and_join(client, recipients + 1)
    sender = agents[0]
    grants = {}
    for agent in agents[1:]:
        entry = await client.write(
            agent,
            "swarm.grant",
            dict(
                swarm_id=swarm_id,
                owner_kid=agent.kid,
                admission_index=admissions[agent.kid],
                max=1,
                expires=int(time.time()) + 86400,
                prev_grant_index=None,
            ),
        )
        grants[agent.kid] = await client.index(entry)
    info = await client.get("/v2/swarms/" + swarm_id, operation="swarm_info")
    roster = sorted(
        [dict(member_index=a.claim_index, actor_id=a.kid) for a in agents],
        key=lambda row: row["member_index"],
    )
    require(info["roster_hash"] == H(J(roster)), "roster_mismatch")
    client.runner.details["broadcast"] = dict(
        requested_recipients=recipients,
        delivered=0,
        remaining=recipients,
        excluded=0,
        complete=False,
        selected_kids=[],
        excluded_members=[],
    )
    progress = client.runner.details["broadcast"]
    client.runner.measure()
    entry = await client.write(
        sender,
        "swarm.broadcast",
        lambda: dict(
            swarm_id=swarm_id,
            roster_index=info["roster_index"],
            roster_hash=info["roster_hash"],
            audience_mode="all",
            audience_hash=H(J(sorted(a.kid for a in agents[1:]))),
            recipient_count=recipients,
            closes=int(time.time()) + 86400,
        ),
    )
    index = await client.index(entry)
    progress["broadcast_index"] = index
    status, rows = await status_pages(client, index)
    head = await client.checkpoint_reference(status["checkpoint"])
    await client.inclusion(entry, index, head)
    progress["start_inclusion_verified"] = True
    progress["selected_kids"] = [r["actor_id"] for r in rows if r["selected"]]
    progress["excluded_members"] = [r for r in rows if not r["selected"]]
    require(sorted(progress["selected_kids"]) == sorted(a.kid for a in agents[1:]), "audience_mismatch")
    for agent in sorted(agents[1:], key=lambda a: a.kid):
        nonce = U(secrets.token_bytes(16))
        header = J(
            dict(
                from_kid=sender.kid,
                to_kid=agent.kid,
                envelope_nonce=nonce,
                swarm_id=swarm_id,
                broadcast_index=index,
                membership_index=info["roster_index"],
            )
        )
        plaintext = len(header).to_bytes(4, "big") + header + b"x" * client.runner.config.body_bytes
        ciphertext = SealedBox(PublicKey(DU(agent.x))).encrypt(plaintext)
        await client.write(
            sender,
            "swarm.delivery",
            dict(
                broadcast_index=index,
                to_kid=agent.kid,
                to_key_leaf_index=agent.claim_index,
                grant_index=grants[agent.kid],
                encryption="x25519-xsalsa20-poly1305",
                eph_pk=U(ciphertext[:32]),
                ct_hash=H(ciphertext),
                size=len(ciphertext),
            ),
            ciphertext,
            nonce=nonce,
        )
        progress["delivered"] += 1
        progress["remaining"] -= 1
        await client.runner.sleep(client.runner.config.think_time)
    status, rows = await status_pages(client, index)
    require(
        status["state"] == "complete"
        and status["delivered_count"] == recipients
        and status["remaining_count"] == 0
        and all(x["delivery_index"] is not None for x in rows),
        "broadcast_incomplete",
    )
    progress.update(complete=True, complete_index=status["complete_index"])

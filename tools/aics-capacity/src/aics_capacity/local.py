"""Tool-local extension of the committed conformance FakeServer.

Only the happy-path SWARMS workload subset is modeled: introductions, formation,
join, consent, all-audience starts, deliveries and paginated status. This is not a
production server or a substitute for swarm conformance. All base crypto, receipts,
refusals and gates remain the repository fake's implementation.
"""

import copy
from urllib.parse import parse_qs, unquote, urlsplit

from aics_conformance.client import Response
from aics_conformance.fakes import FakeServer
from aics_conformance.protocol import H, J, U, verify_signature
from aics_tlog import Checkpoint, IncrementalTileWriter, MemoryTileStore, leaf_hash, sign_checkpoint


class CapacityFake(FakeServer):
    def __init__(self, *faults, writes_per_minute=100_000):
        self.local_write_count = writes_per_minute
        self.store = MemoryTileStore()
        self.writer = IncrementalTileWriter(self.store)
        self.indices, self.introductions, self.swarms = {}, {}, {}
        self.swarm_grants, self.broadcasts, self.used_deliveries = {}, {}, {}
        self.snapshots = {}
        super().__init__(*faults)

    def make_card(self):
        card = super().make_card()
        card.pop("signatures")
        card["limits"]["writes"]["count"] = self.local_write_count
        card["limits"]["registrations"]["count"] = self.local_write_count
        protected = U(J(dict(alg="EdDSA", kid=self.policy_actor.kid, typ="JOSE")))
        signature = U(self.policy_actor.key.sign((protected + "." + U(J(card))).encode()))
        card["signatures"] = [{"protected": protected, "signature": signature}]
        return card

    def append(self, entry, body=None):
        index = super().append(entry, body)
        raw = J(entry)
        self.indices[leaf_hash(raw).hex()] = index
        self.writer.append([raw])
        return index

    def checkpoint(self, mirror=False):
        if self.faults:
            return super().checkpoint(mirror)
        self.head_calls += 1
        return sign_checkpoint(
            Checkpoint(self.origin, self.writer.size, self.writer.root()), self.log, self.origin
        ).to_bytes()

    def resources(self):
        return super().resources() if self.faults else self.store.tiles

    def roster(self, swarm):
        return [
            {"member_index": i, "actor_id": self.introductions[i]["kid"]} for i in sorted(swarm["members"])
        ]

    def roster_hash(self, swarm):
        return H(J(self.roster(swarm)))

    def targets(self, swarm, sender):
        selected, excluded = [], []
        for member in sorted(swarm["members"]):
            kid = self.introductions[member]["kid"]
            if kid == sender:
                continue
            grant = self.swarm_grants.get((swarm["id"], kid))
            reason = None
            if not grant or grant["max"] == 0 or grant["expires"] <= self.now:
                reason = "no_consent"
            elif self.used_deliveries.get(grant["index"], 0) >= grant["max"]:
                reason = "grant_exhausted"
            row = dict(
                member_index=member,
                actor_id=kid,
                selected=reason is None,
                exclusion=reason,
                delivery_index=None,
            )
            (selected if reason is None else excluded).append(row)
        return selected, excluded

    def validate_swarm(self, env, body):
        p, q = env["protected"], env["payload"]
        typ, kid = p["type"], p["kid"]
        if body is not None:
            if H(body) != q.get("body_hash", q.get("ct_hash")) or len(body) != q["size"]:
                return "malformed"
        if typ == "agent.introduce":
            if any(x["kid"] == kid for x in self.introductions.values()):
                return "swarm_stale"
            if q["member_index"] is not None or q["prev_intro_index"] is not None:
                return "swarm_stale"
        elif typ == "swarm.form":
            a, b = self.introductions[q["founder_member_index"]], self.introductions[q["peer_member_index"]]
            if a["kid"] != kid or a["swarm"] or b["swarm"] or a is b:
                return "swarm_stale"
            if q["peer_actor_id"] != b["kid"] or q["peer_intro_index"] != q["peer_member_index"]:
                return "swarm_stale"
        elif typ == "swarm.join":
            swarm = self.swarms[q["swarm_id"]]
            intro = self.introductions[q["member_index"]]
            if intro["kid"] != kid or intro["swarm"] or q["target_member_index"] not in swarm["members"]:
                return "swarm_membership"
            if q["roster_index"] != swarm["roster_index"]:
                return "swarm_stale"
        elif typ == "swarm.grant":
            swarm = self.swarms[q["swarm_id"]]
            intro = next(v for v in self.introductions.values() if v["kid"] == kid)
            if q["owner_kid"] != kid or intro["swarm"] != q["swarm_id"]:
                return "swarm_membership"
            if q["admission_index"] != swarm["members"][intro["index"]]:
                return "swarm_stale"
        elif typ == "swarm.broadcast":
            swarm = self.swarms[q["swarm_id"]]
            if kid not in [x["actor_id"] for x in self.roster(swarm)]:
                return "swarm_membership"
            selected, _ = self.targets(swarm, kid)
            if not selected:
                return "swarm_empty_audience"
            if q["audience_mode"] != "all" or q["recipient_count"] != len(selected):
                return "swarm_stale"
            if q["audience_hash"] != H(J(sorted(x["actor_id"] for x in selected))):
                return "swarm_stale"
            if q["roster_index"] != swarm["roster_index"] or q["roster_hash"] != self.roster_hash(swarm):
                return "swarm_stale"
            if not self.now < q["closes"] <= self.now + 86400:
                return "expired"
        elif typ == "swarm.delivery":
            broadcast = self.broadcasts[q["broadcast_index"]]
            start = broadcast["entry"]
            sq = start["payload"]
            if kid != start["actor_kid"] or self.now >= sq["closes"]:
                return "expired"
            target = next(
                (x for x in broadcast["rows"] if x["actor_id"] == q["to_kid"] and x["selected"]), None
            )
            if target is None:
                return "no_consent"
            if target["delivery_index"] is not None:
                return "swarm_duplicate_delivery"
            intro = self.introductions[target["member_index"]]
            grant = self.swarm_grants[sq["swarm_id"], q["to_kid"]]
            if q["to_key_leaf_index"] != intro["index"]:
                return "stale_key"
            if q["grant_index"] != grant["index"] or grant["expires"] <= self.now:
                return "no_consent"
            if self.used_deliveries.get(grant["index"], 0) >= grant["max"]:
                return "grant_exhausted"
            if q["encryption"] != "x25519-xsalsa20-poly1305" or U(body[:32]) != q["eph_pk"]:
                return "unsupported_scheme"
        return None

    def submit(self, env, body, headers, url, *, gate=False):
        try:
            verify_signature(env)
        except Exception:
            return super().submit(env, body, headers, url, gate=gate)
        p = env["protected"]
        previous = self.last.get(p["kid"])
        if p["seq"] != (previous["protected"]["seq"] + 1 if previous else 0):
            return self.refuse(env, "seq_gap")
        if p["prev"] != (H(J(previous)) if previous else None):
            return self.refuse(env, "seq_gap")
        if p["type"].startswith("swarm.") or p["type"] == "agent.introduce":
            try:
                reason = self.validate_swarm(env, body)
            except (KeyError, StopIteration, TypeError):
                reason = "malformed"
            if reason:
                return self.refuse(env, reason)
        return super().submit(env, body, headers, url, gate=gate)

    def accept(self, env, body=None):
        index = len(self.entries)
        entry = super().accept(env, body)
        p, q = env["protected"], env["payload"]
        typ, kid = p["type"], p["kid"]
        if typ == "agent.introduce":
            self.introductions[index] = dict(index=index, kid=kid, swarm=None, x=q["x25519"])
        elif typ == "swarm.form":
            members = {q["founder_member_index"]: index, q["peer_member_index"]: index}
            self.swarms[q["swarm_id"]] = dict(
                id=q["swarm_id"], members=members, roster_index=index, form_index=index
            )
            for member in members:
                self.introductions[member]["swarm"] = q["swarm_id"]
        elif typ == "swarm.join":
            swarm = self.swarms[q["swarm_id"]]
            swarm["members"][q["member_index"]] = index
            swarm["roster_index"] = index
            self.introductions[q["member_index"]]["swarm"] = q["swarm_id"]
        elif typ == "swarm.grant":
            self.swarm_grants[q["swarm_id"], kid] = dict(q, index=index)
        elif typ == "swarm.broadcast":
            selected, excluded = self.targets(self.swarms[q["swarm_id"]], kid)
            self.broadcasts[index] = dict(
                entry=entry, rows=sorted(selected + excluded, key=lambda x: x["member_index"])
            )
        elif typ == "swarm.delivery":
            for row in self.broadcasts[q["broadcast_index"]]["rows"]:
                if row["actor_id"] == q["to_kid"]:
                    row["delivery_index"] = index
            gi = q["grant_index"]
            self.used_deliveries[gi] = self.used_deliveries.get(gi, 0) + 1
        return entry

    def snapshot(self):
        size = len(self.entries)
        if size not in self.snapshots:
            note = self.checkpoint()
            self.snapshots[size] = (
                copy.deepcopy(self.swarms),
                copy.deepcopy(self.broadcasts),
                dict(size=size, note_hash=H(note), note=U(note)),
            )
        return self.snapshots[size]

    @staticmethod
    def page(rows, cursor, key):
        rows = [row for row in rows if cursor is None or row[key] > cursor]
        return dict(items=rows[:25], next_after=rows[24][key] if len(rows) > 25 else None)

    def request(self, method, url, body=None, headers=None):
        parts = urlsplit(url)
        path, query = unquote(parts.path), parse_qs(parts.query)
        if path.startswith("/v2/tlog/index/") and not self.faults:
            digest = path.rsplit("/", 1)[1]
            index = self.indices.get(digest)
            return Response(200 if index is not None else 404, J(dict(entry_hash=digest, index=index)), {})
        if path.startswith(("/v2/swarms/", "/v2/swarm-broadcasts/")):
            size = int(query["at_size"][0]) if "at_size" in query else len(self.entries)
            if "at_size" not in query:
                self.snapshot()
            if size not in self.snapshots:
                return Response(404, J({"error": "unknown_checkpoint"}), {})
            swarms, broadcasts, checkpoint = self.snapshots[size]
            if path.startswith("/v2/swarms/"):
                swarm = swarms[path.rsplit("/", 1)[1]]
                rows = [
                    dict(row, tier="verified", admission_index=swarm["members"][row["member_index"]])
                    for row in self.roster(swarm)
                ]
                after = int(query["members_after"][0]) if "members_after" in query else None
                obj = dict(
                    swarm_id=swarm["id"],
                    form_index=swarm["form_index"],
                    roster_index=swarm["roster_index"],
                    roster_hash=self.roster_hash(swarm),
                    members=self.page(rows, after, "member_index"),
                    checkpoint=checkpoint,
                )
            else:
                index = int(path.rsplit("/", 1)[1])
                broadcast = broadcasts[index]
                rows = broadcast["rows"]
                selected = [x for x in rows if x["selected"]]
                delivered = [x for x in selected if x["delivery_index"] is not None]
                remaining = len(selected) - len(delivered)
                after = int(query["after_member_index"][0]) if "after_member_index" in query else None
                obj = dict(
                    broadcast_index=index,
                    audience_mode="all",
                    recipient_count=len(selected),
                    excluded_count=len(rows) - len(selected),
                    delivered_count=len(delivered),
                    remaining_count=remaining,
                    recipients=self.page(rows, after, "member_index"),
                    state="pending" if remaining else "complete",
                    complete_index=None if remaining else max(x["delivery_index"] for x in delivered),
                    evaluated_at=int(self.now),
                    checkpoint=checkpoint,
                )
            return Response(200, J(obj), {})
        return super().request(method, url, body, headers)

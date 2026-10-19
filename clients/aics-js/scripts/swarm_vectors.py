"""Generate the SWARMS-1 vectors of the npm client from the real aics-server of this repository.

Run inside packages/aics-server (its venv has the server, its test helpers and pytest):

    cd packages/aics-server && uv run --no-sync python -I ../../clients/aics-js/scripts/swarm_vectors.py \
        ../../clients/aics-js/test/fixtures/swarms-server.json

The server boots in-process exactly as packages/aics-server/tests/test_swarms.py boots it (create_app with
``swarms=True``, a bootstrap SWARMS-1 card, a controlled clock), and one journey writes every one of the ten
SWARMS-1 entry types through the ordinary RFC 9421 + ``POST /v2/entries`` binding, with logged refusals.  The output
holds the complete leaf prefix, the out-of-band pins, the public bodies, two delivery ciphertexts with the recipients'
X25519 test secrets (throwaway keys made for this file, never a service key) and the server's read projections, so the
client's History can be compared with them.  The keys are random: regenerating changes every byte, never the shape.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve()
SERVER = HERE.parents[3] / "packages" / "aics-server"
sys.path.insert(0, str(SERVER / "tests"))

OUT = Path(sys.argv[1]).resolve()
ROOT = Path(tempfile.mkdtemp(prefix="aics-js-swarms-"))
for name in [k for k in os.environ if k.startswith("AICS_")]:
    del os.environ[name]
(ROOT / "terms.md").write_bytes(b"aics-js swarm vectors terms.\n")
(ROOT / "privacy.md").write_bytes(b"aics-js swarm vectors privacy.\n")
os.environ.update(AICS_TERMS_FILE=str(ROOT / "terms.md"), AICS_PRIVACY_FILE=str(ROOT / "privacy.md"), AICS_DEV_GENESIS="1")

clock = [int(time.time())]
time.time = lambda: clock[0]  # the server and the helpers read this clock, like the tests' fixture

from fastapi.testclient import TestClient  # noqa: E402
from nacl.public import PublicKey, SealedBox  # noqa: E402

from aics_identity import canonicalize, envelope, keys, sealed  # noqa: E402
from aics_server.app import create_app  # noqa: E402
from conftest import TEST_LIMITS, Agent, OutOfBand, Owner, Signer, entry_of, leaf_index, post_body, post_q, reason, submit_entry  # noqa: E402

H = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
J = canonicalize
U = keys.b64u_encode

owner = Owner()
client = TestClient(create_app(db_path=ROOT / "aics.db", owner_public_key=owner.public_key_b64u,
                               pubkeys_out=ROOT / "aics-keys.txt", announce=False, limits=TEST_LIMITS, swarms=True))
oob = OutOfBand.from_file(ROOT / "aics-keys.txt")
ORIGIN = oob.origin
refusals: list[dict] = []


def get(path, **params):
    r = client.get(path, params={k: json.dumps(v, ensure_ascii=False) for k, v in params.items() if v is not None})
    assert r.status_code == 200, (path, r.text)
    return r.json()


class M:
    """An agent of the journey: its own signing and X25519 keys, its stable root and latest introduction."""

    def __init__(self, label, model, words, code=None):
        self.label, self.signer, self.x = label, Signer(), sealed.generate_x25519_key()
        self.model, self.words, self.code, self.index, self.latest = model, list(words), code, None, None

    @property
    def kid(self):
        return self.signer.kid

    def write(self, typ, q, body=None, *, expect=202, code=None, **kw):
        r = submit_entry(client, self.signer, {"type": typ, "origin": ORIGIN, **q}, body, **kw)[0]
        if expect == 202:
            assert r.status_code == 202, (typ, r.text)
            return leaf_index(r)
        assert 400 <= r.status_code < 500 and reason(r) == code, (typ, code, r.status_code, r.text)
        refusals.append({"label": f"{self.label} {typ}", "index": leaf_index(r, client),
                         "reason_code": code, "conflict_index": entry_of(r)["payload"]["conflict_index"]})
        return None

    def intro(self, *, connectable=True, model=None, code="keep"):
        self.model = model or self.model
        if code != "keep":
            self.code = code
        body = J({"model": self.model, "keywords": self.words})
        q = {"member_index": self.index, "prev_intro_index": self.latest, "ed25519": self.signer.public_key_b64u,
             "x25519": sealed.format_x25519_public_key(self.x), "tier": "verified", "body_hash": H(body), "size": len(body),
             "code_hash": self.code, "connectable": connectable}
        self.latest = self.write("agent.introduce", q, body)
        self.index = self.latest if self.index is None else self.index
        return self.latest


def swarm_id(founder, nonce, code=None):
    if code is not None:
        return H(b"AICS-SWARMS-1 code-swarm\n" + J({"origin": ORIGIN, "code_hash": code}))
    return H(b"AICS-SWARMS-1 swarm\n" + J({"origin": ORIGIN, "founder_member_index": founder, "nonce": nonce}))


def channel(sid):
    return "swarm-" + base64.b32encode(bytes.fromhex(sid)).decode().lower().rstrip("=")


def form(founder, peer, title, text, code=None):
    nonce = envelope.new_nonce()
    sid = swarm_id(founder.index, nonce, code)
    body = J({"channel": channel(sid), "title": title, "text": text})
    q = {"swarm_id": sid, "founder_member_index": founder.index, "peer_member_index": peer.index, "peer_actor_id": peer.kid,
         "peer_intro_index": peer.latest, "code_hash": code, "channel_sha256": H(channel(sid).encode()), "body_hash": H(body),
         "size": len(body), "title_sha256": H(title.encode())}
    return sid, founder.write("swarm.form", q, body, nonce=nonce)


def info(sid):
    return get(f"/v2/swarms/{sid}")


def join(m, target, sid, **kw):
    return m.write("swarm.join", {"swarm_id": sid, "member_index": m.index, "target_member_index": target.index,
                                  "roster_index": info(sid)["roster_index"]}, **kw)


def admission(m):
    return get(f"/v2/agents/{m.index}")["admission_index"]


def leave(m, sid):
    return m.write("swarm.leave", {"swarm_id": sid, "member_index": m.index, "admission_index": admission(m)})


def propose(m, sid, *, name=None, target=None, closes=60):
    s = info(sid)
    q = {"swarm_id": sid, "kind": "name" if target is None else "eject", "roster_index": s["roster_index"],
         "roster_hash": s["roster_hash"], "closes": clock[0] + closes}
    body = None
    if target is None:
        body = J({"name": name})
        q.update(base_name_index=s["name_index"], body_hash=H(body), size=len(body), name_hash=H(name.encode()))
    else:
        q["target_member_index"] = target.index
    return m.write("swarm.propose", q, body)


def vote(m, p, choice):
    return m.write("swarm.vote", {"proposal_index": p, "choice": choice})


def resolve(m, p, outcome, yes, no, electorate, **kw):
    return m.write("swarm.resolve", {"proposal_index": p, "outcome": outcome, "yes": yes, "no": no, "electorate": electorate}, **kw)


def grant(m, sid, maximum, prev=None):
    return m.write("swarm.grant", {"swarm_id": sid, "owner_kid": m.kid, "admission_index": admission(m), "max": maximum,
                                   "expires": clock[0] + 86400 * 3, "prev_grant_index": prev})


def broadcast(m, sid, targets, closes=3600):
    s = info(sid)
    kids = sorted(t.kid for t in targets)
    return m.write("swarm.broadcast", {"swarm_id": sid, "roster_index": s["roster_index"], "roster_hash": s["roster_hash"],
                                       "audience_mode": "all", "audience_hash": H(J(kids)), "recipient_count": len(kids),
                                       "closes": clock[0] + closes})


deliveries: list[dict] = []


def deliver(sender, target, start, sid, roster, grant_index, key_leaf, content, **kw):
    nonce = envelope.new_nonce()
    header = J({"from_kid": sender.kid, "to_kid": target.kid, "envelope_nonce": nonce, "swarm_id": sid,
                "broadcast_index": start, "membership_index": roster})
    frame = len(header).to_bytes(4, "big") + header + content.encode()
    ct = SealedBox(PublicKey(keys.b64u_decode(sealed.format_x25519_public_key(target.x)))).encrypt(frame)
    q = {"broadcast_index": start, "to_kid": target.kid, "to_key_leaf_index": key_leaf, "grant_index": grant_index,
         "encryption": sealed.SCHEME, "eph_pk": U(ct[:32]), "ct_hash": H(ct), "size": len(ct)}
    index = sender.write("swarm.delivery", q, ct, nonce=nonce, **kw)
    if index is not None:
        deliveries.append({"index": index, "ciphertext": U(ct), "recipient_x25519_secret": U(bytes(target.x)),
                           "recipient": target.label, "content": content,
                           "expected": {"from_kid": sender.kid, "to_kid": target.kid, "envelope_nonce": nonce, "swarm_id": sid,
                                        "broadcast_index": start, "membership_index": roster}})
    return index


def tick(seconds=1):
    clock[0] += seconds


# --- the journey -------------------------------------------------------------------------------------------------
raw_code = secrets.token_bytes(32)
code_hash = H(b"AICS-SWARMS-1 rendezvous\n" + J({"origin": ORIGIN, "code": U(raw_code)}))
a = M("a", "Model A (self-reported)", ["orbit", "blue", "friends"])
b = M("b", "Model B", ["orbit", "red", "Ärger"])
c = M("c", "Model C", ["green", "blue", "kite"])
d = M("d", "Model D", ["code", "pair", "one"], code=code_hash)
e = M("e", "Model E", ["code", "pair", "two"], code=code_hash)
f = M("f", "Model F", ["solo", "quiet", "loner"])
for m in (a, b, c, d, e, f):
    m.intro(); tick()
b_original = b.kid
s1, root1 = form(a, b, "Orbit friends", "Agent-authored first public thread."); tick()
post = post_body("Re: root", "A member reply in the swarm channel.", channel(s1))
outsider_post = submit_entry(client, f.signer, {"type": "post", "origin": ORIGIN, **post_q(post, root1)}, post)[0]
assert reason(outsider_post) == "swarm_membership"
refusals.append({"label": "f post (nonmember)", "index": leaf_index(outsider_post, client), "reason_code": "swarm_membership",
                 "conflict_index": entry_of(outsider_post)["payload"]["conflict_index"]})
tick()
a.write("post", post_q(post, root1), post); tick()
join_c = join(c, a, s1); tick()
s2, root2 = form(d, e, "Code pair", "Formed by a shared rendezvous code.", code=code_hash); tick()
# rename: 2 yes, 1 no out of 3 -> passed
p_name = propose(a, s1, name="Orbit renamed"); tick()
vote(a, p_name, "yes"); tick(); vote(b, p_name, "no"); tick(); vote(c, p_name, "yes"); tick()
resolve(a, p_name, "passed", 2, 1, 3, expect=400, code="swarm_proposal_open"); tick()
tick(60)
resolve(f, p_name, "rejected", 2, 1, 3, expect=400, code="swarm_result"); tick()
r_name = resolve(f, p_name, "passed", 2, 1, 3); tick()
# eject c: one yes, the rest abstain -> passed; c cannot rejoin for 24 hours
p_eject = propose(a, s1, target=c); tick()
vote(a, p_eject, "yes"); tick(); tick(60)
r_eject = resolve(b, p_eject, "passed", 1, 0, 3); tick()
join(c, a, s1, expect=400, code="swarm_ejected"); tick()
tick(86400)
join_c2 = join(c, b, s1); tick()
# b claims a handle after introducing (same pair and tier), then rotates its X25519 key (membership unchanged)
named_b = Agent(client, ORIGIN, b.signer)
named_b.x25519, named_b.x25519_b64u = b.x, sealed.format_x25519_public_key(b.x)
r = named_b.claim("bee-agent"); assert r.status_code == 202, r.text; b_claim = leaf_index(r); tick()
r = named_b.rotate_x25519(); assert r.status_code == 202, r.text; b_x = leaf_index(r); b.x = named_b.x25519; tick()
# private broadcast: b and c consent, a starts and delivers to both
g_b = grant(b, s1, 2); tick()
g_c = grant(c, s1, 1); tick()
roster = info(s1)["roster_index"]
start = broadcast(a, s1, [b, c]); tick()
deliver(a, b, start, s1, roster, g_b, b_x, "Private to b"); tick()
deliver(a, c, start, s1, roster, g_c, c.index, "Private to c"); tick()
deliver(a, c, start, s1, roster, g_c, c.index, "Again", expect=400, code="swarm_duplicate_delivery"); tick()
# a second start: c's one-message grant is spent (skipped as grant_exhausted), b still consents
start2 = broadcast(a, s1, [b]); tick()
# c leaves; the code swarm empties and retires; b rotates its signing key (roster revision changes)
leave(c, s1); tick()
leave(d, s2); tick(); retired = leave(e, s2); tick()
replacement = Signer()
r = named_b.rotate(replacement); assert r.status_code == 202, r.text; b.signer = replacement; b_rot = leaf_index(r); tick()
# f withdraws its standing pairing permission
f.intro(connectable=False); tick()

size = get("/v2/tlog/checkpoint")["tree_size"]
entries = []
for n in range(size):
    entries.append(get(f"/v2/entries/{n}")["entry_bytes"])
bodies = {}
for raw in entries:
    entry = json.loads(keys.b64u_decode(raw))
    q = entry["payload"]
    h = q.get("body_hash") if entry["type"] != "swarm.delivery" else q.get("ct_hash")
    if entry["type"] in ("agent.introduce", "swarm.form", "swarm.propose", "post", "swarm.delivery") and h:
        r = client.get(f"/v2/bodies/{h}")
        if r.status_code == 200:
            bodies[h] = U(r.content)


def pages(path, cursor_in, cursor_out, array, **params):
    page = get(path, **params)
    out = [page]
    while page[array]["next_after"] is not None:
        page = get(path, at_size=page["checkpoint"]["size"], **{**params, cursor_in: page[array]["next_after"]})
        out.append(page)
    return out


members = {m.label: m.index for m in (a, b, c, d, e, f)}
projections = {
    "swarms": {s1: info(s1), s2: info(s2)},
    "agents": {str(m.index): get(f"/v2/agents/{m.index}") for m in (a, b, c, d, e, f)},
    "arrivals": get("/v2/arrivals", q=""),
    "arrivals_search": {"q=orbit": get("/v2/arrivals", q="orbit"), "keyword=BLUE": get("/v2/arrivals", q="", keyword="BLUE"),
                        "model=model b": get("/v2/arrivals", q="", model="model b"),
                        "swarm_name=Orbit renamed": get("/v2/arrivals", q="", swarm_name="Orbit renamed"),
                        "q=ärger": get("/v2/arrivals", q="ärger"), "q=Ärger": get("/v2/arrivals", q="Ärger")},
    "broadcasts": {str(start): get(f"/v2/swarm-broadcasts/{start}"), str(start2): get(f"/v2/swarm-broadcasts/{start2}")},
    "inbox": {b.label: get(f"/v2/swarm-inbox/{b_original}", **{"from": 0}),
              c.label: get(f"/v2/swarm-inbox/{c.kid}", **{"from": 0})},
    "rendezvous": get(f"/v2/rendezvous/{code_hash}"),
}
card = get("/.well-known/aics-card.json")
doc = {
    "description": "SWARMS-1 vectors generated by clients/aics-js/scripts/swarm_vectors.py from packages/aics-server (in-process, "
                   "swarms=True). Test keys only; every leaf was accepted or refused by the real server.",
    "trust": {"origin": ORIGIN, "log_vkey": oob.log_vkey_text, "policy_kid": oob.policy_kid, "owner_kid": oob.owner_kid},
    "card_spec": card["spec"],
    "card": card,
    "generated_at": clock[0],
    "entries": entries,
    "bodies": bodies,
    "members": members,
    "kids": {m.label: m.kid for m in (a, b, c, d, e, f)} | {"b_original": b_original},
    "swarms": {"orbit": s1, "code": s2},
    "code_hash": code_hash,
    "indices": {"root1": root1, "root2": root2, "join_c": join_c, "join_c2": join_c2, "p_name": p_name, "r_name": r_name,
                "p_eject": p_eject, "r_eject": r_eject, "b_claim": b_claim, "b_x25519": b_x, "g_b": g_b, "g_c": g_c,
                "start": start, "start2": start2, "retired": retired, "b_rotate": b_rot},
    "refusals": refusals,
    "deliveries": deliveries,
    "projections": projections,
}
OUT.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", "utf-8")
client.close()
print(f"wrote {OUT} ({size} leaves)")

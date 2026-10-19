// AICS-1 §19 / SWARMS-1: the ten swarm entry types, membership replay, governance, grants, broadcasts and the
// recipient-side delivery checks. Part one replays a log the real aics-server wrote (fixtures/swarms-server.json, made
// by scripts/swarm_vectors.py) and compares this client's reconstruction with the server's own read projections. Part
// two builds logs with the test log builder to check each rule, with the refusal code the server would log.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { History } from '../dist/history.js';
import { b64u, decodeU64, hexH, utf8 } from '../dist/bytes.js';
import { canonicalize } from '../dist/canonical.js';
import { parseEntry, payloadProblems } from '../dist/entry.js';
import { verifyCard } from '../dist/card.js';
import { publicKey, x25519PublicKey, didKey } from '../dist/keys.js';
import { SUPPORTED_PROFILES, SWARMS_TYPES, REFUSAL_SWARMS, TEXT_VERBS, entryTypes, refusalRegistry } from '../dist/registry.js';
import { textCommand, nextChain, secretAttestationMessage } from '../dist/envelope.js';
import { sign } from '../dist/keys.js';
import * as sw from '../dist/swarms.js';
import { TestLog, seed, kidOf, T } from './log-builder.mjs';

const vectors = JSON.parse(readFileSync(new URL('./fixtures/swarms-server.json', import.meta.url), 'utf8'));
const raw = vectors.entries.map(s => decodeU64(s)), profiles = ['SWARMS-1', 'SUP-1'];
const bodies = h => (vectors.bodies[h] ? decodeU64(vectors.bodies[h]) : null);
const items = page => page.items;
const strip = ({ checkpoint: _c, ...rest }) => rest;

test('registry: SWARMS-1 is a supported profile with exactly ten types (27 base+swarms), twelve codes and its gate verbs', () => {
  assert.deepEqual([...SUPPORTED_PROFILES].sort(), ['SUP-1', 'SWARMS-1']);
  assert.equal(SWARMS_TYPES.length, 10); assert.equal(entryTypes(['SWARMS-1']).length, 27); assert.equal(entryTypes(['SWARMS-1', 'SUP-1']).length, 30);
  assert.equal(REFUSAL_SWARMS.length, 12); assert(REFUSAL_SWARMS.every(c => refusalRegistry(['SWARMS-1']).has(c) && !refusalRegistry().has(c)));
  assert.equal(TEXT_VERBS['agent.introduce'], 'intro'); assert.equal(TEXT_VERBS['swarm.delivery'], 'swarm-deliver'); assert.equal(TEXT_VERBS['swarm.form'], 'swarm-form');
  const u = { v: 1, protected: { alg: 'EdDSA', origin: 'o', type: 'swarm.leave', kid: 'k', created: 0, expires: 1, nonce: 'n', seq: 0, prev: null, seen: null }, payload: { swarm_id: 'x' }, auth: { scheme: 'text-ed25519', session: 's' } };
  assert.match(textCommand(u), /^swarm-leave /);
});

test('server vectors: the card activates AICS-1+SWARMS-1+SUP-1 and verifies with the SWARMS R47 member', () => {
  assert.equal(vectors.card_spec, 'AICS-1+SWARMS-1+SUP-1');
  const v = verifyCard(vectors.card, { trust: vectors.trust, checkTimes: false });
  assert.deepEqual(v.problems, []); assert.deepEqual(v.profiles.sort(), ['SUP-1', 'SWARMS-1']);
  const bad = structuredClone(vectors.card); bad.swarms.discovery_window = 50;
  assert(verifyCard(bad, { trust: vectors.trust, checkTimes: false }).problems.some(p => p.startsWith('$.swarms')));
  const noMember = structuredClone(vectors.card); delete noMember.swarms;
  assert(verifyCard(noMember, { trust: vectors.trust, checkTimes: false }).problems.some(p => /missing swarms/.test(p)));
});

test('server vectors: a base-only (or SUP-1 only) verifier refuses the first swarm leaf (T01)', () => {
  assert.throws(() => new History(raw, { trust: vectors.trust, profiles: ['SUP-1'] }), e => e.index === 2 && /no closed schema|not an entry type/.test(e.message));
});

test('server vectors: the complete prefix the server wrote replays under AICS-1+SWARMS-1+SUP-1, refusals included', () => {
  const h = new History(raw, { trust: vectors.trust, profiles });
  assert.equal(h.size, raw.length);
  const types = new Set(h.entries.map(e => e.type)); for (const t of SWARMS_TYPES) assert(types.has(t), t);
  for (const r of vectors.refusals) { const e = h.entries[r.index]; assert.equal(e.type, 'refusal'); assert.equal(e.payload.reason_code, r.reason_code); assert.equal(e.payload.conflict_index, r.conflict_index); }
  // R09: no model, keyword, name, title or private content on any leaf
  const all = Buffer.concat(raw.map(b => Buffer.from(b))).toString('utf8');
  for (const s of ['Model A', 'orbit', 'Ärger', 'Orbit friends', 'Orbit renamed', 'Private to b', 'Agent-authored']) assert(!all.includes(s), s);
});

test('server vectors: the replayed roster, revisions, names, ejections and agents equal the server projections (R43)', () => {
  const h = new History(raw, { trust: vectors.trust, profiles }), s = h.swarms;
  for (const [sid, want] of Object.entries(vectors.projections.swarms)) {
    const got = s.swarmInfo(sid), { members, proposal_indices, ejections, ...rest } = strip(want);
    const { members: gm, proposal_indices: gp, ejections: ge, retired: _r, ...grest } = got;
    assert.deepEqual(grest, rest); assert.deepEqual(gm, items(members)); assert.deepEqual(gp, items(proposal_indices)); assert.deepEqual(ge, items(ejections));
  }
  assert.equal(s.swarmInfo(vectors.swarms.code).retired, true); assert.equal(s.swarmInfo(vectors.swarms.orbit).retired, false);
  assert.equal(s.swarmInfo(vectors.swarms.orbit).channel, sw.channelSlug(vectors.swarms.orbit)); assert.equal(sw.channelSlug(vectors.swarms.orbit).length, 58);
  for (const [index, want] of Object.entries(vectors.projections.agents)) {
    const { key_event_indices, ...rest } = strip(want), { key_event_indices: gk, ...grest } = s.agentInfo(Number(index));
    assert.deepEqual(grest, rest); assert.deepEqual(gk, items(key_event_indices));
  }
  // the 24-hour ejection is recorded on the resolve leaf (R21) and b keeps its seat through claim, X25519 and signing rotation (R22)
  const orbit = s.swarmInfo(vectors.swarms.orbit), resolve = h.entries[vectors.indices.r_eject];
  assert.deepEqual(orbit.ejections, [{ member_index: vectors.members.c, resolve_index: vectors.indices.r_eject, until: resolve.ts + 86400 }]);
  assert.equal(orbit.roster_index, vectors.indices.b_rotate); assert.equal(s.agentInfo(vectors.members.b).actor_id, vectors.kids.b);
  assert.equal(s.agentInfo(vectors.members.b).claim_index, vectors.indices.b_claim);
});

test('server vectors: discovery, search, broadcast status, inboxes and rendezvous equal the server projections (R15-R16, R31-R39)', () => {
  const h = new History(raw, { trust: vectors.trust, profiles }), s = h.swarms, p = vectors.projections;
  const arrivals = s.arrivals(h.entries, bodies);
  assert.deepEqual(arrivals.rows, p.arrivals.rows); assert.equal(arrivals.window_count, p.arrivals.window_count); assert.equal(arrivals.oldest_intro_index, p.arrivals.oldest_intro_index);
  assert.equal(arrivals.notice, sw.FLOOD_NOTICE);
  const searches = { 'q=orbit': { q: 'orbit' }, 'keyword=BLUE': { keyword: 'BLUE' }, 'model=model b': { model: 'model b' }, 'swarm_name=Orbit renamed': { swarm_name: 'Orbit renamed' }, 'q=ärger': { q: 'ärger' }, 'q=Ärger': { q: 'Ärger' } };
  for (const [k, search] of Object.entries(searches)) assert.deepEqual(s.arrivals(h.entries, bodies, search).rows, p.arrivals_search[k].rows, k);
  assert.deepEqual(s.arrivals(h.entries, () => null).rows.map(r => r.profile_status), p.arrivals.rows.map(() => 'unavailable'));
  const hidden = s.arrivals(h.entries, bodies, { q: 'orbit' }, new Map([[vectors.members.a, 99], [vectors.indices.p_name, 99]]));
  assert.deepEqual(hidden.rows.map(r => [r.member_index, r.profile_status, r.swarm_name_status]), [[vectors.members.b, 'available', 'tombstoned']]);
  for (const [index, want] of Object.entries(p.broadcasts)) {
    const got = s.broadcastStatus(Number(index), want.evaluated_at), { recipients, ...rest } = strip(want), { recipients: gr, ...grest } = got;
    assert.deepEqual(grest, rest); assert.deepEqual(gr, items(recipients));
  }
  assert.deepEqual(s.broadcastStatus(vectors.indices.start2, vectors.generated_at).recipients.find(r => !r.selected).exclusion, 'grant_exhausted');
  for (const [label, want] of Object.entries(p.inbox)) assert.deepEqual(s.inbox(want.owner_kid), items(want.deliveries).map(({ index, broadcast_index }) => ({ index, broadcast_index })), label);
  assert.deepEqual(s.rendezvous(vectors.code_hash), strip(p.rendezvous));
  assert.equal(sw.codeSwarmId(vectors.trust.origin, vectors.code_hash), vectors.swarms.code);
});

test('server vectors: bodies verify against their leaves (R10, R28)', () => {
  const h = new History(raw, { trust: vectors.trust, profiles });
  const intro = h.entries[vectors.members.a].payload.envelope.payload;
  assert.deepEqual(sw.parseProfileBody(bodies(intro.body_hash), intro), { model: 'Model A (self-reported)', keywords: ['orbit', 'blue', 'friends'] });
  const form = h.entries[vectors.indices.root1].payload.envelope.payload, f = sw.parseFormationBody(bodies(form.body_hash), form);
  assert.equal(f.channel, sw.channelSlug(vectors.swarms.orbit)); assert.equal(f.title, 'Orbit friends');
  const prop = h.entries[vectors.indices.p_name].payload.envelope.payload; assert.equal(sw.parseNameBody(bodies(prop.body_hash), prop), 'Orbit renamed');
  assert.throws(() => sw.parseNameBody(bodies(intro.body_hash), prop), /digest_mismatch/);
  assert.throws(() => sw.parseFormationBody(bodies(form.body_hash), { ...form, swarm_id: vectors.swarms.code }), /swarm_channel/);
});

test('server vectors: each recipient opens its own delivery locally; every tampering is rejected (R32, R35, T35)', () => {
  const h = new History(raw, { trust: vectors.trust, profiles }), s = h.swarms;
  for (const d of vectors.deliveries) {
    const ct = decodeU64(d.ciphertext), secret = decodeU64(d.recipient_x25519_secret);
    assert.deepEqual(s.deliveryContext(d.index, h.entries), d.expected);
    assert.equal(s.openDelivery(d.index, h.entries, ct, secret).text, d.content);
  }
  const d = vectors.deliveries[0], ct = decodeU64(d.ciphertext), secret = decodeU64(d.recipient_x25519_secret), q = h.entries[d.index].payload.envelope.payload, pub = x25519PublicKey(secret);
  assert.throws(() => sw.verifyDeliveryCiphertext(ct, { ...q, ct_hash: '0'.repeat(64) }), /digest_mismatch/);
  const rewrapped = sw.sealDelivery(d.expected, d.content, pub);
  assert.throws(() => sw.verifyDeliveryCiphertext(rewrapped, q), /digest_mismatch/);
  const changes = { from_kid: d.expected.to_kid, to_kid: d.expected.from_kid, envelope_nonce: b64u(new Uint8Array(16)), swarm_id: '0'.repeat(64), broadcast_index: d.expected.broadcast_index + 1, membership_index: d.expected.membership_index + 1 };
  for (const [k, v] of Object.entries(changes)) {
    const altered = sw.sealDelivery({ ...d.expected, [k]: v }, 'tampered', pub);
    assert.throws(() => sw.openDelivery(altered, secret, { metadata: sw.deliveryPayload(altered, { broadcast_index: 0, to_kid: d.expected.to_kid, to_key_leaf_index: 0, grant_index: 0 }), expected: d.expected }), /inner header/, k);
  }
  const frame = (header) => { const hb = utf8(header); return Buffer.concat([Buffer.from([0, 0, hb.length >> 8, hb.length & 255]), hb, Buffer.from('x')]); };
  const extra = frame(JSON.stringify({ ...d.expected, unregistered: 'field' })), noncanonical = frame(JSON.stringify(d.expected, null, 1));
  for (const plain of [extra, noncanonical]) assert.throws(() => sw.verifyDeliveryPlaintext(new Uint8Array(plain), d.expected), /inner header/);
  assert.throws(() => sw.openDelivery(ct, seed(0x77), { metadata: q, expected: d.expected }), /does not open/);
});

// --- part two: rule-by-rule logs ---------------------------------------------------------------------------------
const A = seed(0x11), B = seed(0x12), C = seed(0x13), D = seed(0x14), AX = seed(0x21), BX = seed(0x22), CX = seed(0x23), DX = seed(0x24);
const SWARMS = ['SWARMS-1'];
class SwarmLog extends TestLog {
  constructor() { super('log.test/aics', SWARMS); this.roots = new Map(); this.latest = new Map(); }
  intro(s, xs, o = {}) {
    const k = kidOf(s), member = this.roots.has(k) ? { member_index: this.roots.get(k), latest_intro_index: this.latest.get(k) } : undefined;
    const { q, body } = sw.introducePayload({ model: o.model ?? 'test model', keywords: o.keywords ?? ['one', 'two', 'three'], ed25519: publicKey(s), x25519: x25519PublicKey(o.x ?? xs), code_hash: o.code ?? null, member, connectable: o.connectable });
    const r = this.append(s, 'agent.introduce', { ...q, ...(o.q ?? {}) }, o); if (!this.roots.has(k)) this.roots.set(k, r.index); this.latest.set(k, r.index); return { ...r, body };
  }
  root(s) { return this.roots.get(kidOf(s)); }
  form(founder, peer, o = {}) {
    const nonce = o.nonce ?? this.nonce(), { q, body, swarm_id } = sw.formPayload({ origin: this.origin, nonce, founder_member_index: this.root(founder), peer: { member_index: this.root(peer), actor_id: o.peerKid ?? kidOf(peer), latest_intro_index: this.latest.get(kidOf(peer)) }, title: 'A swarm', text: 'root text', code_hash: o.code });
    return { ...this.append(founder, 'swarm.form', { ...q, ...(o.q ?? {}) }, { ...o, nonce }), sid: swarm_id, body };
  }
  replay() { return new History(this.raw, { trust: this.trust, profiles: SWARMS }); }
  /** Drop the last entry and rewind its signer's chain to that signer's previous entry. */
  undo() { const e = this.entries.pop(); this.raw.pop(); const kid = e.actor_kid, prev = [...this.entries].reverse().find(x => x.actor_kid === kid); if (prev) this.last.set(kid, prev.payload.envelope); else this.last.delete(kid); }
  roster(sid) { return this.replay().swarms.swarmInfo(sid); }
  join(s, sid, target, o = {}) { return this.append(s, 'swarm.join', sw.joinPayload({ swarm_id: sid, member_index: this.root(s), target_member_index: this.root(target), roster_index: o.roster ?? this.roster(sid).roster_index }), o); }
  leave(s, sid, admission) { return this.append(s, 'swarm.leave', sw.leavePayload({ swarm_id: sid, member_index: this.root(s), admission_index: admission ?? this.replay().swarms.member(kidOf(s)).admission_index })); }
  propose(s, sid, o = {}) {
    const info = this.roster(sid), closes = o.closes ?? this.clock + this.size + 10;
    if (o.target) return this.append(s, 'swarm.propose', sw.ejectProposalPayload({ swarm_id: sid, roster_index: info.roster_index, roster_hash: info.roster_hash, target_member_index: this.root(o.target), closes }));
    return this.append(s, 'swarm.propose', sw.nameProposalPayload({ swarm_id: sid, roster_index: info.roster_index, roster_hash: info.roster_hash, base_name_index: o.base ?? info.name_index, name: o.name ?? 'New name', closes }).q);
  }
  vote(s, p, choice = 'yes', o = {}) { return this.append(s, 'swarm.vote', sw.votePayload(p, choice), o); }
  resolve(s, p, o = {}) { const ts = this.clock + this.size; return this.append(s, 'swarm.resolve', { ...this.replay().swarms.planResolve(p, ts), ...(o.q ?? {}) }, { ts }); }
  swarmGrant(s, sid, max = 2, o = {}) { const sw_ = this.replay().swarms, m = sw_.member(kidOf(s)), prev = sw_.grants.get(kidOf(s) + '\n' + sid); return this.append(s, 'swarm.grant', sw.swarmGrantPayload({ swarm_id: sid, owner_kid: kidOf(s), admission_index: m?.admission_index ?? 0, max, expires: o.expires ?? T + 100000, prev_grant_index: o.prev !== undefined ? o.prev : prev?.index ?? null })); }
  broadcast(s, sid, o = {}) { const ts = this.clock + this.size; let q; try { q = this.replay().swarms.planBroadcast(sid, kidOf(s), ts, ts + 100); } catch { const info = this.roster(sid); q = { swarm_id: sid, roster_index: info.roster_index, roster_hash: info.roster_hash, audience_mode: 'all', audience_hash: sw.audienceHash([]), recipient_count: 0, closes: ts + 100 }; } return this.append(s, 'swarm.broadcast', { ...q, ...(o.q ?? {}) }, { ts }); }
  deliver(s, start, to, toX, o = {}) {
    const h = this.replay(), b = h.swarms.broadcasts.get(start), r = h.swarms.member(kidOf(to)), nonce = this.nonce();
    const ct = sw.sealDelivery({ from_kid: kidOf(s), to_kid: kidOf(to), envelope_nonce: nonce, swarm_id: b.swarm_id, broadcast_index: start, membership_index: b.roster_index }, o.text ?? 'private', x25519PublicKey(toX));
    const g = h.swarms.grants.get(kidOf(to) + '\n' + b.swarm_id);
    const q = sw.deliveryPayload(ct, { broadcast_index: start, to_kid: kidOf(to), to_key_leaf_index: o.keyLeaf ?? r.key_leaf_index, grant_index: o.grant ?? g?.index ?? 0 });
    return { ...this.append(s, 'swarm.delivery', q, { ...o, nonce }), ciphertext: ct };
  }
}
/** charter, a, b, c introduced; a and b form a swarm. */
function pair() { const log = new SwarmLog(); log.charter(); log.intro(A, AX); log.intro(B, BX); log.intro(C, CX); const f = log.form(A, B); return { log, sid: f.sid, root: f.index }; }
const fails = (log, pattern, index = log.size - 1) => assert.throws(() => log.replay(), e => e.index === index && pattern.test(e.message), `expected ${pattern} at ${index}`);

test('swarms: §5.3-style payload checks of the ten types (R09-R13, R23, R30-R32)', () => {
  const o = { origin: 'log.test/aics', profiles: SWARMS }, base = sw.introducePayload({ model: 'm', keywords: ['a', 'b', 'c'], ed25519: publicKey(A), x25519: x25519PublicKey(AX) }).q;
  assert.deepEqual(payloadProblems('agent.introduce', base, T, o), []);
  assert.match(payloadProblems('agent.introduce', base, T, { origin: o.origin })[0], /no closed schema/);
  assert.match(payloadProblems('agent.introduce', { ...base, text: 'free text' }, T, o)[0], /members/);
  assert.match(payloadProblems('agent.introduce', { ...base, x25519: null }, T, o)[0], /both keys/);
  assert.match(payloadProblems('agent.introduce', { ...base, tier: 'unverified' }, T, o)[0], /neither/);
  assert.match(payloadProblems('agent.introduce', { ...base, connectable: false }, T, o)[0], /connectable true/);
  assert.match(payloadProblems('agent.introduce', { ...base, connectable: 1 }, T, o)[0], /bool/);
  assert.match(payloadProblems('agent.introduce', { ...base, member_index: 3 }, T, o)[0], /both null/);
  const e = { swarm_id: 'a'.repeat(64), kind: 'eject', roster_index: 1, roster_hash: 'b'.repeat(64), target_member_index: 2, closes: T + 604800 };
  assert.deepEqual(payloadProblems('swarm.propose', e, T, o), []); assert.match(payloadProblems('swarm.propose', { ...e, closes: T + 604801 }, T, o)[0], /604800/);
  assert.match(payloadProblems('swarm.propose', { ...e, kind: 'other' }, T, o)[0], /no closed schema/);
  assert.match(payloadProblems('swarm.propose', { ...e, kind: 'name' }, T, o)[0], /members/);
  assert.match(payloadProblems('swarm.vote', { proposal_index: 1, choice: 'abstain' }, T, o)[0], /swarm_choice/);
  assert.match(payloadProblems('swarm.resolve', { proposal_index: 1, outcome: 'tie', yes: 0, no: 0, electorate: 1 }, T, o)[0], /swarm_outcome/);
  const b = { swarm_id: 'a'.repeat(64), roster_index: 1, roster_hash: 'b'.repeat(64), audience_mode: 'all', audience_hash: 'c'.repeat(64), recipient_count: 1, closes: T + 86400 };
  assert.deepEqual(payloadProblems('swarm.broadcast', b, T, o), []); assert.match(payloadProblems('swarm.broadcast', { ...b, audience_mode: 'consenting' }, T, o)[0], /audience_mode/);
  assert.match(payloadProblems('swarm.broadcast', { ...b, closes: T + 86401 }, T, o)[0], /86400/);
  const g = { swarm_id: 'a'.repeat(64), owner_kid: kidOf(A), admission_index: 1, max: 1, expires: T, prev_grant_index: null };
  assert.match(payloadProblems('swarm.grant', g, T, o)[0], /expires after ts/); assert.deepEqual(payloadProblems('swarm.grant', { ...g, max: 0 }, T, o), []);
  const d = { broadcast_index: 1, to_kid: kidOf(B), to_key_leaf_index: 2, grant_index: 3, encryption: 'age-v1', eph_pk: b64u(new Uint8Array(32)), ct_hash: 'a'.repeat(64), size: 100 };
  assert.match(payloadProblems('swarm.delivery', d, T, o)[0], /sealed_scheme/); assert.match(payloadProblems('swarm.delivery', { ...d, encryption: 'x25519-xsalsa20-poly1305', size: 70000 }, T, o)[0], /65536/);
});

test('swarms: identifiers and bodies (R10, R11, R28, R38)', () => {
  const sid = sw.swarmId('o', 2, b64u(new Uint8Array(16)));
  assert.equal(sid, hexH(Buffer.concat([Buffer.from('AICS-SWARMS-1 swarm\n'), Buffer.from(canonicalize({ origin: 'o', founder_member_index: 2, nonce: b64u(new Uint8Array(16)) }))])));
  assert.notEqual(sid, sw.swarmId('o', 2, b64u(new Uint8Array(16).fill(1)))); assert.match(sw.channelSlug(sid), sw.RESERVED_CHANNEL);
  assert.equal(sw.channelSlug('00'.repeat(32)), 'swarm-' + 'a'.repeat(52)); assert.equal(sw.channelSlug('ff'.repeat(32)), 'swarm-' + '7'.repeat(51) + 'q');
  const code = b64u(new Uint8Array(32).fill(7)); assert.notEqual(sw.rendezvousHash('o', code), sw.rendezvousHash('p', code)); assert.equal(sw.parseJoinCode(`aics-swarm:${code}`), code);
  assert.throws(() => sw.rendezvousHash('o', b64u(new Uint8Array(31))), /32/);
  for (const bad of ['', ' lead', 'trail ', 'x\u007f', 'm'.repeat(129)]) assert.throws(() => sw.profileBody(bad, ['a', 'b', 'c']), /malformed/);
  for (const words of [['same', 'same', 'x'], ['a', 'b'], ['k'.repeat(33), 'b', 'c']]) assert.throws(() => sw.profileBody('ok', words), /malformed/);
  assert.equal(Buffer.from(sw.profileBody('é'.repeat(64), ['é'.repeat(16), 'é', 'é'])).toString(), JSON.stringify({ keywords: ['é'.repeat(16), 'é', 'é'], model: 'é'.repeat(64) }));
  assert.equal(sw.majority(0, 0), 'rejected'); assert.equal(sw.majority(1, 0), 'passed'); assert.equal(sw.majority(1, 1), 'rejected'); assert.equal(sw.majority(2, 1), 'passed');
});

test('swarms: introductions — one root per identity, updates keep the pair and tier, rotated or service keys cannot introduce (R11, R12)', () => {
  let { log } = pair(); log.intro(A, AX, { model: 'updated' }); const h = log.replay(); assert.equal(h.swarms.member(kidOf(A)).latest_intro_index, log.size - 1); assert.equal(h.swarms.arrivalWindow()[0], 3);
  ({ log } = pair()); log.append(A, 'agent.introduce', sw.introducePayload({ model: 'm', keywords: ['a', 'b', 'c'], ed25519: publicKey(A), x25519: x25519PublicKey(AX) }).q); fails(log, /key_reuse/);
  ({ log } = pair()); log.intro(A, AX, { x: seed(0x31) }); fails(log, /stale_key/);
  ({ log } = pair()); log.intro(A, AX, { q: { prev_intro_index: 3 } }); fails(log, /swarm_stale/);
  log = new SwarmLog(); log.charter(); log.intro(log.policy, AX); fails(log, /key_reuse/);
  log = new SwarmLog(); log.charter(); log.claim(A, AX, 'alice'); log.rotate(A, D, 'alice', 1); log.intro(A, AX); fails(log, /stale_key/);
  log = new SwarmLog(); log.charter(); log.claim(A, AX, 'alice'); log.intro(A, AX); log.post(A, 'named and introduced'); assert.equal(log.replay().swarms.member(kidOf(A)).claim_index, 1);
  log = new SwarmLog(); log.charter(); log.claim(A, AX, 'alice'); log.intro(A, seed(0x32)); fails(log, /stale_key/);
});

test('swarms: claiming a handle after introducing keeps seat and pair; an introduced key is never another identity\'s (R12, T12)', () => {
  let { log, sid } = pair(); log.claim(B, BX, 'bee'); const h = log.replay(); assert.equal(h.swarms.member(kidOf(B)).claim_index, log.size - 1); assert.equal(h.swarms.member(kidOf(B)).swarm_id, sid);
  assert.equal(h.swarms.member(kidOf(B)).key_leaf_index, log.size - 1);
  ({ log } = pair()); log.claim(B, seed(0x33), 'bee'); fails(log, /stale_key/);
  ({ log } = pair()); log.claim(D, DX, 'dee'); log.rotate(D, C, 'dee', log.size - 1); fails(log, /key_reuse/);
});

test('swarms: unnamed introduced identities post in ordinary channels and receive DMs under a base grant (§19)', () => {
  const { log } = pair(); log.post(C, 'an unnamed agent speaks', 'general');
  log.grant(C, kidOf(A), 1, T + 100000); log.dm(A, kidOf(C), x25519PublicKey(CX), 3, log.size - 1, 'hello c');
  assert.equal(log.replay().size, log.size);
  log.post(D, 'never introduced'); fails(log, /not a current key/);
});

test('swarms: formation needs two introduced loners, one signature, the derived ID and channel; races lose (R18, R28, T18)', () => {
  let { log, sid, root } = pair(); let info = log.roster(sid); assert.deepEqual(info.members.map(m => m.member_index), [1, 2]); assert.equal(info.roster_index, root); assert.equal(info.roster_hash, sw.rosterHash([{ member_index: 1, actor_id: kidOf(A) }, { member_index: 2, actor_id: kidOf(B) }]));
  ({ log } = pair()); log.form(C, B); fails(log, /swarm_stale/);
  ({ log } = pair()); log.form(A, C); fails(log, /swarm_membership.*loner/);
  ({ log } = pair()); log.intro(D, DX); log.form(C, D, { q: { swarm_id: 'f'.repeat(64) } }); fails(log, /digest_mismatch/);
  ({ log } = pair()); log.intro(D, DX); const n = log.nonce(); log.form(C, D, { nonce: n, q: { channel_sha256: 'e'.repeat(64) } }); fails(log, /swarm_channel/);
  ({ log } = pair()); log.intro(D, DX, { connectable: true }); log.intro(D, DX, { connectable: false }); log.form(C, D); fails(log, /swarm_stale/);
  ({ log } = pair()); log.form(C, C); fails(log, /distinct/);
  const code = sw.rendezvousHash('log.test/aics', b64u(new Uint8Array(32).fill(9)));
  log = new SwarmLog(); log.charter(); log.intro(A, AX, { code }); log.intro(B, BX, { code }); log.intro(C, CX);
  assert.equal(log.replay().swarms.rendezvous(code).state, 'pair'); assert.equal(log.replay().swarms.rendezvous(code, 1).target_member_index, 2);
  const f = log.form(A, B, { code }); assert.equal(f.sid, sw.codeSwarmId(log.origin, code)); assert.equal(log.replay().swarms.rendezvous(code, 3).state, 'join');
  log.intro(D, DX, { code }); log.form(C, D, { code }); fails(log, /swarm_stale|swarm_id_taken/);
  log = new SwarmLog(); log.charter(); log.intro(A, AX, { code }); log.intro(B, BX); log.form(A, B, { code }); fails(log, /rendezvous/);
});

test('swarms: join is automatic, cites the current roster and never merges swarms; leave needs only its admission; empty swarms retire (R19, R20)', () => {
  let { log, sid, root } = pair(); const j = log.join(C, sid, A); assert.equal(log.roster(sid).roster_index, j.index);
  log.intro(D, DX); log.join(D, sid, B, { roster: root }); fails(log, /swarm_stale/);
  ({ log, sid } = pair()); log.join(C, sid, C); fails(log, /swarm_stale/);
  ({ log, sid } = pair()); log.intro(D, DX); const other = log.form(C, D).sid; log.join(C, sid, A); fails(log, /leave the current swarm/);
  ({ log, sid, root } = pair()); log.join(C, sid, A); log.leave(B, sid, root); const h = log.replay(); assert.equal(h.swarms.agentInfo(2).connectable, false); assert.equal(h.swarms.agentInfo(2).swarm_id, null);
  ({ log, sid, root } = pair()); log.leave(B, sid, root + 1); fails(log, /swarm_stale/);
  ({ log, sid, root } = pair()); log.leave(B, sid); log.leave(A, sid); assert.equal(log.roster(sid).retired, true); log.join(C, sid, A, { roster: log.roster(sid).roster_index }); fails(log, /swarm_retired/);
  void other;
});

test('swarms: proposals, votes-cast majority and explicit resolution (R23-R26, T25, T26)', () => {
  const outcome = choices => { const { log, sid } = pair(); log.join(C, sid, A); const p = log.propose(A, sid).index; [A, B, C].forEach((s, n) => { if (choices[n]) log.vote(s, p, choices[n]); }); log.clock += 20; const r = log.resolve(C, p); return { log, sid, r, q: r.envelope.payload }; };
  assert.equal(outcome([]).q.outcome, 'rejected'); assert.equal(outcome(['yes']).q.outcome, 'passed'); assert.equal(outcome(['yes', 'no']).q.outcome, 'rejected');
  assert.equal(outcome(['yes', 'yes', 'no']).q.outcome, 'passed'); assert.equal(outcome(['yes', 'no', 'no']).q.outcome, 'rejected'); assert.equal(outcome(['yes']).q.electorate, 3);
  const passed = outcome(['yes']); const info = passed.log.roster(passed.sid); assert.equal(info.name_index, passed.r.index); assert.equal(info.name_body_index, passed.q.proposal_index);
  let { log, sid } = pair(); let p = log.propose(A, sid).index; log.vote(A, p); log.vote(B, p); log.append(A, 'swarm.resolve', { proposal_index: p, outcome: 'passed', yes: 2, no: 0, electorate: 2 }); fails(log, /swarm_proposal_open/);
  ({ log, sid } = pair()); p = log.propose(A, sid).index; log.vote(A, p); log.clock += 20; log.resolve(A, p, { q: { yes: 2 } }); fails(log, /swarm_result/);
  ({ log, sid } = pair()); p = log.propose(A, sid).index; log.vote(A, p); log.clock += 20; log.resolve(A, p); log.append(B, 'swarm.resolve', { proposal_index: p, outcome: 'passed', yes: 1, no: 0, electorate: 2 }); fails(log, /swarm_proposal_closed/);
  ({ log, sid } = pair()); p = log.propose(A, sid).index; log.vote(B, p, 'no'); log.vote(B, p, 'yes'); fails(log, /already_voted/);
  ({ log, sid } = pair()); p = log.propose(A, sid).index; log.clock += 20; log.vote(A, p); fails(log, /swarm_proposal_closed/);
  ({ log, sid } = pair()); p = log.propose(A, sid).index; log.vote(C, p); fails(log, /swarm_membership/);
  ({ log, sid } = pair()); p = log.propose(A, sid).index; log.join(C, sid, A); log.vote(A, p); fails(log, /swarm_stale/);
  ({ log, sid } = pair()); p = log.propose(A, sid).index; log.join(C, sid, A); const stale = log.resolve(C, p); assert.equal(stale.envelope.payload.outcome, 'stale'); assert.equal(log.replay().size, log.size);
  ({ log, sid } = pair()); log.propose(C, sid); fails(log, /swarm_membership/);
  ({ log, sid } = pair()); log.propose(A, sid, { target: A }); fails(log, /another current member/);
  ({ log, sid } = pair()); log.propose(A, sid, { base: 0 }); fails(log, /obsolete base/);
  ({ log, sid } = pair()); const p1 = log.propose(A, sid, { name: 'one' }).index, p2 = log.propose(B, sid, { name: 'two' }).index; log.vote(A, p1); log.vote(B, p2); log.clock += 20; log.resolve(A, p1);
  assert.equal(log.resolve(A, p2).envelope.payload.outcome, 'stale'); assert.equal(log.replay().size, log.size);
});

test('swarms: a passed eject removes the seat and blocks rejoining for exactly 24 hours (R21, T21)', () => {
  const { log, sid } = pair(); log.join(C, sid, A); const p = log.propose(A, sid, { target: C }).index; log.vote(A, p); log.vote(C, p, 'no'); log.vote(B, p); log.clock += 20;
  const r = log.resolve(B, p); assert.equal(r.envelope.payload.outcome, 'passed'); assert.equal(log.replay().swarms.member(kidOf(C)).swarm_id, null);
  const until = r.entry.ts + 86400, roster = log.roster(sid).roster_index;
  const blocked = log.size; log.join(C, sid, A, { ts: until - 1, roster }); assert.throws(() => log.replay(), e => e.index === blocked && /swarm_ejected/.test(e.message));
  log.undo(); log.join(C, sid, A, { ts: until, roster }); assert.equal(log.replay().swarms.member(kidOf(C)).swarm_id, sid);
});

test('swarms: members-only posting in the reserved channel, replies to its root (R29, T29)', () => {
  const { log, sid, root } = pair(), channel = sw.channelSlug(sid);
  log.post(A, 'member reply', channel); fails(log, /swarm_channel/); log.undo();
  const body = canonicalize({ channel, title: null, text: 'reply' }), q = { channel_sha256: hexH(utf8(channel)), parent_index: root, body_hash: hexH(body), size: body.length, title_sha256: null };
  log.append(A, 'post', q); log.append(B, 'post', { ...q, parent_index: log.size - 1 }); assert.equal(log.replay().size, log.size);
  log.append(C, 'post', q); fails(log, /swarm_membership/);
});

test('swarms: grants, the all-broadcast snapshot with disclosed skips, and deliveries (R30-R34, T30-T33)', () => {
  let { log, sid } = pair(); log.join(C, sid, A); log.broadcast(A, sid); fails(log, /swarm_empty_audience/);
  ({ log, sid } = pair()); log.join(C, sid, A); const g = log.swarmGrant(B, sid, 1).index; const start = log.broadcast(A, sid).index;
  let h = log.replay(), status = h.swarms.broadcastStatus(start, T);
  assert.deepEqual(status.recipients.map(r => [r.member_index, r.selected, r.exclusion]), [[2, true, null], [3, false, 'no_consent']]); assert.equal(status.excluded_count, 1);
  assert.equal(h.entries[start].payload.audience_hash, sw.audienceHash([kidOf(B)]));
  const d = log.deliver(A, start, B, BX, { text: 'for b only' }); h = log.replay();
  assert.equal(h.swarms.openDelivery(d.index, h.entries, d.ciphertext, BX).text, 'for b only'); assert.equal(h.swarms.broadcastStatus(start, T).state, 'complete');
  log.deliver(A, start, B, BX); fails(log, /swarm_duplicate_delivery/);
  log.undo(); log.deliver(A, start, C, CX); fails(log, /committed target set/); log.undo();
  const s2 = log.broadcast(A, sid, { q: { audience_hash: sw.audienceHash([kidOf(B)]), recipient_count: 1 } }); fails(log, /swarm_empty_audience/);
  void g; void s2;
  ({ log, sid } = pair()); log.join(C, sid, A); log.swarmGrant(B, sid, 2); log.broadcast(A, sid, { q: { audience_hash: sw.audienceHash([kidOf(B), kidOf(C)]), recipient_count: 2 } }); fails(log, /swarm_stale/);
  ({ log, sid } = pair()); log.swarmGrant(B, sid, 2); let st = log.broadcast(A, sid).index; log.deliver(A, st, B, BX, { keyLeaf: 99 }); fails(log, /stale_key/);
  ({ log, sid } = pair()); log.swarmGrant(B, sid, 2); st = log.broadcast(A, sid).index; log.clock += 200; log.deliver(A, st, B, BX); fails(log, /swarm_broadcast_closed/);
  ({ log, sid } = pair()); log.swarmGrant(B, sid, 2); st = log.broadcast(A, sid).index; log.deliver(A, st, B, BX, { grant: 0 }); fails(log, /stale_grant/);
  ({ log, sid } = pair()); log.swarmGrant(B, sid, 2, { prev: 7 }); fails(log, /stale_grant/);
  ({ log, sid } = pair()); log.swarmGrant(C, sid, 2); fails(log, /swarm_membership/);
  ({ log, sid } = pair()); const g1 = log.swarmGrant(B, sid, 2).index; st = log.broadcast(A, sid).index; log.leave(B, sid); log.join(B, sid, A); log.swarmGrant(B, sid, 2, { prev: g1 }); log.deliver(A, st, B, BX); fails(log, /swarm_stale/);
  ({ log, sid } = pair()); const gx = log.swarmGrant(B, sid, 2).index; log.swarmGrant(B, sid, 0, { prev: gx, expires: T + log.size }); log.broadcast(A, sid); fails(log, /swarm_empty_audience/);
});

test('swarms: signing rotation changes the roster revision, stales the snapshot and keeps the seat; revocation removes it (R22)', () => {
  const { log, sid, root } = pair(); log.claim(B, BX, 'bee'); const claim = log.size - 1; const p = log.propose(A, sid).index;
  log.append(B, 'x25519.rotate', { name_norm: 'bee', prev_event_index: claim, new_x25519: b64u(x25519PublicKey(seed(0x41))) }); assert.equal(log.roster(sid).roster_index, root);
  log.vote(B, p); const rot = log.rotate(B, D, 'bee', claim + 2); let h = log.replay();
  assert.equal(h.swarms.member(kidOf(D)).member_index, 2); assert.equal(log.roster(sid).roster_index, rot.index); assert.equal(h.swarms.member(kidOf(D)).admission_index, root);
  log.clock += 20; assert.equal(log.resolve(A, p).envelope.payload.outcome, 'stale');
  log.revoke(D, 'bee', rot.index); h = log.replay(); assert.equal(h.swarms.member(kidOf(D)).swarm_id, null); assert.equal(h.swarms.agentInfo(2).connectable, false);
  log.intro(D, DX); fails(log, /revoked|stale_key/);
});

/** A shared-secret (unverified tier) write: alg none, an unverified identifier, no signature, the policy attestation (§3.3, §5.1). */
function secretWrite(log, id, type, q) {
  const ts = log.clock + log.size, prev = log.last.get(id) ?? null;
  const e = { v: 1, protected: { alg: 'none', origin: log.origin, type, kid: id, created: ts, expires: ts + 300, nonce: log.nonce(), ...nextChain(prev), seen: null }, payload: q, auth: { scheme: 'shared-secret' }, sig: null };
  return log.append(null, type, q, { envelope: e, ts, mutate: entry => { entry.payload.attestation = b64u(sign(secretAttestationMessage(e, ts), log.policy)); } });
}
test('swarms: an unverified (chosen-secret) identity introduces and joins, is skipped as unverified, and cannot govern or grant (R13, T13)', () => {
  const { log, sid } = pair(), id = 'unverified:' + b64u(new Uint8Array(16).fill(5)), body = sw.profileBody('secret tier', ['x', 'y', 'z']);
  const intro = secretWrite(log, id, 'agent.introduce', { member_index: null, prev_intro_index: null, ed25519: null, x25519: null, tier: 'unverified', body_hash: hexH(body), size: body.length, code_hash: null, connectable: true });
  secretWrite(log, id, 'swarm.join', { swarm_id: sid, member_index: intro.index, target_member_index: 1, roster_index: log.roster(sid).roster_index });
  log.swarmGrant(B, sid, 1); const start = log.broadcast(A, sid).index, h = log.replay();
  assert.deepEqual(h.swarms.broadcastStatus(start, T).recipients.map(r => [r.member_index, r.exclusion]), [[2, null], [intro.index, 'unverified']]);
  assert.equal(h.swarms.swarmInfo(sid).members.find(m => m.member_index === intro.index).tier, 'unverified');
  const info = log.roster(sid);
  secretWrite(log, id, 'swarm.propose', { swarm_id: sid, kind: 'eject', roster_index: info.roster_index, roster_hash: info.roster_hash, target_member_index: 1, closes: log.clock + log.size + 10 }); fails(log, /tier_required|secret tier cannot authorize/);
  log.undo(); log.append(A, 'agent.introduce', { ...sw.introducePayload({ model: 'm', keywords: ['a', 'b', 'c'], ed25519: publicKey(D), x25519: x25519PublicKey(DX) }).q, tier: 'unverified', ed25519: null, x25519: null }); fails(log, /key_reuse|tier_required/);
});

test('history (decision 26): a (kid, nonce) carried by an earlier leaf is a replay forever, also after it expired', () => {
  const log = new TestLog(); log.charter(); log.claim(A, AX, 'alice'); const p = log.post(A, 'one');
  log.post(A, 'two', 'test', { nonce: p.envelope.protected.nonce, ts: p.entry.ts + 100000 });
  assert.throws(() => new History(log.raw, { trust: log.trust }), e => e.index === 3 && /reused nonce.*entry 2/.test(e.message));
  const log2 = new TestLog(); log2.charter(); log2.claim(A, AX, 'alice');
  const attempt = log2.envelope(A, 'post', { channel_sha256: hexH(utf8('test')), parent_index: null, body_hash: hexH(utf8('{}')), size: 2, title_sha256: null });
  log2.refusal(attempt, 'rate_limit'); log2.clock += 100000;
  log2.post(A, 'later', 'test', { nonce: attempt.protected.nonce });
  assert.throws(() => new History(log2.raw, { trust: log2.trust }), e => e.index === 3 && /reused nonce.*entry 2/.test(e.message));
  const log3 = new TestLog(); log3.charter(); log3.claim(A, AX, 'alice'); log3.post(A, 'one'); log3.post(A, 'two'); assert.equal(new History(log3.raw, { trust: log3.trust }).size, 4);
});

test('server vectors: the entries parse as canonical bytes and every kid on a swarm leaf is a did:key', () => {
  for (const b of raw) { const e = parseEntry(b); if (SWARMS_TYPES.includes(e.type)) assert.match(e.actor_kid, /^did:key:z6Mk/); }
  assert.equal(didKey(publicKey(seed(1))).startsWith('did:key:'), true);
});

// The npm client against the real aics-server with the SWARMS-1 profile bootstrapped (loopback HTTP, a production
// genesis on throwaway paths): introductions, formation, a join, a private broadcast with one delivery, the R08 read
// projections through AicsClient, and the client's own replay of the complete tiles compared with those projections.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { AicsClient } from '../dist/index.js';
import { generateKeypair, generateX25519Keypair, didKey } from '../dist/keys.js';
import { signEnvelope, nextChain, newNonce } from '../dist/envelope.js';
import { b64u } from '../dist/bytes.js';
import { History } from '../dist/history.js';
import { verifyCard } from '../dist/card.js';
import { HttpTileReader, readEntries, verifyCheckpoint } from '../dist/tlog.js';
import * as sw from '../dist/swarms.js';
/** AicsClient answers are null-prototype objects (strict JSON parsing); compare them as plain JSON. */
const plain = x => JSON.parse(JSON.stringify(x));
const here = fileURLToPath(new URL('..', import.meta.url)), serverDir = path.resolve(here, '../../packages/aics-server');
const available = spawnSync('uv', ['--version']).status === 0 && existsSync(path.join(serverDir, '.venv'));
async function boot(t) {
  const root = path.join(here, '.tmp', `swarms-${process.pid}-${Date.now()}`), owner = generateKeypair();
  for (const dir of ['.cache/uv', '.tmp']) mkdirSync(path.join(here, dir), { recursive: true });
  const child = spawn('uv', ['run', '--no-sync', 'python', '-I', path.join(here, 'test/python/serve_aics.py'), root, b64u(owner.publicKey), 'swarms'], { cwd: serverDir, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', UV_CACHE_DIR: path.join(here, '.cache/uv'), UV_PYTHON_DOWNLOADS: 'never', TMPDIR: path.join(here, '.tmp') } });
  let stderr = ''; child.stderr.on('data', d => { stderr += d; });
  t.after(() => { child.kill('SIGTERM'); rmSync(root, { recursive: true, force: true }); });
  const line = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('aics-server did not start: ' + stderr)), 60000);
    createInterface({ input: child.stdout }).once('line', l => { clearTimeout(timer); resolve(l); }); child.once('exit', code => { clearTimeout(timer); reject(new Error(`aics-server exited ${code}: ${stderr}`)); });
  });
  const pins = JSON.parse(line); return { ...pins, base: `http://127.0.0.1:${pins.port}` };
}
test('live: the npm client writes and verifies SWARMS-1 against aics-server', { skip: available ? false : 'uv or packages/aics-server/.venv is not available', timeout: 180000 }, async t => {
  const s = await boot(t), trustBundle = { origin: s.origin, log_vkey: s.log_vkey, policy_kid: s.policy_kid, owner_kid: s.owner_kid }, origin = s.origin;
  const card = await (await fetch(`${s.base}/.well-known/aics-card.json`)).json(), v = verifyCard(card, { trust: trustBundle });
  assert.deepEqual(v.problems, []); assert(v.profiles.includes('SWARMS-1'), v.spec);
  const profiles = v.profiles, trust = { origin, logKey: s.log_vkey, policyKid: s.policy_kid };
  const agents = ['a', 'b', 'c'].map(label => { const k = generateKeypair(), x = generateX25519Keypair(); return { label, k, x, kid: didKey(k.publicKey), last: null, client: new AicsClient({ baseUrl: s.base, allowHttp: true, signingKey: k.privateKey, trust, profiles }) }; });
  const [a, b, c] = agents;
  const write = async (who, type, q, body = null, nonce = undefined) => {
    const e = signEnvelope(q, who.k.privateKey, { origin, type, profiles, nonce, ...nextChain(who.last) }), r = await who.client.submit(e, body); who.last = e;
    return Number(/\/v2\/entries\/(\d+)$/.exec(r.location)[1]);
  };
  for (const who of agents) {
    const { q, body } = sw.introducePayload({ model: `Live model ${who.label}`, keywords: ['live', 'node', who.label], ed25519: who.k.publicKey, x25519: who.x.publicKey });
    who.root = await write(who, 'agent.introduce', q, body);
  }
  const nonce = newNonce(), f = sw.formPayload({ origin, nonce, founder_member_index: a.root, peer: { member_index: b.root, actor_id: b.kid, latest_intro_index: b.root }, title: 'Live swarm', text: 'Formed by the npm client.' });
  const root = await write(a, 'swarm.form', f.q, f.body, nonce);
  const info = await c.client.swarm(f.swarm_id); assert.equal(info.roster_index, root); assert.equal(info.channel, f.channel);
  const join = await write(c, 'swarm.join', sw.joinPayload({ swarm_id: f.swarm_id, member_index: c.root, target_member_index: a.root, roster_index: info.roster_index }));
  const now = Math.floor(Date.now() / 1000);
  const grant = await write(b, 'swarm.grant', sw.swarmGrantPayload({ swarm_id: f.swarm_id, owner_kid: b.kid, admission_index: root, max: 2, expires: now + 3600, prev_grant_index: null }));
  const reader = new HttpTileReader([`${s.base}/tiles`], { allowHttp: true });
  const replay = async () => { const note = await reader.read('checkpoint'), cp = verifyCheckpoint(note, s.log_vkey, { expectedOrigin: origin }); assert(cp.ok, cp.error); return new History(await readEntries(reader, cp.checkpoint.size), { trust: trustBundle, profiles }); };
  let h = await replay();
  const start = await write(a, 'swarm.broadcast', h.swarms.planBroadcast(f.swarm_id, a.kid, now, now + 600));
  h = await replay(); const bcast = h.swarms.broadcasts.get(start), dn = newNonce();
  const ct = sw.sealDelivery({ from_kid: a.kid, to_kid: b.kid, envelope_nonce: dn, swarm_id: f.swarm_id, broadcast_index: start, membership_index: bcast.roster_index }, 'live private content', b.x.publicKey);
  const delivery = await write(a, 'swarm.delivery', sw.deliveryPayload(ct, { broadcast_index: start, to_kid: b.kid, to_key_leaf_index: b.root, grant_index: grant }), ct, dn);
  h = await replay(); assert.equal(h.size, delivery + 1);
  // the projections the server serves equal this client's replay of the authenticated tiles
  const got = await a.client.swarm(f.swarm_id), mine = h.swarms.swarmInfo(f.swarm_id);
  assert.deepEqual(plain(got.members.items), mine.members); assert.equal(got.roster_hash, mine.roster_hash); assert.equal(got.roster_index, join);
  for (const who of agents) { const g = await a.client.agent(who.root), m = h.swarms.agentInfo(who.root); assert.equal(g.swarm_id, m.swarm_id); assert.equal(g.admission_index, m.admission_index); assert.equal(g.actor_id, who.kid); }
  const arrivals = await a.client.arrivals({ keyword: 'NODE' }), bodies = new Map();
  for (const e of h.entries) { const q = e.payload.envelope.payload; if (['agent.introduce', 'swarm.form'].includes(e.type)) { const r = await a.client.body(q.body_hash); if (r.state === 'available') bodies.set(q.body_hash, r.bytes); } }
  assert.deepEqual(plain(arrivals.rows), h.swarms.arrivals(h.entries, x => bodies.get(x), { keyword: 'NODE' }).rows);
  const status = await a.client.swarmBroadcast(start), local = h.swarms.broadcastStatus(start, status.evaluated_at);
  assert.deepEqual(plain(status.recipients.items), local.recipients); assert.equal(status.state, 'complete'); assert.equal(local.excluded_count, 1);
  const inbox = await b.client.swarmInbox(b.kid); assert.deepEqual(inbox.deliveries.items.map(r => r.index), h.swarms.inbox(b.kid).map(r => r.index));
  const fetched = await b.client.body(h.entries[delivery].payload.ct_hash); assert.equal(fetched.state, 'available');
  assert.equal(h.swarms.openDelivery(delivery, h.entries, fetched.bytes, b.x.privateKey).text, 'live private content');
  assert.equal((await a.client.rendezvous(sw.rendezvousHash(origin, b64u(new Uint8Array(32).fill(3))))).state, 'waiting');
  const part = await a.client.checkpointPart(got.checkpoint.note_hash); assert.equal(part.offset, 0);
});

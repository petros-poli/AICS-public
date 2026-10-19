// The client against the real aics-server of this repository (a production genesis on throwaway paths, loopback HTTP):
// native writes with the §12.1 request signature, receipts, §14.3 bundles, bodies, a sealed DM, a logged refusal, the
// text gate's onboarding, the tiles, the complete history and the card. Trust comes from the server's key file.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { AicsClient, RefusalError, HttpsGateClient, onboard } from '../dist/index.js';
import { generateKeypair, generateX25519Keypair, didKey } from '../dist/keys.js';
import { signEnvelope, nextChain, newNonce } from '../dist/envelope.js';
import { canonicalize, parseJson } from '../dist/canonical.js';
import { b64u, hexH, utf8 } from '../dist/bytes.js';
import { seal, ciphertextMetadata, openSealed } from '../dist/sealed.js';
import { History } from '../dist/history.js';
import { supAssetDescriptor } from '../dist/registry.js';
import { verifyCard } from '../dist/card.js';
import { HttpTileReader, TileTree, readEntries, verifyCheckpoint, parseNote, parseCheckpoint } from '../dist/tlog.js';
const here = fileURLToPath(new URL('..', import.meta.url)), serverDir = path.resolve(here, '../../packages/aics-server');
const available = spawnSync('uv', ['--version']).status === 0 && existsSync(path.join(serverDir, '.venv'));
async function boot(t) {
  const root = path.join(here, '.tmp', `server-${process.pid}-${Date.now()}`), owner = generateKeypair();
  for (const dir of ['.cache/uv', '.tmp']) mkdirSync(path.join(here, dir), { recursive: true });
  const child = spawn('uv', ['run', '--no-sync', 'python', '-I', path.join(here, 'test/python/serve_aics.py'), root, b64u(owner.publicKey)], { cwd: serverDir, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', UV_CACHE_DIR: path.join(here, '.cache/uv'), UV_PYTHON_DOWNLOADS: 'never', TMPDIR: path.join(here, '.tmp') } });
  let stderr = ''; child.stderr.on('data', d => { stderr += d; });
  t.after(() => { child.kill('SIGTERM'); rmSync(root, { recursive: true, force: true }); });
  const line = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('aics-server did not start: ' + stderr)), 60000);
    createInterface({ input: child.stdout }).once('line', l => { clearTimeout(timer); resolve(l); }); child.once('exit', code => { clearTimeout(timer); reject(new Error(`aics-server exited ${code}: ${stderr}`)); });
  });
  const pins = JSON.parse(line); return { ...pins, owner, base: `http://127.0.0.1:${pins.port}` };
}
const post = text => { const body = canonicalize({ channel: 'live', title: null, text }); return { q: { channel_sha256: hexH(utf8('live')), parent_index: null, body_hash: hexH(body), size: body.length, title_sha256: null }, body }; };
const claimQ = (k, x, name, grant = null) => ({ name_norm: name, prev_event_index: null, ed25519: b64u(k.publicKey), x25519: b64u(x.publicKey), tier: 'verified', recovery_kid: null, recovery_pop: null, initial_grant: grant });
test('live: the npm client against aics-server', { skip: available ? false : 'uv or packages/aics-server/.venv is not available', timeout: 180000 }, async t => {
  const s = await boot(t), trustBundle = { origin: s.origin, log_vkey: s.log_vkey, policy_kid: s.policy_kid, owner_kid: s.owner_kid };
  const trust = { origin: s.origin, logKey: s.log_vkey, policyKid: s.policy_kid }, origin = s.origin;
  const alice = generateKeypair(), ax = generateX25519Keypair(), bob = generateKeypair(), bx = generateX25519Keypair();
  const A = new AicsClient({ baseUrl: s.base, allowHttp: true, signingKey: alice.privateKey, trust, profiles: ['SUP-1'] });
  const B = new AicsClient({ baseUrl: s.base, allowHttp: true, signingKey: bob.privateKey, trust, profiles: ['SUP-1'] });
  /** The index a write landed at, authenticated: the bundle at the Location index carries exactly that entry. */
  const landed = async (client, r) => { const index = Number(/\/v2\/entries\/(\d+)$/.exec(r.location)[1]), b = await client.entry(index); assert.equal(b.verification.entryHash, r.entryHash); return { index, bundle: b }; };
  let aliceLast, bobIndex, dmIndex, dmEnvelope;
  await t.test('name.claim by POST /v2/entries: entry, receipt and bundle verify under the pinned keys', async () => {
    const e = signEnvelope(claimQ(alice, ax, 'alice-node'), alice.privateKey, { origin, type: 'name.claim' }), r = await A.submit(e);
    assert.equal(r.receipt.origin, origin); assert.equal(r.receipt.submitted_at, r.entry.ts); assert.equal(r.entry.actor_kid, didKey(alice.publicKey));
    const { index, bundle } = await landed(A, r); assert.equal(index, 1); assert.equal(bundle.verification.history, 'incomplete'); aliceLast = e;
    const be = signEnvelope(claimQ(bob, bx, 'bob-node', { sender_kid: didKey(alice.publicKey), max: 2, expires: Math.floor(Date.now() / 1000) + 3600 }), bob.privateKey, { origin, type: 'name.claim' });
    bobIndex = (await landed(B, await B.submit(be))).index;
  });
  await t.test('post with a public body: the bundle carries it, GET /v2/bodies/{hash} returns the exact bytes', async () => {
    const { q, body } = post('hello from node'), e = signEnvelope(q, alice.privateKey, { origin, type: 'post', ...nextChain(aliceLast) }), r = await A.submit(e, body); aliceLast = e;
    const { bundle } = await landed(A, r); assert.equal(Buffer.from(bundle.verification.body).toString(), Buffer.from(body).toString()); assert.equal(bundle.bodyStatus, 'available');
    const got = await B.body(q.body_hash); assert.equal(got.state, 'available'); assert.equal(Buffer.from(got.bytes).toString(), Buffer.from(body).toString());
  });
  await t.test('a sealed DM under the initial grant opens for the recipient from the verified bundle', async () => {
    const nonce = newNonce(), chain = nextChain(aliceLast), to = didKey(bob.publicKey), ct = seal({ from_kid: didKey(alice.publicKey), to_kid: to, envelope_nonce: nonce }, 'private — for bob', bx.publicKey);
    dmEnvelope = signEnvelope({ to_kid: to, to_key_leaf_index: bobIndex, ...ciphertextMetadata(ct), grant_index: bobIndex, ...chain }, alice.privateKey, { origin, type: 'dm', nonce, ...chain });
    const r = await A.submit(dmEnvelope, ct); aliceLast = dmEnvelope; const { index, bundle } = await landed(B, r); dmIndex = index;
    assert.equal(openSealed(bundle.verification.body, bx.privateKey, { envelope: bundle.verification.envelope, recipientKid: to }).text, 'private — for bob');
  });
  await t.test('a replayed write is a logged refusal with its receipt, naming the accepted entry', async () => {
    await assert.rejects(() => A.submit(dmEnvelope, null), err => { assert(err instanceof RefusalError, String(err)); assert.equal(err.reasonCode, 'replay'); assert.equal(err.conflictIndex, dmIndex); assert.equal(err.entry.actor_kid, s.policy_kid); assert.equal(err.receipt.submitted_at, err.entry.ts); return true; });
  });
  await t.test('onboarding at the HTTPS text gate: the proposal is inspected, the claim entry and receipt verify', async () => {
    const carol = generateKeypair(), cx = generateX25519Keypair(), gate = new HttpsGateClient(`${s.base}/t`, { allowHttp: true });
    try { const r = await onboard(gate, { name: 'carol-node', signingKey: carol.privateKey, encryptionKey: cx.privateKey, origin, logKey: s.log_vkey }); assert.equal(r.kid, didKey(carol.publicKey)); assert.equal(r.entry.payload.envelope.auth.scheme, 'text-ed25519'); assert(r.receipt); }
    finally { gate.close(); }
  });
  await t.test('SUP-1: the owner publishes a task and awards a submission; the award pays a hosting spend', async () => {
    const O = new AicsClient({ baseUrl: s.base, allowHttp: true, signingKey: s.owner.privateKey, trust, profiles: ['SUP-1'] }), asset = hexH(canonicalize(supAssetDescriptor(origin)));
    const taskBody = canonicalize({ title: 'review', text: 'review the npm client' }), now = Math.floor(Date.now() / 1000);
    const task = signEnvelope({ body_hash: hexH(taskBody), size: taskBody.length, asset_hash: asset, reward: 5, max_awards: 1, closes: now + 3600 }, s.owner.privateKey, { origin, type: 'sup.task', profiles: ['SUP-1'] });
    const taskIndex = (await landed(O, await O.submit(task, taskBody))).index;
    const { q, body } = post('my review'), sub = signEnvelope(q, alice.privateKey, { origin, type: 'post', ...nextChain(aliceLast) }); aliceLast = sub;
    const subIndex = (await landed(A, await A.submit(sub, body))).index;
    const award = signEnvelope({ source: 'task', account_kid: didKey(alice.publicKey), task_index: taskIndex, submission_index: subIndex, asset_hash: asset, amount: 5 }, s.owner.privateKey, { origin, type: 'sup.credit', profiles: ['SUP-1'], ...nextChain(task) });
    await O.submit(award);
    const spend = signEnvelope({ purpose: 'hosting', ref_index: null, asset_hash: asset, amount: 2, bytes: 0 }, alice.privateKey, { origin, type: 'sup.spend', profiles: ['SUP-1'], ...nextChain(aliceLast) }); aliceLast = spend;
    await A.submit(spend);
    const over = signEnvelope({ purpose: 'hosting', ref_index: null, asset_hash: asset, amount: 9, bytes: 0 }, alice.privateKey, { origin, type: 'sup.spend', profiles: ['SUP-1'], ...nextChain(aliceLast) });
    await assert.rejects(() => A.submit(over), err => err instanceof RefusalError && err.reasonCode === 'insufficient_balance');
  });
  await t.test('the tiles authenticate against the checkpoint and the complete history replays', async () => {
    const reader = new HttpTileReader([`${s.base}/tiles`], { allowHttp: true }), note = await reader.read('checkpoint');
    const cp = verifyCheckpoint(note, s.log_vkey, { expectedOrigin: origin }); assert(cp.ok, cp.error); assert.equal(cp.freshness, 'unproven');
    const tree = new TileTree(reader, cp.checkpoint.size); await tree.verifyRoot(cp.checkpoint);
    const entries = await readEntries(reader, cp.checkpoint.size), h = new History(entries, { trust: trustBundle, profiles: ['SUP-1'] });
    assert.equal(h.size, cp.checkpoint.size); assert.deepEqual(h.policyEvents, [0]); assert.equal(h.name('alice-node').kid, didKey(alice.publicKey)); assert.equal(h.name('carol-node').tier, 'verified');
    assert.equal(h.entries[dmIndex].type, 'dm'); assert(h.entries.some(e => e.type === 'refusal' && e.payload.reason_code === 'replay'));
    assert.equal(h.balances.get('alice-node'), 3); assert(h.entries.some(e => e.type === 'refusal' && e.payload.reason_code === 'insufficient_balance'));
    const { result } = await A.checkpoint(); assert(result.ok, result.error);
  });
  await t.test('the card is signed by the pinned policy key and follows §13.1: its ciphertext budget is the one the server enforces (F27 retired)', async () => {
    const r = await fetch(`${s.base}/.well-known/aics-card.json`), bytes = new Uint8Array(await r.arrayBuffer()), v = verifyCard(bytes, { trust: trustBundle });
    assert.equal(v.spec, 'AICS-1+SUP-1'); assert.deepEqual(v.problems, []);
    const card = parseJson(bytes); assert.equal(card.policy_kid, s.policy_kid);
    const budget = card.retention.ciphertext_budget_bytes, limits = await (await fetch(`${s.base}/v2/limits`)).json();
    assert(Number.isInteger(budget) && budget > 0); assert.equal(budget, limits.limits.ciphertext_budget_bytes);
  });
});

// §14.3 step 2 (complete history), §14.3 bundles and packages, and §14.6 gossip on logs made with the test log builder.
import test from 'node:test';
import assert from 'node:assert/strict';
import { History } from '../dist/history.js';
import { verifyBundle } from '../dist/bundle.js';
import { b64, b64u, hexH, utf8 } from '../dist/bytes.js';
import { canonicalize } from '../dist/canonical.js';
import { entryHash } from '../dist/entry.js';
import { supAssetDescriptor } from '../dist/registry.js';
import { nextChain } from '../dist/envelope.js';
import { openSealed } from '../dist/sealed.js';
import { publicKey, sign, x25519PublicKey } from '../dist/keys.js';
import { charterBytes, rotationBytes } from '../dist/history.js';
import * as tlog from '../dist/tlog.js';
import { TestLog, seed, kidOf, vkeyOf, T } from './log-builder.mjs';
const alice = seed(0xb1), bob = seed(0xb2), carol = seed(0xb4), alice2 = seed(0xb5), ax = seed(0xc1), bx = seed(0xc2), cx = seed(0xc4);
/** charter, alice (closed inbox), bob (one message from alice allowed), carol (open to all, two messages). */
function base() {
  const log = new TestLog(); log.charter();
  log.claim(alice, ax, 'alice'); log.claim(bob, bx, 'bob', { sender_kid: kidOf(alice), max: 1, expires: T + 3600 }); log.claim(carol, cx, 'carol', { sender_kid: '*', max: 2, expires: T + 3600 });
  return log;
}
const replay = log => new History(log.raw, { trust: log.trust });
const fails = (log, pattern, index = log.size - 1) => assert.throws(() => replay(log), e => e.index === index && pattern.test(e.message), `expected ${pattern} at ${index}`);
test('history: a consistent log replays; names, keys, grants and DMs are tracked by index', () => {
  const log = base(), dm = log.dm(alice, kidOf(bob), x25519PublicKey(bx), 2, 2, 'hi bob');
  log.dm(bob, kidOf(carol), x25519PublicKey(cx), 3, 3); log.dm(alice, kidOf(carol), x25519PublicKey(cx), 3, 3); log.post(alice, 'hello');
  const h = replay(log); assert.equal(h.size, 8); assert.equal(h.name('bob').kid, kidOf(bob)); assert.equal(h.currentName(kidOf(alice)), 'alice'); assert.deepEqual(h.policyEvents, [0]);
  assert.equal(openSealed(dm.ciphertext, bx, { envelope: dm.envelope, recipientKid: kidOf(bob) }).text, 'hi bob');
});
test('history: consent (§9) — no grant, an exhausted grant, a wildcard total, an exact revocation never falling back', () => {
  let log = base(); log.dm(bob, kidOf(alice), x25519PublicKey(ax), 1, 1); fails(log, /consent/);
  log = base(); log.dm(alice, kidOf(bob), x25519PublicKey(bx), 2, 2); log.dm(alice, kidOf(bob), x25519PublicKey(bx), 2, 2); fails(log, /consent/);
  log = base(); log.dm(alice, kidOf(carol), x25519PublicKey(cx), 3, 3); log.dm(bob, kidOf(carol), x25519PublicKey(cx), 3, 3); log.dm(bob, kidOf(carol), x25519PublicKey(cx), 3, 3); fails(log, /consent/);
  log = base(); const g = log.grant(carol, kidOf(alice), 0, T + 4); log.dm(alice, kidOf(carol), x25519PublicKey(cx), 3, 3); fails(log, /consent/);
  log = base(); log.grant(carol, kidOf(alice), 0, T + 4); log.dm(alice, kidOf(carol), x25519PublicKey(cx), 3, g.index); fails(log, /consent/);
  log = base(); log.dm(alice, kidOf(bob), x25519PublicKey(bx), 2, 2, 'x', { ts: T + 3600 }); fails(log, /consent/);
  log = base(); log.grant(carol, kidOf(alice), 5, T + 3600, null); log.grant(carol, kidOf(alice), 5, T + 3600, null); fails(log, /grant predecessor/);
});
test('history: recipient key provenance and capsule ownership', () => {
  let log = base(); log.dm(alice, kidOf(bob), x25519PublicKey(bx), 1, 2); fails(log, /recipient key provenance/);
  log = base(); log.append(bob, 'x25519.rotate', { name_norm: 'bob', prev_event_index: 2, new_x25519: b64u(x25519PublicKey(seed(0xc9))) }); log.dm(alice, kidOf(bob), x25519PublicKey(bx), 2, 2); fails(log, /recipient key provenance/);
  log = base(); log.append(bob, 'x25519.rotate', { name_norm: 'bob', prev_event_index: 2, new_x25519: b64u(x25519PublicKey(seed(0xc9))) }); log.dm(alice, kidOf(bob), x25519PublicKey(seed(0xc9)), 4, 2); assert.equal(replay(log).size, 6);
});
test('history: §4.2-4.3 per-key sequences and nonce uniqueness come from the leaves', () => {
  let log = base(); const p = log.post(alice, 'one'); log.append(alice, 'post', p.envelope.payload, { chainFrom: p.envelope, nonce: p.envelope.protected.nonce }); fails(log, /reused nonce/);
  log = base(); log.post(alice, 'one'); log.append(alice, 'post', log.entries[4].payload.envelope.payload, { chainFrom: log.entries[1].payload.envelope }); fails(log, /sequence/);
  log = base(); log.post(alice, 'one', 'test', { chainFrom: null }); fails(log, /sequence/);
});
test('history: §7 claims, key reuse, two-signature rotation, first rotation wins, revocation is permanent', () => {
  let log = base(); log.claim(seed(0xb9), seed(0xc9), 'alice'); fails(log, /duplicate claim/);
  log = base(); log.claim(alice, ax, 'alice-two', null, { chainFrom: log.entries[1].payload.envelope }); fails(log, /duplicate claim or key reuse/);
  log = base(); log.claim(log.policy, ax, 'service'); fails(log, /distinct/);
  log = base(); log.rotate(alice, alice2, 'alice', 1); log.post(alice2, 'from the new key'); const h = replay(log); assert.equal(h.name('alice').kid, kidOf(alice2)); assert.equal(h.currentName(kidOf(alice)), undefined);
  log = base(); log.rotate(alice, alice2, 'alice', 1); log.post(alice, 'from the old key'); fails(log, /not a current key/);
  log = base(); log.rotate(alice, alice2, 'alice', 1); log.rotate(alice2, seed(0xb6), 'alice', 1); fails(log, /fork/);
  log = base(); log.rotate(alice, bob, 'alice', 1); fails(log, /key reuse/);
  log = base(); const data = rotationBytes({ origin: log.origin, name_norm: 'alice', prev_event_index: 1, new_ed25519: b64u(publicKey(alice2)), new_x25519: null, new_tier: 'verified', mode: 'rotate' });
  log.append(alice, 'key.rotate', { mode: 'rotate', name_norm: 'alice', prev_event_index: 1, new_ed25519: b64u(publicKey(alice2)), new_x25519: null, new_tier: 'verified', sig_old: { scheme: 'ed25519', signature: b64u(sign(data, alice)) }, sig_new: { scheme: 'ed25519', signature: b64u(sign(data, bob)) } }); fails(log, /sig_new/);
  log = base(); log.revoke(alice, 'alice', 1); log.post(alice, 'after revocation'); fails(log, /not a current key/);
  log = base(); log.revoke(alice, 'alice', 1); log.claim(seed(0xba), seed(0xca), 'alice'); fails(log, /duplicate claim/);
});
test('history: administrative entries need the pinned keys; leaf 0 is the dual-signed charter', () => {
  let log = base(); log.append(alice, 'tombstone', { target_index: 3, reason_code: 'erasure', evidence_hash: null, receipt_hash: null }); fails(log, /administrative actor/);
  log = base(); const dm = log.dm(alice, kidOf(bob), x25519PublicKey(bx), 2, 2); log.append(log.policy, 'tombstone', { target_index: dm.index, reason_code: 'erasure', evidence_hash: null, receipt_hash: null }); fails(log, /ciphertext tombstone/);
  log = base(); log.append(log.policy, 'tombstone', { target_index: 9, reason_code: 'order', evidence_hash: null, receipt_hash: null }); fails(log, /earlier entry/);
  log = base(); log.charter(); fails(log, /policy chain/);
  log = new TestLog(); log.claim(alice, ax, 'alice'); log.charter(); fails(log, /charter|policy chain/, 1);
  log = new TestLog(); const doc = utf8('charter'), q = { kind: 'charter', document_hash: hexH(doc), size: doc.length, prev_policy_index: null, effective_after: 0, not_before: T, log_kid: kidOf(log.log), policy_kid: kidOf(log.policy), owner_kid: kidOf(log.owner) };
  log.append(log.policy, 'policy', { ...q, log_sig: b64u(sign(charterBytes(q), log.policy)) }); fails(log, /countersignature/, 0);
  log = base(); log.refusal(log.envelope(alice, 'post', { channel_sha256: hexH(utf8('test')), parent_index: null, body_hash: hexH(utf8('{}')), size: 2, title_sha256: null }), 'rate_limit'); assert.equal(replay(log).size, 5);
});
test('history: a refusal records the refused (kid, nonce) so the attempt cannot be accepted inside its window', () => {
  const log = base(), attempt = log.envelope(alice, 'post', { channel_sha256: hexH(utf8('test')), parent_index: null, body_hash: hexH(utf8('{}')), size: 2, title_sha256: null });
  log.refusal(attempt, 'rate_limit'); log.append(alice, 'post', attempt.payload, { envelope: attempt }); fails(log, /reused nonce/);
});
test('bundles: a bundle from the test log verifies; its history stays incomplete; a witness quorum is enforced', () => {
  const log = base(), p = log.post(alice, 'bundled'), witness = { name: 'witness.test/w1', seed: seed(0xd1), time: T + 100 }, note = log.note(log.size, witness);
  const proof = [];
  const leaves = log.raw.map(tlog.leafHash); const path = (m, lo, hi) => { if (hi - lo === 1) return; const k = tlog.splitPower(hi - lo); if (m < k) { path(m, lo, lo + k); proof.push(tlog.merkleRoot(leaves.slice(lo + k, hi))); } else { path(m - k, lo + k, hi); proof.push(tlog.merkleRoot(leaves.slice(lo, lo + k))); } };
  path(p.index, 0, log.size);
  const bundle = { entry_bytes: b64u(p.bytes), index: p.index, inclusion_proof: proof.map(b64), checkpoint_note: b64u(note), envelope: p.envelope, body_or_ct: b64u(p.body) };
  const wv = vkeyOf(witness.name, witness.seed, 4), v = verifyBundle(bundle, { logKey: log.trust.log_vkey, witnesses: [wv], quorum: 1 });
  assert.equal(v.history, 'incomplete'); assert.equal(Buffer.from(v.body).toString(), Buffer.from(p.body).toString());
  assert.equal(verifyBundle(bundle, { logKey: log.trust.log_vkey, witnesses: [wv], quorum: 1, now: T + 150, maxAgeSeconds: 300 }).freshness, 'verified');
  assert.throws(() => verifyBundle(bundle, { logKey: log.trust.log_vkey, witnesses: [wv], quorum: 1, now: T + 401, maxAgeSeconds: 300 }), /quorum/);
  assert.throws(() => verifyBundle({ ...bundle, checkpoint_note: b64u(log.note()) }, { logKey: log.trust.log_vkey, witnesses: [wv], quorum: 1 }), /quorum/);
  assert.throws(() => verifyBundle({ ...bundle, body_or_ct: b64u(utf8('{}')) }, { logKey: log.trust.log_vkey }), /body/);
  assert.throws(() => verifyBundle({ ...bundle, inclusion_proof: [...bundle.inclusion_proof, b64(new Uint8Array(32))] }, { logKey: log.trust.log_vkey }), /inclusion/);
  assert.throws(() => verifyBundle({ ...bundle, entry_bytes: b64u(utf8(Buffer.from(p.bytes).toString().replace('{', '{ '))) }, { logKey: log.trust.log_vkey }), /inclusion|canonical/);
  assert.throws(() => verifyBundle(bundle, { logKey: log.trust.log_vkey, origin: 'other.test/aics' }), /origin/);
});
test('gossip: a valid consistency proof suffices; a bad proof alone never proves a split', () => {
  const log = base(), small = log.note(3); log.post(alice, 'more'); const big = log.note();
  const proof = []; // consistency 3 -> 5 by the RFC 9162 subproof
  const leaves = log.raw.map(tlog.leafHash), sub = (m, lo, hi, b) => { const n = hi - lo; if (m === n) { if (!b) proof.push(tlog.merkleRoot(leaves.slice(lo, hi))); return; } const k = tlog.splitPower(n); if (m <= k) { sub(m, lo, lo + k, b); proof.push(tlog.merkleRoot(leaves.slice(lo + k, hi))); } else { sub(m - k, lo + k, hi, false); proof.push(tlog.merkleRoot(leaves.slice(lo, lo + k))); } };
  sub(3, 0, log.size, true);
  assert.equal(tlog.classifyGossip(small, big, { logKey: log.trust.log_vkey, proof }).relation, 'consistent');
  assert.equal(tlog.classifyGossip(small, big, { logKey: log.trust.log_vkey, proof: [new Uint8Array(32)] }).relation, 'consistency-unproven');
  assert.equal(tlog.classifyGossip(small, big, { logKey: log.trust.log_vkey, largerEntries: log.raw.slice(0, 4) }).relation, 'consistency-unproven', 'an incomplete prefix proves nothing');
  const tampered = [...log.raw]; tampered[4] = utf8('{}'); assert.equal(tlog.classifyGossip(small, big, { logKey: log.trust.log_vkey, largerEntries: tampered }).relation, 'consistency-unproven', 'unauthenticated entries prove nothing');
  assert.equal(tlog.classifyGossip(small, big, { logKey: log.trust.log_vkey, largerEntries: log.raw }).relation, 'consistent');
  const other = new TestLog(); other.origin = 'other.test/aics'; assert.equal(tlog.classifyGossip(small, other.note(0), { logKey: log.trust.log_vkey }).relation, 'not-evidence');
});
test('notes: verifyNote reports why a note is or is not evidence', () => {
  const log = base(), note = Buffer.from(log.note()).toString(), vk = log.trust.log_vkey;
  assert.equal(tlog.verifyNote(note, vk).ok, true); assert.equal(tlog.verifyNote(note, vk, { expectedOrigin: 'x.test/a' }).reason, 'origin');
  const blob = Buffer.from(note.trimEnd().split(' ').at(-1), 'base64'); blob[20] ^= 1;
  assert.equal(tlog.verifyNote(note.replace(/ [A-Za-z0-9+/=]+\n$/, ' ' + blob.toString('base64') + '\n'), vk).reason, 'bad_signature');
  const line = note.split('\n\n')[1]; assert.equal(tlog.verifyNote(note + line, vk).reason, 'duplicate_recognized');
  assert.equal(tlog.verifyNote(note.split('\n\n')[0] + '\n\n— unknown.test/k ' + b64(new Uint8Array(68)) + '\n', vk).reason, 'no_log_signature');
  assert.equal(tlog.verifyNote('not a note', vk).reason, 'malformed');
  assert.equal(tlog.verifyNote(note, vk, { witnesses: [vkeyOf('w.test/w', seed(0xd2), 4)], quorum: 1 }).reason, 'quorum');
});
test('tiles: readEntries falls back from a retired partial bundle to its full replacement', async () => {
  const log = new TestLog(); log.charter(); for (let i = 0; i < 3; i++) log.post(alice, 'p' + i);
  const bundle = Buffer.concat(log.raw.map(e => Buffer.concat([Buffer.from([e.length >> 8, e.length & 255]), Buffer.from(e)])));
  const entries = await tlog.readEntries(new tlog.MemoryTileReader({ 'tile/entries/000.p/4': new Uint8Array(bundle) }), 4); assert.equal(entries.length, 4);
  const full = Array.from({ length: 256 }, (_, i) => utf8('e' + i)), fullBundle = Buffer.concat(full.map(e => Buffer.concat([Buffer.from([0, e.length]), Buffer.from(e)])));
  const fallback = await tlog.readEntries(new tlog.MemoryTileReader({ 'tile/entries/000': new Uint8Array(fullBundle) }), 4); assert.deepEqual(fallback.map(e => Buffer.from(e).toString()), ['e0', 'e1', 'e2', 'e3']);
  assert.equal(await tlog.readEntries(new tlog.MemoryTileReader({}), 4), null);
  assert.equal(nextChain(null).seq, 0); assert.equal(hexH(canonicalize({})), hexH(utf8('{}'))); assert.equal(publicKey(alice).length, 32);
});

// ---------------------------------------------------------------- AICS-1+SUP-1 (§20)
function supLog() {
  const log = new TestLog('log.test/aics', ['SUP-1']); log.charter(); log.claim(alice, ax, 'alice'); log.claim(bob, bx, 'bob');
  const asset = hexH(canonicalize(supAssetDescriptor(log.origin))), taskBody = canonicalize({ title: 'translate', text: 'translate the charter' });
  const task = log.append(log.owner, 'sup.task', { body_hash: hexH(taskBody), size: taskBody.length, asset_hash: asset, reward: 5, max_awards: 2, closes: T + 3600 });
  const submission = log.post(alice, 'done');
  const award = (sub, kid, amount = 5) => log.append(log.owner, 'sup.credit', { source: 'task', account_kid: kid, task_index: task.index, submission_index: sub.index, asset_hash: asset, amount });
  return { log, asset, task, submission, award };
}
const supReplay = log => new History(log.raw, { trust: log.trust, profiles: ['SUP-1'] });
const supFails = (log, pattern) => assert.throws(() => supReplay(log), e => e.index === log.size - 1 && pattern.test(e.message), String(pattern));
test('SUP-1: a task award, a priced and completed owner action, its payment and a hosting spend replay with balances', () => {
  const { log, asset, submission, award } = supLog(); award(submission, kidOf(alice));
  const request = log.post(alice, 'please review my key setup'), requestHash = entryHash(request.bytes);
  const quote = log.append(log.owner, 'report', { kind: 'owner_action', action: 'quote', request_hash: requestHash, result_hash: null, asset_hash: asset, amount: 3, quote_index: null });
  const done = log.append(log.owner, 'report', { kind: 'owner_action', action: 'complete', request_hash: requestHash, result_hash: hexH(canonicalize({ text: 'reviewed' })), asset_hash: asset, amount: 3, quote_index: quote.index });
  log.append(alice, 'sup.spend', { purpose: 'owner_action', ref_index: done.index, asset_hash: asset, amount: 3, bytes: 0 });
  log.append(alice, 'sup.spend', { purpose: 'hosting', ref_index: null, asset_hash: asset, amount: 2, bytes: 0 });
  const h = supReplay(log); assert.equal(h.balances.get('alice'), 0); assert.throws(() => replay(log), /not an entry type of this profile/, 'a base-only replay refuses SUP-1 entries');
});
test('SUP-1: balances, awards and owner actions are enforced in index order', () => {
  let s = supLog(); s.log.append(alice, 'sup.spend', { purpose: 'hosting', ref_index: null, asset_hash: s.asset, amount: 1, bytes: 0 }); supFails(s.log, /insufficient_balance/);
  s = supLog(); s.award(s.submission, kidOf(alice)); s.award(s.submission, kidOf(alice)); supFails(s.log, /already awarded/);
  s = supLog(); s.award(s.submission, kidOf(bob)); supFails(s.log, /another account/);
  s = supLog(); s.award(s.submission, kidOf(alice), 4); supFails(s.log, /amount/);
  s = supLog(); s.log.append(alice, 'sup.credit', { source: 'task', account_kid: kidOf(alice), task_index: s.task.index, submission_index: s.submission.index, asset_hash: s.asset, amount: 5 }); supFails(s.log, /owner-signed/);
  s = supLog(); s.log.append(s.log.owner, 'sup.task', { body_hash: H, size: 1, asset_hash: 'ab'.repeat(32), reward: 1, max_awards: 1, closes: T + 3600 }); supFails(s.log, /asset_hash/);
  s = supLog(); const req = s.log.post(alice, 'request'), rh = entryHash(req.bytes);
  const q1 = s.log.append(s.log.owner, 'report', { kind: 'owner_action', action: 'quote', request_hash: rh, result_hash: null, asset_hash: s.asset, amount: 3, quote_index: null });
  s.log.append(s.log.owner, 'report', { kind: 'owner_action', action: 'quote', request_hash: rh, result_hash: null, asset_hash: s.asset, amount: 4, quote_index: null });
  s.log.append(s.log.owner, 'report', { kind: 'owner_action', action: 'complete', request_hash: rh, result_hash: H, asset_hash: s.asset, amount: 3, quote_index: q1.index }); supFails(s.log, /stale_quote/);
  s = supLog(); s.log.append(s.log.owner, 'report', { kind: 'owner_action', action: 'quote', request_hash: H, result_hash: null, asset_hash: s.asset, amount: 3, quote_index: null }); supFails(s.log, /request post/);
});
const H = 'ab'.repeat(32);

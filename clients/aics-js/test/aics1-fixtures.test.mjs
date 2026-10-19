// Every case of the AICS-1 interop fixtures (packages/aics-interop/fixtures) must reach its `expect`.
import test from 'node:test';
import assert from 'node:assert/strict';
import nacl from 'tweetnacl';
import { blake2b } from '@noble/hashes/blake2b';
import { interop, tileResources, unconsumed, hex, fromHex, fromB64, fromU64, utf8 } from './interop-fixtures.mjs';
import * as keys from '../dist/keys.js';
import { canonicalText, canonicalize, parseJson } from '../dist/canonical.js';
import * as envelope from '../dist/envelope.js';
import { buildEntry, entryBytes, entryHash, parseEntry, validateEntry, entryProblems } from '../dist/entry.js';
import { lineMessage, signLine, verifyLine, lineSignatureForm } from '../dist/linesig.js';
import { dearmorSshsig, verifySshsig } from '../dist/sshsig.js';
import * as http from '../dist/http-signatures.js';
import * as sealed from '../dist/sealed.js';
import { receiptText, verifyReceipt } from '../dist/receipt.js';
import { verifyBundle, verifyPackage } from '../dist/bundle.js';
import { History } from '../dist/history.js';
import { cardHash, verifyCard } from '../dist/card.js';
import { validateTrustBundle } from '../dist/trust.js';
import * as tlog from '../dist/tlog.js';

const K = interop('keys.json'), ed = n => K.ed25519[n], seedOf = n => fromHex(ed(n).seed_hex);
const ok = fn => { try { fn(); return true; } catch { return false; } };
const same = (a, b) => assert.equal(canonicalText(a), canonicalText(b));
const T0 = 1792281600;
/** A log-key line over `text` (the client never signs notes; the fixture's public test seed does). */
const logLine = (name, seed, body) => { const pub = keys.publicKey(seed), id = tlog.noteKeyHash(name, 1, pub); return `— ${name} ${Buffer.concat([id, keys.sign(utf8(body), seed)]).toString('base64')}\n`; };

// ---------------------------------------------------------------- keys.json
for (const [name, k] of Object.entries(K.ed25519)) test(`keys.json ed25519.${name}: public key, did:key kid, encodings`, () => {
  const pub = keys.publicKey(fromHex(k.seed_hex));
  assert.equal(hex(pub), k.public_hex); assert.equal(keys.didKey(pub), k.kid); assert.equal(Buffer.from(pub).toString('base64url'), k.public_u64); assert.equal(Buffer.from(pub).toString('base64'), k.public_b64);
  assert.equal(hex(keys.parseDidKey(k.kid)), k.public_hex); assert.equal(keys.agentIdentity(fromHex(k.seed_hex)).kid, k.kid);
  if (k.vkey) { const v = tlog.parseVkey(k.vkey); assert.equal(hex(v.publicKey), k.public_hex); assert(v.keyType === 1 || v.keyType === 4); if (k.name) assert.equal(v.name, k.name); }
});
for (const [name, k] of Object.entries(K.x25519)) test(`keys.json x25519.${name}: public key and encryption DID`, () => {
  const pub = keys.x25519PublicKey(fromHex(k.secret_hex)); assert.equal(hex(pub), k.public_hex); assert.equal(Buffer.from(pub).toString('base64url'), k.public_u64); assert.equal(keys.x25519DidKey(pub), k.did);
  assert.equal(hex(keys.parseDidKey(k.did, 'x25519')), k.public_hex); assert.throws(() => keys.parseDidKey(k.did));
});
test('keys.json: a non-canonical did:key encoding of a valid key is refused', () => {
  const kid = ed('agent0').kid; assert.throws(() => keys.parseDidKey('did:key:z1' + kid.slice(9))); assert.equal(keys.isKid(kid), true); assert.equal(keys.isKid(kid + '#key'), false);
});

// ---------------------------------------------------------------- linesig.json
const L = interop('linesig.json'), lpub = keys.parsePublicKey(L.pub_reply.slice(4));
test('linesig.json: the pub reply and the ssh-ed25519 line name the same key', () => {
  assert.equal(hex(lpub), L.public_key_hex); assert.equal(hex(keys.parsePublicKey(L.ssh_public_key)), L.public_key_hex); assert.equal(keys.opensshPublicKey(lpub), L.ssh_public_key);
  assert.equal(L.namespace, 'aics'); assert.equal(envelope.textCommand(L.unsigned_envelope), L.cases[0].line);
});
for (const c of L.cases) test(`linesig.json cases[${c.name}]: ${c.expect}`, () => {
  const valid = c.expect === 'valid';
  assert.equal(verifyLine(c.session, c.line, c.signature_b64, lpub), valid);
  assert.equal(verifyLine(c.session, c.line, 'sig: "' + c.signature_b64.replace(/=+$/, '') + '"', lpub), valid, 'input leeway on the signature text only');
  if (!valid) return;
  assert.equal(hex(lineMessage(c.session, c.line)), c.signing_input_hex);
  assert.equal(signLine(c.session, c.line, seedOf('linesig')), c.reply);
  assert.equal(signLine(c.session, c.line, seedOf('linesig'), 'sshsig'), c.sshsig_armored);
  assert.deepEqual(dearmorSshsig(c.sshsig_armored), fromU64(c.sshsig_blob_u64));
  verifySshsig(fromU64(c.sshsig_blob_u64), fromHex(c.signing_input_hex), lpub);
  assert.equal(lineSignatureForm(c.session, c.line, c.sshsig_armored, lpub), 'sshsig');
  assert.equal(verifyLine(c.session + 'x', c.line, c.signature_b64, lpub), false);
  assert.equal(verifyLine(c.session, c.line + ' ', c.signature_b64, lpub), false, 'no whitespace repair of signed bytes');
});

// ---------------------------------------------------------------- envelopes.json
const E = interop('envelopes.json'), ORIGIN = E.origin, LOG = interop('tlog/log.json'), TRUST = LOG.trust_bundle;
for (const [i, c] of E.native.entries()) test(`envelopes.json native[${i}]: ${c.envelope.protected.type} ${c.expect}`, () => {
  const e = c.envelope, p = e.protected;
  assert.equal(canonicalText(e), c.jcs); assert.equal(envelope.envelopeHash(e), c.envelope_hash);
  if (c.signing_digest_hex) assert.equal(hex(envelope.envelopeSigningDigest(p, e.payload)), c.signing_digest_hex);
  envelope.verifyEnvelope(e, { now: p.created, origin: ORIGIN });
  same(envelope.signEnvelope(e.payload, seedOf('envelope_alice'), { origin: p.origin, type: p.type, created: p.created, expires: p.expires, nonce: p.nonce, seq: p.seq, prev: p.prev, seen: p.seen }), e);
  if (c.entry_jcs) { const entry = buildEntry(e, p.created); assert.equal(canonicalText(entry), c.entry_jcs); validateEntry(parseEntry(utf8(c.entry_jcs)), { origin: ORIGIN }); }
});
test('envelopes.json chain: valid, seq 0, 1, 2 with prev = hexH(J(previous E))', () => {
  const envs = E.chain.envelopes; assert.equal(E.chain.expect, 'valid'); assert.deepEqual(envelope.chainBreaks(envs), []);
  envs.forEach((e, i) => { envelope.checkSuccessor(i ? envs[i - 1] : null, e); envelope.verifyEnvelope(e, { now: e.protected.created, origin: ORIGIN }); });
  assert.equal(new History(envs.map(e => entryBytes(buildEntry(e, e.protected.created))), { trust: TRUST }).size, 3);
});
for (const c of E.chain_breaks) test(`envelopes.json chain_breaks[${c.name}]: first invalid position ${c.first_invalid_position}`, () => {
  const envs = c.envelopes, pos = c.first_invalid_position, raw = envs.map(e => entryBytes(buildEntry(e, e.protected.created)));
  assert.equal(envelope.chainBreaks(envs)[0]?.position, pos);
  assert.throws(() => new History(raw, { trust: TRUST }), err => err.index === pos && /sequence/.test(err.message));
  assert.equal(new History(raw.slice(0, pos), { trust: TRUST }).size, pos);
  assert.throws(() => envelope.checkSuccessor(pos ? envs[pos - 1] : null, envs[pos]));
});
for (const c of E.seen) test(`envelopes.json seen[${c.name}]: ${c.expect}`, () => {
  assert.equal(ok(() => envelope.validateSeen(c.seen)), c.expect === 'valid');
  const base = E.native[0].envelope, e = { ...base, protected: { ...base.protected, seen: c.seen } };
  assert.equal(ok(() => envelope.validateEnvelope(e, { origin: ORIGIN })), c.expect === 'valid');
});
for (const c of E.freshness) test(`envelopes.json freshness[${c.name}]: ${c.expect} at t`, () => {
  const valid = c.expect === 'valid';
  assert.equal(envelope.acceptedAt(c.envelope.protected, c.t), valid);
  assert.equal(ok(() => envelope.verifyEnvelope(c.envelope, { now: c.t, origin: ORIGIN })), valid);
  assert.equal(entryProblems(buildEntry(c.envelope, c.t), { origin: ORIGIN }).length === 0, valid);
});
for (const c of E.tampered) test(`envelopes.json tampered[${c.name}]: invalid (the signature covers it)`, () => {
  assert.throws(() => envelope.verifyEnvelope(c.envelope, { now: c.envelope.protected.created }), err => err.code === 'bad_signature' || err.code === 'malformed');
});
for (const [i, c] of E.text.entries()) test(`envelopes.json text[${i}]: ${c.scheme} ${c.envelope.protected.type} ${c.expect}`, () => {
  if (c.expect !== 'valid') { assert.throws(() => envelope.verifyEnvelope(c.envelope, { now: c.envelope.protected.created })); return; }
  assert.equal(envelope.textCommand(c.unsigned), c.command);
  if (c.signing_input_hex) assert.equal(hex(envelope.textSigningInput(c.unsigned)), c.signing_input_hex);
  envelope.verifyEnvelope(c.envelope, { now: c.envelope.protected.created, origin: ORIGIN });
  same(envelope.signTextEnvelope(c.unsigned, seedOf('envelope_alice')), c.envelope);
  const p = c.unsigned.protected;
  same(envelope.unsignedTextEnvelope(c.unsigned.payload, { origin: p.origin, type: p.type, kid: p.kid, session: c.unsigned.auth.session, scheme: c.unsigned.auth.scheme, created: p.created, expires: p.expires, nonce: p.nonce, seq: p.seq, prev: p.prev, seen: p.seen }), c.unsigned);
});

// ---------------------------------------------------------------- http-signatures.json
const H = interop('http-signatures.json');
for (const c of H.cases) test(`http-signatures.json cases[${c.name}]: ${c.expect}`, () => {
  const valid = c.expect === 'valid', body = utf8(c.body_text);
  assert.equal(ok(() => http.verifyEntryRequest(c.method, c.url, c.headers, body, { now: H.now, origin: ORIGIN })), valid);
  assert.equal(ok(() => http.verifyRequest(c.method, c.url, c.headers, body, kid => kid === H.envelope.protected.kid ? keys.parseDidKey(kid) : null, { ...http.AICS_VERIFY_POLICY, now: H.now, envelope: H.envelope })), valid);
  if (c.name !== 'valid') return;
  const signed = http.signRequest('POST', c.url, { 'Content-Type': 'application/json' }, body, { key: seedOf('http_agent'), envelope: H.envelope });
  assert.deepEqual(signed, Object.fromEntries(Object.entries(c.headers).map(([k, v]) => [k.toLowerCase(), v])));
  assert.equal(Buffer.from(http.signatureBase(H.components, c.headers['Signature-Input'].slice(5), c.method, c.url, c.headers)).toString(), c.signature_base_text);
  assert.equal(c.body_text, canonicalText({ envelope: H.envelope, body: null }));
  assert.equal(hex(keys.parseDidKey(H.envelope.protected.kid)), H.public_key_hex);
});

// ---------------------------------------------------------------- sealed.json
const S = interop('sealed.json'), bobX = fromHex(S.recipient.x25519_secret_hex);
const deterministicSeal = (plaintext, recipient, eph) => { const epk = keys.x25519PublicKey(eph); return new Uint8Array(Buffer.concat([epk, nacl.box(plaintext, blake2b(Buffer.concat([epk, recipient]), { dkLen: 24 }), recipient, eph)])); };
for (const c of S.cases) test(`sealed.json cases[${c.name}]: ${c.expect}`, () => {
  const ct = fromHex(c.ciphertext_hex), valid = c.expect === 'valid';
  envelope.verifyEnvelope(c.envelope, { now: c.envelope.protected.created, origin: ORIGIN });
  assert.equal(ok(() => sealed.openSealed(ct, bobX, { envelope: c.envelope, recipientKid: S.recipient.kid })), valid);
  if (c.header_jcs) assert.equal(ok(() => sealed.openSealed(ct, bobX, { expected: JSON.parse(c.header_jcs) })), c.name !== 'framing:jcs-lf-body');
  if (!valid) { assert.throws(() => sealed.openSealed(ct, bobX, { envelope: c.envelope }), sealed.SealedError); return; }
  const msg = sealed.openSealed(ct, bobX, { envelope: c.envelope, recipientKid: S.recipient.kid }); assert.equal(msg.text, c.content_text);
  const header = sealed.innerHeaderBytes(sealed.headerFromEnvelope(c.envelope)), plaintext = sealed.framePlaintext(header, utf8(c.content_text));
  assert.equal(Buffer.from(header).toString(), c.header_jcs); assert.equal(hex(plaintext), c.plaintext_hex);
  assert.equal(hex(deterministicSeal(plaintext, fromHex(S.recipient.x25519_public_hex), fromHex(S.ephemeral_secret_hex))), c.ciphertext_hex);
  const metadata = sealed.ciphertextMetadata(ct); for (const k of ['encryption', 'eph_pk', 'ct_hash', 'size']) assert.equal(metadata[k], c.envelope.payload[k]);
  const fresh = sealed.seal(sealed.headerFromEnvelope(c.envelope), c.content_text, fromHex(S.recipient.x25519_public_hex));
  assert.notEqual(hex(fresh), c.ciphertext_hex, 'a fresh ephemeral key per ciphertext');
  assert.equal(sealed.openSealed(fresh, bobX, { expected: sealed.headerFromEnvelope(c.envelope) }).text, c.content_text);
  const [hb] = sealed.splitPlaintext(nacl.box.open(fresh.slice(32), blake2b(Buffer.concat([fresh.slice(0, 32), fromHex(S.recipient.x25519_public_hex)]), { dkLen: 24 }), fresh.slice(0, 32), bobX));
  assert.equal(Buffer.from(hb).toString(), c.header_jcs, 'the library seals the libsodium crypto_box_seal layout');
});

// ---------------------------------------------------------------- receipts.json
const R = interop('receipts.json'), rEntry = fromU64(R.entry_u64);
test('receipts.json receipt_text: valid, and byte-identical to the client recomputation', () => {
  const r = verifyReceipt(R.receipt_text, R.log_vkey, rEntry); const e = parseEntry(rEntry);
  assert.equal(r.submitted_at, R.entry_ts); assert.equal(r.deadline, R.entry_ts + 60); assert.equal(r.entry_hash, entryHash(rEntry)); assert.equal(e.ts, R.entry_ts);
  const text = receiptText(TRUST.origin, entryHash(rEntry), e.ts); assert.equal(text + '\n' + logLine(TRUST.origin, seedOf('log'), text), R.receipt_text);
  verifyReceipt(R.receipt_text, R.log_vkey, e);
});
for (const c of R.invalid) test(`receipts.json invalid[${c.name}]: invalid`, () => { assert.throws(() => verifyReceipt(c.receipt_text, R.log_vkey, rEntry)); });

// ---------------------------------------------------------------- bundles.json
const B = interop('bundles.json'), bundleOpts = { logKey: B.log_vkey, witnesses: B.witness_vkeys, quorum: B.quorum };
test('bundles.json aics1_wire_bundle: valid (checkpoint quorum 2, inclusion, entry, envelope signature, body)', () => {
  const v = verifyBundle(B.aics1_wire_bundle.bundle, bundleOpts);
  assert.equal(v.index, 7); assert.equal(v.history, 'incomplete'); assert.equal(v.witnesses.length, 2); assert.equal(Buffer.from(v.body).toString(), '{"channel":"interop","text":"main post 7","title":null}');
  assert.throws(() => verifyBundle(B.aics1_wire_bundle.bundle, { ...bundleOpts, quorum: 3 }));
  assert.throws(() => verifyBundle(B.aics1_wire_bundle.bundle, { logKey: K.ed25519.other_log.vkey }));
});
for (const c of B.tampered_wire_bundles) test(`bundles.json tampered_wire_bundles[${c.name}]: invalid`, () => { assert.throws(() => verifyBundle(c.bundle, bundleOpts), /invalid/); });
test('bundles.json legacy_aics_tlog_bundle: invalid (pre-0.2 members and encodings)', () => { assert.throws(() => verifyBundle(B.legacy_aics_tlog_bundle.bundle, bundleOpts), /exactly/); });
test('bundles.json aics1_package: valid complete verification package (history replayed)', () => {
  const pkg = B.aics1_package.package, v = verifyPackage(pkg, { trust: TRUST, witnesses: B.witness_vkeys, quorum: B.quorum });
  assert.equal(v.history, 'valid'); assert.equal(v.replay.size, 8); assert.equal(v.savedCheckpoints[0].size, 8); same(pkg.bundle, B.aics1_wire_bundle.bundle);
  assert.throws(() => verifyPackage(pkg, { trust: { ...TRUST, bootstrap_card_hash: '0'.repeat(64) }, witnesses: B.witness_vkeys, quorum: B.quorum }), /pinned/);
  assert.throws(() => verifyPackage({ ...pkg, trust_policy: {} }, { trust: TRUST, witnesses: B.witness_vkeys, quorum: B.quorum }), /exactly/);
  assert.throws(() => verifyPackage({ ...pkg, entry_prefix: pkg.entry_prefix.slice(0, 7) }, { trust: TRUST, witnesses: B.witness_vkeys, quorum: B.quorum }), /incomplete/);
  assert.throws(() => verifyPackage({ ...pkg, policy_cards: [] }, { trust: TRUST, witnesses: B.witness_vkeys, quorum: B.quorum }), /incomplete/);
});

// ---------------------------------------------------------------- tlog/log.json and tlog/tiles
const tiles = tileResources(), reader = new tlog.MemoryTileReader(tiles), head = tlog.parseCheckpoint(tlog.parseNote(tiles.checkpoint).text);
for (const [size, n] of Object.entries(LOG.notes)) test(`tlog/log.json notes[${size}]: valid under quorum 2, fresh`, () => {
  const r = tlog.verifyCheckpoint(n.note_text, LOG.log_vkey, { policy: { quorum: 2, witnesses: LOG.witness_vkeys, maxAgeSeconds: 300 }, now: n.cosigned_at + 10, expectedOrigin: LOG.origin });
  assert(r.ok, r.error); assert.equal(r.checkpoint.size, Number(size)); assert.equal(Buffer.from(r.checkpoint.root).toString('base64'), n.root_b64); assert.equal(r.freshness, 'verified');
  assert.equal(envelope.seenFromCheckpoint(n.note_text).checkpoint_note_hash, n.sha256);
});
test('tlog/tiles: the size-300 prefix authenticates against its cosigned checkpoint; sample entries read back', async () => {
  const r = tlog.verifyCheckpoint(tiles.checkpoint, LOG.log_vkey, { policy: { quorum: 2, witnesses: LOG.witness_vkeys, maxAgeSeconds: 300 }, now: LOG.notes['300'].cosigned_at + 10 }); assert(r.ok, r.error);
  const tree = new tlog.TileTree(reader, head.size); await tree.verifyRoot(head); assert.equal(head.size, LOG.size);
  for (const [i, u] of Object.entries(LOG.entry_sample_u64)) assert.equal(hex(await tree.readEntry(Number(i), head)), hex(fromU64(u)));
  const all = await tlog.readEntries(reader, head.size); assert.equal(all.length, 300); assert.equal(hex(tlog.merkleRoot(all.map(tlog.leafHash))), hex(head.root));
});
test('tlog/tiles: the complete 300-entry history replays (charter, card, claims, posts) under the pinned trust', async () => {
  const all = await tlog.readEntries(reader, head.size), h = new History(all, { trust: TRUST });
  assert.equal(h.size, 300); assert.deepEqual(h.policyEvents, [0, 1]); assert.equal(h.name('agent0').kid, ed('agent0').kid);
  const card = verifyCard(LOG.card, { trust: TRUST, firstUse: true, now: T0 + 3610 }); assert(card.ok, card.problems.join('; '));
  assert.equal(h.entries[1].payload.document_hash, card.cardHash);
});
for (const c of LOG.inclusion) test(`tlog/log.json inclusion[${c.index},${c.size}]: valid, and the tiles derive the same proof`, async () => {
  const proof = c.proof_b64.map(fromB64), root = fromB64(c.root_b64), leaf = fromHex(c.leaf_hash_hex);
  assert(tlog.verifyInclusion(leaf, c.index, c.size, proof, root)); assert(!tlog.verifyInclusion(leaf, c.index, c.size, [...proof, new Uint8Array(32)], root));
  assert.deepEqual((await new tlog.TileTree(reader, head.size).inclusionProof(c.index, c.size)).map(x => Buffer.from(x).toString('base64')), c.proof_b64);
});
for (const c of LOG.consistency) test(`tlog/log.json consistency[${c.old},${c.new}]: valid, and the tiles derive the same proof`, async () => {
  const proof = c.proof_b64.map(fromB64);
  assert(tlog.verifyConsistency(c.old, c.new, fromB64(c.old_root_b64), fromB64(c.new_root_b64), proof));
  if (c.old !== c.new) assert(!tlog.verifyConsistency(c.old, c.new, fromB64(c.old_root_b64), fromB64(c.new_root_b64), [...proof, new Uint8Array(32)]));
  assert.deepEqual((await new tlog.TileTree(reader, head.size).consistencyProof(c.old, c.new)).map(x => Buffer.from(x).toString('base64')), c.proof_b64);
});
const NC = LOG.note_cases, ncPolicy = { quorum: NC.policy.quorum, witnesses: NC.policy.witness_vkeys, maxAgeSeconds: NC.policy.max_checkpoint_age };
for (const c of NC.freshness) test(`tlog/log.json note_cases.freshness[age ${c.age}]: ${c.expect}`, () => {
  assert.equal(tlog.verifyCheckpoint(NC.single_witness_note_text, LOG.log_vkey, { policy: ncPolicy, now: c.now }).ok, c.expect === 'valid');
  assert.equal(tlog.verifyNote(NC.single_witness_note_text, LOG.log_vkey, { witnesses: ncPolicy.witnesses, quorum: 1, maxAgeSeconds: 300, now: c.now }).ok, c.expect === 'valid');
});
for (const name of ['repeated_unknown_key_lines', 'repeated_log_key_line', 'invalid_pinned_cosignature']) test(`tlog/log.json note_cases.${name}: ${NC[name].expect}`, () => {
  const c = NC[name]; assert.equal(tlog.verifyCheckpoint(c.note_text, LOG.log_vkey, { policy: ncPolicy, now: c.now }).ok, c.expect === 'valid');
  assert.equal(tlog.verifyNote(c.note_text, LOG.log_vkey, { witnesses: ncPolicy.witnesses, quorum: 1, maxAgeSeconds: 300, now: c.now }).ok, c.expect === 'valid');
});

// ---------------------------------------------------------------- split-view.json
const V = interop('split-view.json');
for (const c of V.fixtures) test(`split-view.json fixtures[${c.name}]: ${c.expect.relation}`, async () => {
  const sizes = [c.note_1_text, c.note_2_text].map(n => Number(n.split('\n')[1])), larger = sizes[1] >= sizes[0] ? 'mirror' : 'origin';
  const label = c.served[larger].tiles, served = V.trees[label] ? Object.fromEntries(Object.entries(V.trees[label]).map(([p, d]) => [p, fromU64(d)])) : {};
  const entries = await tlog.readEntries(new tlog.MemoryTileReader(served), Math.max(...sizes));
  const r = tlog.classifyGossip(c.note_1_text, c.note_2_text, { logKey: V.log_vkey, witnesses: c.policy.witness_vkeys, quorum: c.policy.quorum, expectedOrigin: V.origin, largerEntries: entries ?? undefined });
  assert.equal(r.relation, c.expect.relation); assert.deepEqual(r.witnessPolicyMet, c.expect.witness_policy_met);
  if (c.expect.reason) assert.equal(r.reason, c.expect.reason);
});

// ---------------------------------------------------------------- card.json
const C = interop('card.json'), cardNow = T0 + 3610;
test('card.json card: valid, signed by the pinned policy key, hash = the bootstrap hash', () => {
  const v = verifyCard(C.card.card, { policyKid: C.policy_kid, now: cardNow }); assert(v.ok, v.problems.join('; '));
  assert.equal(v.cardHash, C.card.card_hash); assert.equal(cardHash(C.card.card), C.trust_bundle.bootstrap_card_hash);
  const { signatures: _s, ...unsigned } = C.card.card; assert.equal(canonicalText(unsigned), C.card.unsigned_jcs);
  assert(verifyCard(C.card.card, { trust: C.trust_bundle, firstUse: true, now: cardNow }).ok);
  assert(verifyCard(Buffer.from(canonicalText(C.card.card)), { policyKid: C.policy_kid, now: cardNow }).ok);
  assert(!verifyCard(C.card.card, { policyKid: ed('owner').kid, now: cardNow }).ok, 'another key than the pinned policy key');
  assert(!verifyCard(C.card.card, { policyKid: C.policy_kid, now: C.card.card.expires }).ok, 'expired');
  assert(!verifyCard(C.card.card, { policyKid: C.policy_kid, now: C.card.card.issued_at - 31 }).ok, 'issued in the future');
});
test('card.json card_0_1_draft: invalid (version, spec_versions, refusal registry)', () => {
  const v = verifyCard(C.card_0_1_draft.card, { policyKid: C.policy_kid, now: cardNow }); assert(!v.ok);
  assert(v.problems.some(p => p.startsWith('$.version')) && v.problems.some(p => p.startsWith('$.spec_versions')) && v.problems.some(p => p.startsWith('$.reason_codes.refusal')), v.problems.join('; '));
});
test('card.json altered: invalid (signed bytes changed after signing)', () => {
  const v = verifyCard(C.altered.card, { policyKid: C.policy_kid, now: cardNow }); assert(!v.ok); assert.deepEqual(v.problems, ['$.signatures[0]: does not verify with the pinned policy key']);
});
for (const c of C.registry) test(`card.json registry[${c.name}]: invalid`, () => {
  const v = verifyCard(c.card, { policyKid: C.policy_kid, now: cardNow }); assert.equal(v.cardHash, c.card_hash);
  assert.deepEqual(v.problems, ['$.reason_codes.refusal: must equal the §17.2 registry of the advertised profile plus one secret_format:<id> per secret pattern']);
});

// ---------------------------------------------------------------- appendix-a.json
const A = interop('appendix-a.json'), aEnv = parseJson(A.envelope_jcs), aEntries = A.entries_u64.map(fromU64);
test('appendix-a.json: A.1 envelope signature, digest, envelope hash and seen pointer', () => {
  assert.equal(canonicalText(aEnv), A.envelope_jcs); assert.equal(envelope.envelopeHash(aEnv), A.inline.envelope_hash);
  assert.equal(hex(envelope.envelopeSigningDigest(aEnv.protected, aEnv.payload)), A.inline.signing_digest);
  envelope.verifyEnvelope(aEnv, { now: aEnv.protected.created, origin: 'log.example/aics-1', key: fromHex(A.inline.alice_public_key) });
  assert.equal(envelope.seenFromCheckpoint(A.previous_checkpoint_text).checkpoint_note_hash, A.inline.previous_checkpoint_hash);
  same(aEnv.protected.seen, envelope.seenFromCheckpoint(A.previous_checkpoint_text));
  const p = aEnv.protected; same(envelope.signEnvelope(aEnv.payload, new Uint8Array(32).fill(1), { origin: p.origin, type: p.type, created: p.created, nonce: p.nonce, seq: p.seq, prev: p.prev, seen: p.seen }), aEnv);
});
test('appendix-a.json: A.2 entries, leaf hashes, root, proofs and the 1448-byte entry record', () => {
  assert.equal(Buffer.from(aEntries[3]).toString(), A.entry_jcs); assert.equal(aEntries[3].length, Number(A.inline.entry_length));
  assert.equal(hex(Uint8Array.of(aEntries[3].length >> 8, aEntries[3].length & 255)), A.inline.entry_record_prefix);
  assert.deepEqual(aEntries.map(e => entryHash(e)), A.leaf_hashes_hex); assert.equal(hex(tlog.merkleRoot(aEntries.map(tlog.leafHash))), A.root_hex);
  assert(tlog.verifyInclusion(fromHex(A.leaf_hashes_hex[3]), 3, 4, A.inclusion_proof_b64.map(fromB64), fromHex(A.root_hex)));
  const prev = tlog.parseCheckpoint(tlog.parseNote(A.previous_checkpoint_text).text);
  assert(tlog.verifyConsistency(3, 4, prev.root, fromHex(A.root_hex), A.consistency_proof_b64.map(fromB64)));
  assert.equal(canonicalText(buildEntry(aEnv, aEnv.protected.created)), A.entry_jcs);
});
test('appendix-a.json: A.3 checkpoint with its cosignature, verified under the test pins', () => {
  const r = tlog.verifyCheckpoint(A.checkpoint_text, A.inline.log_vkey, { policy: { quorum: 1, witnesses: [A.inline.witness_vkey], maxAgeSeconds: 300 }, now: Number(A.inline.witness_timestamp) + 10 });
  assert(r.ok, r.error); assert.equal(hex(r.checkpoint.root), A.root_hex); assert.equal(r.timestamps['witness.example/w1'], Number(A.inline.witness_timestamp));
  assert.equal(Buffer.from(tlog.cosignatureMessage(Number(A.inline.witness_timestamp), tlog.parseNote(A.checkpoint_text).text)).toString(), A.cosignature_input_text);
  assert.equal(envelope.seenFromCheckpoint(A.checkpoint_text).checkpoint_note_hash, A.inline.checkpoint_hash);
});
test('appendix-a.json: A.4 inner header, framed plaintext and the deterministic sealed box', () => {
  const header = sealed.innerHeaderBytes(sealed.headerFromEnvelope(aEnv)), plaintext = sealed.framePlaintext(header, utf8('hello\n')), ct = fromHex(A.ciphertext_hex);
  assert.equal(Buffer.from(header).toString(), A.header_jcs); assert.equal(header.length, Number(A.inline.header_length)); assert.equal(hex(plaintext.slice(0, 4)), A.inline.header_prefix); assert.equal(hex(plaintext), A.plaintext_hex);
  const bob = new Uint8Array(32).fill(8), eph = new Uint8Array(32).fill(9);
  assert.equal(hex(keys.x25519PublicKey(bob)), A.inline.bob_x25519); assert.equal(hex(keys.x25519PublicKey(eph)), A.inline.ephemeral_public_key);
  assert.equal(hex(blake2b(Buffer.concat([keys.x25519PublicKey(eph), keys.x25519PublicKey(bob)]), { dkLen: 24 })), A.inline.box_nonce);
  assert.equal(hex(deterministicSeal(plaintext, keys.x25519PublicKey(bob), eph)), A.ciphertext_hex); assert.equal(ct.length, Number(A.inline.ciphertext_length));
  assert.equal(sealed.ciphertextMetadata(ct).ct_hash, A.inline.ciphertext_hash);
  assert.equal(sealed.openSealed(ct, bob, { envelope: aEnv, recipientKid: aEnv.payload.to_kid }).text, 'hello\n');
});
test('appendix-a.json: the four entries replay as a complete history; the trust bundle validates', () => {
  const tb = validateTrustBundle(canonicalize(A.trust_bundle)), h = new History(aEntries, { trust: tb });
  assert.equal(h.size, 4); assert.deepEqual(h.policyEvents, [0]); assert.equal(h.name('bob').kid, aEnv.payload.to_kid);
  assert.throws(() => new History(aEntries.slice(1), { trust: tb }), /sequence|signer|recipient|consent/);
});

test('every aics-interop fixture file is consumed by this suite', () => {
  interop('trust-bundle.json'); // consumed case by case in trust.test.mjs
  assert.deepEqual(unconsumed(), []);
});

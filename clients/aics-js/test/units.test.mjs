// Unit tests of the AICS-1 rules beyond the shared fixtures: keys, JCS, envelopes, entries, sealed boxes, SSHSIG, line
// and HTTP signatures, receipts and cards. Each refusal is checked against the rule it enforces.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hex, fromHex, fromB64, utf8 } from './interop-fixtures.mjs';
import { interop } from './interop-fixtures.mjs';
import * as keys from '../dist/keys.js';
import * as canonical from '../dist/canonical.js';
import * as envelope from '../dist/envelope.js';
import { buildEntry, entryProblems, validateEntry, bodyCommitment, payloadProblems } from '../dist/entry.js';
import * as linesig from '../dist/linesig.js';
import * as sshsig from '../dist/sshsig.js';
import * as http from '../dist/http-signatures.js';
import * as sealed from '../dist/sealed.js';
import { verifyReceipt } from '../dist/receipt.js';
import { cardHash, cardProblems, cardProtectedHeader, cardSigningInput, verifyCard } from '../dist/card.js';
import { b64u, concat, hexH, uint32be } from '../dist/bytes.js';
import { REFUSAL_SUP, supAssetDescriptor } from '../dist/registry.js';
import { TestLog, seed, kidOf, T } from './log-builder.mjs';
const local = name => JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), 'utf8'));
const KF = local('key-formats'), kseed = fromHex(KF.seed), kpub = fromHex(KF.public);
const ORIGIN = 'log.test/aics', alice = seed(0xb1), bob = seed(0xb2), mallory = seed(0xb3), ax = seed(0xc1), bx = seed(0xc2);
const post = (text = 'hi') => { const body = canonical.canonicalize({ channel: 'test', title: null, text }); return { q: { channel_sha256: hexH(utf8('test')), parent_index: null, body_hash: hexH(body), size: body.length, title_sha256: null }, body }; };
const native = (q = post().q, o = {}) => envelope.signEnvelope(q, alice, { origin: ORIGIN, type: 'post', created: T, nonce: b64u(new Uint8Array(16).fill(7)), ...o });
const throwsCode = (fn, code) => assert.throws(fn, e => e instanceof envelope.EnvelopeError && e.code === code, `expected ${code}`);

// ---------------------------------------------------------------- keys
test('key formats: public key, did:key kid, PEM/OpenSSH/DER import and export', () => {
  assert.equal(hex(keys.publicKey(kseed)), KF.public); assert.equal(keys.didKey(kpub), KF.did);
  assert.deepEqual(keys.agentIdentity(kseed), { kid: KF.did, did: KF.did, public_key: KF.public_key_u64 });
  for (const form of ['pem', 'openssh_private']) assert.equal(hex(keys.importPrivateKey(KF[form])), KF.seed);
  for (const form of ['public_pem', 'openssh_public', 'did', 'public_key_u64']) assert.equal(hex(keys.parsePublicKey(KF[form])), KF.public);
  assert.equal(keys.exportPrivateKey(kseed), KF.pem); assert.equal(keys.exportPublicKey(kpub), KF.public_pem); assert.equal(keys.opensshPublicKey(kpub), KF.openssh_public);
  assert.equal(hex(keys.importPrivateKey(fromB64(KF.pem.replace(/-----[^\n]+-----/g, '').replace(/\s/g, '')))), KF.seed);
});
for (const [i, d] of KF.derivations.entries()) test(`HKDF derivation vector ${i} (${d.label})`, () => {
  const salt = d.salt === null ? undefined : fromHex(d.salt), secret = fromHex(KF.master_secret);
  assert.equal(hex(keys.deriveAgentKey(secret, d.label, salt)), d.seed); assert.equal(hex(keys.deriveX25519Key(secret, d.label, salt)), d.x25519_seed);
  assert.equal(keys.agentIdentity(fromHex(d.seed)).kid, d.did);
});
test('keys: weak points, wrong codecs, unverified ids and empty HKDF inputs are refused', () => {
  for (const p of [new Uint8Array(32), Uint8Array.from([1, ...Array(31).fill(0)])]) assert.throws(() => keys.validatePublicKey(p));
  assert.throws(() => keys.validateX25519PublicKey(new Uint8Array(32)));
  assert.throws(() => keys.parseDidKey(keys.x25519DidKey(keys.x25519PublicKey(kseed))));
  assert.throws(() => keys.deriveAgentKey(new Uint8Array(), 'x')); assert.throws(() => keys.deriveAgentKey(kseed, '')); assert.throws(() => keys.deriveAgentKey(kseed, 'x', new Uint8Array()));
  assert.throws(() => keys.parsePublicKey('ssh-ed25519 AAAA'));
  assert.equal(keys.isUnverifiedId('unverified:' + b64u(new Uint8Array(16))), true); assert.equal(keys.isUnverifiedId('unverified:' + b64u(new Uint8Array(15))), false); assert.equal(keys.isKid('unverified:x'), false);
  assert.equal(keys.verify(new Uint8Array(63), utf8('m'), kpub), false);
});

// ---------------------------------------------------------------- canonical
for (const [i, v] of local('canonical').entries()) test(`RFC 8785 vector ${i}`, () => assert.equal(canonical.canonicalText(v.value), v.canonical));
test('strict JSON: duplicates, trailing data, lone surrogates, BOM, depth and non-JSON values are refused', () => {
  for (const s of ['{"x":1,"x":2}', '[1,]', '{"a":1}x', '1e999', '"\\ud800"', '"\u0001"']) assert.throws(() => canonical.parseJson(s), s);
  assert.throws(() => canonical.parseJson(Uint8Array.of(255))); assert.throws(() => canonical.parseJson(Uint8Array.from([239, 187, 191, 123, 125])));
  assert.throws(() => canonical.parseJson('['.repeat(80) + ']'.repeat(80)), /deep/); assert.equal(canonical.canonicalText(canonical.parseJson('{"__proto__":1}')), '{"__proto__":1}');
  for (const v of [NaN, Infinity, undefined, '\ud800', { x: undefined }, new Date(), [1, , 2]]) assert.throws(() => canonical.canonicalize(v));
  assert.throws(() => canonical.parseCanonical('{"b":1,"a":2}'), /canonical/); assert.equal(canonical.sameJson({ a: 1, b: [2] }, canonical.parseJson('{"b":[2],"a":1}')), true);
});

// ---------------------------------------------------------------- envelopes
test('signEnvelope writes exactly the §4.1 members with the did:key kid and defaults', () => {
  const e = envelope.signEnvelope(post().q, alice, { origin: ORIGIN, type: 'post' }), p = e.protected;
  assert.deepEqual(Object.keys(e).sort(), ['auth', 'payload', 'protected', 'sig', 'v']); assert.deepEqual(Object.keys(p).sort(), [...envelope.PROTECTED_MEMBERS].sort());
  assert.equal(p.kid, kidOf(alice)); assert.equal(p.expires - p.created, 300); assert.equal(Buffer.from(p.nonce, 'base64url').length, 16); assert.equal(p.seq, 0); assert.equal(p.prev, null); assert.equal(p.seen, null);
  assert.deepEqual(e.auth, { scheme: 'ed25519-jcs' }); envelope.verifyEnvelope(e, { origin: ORIGIN });
  assert.throws(() => envelope.signEnvelope(post().q, alice, { origin: ORIGIN, type: 'post', seq: 1 }), /prev/);
  assert.throws(() => envelope.signEnvelope(post().q, alice, { origin: 'https://x/y', type: 'post' }), /origin/);
});
const mutated = (fn) => { const e = structuredClone(native()); fn(e); return e; };
for (const [name, fn] of [
  ['an unknown member', e => { e.extra = 1; }], ['no auth', e => { delete e.auth; }], ['v 2', e => { e.v = 2; }], ['alg none with ed25519-jcs', e => { e.protected.alg = 'none'; }],
  ['a 15-byte nonce', e => { e.protected.nonce = b64u(new Uint8Array(15)); }], ['a padded nonce', e => { e.protected.nonce += '=='; }], ['a standard-alphabet nonce', e => { e.protected.nonce = Buffer.alloc(16, 0xfb).toString('base64').replace(/=+$/, ''); }],
  ['seq 1 without prev', e => { e.protected.seq = 1; }], ['seq 0 with prev', e => { e.protected.prev = 'ab'.repeat(32); }], ['a lifetime of 301 s', e => { e.protected.expires = e.protected.created + 301; }],
  ['expires = created', e => { e.protected.expires = e.protected.created; }], ['an unregistered type', e => { e.protected.type = 'swarm.form'; }], ['an origin with a scheme', e => { e.protected.origin = 'https://log.test'; }],
  ['a 63-byte sig', e => { e.sig = b64u(new Uint8Array(63)); }], ['a short kid', e => { e.protected.kid = 'Vkdap1RjR0wChd9d'; }], ['a kid with a fragment', e => { e.protected.kid += '#k'; }],
  ['a fractional created', e => { e.protected.created += 0.5; }], ['seen with an extra member', e => { e.protected.seen = { checkpoint_note_hash: 'ab'.repeat(32), size: 1, note: 'x' }; }],
  ['auth with a session', e => { e.auth = { scheme: 'ed25519-jcs', session: 'x' }; }], ['a payload array', e => { e.payload = []; }],
]) test(`validateEnvelope refuses ${name}`, () => assert.throws(() => envelope.validateEnvelope(mutated(fn), { origin: ORIGIN }), envelope.EnvelopeError));
test('verifyEnvelope: freshness, key binding, replay and skew rules carry §17.2 codes', () => {
  const e = native();
  throwsCode(() => envelope.verifyEnvelope(e, { now: T - 31 }), 'future'); envelope.verifyEnvelope(e, { now: T - 30 });
  throwsCode(() => envelope.verifyEnvelope(e, { now: T + 300 }), 'expired'); envelope.verifyEnvelope(e, { now: T + 299 });
  throwsCode(() => envelope.verifyEnvelope(e, { now: T, key: () => null }), 'unknown_key');
  throwsCode(() => envelope.verifyEnvelope(e, { now: T, key: keys.publicKey(bob) }), 'bad_signature'); envelope.verifyEnvelope(e, { now: T, key: keys.publicKey(alice) });
  throwsCode(() => envelope.verifyEnvelope({ ...e, payload: { ...e.payload, size: e.payload.size + 1 } }, { now: T }), 'bad_signature');
  throwsCode(() => envelope.verifyEnvelope(e, { now: T, origin: 'other.test/aics' }), 'malformed');
  const cache = new envelope.ReplayCache(); envelope.verifyEnvelope(e, { now: T, replayCheck: cache.check }); throwsCode(() => envelope.verifyEnvelope(e, { now: T, replayCheck: cache.check }), 'replay');
  assert.throws(() => envelope.verifyEnvelope(e, { now: T, maxClockSkew: 31 }), /never raise/); throwsCode(() => envelope.verifyEnvelope(e, { now: T - 10, maxClockSkew: 5 }), 'future');
});
test('profiles: a SUP-1 type is an entry type only once the profile is activated', () => {
  const q = { purpose: 'hosting', ref_index: null, asset_hash: hexH(canonical.canonicalize(supAssetDescriptor(ORIGIN))), amount: 1, bytes: 0 };
  assert.throws(() => envelope.signEnvelope(q, alice, { origin: ORIGIN, type: 'sup.spend' }), envelope.EnvelopeError);
  const e = envelope.signEnvelope(q, alice, { origin: ORIGIN, type: 'sup.spend', profiles: ['SUP-1'], created: T });
  assert.equal(entryProblems(buildEntry(e, T), { origin: ORIGIN, profiles: ['SUP-1'] }).length, 0); assert.notEqual(entryProblems(buildEntry(e, T), { origin: ORIGIN }).length, 0);
});
test('chain helpers: nextChain, checkSuccessor and chainBreaks', () => {
  const a = native(), b = native(post('two').q, { ...envelope.nextChain(a), nonce: b64u(new Uint8Array(16).fill(8)) });
  assert.deepEqual(envelope.nextChain(a), { seq: 1, prev: envelope.envelopeHash(a) }); envelope.checkSuccessor(a, b); assert.deepEqual(envelope.chainBreaks([a, b]), []);
  const other = envelope.signEnvelope(post().q, bob, { origin: ORIGIN, type: 'post', seq: 1, prev: envelope.envelopeHash(a) });
  throwsCode(() => envelope.checkSuccessor(a, other), 'sequence'); assert.equal(envelope.chainBreaks([a, other])[0].reason, 'kid');
  throwsCode(() => envelope.checkSuccessor(null, b), 'sequence'); assert.throws(() => envelope.envelopeHash({ ...a, extra: 1 }));
});
test('text envelopes: U, the canonical command, both text schemes and the upgrade verb', () => {
  const session = b64u(utf8('session-0123456!')), u = envelope.unsignedTextEnvelope(post().q, { origin: ORIGIN, type: 'post', kid: kidOf(alice), session, created: T });
  const cmd = envelope.textCommand(u); assert.match(cmd, /^post [A-Za-z0-9_-]+$/); assert.equal(Buffer.from(cmd.slice(5), 'base64url').toString(), canonical.canonicalText(u));
  for (const scheme of ['text-ed25519', 'text-sshsig']) { const e = envelope.signTextEnvelope({ ...u, auth: { scheme, session } }, alice); envelope.verifyEnvelope(e, { now: T }); throwsCode(() => envelope.verifyEnvelope({ ...e, auth: { scheme, session: b64u(utf8('another-session!')) } }, { now: T }), 'bad_signature'); }
  assert.throws(() => envelope.signTextEnvelope(u, bob), /kid/); assert.throws(() => envelope.unsignedTextEnvelope(post().q, { origin: ORIGIN, type: 'post', kid: kidOf(alice), session: 'short', created: T }));
  const up = { mode: 'upgrade', name_norm: 'ada', prev_event_index: 0, new_ed25519: b64u(keys.publicKey(alice)), new_x25519: b64u(keys.x25519PublicKey(ax)), new_tier: 'verified', sig_old: null, sig_new: { scheme: 'ed25519', signature: b64u(new Uint8Array(64)) }, secret_check: b64u(new Uint8Array(64)) };
  assert.match(envelope.textCommand(envelope.unsignedTextEnvelope(up, { origin: ORIGIN, type: 'key.rotate', kid: kidOf(alice), session, created: T })), /^claim-upgrade ada [0-9a-f]{64}$/);
});
test('fallback envelopes: never an agent signature; the policy attestation binds the entry', () => {
  const policy = seed(0xa2), kid = 'unverified:' + b64u(new Uint8Array(16).fill(3));
  const e = { v: 1, protected: { alg: 'none', origin: ORIGIN, type: 'post', kid, created: T, expires: T + 300, nonce: b64u(new Uint8Array(16).fill(4)), seq: 0, prev: null, seen: null }, payload: post().q, auth: { scheme: 'shared-secret' }, sig: null };
  assert.equal(envelope.validateEnvelope(e), 'shared-secret'); throwsCode(() => envelope.verifyEnvelope(e, { now: T }), 'unsupported_scheme');
  const attestation = b64u(keys.sign(envelope.secretAttestationMessage(e, T), policy)); envelope.verifySecretAttestation(e, attestation, kidOf(policy), T);
  assert.deepEqual(entryProblems(buildEntry(e, T, attestation), { origin: ORIGIN, policyKid: kidOf(policy) }), []);
  assert.deepEqual(entryProblems(buildEntry(e, T + 1, attestation), { origin: ORIGIN, policyKid: kidOf(policy) }), ['attestation does not verify with the policy key']);
  assert.notEqual(entryProblems(buildEntry(e, T), { origin: ORIGIN }).length, 0, 'an entry without its attestation');
  assert.throws(() => envelope.validateEnvelope({ ...e, sig: b64u(new Uint8Array(64)) }));
});

// ---------------------------------------------------------------- entries
test('entries: the exact copy of Q, the members, the bindings and the size bound', () => {
  const e = native(), good = buildEntry(e, T); assert.deepEqual(validateEntry(good, { origin: ORIGIN }), good);
  const copy = structuredClone(good); copy.payload.size += 1; assert.deepEqual(entryProblems(copy, { origin: ORIGIN }), ['payload copies of Q differ from the signed Q']);
  const missing = structuredClone(good); delete missing.payload.size; assert.match(entryProblems(missing, { origin: ORIGIN })[0], /copy of Q/);
  const extra = structuredClone(good); extra.payload.note = 'x'; assert.match(entryProblems(extra, { origin: ORIGIN })[0], /copy of Q/);
  assert.match(entryProblems({ ...good, v: 3 }, { origin: ORIGIN })[0], /v must be 2/); assert.match(entryProblems({ ...good, actor_kid: kidOf(bob) }, { origin: ORIGIN })[0], /type\/kid/);
  assert.match(entryProblems({ ...good, origin: 'x.test/a' }, { origin: ORIGIN })[0], /origin/); assert.match(entryProblems({ ...good, extra: 1 }, { origin: ORIGIN })[0], /members/);
  assert.match(entryProblems(buildEntry(e, T + 300), { origin: ORIGIN }).join(), /freshness/);
  const big = structuredClone(good); big.payload.pad = 'x'.repeat(70000); assert(entryProblems(big, { origin: ORIGIN }).includes('entry exceeds 65535 bytes'));
  assert.deepEqual(bodyCommitment(e.payload), { hash: e.payload.body_hash, size: e.payload.size });
});
const H64 = 'ab'.repeat(32), K32 = b64u(keys.publicKey(alice)), kid = kidOf(alice);
for (const [type, q, ts, pattern] of [
  ['poll', { channel_sha256: H64, body_hash: H64, size: 1, title_sha256: H64, options_sha256: [H64, 'cd'.repeat(32)], closes: T + 10, min_key_age_seconds: 0, pow_bits: 25 }, T, /pow_bits/],
  ['poll', { channel_sha256: H64, body_hash: H64, size: 1, title_sha256: H64, options_sha256: [H64, 'cd'.repeat(32)], closes: T, min_key_age_seconds: 0, pow_bits: 0 }, T, /closes > ts/],
  ['poll', { channel_sha256: H64, body_hash: H64, size: 1, title_sha256: H64, options_sha256: [H64, H64], closes: T + 10, min_key_age_seconds: 0, pow_bits: 0 }, T, /options/],
  ['vote', { poll_index: 1, option: 0, pow_nonce: null, reason_sha256: null, body_hash: null, size: 3 }, T, /no body/],
  ['capsule', { owner_kid: kid, to_key_leaf_index: 1, key_hash: H64, encryption: 'x25519-xsalsa20-poly1305', eph_pk: K32, ct_hash: H64, size: 48, expires: T + 7775999, prev_capsule_index: null }, T, /90 days/],
  ['dm', { to_kid: kid, to_key_leaf_index: 1, encryption: 'cleartext', eph_pk: K32, ct_hash: H64, size: 48, seq: 1, prev: H64, grant_index: 1 }, T, /scheme/],
  ['report', { kind: 'daily', day: 1, counts: [{ reason_code: 'sig', count: 0 }, { reason_code: 'expired', count: 1 }] }, T, /sorted/],
  ['report', { kind: 'owner_action', action: 'quote', request_hash: H64, result_hash: H64, asset_hash: H64, amount: 1, quote_index: null }, T, /quote/],
  ['report', { kind: 'gossip', x: 1 }, T, /no closed schema/],
  ['refusal', { envelope_hash: H64, request_hash: null, attempt_kid: null, attempt_nonce: null, attempt_expires: null, reason_code: 'invalid_signature', conflict_index: null, receipt_hash: null }, T, /refusal/],
  ['name.claim', { name_norm: 'ada', prev_event_index: null, ed25519: K32, x25519: K32, tier: 'unverified', recovery_kid: null, recovery_pop: null, initial_grant: null }, T, /unverified claim/],
  ['name.claim', { name_norm: 'Ada', prev_event_index: null, ed25519: K32, x25519: K32, tier: 'verified', recovery_kid: null, recovery_pop: null, initial_grant: null }, T, /name/],
  ['key.rotate', { mode: 'upgrade', name_norm: 'ada', prev_event_index: 0, new_ed25519: K32, new_x25519: null, new_tier: 'verified', sig_old: null, sig_new: { scheme: 'ed25519', signature: b64u(new Uint8Array(64)) }, secret_check: b64u(new Uint8Array(64)) }, T, /new_x25519/],
  ['sup.task', { body_hash: H64, size: 1, asset_hash: H64, reward: 1, max_awards: 1, closes: T + 10 }, T, /no closed schema/],
]) test(`§5.3 schema refuses ${type} (${pattern.source})`, () => assert.match(payloadProblems(type, q, ts, { origin: ORIGIN }).join(' | '), pattern));
test('§5.3 schemas: secret_format codes are a closed expansion over the card patterns', () => {
  const q = { envelope_hash: H64, request_hash: null, attempt_kid: null, attempt_nonce: null, attempt_expires: null, reason_code: 'secret_format:github_pat', conflict_index: null, receipt_hash: null };
  assert.deepEqual(payloadProblems('refusal', q, T, { origin: ORIGIN }), []); assert.deepEqual(payloadProblems('refusal', q, T, { origin: ORIGIN, secretIds: ['github_pat'] }), []);
  assert.notEqual(payloadProblems('refusal', q, T, { origin: ORIGIN, secretIds: [] }).length, 0); assert.notEqual(payloadProblems('refusal', { ...q, reason_code: 'insufficient_balance' }, T, { origin: ORIGIN }).length, 0);
  assert.deepEqual(payloadProblems('refusal', { ...q, reason_code: 'insufficient_balance' }, T, { origin: ORIGIN, profiles: ['SUP-1'] }), []);
});

// ---------------------------------------------------------------- sealed boxes
const dmEnvelope = (ct, o = {}) => envelope.signEnvelope({ to_kid: o.to ?? kidOf(bob), to_key_leaf_index: 2, ...sealed.ciphertextMetadata(ct), ...(o.q ?? {}), grant_index: 2, seq: 0, prev: null }, alice, { origin: ORIGIN, type: 'dm', created: T, nonce: o.nonce });
const sealTo = (nonce, text = 'secret', to = kidOf(bob)) => sealed.seal({ from_kid: kidOf(alice), to_kid: to, envelope_nonce: nonce }, text, keys.x25519PublicKey(bx));
test('sealed: the envelope must commit to ct_hash, eph_pk, size and the scheme before anything is opened', () => {
  const nonce = envelope.newNonce(), ct = sealTo(nonce), e = dmEnvelope(ct, { nonce });
  assert.equal(sealed.openSealed(ct, bx, { envelope: e, recipientKid: kidOf(bob) }).text, 'secret');
  for (const [k, v] of [['ct_hash', '00'.repeat(32)], ['eph_pk', b64u(new Uint8Array(32).fill(9))], ['size', ct.length + 1], ['encryption', 'age-v1']])
    assert.throws(() => sealed.openSealed(ct, bx, { envelope: { ...e, payload: { ...e.payload, [k]: v } } }), sealed.SealedError, k);
  assert.throws(() => sealed.openSealed(ct, bx, { envelope: e, recipientKid: kidOf(mallory) }), /another kid/);
  assert.throws(() => sealed.openSealed(ct, ax, { envelope: e }), /does not open/); assert.throws(() => sealed.openSealed(ct, bx, { envelope: e, expected: sealed.headerFromEnvelope(e) }), /exactly one/);
});
test('sealed: the 4096-byte header bound holds even for a header fully contained in the plaintext', () => {
  assert.throws(() => sealed.splitPlaintext(concat(uint32be(5000), new Uint8Array(5000).fill(0x20))), /out of range/);
  assert.equal(sealed.splitPlaintext(concat(uint32be(4096), new Uint8Array(4096).fill(0x20), utf8('x')))[1].length, 1);
  assert.throws(() => sealed.splitPlaintext(concat(uint32be(0), utf8('x'))), /out of range/); assert.throws(() => sealed.splitPlaintext(Uint8Array.of(0, 0, 1)), /length/);
  assert.throws(() => sealed.framePlaintext(new Uint8Array(4097), new Uint8Array()), /4096/);
});
test('sealed: headers name signing kids and the envelope nonce; content is UTF-8; capsules name their owner twice', () => {
  assert.throws(() => sealTo('nonce-not-16-bytes'), /envelope_nonce/); assert.throws(() => sealed.seal({ from_kid: 'Vkdap1RjR0wChd9d', to_kid: kidOf(bob), envelope_nonce: envelope.newNonce() }, 'x', keys.x25519PublicKey(bx)), /kids/);
  assert.throws(() => sealed.seal({ from_kid: kidOf(alice), to_kid: kidOf(bob), envelope_nonce: envelope.newNonce() }, Uint8Array.of(0xff), keys.x25519PublicKey(bx)), /UTF-8/);
  assert.throws(() => sealed.seal({ from_kid: kidOf(alice), to_kid: kidOf(bob), envelope_nonce: envelope.newNonce() }, 'x', new Uint8Array(32)));
  assert.throws(() => sealed.seal({ from_kid: kidOf(alice), to_kid: kidOf(bob), envelope_nonce: envelope.newNonce() }, 'x'.repeat(65536), keys.x25519PublicKey(bx)), /limit/);
  const nonce = envelope.newNonce(), ct = sealed.seal({ from_kid: kidOf(alice), to_kid: kidOf(alice), envelope_nonce: nonce }, 'memory', keys.x25519PublicKey(ax));
  const cap = envelope.signEnvelope({ owner_kid: kidOf(alice), to_key_leaf_index: 1, key_hash: H64, ...sealed.ciphertextMetadata(ct), expires: T + 7776000, prev_capsule_index: null }, alice, { origin: ORIGIN, type: 'capsule', created: T, nonce });
  assert.deepEqual(sealed.headerFromEnvelope(cap), { from_kid: kidOf(alice), to_kid: kidOf(alice), envelope_nonce: nonce }); assert.equal(sealed.openSealed(ct, ax, { envelope: cap }).text, 'memory');
  assert.throws(() => sealed.headerFromEnvelope(native()), /dm and capsule/);
});

// ---------------------------------------------------------------- SSHSIG and line signatures
test('SSHSIG: the profile is version 1, ssh-ed25519, namespace aics, empty reserved, sha512 and the exact key', () => {
  const msg = linesig.lineMessage('s', 'help'), blob = sshsig.signSshsig(msg, alice); sshsig.verifySshsig(blob, msg, keys.publicKey(alice));
  assert.deepEqual(sshsig.dearmorSshsig('sig-begin\n' + sshsig.armorSshsig(blob) + 'sig-end\n'), blob);
  assert.throws(() => sshsig.verifySshsig(sshsig.signSshsig(msg, alice, 'git'), msg, keys.publicKey(alice)), /namespace/);
  assert.throws(() => sshsig.verifySshsig(blob, msg, keys.publicKey(bob)), /another key/); assert.throws(() => sshsig.verifySshsig(blob, utf8('s\nhelp\n'), keys.publicKey(alice)), /does not verify/);
  const p = sshsig.parseSshsig(blob); assert.equal(p.hashAlgorithm, 'sha512'); assert.throws(() => sshsig.parseSshsig(concat(blob, Uint8Array.of(0))), /Trailing/);
  const sha256 = Buffer.from(blob).toString('latin1').replace('\x00\x00\x00\x06sha512', '\x00\x00\x00\x06sha256'); assert.throws(() => sshsig.verifySshsig(new Uint8Array(Buffer.from(sha256, 'latin1')), msg, keys.publicKey(alice)), /sha512/);
});
test('line signatures: exact bytes only, both reply forms, no repaired variants', () => {
  const sig = linesig.signLine('s', 'post x', alice), pub = keys.publicKey(alice);
  assert(linesig.verifyLine('s', 'post x', sig, pub)); assert(!linesig.verifyLine('s', ' post x ', sig, pub)); assert(!linesig.verifyLine('s', 'post  x', sig, pub));
  const lf = 'sig ' + Buffer.from(keys.sign(utf8('s\npost x\n'), alice)).toString('base64'); assert(!linesig.verifyLine('s', 'post x', lf, pub));
  assert.equal(linesig.lineSignatureForm('s', 'post x', linesig.signLine('s', 'post x', alice, 'sshsig'), pub), 'sshsig');
  assert.throws(() => linesig.signLine('s\nx', 'x', alice)); assert.throws(() => linesig.signLine('s', 'x\ny', alice)); assert.throws(() => linesig.signLine('s', 'post \ud800', alice), /Unicode/);
  assert(!linesig.verifyLine('s', 'post x', sig.replace(/=+$/, '') + 'A', pub)); assert(!linesig.verifyLine('s', 'post x', 'sig ' + Buffer.from(keys.sign(utf8('s\npost x'), alice)).toString('base64url').slice(0, -1) + '-+', pub), 'mixed alphabets');
});

// ---------------------------------------------------------------- HTTP signatures
const rfc = local('http-rfc9421-b26');
test('RFC 9421 B.2.6: exact signature base and Ed25519 signature', () => {
  const headers = http.signRequest(rfc.method, rfc.url, rfc.headers, fromB64(rfc.body), { key: fromHex(rfc.seed), keyid: 'test-key-ed25519', created: rfc.created, expires: null, nonce: null, alg: null, tag: null, components: rfc.components, label: 'sig-b26', addContentDigest: false });
  assert.equal(headers['signature-input'], rfc.signature_input); assert.equal(headers.signature, 'sig-b26=:' + rfc.signature + ':');
  assert.equal(http.verifyRequest(rfc.method, rfc.url, headers, fromB64(rfc.body), () => fromHex(rfc.public), { now: rfc.created + 60, requireExpires: false, requiredComponents: rfc.components })[0].signatureBase, rfc.signature_base);
});
const entryRequest = (o = {}) => {
  const e = o.envelope ?? native(), content = utf8(o.content ?? canonical.canonicalText({ envelope: e, body: null })), url = o.url ?? 'https://api.log.test/v2/entries';
  return { e, content, url, headers: http.signRequest('POST', url, { 'content-type': 'application/json' }, content, { key: alice, envelope: e, ...(o.sign ?? {}) }) };
};
test('§12.1 receiver: the digest, the exact body, the envelope binding and the native envelope', () => {
  const r = entryRequest(); assert.equal(http.verifyEntryRequest('POST', r.url, r.headers, r.content, { now: T, origin: ORIGIN }).envelope.protected.kid, kidOf(alice));
  assert.throws(() => http.verifyEntryRequest('POST', r.url + '?x=1', r.headers, r.content, { now: T }), /no query/);
  assert.throws(() => http.verifyEntryRequest('GET', r.url, r.headers, r.content, { now: T }), /POST/);
  const extra = entryRequest({ content: canonical.canonicalText({ envelope: native(), body: null, x: 1 }) }); assert.throws(() => http.verifyEntryRequest('POST', extra.url, extra.headers, extra.content, { now: T }), /exactly/);
  const { 'content-digest': _d, ...noDigest } = r.headers; assert.throws(() => http.verifyEntryRequest('POST', r.url, noDigest, r.content, { now: T }), /Digest/);
  assert.throws(() => http.verifyEntryRequest('POST', r.url, r.headers, r.content, { now: T + 400 }));
  assert.throws(() => http.signRequest('POST', r.url, {}, r.content, { key: alice, envelope: r.e, nonce: 'x' }), /envelope/); assert.throws(() => http.signRequest('POST', r.url, {}, r.content, { key: bob, envelope: r.e }), /envelope/);
  const authority = http.verifyRequest('POST', r.url, r.headers, r.content, k => keys.parseDidKey(k), { ...http.AICS_VERIFY_POLICY, now: T })[0]; assert.deepEqual(authority.components, [...http.AICS_COMPONENTS]);
  assert.throws(() => http.verifyRequest('POST', 'https://other.test/v2/entries', r.headers, r.content, k => keys.parseDidKey(k), { ...http.AICS_VERIFY_POLICY, now: T }), /Invalid HTTP signature/);
});
test('§12.1 profile: extra components, missing alg and duplicate structured fields are refused', () => {
  const e = native(), content = utf8('{}'), url = 'https://api.log.test/x?a=%2F';
  const withQuery = http.signRequest('POST', url, {}, content, { key: alice, envelope: e, components: [...http.AICS_COMPONENTS, '@query'] });
  assert.throws(() => http.verifyRequest('POST', url, withQuery, content, k => keys.parseDidKey(k), { ...http.AICS_VERIFY_POLICY, now: T }), /exactly/);
  assert.equal(http.verifyRequest('POST', url, withQuery, content, k => keys.parseDidKey(k), { now: T, requiredComponents: [...http.AICS_COMPONENTS, '@query'] }).length, 1);
  assert.throws(() => http.verifyRequest('POST', 'https://api.log.test/x?a=/', withQuery, content, k => keys.parseDidKey(k), { now: T }), /Invalid HTTP signature/);
  const noAlg = http.signRequest('POST', url, {}, content, { key: alice, envelope: e, alg: null }); assert.throws(() => http.verifyRequest('POST', url, noAlg, content, k => keys.parseDidKey(k), { ...http.AICS_VERIFY_POLICY, now: T }), /alg/);
  const dup = { ...withQuery, 'signature-input': withQuery['signature-input'] + ';created=1' }; assert.throws(() => http.verifyRequest('POST', url, dup, content, k => keys.parseDidKey(k), { now: T }), /Duplicate/);
  assert.throws(() => http.signatureBase(['@method', '@method'], '()', 'POST', url, {}), /Duplicate/);
});

// ---------------------------------------------------------------- receipts
test('receipts: only the pinned log key, one line, the exact text and the exact entry', () => {
  const log = new TestLog(), { entry } = log.post(alice, 'x'), note = log.receipt(entry), vk = log.trust.log_vkey;
  const r = verifyReceipt(note, vk, entry); assert.equal(r.deadline, entry.ts + 60);
  const other = new TestLog(); other.log = seed(0xee); assert.throws(() => verifyReceipt(other.receipt(entry), vk, entry), /pinned log key/);
  const twice = Buffer.concat([note, Buffer.from(Buffer.from(note).toString().split('\n\n')[1])]); assert.throws(() => verifyReceipt(new Uint8Array(twice), vk, entry), /pinned log key/);
  assert.throws(() => verifyReceipt(note, vk, { ...entry, ts: entry.ts + 1 }), /leaf hash/);
});

// ---------------------------------------------------------------- cards
const CF = interop('card.json'), policySeed = fromHex(interop('keys.json').ed25519.policy.seed_hex), cardNow = T + 3610;
const resign = card => { const { signatures: _s, ...unsigned } = card, protectedHeader = cardProtectedHeader(CF.policy_kid); return { ...unsigned, signatures: [{ protected: protectedHeader, signature: b64u(keys.sign(cardSigningInput(unsigned, protectedHeader), policySeed)) }] }; };
const supCard = (over = {}) => resign({ ...CF.card.card, spec: 'AICS-1+SUP-1', reason_codes: { ...CF.card.card.reason_codes, refusal: [...CF.card.card.reason_codes.refusal, ...REFUSAL_SUP] }, sup: { asset_hash: hexH(canonical.canonicalize(supAssetDescriptor(CF.card.card.origin))), contributions: [{ network: 'base', asset: 'USDC', decimals: 6, address: '0xabc', units_per_sup: 100 }], intent_seconds: 3600, claim_seconds: 86400, record_seconds: 31536000, storage: null }, ...over });
test('cards: an AICS-1+SUP-1 card with its sup member and the §20.8 codes verifies; base-only rules still apply', () => {
  const v = verifyCard(supCard(), { policyKid: CF.policy_kid, now: cardNow }); assert(v.ok, v.problems.join('; ')); assert.deepEqual(v.profiles, ['SUP-1']);
  assert.match(verifyCard(resign({ ...supCard(), spec: 'AICS-1' }), { policyKid: CF.policy_kid, now: cardNow }).problems.join(), /sup|refusal/);
  assert.match(verifyCard(supCard({ sup: { ...supCard().sup, asset_hash: H64 } }), { policyKid: CF.policy_kid, now: cardNow }).problems.join(), /asset hash/);
  assert.match(verifyCard(supCard({ sup: { ...supCard().sup, intent_seconds: 90000 } }), { policyKid: CF.policy_kid, now: cardNow }).problems.join(), /intent_seconds/);
  // SWARMS-1 is a supported profile now: a base card relabelled as one lacks its R47 member; an unknown profile is refused.
  assert.match(verifyCard(resign({ ...CF.card.card, spec: 'AICS-1+SWARMS-1' }), { policyKid: CF.policy_kid, now: cardNow }).problems.join(), /missing swarms/);
  assert.match(verifyCard(resign({ ...CF.card.card, spec: 'AICS-1+OTHER-1' }), { policyKid: CF.policy_kid, now: cardNow }).problems.join(), /\$\.spec/);
});
for (const [name, change, pattern] of [
  ['a null ciphertext budget (finding F27)', c => { c.retention = { ...c.retention, ciphertext_budget_bytes: null }; }, /ciphertext_budget_bytes/],
  ['a control character in a claim', c => { c.assurances = c.assurances.map((a, i) => i ? a : { ...a, claim: 'G1\u001b[2J' }); }, /control/],
  ['an N assurance that is promised', c => { c.assurances = c.assurances.map(a => a.id === 'N1' ? { ...a, status: 'promised' } : a); }, /not-offered/],
  ['a missing G10', c => { c.assurances = c.assurances.filter(a => a.id !== 'G10'); }, /G10/],
  ['a witness that reuses the log key', c => { c.witness_policy = { quorum: 1, witnesses: [{ name: 'w', vkey: interop('keys.json').ed25519.log.vkey, trust_domain: 'x', independent: false }] }; }, /witness|vkey/],
  ['a quorum above the witnesses', c => { c.witness_policy = { ...c.witness_policy, quorum: 3 }; }, /quorum/],
  ['an http tile prefix', c => { c.tile_prefixes = ['http://api.interop.test/tiles']; }, /https/],
  ['a gate port outside 1-65535', c => { c.gate = { ...c.gate, tls_port: 70000 }; }, /tls_port/],
  ['the same gate port twice', c => { c.gate = { ...c.gate, plaintext_port: c.gate.tls_port }; }, /plaintext_port/],
  ['an unregistered tier', c => { c.tiers = [...c.tiers, 'gold']; }, /tiers/],
  ['issued_at after expires', c => { c.expires = c.issued_at; }, /issued_at/],
  ['a dm retention below 90 days', c => { c.retention = { ...c.retention, dm_seconds: 86400 }; }, /dm_seconds/],
]) test(`cards: §13.1 refuses ${name}`, () => { const c = structuredClone(CF.card.card); change(c); assert.match(cardProblems(c).join(' | '), pattern); assert.equal(verifyCard(resign(c), { policyKid: CF.policy_kid, now: cardNow }).ok, false); });
test('cards: the gate names the instance\'s own ports (a staging card beside production, §13.1)', () => {
  const c = structuredClone(CF.card.card); c.gate = { ...c.gate, tls_port: 7800, plaintext_port: 7801 };
  assert.deepEqual(cardProblems(c), []);
  assert.equal(verifyCard(resign(c), { policyKid: CF.policy_kid, now: cardNow }).ok, true);
});
test('cards: a signature under another protected header or key is refused; the hash covers the signatures', () => {
  const c = structuredClone(CF.card.card); c.signatures = [{ ...c.signatures[0], protected: b64u(canonical.canonicalize({ alg: 'EdDSA', kid: CF.policy_kid, typ: 'JWT' })) }];
  assert.match(verifyCard(c, { policyKid: CF.policy_kid, now: cardNow }).problems.join(), /protected/);
  assert.notEqual(cardHash(resign(CF.card.card)), cardHash({ ...CF.card.card, signatures: [] }));
  assert.throws(() => verifyCard(CF.card.card, {}), /policy kid/);
});

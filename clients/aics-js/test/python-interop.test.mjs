// Fresh artifacts made by this client (random nonces, random ephemeral keys, both text schemes, both line-signature
// forms) verified live by the Python reference package aics-identity in this repository. The byte-fixed artifacts are
// compared with packages/aics-interop/fixtures in aics1-fixtures.test.mjs; this checks the producer side end to end.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { generateKeypair, generateX25519Keypair, didKey } from '../dist/keys.js';
import { signEnvelope, unsignedTextEnvelope, signTextEnvelope, nextChain, newNonce } from '../dist/envelope.js';
import { canonicalize } from '../dist/canonical.js';
import { b64u, hexH, utf8 } from '../dist/bytes.js';
import { signRequest } from '../dist/http-signatures.js';
import { signLine } from '../dist/linesig.js';
import { seal, ciphertextMetadata } from '../dist/sealed.js';
const here = fileURLToPath(new URL('..', import.meta.url)), identity = path.resolve(here, '../../packages/aics-identity');
const uv = spawnSync('uv', ['--version'], { encoding: 'utf8' });
const available = uv.status === 0 && existsSync(path.join(identity, '.venv'));
test('live: aics-identity (Python) verifies envelopes, text envelopes, §12.1 requests, line signatures and sealed boxes made here', { skip: available ? false : 'uv or packages/aics-identity/.venv is not available' }, () => {
  const origin = 'api.live.test/tiles', a = generateKeypair(), b = generateKeypair(), bx = generateX25519Keypair(), now = Math.floor(Date.now() / 1000);
  const body = canonicalize({ channel: 'live', title: null, text: 'from node' }), q = { channel_sha256: hexH(utf8('live')), parent_index: null, body_hash: hexH(body), size: body.length, title_sha256: null };
  const e0 = signEnvelope(q, a.privateKey, { origin, type: 'post', created: now }), e1 = signEnvelope(q, a.privateKey, { origin, type: 'post', created: now, ...nextChain(e0) });
  const session = b64u(crypto.getRandomValues(new Uint8Array(16)));
  const texts = ['text-ed25519', 'text-sshsig'].map(scheme => signTextEnvelope(unsignedTextEnvelope(q, { origin, type: 'post', kid: didKey(a.publicKey), session, scheme, created: now }), a.privateKey));
  const content = canonicalize({ envelope: e1, body: b64u(body) }), url = 'https://api.live.test/v2/entries';
  const headers = signRequest('POST', url, { 'content-type': 'application/json' }, content, { key: a.privateKey, envelope: e1 });
  const nonce = newNonce(), to = didKey(b.publicKey), ct = seal({ from_kid: didKey(a.publicKey), to_kid: to, envelope_nonce: nonce }, 'privé ✓', bx.publicKey);
  const dm = signEnvelope({ to_kid: to, to_key_leaf_index: 2, ...ciphertextMetadata(ct), grant_index: 2, ...nextChain(e1) }, a.privateKey, { origin, type: 'dm', created: now, nonce, ...nextChain(e1) });
  const lines = ['raw', 'sshsig'].map(form => ({ session, line: 'claim live-agent ' + 'ab'.repeat(32), signature: signLine(session, 'claim live-agent ' + 'ab'.repeat(32), a.privateKey, form), kid: didKey(a.publicKey), form }));
  const data = { envelopes: [e0, e1, dm], text_envelopes: texts, requests: [{ method: 'POST', url, headers, body_b64: Buffer.from(content).toString('base64'), envelope: e1 }], lines,
    sealed: [{ ciphertext_b64: Buffer.from(ct).toString('base64'), secret_hex: Buffer.from(bx.privateKey).toString('hex'), envelope: dm, recipient_kid: to, text: 'privé ✓' }] };
  for (const dir of ['.cache/uv', '.tmp']) mkdirSync(path.join(here, dir), { recursive: true });
  const r = spawnSync('uv', ['run', '--no-sync', 'python', '-I', path.join(here, 'test/python/verify_js.py')], { cwd: identity, input: JSON.stringify(data), encoding: 'utf8', timeout: 60000,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1', UV_CACHE_DIR: path.join(here, '.cache/uv'), UV_PYTHON_DOWNLOADS: 'never', TMPDIR: path.join(here, '.tmp') } });
  assert.equal(r.status, 0, r.stderr || r.error?.message);
  for (const [kind, n] of [['envelopes', 3], ['text_envelopes', 2], ['requests', 1], ['lines', 2], ['sealed', 1]]) assert.match(r.stdout, new RegExp(`verified ${n} ${kind}`));
});

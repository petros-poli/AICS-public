// The gate client (HTTPS POST/GET, TLS and plain TCP), the §12.1 HTTP client and the CLI, against loopback servers.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, readFile, stat, mkdir } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { HttpsGateClient, TcpGateClient, SessionExpiredError, onboard, parseGateEvidence } from '../dist/gate.js';
import { AicsClient, ApiError, RefusalError } from '../dist/client.js';
import { signEnvelope, unsignedTextEnvelope, textCommand, nextChain, envelopeHash } from '../dist/envelope.js';
import { buildEntry, entryBytes } from '../dist/entry.js';
import { canonicalText, canonicalize, parseJson } from '../dist/canonical.js';
import { b64u, hexH, utf8 } from '../dist/bytes.js';
import { verifyEntryRequest } from '../dist/http-signatures.js';
import { publicKey, sign, x25519PublicKey } from '../dist/keys.js';
import { verifyLine } from '../dist/linesig.js';
import { TestLog, seed, kidOf, T } from './log-builder.mjs';
import { interop } from './interop-fixtures.mjs';
const fixture = name => JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), 'utf8'));
const agent = seed(0xe1), agentX = seed(0xe2), sid = b64u(utf8('session-0123456!')), now = () => Math.floor(Date.now() / 1000);
const log = new TestLog('test.example/tiles'), origin = log.origin;
/** A scripted §11.4 gate: proposes U, checks the signature, answers with the entry, receipt and checkpoint lines. */
function dialogue({ tamper = false, noProposal = false, badEntry = false } = {}) {
  const seen = []; let claim, u;
  const reply = line => {
    seen.push(line);
    if (!line) return `session ${sid}\n? Which of these can you run: openssl, ssh-keygen, python3? Reply exactly: tools <space-separated list> or tools none\n>\n`;
    if (line === 'tools openssl') return '? Reply exactly: pub <base64 of 32 bytes>\n>\n';
    if (line.startsWith('pub ')) { assert.equal(line, 'pub ' + Buffer.from(publicKey(agent)).toString('base64')); return '? Reply exactly: enc <base64 of 32-byte X25519 public key>\n>\n'; }
    if (line.startsWith('enc ')) { assert.equal(line, 'enc ' + Buffer.from(x25519PublicKey(agentX)).toString('base64')); return '? Reply exactly: recovery <base64 of 32-byte Ed25519 public key> or recovery none\n>\n'; }
    if (line === 'recovery none') return '? Reply exactly: name <name>\n>\n';
    if (line === 'name node-agent') return 'ok name node-agent is free\n? Reply exactly: closed or open <max messages> <expiry Unix seconds>\n>\n';
    if (line === 'closed') {
      const q = { name_norm: 'node-agent', prev_event_index: null, ed25519: b64u(publicKey(agent)), x25519: b64u(x25519PublicKey(agentX)), tier: 'verified', recovery_kid: null, recovery_pop: null, initial_grant: tamper ? { sender_kid: '*', max: 100, expires: 9999999999 } : null };
      u = unsignedTextEnvelope(q, { origin, type: 'name.claim', kid: kidOf(agent), session: sid, created: now() }); claim = textCommand(u);
      return (noProposal ? '' : `ok envelope ${b64u(canonicalize(u))}\n`) + `? Sign this exactly: ${claim}\n>\n`;
    }
    if (line === claim) return '? Reply exactly: sig <base64> (the 64-byte Ed25519 signature of the signing input)\n>\n';
    if (line.startsWith('sig ')) {
      assert(verifyLine(sid, claim, line, publicKey(agent)));
      const e = { ...u, sig: b64u(Buffer.from(line.slice(4), 'base64')) }, entry = buildEntry(e, e.protected.created);
      if (badEntry) entry.payload.envelope = { ...entry.payload.envelope, sig: b64u(new Uint8Array(64)) };
      return `ok name node-agent bound to key ${kidOf(agent)} at leaf 1; verify at /tiles\nentry ${b64u(entryBytes(entry))}\nreceipt ${b64u(log.receipt(entry))}\ncheckpoint ${b64u(log.note())}\n>\n`;
    }
    if (line === 'help') return 'ok help\n>\n';
    return 'err malformed unexpected command\n>\n';
  };
  return { reply, seen };
}
async function listen(t, server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections?.(); })); return server.address().port; }
const memory = d => ({ session: sid, start: async () => d.reply(''), send: async line => d.reply(line), close() {} });
for (const method of ['POST', 'GET']) test(`${method} text gate onboarding inspects U, signs the exact claim and verifies the entry and receipt`, async t => {
  const d = dialogue(); const server = http.createServer(async (req, res) => {
    let body = ''; for await (const c of req) body += c; const url = new URL(req.url, 'http://test'); let line;
    if (method === 'GET') { assert.equal(req.method, 'GET'); line = url.searchParams.get('l'); if (d.seen.length) assert.equal(url.searchParams.get('s'), sid); }
    else { assert.match(req.headers['content-type'], /^text\/plain/); const lines = body.trimEnd().split('\n'); if (d.seen.length) assert.equal(lines.shift(), 'session ' + sid); line = lines.join('\n'); }
    res.end(d.reply(line));
  }); const port = await listen(t, server);
  const c = new HttpsGateClient(`http://127.0.0.1:${port}/t`, { method, allowHttp: true });
  const r = await onboard(c, { name: 'node-agent', signingKey: seed(0xe1), encryptionKey: agentX, origin, logKey: log.trust.log_vkey });
  assert.equal(r.kid, kidOf(agent)); assert.equal(r.index, 1); assert.equal(r.receipt.submitted_at, r.entry.ts); assert.equal(r.entry.type, 'name.claim'); assert(d.seen.includes('closed'));
  if (method === 'GET') await assert.rejects(() => c.send('post unsafe'), /GET gate/); assert.equal(await c.send('help'), 'ok help\n>\n');
});
test('Onboarding refuses to sign without a proposed U, a changed grant, or an entry that does not embed the signature', async () => {
  for (const [opts, pattern] of [[{ noProposal: true }, /without proposing U/], [{ tamper: true }, /differs/], [{ badEntry: true }, /not valid|does not embed/]]) {
    const d = dialogue(opts); await assert.rejects(() => onboard(memory(d), { name: 'node-agent', signingKey: agent, encryptionKey: agentX, origin }), pattern);
    if (!opts.badEntry) assert(!d.seen.some(l => l.startsWith('sig ')), 'no signature leaves the client');
  }
  const d = dialogue(); await assert.rejects(() => onboard(memory(d), { name: 'node-agent', signingKey: agent, encryptionKey: agentX, origin: 'other.example/tiles' }), /origin/);
  const other = new TestLog(origin); other.log = seed(0x77); await assert.rejects(() => onboard(memory(dialogue()), { name: 'node-agent', signingKey: agent, encryptionKey: agentX, origin, logKey: other.trust.log_vkey }), /pinned log key/);
  await assert.rejects(() => onboard(memory(dialogue()), { name: 'node-agent', signingKey: agent, origin }), /X25519/);
});
test('Gate evidence lines are parsed exactly once each', () => {
  const ev = parseGateEvidence('ok write\nentry AAEC\nreceipt AwQF\n>\n'); assert.deepEqual([...ev.entry], [0, 1, 2]); assert.deepEqual([...ev.receipt], [3, 4, 5]);
  assert.throws(() => parseGateEvidence('entry AA\nentry AA\n'), /Repeated/); assert.throws(() => parseGateEvidence('entry AA==\n'));
});
test('HTTP gate refuses session replacement, secret GET and multiline injection', async () => {
  let n = 0; const c = new HttpsGateClient(undefined, { method: 'GET', fetch: async () => new Response(`session ${n++ ? 'new-session' : sid}\nok help\n>\n`) });
  await c.start(); await assert.rejects(() => c.send('help'), SessionExpiredError); await assert.rejects(() => c.send('secret abc')); await assert.rejects(() => c.send('help\npost x')); assert.throws(() => new HttpsGateClient('http://example.com/t'));
});
for (const secure of [false, true]) test(`${secure ? 'TLS' : 'plain TCP'} gate handles fragmented frames and onboarding`, async t => {
  const d = dialogue(); const connection = socket => { socket.on('error', () => {}); const greeting = d.reply(''); socket.write(greeting.slice(0, 9)); setTimeout(() => socket.write(greeting.slice(9)), 2); let buffer = ''; socket.setEncoding('utf8'); socket.on('data', chunk => { buffer += chunk; while (buffer.includes('\n')) { const end = buffer.indexOf('\n'), line = buffer.slice(0, end); buffer = buffer.slice(end + 1); socket.write(d.reply(line)); } }); };
  const cert = fixture('tls-localhost'), server = secure ? tls.createServer(cert, connection) : net.createServer(connection); const port = await listen(t, server);
  const c = new TcpGateClient({ host: '127.0.0.1', port, tls: secure, ca: cert.cert, timeoutMs: 3000 }); t.after(() => c.close());
  assert.equal((await onboard(c, { name: 'node-agent', signingKey: agent, encryptionKey: agentX, origin })).kid, kidOf(agent)); c.close();
});
test('TCP TLS rejects an untrusted certificate', async t => {
  const server = tls.createServer(fixture('tls-localhost'), socket => socket.end('ok\n>\n')); server.on('tlsClientError', () => {}); const port = await listen(t, server);
  const c = new TcpGateClient({ host: '127.0.0.1', port, timeoutMs: 1000 }); t.after(() => c.close()); await assert.rejects(() => c.start()); c.close();
});
test('HTTPS gate validates TLS using the platform fetch transport', async t => {
  const server = https.createServer(fixture('tls-localhost'), (_req, res) => res.end('ok\n>\n')); const port = await listen(t, server); await assert.rejects(() => new HttpsGateClient(`https://127.0.0.1:${port}/t`).start());
});
test('TCP timeout and early close reject the pending exchange; an idle prompt does not time out', async t => {
  const sockets = []; const server = net.createServer(socket => sockets.push(socket)); const port = await listen(t, server); t.after(() => sockets.forEach(s => s.destroy()));
  const c = new TcpGateClient({ host: '127.0.0.1', port, tls: false, timeoutMs: 50 }); await assert.rejects(() => c.start(), /timeout/); c.close(); sockets.forEach(s => s.destroy());
  const live = net.createServer(socket => { socket.on('error', () => {}); socket.write(`session ${sid}\nok ready\n>\n`); socket.on('data', () => socket.write('ok help\n>\n')); }); const p2 = await listen(t, live);
  const g = new TcpGateClient({ host: '127.0.0.1', port: p2, tls: false, timeoutMs: 25 }); t.after(() => g.close()); await g.start(); await new Promise(r => setTimeout(r, 50)); assert.equal(await g.send('help'), 'ok help\n>\n'); g.close();
});

// ---------------------------------------------------------------- the §12.1 HTTP client
/** A loopback §12.1 server over the test log: it verifies each native write as the binding requires. */
async function apiServer(t, { refuse, rewrite } = {}) {
  const tl = new TestLog(origin), requests = []; tl.charter();
  const server = http.createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c); const body = Buffer.concat(chunks), url = `http://127.0.0.1:${server.address().port}${req.url}`;
    requests.push({ method: req.method, url: req.url, signed: 'signature' in req.headers });
    const json = (status, v, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', ...headers }); res.end(canonicalText(v)); };
    if (req.method === 'POST' && req.url === '/v2/entries') {
      assert.equal(+req.headers['content-length'], body.length);
      const { envelope } = verifyEntryRequest('POST', url, req.headers, new Uint8Array(body), { origin });
      if (refuse) { const r = tl.refusal(envelope, refuse, 1); return json(409, { entry: r.entry, receipt_note: b64u(tl.receipt(r.entry)) }, { 'x-aics-hint': 'test refusal' }); }
      const r = tl.append(null, null, null, { envelope, ts: envelope.protected.created }); const entry = rewrite ? rewrite(r.entry) : r.entry;
      return json(202, { entry, receipt_note: b64u(tl.receipt(r.entry)) }, { location: `/v2/entries/${r.index}` });
    }
    const m = /^\/v2\/entries\/(\d+)$/.exec(req.url);
    if (m) { const i = Number(m[1]), b = tl.bundleFor?.(i); return b ? json(200, b, { 'x-aics-body-status': 'available' }) : json(404, { detail: 'no entry' }); }
    if (req.url === '/v2/bodies/' + hexH(utf8('body'))) { res.end('body'); return; }
    if (req.url === '/v2/bodies/' + 'ab'.repeat(32)) { res.end('not the body'); return; }
    if (req.url === '/v2/bodies/' + 'cd'.repeat(32)) return json(410, { state: 'tombstoned', tombstone_index: 3, reason_code: 'erasure', policy_index: null });
    return json(200, { evidence: 'unverified response' });
  });
  const port = await listen(t, server); return { tl, requests, base: `http://127.0.0.1:${port}` };
}
const postQ = text => { const b = canonicalize({ channel: 'test', title: null, text }); return { q: { channel_sha256: hexH(utf8('test')), parent_index: null, body_hash: hexH(b), size: b.length, title_sha256: null }, body: b }; };
test('submit: a signed POST /v2/entries; the accepted entry embeds the envelope and its receipt verifies under the pinned log key', async t => {
  const s = await apiServer(t), client = new AicsClient({ baseUrl: s.base, allowHttp: true, signingKey: agent, trust: { origin, logKey: s.tl.trust.log_vkey, policyKid: s.tl.trust.policy_kid } });
  const claim = signEnvelope({ name_norm: 'node-agent', prev_event_index: null, ed25519: b64u(publicKey(agent)), x25519: b64u(x25519PublicKey(agentX)), tier: 'verified', recovery_kid: null, recovery_pop: null, initial_grant: null }, agent, { origin, type: 'name.claim' });
  const r = await client.submit(claim); assert.equal(r.entry.type, 'name.claim'); assert.equal(r.receipt.submitted_at, r.entry.ts); assert.equal(r.location, '/v2/entries/1');
  const { q, body } = postQ('hello'), p = signEnvelope(q, agent, { origin, type: 'post', ...nextChain(claim) }); const r2 = await client.submit(p, body); assert.equal(r2.entry.payload.body_hash, q.body_hash);
  await assert.rejects(() => client.submit(signEnvelope(q, agent, { origin, type: 'post', ...nextChain(p) }), utf8('other body')), /commitment/);
  await assert.rejects(() => client.submit(signEnvelope(q, seed(0xe9), { origin, type: 'post' }), body), /client key/);
  await assert.rejects(() => new AicsClient({ baseUrl: s.base, allowHttp: true }).submit(p), /Signing key/);
});
test('submit: a logged refusal is evidence (RefusalError with the policy-signed entry and receipt); a forged acceptance is refused', async t => {
  const s = await apiServer(t, { refuse: 'rate_limit' }), client = new AicsClient({ baseUrl: s.base, allowHttp: true, signingKey: agent, trust: { origin, logKey: s.tl.trust.log_vkey, policyKid: s.tl.trust.policy_kid } });
  const { q, body } = postQ('refused'), e = signEnvelope(q, agent, { origin, type: 'post' });
  await assert.rejects(() => client.submit(e, body), err => err instanceof RefusalError && err.reasonCode === 'rate_limit' && err.conflictIndex === 1 && err.entry.payload.envelope_hash === envelopeHash(e) && err.receipt.entry_hash.length === 64 && err.hint === 'test refusal');
  const forged = await apiServer(t, { rewrite: entry => ({ ...entry, ts: entry.ts + 1 }) });
  await assert.rejects(() => new AicsClient({ baseUrl: forged.base, allowHttp: true, signingKey: agent, trust: { origin, logKey: forged.tl.trust.log_vkey } }).submit(signEnvelope(q, agent, { origin, type: 'post' }), body), /leaf hash|receipt/);
  const swapped = await apiServer(t, { rewrite: entry => buildEntry(signEnvelope(q, agent, { origin, type: 'post', created: entry.ts }), entry.ts) });
  await assert.rejects(() => new AicsClient({ baseUrl: swapped.base, allowHttp: true, signingKey: agent }).submit(signEnvelope(q, agent, { origin, type: 'post' }), body), /embed/);
});
test('reads are anonymous: bundles are verified under the pinned trust, bodies are re-hashed, statuses parsed', async t => {
  const s = await apiServer(t), b = interop('bundles.json'), keys = interop('keys.json');
  s.tl.bundleFor = i => i === 7 ? b.aics1_wire_bundle.bundle : i === 6 ? { ...b.aics1_wire_bundle.bundle, index: 6 } : null;
  const trust = { origin: 'api.interop.test/tiles', logKey: b.log_vkey, witnesses: b.witness_vkeys, quorum: 2 };
  const client = new AicsClient({ baseUrl: s.base, allowHttp: true, signingKey: agent, trust });
  const r = await client.entry(7); assert.equal(r.verification.status, 'valid'); assert.equal(r.verification.history, 'incomplete'); assert.equal(r.bodyStatus, 'available');
  await assert.rejects(() => client.entry(6), /invalid/); await assert.rejects(() => client.entry(9), e => e instanceof ApiError && e.status === 404);
  assert.equal((await new AicsClient({ baseUrl: s.base, allowHttp: true }).entry(7)).verification, null);
  await assert.rejects(() => new AicsClient({ baseUrl: s.base, allowHttp: true, trust: { ...trust, logKey: keys.ed25519.other_log.vkey } }).entry(7), /checkpoint/);
  assert.equal(Buffer.from((await client.body(hexH(utf8('body')))).bytes).toString(), 'body'); await assert.rejects(() => client.body('ab'.repeat(32)), /does not match/);
  assert.deepEqual(await client.body('cd'.repeat(32)), { state: 'tombstoned', tombstone_index: 3, reason_code: 'erasure', policy_index: null });
  await client.index('ab'.repeat(32)); await client.consistency(1, 2); await client.inclusion(0, 2); await client.name('node-agent'); await client.inbox(kidOf(agent), 0);
  assert(s.requests.every(r => !r.signed), 'no read carries a signature'); assert(s.requests.some(r => r.url === '/v2/tlog/consistency?from=1&to=2'));
});
test('notice is keyless on the pages host; API errors retain their bytes; HTTPS is required', async () => {
  const client = new AicsClient({ signingKey: agent, fetch: async (url, init) => { assert.equal(new URL(url).host, 'wesupport-ai.com'); assert.equal(init.headers.signature, undefined); return new Response('{"notice_id":"one"}'); } });
  assert.equal((await client.notice({ message: 'test' })).notice_id, 'one');
  const bad = new AicsClient({ fetch: async () => new Response('{"detail":"x"}', { status: 409 }) }); await assert.rejects(() => bad.name('a'), e => e instanceof ApiError && e.status === 409 && Buffer.from(e.body).toString().includes('detail'));
  assert.throws(() => new AicsClient({ baseUrl: 'http://example.com' }));
});

// ---------------------------------------------------------------- the CLI
const here = fileURLToPath(new URL('..', import.meta.url));
const cli = (...args) => spawnSync(process.execPath, [path.join(here, 'dist/cli.js'), ...args], { encoding: 'utf8', timeout: 20000 });
const tmp = async name => { await mkdir(path.join(here, '.tmp'), { recursive: true }); return mkdtemp(path.join(here, `.tmp/${name}-`)); };
test('CLI keys new/show (did:key kid), sign-line and strict verify-line in both forms, no overwrites', async () => {
  const dir = await tmp('cli'), key = path.join(dir, 'aics.key');
  let r = cli('keys', 'new', '--out', key); assert.equal(r.status, 0, r.stderr); const identity = JSON.parse(r.stdout); assert.equal((await stat(key)).mode & 0o777, 0o600); assert.equal((await readFile(key + '.x25519')).length, 32);
  assert.match(identity.kid, /^did:key:z6Mk/); assert.equal(identity.kid, identity.did);
  r = cli('keys', 'new', '--out', key); assert.notEqual(r.status, 0); assert.match(r.stderr, /overwrite/);
  r = cli('keys', 'show', '--key', key); assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).kid, identity.kid);
  await writeFile(path.join(dir, 'pub'), identity.kid);
  r = cli('sign-line', '--key', key, '--session=-session', '--line', 'claim node x'); assert.equal(r.status, 0, r.stderr); const sig = r.stdout.trim();
  r = cli('verify-line', '--public-key', path.join(dir, 'pub'), '--session=-session', '--line', 'claim node x', '--signature', sig); assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).form, 'raw');
  r = cli('verify-line', '--public-key', path.join(dir, 'pub'), '--session=-session', '--line', 'claim node x ', '--signature', sig); assert.notEqual(r.status, 0, 'no whitespace repair');
  r = cli('sign-line', '--key', key, '--session', 's1', '--line', 'help', '--sshsig'); assert.equal(r.status, 0, r.stderr); await writeFile(path.join(dir, 'sig.txt'), r.stdout);
  r = cli('verify-line', '--public-key', path.join(dir, 'pub'), '--session', 's1', '--line', 'help', '--signature-file', path.join(dir, 'sig.txt')); assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).form, 'sshsig');
});
test('CLI verify checkpoint and consistency authenticate fixture notes and reject tampered proofs', async () => {
  const v = fixture('tlog-python'), dir = await tmp('log');
  for (const [name, value] of Object.entries({ 'log.vkey': v.log_vkey, 'old.note': v.notes[256], 'new.note': v.notes[513], 'policy.json': JSON.stringify({ quorum: 1, witnesses: [v.witness_vkey], max_checkpoint_age: 300 }), 'proof.json': JSON.stringify(v.consistency.find(p => p.old === 256 && p.new === 513)?.hashes) })) await writeFile(path.join(dir, name), value);
  const base = ['--vkey-file', path.join(dir, 'log.vkey'), '--witness-policy', path.join(dir, 'policy.json'), '--now', String(v.timestamp)];
  let r = cli('verify', 'checkpoint', '--note', path.join(dir, 'new.note'), ...base); assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).freshness, 'verified');
  r = cli('verify', 'consistency', '--old', path.join(dir, 'old.note'), '--new', path.join(dir, 'new.note'), '--proof', path.join(dir, 'proof.json'), ...base); assert.equal(r.status, 0, r.stderr);
  await writeFile(path.join(dir, 'proof.json'), '[]'); r = cli('verify', 'consistency', '--old', path.join(dir, 'old.note'), '--new', path.join(dir, 'new.note'), '--proof', path.join(dir, 'proof.json'), ...base); assert.notEqual(r.status, 0); assert.match(r.stderr, /consistency proof failed/);
});
test('CLI verify bundle, receipt and card with pins from the published trust bundle', async () => {
  const dir = await tmp('evidence'), b = interop('bundles.json'), rc = interop('receipts.json'), card = interop('card.json'), tb = interop('trust-bundle.json');
  const files = { 'trust.txt': tb.readme_block, 'bundle.json': JSON.stringify(b.aics1_wire_bundle.bundle), 'policy.json': JSON.stringify({ quorum: 2, witnesses: b.witness_vkeys, max_checkpoint_age: 300 }), 'receipt.note': rc.receipt_text, 'entry.json': Buffer.from(rc.entry_u64, 'base64url').toString(), 'card.json': canonicalText(card.card.card), 'bad-card.json': canonicalText(card.altered.card), 'tampered.json': JSON.stringify(b.tampered_wire_bundles[0].bundle) };
  for (const [name, value] of Object.entries(files)) await writeFile(path.join(dir, name), value);
  const pin = ['--trust', path.join(dir, 'trust.txt')];
  let r = cli('verify', 'bundle', '--bundle', path.join(dir, 'bundle.json'), ...pin, '--witness-policy', path.join(dir, 'policy.json')); assert.equal(r.status, 0, r.stderr); const out = JSON.parse(r.stdout); assert.equal(out.status, 'valid'); assert.equal(out.history, 'incomplete'); assert.equal(out.witnesses.length, 2);
  r = cli('verify', 'bundle', '--bundle', path.join(dir, 'tampered.json'), ...pin, '--witness-policy', path.join(dir, 'policy.json')); assert.notEqual(r.status, 0); assert.match(r.stderr, /inclusion/);
  r = cli('verify', 'bundle', '--bundle', path.join(dir, 'bundle.json'), ...pin, '--witness-policy', path.join(dir, 'policy.json'), '--profile', 'SWARMS-1', '--profile', 'SUP-1'); assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).status, 'valid');
  r = cli('verify', 'bundle', '--bundle', path.join(dir, 'bundle.json'), ...pin, '--witness-policy', path.join(dir, 'policy.json'), '--profile', 'OTHER-1'); assert.notEqual(r.status, 0); assert.match(r.stderr, /--profile is one of SUP-1, SWARMS-1/);
  r = cli('verify', 'receipt', '--receipt', path.join(dir, 'receipt.note'), '--entry', path.join(dir, 'entry.json'), ...pin); assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).deadline, rc.entry_ts + 60);
  r = cli('verify', 'card', '--card', path.join(dir, 'card.json'), ...pin, '--first-use', '--now', String(T + 3610)); assert.equal(r.status, 0, r.stderr); assert.equal(JSON.parse(r.stdout).ok, true);
  r = cli('verify', 'card', '--card', path.join(dir, 'bad-card.json'), ...pin, '--now', String(T + 3610)); assert.equal(r.status, 2); assert.equal(JSON.parse(r.stdout).ok, false);
  await writeFile(path.join(dir, 'wrong.txt'), tb.readme_block_wrong_digest.text); r = cli('verify', 'receipt', '--receipt', path.join(dir, 'receipt.note'), '--entry', path.join(dir, 'entry.json'), '--trust', path.join(dir, 'wrong.txt')); assert.notEqual(r.status, 0); assert.match(r.stderr, /sha256/);
});

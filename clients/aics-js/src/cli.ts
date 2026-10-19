#!/usr/bin/env node
import { readFile, writeFile, access } from 'node:fs/promises';
import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';
import { assert, decodeB64, decodeB64u, hex } from './bytes.js';
import { isObject, parseJson, type JsonObject } from './canonical.js';
import { verifyBundle } from './bundle.js';
import { verifyCard } from './card.js';
import { AicsClient } from './client.js';
import { entryBytes, entryHash, type Entry } from './entry.js';
import { agentIdentity, exportPrivateKey, generateKeypair, generateX25519Keypair, importPrivateKey, parsePublicKey, x25519DidKey } from './keys.js';
import { lineSignatureForm, signLine } from './linesig.js';
import { HttpsGateClient, TcpGateClient, onboard } from './gate.js';
import { verifyReceipt } from './receipt.js';
import { HttpTileReader, TileTree, parseVkey, readVkeyFile, verifyCheckpoint, verifyConsistency, type VKey, type WitnessPolicy } from './tlog.js';
import { trustBundleFromReadme, trustBundleFromTxt, validateTrustBundle, type TrustBundle } from './trust.js';
const usage = `aics-js — Node 20+ AICS-1 client
  keys new --out aics.key [--x25519-out aics.key.x25519]
  keys show --key aics.key
  sign-line --key aics.key --session ID --line 'claim name commitment' [--sshsig]
  verify-line --public-key aics.pub --session ID --line LINE (--signature 'sig BASE64' | --signature-file sig.txt)
  verify checkpoint (--tiles URL [--mirror URL] | --note checkpoint.note) PIN [--witness-policy policy.json]
    [--previous previous.note] [--save checkpoint.note] [--now UNIX_SECONDS]
  verify consistency --old old.note --new new.note PIN (--tiles URL | --proof proof.json) [--witness-policy policy.json] [--now UNIX_SECONDS]
  verify bundle --bundle bundle.json PIN [--witness-policy policy.json] [--now UNIX_SECONDS]
  verify receipt --receipt receipt.note --entry entry.json PIN
  verify card --card card.json PIN [--first-use] [--now UNIX_SECONDS]
  entry --index N [--api https://api.wesupport-ai.com] PIN [--witness-policy policy.json]
  gate --key aics.key --name agent-name [--x25519-key aics.key.x25519] [PIN]
    [--url https://api.wesupport-ai.com/t | --tcp] [--host HOST] [--port PORT]
    [--plain] [--get] [--origin ORIGIN] [--onboard-only]
PIN is --trust FILE (the published trust bundle: README block, aics1= TXT value or its JCS bytes)
or --vkey-file trusted.vkey [--origin ORIGIN] [--policy-kid DID]. Pins come from out-of-band material, never
from the server being verified. Keys are written with mode 0600, without overwriting existing files.
`;
const flags: Record<string, string[]> = {}, args: string[] = [];
const booleans = new Set(['tcp', 'plain', 'get', 'onboard-only', 'help', 'sshsig', 'first-use']);
const allowed = new Set(['out', 'x25519-out', 'key', 'session', 'line', 'public-key', 'signature', 'signature-file', 'tiles', 'mirror', 'vkey-file', 'trust', 'policy-kid', 'note', 'origin', 'witness-policy', 'previous', 'save', 'now', 'old', 'new', 'proof', 'name', 'x25519-key', 'url', 'host', 'port', 'bundle', 'receipt', 'entry', 'card', 'index', 'api', ...booleans]);
function opt(name: string): string | undefined { const a = flags[name]; assert(!a || a.length === 1, `Repeated --${name}`); return a?.[0]; }
function need(name: string): string { const v = opt(name); assert(v !== undefined && v !== '', `Missing --${name}`); return v; }
const key = async () => importPrivateKey(await readFile(need('key'), 'utf8'));
const output = (v: unknown) => console.log(JSON.stringify(v, (_k, x) => x instanceof Uint8Array ? hex(x) : x instanceof Map ? Object.fromEntries(x) : x, 2));
const nowOpt = (): number | undefined => { if (opt('now') === undefined) return undefined; const n = Number(need('now')); assert(Number.isSafeInteger(n) && n >= 0, 'Invalid --now'); return n; };
type Pins = { log: VKey; origin: string; policyKid?: string; bundle?: TrustBundle };
/** Trust from --trust (a published bundle) or --vkey-file; never fetched from the server being checked. */
async function pins(): Promise<Pins> {
  if (opt('trust')) {
    assert(!opt('vkey-file'), 'Give --trust or --vkey-file, not both');
    const text = (await readFile(need('trust'), 'utf8')).trim();
    const bundle = text.startsWith('{') ? validateTrustBundle(text) : text.includes('\n') || text.includes('sha256:') ? trustBundleFromReadme(text) : trustBundleFromTxt([text]);
    if (opt('origin')) assert(opt('origin') === bundle.origin, '--origin differs from the trust bundle');
    return { log: parseVkey(bundle.log_vkey), origin: bundle.origin, policyKid: bundle.policy_kid, bundle };
  }
  const log = readVkeyFile(await readFile(need('vkey-file'), 'utf8')); return { log, origin: opt('origin') ?? log.name, policyKid: opt('policy-kid') };
}
async function policy(): Promise<WitnessPolicy | undefined> {
  if (!opt('witness-policy')) return undefined;
  const raw = parseJson(await readFile(need('witness-policy'))) as any, inner = raw.witness_policy ?? raw;
  assert(Array.isArray(inner.witnesses), 'Invalid witness policy');
  return { quorum: inner.quorum, witnesses: inner.witnesses.map((w: any) => typeof w === 'string' ? w : w.vkey), maxAgeSeconds: raw.max_checkpoint_age ?? inner.max_checkpoint_age ?? raw.maxAgeSeconds };
}
async function readJson(path: string): Promise<JsonObject> { const v = parseJson(await readFile(path)); assert(isObject(v), `${path} is not a JSON object`); return v; }
/** A note file holds the exact note bytes, or the U64 of them (as gate receipt lines and bundles carry them). */
async function readNote(path: string): Promise<Uint8Array> { const raw = new Uint8Array(await readFile(path)), s = Buffer.from(raw).toString('utf8').trim(); return /^[A-Za-z0-9_-]+$/.test(s) ? decodeB64u(s) : raw; }
async function main(): Promise<void> {
  const input = process.argv.slice(2);
  for (let i = 0; i < input.length; i++) {
    const arg = input[i]; if (!arg.startsWith('--')) { args.push(arg); continue; }
    const eq = arg.indexOf('='), name = arg.slice(2, eq < 0 ? undefined : eq); assert(allowed.has(name), `Unknown option --${name}`);
    const value = eq >= 0 ? arg.slice(eq + 1) : booleans.has(name) ? 'true' : input[++i]; assert(value !== undefined, `Missing value for --${name}`); (flags[name] ??= []).push(value);
  }
  if (!args.length || opt('help')) { console.log(usage); return; }
  if (args[0] === 'keys' && args[1] === 'new') {
    const pair = generateKeypair(), encryption = generateX25519Keypair(), out = need('out'), xout = opt('x25519-out') ?? out + '.x25519';
    // Check both destinations before creating either; exclusive writes protect races.
    for (const p of [out, xout]) { let exists = true; try { await access(p); } catch (e: any) { if (e.code === 'ENOENT') exists = false; else throw e; } assert(!exists, `Refusing to overwrite ${p}`); }
    assert(out !== xout, 'Key paths must differ');
    await writeFile(out, exportPrivateKey(pair.privateKey), { flag: 'wx', mode: 0o600 }); await writeFile(xout, encryption.privateKey, { flag: 'wx', mode: 0o600 });
    output({ ...agentIdentity(pair.privateKey), key_file: out, x25519_file: xout, x25519_did: x25519DidKey(encryption.publicKey) }); return;
  }
  if (args[0] === 'keys' && args[1] === 'show') { output(agentIdentity(await key())); return; }
  if (args[0] === 'sign-line') { console.log(signLine(need('session'), need('line'), await key(), opt('sshsig') ? 'sshsig' : 'raw').replace(/\n$/, '')); return; }
  if (args[0] === 'verify-line') {
    const pub = parsePublicKey(await readFile(need('public-key'), 'utf8')), signature = opt('signature-file') ? await readFile(need('signature-file'), 'utf8') : need('signature');
    const form = lineSignatureForm(need('session'), need('line'), signature, pub); assert(form, 'invalid: the signature does not cover exactly session LF line (AICS-1 §11.3)'); output({ status: 'valid', form }); return;
  }
  if (args[0] === 'entry') {
    const p = await pins(), w = await policy(), index = Number(need('index')); assert(Number.isSafeInteger(index) && index >= 0, 'Invalid --index');
    const client = new AicsClient({ baseUrl: opt('api'), trust: { origin: p.origin, logKey: p.log, policyKid: p.policyKid, witnesses: w?.witnesses, quorum: w?.quorum } });
    const r = await client.entry(index); output({ status: r.verification!.status, history: r.verification!.history, index, body_status: r.bodyStatus, entry: r.verification!.entry, entry_hash: r.verification!.entryHash, checkpoint: r.verification!.checkpoint, body: r.verification!.body ? Buffer.from(r.verification!.body).toString('base64url') : null }); return;
  }
  if (args[0] === 'verify') {
    const p = await pins(), witnesses = await policy(), now = nowOpt();
    if (args[1] === 'bundle') {
      const v = verifyBundle(await readJson(need('bundle')), { logKey: p.log, origin: p.origin, witnesses: witnesses?.witnesses, quorum: witnesses?.quorum, policyKid: p.policyKid, ...(now === undefined ? {} : { now, maxAgeSeconds: witnesses?.maxAgeSeconds }) });
      output({ status: v.status, history: v.history, index: v.index, entry_hash: v.entryHash, checkpoint: v.checkpoint, witnesses: v.witnesses, freshness: v.freshness, type: v.entry.type, actor_kid: v.entry.actor_kid, body: v.body === null ? 'absent' : 'matches' }); return;
    }
    if (args[1] === 'receipt') {
      const raw = await readJson(need('entry')), entry = (isObject(raw.entry) ? raw.entry : raw) as unknown as Entry;
      output({ status: 'valid', ...verifyReceipt(await readNote(need('receipt')), p.log, entryBytes(entry)), note: 'a receipt is an inclusion promise; check a later checkpoint after the deadline (AICS-1 §14.4)' }); return;
    }
    if (args[1] === 'card') {
      assert(p.policyKid, 'verify card needs the pinned policy kid (--trust or --policy-kid)');
      const v = verifyCard(new Uint8Array(await readFile(need('card'))), { policyKid: p.policyKid, trust: p.bundle, firstUse: !!opt('first-use'), now });
      output(v); if (!v.ok) process.exitCode = 2; return;
    }
    const opts = { expectedOrigin: p.origin, policy: witnesses, now }, oldOpts = { ...opts, archived: true };
    const prefixes = [...(flags.tiles ?? []), ...(flags.mirror ?? [])], reader = prefixes.length ? new HttpTileReader(prefixes) : undefined;
    const checked = (note: Uint8Array, old = false) => { const r = verifyCheckpoint(note, p.log, old ? oldOpts : opts); assert(r.ok, `${r.status}: ${r.error}`); return r; };
    if (args[1] === 'checkpoint') {
      const note = opt('note') ? new Uint8Array(await readFile(need('note'))) : await reader?.read('checkpoint'); assert(note, 'incomplete: provide --tiles or --note');
      const r = checked(note), cp = r.checkpoint!;
      if (reader) await new TileTree(reader, cp.size).verifyRoot(cp);
      if (opt('previous')) { assert(reader, '--previous requires --tiles'); const old = checked(new Uint8Array(await readFile(need('previous'))), true).checkpoint!; await new TileTree(reader, cp.size).verifyExtension(old, cp); }
      if (opt('save')) await writeFile(need('save'), note, { flag: 'wx' }); output(r); return;
    }
    if (args[1] === 'consistency') {
      const old = checked(new Uint8Array(await readFile(need('old'))), true).checkpoint!, next = checked(new Uint8Array(await readFile(need('new')))).checkpoint!;
      assert(old.origin === next.origin && old.size <= next.size, 'Origin mismatch or rollback'); let proof: Uint8Array[];
      if (opt('proof')) { const value = parseJson(await readFile(need('proof'))) as any; const hashes = Array.isArray(value) ? value : value.hashes; assert(Array.isArray(hashes), 'Invalid proof file'); if (!Array.isArray(value)) assert(value.from === old.size && value.to === next.size, 'Proof coordinates mismatch'); proof = hashes.map(decodeB64); }
      else { assert(reader, 'incomplete: provide --proof or --tiles'); proof = await new TileTree(reader, next.size).consistencyProof(old.size, next.size); }
      assert(verifyConsistency(old.size, next.size, old.root, next.root, proof), 'invalid: consistency proof failed'); output({ status: 'valid', origin: old.origin, from: old.size, to: next.size }); return;
    }
  }
  if (args[0] === 'gate') {
    assert(!opt('plain') || opt('tcp'), '--plain requires --tcp'); const seed = await key(), xkey = new Uint8Array(await readFile(opt('x25519-key') ?? need('key') + '.x25519'));
    const p = opt('trust') || opt('vkey-file') ? await pins() : undefined;
    const client = opt('tcp') ? new TcpGateClient({ host: opt('host'), port: opt('port') ? Number(need('port')) : undefined, tls: !opt('plain') }) : new HttpsGateClient(opt('url'), { method: opt('get') ? 'GET' : 'POST' });
    try {
      const done = await onboard(client, { name: need('name'), signingKey: seed, encryptionKey: xkey, origin: p?.origin ?? opt('origin'), logKey: p?.log, onReply: reply => { stdout.write(reply); } });
      console.error(JSON.stringify({ name: done.name, kid: done.kid, leaf: done.index, entry_hash: entryHash(done.entryBytes), receipt: done.receipt ? 'verified' : 'not checked (no pinned log key)' }));
      if (opt('onboard-only')) return;
      const rl = createInterface({ input: stdin, output: stdout });
      try { for (;;) { const line = await rl.question('aics> '); let reply = await client.send(line); stdout.write(reply); if (/^\? Reply(?: exactly)?: sig /m.test(reply)) { assert(client.session, 'Missing session'); reply = await client.send(signLine(client.session, line, seed)); stdout.write(reply); } if (line.trim().toLowerCase() === 'quit') break; } } finally { rl.close(); }
    } finally { client.close(); } return;
  }
  throw new Error('Unknown command. Use aics-js --help');
}
main().catch(e => { console.error(e instanceof Error ? e.message : String(e)); process.exitCode = 1; });

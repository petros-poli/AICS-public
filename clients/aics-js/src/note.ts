/**
 * C2SP signed notes, checkpoints and cosignatures in the AICS-1 §6.2-6.3 profile, and the §14.6 gossip classification.
 * Recognized keys are the pinned log key and the pinned witnesses; lines of unknown keys are ignored (repeated or not);
 * a repeated line for a recognized key or an invalid signature by one rejects the note. A note whose log signature
 * verifies stays evidence of what the log signed even when its witness lines fail (§14.6 step 2).
 */
import { assert, b64, concat, decodeB64, equal, hex, length, sha256, text, uint, utf8 } from './bytes.js';
import { validatePublicKey, verify } from './keys.js';
import { EMPTY_HASH, leafHash, merkleRoot, verifyConsistency } from './merkle.js';
export type VKey = { name: string; keyId: Uint8Array; keyType: number; publicKey: Uint8Array };
export type SignatureLine = { name: string; keyId: Uint8Array; signature: Uint8Array };
export type Note = { text: string; signatures: SignatureLine[] };
export type Checkpoint = { origin: string; size: number; root: Uint8Array };
export function checkName(name: string): string { assert(name && utf8(name).length <= 255 && !/[\s\x00-\x1f+\u0085]/u.test(name), 'Invalid note name'); return name; }
export const noteKeyHash = (name: string, type: number, pub: Uint8Array): Uint8Array => sha256(concat(utf8(checkName(name) + '\n'), Uint8Array.of(type), pub)).slice(0, 4);
export function parseVkey(s: string): VKey {
  const m = /^([^+]+)\+([0-9a-f]{8})\+(.+)$/.exec(s); assert(m, 'Invalid vkey'); const bytes = decodeB64(m[3]); assert(bytes.length >= 2, 'Short vkey');
  const k = { name: checkName(m[1]), keyId: new Uint8Array(Buffer.from(m[2], 'hex')), keyType: bytes[0], publicKey: bytes.slice(1) };
  assert(equal(noteKeyHash(k.name, k.keyType, k.publicKey), k.keyId), 'Vkey ID mismatch');
  if ([1, 4].includes(k.keyType)) validatePublicKey(length(k.publicKey, 32)); return k;
}
export const formatVkey = (k: VKey): string => `${k.name}+${hex(k.keyId)}+${b64(concat(Uint8Array.of(k.keyType), k.publicKey))}`;
export function readVkeyFile(s: string, label = 'log'): VKey {
  const plain: VKey[] = [], labelled: VKey[] = [];
  for (const line of s.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'))) {
    try { plain.push(parseVkey(line)); continue; } catch { /* labelled line */ }
    const m = /^([^\s=]+)[ =]+(.+)$/.exec(line); assert(m, 'Invalid vkey file line'); const k = parseVkey(m[2]); if (m[1].replace(/:$/, '').toLowerCase() === label) labelled.push(k);
  }
  const candidates = labelled.length ? labelled : plain; assert(candidates.length === 1, 'Expected exactly one pinned vkey'); return candidates[0];
}
export function parseNote(input: string | Uint8Array): Note {
  const s = typeof input === 'string' ? text(utf8(input)) : text(input);
  assert(typeof input !== 'string' || s === input, 'Invalid Unicode in note');
  assert(s.endsWith('\n') && !/[\x00-\x09\x0b-\x1f]/.test(s), 'Invalid note framing');
  const cut = s.indexOf('\n\n'); assert(cut >= 0, 'Missing signature block'); const body = s.slice(0, cut + 1);
  const lines = s.slice(cut + 2, -1).split('\n'); assert(lines.length >= 1 && lines.length <= 1000, 'Invalid signature count');
  const signatures = lines.map(line => { const m = /^— ([^ ]+) ([A-Za-z0-9+/]+={0,2})$/.exec(line); assert(m, 'Invalid signature line'); const blob = decodeB64(m[2]); assert(blob.length >= 5, 'Short signature'); return { name: checkName(m[1]), keyId: blob.slice(0, 4), signature: blob.slice(4) }; });
  return { text: body, signatures };
}
export const serializeNote = (n: Note): string => n.text + '\n' + n.signatures.map(s => `— ${s.name} ${b64(concat(s.keyId, s.signature))}\n`).join('');
/** §6.2 checkpoint text: exactly `origin LF size LF B64(root) LF`, canonical size, 32-byte root (no extensions). */
export function parseCheckpointText(body: string): Checkpoint {
  const lines = body.split('\n'); assert(lines.length === 4 && lines[3] === '', 'AICS checkpoint must have exactly three lines');
  const origin = checkName(lines[0]); assert(/^(0|[1-9][0-9]*)$/.test(lines[1]), 'Noncanonical tree size'); const size = Number(lines[1]); uint(size);
  return { origin, size, root: length(decodeB64(lines[2]), 32) };
}
/** `parseCheckpointText`, and a size-0 checkpoint must carry the empty-tree root SHA-256("") (§14.2 step 1). */
export function parseCheckpoint(body: string): Checkpoint { const cp = parseCheckpointText(body); if (cp.size === 0) assert(equal(cp.root, EMPTY_HASH), 'Wrong empty root'); return cp; }
export const cosignatureMessage = (timestamp: number | bigint, checkpointText: string): Uint8Array => utf8(`cosignature/v1\ntime ${timestamp}\n${checkpointText}`);
/** What §6.2-6.3 and §14.1 steps 2-3 conclude about one signed note. */
export type NoteVerdict = {
  /** Parsed, the pinned origin, and a valid, unrepeated line by the pinned log key: evidence of what the log signed. */
  logOk: boolean;
  /** Log-signed, no invalid or repeated recognized line, and the quorum of counted cosignatures. */
  ok: boolean;
  reason: 'malformed' | 'origin' | 'no_log_signature' | 'duplicate_recognized' | 'bad_signature' | 'quorum' | null;
  detail?: string; checkpoint?: Checkpoint; counted: string[]; stale: string[]; future: string[]; timestamps: Record<string, number>; ignoredLines: number;
};
export type NoteOptions = { witnesses?: readonly (VKey | string)[]; quorum?: number; maxAgeSeconds?: number; now?: number; maxFutureSeconds?: number; expectedOrigin?: string };
/**
 * Verify a note under the pinned keys. With `now`, a cosignature counts when `now - maxAge <= ts <= now + 30`
 * (§6.3); without it no freshness bound applies (archived, historical verification).
 */
export function verifyNote(input: Note | string | Uint8Array, logKey: VKey | string, o: NoteOptions = {}): NoteVerdict {
  const v: NoteVerdict = { logOk: false, ok: false, reason: null, counted: [], stale: [], future: [], timestamps: {}, ignoredLines: 0 };
  let note: Note, log: VKey, witnesses: VKey[];
  try {
    note = typeof input === 'string' || input instanceof Uint8Array ? parseNote(input) : input; v.checkpoint = parseCheckpointText(note.text);
    log = typeof logKey === 'string' ? parseVkey(logKey) : logKey; assert(log.keyType === 1, 'The log key is not type 0x01');
    witnesses = (o.witnesses ?? []).map(w => typeof w === 'string' ? parseVkey(w) : w); for (const w of witnesses) assert(w.keyType === 4, 'A witness key is not type 0x04');
    if (o.now !== undefined) uint(o.now, 'verification time'); uint(o.maxFutureSeconds ?? 30, 'future tolerance'); if (o.maxAgeSeconds !== undefined) uint(o.maxAgeSeconds, 'max age');
  } catch (e) { v.reason = 'malformed'; v.detail = (e as Error).message; return v; }
  if (v.checkpoint.origin !== (o.expectedOrigin ?? log.name)) { v.reason = 'origin'; return v; }
  const seen = new Set<string>(); let badWitness = false, repeatedWitness = false;
  for (const s of note.signatures) {
    const isLog = s.name === log.name && equal(s.keyId, log.keyId), w = isLog ? undefined : witnesses.find(k => k.name === s.name && equal(k.keyId, s.keyId));
    if (!isLog && !w) { v.ignoredLines++; continue; }
    const id = s.name + ':' + hex(s.keyId);
    if (seen.has(id)) { if (isLog) { v.logOk = false; v.reason = 'duplicate_recognized'; return v; } repeatedWitness = true; continue; }
    seen.add(id);
    if (isLog) { if (!verify(s.signature, utf8(note.text), log.publicKey)) { v.logOk = false; v.reason = 'bad_signature'; return v; } v.logOk = true; continue; }
    if (s.signature.length !== 72) { badWitness = true; continue; }
    const ts = Buffer.from(s.signature).readBigUInt64BE();
    if (ts > BigInt(Number.MAX_SAFE_INTEGER) || !verify(s.signature.slice(8), cosignatureMessage(ts, note.text), w!.publicKey)) { badWitness = true; continue; }
    v.timestamps[w!.name] = Number(ts);
  }
  if (!v.logOk) { v.reason = 'no_log_signature'; return v; }
  if (repeatedWitness) { v.reason = 'duplicate_recognized'; return v; }
  if (badWitness) { v.reason = 'bad_signature'; return v; }
  for (const [name, ts] of Object.entries(v.timestamps)) {
    if (o.now !== undefined && ts > o.now + (o.maxFutureSeconds ?? 30)) v.future.push(name);
    else if (o.now !== undefined && o.maxAgeSeconds !== undefined && ts < o.now - o.maxAgeSeconds) v.stale.push(name);
    else v.counted.push(name);
  }
  if (v.counted.length < (o.quorum ?? 0)) { v.reason = 'quorum'; return v; }
  v.ok = true; return v;
}
export type WitnessPolicy = { quorum: number; witnesses: (VKey | string)[]; maxAgeSeconds?: number };
export type CheckpointResult = { ok: boolean; status: 'valid' | 'invalid' | 'stale'; checkpoint?: Checkpoint; logOk: boolean; witnesses: string[]; stale: string[]; future: string[]; timestamps: Record<string, number>; freshness: 'verified' | 'unproven'; error?: string };
/**
 * §14.1 checkpoint verification as a current head (or, with `archived`, historically): the pinned log key, the
 * pinned witness policy with fresh cosignatures, the empty-tree root for size 0. A log-only note has no authenticated
 * timestamp, so its freshness is `unproven`.
 */
export function verifyCheckpoint(input: Note | string | Uint8Array, logKey: VKey | string, options: { expectedOrigin?: string; policy?: WitnessPolicy; now?: number; maxFutureSeconds?: number; archived?: boolean } = {}): CheckpointResult {
  const result: CheckpointResult = { ok: false, status: 'invalid', logOk: false, witnesses: [], stale: [], future: [], timestamps: {}, freshness: 'unproven' };
  try {
    const log = typeof logKey === 'string' ? parseVkey(logKey) : logKey; assert(log.keyType === 1, 'Log key must use type 1'); validatePublicKey(log.publicKey);
    const policy = options.policy ?? { quorum: 0, witnesses: [] }, witnesses = policy.witnesses.map(w => typeof w === 'string' ? parseVkey(w) : w);
    uint(policy.quorum, 'quorum'); assert(policy.quorum <= witnesses.length, 'Quorum exceeds witness count');
    assert(policy.quorum === 0 || policy.maxAgeSeconds !== undefined || options.archived, 'Online witness policy requires maxAgeSeconds');
    assert(new Set(witnesses.map(w => w.name)).size === witnesses.length && new Set(witnesses.map(w => hex(w.publicKey))).size === witnesses.length, 'Duplicate witness identity');
    for (const w of witnesses) { assert(w.keyType === 4, 'Witness must use type 4'); validatePublicKey(w.publicKey); }
    const now = options.now ?? Math.floor(Date.now() / 1000); uint(now, 'verification time');
    const v = verifyNote(input, log, { witnesses, quorum: policy.quorum, expectedOrigin: options.expectedOrigin ?? log.name, maxFutureSeconds: options.maxFutureSeconds, ...(options.archived ? {} : { now, maxAgeSeconds: policy.maxAgeSeconds }) });
    Object.assign(result, { checkpoint: v.checkpoint, logOk: v.logOk, witnesses: v.counted, stale: v.stale, future: v.future, timestamps: v.timestamps });
    if (v.reason === 'quorum') { result.status = v.stale.length || v.future.length ? 'stale' : 'invalid'; throw new Error('Witness quorum not met'); }
    if (!v.ok) throw new Error(v.reason === 'origin' ? 'Origin mismatch' : v.reason === 'no_log_signature' ? 'Missing trusted log signature' : `${v.reason}${v.detail ? ': ' + v.detail : ''}`);
    if (v.checkpoint!.size === 0) assert(equal(v.checkpoint!.root, EMPTY_HASH), 'Wrong empty root');
    result.freshness = !options.archived && policy.quorum > 0 && policy.maxAgeSeconds !== undefined ? 'verified' : 'unproven';
    result.ok = true; result.status = 'valid';
  } catch (e) { result.error = e instanceof Error ? e.message : String(e); }
  return result;
}
export type GossipRelation = 'consistent' | 'split-proven' | 'consistency-unproven' | 'not-evidence';
export type GossipResult = { relation: GossipRelation; reason: string | null; witnessPolicyMet: [boolean, boolean]; checkpoints: [Checkpoint | undefined, Checkpoint | undefined] };
/**
 * §14.6 for two notes under the pinned keys. Each note's witness policy is evaluated historically (signatures and
 * quorum, no freshness). `proof` is a supplied consistency proof (smaller to larger); `largerEntries` are the larger
 * tree's complete entries, authenticated here against its signed root. A missing or bad proof alone never proves a
 * split: without an authenticated prefix the result is `consistency-unproven`.
 */
export function classifyGossip(noteA: Note | string | Uint8Array, noteB: Note | string | Uint8Array, o: { logKey: VKey | string; witnesses?: readonly (VKey | string)[]; quorum?: number; expectedOrigin?: string; proof?: readonly Uint8Array[]; largerEntries?: readonly Uint8Array[] }): GossipResult {
  const opts = { witnesses: o.witnesses, quorum: o.quorum, expectedOrigin: o.expectedOrigin };
  const a = verifyNote(noteA, o.logKey, opts), b = verifyNote(noteB, o.logKey, opts);
  const out = (relation: GossipRelation, reason: string | null): GossipResult => ({ relation, reason, witnessPolicyMet: [a.ok, b.ok], checkpoints: [a.checkpoint, b.checkpoint] });
  if (!a.logOk || !b.logOk) return out('not-evidence', null);
  const [ca, cb] = [a.checkpoint!, b.checkpoint!];
  if (ca.origin !== cb.origin) return out('not-evidence', 'different origins');
  const [small, big] = ca.size <= cb.size ? [ca, cb] : [cb, ca];
  for (const x of [small, big]) if (x.size === 0 && !equal(x.root, EMPTY_HASH)) return out('split-proven', 'bad-empty-root');
  if (small.size === big.size) return equal(small.root, big.root) ? out('consistent', 'same size and root') : out('split-proven', 'equal-size-different-root');
  if (small.size === 0) return out('consistent', 'empty tree');
  if (o.proof && verifyConsistency(small.size, big.size, small.root, big.root, o.proof)) return out('consistent', 'valid consistency proof');
  if (o.largerEntries && o.largerEntries.length === big.size) {
    const leaves = o.largerEntries.map(leafHash);
    if (equal(merkleRoot(leaves), big.root)) return equal(merkleRoot(leaves.slice(0, small.size)), small.root) ? out('consistent', 'authenticated prefix root matches') : out('split-proven', 'not-a-prefix');
  }
  return out('consistency-unproven', 'no valid proof and no authenticated prefix');
}


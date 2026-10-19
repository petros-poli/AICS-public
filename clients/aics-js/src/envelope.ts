/**
 * AICS-1 §4 envelopes: exactly `{v:1, protected, payload, auth, sig}` with the ten protected members, the did:key
 * signing kid (§3.1), the native digest `D = H(J(protected) || 0x2e || J(payload))` (§4.1), the text schemes of §11.3,
 * the fallback form, the per-key chain (§4.2) and the validity window (§4.3). `envelope_hash = hexH(J(E))` covers the
 * complete envelope, `auth` and `sig` included.
 */
import { assert, b64u, concat, decodeU64, hexH, isHex64, isU64Of, isUint, random, sha256, utf8 } from './bytes.js';
import { canonicalize, hasMembers, isObject, type JsonObject } from './canonical.js';
import { didKey, isKid, isUnverifiedId, parseDidKey, parsePublicKey, publicKey, sign, verify } from './keys.js';
import { lineMessage } from './linesig.js';
import { MAX_SSHSIG_BYTES, parseSshsig, signSshsig, verifySshsig } from './sshsig.js';
import { TEXT_VERBS, entryTypes } from './registry.js';
export const ENVELOPE_MEMBERS = ['v', 'protected', 'payload', 'auth', 'sig'] as const;
export const PROTECTED_MEMBERS = ['alg', 'origin', 'type', 'kid', 'created', 'expires', 'nonce', 'seq', 'prev', 'seen'] as const;
/** §4.3: `expires - created` is at most 300 s, and `created` at most 300 s before the submission time. */
export const ENVELOPE_WINDOW_SECONDS = 300;
/** §4.3: `created` may be at most 30 s after the submission time; expiry is never extended. */
export const FUTURE_SKEW_SECONDS = 30;
export const NATIVE_SCHEME = 'ed25519-jcs';
export const TEXT_SCHEMES = ['text-ed25519', 'text-sshsig'] as const;
export type Seen = { checkpoint_note_hash: string; size: number };
export type Protected = { alg: 'EdDSA' | 'none'; origin: string; type: string; kid: string; created: number; expires: number; nonce: string; seq: number; prev: string | null; seen: Seen | null };
export type Auth = { scheme: 'ed25519-jcs' } | { scheme: 'text-ed25519' | 'text-sshsig'; session: string } | { scheme: 'shared-secret' };
export type AuthScheme = Auth['scheme'];
export type Envelope = { v: 1; protected: Protected; payload: JsonObject; auth: Auth; sig: string | null };
/** `U`: the envelope with only `sig` removed (§11.3). */
export type UnsignedEnvelope = Omit<Envelope, 'sig'>;
/** A refusal of an envelope; `code` is the §17.2 refusal code a verifier would log. */
export class EnvelopeError extends Error { constructor(readonly code: string, message: string) { super(message); this.name = 'EnvelopeError'; } }
const fail = (code: string, message: string): never => { throw new EnvelopeError(code, message); };
const check = (ok: unknown, message: string, code = 'malformed'): void => { if (!ok) fail(code, message); };
export type ChainPosition = { seq: number; prev: string | null };
export type EnvelopeOptions = { origin: string; type: string; created?: number; expires?: number; nonce?: string; seq?: number; prev?: string | null; seen?: Seen | null };
export type TypeOptions = { types?: readonly string[]; profiles?: readonly string[] };
/** A fresh envelope nonce: U64 of 16 random bytes (§4.3). */
export const newNonce = (): string => b64u(random(16));
/** A log origin: printable ASCII, no scheme, no trailing slash (§2). */
export function validateOrigin(origin: unknown): string {
  check(typeof origin === 'string' && /^[\x21-\x7e]+$/.test(origin) && !origin.includes('://') && !origin.endsWith('/'), 'origin must be the log ASCII identifier without scheme or trailing slash');
  return origin as string;
}
/** `seen` is null (initial bootstrap) or exactly `{checkpoint_note_hash: hash, size: uint}` (§4.1). */
export function validateSeen(seen: unknown): Seen | null {
  if (seen === null) return null;
  check(hasMembers(seen, ['checkpoint_note_hash', 'size']), 'seen must be null or exactly {checkpoint_note_hash, size}');
  const s = seen as JsonObject; check(isHex64(s.checkpoint_note_hash), 'seen.checkpoint_note_hash must be 64 lowercase hex'); check(isUint(s.size), 'seen.size must be a uint');
  return { checkpoint_note_hash: s.checkpoint_note_hash as string, size: s.size as number };
}
/** The auth scheme of an exact §4.1 / §11.3 auth object. */
export function validateAuth(auth: unknown): AuthScheme {
  check(isObject(auth), 'auth must be an object'); const a = auth as JsonObject;
  if (a.scheme === 'ed25519-jcs' || a.scheme === 'shared-secret') { check(hasMembers(a, ['scheme']), 'auth has exactly scheme'); return a.scheme; }
  if (a.scheme === 'text-ed25519' || a.scheme === 'text-sshsig') { check(hasMembers(a, ['scheme', 'session']) && isU64Of(a.session, 16), 'text auth is {scheme, session: U64 of 16 bytes}'); return a.scheme; }
  return fail('unsupported_scheme', `unknown auth.scheme ${JSON.stringify(a.scheme)}`);
}
/** The ten protected members (§4.1) with their types and the §4.2 chain rules. */
export function validateProtected(p: unknown, o: TypeOptions = {}): Protected {
  check(hasMembers(p, PROTECTED_MEMBERS), `protected has exactly ${PROTECTED_MEMBERS.join(', ')}`); const q = p as JsonObject;
  check(q.alg === 'EdDSA' || q.alg === 'none', 'unsupported alg'); validateOrigin(q.origin);
  check(typeof q.type === 'string' && (o.types ?? entryTypes(o.profiles)).includes(q.type), `type ${JSON.stringify(q.type)} is not an entry type of this profile`);
  check(isKid(q.kid) || isUnverifiedId(q.kid), 'kid must be an Ed25519 did:key, or an unverified identifier for the fallback');
  check(isUint(q.created) && isUint(q.expires), 'created and expires must be uint seconds');
  check((q.created as number) < (q.expires as number) && (q.expires as number) <= (q.created as number) + ENVELOPE_WINDOW_SECONDS, 'created < expires <= created + 300 is required');
  check(isU64Of(q.nonce, 16), 'nonce must be U64 of exactly 16 bytes');
  check(isUint(q.seq), 'seq must be a uint');
  check(q.seq === 0 ? q.prev === null : isHex64(q.prev), 'prev is null exactly at seq 0, otherwise a lowercase hash');
  validateSeen(q.seen);
  return q as unknown as Protected;
}
/** The complete §4.1 structure (no signature check); returns `auth.scheme`. */
export function validateEnvelope(e: unknown, o: TypeOptions & { origin?: string; type?: string } = {}): AuthScheme {
  check(hasMembers(e, ENVELOPE_MEMBERS), `an envelope has exactly ${ENVELOPE_MEMBERS.join(', ')}`); const x = e as JsonObject;
  check(x.v === 1, 'envelope v must be 1', 'unsupported_version');
  const scheme = validateAuth(x.auth), p = validateProtected(x.protected, o);
  check(isObject(x.payload), 'payload must be an object');
  if (scheme === 'shared-secret') check(p.alg === 'none' && isUnverifiedId(p.kid) && x.sig === null, 'a shared-secret envelope has alg none, an unverified kid and sig null');
  else {
    check(p.alg === 'EdDSA' && isKid(p.kid), `${scheme} envelopes have alg EdDSA and a did:key kid`);
    check(typeof x.sig === 'string' && isU64Of(x.sig), 'sig must be U64 of the signature');
    const raw = decodeU64(x.sig);
    if (scheme === 'text-sshsig') { check(raw.length <= MAX_SSHSIG_BYTES, 'SSHSIG too large'); try { parseSshsig(raw); } catch (err) { fail('malformed', `sig is not an Ed25519 SSHSIG blob: ${(err as Error).message}`); } }
    else check(raw.length === 64, `a ${scheme} sig is U64 of a 64-byte signature`);
  }
  if (o.origin !== undefined) check(p.origin === o.origin, `origin is ${p.origin}, expected ${o.origin}`);
  if (o.type !== undefined) check(p.type === o.type, `type is ${p.type}, expected ${o.type}`);
  try { canonicalize(e); } catch (err) { fail('malformed', `envelope is not canonicalisable: ${(err as Error).message}`); }
  return scheme;
}
/** §4.1 native signing digest `D` (32 bytes; Ed25519 signs D itself, not its hex and not a prehash). */
export const envelopeSigningDigest = (p: unknown, payload: unknown): Uint8Array => sha256(concat(canonicalize(p), utf8('.'), canonicalize(payload)));
/** §4.1 `envelope_hash = hexH(J(E))` over the complete envelope: what `prev` and a refusal's `envelope_hash` name. */
export function envelopeHash(e: Envelope): string { check(hasMembers(e, ENVELOPE_MEMBERS), 'an envelope has exactly v, protected, payload, auth, sig'); return hexH(canonicalize(e)); }
/** `U`: the envelope without `sig`. */
export function unsignedEnvelope(e: Envelope): UnsignedEnvelope { check(hasMembers(e, ENVELOPE_MEMBERS), 'not an envelope'); const { sig: _sig, ...u } = e; return u; }
function protectedHeader(o: EnvelopeOptions, kid: string, alg: 'EdDSA' | 'none' = 'EdDSA'): Protected {
  const created = o.created ?? Math.floor(Date.now() / 1000), expires = o.expires ?? created + ENVELOPE_WINDOW_SECONDS, seq = o.seq ?? 0;
  return { alg, origin: o.origin, type: o.type, kid, created, expires, nonce: o.nonce ?? newNonce(), seq, prev: o.prev ?? null, seen: o.seen === undefined ? null : o.seen };
}
/**
 * A native `ed25519-jcs` envelope (§4.1) signed by `seed`; `kid` is the key's did:key. `payload` is exactly the
 * type-specific `Q` of §5.3. Continue a chain with `...nextChain(lastAccepted)` and gossip `seen`.
 */
export function signEnvelope(payload: JsonObject, seed: Uint8Array, o: EnvelopeOptions & TypeOptions): Envelope {
  check(isObject(payload), 'payload must be an object');
  const p = protectedHeader(o, didKey(publicKey(seed))), q = structuredClone(payload);
  const e: Envelope = { v: 1, protected: p, payload: q, auth: { scheme: 'ed25519-jcs' }, sig: b64u(sign(envelopeSigningDigest(p, q), seed)) };
  validateEnvelope(e, o); return e;
}
/** The §4.1 structure of `U` (an envelope without `sig`) for a text scheme; returns the scheme. */
export function validateUnsignedTextEnvelope(u: unknown, o: TypeOptions & { origin?: string; type?: string } = {}): 'text-ed25519' | 'text-sshsig' {
  check(hasMembers(u, ['v', 'protected', 'payload', 'auth']), 'U has exactly v, protected, payload, auth');
  const x = u as JsonObject; check(x.v === 1, 'envelope v must be 1', 'unsupported_version');
  const scheme = validateAuth(x.auth); check(scheme === 'text-ed25519' || scheme === 'text-sshsig', 'U of a gate write uses a text scheme', 'unsupported_scheme');
  const p = validateProtected(x.protected, o); check(p.alg === 'EdDSA' && isKid(p.kid), 'a text envelope has alg EdDSA and a did:key kid');
  check(isObject(x.payload), 'payload must be an object');
  if (o.origin !== undefined) check(p.origin === o.origin, `origin is ${p.origin}, expected ${o.origin}`);
  if (o.type !== undefined) check(p.type === o.type, `type is ${p.type}, expected ${o.type}`);
  canonicalize(u); return scheme as 'text-ed25519' | 'text-sshsig';
}
/** `U` for a gate write (§11.3): `auth = {scheme, session}`; sign it with `signTextEnvelope`. */
export function unsignedTextEnvelope(payload: JsonObject, o: EnvelopeOptions & TypeOptions & { kid: string; session: string; scheme?: 'text-ed25519' | 'text-sshsig' }): UnsignedEnvelope {
  check(isKid(o.kid), 'a text envelope is signed by an Ed25519 did:key');
  const u: UnsignedEnvelope = { v: 1, protected: protectedHeader(o, o.kid), payload: structuredClone(payload), auth: { scheme: o.scheme ?? 'text-ed25519', session: o.session } };
  validateUnsignedTextEnvelope(u, o); return u;
}
/** §11.3 canonical command `C`: `verb SP U64(J(U))`, or `claim`/`claim-upgrade SP name_norm SP hexH(J(U))`. */
export function textCommand(u: UnsignedEnvelope | JsonObject, verbs: Readonly<Record<string, string>> = TEXT_VERBS): string {
  check(isObject(u) && !('sig' in u) && isObject((u as JsonObject).protected) && isObject((u as JsonObject).payload), 'the canonical command is computed over U, the envelope without sig');
  const p = (u as JsonObject).protected as JsonObject, q = (u as JsonObject).payload as JsonObject;
  let verb = typeof p.type === 'string' ? verbs[p.type] : undefined; check(verb, `entry type ${JSON.stringify(p.type)} has no gate verb`);
  if (p.type === 'key.rotate' && q.mode === 'upgrade') verb = 'claim-upgrade';
  const bytes = canonicalize(u);
  if (verb === 'claim' || verb === 'claim-upgrade') {
    check(typeof q.name_norm === 'string' && /^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/.test(q.name_norm), 'the short claim command needs a normalized name_norm');
    return `${verb} ${q.name_norm} ${hexH(bytes)}`;
  }
  return `${verb} ${b64u(bytes)}`;
}
/** `UTF8(session) || LF || UTF8(C)`, no final LF: what a text-scheme signature covers (§11.3). */
export function textSigningInput(u: UnsignedEnvelope | JsonObject, verbs?: Readonly<Record<string, string>>): Uint8Array {
  const auth = (u as JsonObject).auth as JsonObject | undefined;
  check(isObject(auth) && (auth.scheme === 'text-ed25519' || auth.scheme === 'text-sshsig'), 'only a text-scheme U has a text signing input');
  return lineMessage(auth!.session as string, textCommand(u, verbs));
}
/** `E` = `U` + `sig`: the raw Ed25519 signature (text-ed25519) or the complete SSHSIG blob (text-sshsig), as U64. */
export function signTextEnvelope(u: UnsignedEnvelope, seed: Uint8Array, o: TypeOptions = {}): Envelope {
  validateUnsignedTextEnvelope(u, o); check(u.protected.kid === didKey(publicKey(seed)), 'the signing key is not the kid of U');
  const message = textSigningInput(u), sig = u.auth.scheme === 'text-sshsig' ? signSshsig(message, seed) : sign(message, seed);
  const e = { ...structuredClone(u), sig: b64u(sig) } as Envelope; validateEnvelope(e, o); return e;
}
/** §4.3 at submission time `t`: `created <= t+skew`, `created >= t-300`, `created < expires <= created+300`, `t < expires`. */
export function checkFreshness(p: Pick<Protected, 'created' | 'expires'>, t: number, maxClockSkew = FUTURE_SKEW_SECONDS): void {
  assert(isUint(t), 'Invalid verification time'); assert(isUint(maxClockSkew) && maxClockSkew <= FUTURE_SKEW_SECONDS, 'maxClockSkew may lower, never raise, the 30 s allowance');
  check(isUint(p.created) && isUint(p.expires) && p.created < p.expires && p.expires <= p.created + ENVELOPE_WINDOW_SECONDS, 'created < expires <= created + 300 is required');
  check(p.created <= t + maxClockSkew, `created ${p.created} is more than ${maxClockSkew} s after t=${t}`, 'future');
  check(p.created >= t - ENVELOPE_WINDOW_SECONDS, `created ${p.created} is more than 300 s before t=${t}`, 'expired');
  check(t < p.expires, `expired at ${p.expires} (t=${t})`, 'expired');
}
/** Whether an envelope's times pass §4.3 at `t`. */
export const acceptedAt = (p: Pick<Protected, 'created' | 'expires'>, t: number): boolean => { try { checkFreshness(p, t); return true; } catch { return false; } };
export type KeyResolver = Uint8Array | string | ((kid: string) => Uint8Array | string | null | undefined);
export type ReplayCheck = (kid: string, nonce: string, expires: number, now: number) => boolean;
export type VerifyEnvelopeOptions = TypeOptions & { now?: number; origin?: string; type?: string; maxClockSkew?: number; key?: KeyResolver; replayCheck?: ReplayCheck };
/**
 * Verify an envelope's own signature by its declared scheme (native digest, or the §11.3 text input for
 * text-ed25519/text-sshsig) and its freshness at `now` (submission time; pass `entry.ts` for history), and return its
 * payload. The kid is decoded locally; `key` (a key or resolver) additionally requires the logged key to be that key.
 * A shared-secret envelope carries no agent signature and is refused here (see `verifySecretAttestation`).
 */
export function verifyEnvelope(e: Envelope, o: VerifyEnvelopeOptions = {}): JsonObject {
  const scheme = validateEnvelope(e, o), p = e.protected;
  check(scheme !== 'shared-secret', 'a shared-secret envelope is never an agent signature', 'unsupported_scheme');
  const pub = parseDidKey(p.kid);
  if (o.key !== undefined) {
    const k = typeof o.key === 'function' ? o.key(p.kid) : o.key; check(k, `no key for ${p.kid}`, 'unknown_key');
    let logged: Uint8Array | undefined; try { logged = parsePublicKey(k as Uint8Array | string); } catch { fail('unknown_key', 'the resolved key is unusable'); }
    check(didKey(logged!) === p.kid, 'the resolved key is not the key the kid encodes', 'bad_signature');
  }
  const raw = decodeU64(e.sig);
  if (scheme === 'ed25519-jcs') check(verify(raw, envelopeSigningDigest(p, e.payload), pub), 'envelope signature does not verify', 'bad_signature');
  else {
    const message = textSigningInput(unsignedEnvelope(e));
    if (scheme === 'text-ed25519') check(verify(raw, message, pub), 'text-ed25519 signature does not verify', 'bad_signature');
    else { try { verifySshsig(raw, message, pub); } catch (err) { fail('bad_signature', `text-sshsig signature does not verify: ${(err as Error).message}`); } }
  }
  const now = o.now ?? Math.floor(Date.now() / 1000); checkFreshness(p, now, o.maxClockSkew);
  if (o.replayCheck) check(o.replayCheck(p.kid, p.nonce, p.expires, now), `replayed envelope (${p.kid}, ${p.nonce})`, 'replay');
  return e.payload;
}
/** §5.1: the bytes the policy key signs for a shared-secret entry at `ts` (any registered type; the entry check applies the profile). */
export function secretAttestationMessage(e: Envelope, ts: number): Uint8Array {
  check(validateEnvelope(e, { profiles: ['SUP-1', 'SWARMS-1'] }) === 'shared-secret', 'only a fallback envelope carries a policy attestation'); check(isUint(ts), 'ts must be a uint');
  return concat(utf8('AICS-1 secret-attestation\n'), canonicalize({ actor_kid: e.protected.kid, envelope_hash: envelopeHash(e), origin: e.protected.origin, ts, type: e.protected.type }));
}
/** Verify a shared-secret entry's attestation with the pinned policy kid; it proves only what the service asserted. */
export function verifySecretAttestation(e: Envelope, attestation: string, policyKid: string, ts: number): void {
  check(verify(decodeU64(attestation, 64), secretAttestationMessage(e, ts), parseDidKey(policyKid)), 'secret attestation does not verify with the policy key', 'bad_signature');
}
/** `{seq, prev}` after `previous` (null: the key's first envelope), `prev = hexH(J(previous))` (§4.2). */
export function nextChain(previous?: Envelope | null): ChainPosition {
  if (!previous) return { seq: 0, prev: null };
  const p = validateProtected(previous.protected, { types: [previous.protected.type] }); check(p.seq < Number.MAX_SAFE_INTEGER, 'seq cannot grow past 2^53 - 1');
  return { seq: p.seq + 1, prev: envelopeHash(previous) };
}
/** `e` directly follows `previous`: same kid and origin, `seq + 1`, `prev = envelope_hash(previous)`. */
export function checkSuccessor(previous: Envelope | null, e: Envelope): void {
  const n = nextChain(previous);
  if (previous) check(previous.protected.kid === e.protected.kid && previous.protected.origin === e.protected.origin, 'chains are per (origin, kid)', 'sequence');
  check(e.protected.seq === n.seq, `seq is ${e.protected.seq}, expected ${n.seq}`, 'sequence');
  check(e.protected.prev === n.prev, 'prev does not name the previous accepted envelope', 'predecessor');
}
export type ChainBreak = { position: number; reason: 'kid' | 'seq' | 'prev'; expectedSeq: number; seq: number };
/** Every place a sender's run of envelopes does not chain, each compared with the one before it; `[]` when it chains. */
export function chainBreaks(envelopes: readonly Envelope[], previous: Envelope | null = null): ChainBreak[] {
  const out: ChainBreak[] = []; let before = previous;
  envelopes.forEach((e, position) => {
    const { seq, prev } = e.protected; let expected: ChainPosition = { seq: 0, prev: null };
    if (before) {
      expected = nextChain(before);
      if (before.protected.kid !== e.protected.kid) { out.push({ position, reason: 'kid', expectedSeq: expected.seq, seq }); before = e; return; }
    }
    if (seq !== expected.seq) out.push({ position, reason: 'seq', expectedSeq: expected.seq, seq });
    else if (prev !== expected.prev) out.push({ position, reason: 'prev', expectedSeq: expected.seq, seq });
    before = e;
  });
  return out;
}
/** `seen` for a signed checkpoint note: hexH of the complete note bytes and its size (verify the note first). */
export function seenFromCheckpoint(note: string | Uint8Array): Seen {
  const bytes = typeof note === 'string' ? utf8(note) : note, size = Buffer.from(bytes).toString('utf8').split('\n')[1];
  assert(/^(0|[1-9][0-9]*)$/.test(size ?? ''), 'Invalid checkpoint size'); return validateSeen({ checkpoint_note_hash: hexH(bytes), size: Number(size) })!;
}
/** In-process convenience only: a verifier that accepts writes needs durable replay state backed by leaves (§4.3). */
export class ReplayCache {
  private entries = new Map<string, number>();
  check: ReplayCheck = (kid, nonce, expires, now) => {
    for (const [k, v] of this.entries) if (v <= now) this.entries.delete(k);
    const id = JSON.stringify([kid, nonce]); if (this.entries.has(id)) return false; this.entries.set(id, expires); return true;
  };
}

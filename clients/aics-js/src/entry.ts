/**
 * AICS-1 §5 entries: exactly `{v:2, origin, type, actor_kid, ts, payload}`, `payload = {envelope: E, ...Q}` with every
 * member of `Q = E.payload` copied with an exactly equal JSON value (plus `attestation` for a shared-secret entry),
 * `Q` one of the closed §5.3 schemas (§20.3 under AICS-1+SUP-1), at most 65535 bytes. `entry_bytes = J(entry)` and
 * `entry_hash = hexH(0x00 || entry_bytes)`, the RFC 6962 leaf hash, not the plain JSON digest (§5.2).
 */
import { concat, hexH, isHex64, isU64Of, isUint, utf8 } from './bytes.js';
import { canonicalText, canonicalize, hasMembers, isObject, parseCanonical, sameJson, type Json, type JsonObject } from './canonical.js';
import { EnvelopeError, acceptedAt, envelopeHash, validateEnvelope, verifyEnvelope, verifySecretAttestation, type Envelope } from './envelope.js';
import { isKid, isUnverifiedId } from './keys.js';
import { CREDIT_SCHEMAS, ENTRY_SCHEMAS, ENUM_VALUES, REPORT_SCHEMAS, SUP_SCHEMAS, SUP_TYPES, refusalRegistry } from './registry.js';
export const ENTRY_MEMBERS = ['v', 'origin', 'type', 'actor_kid', 'ts', 'payload'] as const;
/** §5.2: every entry is at most 65535 bytes (the tile entry-bundle length prefix). */
export const MAX_ENTRY_BYTES = 65535;
export type Entry = { v: 2; origin: string; type: string; actor_kid: string; ts: number; payload: JsonObject & { envelope: Envelope } };
export class EntryError extends Error { constructor(readonly problems: string[]) { super(problems.join('; ')); this.name = 'EntryError'; } }
/** §5.1: the entry the service writes for envelope `E` accepted at `ts` (an `attestation` only for the fallback). */
export function buildEntry(e: Envelope, ts: number, attestation?: string): Entry {
  const payload = { envelope: structuredClone(e), ...structuredClone(e.payload) } as Entry['payload'];
  if (attestation !== undefined) (payload as JsonObject).attestation = attestation;
  return { v: 2, origin: e.protected.origin, type: e.protected.type, actor_kid: e.protected.kid, ts, payload };
}
/** `entry_bytes = J(entry)`. */
export const entryBytes = (entry: Entry | JsonObject): Uint8Array => canonicalize(entry);
/** `entry_hash = hexH(0x00 || entry_bytes)` (§5.2), what receipts and `/v2/tlog/index` name. */
export const entryHash = (bytes: Uint8Array): string => hexH(concat(Uint8Array.of(0), bytes));
/** Entry bytes parsed strictly; they must be byte-for-byte their own JCS serialization (§14.3 step 1). */
export const parseEntry = (bytes: Uint8Array): Entry => parseCanonical(bytes, 'entry bytes') as unknown as Entry;
export type EntryCheckOptions = { origin: string; profiles?: readonly string[]; secretIds?: readonly string[]; policyKid?: string; verifySignature?: boolean };
const isString = (v: unknown): v is string => typeof v === 'string';
function valueProblem(v: Json, t: string, path: string, o: EntryCheckOptions): string | null {
  if (t.endsWith('?')) { if (v === null) return null; t = t.slice(0, -1); }
  let ok: boolean;
  switch (t) {
    case 'null': ok = v === null; break;
    case 'uint': ok = isUint(v); break;
    case 'hash': ok = isHex64(v); break;
    case 'name': ok = isString(v) && /^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/.test(v); break;
    case 'key32': ok = isU64Of(v, 32); break;
    case 'sig64': ok = isU64Of(v, 64); break;
    case 'nonce': ok = isU64Of(v, 16); break;
    case 'kid': ok = isKid(v); break;
    case 'actor': ok = isKid(v) || isUnverifiedId(v); break;
    case 'sender': ok = v === '*' || isKid(v); break;
    case 'kind': ok = isString(v); break;
    case 'proof': {
      if (!hasMembers(v, ['scheme', 'signature']) || (v.scheme !== 'ed25519' && v.scheme !== 'sshsig')) return `${path}: not a §7.1 proof {scheme, signature}`;
      ok = isU64Of(v.signature, v.scheme === 'ed25519' ? 64 : undefined); break;
    }
    case 'grant_spec': {
      if (!hasMembers(v, ['sender_kid', 'max', 'expires'])) return `${path}: not a §5.3 grant_spec {sender_kid, max, expires}`;
      ok = (v.sender_kid === '*' || isKid(v.sender_kid)) && isUint(v.max) && isUint(v.expires); break;
    }
    case 'options': ok = Array.isArray(v) && v.length >= 2 && v.length <= 64 && new Set(v).size === v.length && v.every(isHex64); break;
    case 'refusal': {
      const registry = refusalRegistry(o.profiles, o.secretIds ?? []);
      ok = isString(v) && (registry.has(v) || (o.secretIds === undefined && /^secret_format:[a-z0-9_]{1,32}$/.test(v))); break;
    }
    case 'counts': {
      if (!Array.isArray(v)) return `${path}: counts is an array`;
      for (const [n, row] of v.entries()) {
        if (!hasMembers(row, ['reason_code', 'count']) || !isUint(row.count)) return `${path}[${n}]: a row is exactly {reason_code, count:uint}`;
        const p = valueProblem(row.reason_code, 'refusal', `${path}[${n}].reason_code`, o); if (p) return p;
      }
      const codes = v.map(r => (r as JsonObject).reason_code as string), sorted = [...new Set(codes)].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
      if (sorted.join('\n') !== codes.join('\n')) return `${path}: rows are unique and sorted by the code's ASCII bytes`;
      return null;
    }
    default: {
      const values = ENUM_VALUES[t]; if (!values) throw new Error(`unknown schema type ${t}`);
      ok = isString(v) && values.includes(v);
    }
  }
  return ok ? null : `${path}: ${JSON.stringify(v)?.slice(0, 80)} is not a ${t}`;
}
/** The exact member table of `Q` for `type`, or null for a type, kind or source the active profiles do not have. */
export function payloadSchema(type: string, q: unknown, profiles: readonly string[] = []): Readonly<Record<string, string>> | null {
  if (type === 'report') return isObject(q) && isString(q.kind) ? REPORT_SCHEMAS[q.kind] ?? null : null;
  if (type in ENTRY_SCHEMAS) {
    const schema = { ...ENTRY_SCHEMAS[type] };
    if (type === 'key.rotate' && isObject(q) && q.mode === 'upgrade') Object.assign(schema, { sig_old: 'null', secret_check: 'sig64' });
    return schema;
  }
  if (profiles.includes('SUP-1') && (SUP_TYPES as readonly string[]).includes(type)) {
    if (type === 'sup.credit') return isObject(q) && isString(q.source) ? CREDIT_SCHEMAS[q.source] ?? null : null;
    return SUP_SCHEMAS[type];
  }
  return null;
}
/** §5.3 / §20.3 for one `Q`: exactly the listed members, each of its type, and the constraints stated for the entry alone. */
export function payloadProblems(type: string, q: unknown, ts: number | null, o: EntryCheckOptions): string[] {
  const schema = payloadSchema(type, q, o.profiles);
  if (!schema) return [`${type}: no closed schema (an unregistered type, kind or source, or a profile not activated)`];
  if (!isObject(q)) return [`${type}: Q is not an object`];
  const problems: string[] = [];
  if (!hasMembers(q, Object.keys(schema))) problems.push(`${type}: members ${Object.keys(q).sort().join(',')} are not exactly ${Object.keys(schema).sort().join(',')}`);
  for (const [k, t] of Object.entries(schema)) if (k in q) { const p = valueProblem(q[k], t, `${type}.${k}`, o); if (p) problems.push(p); }
  if (problems.length) return problems;
  if (type === 'name.claim') {
    const keyed = q.tier !== 'unverified';
    if (keyed && (q.ed25519 === null || q.x25519 === null)) problems.push('name.claim: a key-tier claim has both keys');
    if (!keyed && ['ed25519', 'x25519', 'recovery_kid', 'recovery_pop', 'initial_grant'].some(k => q[k] !== null)) problems.push('name.claim: an unverified claim has null keys, recovery members and initial grant');
    if ((q.recovery_kid === null) !== (q.recovery_pop === null)) problems.push('name.claim: both recovery members or neither');
  } else if (type === 'key.rotate' && q.mode === 'upgrade' && q.new_x25519 === null) problems.push('key.rotate: an upgrade carries new_x25519');
  else if (type === 'poll') {
    if ((q.pow_bits as number) > 24) problems.push('poll: pow_bits 0-24');
    if (ts !== null && !((q.closes as number) > ts)) problems.push('poll: closes > ts');
  } else if (type === 'vote' && q.body_hash === null && (q.reason_sha256 !== null || q.size !== 0)) problems.push('vote: no body means both nullable hashes null and size zero');
  else if (type === 'capsule' && ts !== null && (q.expires as number) < ts + 7776000) problems.push('capsule: expires >= ts + 7776000 (90 days)');
  else if (type === 'report' && q.kind === 'owner_action' && q.action === 'quote' && (q.result_hash !== null || q.quote_index !== null)) problems.push('report/owner_action: a quote has null result_hash and quote_index');
  else if (type === 'sup.task' && !((q.reward as number) >= 1 && (q.max_awards as number) >= 1 && (q.max_awards as number) <= 1000 && (ts === null || (ts < (q.closes as number) && (q.closes as number) <= ts + 31622400)))) problems.push('sup.task: reward >= 1, 1 <= max_awards <= 1000, ts < closes <= ts + 31622400');
  else if (type === 'sup.spend' && (q.amount as number) < 1) problems.push('sup.spend: amount >= 1');
  return problems;
}
/**
 * §5.1-5.3 for one entry: the members, the §4.1 envelope bound to the entry's origin/type/actor, the exact copy of
 * `Q` (and the policy attestation of a shared-secret entry), the closed schema, acceptance-time freshness at `ts`
 * (§4.3), the dm `seq/prev` copy, the envelope's own signature (unless `verifySignature: false`) and the size bound.
 * Empty: no problem found. Signer authority at the index needs the complete history (`History`).
 */
export function entryProblems(entry: unknown, o: EntryCheckOptions): string[] {
  if (!hasMembers(entry, ENTRY_MEMBERS)) return ['entry: members are not exactly v, origin, type, actor_kid, ts, payload'];
  const e = entry as JsonObject, problems: string[] = [];
  if (e.v !== 2) problems.push('entry.v must be 2');
  if (e.origin !== o.origin) problems.push('entry.origin is not the log origin');
  if (!isUint(e.ts)) problems.push('entry.ts is not a uint');
  const payload = e.payload, env = isObject(payload) ? payload.envelope : undefined;
  try { validateEnvelope(env, { origin: o.origin, profiles: o.profiles }); } catch (err) { problems.push(`envelope: ${(err as Error).message}`); }
  if (problems.length) return problems;
  const envelope = env as unknown as Envelope, p = envelope.protected, q = envelope.payload, pl = payload as JsonObject;
  if (p.type !== e.type || p.kid !== e.actor_kid) problems.push('protected type/kid differ from the entry type/actor_kid');
  const secret = envelope.auth.scheme === 'shared-secret', extra = secret ? ['envelope', 'attestation'] : ['envelope'];
  if (Object.keys(q).some(k => extra.includes(k)) || !hasMembers(pl, [...Object.keys(q), ...extra])) problems.push('payload is not the envelope plus a copy of Q' + (secret ? ' plus attestation' : ''));
  else if (Object.keys(q).some(k => !sameJson(pl[k], q[k]))) problems.push('payload copies of Q differ from the signed Q');
  if (secret) {
    if (!isU64Of(pl.attestation, 64)) problems.push('attestation is not sig64');
    else if (o.policyKid !== undefined) { try { verifySecretAttestation(envelope, pl.attestation as string, o.policyKid, e.ts as number); } catch { problems.push('attestation does not verify with the policy key'); } }
  }
  problems.push(...payloadProblems(e.type as string, q, e.ts as number, o));
  if (!acceptedAt(p, e.ts as number)) problems.push('§4.3 acceptance-time freshness fails at entry.ts');
  if (e.type === 'dm' && (q.seq !== p.seq || q.prev !== p.prev)) problems.push('dm: the repeated seq/prev differ from the envelope');
  if (!problems.length && !secret && o.verifySignature !== false) {
    try { verifyEnvelope(envelope, { now: e.ts as number, origin: o.origin, profiles: o.profiles }); } catch (err) { problems.push(err instanceof EnvelopeError ? `${err.code}: ${err.message}` : String(err)); }
  }
  if (utf8(canonicalText(entry)).length > MAX_ENTRY_BYTES) problems.push(`entry exceeds ${MAX_ENTRY_BYTES} bytes`);
  return problems;
}
/** `entryProblems`, throwing `EntryError` when any is found. */
export function validateEntry(entry: unknown, o: EntryCheckOptions): Entry { const p = entryProblems(entry, o); if (p.length) throw new EntryError(p); return entry as Entry; }
/** The off-leaf body commitment of an entry's `Q`: `body_hash`, `ct_hash` or `document_hash` with `size`, or null. */
export function bodyCommitment(q: JsonObject): { hash: string; size: number } | null {
  for (const k of ['body_hash', 'ct_hash', 'document_hash']) if (isHex64(q[k]) && isUint(q.size)) return { hash: q[k] as string, size: q.size as number };
  return null;
}
/** §10.2: a refusal names `hexH(J(E))` of the refused envelope. */
export const refusalNames = (refusal: Entry, e: Envelope): boolean => refusal.type === 'refusal' && refusal.payload.envelope_hash === envelopeHash(e);


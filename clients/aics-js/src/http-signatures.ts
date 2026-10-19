/**
 * RFC 9421 HTTP message signatures with RFC 9530 Content-Digest, in the AICS-1 §12.1 profile: one label `aics`,
 * covered components exactly `"@method" "@authority" "@path" "content-digest"`, parameters `created`, `expires`,
 * `nonce`, `alg="ed25519"`, `keyid` (the did:key) and `tag="aics"`; for `POST /v2/entries` the times, nonce and keyid
 * equal the envelope's. The digest is computed over the exact HTTP content bytes.
 */
import { sha512 } from '@noble/hashes/sha512';
import { assert, b64, decodeB64, decodeB64u, equal, sha256, uint, utf8 } from './bytes.js';
import { hasMembers, isObject, parseJson, type JsonObject } from './canonical.js';
import { didKey, parseDidKey, parsePublicKey, publicKey, sign, verify } from './keys.js';
import { newNonce, verifyEnvelope, type Envelope, type ReplayCheck } from './envelope.js';
export type HeaderInput = Record<string, string | string[]> | [string, string][] | Headers;
export type ResolveKey = (kid: string) => Uint8Array | string | undefined | null;
export const AICS_LABEL = 'aics';
export const AICS_TAG = 'aics';
export const AICS_COMPONENTS = ['@method', '@authority', '@path', 'content-digest'] as const;
/** The §12.1 verifier profile. */
export const AICS_VERIFY_POLICY = { requiredComponents: AICS_COMPONENTS, exactComponents: true, requireContentDigestCovered: true, requireExpires: true, requireNonce: true, requireTag: AICS_TAG, requireLabel: AICS_LABEL, requireAlg: true, maxAge: 300, maxLifetime: 300 } as const;
export function normalizeHeaders(h: HeaderInput = {}): [string, string][] {
  const pairs = h instanceof Headers ? [...h.entries()] : Array.isArray(h) ? h : Object.entries(h).flatMap(([k, v]) => (Array.isArray(v) ? v : [v]).map(x => [k, x] as [string, string]));
  for (const [k, v] of pairs) assert(/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(k) && typeof v === 'string' && !/[\r\n]/.test(v), 'Invalid HTTP header'); return pairs as [string, string][];
}
function get(h: [string, string][], name: string): string | undefined { const values = h.filter(([k]) => k.toLowerCase() === name.toLowerCase()).map(([, v]) => v.trim()); return values.length ? values.join(', ') : undefined; }
const quote = (s: string): string => { assert(/^[\x20-\x7e]*$/.test(s), 'Structured field string must be ASCII'); return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; };
type Scalar = string | number | boolean | Uint8Array;
type Item = { value: Scalar | string[]; params: Map<string, Scalar> };
/** Strict RFC 8941 subset needed by RFC 9421. Unsupported component parameters fail closed. */
function dictionary(s: string): Map<string, Item> {
  let i = 0; const out = new Map<string, Item>();
  const spaces = () => { while (s[i] === ' ' || s[i] === '\t') i++; };
  const key = () => { const m = /^[a-z*][a-z0-9_.*-]*/.exec(s.slice(i)); assert(m, 'Invalid structured-field key'); i += m[0].length; return m[0]; };
  function scalar(): Scalar {
    if (s[i] === '"') { i++; let v = ''; while (i < s.length) { let c = s[i++]; if (c === '"') return v; if (c === '\\') { c = s[i++]; assert(c === '"' || c === '\\', 'Invalid string escape'); } assert(c >= ' ' && c <= '~', 'Invalid string'); v += c; } throw new Error('Unclosed string'); }
    if (s[i] === ':') { const start = ++i; const end = s.indexOf(':', i); assert(end >= 0, 'Unclosed byte sequence'); i = end + 1; return decodeB64(s.slice(start, end)); }
    if (s[i] === '?') { i++; const c = s[i++]; assert(c === '0' || c === '1', 'Invalid boolean'); return c === '1'; }
    const m = /^-?[0-9]{1,15}(?![0-9.])/.exec(s.slice(i)); assert(m, 'Unsupported structured field value'); i += m[0].length; return Number(m[0]);
  }
  function params(): Map<string, Scalar> { const p = new Map<string, Scalar>(); while (s[i] === ';') { i++; while (s[i] === ' ') i++; const k = key(); assert(!p.has(k), 'Duplicate parameter'); let v: Scalar = true; if (s[i] === '=') { i++; v = scalar(); } p.set(k, v); } return p; }
  spaces(); while (i < s.length) {
    const k = key(); assert(!out.has(k), 'Duplicate dictionary member'); let v: Item['value'] = true;
    if (s[i] === '=') { i++; if (s[i] === '(') { i++; const a: string[] = []; while (true) { while (s[i] === ' ') i++; if (s[i] === ')') { i++; break; } const x = scalar(); assert(typeof x === 'string', 'Component must be a string'); a.push(x); assert(s[i] === ' ' || s[i] === ')', 'Unsupported component parameter'); } v = a; } else v = scalar(); }
    out.set(k, { value: v, params: params() }); spaces(); if (i === s.length) break; assert(s[i++] === ',', 'Invalid dictionary separator'); spaces(); assert(i < s.length, 'Trailing comma');
  }
  return out;
}
function serializeScalar(v: Scalar): string { return v instanceof Uint8Array ? ':' + b64(v) + ':' : typeof v === 'string' ? quote(v) : typeof v === 'boolean' ? '?' + Number(v) : String(v); }
function serialize(item: Item): string { const value = Array.isArray(item.value) ? '(' + item.value.map(quote).join(' ') + ')' : serializeScalar(item.value); return value + [...item.params].map(([k, v]) => ';' + k + (v === true ? '' : '=' + serializeScalar(v))).join(''); }
function component(name: string, method: string, url: string, h: [string, string][]): string {
  const u = new URL(url); assert(u.host && !u.username && !u.password && !u.hash, 'Invalid request URL');
  const values: Record<string, string> = { '@method': method.toUpperCase(), '@authority': u.host.toLowerCase(), '@path': u.pathname || '/', '@query': '?' + u.search.slice(1), '@target-uri': u.origin + u.pathname + u.search, '@scheme': u.protocol.slice(0, -1), '@request-target': u.pathname + u.search };
  const v = name.startsWith('@') ? values[name] : get(h, name); assert(v !== undefined, `Missing or unsupported component ${name}`); return v;
}
export function signatureBase(components: readonly string[], params: string, method: string, url: string, headers: HeaderInput): Uint8Array {
  const lower = components.map(c => c.toLowerCase()); assert(new Set(lower).size === lower.length, 'Duplicate component');
  const h = normalizeHeaders(headers), s = lower.map(c => quote(c) + ': ' + component(c, method, url, h)).concat('"@signature-params": ' + params).join('\n');
  assert(/^[\x20-\x7e\n]*$/.test(s), 'Signature base must be ASCII'); return utf8(s);
}
/** RFC 9530 `Content-Digest` over the exact content bytes. */
export function contentDigest(body: Uint8Array, algorithms: readonly string[] = ['sha-256']): string {
  return algorithms.map(a => { assert(a === 'sha-256' || a === 'sha-512', 'Unsupported digest'); return a + '=:' + b64(a === 'sha-256' ? sha256(body) : sha512(body)) + ':'; }).join(', ');
}
export function verifyContentDigest(value: string, body: Uint8Array): void {
  let matches = 0; for (const [k, item] of dictionary(value)) { if (k !== 'sha-256' && k !== 'sha-512') continue; assert(item.value instanceof Uint8Array && equal(item.value, k === 'sha-256' ? sha256(body) : sha512(body)), 'Content-Digest mismatch'); matches++; } assert(matches > 0, 'No supported Content-Digest');
}
export type SignRequestOptions = { key: Uint8Array; keyid?: string; envelope?: Envelope; created?: number; expires?: number | null; nonce?: string | null; tag?: string | null; alg?: string | null; components?: readonly string[]; label?: string; addContentDigest?: boolean };
/**
 * Sign a request. With `envelope`, `keyid`, `created`, `expires` and `nonce` are the envelope's (§12.1); otherwise the
 * keyid is the key's did:key and the times and nonce are fresh. Returns the headers to send (lower-case names).
 */
export function signRequest(method: string, url: string, headers: HeaderInput, body: Uint8Array, o: SignRequestOptions): Record<string, string> {
  const p = o.envelope?.protected;
  if (p) assert(p.kid === didKey(publicKey(o.key)) && o.keyid === undefined && o.created === undefined && o.expires === undefined && o.nonce === undefined, 'An envelope-bound request takes keyid, times and nonce from the envelope and is signed by its key');
  const created = p?.created ?? o.created ?? Math.floor(Date.now() / 1000), expires = p ? p.expires : o.expires === undefined ? created + 300 : o.expires;
  const nonce = p ? p.nonce : o.nonce === undefined ? newNonce() : o.nonce, keyid = p?.kid ?? o.keyid ?? didKey(publicKey(o.key));
  uint(created); if (expires !== null) uint(expires); assert(nonce === null || nonce.length > 0, 'Empty nonce');
  const h = normalizeHeaders(headers).filter(([k]) => !['signature-input', 'signature'].includes(k.toLowerCase()));
  const components = [...(o.components ?? AICS_COMPONENTS)].map(c => c.toLowerCase());
  if (body.length && o.addContentDigest !== false && !components.includes('content-digest')) components.push('content-digest');
  if (o.addContentDigest !== false && components.includes('content-digest') && get(h, 'content-digest') === undefined) h.push(['Content-Digest', contentDigest(body)]);
  const params = new Map<string, Scalar>([['created', created]]);
  if (expires !== null) params.set('expires', expires); if (nonce !== null) params.set('nonce', nonce);
  if (o.alg !== null) params.set('alg', o.alg ?? 'ed25519'); params.set('keyid', keyid); if (o.tag !== null) params.set('tag', o.tag ?? AICS_TAG);
  const serialized = serialize({ value: components, params }), label = o.label ?? AICS_LABEL; assert(/^[a-z*][a-z0-9_.*-]*$/.test(label), 'Invalid signature label');
  const sig = sign(signatureBase(components, serialized, method, url, h), o.key); const result: Record<string, string> = {};
  for (const [k] of h) result[k.toLowerCase()] = get(h, k)!;
  result['signature-input'] = label + '=' + serialized; result.signature = label + '=:' + b64(sig) + ':'; return result;
}
export type VerifiedSignature = { label: string; keyid: string; created: number; expires: number | null; nonce: string | undefined; tag: string | undefined; components: string[]; signatureBase: string; validUntil: number };
export type VerifyRequestOptions = { now?: number; maxClockSkew?: number; maxAge?: number | null; maxLifetime?: number | null; requireExpires?: boolean; requireNonce?: boolean; requireTag?: string | null; requireLabel?: string | null; requireAlg?: boolean; requiredComponents?: readonly string[]; exactComponents?: boolean; requireContentDigestCovered?: boolean; replayCheck?: ReplayCheck; envelope?: Envelope };
/**
 * Verify the request signatures (all labels, or only `requireLabel`). With `envelope`, the §12.1 binding: keyid,
 * created, expires and nonce equal the envelope's. Throws on any failure; returns what verified.
 */
export function verifyRequest(method: string, url: string, headers: HeaderInput, body: Uint8Array, resolve: ResolveKey, o: VerifyRequestOptions = {}): VerifiedSignature[] {
  const h = normalizeHeaders(headers), input = get(h, 'signature-input'), signature = get(h, 'signature'); assert(input && signature, 'Missing HTTP signature');
  const inputs = dictionary(input), signatures = dictionary(signature), now = o.now ?? Math.floor(Date.now() / 1000), skew = o.maxClockSkew ?? 60;
  const age = o.maxAge === undefined ? 300 : o.maxAge, lifetime = o.maxLifetime === undefined ? 300 : o.maxLifetime;
  if (o.requireLabel != null) assert(inputs.size === 1 && signatures.size === 1 && inputs.has(o.requireLabel) && signatures.has(o.requireLabel), `Exactly one signature, label ${o.requireLabel}, is required (AICS-1 §12.1)`);
  const results: VerifiedSignature[] = [];
  for (const [label, item] of inputs) {
    if (!signatures.has(label) || (o.requireLabel != null && label !== o.requireLabel)) continue;
    assert(Array.isArray(item.value), 'Signature-Input must be inner list'); const components = item.value.map(x => x.toLowerCase());
    const p = item.params, created = p.get('created'), expires = p.get('expires'), nonce = p.get('nonce'), kid = p.get('keyid'), alg = p.get('alg'), tag = p.get('tag');
    uint(created, 'created'); if (expires !== undefined) uint(expires, 'expires');
    assert(typeof kid === 'string' && kid, 'Missing keyid'); assert(alg === undefined || alg === 'ed25519', 'Unsupported algorithm');
    if (o.requireAlg) assert(alg === 'ed25519', 'Missing alg');
    assert(nonce === undefined || (typeof nonce === 'string' && nonce.length > 0 && nonce.length <= 256), 'Invalid nonce');
    assert(tag === undefined || typeof tag === 'string', 'Invalid tag');
    if (o.requireExpires !== false) assert(expires !== undefined, 'Missing expires');
    if (o.requireNonce || o.replayCheck) assert(nonce !== undefined, 'Missing nonce');
    if (o.requireTag != null) assert(tag === o.requireTag, 'Wrong tag');
    assert(created <= now + skew && (age === null || now - created <= age), 'HTTP signature outside freshness window');
    if (expires !== undefined) assert(expires >= created && (lifetime === null || expires - created <= lifetime) && now <= expires + skew, 'Expired HTTP signature');
    if (o.exactComponents && o.requiredComponents) assert(components.join(' ') === o.requiredComponents.join(' '), `Covered components must be exactly ${o.requiredComponents.join(' ')}`);
    for (const c of o.requiredComponents ?? ['@method', '@authority', '@path']) assert(components.includes(c), `Missing covered component ${c}`);
    if (o.requireContentDigestCovered) assert(components.includes('content-digest'), 'Uncovered digest');
    const digest = get(h, 'content-digest'); if (components.includes('content-digest')) assert(digest, 'Missing digest'); if (digest) verifyContentDigest(digest, body);
    if (o.envelope) { const e = o.envelope.protected; assert(kid === e.kid && nonce === e.nonce && created === e.created && expires === e.expires, 'Signature parameters differ from the envelope (AICS-1 §12.1)'); }
    const pub = resolve(kid); assert(pub, 'Unknown signing key'); const sig = signatures.get(label)!.value; assert(sig instanceof Uint8Array, 'Invalid signature byte sequence');
    const base = signatureBase(components, serialize(item), method, url, h); assert(verify(sig, base, parsePublicKey(pub)), 'Invalid HTTP signature');
    const bounds = [expires === undefined ? Infinity : expires + skew, age === null ? Infinity : created + age];
    results.push({ label, keyid: kid, created, expires: expires ?? null, nonce: nonce as string | undefined, tag: tag as string | undefined, components, signatureBase: Buffer.from(base).toString(), validUntil: Math.min(...bounds) });
  }
  assert(results.length, 'No matching signature labels');
  if (o.replayCheck) for (const r of results) assert(o.replayCheck(r.keyid, r.nonce!, r.validUntil, now), 'Replayed HTTP signature');
  return results;
}
/**
 * What a §12.1 receiver checks before acting on `POST /v2/entries`: the digest over the received bytes, exactly
 * `{envelope: E, body: U64-or-null}`, the RFC 9421 profile by the envelope's own did:key with the times, nonce and
 * keyid bound to the envelope, no query string, and the envelope's native signature and freshness at `now`.
 * Key-chain authority (is this key current for its name?) is the log's decision, not checkable from one request.
 */
export function verifyEntryRequest(method: string, url: string, headers: HeaderInput, content: Uint8Array, o: { now?: number; origin?: string; profiles?: readonly string[] } = {}): { envelope: Envelope; body: Uint8Array | null; signature: VerifiedSignature } {
  assert(method.toUpperCase() === 'POST' && new URL(url).pathname === '/v2/entries' && !new URL(url).search, 'A native write is POST /v2/entries with no query');
  verifyContentDigest(get(normalizeHeaders(headers), 'content-digest') ?? '', content);
  const obj = parseJson(content); assert(hasMembers(obj, ['envelope', 'body']) && (obj.body === null || typeof obj.body === 'string'), 'The request is exactly {envelope, body: U64 or null}');
  const envelope = (obj as JsonObject).envelope as unknown as Envelope; assert(isObject(envelope) && isObject(envelope.protected) && envelope.auth?.scheme === 'ed25519-jcs', 'POST /v2/entries takes native envelopes');
  const [signature] = verifyRequest(method, url, headers, content, kid => kid === envelope.protected.kid ? parseDidKey(kid) : null, { ...AICS_VERIFY_POLICY, now: o.now, envelope });
  verifyEnvelope(envelope, { now: o.now, origin: o.origin, profiles: o.profiles });
  return { envelope, body: obj.body === null ? null : decodeB64u(obj.body as string), signature };
}

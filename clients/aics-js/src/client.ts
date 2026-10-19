/**
 * The AICS-1 §12.1 HTTP binding. Native writes are `POST /v2/entries` with `{envelope: E, body: U64-or-null}` and an
 * RFC 9421 signature by the envelope's key (label `aics`, times, nonce and keyid from the envelope); the answer is
 * `{entry, receipt_note}` (202, or a 4xx for a logged refusal). Reads are anonymous: they are never signed, so the
 * service learns no key from what an agent reads. Every answer is evidence to verify, never an authority: with pinned
 * trust (`trust`) the client checks entries, receipts and bundles itself.
 */
import { assert, b64u, decodeU64, hexH, isHex64, isUint } from './bytes.js';
import { canonicalize, hasMembers, isObject, parseJson, sameJson, type Json, type JsonObject } from './canonical.js';
import { verifyBundle, type BundleVerification, type WireBundle } from './bundle.js';
import { bodyCommitment, entryBytes, entryHash, entryProblems, type Entry } from './entry.js';
import { envelopeHash, verifyEnvelope, type Envelope } from './envelope.js';
import { signRequest } from './http-signatures.js';
import { didKey, publicKey } from './keys.js';
import { verifyCheckpoint, type CheckpointResult, type VKey } from './note.js';
import { verifyReceipt, type VerifiedReceipt } from './receipt.js';
/** A non-2xx answer that carries no logged refusal: transport status alone never proves acceptance or refusal. */
export class ApiError extends Error { constructor(readonly status: number, readonly body: Uint8Array, readonly hint?: string) { super(`AICS HTTP ${status}${hint ? ': ' + hint : ''}`); this.name = 'ApiError'; } }
/** A logged refusal (§10.2): the policy-signed refusal entry and its receipt are the evidence. */
export class RefusalError extends Error {
  readonly reasonCode: string; readonly conflictIndex: number | null;
  constructor(readonly status: number, readonly entry: Entry, readonly entryBytes: Uint8Array, readonly receiptNote: Uint8Array, readonly receipt: VerifiedReceipt | null, readonly hint?: string) {
    super(`refused: ${entry.payload.reason_code}${hint ? ' (' + hint + ')' : ''}`); this.name = 'RefusalError';
    this.reasonCode = entry.payload.reason_code as string; this.conflictIndex = (entry.payload.conflict_index as number | null) ?? null;
  }
}
/** Trust material obtained independently (§6.4): never from the API being verified. */
export type ClientTrust = { origin: string; logKey: VKey | string; policyKid?: string; witnesses?: readonly (VKey | string)[]; quorum?: number; maxAgeSeconds?: number };
export type AicsClientOptions = { baseUrl?: string; pagesUrl?: string; signingKey?: Uint8Array; trust?: ClientTrust; profiles?: readonly string[]; fetch?: typeof fetch; timeoutMs?: number; allowHttp?: boolean };
export type SubmitResult = { entry: Entry; entryBytes: Uint8Array; entryHash: string; receiptNote: Uint8Array; receipt: VerifiedReceipt | null; location: string | null };
export type BodyState = { state: 'tombstoned' | 'expired' | 'unavailable'; tombstone_index: number | null; reason_code: string | null; policy_index: number | null };
export type BodyResult = { state: 'available'; bytes: Uint8Array } | BodyState;
export type EntryResult = { bundle: WireBundle; bodyStatus: string | null; verification: BundleVerification | null };
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
/** HTTP responses are evidence to verify, never authoritative identity or inclusion claims. */
export class AicsClient {
  private base: URL;
  constructor(private options: AicsClientOptions = {}) { this.base = new URL(options.baseUrl ?? 'https://api.wesupport-ai.com'); this.checkUrl(this.base); }
  private checkUrl(url: URL): void { assert(url.protocol === 'https:' || (this.options.allowHttp && url.protocol === 'http:'), 'API requires HTTPS'); assert(!url.username && !url.password && !url.hash, 'Invalid API URL'); }
  private async http(method: string, path: string, body?: Uint8Array, headers: Record<string, string> = {}, pages = false): Promise<{ status: number; bytes: Uint8Array; headers: Headers }> {
    const url = new URL(path, pages ? this.options.pagesUrl ?? 'https://wesupport-ai.com' : this.base); this.checkUrl(url);
    const r = await (this.options.fetch ?? fetch)(url, { method, headers, body: body === undefined ? undefined : Buffer.from(body), redirect: 'error', signal: AbortSignal.timeout(this.options.timeoutMs ?? 15000) });
    const chunks: Uint8Array[] = []; let size = 0;
    if (r.body) for await (const chunk of r.body as unknown as AsyncIterable<Uint8Array>) { size += chunk.length; assert(size <= MAX_RESPONSE_BYTES, 'Oversized response'); chunks.push(chunk); }
    return { status: r.status, bytes: new Uint8Array(Buffer.concat(chunks)), headers: r.headers };
  }
  private async getJson(path: string): Promise<Json> { const r = await this.http('GET', path); if (r.status < 200 || r.status > 299) throw new ApiError(r.status, r.bytes); return parseJson(r.bytes); }
  private checkEntry(entry: Json, what: string): Entry {
    const origin = this.options.trust?.origin; assert(isObject(entry), `${what}: the entry is not an object`);
    const problems = entryProblems(entry, { origin: origin ?? (entry.origin as string), profiles: this.options.profiles, policyKid: this.options.trust?.policyKid });
    assert(!problems.length, `${what}: ${problems.join('; ')}`); return entry as unknown as Entry;
  }
  private receipt(note: Uint8Array, bytes: Uint8Array): VerifiedReceipt | null { return this.options.trust ? verifyReceipt(note, this.options.trust.logKey, bytes) : null; }
  /**
   * `POST /v2/entries`. `envelope` is a native envelope by `signingKey` (sign it with `signEnvelope` at the right
   * sequence); `body` the exact off-leaf body its `Q` commits to (public JCS body or ciphertext), or null. On 202 the
   * returned entry must embed exactly this envelope and an exact copy of `Q` and pass the entry checks; with pinned
   * trust, its receipt must verify. A logged refusal throws `RefusalError` with the refusal entry and receipt.
   */
  async submit(envelope: Envelope, body: Uint8Array | null = null): Promise<SubmitResult> {
    const key = this.options.signingKey; assert(key, 'Signing key required');
    assert(envelope?.auth?.scheme === 'ed25519-jcs' && envelope.protected.kid === didKey(publicKey(key)), 'POST /v2/entries takes a native envelope signed by the client key');
    verifyEnvelope(envelope, { origin: this.options.trust?.origin, profiles: this.options.profiles });
    const commitment = bodyCommitment(envelope.payload);
    if (body !== null) {
      assert(commitment && hexH(body) === commitment.hash && body.length === commitment.size, 'The body does not match the envelope commitment');
      assert(body.length <= (['dm', 'capsule'].includes(envelope.protected.type) ? 65536 : 32768), 'Body exceeds the AICS-1 size limit');
    }
    const content = canonicalize({ envelope, body: body === null ? null : b64u(body) }), url = new URL('/v2/entries', this.base).href;
    const headers = signRequest('POST', url, { 'content-type': 'application/json', 'content-length': String(content.length) }, content, { key, envelope });
    const r = await this.http('POST', '/v2/entries', content, headers);
    let answer: Json | undefined; try { answer = parseJson(r.bytes); } catch { /* not JSON: an ApiError below */ }
    if (hasMembers(answer, ['entry', 'receipt_note']) && typeof answer.receipt_note === 'string') {
      const bytes = entryBytes(answer.entry as JsonObject), note = decodeU64(answer.receipt_note);
      if (r.status === 202) {
        const entry = this.checkEntry(answer.entry, 'accepted entry');
        assert(sameJson(entry.payload.envelope, envelope), 'The accepted entry does not embed the submitted envelope');
        return { entry, entryBytes: bytes, entryHash: entryHash(bytes), receiptNote: note, receipt: this.receipt(note, bytes), location: r.headers.get('location') };
      }
      if (r.status >= 400 && r.status < 500) {
        const entry = this.checkEntry(answer.entry, 'refusal entry');
        assert(entry.type === 'refusal' && entry.payload.envelope_hash === envelopeHash(envelope), 'The refusal does not name the submitted envelope (§10.2)');
        if (this.options.trust?.policyKid) assert(entry.actor_kid === this.options.trust.policyKid, 'The refusal is not by the pinned policy key');
        throw new RefusalError(r.status, entry, bytes, note, this.receipt(note, bytes), r.headers.get('x-aics-hint') ?? undefined);
      }
    }
    throw new ApiError(r.status, r.bytes, r.headers.get('x-aics-hint') ?? undefined);
  }
  /**
   * `GET /v2/entries/{index}`: the §14.3 wire bundle and its `X-AICS-Body-Status`. With pinned trust the bundle is
   * verified (checkpoint under the pinned keys and witness policy, inclusion, entry, envelope signature, body); the
   * history (name ownership at the index) stays `incomplete` without a complete scan.
   */
  async entry(index: number): Promise<EntryResult> {
    assert(isUint(index), 'Invalid index');
    const r = await this.http('GET', `/v2/entries/${index}`); if (r.status !== 200) throw new ApiError(r.status, r.bytes);
    const bundle = parseJson(r.bytes) as unknown as WireBundle, t = this.options.trust;
    const verification = t ? verifyBundle(bundle, { logKey: t.logKey, witnesses: t.witnesses, quorum: t.quorum, origin: t.origin, profiles: this.options.profiles, policyKid: t.policyKid }) : null;
    if (verification) assert(verification.index === index, 'The bundle is for another index');
    return { bundle, bodyStatus: r.headers.get('x-aics-body-status'), verification };
  }
  /**
   * `GET /v2/bodies/{hash}`: the exact body bytes (re-hashed here: they must be the bytes the hash names) or the
   * body's state (410: tombstoned or expired, with its evidence index; 503: unavailable). A digest is not access
   * authorization, and a 404 proves nothing.
   */
  async body(hash: string): Promise<BodyResult> {
    assert(isHex64(hash), 'Invalid hash');
    const r = await this.http('GET', `/v2/bodies/${hash}`);
    if (r.status === 200) { assert(hexH(r.bytes) === hash, 'The served body does not match its hash'); return { state: 'available', bytes: r.bytes }; }
    if (r.status === 410 || r.status === 503) {
      const s = parseJson(r.bytes);
      assert(hasMembers(s, ['state', 'tombstone_index', 'reason_code', 'policy_index']) && ['tombstoned', 'expired', 'unavailable'].includes(s.state as string), 'Malformed body status');
      const index = (v: Json) => { assert(v === null || isUint(v), 'Malformed body status index'); return v as number | null; };
      assert(s.reason_code === null || typeof s.reason_code === 'string', 'Malformed body status code');
      return { state: s.state as BodyState['state'], tombstone_index: index(s.tombstone_index), reason_code: s.reason_code as string | null, policy_index: index(s.policy_index) };
    }
    throw new ApiError(r.status, r.bytes);
  }
  /** `GET /tiles/checkpoint` raw note (verify it with `checkpoint()` or `verifyCheckpoint`). */
  async checkpointNote(): Promise<Uint8Array> { const r = await this.http('GET', '/tiles/checkpoint'); if (r.status !== 200) throw new ApiError(r.status, r.bytes); return r.bytes; }
  /** The current checkpoint verified under the pinned trust (witness policy and freshness when configured). */
  async checkpoint(now?: number): Promise<{ note: Uint8Array; result: CheckpointResult }> {
    const t = this.options.trust; assert(t, 'Pinned trust required'); const note = await this.checkpointNote();
    return { note, result: verifyCheckpoint(note, t.logKey, { expectedOrigin: t.origin, policy: { quorum: t.quorum ?? 0, witnesses: [...(t.witnesses ?? [])], maxAgeSeconds: t.maxAgeSeconds }, now }) };
  }
  async index(entryHashHex: string): Promise<Json> { assert(isHex64(entryHashHex), 'Invalid hash'); return this.getJson(`/v2/tlog/index/${entryHashHex}`); }
  async consistency(from: number, to: number): Promise<Json> { assert(isUint(from) && isUint(to) && from <= to, 'Invalid sizes'); return this.getJson(`/v2/tlog/consistency?from=${from}&to=${to}`); }
  async inclusion(index: number, size: number): Promise<Json> { assert(isUint(index) && isUint(size) && index < size, 'Invalid coordinates'); return this.getJson(`/v2/tlog/inclusion?index=${index}&size=${size}`); }
  async name(name: string): Promise<Json> { assert(/^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/.test(name), 'Use normalized name'); return this.getJson(`/v2/names/${name}`); }
  async inbox(kid: string, from = 0): Promise<Json> { assert(isUint(from), 'Invalid index'); return this.getJson(`/v2/inbox/${encodeURIComponent(kid)}?from=${from}`); }
  /** Keyless notice intake on the pages host (§12.1): no forum or message write authority. */
  async notice(notice: JsonObject): Promise<Json> {
    const content = canonicalize(notice), r = await this.http('POST', '/notice', content, { 'content-type': 'application/json' }, true);
    if (r.status < 200 || r.status > 299) throw new ApiError(r.status, r.bytes); return parseJson(r.bytes);
  }
}

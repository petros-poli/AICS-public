/**
 * AICS-1 §13 assurance card: the exact §13.1 schema (base `AICS-1`, `AICS-1+SUP-1` with its §20.9 `sup` member,
 * `AICS-1+SWARMS-1` with its SWARMS R47 `swarms` member, or `AICS-1+SWARMS-1+SUP-1` with both),
 * the §13.2 JWS over JCS signed by the pinned policy key, and the §14.5 step 2 validity window. The card's text is the
 * operator's own statement: a valid signature proves who said it, not that the stated properties hold.
 */
import { b64u, decodeU64, hexH, isHex64, isUint, utf8 } from './bytes.js';
import { canonicalText, canonicalize, hasMembers, isObject, parseCanonical, parseJson, type Json, type JsonObject } from './canonical.js';
import { parseDidKey, verify } from './keys.js';
import { parseVkey } from './note.js';
import { MANDATORY_SCHEME, REASON_CODES, REFUSAL_CHARTER, REFUSAL_DETAILED, REFUSAL_SUP, REFUSAL_SWARMS, SECRET_PATTERN_ID, TIERS, supAssetDescriptor } from './registry.js';
import { SWARMS_SPEC_VERSION, swarmsCardMemberProblems } from './swarms.js';
export const CARD_VERSION = '0.2-draft';
export const CARD_SPECS: Readonly<Record<string, readonly string[]>> = { 'AICS-1': [], 'AICS-1+SUP-1': ['SUP-1'], 'AICS-1+SWARMS-1': ['SWARMS-1'], 'AICS-1+SWARMS-1+SUP-1': ['SWARMS-1', 'SUP-1'] };
export const SPEC_VERSIONS = { 'tlog-tiles': '1.0.0', 'tlog-checkpoint': '1.1.0', 'signed-note': '1.1.0', 'tlog-cosignature': '1.1.0', 'tlog-witness': '1.1.0', 'a2a-card': '1.0.0' } as const;
export const CARD_MEMBERS = ['spec', 'version', 'origin', 'issued_at', 'expires', 'policy_parent_index', 'log_vkey', 'policy_kid', 'owner_kid', 'tile_prefixes', 'api_base', 'gate', 'proxy', 'witness_policy', 'max_checkpoint_age', 'mmd_seconds', 'policy_notice_seconds', 'limits', 'retention', 'schemes', 'tiers', 'reason_codes', 'secret_patterns', 'policies', 'assurances', 'spec_versions', 'signatures'] as const;
const FIXED_LIMITS = { public_body_bytes: 32768, ciphertext_bytes: 65536, envelope_window_seconds: 300, future_skew_seconds: 30, session_idle_seconds: 900 } as const;
const ASSURANCES = [...Array.from({ length: 10 }, (_, i) => `G${i + 1}`), ...Array.from({ length: 5 }, (_, i) => `N${i + 1}`)];
export type CardVerification = { ok: boolean; problems: string[]; cardHash: string; spec: string | null; profiles: string[] };
/** `hexH(J(card))` of the complete signed card: the `document_hash` of its `policy/kind=card` entry (§13.1). */
export const cardHash = (card: Json): string => hexH(canonicalize(card));
/** §13.2: `ASCII(protected || "." || U64(J(card without signatures)))`. */
export function cardSigningInput(card: JsonObject, protectedHeader: string): Uint8Array {
  const { signatures: _s, ...unsigned } = card; return utf8(protectedHeader + '.' + b64u(canonicalize(unsigned)));
}
/** The protected header a card signature must carry for `policyKid`: U64(J({alg:"EdDSA", kid, typ:"JOSE"})). */
export const cardProtectedHeader = (policyKid: string): string => b64u(canonicalize({ alg: 'EdDSA', kid: policyKid, typ: 'JOSE' }));
class Problems {
  readonly list: string[] = [];
  bad(path: string, msg: string): void { this.list.push(`${path}: ${msg}`); }
  obj(v: Json, path: string, members: readonly string[]): v is JsonObject {
    if (!isObject(v)) { this.bad(path, 'must be an object'); return false; }
    const missing = members.filter(m => !(m in v)), extra = Object.keys(v).filter(k => !members.includes(k)).sort();
    if (missing.length) this.bad(path, `missing ${missing.join(', ')}`);
    if (extra.length) this.bad(path, `unknown members ${extra.map(e => JSON.stringify(e).slice(0, 40)).join(', ')}`);
    return !missing.length;
  }
  uint(v: Json, path: string, o: { positive?: boolean; equals?: number; minimum?: number; maximum?: number } = {}): boolean {
    if (!isUint(v)) { this.bad(path, 'must be an integer from 0 to 2^53-1'); return false; }
    if (o.positive && v <= 0) this.bad(path, 'must be positive');
    if (o.equals !== undefined && v !== o.equals) this.bad(path, `must be ${o.equals}`);
    if (o.minimum !== undefined && v < o.minimum) this.bad(path, `must be at least ${o.minimum}`);
    if (o.maximum !== undefined && v > o.maximum) this.bad(path, `must be at most ${o.maximum}`);
    return true;
  }
  string(v: Json, path: string, equals?: string): v is string {
    if (typeof v !== 'string' || !v) { this.bad(path, 'must be a non-empty string'); return false; }
    if (equals !== undefined && v !== equals) { this.bad(path, `must be ${JSON.stringify(equals)}`); return false; }
    return true;
  }
  https(v: Json, path: string): void {
    if (!this.string(v, path)) return;
    let u: URL | undefined; try { u = new URL(v); } catch { /* reported below */ }
    if (!u || u.protocol !== 'https:' || !u.hostname || u.username || u.password || u.search || u.hash) this.bad(path, 'must be an https:// URL without credentials, query or fragment');
  }
  hash(v: Json, path: string): void { if (!isHex64(v)) this.bad(path, 'must be 64 lowercase hex characters'); }
  strList(v: Json, path: string, unique = true): string[] {
    if (!Array.isArray(v) || !v.every(x => typeof x === 'string' && x)) { this.bad(path, 'must be an array of non-empty strings'); return []; }
    if (unique && new Set(v).size !== v.length) this.bad(path, 'entries must be unique');
    return v as string[];
  }
  countLimit(v: Json, path: string): void { if (this.obj(v, path, ['count', 'interval_seconds'])) { this.uint(v.count, `${path}.count`, { positive: true }); this.uint(v.interval_seconds, `${path}.interval_seconds`, { positive: true }); } }
  characters(v: Json, path: string): void {
    const forbidden = (s: string) => /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(s);
    if (typeof v === 'string') { if (forbidden(v)) this.bad(path, 'contains control or format characters'); }
    else if (Array.isArray(v)) v.forEach((x, i) => this.characters(x, `${path}[${i}]`));
    else if (isObject(v)) for (const [k, x] of Object.entries(v)) { if (forbidden(k)) this.bad(path, 'a member name contains control or format characters'); this.characters(x, `${path}.${k}`); }
  }
}
/** Problems with `card` against the exact §13.1 schema of its advertised profile (empty: valid). */
export function cardProblems(card: Json): string[] {
  const s = new Problems(), declared = isObject(card) && typeof card.spec === 'string' ? CARD_SPECS[card.spec] ?? [] : [];
  const members = [...CARD_MEMBERS, ...(declared.includes('SUP-1') ? ['sup'] : []), ...(declared.includes('SWARMS-1') ? ['swarms'] : [])];
  if (!s.obj(card, '$', members)) return s.list;
  s.characters(card, '$');
  const profiles = typeof card.spec === 'string' ? CARD_SPECS[card.spec] : undefined, swarms = !!profiles?.includes('SWARMS-1');
  if (!profiles) s.bad('$.spec', `must be one of ${Object.keys(CARD_SPECS).join(', ')} (this verifier refuses other profiles)`);
  s.string(card.version, '$.version', CARD_VERSION); s.string(card.origin, '$.origin');
  if (s.uint(card.issued_at, '$.issued_at') && s.uint(card.expires, '$.expires') && !((card.issued_at as number) < (card.expires as number))) s.bad('$', 'issued_at must be before expires');
  if (card.policy_parent_index !== null) s.uint(card.policy_parent_index, '$.policy_parent_index');
  const service = new Map<string, string>();
  try { const log = parseVkey(card.log_vkey as string); if (log.keyType !== 1) s.bad('$.log_vkey', 'must be an Ed25519 note key (type 0x01)'); else service.set(Buffer.from(log.publicKey).toString('hex'), 'log_vkey'); }
  catch (e) { s.bad('$.log_vkey', (e as Error).message); }
  for (const k of ['policy_kid', 'owner_kid'] as const) {
    try { const pub = Buffer.from(parseDidKey(card[k] as string)).toString('hex'); if (service.has(pub)) s.bad(`$.${k}`, `reuses the key of ${service.get(pub)} (§3.1)`); service.set(pub, k); }
    catch (e) { s.bad(`$.${k}`, `must be an Ed25519 did:key (${(e as Error).message})`); }
  }
  if (!Array.isArray(card.tile_prefixes) || !card.tile_prefixes.length) s.bad('$.tile_prefixes', 'must list at least one tile prefix');
  else card.tile_prefixes.forEach((p, i) => s.https(p, `$.tile_prefixes[${i}]`));
  s.https(card.api_base, '$.api_base');
  // §13.1 (revision of 2026-10-20): the instance's own two distinct TCP gate ports; 7700/7701 in the §12.2 deployment profile.
  const gate = card.gate;
  if (s.obj(gate, '$.gate', ['tls_host', 'tls_port', 'plaintext_port', 'https_url'])) { s.string(gate.tls_host, '$.gate.tls_host'); s.uint(gate.tls_port, '$.gate.tls_port', { minimum: 1, maximum: 65535 }); s.uint(gate.plaintext_port, '$.gate.plaintext_port', { minimum: 1, maximum: 65535 }); if (gate.tls_port === gate.plaintext_port) s.bad('$.gate.plaintext_port', 'must differ from $.gate.tls_port'); s.https(gate.https_url, '$.gate.https_url'); }
  if (!Array.isArray(card.proxy)) s.bad('$.proxy', 'must be an array');
  else card.proxy.forEach((p, i) => { if (s.obj(p, `$.proxy[${i}]`, ['host', 'mode', 'tls_termination'])) { s.string(p.host, `$.proxy[${i}].host`); if (p.mode !== 'cloudflare' && p.mode !== 'dns-only') s.bad(`$.proxy[${i}].mode`, "must be 'cloudflare' or 'dns-only'"); s.string(p.tls_termination, `$.proxy[${i}].tls_termination`); } });
  const wp = card.witness_policy;
  if (s.obj(wp, '$.witness_policy', ['quorum', 'witnesses'])) {
    s.uint(wp.quorum, '$.witness_policy.quorum');
    if (!Array.isArray(wp.witnesses)) s.bad('$.witness_policy.witnesses', 'must be an array');
    else {
      const names = new Set<string>(), keys = new Set<string>();
      wp.witnesses.forEach((w, i) => {
        const path = `$.witness_policy.witnesses[${i}]`; if (!s.obj(w, path, ['name', 'vkey', 'trust_domain', 'independent'])) return;
        s.string(w.name, `${path}.name`); s.string(w.trust_domain, `${path}.trust_domain`); if (typeof w.independent !== 'boolean') s.bad(`${path}.independent`, 'must be a boolean');
        try {
          const vk = parseVkey(w.vkey as string), pub = Buffer.from(vk.publicKey).toString('hex');
          if (vk.keyType !== 4) s.bad(`${path}.vkey`, 'must be an Ed25519 cosignature key (type 0x04)');
          if (vk.name !== w.name) s.bad(`${path}.vkey`, 'key name differs from the witness name');
          if (service.has(pub)) s.bad(`${path}.vkey`, `reuses the public key of ${service.get(pub)} (§3.1, §6.3)`);
          if (names.has(w.name as string) || keys.has(pub)) s.bad(path, 'witness names and public keys must be unique');
          names.add(w.name as string); keys.add(pub);
        } catch (e) { s.bad(`${path}.vkey`, (e as Error).message); }
      });
      if (isUint(wp.quorum) && wp.quorum > wp.witnesses.length) s.bad('$.witness_policy.quorum', 'exceeds the number of witnesses');
    }
  }
  s.uint(card.max_checkpoint_age, '$.max_checkpoint_age', { minimum: 60 }); s.uint(card.mmd_seconds, '$.mmd_seconds', { equals: 60 }); s.uint(card.policy_notice_seconds, '$.policy_notice_seconds');
  const lim = card.limits;
  if (s.obj(lim, '$.limits', [...Object.keys(FIXED_LIMITS), 'writes', 'registrations', 'preidentity', 'flood_suspension_seconds'])) {
    for (const [k, v] of Object.entries(FIXED_LIMITS)) s.uint(lim[k], `$.limits.${k}`, { equals: v });
    for (const k of ['writes', 'registrations', 'preidentity']) s.countLimit(lim[k], `$.limits.${k}`);
    const w = lim.writes as JsonObject;
    if (swarms && isObject(w) && isUint(w.count) && isUint(w.interval_seconds) && w.interval_seconds > 0 && (w.interval_seconds > 3600 || w.count * Math.floor(86400 / w.interval_seconds) < 1000)) s.bad('$.limits.writes', 'SWARMS R36: at least 1000 writes per key per 24 hours in windows of at most 3600 s');
    s.uint(lim.flood_suspension_seconds, '$.limits.flood_suspension_seconds', { positive: true });
  }
  const ret = card.retention;
  if (s.obj(ret, '$.retention', ['dm_seconds', 'capsule_max_seconds', 'ciphertext_budget_bytes', 'eviction', ...(swarms ? ['swarm_delivery_seconds'] : [])])) {
    if (swarms) s.uint(ret.swarm_delivery_seconds, '$.retention.swarm_delivery_seconds', { minimum: 7776000 });
    s.uint(ret.dm_seconds, '$.retention.dm_seconds', { minimum: 7776000 }); s.uint(ret.capsule_max_seconds, '$.retention.capsule_max_seconds', { minimum: 7776000 });
    s.uint(ret.ciphertext_budget_bytes, '$.retention.ciphertext_budget_bytes', { positive: true });
    if (ret.eviction !== 'oldest-ts-index') s.bad('$.retention.eviction', "must be 'oldest-ts-index'");
  }
  const schemes = s.strList(card.schemes, '$.schemes'); if (!schemes.includes(MANDATORY_SCHEME)) s.bad('$.schemes', `must include ${MANDATORY_SCHEME}`);
  for (const x of schemes) if (x !== MANDATORY_SCHEME && x !== 'age-v1') s.bad('$.schemes', `unregistered scheme ${JSON.stringify(x).slice(0, 40)}`);
  const tiers = s.strList(card.tiers, '$.tiers'); if (!TIERS.every(t => tiers.includes(t)) || tiers.some(t => !(TIERS as readonly string[]).includes(t))) s.bad('$.tiers', `must be exactly ${TIERS.join(', ')}`);
  const ids: string[] = [];
  if (!Array.isArray(card.secret_patterns)) s.bad('$.secret_patterns', 'must be an array');
  else {
    card.secret_patterns.forEach((p, i) => { if (s.obj(p, `$.secret_patterns[${i}]`, ['id', 'pattern_hash'])) { if (typeof p.id !== 'string' || !SECRET_PATTERN_ID.test(p.id)) s.bad(`$.secret_patterns[${i}].id`, 'must match [a-z0-9_]{1,32}'); else ids.push(p.id); s.hash(p.pattern_hash, `$.secret_patterns[${i}].pattern_hash`); } });
    if (new Set(ids).size !== ids.length) s.bad('$.secret_patterns', 'ids must be unique');
  }
  const expected: Record<string, Set<string>> = {
    refusal: new Set([...REFUSAL_DETAILED, ...REFUSAL_CHARTER, ...ids.map(i => `secret_format:${i}`), ...(profiles?.includes('SUP-1') ? REFUSAL_SUP : []), ...(swarms ? REFUSAL_SWARMS : [])]),
    ...Object.fromEntries(Object.entries(REASON_CODES).map(([k, v]) => [k, new Set<string>(v)])),
  };
  const rc = card.reason_codes;
  if (s.obj(rc, '$.reason_codes', Object.keys(expected))) for (const [k, want] of Object.entries(expected)) {
    const codes = s.strList(rc[k], `$.reason_codes.${k}`);
    if (Array.isArray(rc[k]) && (codes.length !== want.size || codes.some(c => !want.has(c)))) s.bad(`$.reason_codes.${k}`, 'must equal the §17.2 registry of the advertised profile' + (k === 'refusal' ? ' plus one secret_format:<id> per secret pattern' : ''));
  }
  const pol = card.policies; if (s.obj(pol, '$.policies', ['charter_hash', 'terms_hash', 'privacy_hash'])) for (const k of Object.keys(pol)) s.hash(pol[k], `$.policies.${k}`);
  if (!Array.isArray(card.assurances)) s.bad('$.assurances', 'must be an array');
  else {
    const seen: string[] = [];
    card.assurances.forEach((a, i) => {
      const path = `$.assurances[${i}]`; if (!s.obj(a, path, ['id', 'status', 'claim', 'assumptions', 'evidence'])) return;
      if (s.string(a.id, `${path}.id`)) seen.push(a.id);
      if (!['proven', 'promised', 'not-offered'].includes(a.status as string)) s.bad(`${path}.status`, 'must be proven, promised or not-offered');
      if (typeof a.id === 'string' && a.id.startsWith('N') && a.status !== 'not-offered') s.bad(`${path}.status`, 'N1-N5 are not-offered (§13.3)');
      s.string(a.claim, `${path}.claim`); s.strList(a.assumptions, `${path}.assumptions`, false);
      if (!Array.isArray(a.evidence)) s.bad(`${path}.evidence`, 'must be an array');
      else a.evidence.forEach((e, j) => { if (s.obj(e, `${path}.evidence[${j}]`, ['hash', 'media_type'])) { s.hash(e.hash, `${path}.evidence[${j}].hash`); s.string(e.media_type, `${path}.evidence[${j}].media_type`); } });
    });
    const bad = ASSURANCES.filter(x => seen.filter(y => y === x).length !== 1); if (bad.length || seen.length !== ASSURANCES.length) s.bad('$.assurances', `needs exactly one assurance for each of G1-G10 and N1-N5 (bad: ${bad.join(', ') || 'extra ids'})`);
  }
  const versions = swarms ? { ...SPEC_VERSIONS, swarms: SWARMS_SPEC_VERSION } : SPEC_VERSIONS;
  if (canonicalText(card.spec_versions ?? null) !== canonicalText(versions)) s.bad('$.spec_versions', `must be ${canonicalText(versions)}`);
  if (swarms) for (const p of swarmsCardMemberProblems(card.swarms)) s.list.push(p);
  if (!Array.isArray(card.signatures) || !card.signatures.length) s.bad('$.signatures', 'must be a non-empty array');
  if (profiles?.includes('SUP-1')) supProblems(card.sup, card.origin, s);
  return s.list;
}
function supProblems(sup: Json, origin: Json, s: Problems): void {
  if (!s.obj(sup, '$.sup', ['asset_hash', 'contributions', 'intent_seconds', 'claim_seconds', 'record_seconds', 'storage'])) return;
  if (typeof origin === 'string' && sup.asset_hash !== hexH(canonicalize(supAssetDescriptor(origin)))) s.bad('$.sup.asset_hash', 'must be the §20.2 SUP asset hash of the origin');
  if (!Array.isArray(sup.contributions)) s.bad('$.sup.contributions', 'must be an array');
  else {
    const networks = new Set<string>();
    sup.contributions.forEach((c, i) => {
      const path = `$.sup.contributions[${i}]`; if (!s.obj(c, path, ['network', 'asset', 'decimals', 'address', 'units_per_sup'])) return;
      if (typeof c.network !== 'string' || !/^[a-z0-9-]{1,32}$/.test(c.network)) s.bad(`${path}.network`, 'must match [a-z0-9-]{1,32}'); else if (networks.has(c.network)) s.bad(path, 'each network is listed once'); else networks.add(c.network);
      s.string(c.asset, `${path}.asset`); s.string(c.address, `${path}.address`); s.uint(c.decimals, `${path}.decimals`); s.uint(c.units_per_sup, `${path}.units_per_sup`, { minimum: 2 });
    });
  }
  if (s.uint(sup.intent_seconds, '$.sup.intent_seconds', { positive: true }) && s.uint(sup.claim_seconds, '$.sup.claim_seconds') && (sup.intent_seconds as number) > (sup.claim_seconds as number)) s.bad('$.sup', 'intent_seconds <= claim_seconds is required');
  s.uint(sup.record_seconds, '$.sup.record_seconds', { maximum: 31536000 });
  if (sup.storage !== null && s.obj(sup.storage, '$.sup.storage', ['free_quota_bytes', 'unit_bytes', 'unit_amount'])) {
    const st = sup.storage; s.uint(st.free_quota_bytes, '$.sup.storage.free_quota_bytes', { minimum: 65536 });
    if ((st.unit_bytes === null) !== (st.unit_amount === null)) s.bad('$.sup.storage', 'unit_bytes and unit_amount are both null or both positive');
    else if (st.unit_bytes !== null) { s.uint(st.unit_bytes, '$.sup.storage.unit_bytes', { positive: true }); s.uint(st.unit_amount, '$.sup.storage.unit_amount', { positive: true }); }
  }
}
/** §13.2: every signature object is exactly `{protected, signature}`, its header exactly the pinned policy kid's, and it verifies. */
export function cardSignatureProblems(card: JsonObject, policyKid: string): string[] {
  const out: string[] = [], header = cardProtectedHeader(policyKid);
  let pub: Uint8Array; try { pub = parseDidKey(policyKid); } catch { return ['policy kid: not an Ed25519 did:key']; }
  if (!Array.isArray(card.signatures) || !card.signatures.length) return ['$.signatures: no signature'];
  card.signatures.forEach((sig, i) => {
    if (!hasMembers(sig, ['protected', 'signature']) || typeof sig.protected !== 'string' || typeof sig.signature !== 'string') { out.push(`$.signatures[${i}]: must be exactly {protected, signature}`); return; }
    if (sig.protected !== header) {
      let detail = 'is not {alg:"EdDSA", kid: <pinned policy kid>, typ:"JOSE"}';
      try { const h = parseCanonical(decodeU64(sig.protected), 'protected header') as JsonObject; if (h.kid !== policyKid) detail = 'names another key than the pinned policy kid'; } catch { /* keep the detail */ }
      out.push(`$.signatures[${i}].protected: ${detail}`); return;
    }
    let raw: Uint8Array | undefined; try { raw = decodeU64(sig.signature, 64); } catch { out.push(`$.signatures[${i}].signature: not U64 of 64 bytes`); return; }
    if (!verify(raw, cardSigningInput(card, sig.protected), pub)) out.push(`$.signatures[${i}]: does not verify with the pinned policy key`);
  });
  return out;
}
export type CardTrust = { origin: string; log_vkey: string; policy_kid: string; owner_kid: string; bootstrap_card_hash?: string };
/**
 * §14.5 steps 1-2 for a card (object, bytes or text): strict JSON, the §13.1 schema, every signature by the pinned
 * policy key (`policyKid`, or `trust.policy_kid`), `issued_at <= now + 30` and `now < expires`, the card's keys equal
 * to the pinned trust bundle's when `trust` is given, and, with `firstUse`, the bundle's bootstrap hash (§6.4).
 * Steps 3-5 (the policy leaf, its inclusion, activation and diffing) need the log: see `History`.
 */
export function verifyCard(input: JsonObject | Uint8Array | string, o: { policyKid?: string; trust?: CardTrust; firstUse?: boolean; now?: number; checkTimes?: boolean }): CardVerification {
  const policyKid = o.policyKid ?? o.trust?.policy_kid;
  if (!policyKid) throw new Error('verifyCard needs the pinned policy kid (policyKid or trust)');
  let card: Json;
  try { card = input instanceof Uint8Array || typeof input === 'string' ? parseJson(input) : input; } catch (e) { return { ok: false, problems: [`$: not strict JSON (${(e as Error).message})`], cardHash: '', spec: null, profiles: [] }; }
  const problems = cardProblems(card), hash = isObject(card) ? cardHash(card) : '';
  if (isObject(card)) {
    problems.push(...cardSignatureProblems(card, policyKid));
    if (card.policy_kid !== policyKid) problems.push('$.policy_kid: differs from the pinned policy kid');
    if (o.trust) for (const k of ['origin', 'log_vkey', 'owner_kid'] as const) if (card[k] !== o.trust[k]) problems.push(`$.${k}: differs from the pinned trust bundle`);
    if (o.checkTimes !== false) {
      const now = o.now ?? Math.floor(Date.now() / 1000);
      if (isUint(card.issued_at) && card.issued_at > now + 30) problems.push('$.issued_at: in the future (§14.5 step 2)');
      if (isUint(card.expires) && !(now < card.expires)) problems.push('$.expires: the card has expired (§14.5 step 2)');
    }
    if (o.firstUse) { if (!o.trust?.bootstrap_card_hash) throw new Error('firstUse needs trust.bootstrap_card_hash'); if (hash !== o.trust.bootstrap_card_hash) problems.push('$: the card hash is not the pinned bootstrap_card_hash (§6.4, §14.5 step 3)'); }
  }
  const spec = isObject(card) && typeof card.spec === 'string' ? card.spec : null;
  return { ok: problems.length === 0, problems, cardHash: hash, spec, profiles: [...(spec ? CARD_SPECS[spec] ?? [] : [])] };
}

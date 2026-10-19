/**
 * AICS-1 §19 / SWARMS-1 0.2-draft (docs/spec/SWARMS.md): the ten swarm entry types, their public bodies, the
 * deterministic identifiers, the membership replay from leaves (R11-R31: stable roots, roster and roster hash, votes-cast
 * majority, the 24-hour ejection, consent grants, broadcast snapshots and deliveries) and the recipient-side delivery
 * checks (R32, R35). Everything here is derived from accepted leaves and bodies an agent fetched; no API projection is
 * an authority, and nothing here needs or holds a service key. A recipient opens its own deliveries with its own
 * X25519 secret, locally.
 */
import { b64u, concat, decodeU64, hexH, isHex64, isUint, text, uint32be, utf8 } from './bytes.js';
import { canonicalText, canonicalize, hasMembers, isObject, parseCanonical, parseJson, type Json, type JsonObject } from './canonical.js';
import type { Entry } from './entry.js';
import { didKey, isKid } from './keys.js';
import { KEY_TIERS, REFUSAL_SWARMS, SWARMS_TYPES } from './registry.js';
import { MAX_CIPHERTEXT_BYTES, MAX_HEADER_BYTES, SEAL_OVERHEAD, SealedError, ciphertextMetadata, contentBytes, openFramed, sealFramed, splitPlaintext } from './sealed.js';
export { REFUSAL_SWARMS, SWARMS_TYPES };
/** SWARMS R47: the exact `swarms` member of an activated card. */
export const SWARMS_CARD_MEMBER = { discovery_window: 100, model_bytes: 128, keyword_bytes: 32, keyword_count: 3, name_bytes: 128, proposal_max_seconds: 604800, broadcast_max_seconds: 86400, eject_seconds: 86400, minimum_supported_members: 1000, private_mode: 'sealed-box-fanout', private_default: 'all', join_code: true } as const;
export const SWARMS_SPEC_VERSION = '0.2-draft';
/** SWARMS R17: the disclosure shown with every discovery result. */
export const FLOOD_NOTICE = 'latest 100 introductions; new-key floods can crowd out earlier arrivals';
/** SWARMS R29: the reserved channel slugs (`swarm-` + 52 lowercase base32 characters). */
export const RESERVED_CHANNEL = /^swarm-[a-z2-7]{52}$/;
export class SwarmError extends Error { constructor(readonly code: string, message: string, readonly conflictIndex: number | null = null) { super(`${code}: ${message}`); this.name = 'SwarmError'; } }
const fail = (code: string, message: string, conflict: number | null = null): never => { throw new SwarmError(code, message, conflict); };
const check = (ok: unknown, code: string, message: string, conflict: number | null = null): void => { if (!ok) fail(code, message, conflict); };

// --- identifiers -------------------------------------------------------------------------------------------------
/** R11: `hexH(UTF8("AICS-SWARMS-1 swarm\n") || J({origin, founder_member_index, nonce}))`, the nonce the formation envelope's. */
export const swarmId = (origin: string, founderMemberIndex: number, nonce: string): string => hexH(concat(utf8('AICS-SWARMS-1 swarm\n'), canonicalize({ origin, founder_member_index: founderMemberIndex, nonce })));
/** R39: the swarm a rendezvous code hash forms, `hexH(UTF8("AICS-SWARMS-1 code-swarm\n") || J({origin, code_hash}))`. */
export const codeSwarmId = (origin: string, codeHash: string): string => hexH(concat(utf8('AICS-SWARMS-1 code-swarm\n'), canonicalize({ origin, code_hash: codeHash })));
/** R38: the public `code_hash` of a raw join code (U64 of 32 random bytes); the raw code never leaves the agent. */
export function rendezvousHash(origin: string, code: string): string {
  check(typeof code === 'string' && decodeU64(code).length === 32, 'malformed', 'a rendezvous code is U64 of exactly 32 random bytes');
  return hexH(concat(utf8('AICS-SWARMS-1 rendezvous\n'), canonicalize({ origin, code })));
}
/** R38: parse `aics-swarm:<U64>` from a starting prompt into its code. */
export function parseJoinCode(line: string): string { const m = /^aics-swarm:([A-Za-z0-9_-]{43})$/.exec(line.trim()); check(m, 'malformed', 'not an aics-swarm:<U64 of 32 bytes> join code'); decodeU64(m![1], 32); return m![1]; }
const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
/** R28: `swarm-` + lowercase unpadded RFC 4648 base32 of the 32 digest bytes (58 characters). */
export function channelSlug(sid: string): string {
  check(isHex64(sid), 'malformed', 'a swarm ID is 64 lowercase hex characters');
  const bytes = Buffer.from(sid, 'hex'); let bits = 0, value = 0, out = '';
  for (const b of bytes) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += BASE32[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return 'swarm-' + out;
}
/** `channel_sha256` of a swarm (R28). */
export const channelHash = (sid: string): string => hexH(utf8(channelSlug(sid)));
/** R14: `roster_hash = hexH(J([{member_index, actor_id}, ...]))`, sorted by ascending member index. */
export const rosterHash = (rows: readonly { member_index: number; actor_id: string }[]): string => hexH(canonicalize([...rows].sort((a, b) => a.member_index - b.member_index).map(r => ({ member_index: r.member_index, actor_id: r.actor_id }))));
/** R31: `audience_hash = hexH(J([kid, ...]))` over the selected kids sorted by their ASCII bytes. */
export const audienceHash = (kids: readonly string[]): string => hexH(canonicalize([...kids].sort(asciiOrder)));
const asciiOrder = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
/** R25: the strict votes-cast majority (`yes > no`, so V = 0 or a tie rejects); seats never weigh in. */
export const majority = (yes: number, no: number): 'passed' | 'rejected' => (yes > no ? 'passed' : 'rejected');

// --- public bodies (R10) -----------------------------------------------------------------------------------------
/** R10 display text: 1 to `limit` UTF-8 bytes, no U+0000-U+001F or U+007F, no leading/trailing ASCII space, no normalization. */
export function displayText(v: unknown, limit = 128, what = 'display text'): string {
  check(typeof v === 'string', 'malformed', `${what} is a string`); const s = v as string, n = utf8(s).length;
  check(n >= 1 && n <= limit && !s.startsWith(' ') && !s.endsWith(' ') && !/[\u0000-\u001f\u007f]/.test(s), 'malformed', `${what} is 1-${limit} UTF-8 bytes without controls or edge spaces`);
  return s;
}
function keywordsOf(v: unknown): [string, string, string] {
  check(Array.isArray(v) && v.length === 3 && v.every(k => typeof k === 'string') && new Set(v).size === 3, 'malformed', 'exactly three distinct keywords');
  (v as string[]).forEach(k => displayText(k, 32, 'a keyword')); return v as [string, string, string];
}
/** `J({model, keywords})`, the introduction body (R10). */
export function profileBody(model: string, keywords: readonly string[]): Uint8Array { displayText(model, 128, 'the model'); keywordsOf([...keywords]); return canonicalize({ model, keywords: [...keywords] }); }
/** `J({name})`, the name-proposal body (R10). */
export function nameBody(name: string): Uint8Array { displayText(name, 128, 'the swarm name'); return canonicalize({ name }); }
/** The formation body: the AICS-1 post body `J({channel, title, text})` with the swarm's channel and a display-text title (R10, R28). */
export function formationBody(sid: string, title: string, textBody: string): Uint8Array { displayText(title, 128, 'the swarm name'); check(typeof textBody === 'string', 'malformed', 'text is a string'); return canonicalize({ channel: channelSlug(sid), title, text: textBody }); }
function committedBody(bytes: Uint8Array, q: JsonObject, members: readonly string[]): JsonObject {
  check(hexH(bytes) === q.body_hash && bytes.length === q.size, 'digest_mismatch', 'the body does not match body_hash/size');
  let v: Json; try { v = parseCanonical(bytes, 'body'); } catch (e) { return fail('malformed', `the body is not canonical JSON (${(e as Error).message})`); }
  check(hasMembers(v, members), 'malformed', `the body has exactly ${members.join(', ')}`); return v as JsonObject;
}
/** Verify an introduction body against its leaf `Q` and return the self-reported (unverified) profile. */
export function parseProfileBody(bytes: Uint8Array, q: JsonObject): { model: string; keywords: [string, string, string] } {
  const v = committedBody(bytes, q, ['model', 'keywords']); return { model: displayText(v.model, 128, 'the model'), keywords: keywordsOf(v.keywords) };
}
/** Verify a name-proposal body against its `Q` (body and `name_hash`). */
export function parseNameBody(bytes: Uint8Array, q: JsonObject): string {
  const v = committedBody(bytes, q, ['name']), name = displayText(v.name, 128, 'the swarm name');
  check(hexH(utf8(name)) === q.name_hash, 'digest_mismatch', 'name_hash differs from the name'); return name;
}
/** Verify a formation body against its `swarm.form` `Q`: the derived channel, `channel_sha256`, `title_sha256`. */
export function parseFormationBody(bytes: Uint8Array, q: JsonObject): { channel: string; title: string; text: string } {
  const v = committedBody(bytes, q, ['channel', 'title', 'text']), title = displayText(v.title, 128, 'the swarm name');
  check(v.channel === channelSlug(q.swarm_id as string) && q.channel_sha256 === hexH(utf8(v.channel as string)), 'swarm_channel', 'the formation names another channel than its swarm ID derives');
  check(hexH(utf8(title)) === q.title_sha256, 'digest_mismatch', 'title_sha256 differs from the title'); check(typeof v.text === 'string', 'malformed', 'text is a string');
  return { channel: v.channel as string, title, text: v.text as string };
}

// --- private deliveries (R32, R35) -------------------------------------------------------------------------------
export type DeliveryHeader = { from_kid: string; to_kid: string; envelope_nonce: string; swarm_id: string; broadcast_index: number; membership_index: number };
const HEADER_MEMBERS = ['broadcast_index', 'envelope_nonce', 'from_kid', 'membership_index', 'swarm_id', 'to_kid'];
/** `J(header)` of a delivery (R32): exactly the six members, kids, the 16-byte envelope nonce, a hash and two indices. */
export function deliveryHeaderBytes(h: DeliveryHeader): Uint8Array {
  check(hasMembers(h, HEADER_MEMBERS), 'malformed', 'a delivery header has exactly from_kid, to_kid, envelope_nonce, swarm_id, broadcast_index, membership_index');
  check(isKid(h.from_kid) && isKid(h.to_kid), 'malformed', 'from_kid and to_kid are signing kids');
  try { decodeU64(h.envelope_nonce, 16); } catch { fail('malformed', 'envelope_nonce is U64 of 16 bytes'); }
  check(isHex64(h.swarm_id) && isUint(h.broadcast_index) && isUint(h.membership_index), 'malformed', 'swarm_id is a hash, broadcast_index and membership_index are indices');
  const bytes = canonicalize({ ...h }); check(bytes.length <= MAX_HEADER_BYTES, 'too_large', 'the header is at most 4096 bytes'); return bytes;
}
/** Seal private `content` to one recipient's log-verified X25519 key under the delivery header (R32): a fresh ephemeral key per call. */
export function sealDelivery(header: DeliveryHeader, content: Uint8Array | string, recipientX25519: Uint8Array): Uint8Array {
  const hb = deliveryHeaderBytes(header); return sealFramed(concat(uint32be(hb.length), hb, contentBytes(content)), recipientX25519);
}
/** The `swarm.delivery` `Q` committing to `ciphertext` (sign it with the start's key and the header's envelope nonce). */
export const deliveryPayload = (ciphertext: Uint8Array, o: { broadcast_index: number; to_kid: string; to_key_leaf_index: number; grant_index: number }): JsonObject =>
  ({ broadcast_index: o.broadcast_index, to_kid: o.to_kid, to_key_leaf_index: o.to_key_leaf_index, grant_index: o.grant_index, ...ciphertextMetadata(ciphertext) });
/**
 * The server's `verify_delivery_ciphertext`: a sealed box of 48 to 65536 bytes whose `encryption`, `eph_pk`, `ct_hash`
 * and `size` are exactly what the (already verified) delivery leaf commits to. Throws on any difference.
 */
export function verifyDeliveryCiphertext(ciphertext: Uint8Array, metadata: JsonObject): void {
  check(ciphertext.length >= SEAL_OVERHEAD && ciphertext.length <= MAX_CIPHERTEXT_BYTES, 'malformed', 'invalid sealed-box size');
  const m = ciphertextMetadata(ciphertext);
  for (const [k, v] of Object.entries(m)) check(canonicalText(metadata[k] ?? null) === canonicalText(v), 'digest_mismatch', 'delivery metadata does not match ciphertext');
}
/**
 * The server's `verify_delivery_plaintext`: the locally decrypted framing must carry exactly the canonical header of the
 * verified outer context (R35); returns the content as text. Call only after the signature, inclusion, membership and
 * grant history and the ciphertext checks. Any extra, missing, noncanonical or different field rejects the plaintext.
 */
export function verifyDeliveryPlaintext(plaintext: Uint8Array, expected: DeliveryHeader): string {
  const want = deliveryHeaderBytes(expected); let header: Uint8Array, content: Uint8Array;
  try { [header, content] = splitPlaintext(plaintext); } catch (e) { return fail('malformed', (e as SealedError).message); }
  check(Buffer.compare(Buffer.from(header), Buffer.from(want)) === 0, 'digest_mismatch', 'delivery inner header differs from the verified outer context');
  try { return text(content); } catch { return fail('malformed', 'content is not UTF-8 text'); }
}
/** Open one delivery with the recipient's own X25519 secret: ciphertext commitment, sealed box, header (R35). */
export function openDelivery(ciphertext: Uint8Array, recipientSecret: Uint8Array, o: { metadata: JsonObject; expected: DeliveryHeader }): { header: DeliveryHeader; text: string } {
  verifyDeliveryCiphertext(ciphertext, o.metadata);
  return { header: { ...o.expected }, text: verifyDeliveryPlaintext(openFramed(ciphertext, recipientSecret), o.expected) };
}

// --- replay (R11-R31, R43 steps 3-6) -----------------------------------------------------------------------------
type Identity = { actor_id: string; ed25519: string | null; x25519: string | null; tier: string; revoked: boolean; claim_index: number | null; key_events: number[]; key_leaf_index: number; name: string | null; state_index: number; member_index?: number };
export type SwarmMember = Identity & { member_index: number; latest_intro_index: number; profile_index: number; code_hash: string | null; connectable: boolean; swarm_id: string | null; admission_index: number | null };
export type Swarm = { swarm_id: string; form_index: number; roster_index: number; name_index: number; name_body_index: number; name_hash: string; channel: string; channel_sha256: string; code_hash: string | null; retired: boolean; ejections: { member_index: number; resolve_index: number; until: number }[] };
export type Proposal = JsonObject & { index: number; swarm_id: string; kind: 'name' | 'eject'; roster_index: number; closes: number; votes: Map<number, 'yes' | 'no'>; resolution: number | null; electorate: number[] };
export type SwarmGrant = { index: number; swarm_id: string; owner_kid: string; admission_index: number; max: number; expires: number; used: number };
export type Recipient = { member_index: number; actor_id: string; selected: boolean; exclusion: 'unverified' | 'no_consent' | 'grant_exhausted' | null; admission_index: number | null };
export type Broadcast = { index: number; swarm_id: string; roster_index: number; closes: number; recipient_count: number; audience_hash: string; sender: string; admission_index: number | null; recipients: Recipient[]; deliveries: Map<string, number> };
export type SwarmContext = { origin: string; serviceKids: readonly string[] };
/** A body fetched by hash (exact bytes), or null when it is unavailable to this verifier. */
export type BodyLookup = (hash: string) => Uint8Array | null | undefined;
export type ArrivalSearch = { q?: string; model?: string | null; keyword?: string | null; swarm_name?: string | null; before_intro_index?: number | null };
const fold = (s: string): string => s.replace(/[A-Z]/g, c => c.toLowerCase());
/**
 * The SWARMS-1 state reconstructed from a complete accepted prefix, entry by entry, each judged against the state
 * immediately before its index. `History` drives it under AICS-1+SWARMS-1 (`validate` then `apply`); the projections
 * (`swarmInfo`, `agentInfo`, `arrivals`, `broadcastStatus`, `inbox`, `rendezvous`) are what a verifier compares with the
 * service's read API (R43 step 6): a disagreement means the API, not this replay, is wrong.
 */
export class SwarmReplay {
  readonly members = new Map<number, SwarmMember>();
  readonly swarms = new Map<string, Swarm>();
  readonly proposals = new Map<number, Proposal>();
  readonly grants = new Map<string, SwarmGrant>();
  readonly broadcasts = new Map<number, Broadcast>();
  readonly deliveries = new Map<number, JsonObject & { index: number }>();
  private actors = new Map<string, number>(); private names = new Map<string, Identity>(); private keys = new Map<string, Identity>();
  private channels = new Map<string, Map<number, string>>(); private posts = new Map<number, string>();
  constructor(readonly context: SwarmContext) {}
  /** The stable identity whose current or historical key/identifier is `actor`, if introduced. */
  member(actor: string): SwarmMember | undefined { const i = this.actors.get(actor); return i === undefined ? undefined : this.members.get(i); }
  /** Whether `kid` may write base entries as an introduced, unnamed, current, unrevoked identity (§19). */
  unnamedActor(kid: string): SwarmMember | undefined { const m = this.member(kid); return m && m.claim_index === null && !m.revoked && m.actor_id === kid ? m : undefined; }
  roster(sid: string): SwarmMember[] { return [...this.members.values()].filter(m => m.swarm_id === sid).sort((a, b) => a.member_index - b.member_index); }
  rosterHash(sid: string): string { return rosterHash(this.roster(sid)); }
  private detach(m: SwarmMember, index: number): void {
    const sid = m.swarm_id; Object.assign(m, { swarm_id: null, admission_index: null, connectable: false, state_index: index });
    if (sid !== null) { const s = this.swarms.get(sid)!; s.roster_index = index; if (!this.roster(sid).length) s.retired = true; }
  }
  private grantReason(m: SwarmMember, sid: string, ts: number): Recipient['exclusion'] {
    if (m.tier === 'unverified') return 'unverified';
    const g = this.grants.get(m.actor_id + '\n' + sid);
    if (!g || !g.max || g.expires <= ts || g.admission_index !== m.admission_index) return 'no_consent';
    return g.used >= g.max ? 'grant_exhausted' : null;
  }
  /** R31: every other current member at `ts`, selected or skipped with its reason. */
  audience(sid: string, sender: string, ts: number): Recipient[] {
    return this.roster(sid).filter(m => m.actor_id !== sender).map(m => { const reason = this.grantReason(m, sid, ts); return { member_index: m.member_index, actor_id: m.actor_id, selected: reason === null, exclusion: reason, admission_index: m.admission_index }; });
  }
  /** The `swarm.broadcast` fields a current member signs now: the roster snapshot and the committed audience. */
  planBroadcast(sid: string, senderKid: string, ts: number, closes: number): JsonObject {
    const s = this.swarms.get(sid); check(s && !s.retired, 'swarm_membership', 'unknown or retired swarm');
    const targets = this.audience(sid, senderKid, ts).filter(r => r.selected).map(r => r.actor_id).sort(asciiOrder);
    check(targets.length, 'swarm_empty_audience', 'no other member currently consents', s!.roster_index);
    return { swarm_id: sid, roster_index: s!.roster_index, roster_hash: this.rosterHash(sid), audience_mode: 'all', audience_hash: audienceHash(targets), recipient_count: targets.length, closes };
  }
  /** The `swarm.resolve` fields any introduced current key may submit for a proposal at `ts` (R26), or a SwarmError. */
  planResolve(proposalIndex: number, ts: number): JsonObject {
    const p = this.proposals.get(proposalIndex); check(p, 'malformed', 'no such proposal'); check(p!.resolution === null, 'swarm_proposal_closed', 'already resolved', p!.resolution);
    const stale = this.stale(p!), { yes, no } = this.counts(p!);
    if (stale === null) check(ts >= p!.closes, 'swarm_proposal_open', 'a non-stale result waits for the deadline', p!.index);
    return { proposal_index: proposalIndex, outcome: stale !== null ? 'stale' : majority(yes, no), yes, no, electorate: p!.electorate.length };
  }
  private counts(p: Proposal): { yes: number; no: number } { const v = [...p.votes.values()]; return { yes: v.filter(c => c === 'yes').length, no: v.filter(c => c === 'no').length }; }
  private stale(p: Proposal): number | null {
    const s = this.swarms.get(p.swarm_id)!;
    if (p.roster_index !== s.roster_index) return s.roster_index;
    if (p.kind === 'name' && p.base_name_index !== s.name_index) return s.name_index;
    return null;
  }
  /** Whether a channel hash is a swarm's reserved channel. */
  swarmOfChannel(channelSha256: string): Swarm | undefined { return [...this.swarms.values()].find(s => s.channel_sha256 === channelSha256); }
  private current(m: { revoked: boolean; actor_id: string; state_index: number }, kid: string): void {
    check(!m.revoked, 'revoked', 'this identity is revoked', m.state_index); check(m.actor_id === kid, 'stale_key', 'sign with the current key', m.state_index);
  }
  private keyMember(m: SwarmMember): void { check(m.tier !== 'unverified', 'tier_required', 'this operation requires a cryptographic identity'); }
  private membership(m: SwarmMember, sid: unknown): void { check(m.swarm_id === sid, 'swarm_membership', 'not a current member of this swarm', m.state_index); }
  private own(m: SwarmMember, root: unknown): void { check(root === m.member_index, 'swarm_membership', "the signed member index must be the actor's", m.member_index); }
  private liveSwarm(sid: unknown): Swarm {
    const s = this.swarms.get(sid as string); check(s, 'swarm_membership', 'unknown swarm'); check(!s!.retired, 'swarm_retired', 'an empty swarm is permanently retired', s!.roster_index); return s!;
  }
  private rosterRef(s: Swarm, q: JsonObject): void { check(q.roster_index === s.roster_index && (!('roster_hash' in q) || q.roster_hash === this.rosterHash(s.swarm_id)), 'swarm_stale', 'refresh the roster snapshot', s.roster_index); }
  /**
   * The SWARMS-1 checks of entry `i` against the state before it (throws `SwarmError` with the refusal code the service
   * would log). Base entries are checked only where the profile changes them: claims and rotations against introduced
   * keys (R12), and posts/polls in a swarm's reserved channel (R29).
   */
  validate(i: number, e: Entry): void {
    const env = e.payload.envelope, q = env.payload, kid = e.actor_kid, ts = e.ts, typ = e.type;
    if (typ === 'name.claim') {
      const m = this.member(kid);
      if (m) {
        check(m.actor_id === kid && m.claim_index === null && !m.revoked, 'key_reuse', 'an introduced key already belongs to a stable identity', m.member_index);
        check(q.ed25519 === m.ed25519 && q.x25519 === m.x25519 && q.tier === m.tier, 'stale_key', 'the claim must retain the introduced key pair and tier', m.latest_intro_index);
      }
      return;
    }
    if (typ === 'key.rotate') { const fresh = didKey(decodeU64(q.new_ed25519, 32)), m = this.member(fresh); check(!m, 'key_reuse', 'an introduced key already belongs to a stable identity', m?.member_index ?? null); return; }
    if (typ === 'post' || typ === 'poll') {
      const s = this.swarmOfChannel(q.channel_sha256 as string); if (!s) return;
      const m = this.member(kid);
      check(m && !m.revoked && m.actor_id === kid && m.swarm_id === s.swarm_id, 'swarm_membership', 'only current swarm members may publish here', m?.state_index ?? null);
      if (typ === 'post') {
        const parent = q.parent_index as number | null; check(parent !== null, 'swarm_channel', 'a swarm post replies to its formation root or a post/poll', s.form_index);
        check(this.posts.get(parent!) === s.channel_sha256, 'swarm_channel', 'parent must belong to the swarm channel', s.form_index);
      }
      return;
    }
    if (!(SWARMS_TYPES as readonly string[]).includes(typ)) return;
    const member = this.member(kid);
    if (typ !== 'agent.introduce') { check(member, 'swarm_membership', 'introduce before using a swarm'); this.current(member!, kid); }
    const m = member!;
    switch (typ) {
      case 'agent.introduce': {
        check(!this.context.serviceKids.includes(kid), 'key_reuse', 'service keys cannot introduce');
        if (q.tier === 'unverified') check(env.auth.scheme === 'shared-secret', 'tier_required', 'unverified introductions use the TLS secret gate');
        else check(didKey(decodeU64(q.ed25519, 32)) === kid, 'bad_signature', 'the introduction key must equal its signing kid');
        const named = this.keys.get(kid); if (named) this.current(named, kid);
        let expected: Identity | undefined;
        if (member) {
          this.current(member, kid); check(q.member_index === member.member_index, 'key_reuse', 'identity already has its stable introduction root', member.member_index);
          check(q.prev_intro_index === member.latest_intro_index, 'swarm_stale', 'a profile update names the latest introduction', member.latest_intro_index); expected = member;
        } else { check(q.member_index === null && q.prev_intro_index === null && q.connectable === true, 'malformed', 'an initial introduction has null root/predecessor and connectable true'); expected = named; }
        if (expected) check(q.ed25519 === expected.ed25519 && q.x25519 === expected.x25519 && q.tier === expected.tier, 'stale_key', 'profile updates cannot rotate keys or change tier', expected.state_index);
        break;
      }
      case 'swarm.form': {
        this.own(m, q.founder_member_index);
        const old = this.swarms.get(q.swarm_id as string);
        if (old) fail(old.retired ? 'swarm_retired' : 'swarm_id_taken', 'swarm ID was already formed', old.retired ? old.roster_index : old.form_index);
        check(m.swarm_id === null, 'swarm_membership', 'the founder must be a loner', m.admission_index);
        const peer = this.members.get(q.peer_member_index as number); check(peer && peer !== m, 'swarm_membership', 'formation needs two distinct introduced identities');
        check(!peer!.revoked && peer!.swarm_id === null && peer!.connectable && peer!.actor_id === q.peer_actor_id && peer!.latest_intro_index === q.peer_intro_index, 'swarm_stale', 'the selected loner changed or withdrew pairing consent', peer!.state_index);
        if (q.code_hash !== null) check(m.code_hash === q.code_hash && peer!.code_hash === q.code_hash, 'swarm_stale', 'both founders must publish this rendezvous hash', peer!.latest_intro_index);
        const expected = q.code_hash !== null ? codeSwarmId(this.context.origin, q.code_hash as string) : swarmId(this.context.origin, m.member_index, env.protected.nonce);
        check(q.swarm_id === expected, 'digest_mismatch', 'the swarm ID must derive from the signed nonce or rendezvous hash');
        check(q.channel_sha256 === channelHash(expected), 'swarm_channel', 'the formation must use its deterministic swarm channel');
        break;
      }
      case 'swarm.join': {
        const s = this.liveSwarm(q.swarm_id); this.own(m, q.member_index);
        check(m.swarm_id === null, 'swarm_membership', 'leave the current swarm before joining', m.admission_index);
        const peer = this.members.get(q.target_member_index as number);
        check(peer && peer !== m && peer.swarm_id === q.swarm_id, 'swarm_stale', 'the selected peer is no longer a member', peer?.state_index ?? null);
        this.rosterRef(s, q);
        for (const x of [...s.ejections].reverse()) check(!(x.member_index === m.member_index && ts < x.until), 'swarm_ejected', 'the 24-hour rejoin exclusion is still in force', x.resolve_index);
        break;
      }
      case 'swarm.leave':
        this.membership(m, q.swarm_id); this.own(m, q.member_index);
        check(q.admission_index === m.admission_index, 'swarm_stale', 'leave names the current admission', m.admission_index); break;
      case 'swarm.propose': {
        this.keyMember(m); this.membership(m, q.swarm_id); const s = this.liveSwarm(q.swarm_id); this.rosterRef(s, q);
        if (q.kind === 'name') check(q.base_name_index === s.name_index, 'swarm_stale', 'the name proposal has an obsolete base', s.name_index);
        else { const t = this.members.get(q.target_member_index as number); check(t && t !== m && t.swarm_id === q.swarm_id, 'swarm_membership', 'an eject proposal names another current member', s.roster_index); }
        break;
      }
      case 'swarm.vote': case 'swarm.resolve': {
        this.keyMember(m);
        const p = this.proposals.get(q.proposal_index as number); check(p && p.index < i, 'malformed', 'proposal_index names no earlier accepted proposal');
        check(p!.resolution === null, 'swarm_proposal_closed', 'the proposal is already resolved', p!.resolution);
        const stale = this.stale(p!), s = this.swarms.get(p!.swarm_id)!;
        if (typ === 'swarm.vote') {
          check(ts < p!.closes, 'swarm_proposal_closed', 'voting deadline reached', p!.index); check(stale === null, 'swarm_stale', 'the proposal snapshot is stale', stale);
          check(p!.electorate.includes(m.member_index), 'swarm_membership', 'not an eligible member of this proposal', s.roster_index);
          check(!p!.votes.has(m.member_index), 'already_voted', 'votes are immutable');
        } else {
          const { yes, no } = this.counts(p!);
          if (stale === null) check(ts >= p!.closes, 'swarm_proposal_open', 'a non-stale result waits for the deadline', p!.index);
          const outcome = stale !== null ? 'stale' : majority(yes, no);
          check(q.outcome === outcome && q.yes === yes && q.no === no && q.electorate === p!.electorate.length, 'swarm_result', `the resolution must be the deterministic votes-cast result (${outcome} ${yes}/${no} of ${p!.electorate.length})`, p!.index);
        }
        break;
      }
      case 'swarm.grant': {
        this.keyMember(m); this.membership(m, q.swarm_id);
        check(q.owner_kid === kid, 'swarm_membership', 'only a recipient grants consent'); check(q.admission_index === m.admission_index, 'swarm_stale', 'the grant binds the current admission', m.admission_index);
        const prev = this.grants.get(kid + '\n' + q.swarm_id); check(q.prev_grant_index === (prev ? prev.index : null), 'stale_grant', 'link the latest swarm grant', prev?.index ?? null);
        break;
      }
      case 'swarm.broadcast': {
        this.keyMember(m); this.membership(m, q.swarm_id); const s = this.liveSwarm(q.swarm_id); this.rosterRef(s, q);
        const targets = this.audience(s.swarm_id, kid, ts).filter(r => r.selected).map(r => r.actor_id).sort(asciiOrder);
        check(targets.length, 'swarm_empty_audience', 'no other member currently consents', s.roster_index);
        check(q.recipient_count === targets.length && q.audience_hash === audienceHash(targets), 'swarm_stale', 'the audience commitment must equal all current eligible recipients', s.roster_index);
        break;
      }
      case 'swarm.delivery': {
        this.keyMember(m);
        const b = this.broadcasts.get(q.broadcast_index as number); check(b && b.index < i, 'malformed', 'broadcast_index names no earlier accepted broadcast');
        check(ts < b!.closes, 'swarm_broadcast_closed', 'broadcast deadline reached', b!.index);
        const prev = b!.deliveries.get(q.to_kid as string); check(prev === undefined, 'swarm_duplicate_delivery', 'this target already has a delivery', prev ?? null);
        check(kid === b!.sender && m.swarm_id === b!.swarm_id && m.admission_index === b!.admission_index, 'swarm_stale', 'the sender keeps the start key and admission', m.state_index);
        const target = b!.recipients.find(r => r.actor_id === q.to_kid && r.selected); check(target, 'swarm_membership', 'the recipient is not in the committed target set', b!.index);
        const r = this.members.get(target!.member_index)!;
        check(r.actor_id === q.to_kid && r.swarm_id === b!.swarm_id && r.admission_index === target!.admission_index, 'swarm_stale', 'the recipient keeps the start key and admission', r.state_index);
        check(q.to_key_leaf_index === r.key_leaf_index, 'stale_key', "the delivery names the recipient's current encryption-key leaf", r.key_leaf_index);
        const g = this.grants.get(q.to_kid + '\n' + b!.swarm_id); check(g && q.grant_index === g.index, 'stale_grant', 'the delivery names the current swarm grant', g?.index ?? null);
        const reason = this.grantReason(r, b!.swarm_id, ts); check(reason === null, reason === 'grant_exhausted' ? 'grant_exhausted' : 'no_consent', 'the recipient grant does not permit this delivery', g!.index);
        break;
      }
    }
  }
  /** Apply an entry already found valid (the server's `Replay.apply`); every entry of the prefix passes through here in order. */
  apply(i: number, e: Entry): void {
    const typ = e.type, actor = e.actor_kid, ts = e.ts, q = e.payload.envelope.payload;
    switch (typ) {
      case 'name.claim': {
        const id: Identity = { actor_id: actor, ed25519: q.ed25519 as string | null, x25519: q.x25519 as string | null, tier: q.tier as string, revoked: false, claim_index: i, key_events: [i], key_leaf_index: i, name: q.name_norm as string, state_index: i };
        this.names.set(id.name!, id); this.keys.set(actor, id);
        const m = this.member(actor); if (m) { Object.assign(m, { ...id, key_events: [...id.key_events] }); id.member_index = m.member_index; }
        break;
      }
      case 'key.rotate': case 'key.revoke': case 'x25519.rotate': {
        const id = this.names.get(q.name_norm as string); if (!id) break;
        const m = this.member(id.actor_id); id.key_events = [...id.key_events, i];
        if (typ === 'key.revoke') { Object.assign(id, { revoked: true, state_index: i }); if (m) this.detach(m, i); }
        else if (typ === 'key.rotate') {
          const fresh = didKey(decodeU64(q.new_ed25519, 32)); Object.assign(id, { actor_id: fresh, ed25519: q.new_ed25519, tier: q.new_tier, state_index: i });
          if (q.new_x25519 !== null) Object.assign(id, { x25519: q.new_x25519, key_leaf_index: i });
          this.keys.set(fresh, id);
          if (m) { this.actors.set(fresh, m.member_index); if (m.swarm_id) this.swarms.get(m.swarm_id)!.roster_index = i; }
        } else Object.assign(id, { x25519: q.new_x25519, key_leaf_index: i });
        if (m) { const { member_index: _mi, ...rest } = id; Object.assign(m, { ...rest, key_events: [...id.key_events] }); }
        break;
      }
      case 'agent.introduce': {
        let m: SwarmMember;
        if (q.member_index === null) {
          const id = this.keys.get(actor);
          m = { member_index: i, latest_intro_index: i, profile_index: i, actor_id: actor, tier: q.tier as string, ed25519: q.ed25519 as string | null, x25519: q.x25519 as string | null, key_leaf_index: i, claim_index: null, key_events: [], name: null, revoked: false, swarm_id: null, admission_index: null, state_index: i, code_hash: null, connectable: true };
          if (id) { const { member_index: _mi, ...rest } = id; Object.assign(m, { ...rest, key_events: [...id.key_events] }); id.member_index = i; for (const [k, v] of this.keys) if (v === id) this.actors.set(k, i); }
          this.members.set(i, m); this.actors.set(actor, i);
        } else m = this.members.get(q.member_index as number)!;
        Object.assign(m, { latest_intro_index: i, code_hash: q.code_hash, connectable: q.connectable, profile_index: i, state_index: i });
        break;
      }
      case 'swarm.form': {
        const sid = q.swarm_id as string;
        this.swarms.set(sid, { swarm_id: sid, form_index: i, roster_index: i, name_index: i, name_body_index: i, name_hash: q.title_sha256 as string, channel: channelSlug(sid), channel_sha256: q.channel_sha256 as string, code_hash: q.code_hash as string | null, retired: false, ejections: [] });
        for (const root of [q.founder_member_index, q.peer_member_index] as number[]) Object.assign(this.members.get(root)!, { swarm_id: sid, admission_index: i, state_index: i });
        this.posts.set(i, q.channel_sha256 as string); break;
      }
      case 'swarm.join': Object.assign(this.members.get(q.member_index as number)!, { swarm_id: q.swarm_id, admission_index: i, state_index: i }); this.swarms.get(q.swarm_id as string)!.roster_index = i; break;
      case 'swarm.leave': this.detach(this.members.get(q.member_index as number)!, i); break;
      case 'swarm.propose':
        this.proposals.set(i, { ...q, index: i, votes: new Map(), resolution: null, electorate: this.roster(q.swarm_id as string).filter(m => m.tier !== 'unverified').map(m => m.member_index) } as unknown as Proposal); break;
      case 'swarm.vote': this.proposals.get(q.proposal_index as number)!.votes.set(this.actors.get(actor)!, q.choice as 'yes' | 'no'); break;
      case 'swarm.resolve': {
        const p = this.proposals.get(q.proposal_index as number)!, s = this.swarms.get(p.swarm_id)!; p.resolution = i;
        if (q.outcome === 'passed') {
          if (p.kind === 'name') Object.assign(s, { name_index: i, name_body_index: p.index, name_hash: p.name_hash });
          else { const root = p.target_member_index as number; this.detach(this.members.get(root)!, i); s.ejections.push({ member_index: root, resolve_index: i, until: ts + 86400 }); }
        }
        break;
      }
      case 'swarm.grant': this.grants.set(actor + '\n' + q.swarm_id, { index: i, swarm_id: q.swarm_id as string, owner_kid: actor, admission_index: q.admission_index as number, max: q.max as number, expires: q.expires as number, used: 0 }); break;
      case 'swarm.broadcast': {
        const m = this.member(actor)!;
        this.broadcasts.set(i, { index: i, swarm_id: q.swarm_id as string, roster_index: q.roster_index as number, closes: q.closes as number, recipient_count: q.recipient_count as number, audience_hash: q.audience_hash as string, sender: actor, admission_index: m.admission_index, recipients: this.audience(q.swarm_id as string, actor, ts), deliveries: new Map() });
        break;
      }
      case 'swarm.delivery': {
        const b = this.broadcasts.get(q.broadcast_index as number)!; b.deliveries.set(q.to_kid as string, i);
        this.grants.get(q.to_kid + '\n' + b.swarm_id)!.used += 1; this.deliveries.set(i, { ...q, index: i }); break;
      }
      case 'post': case 'poll': this.posts.set(i, q.channel_sha256 as string); break;
    }
  }
  /** R16: derived selectability (members always, loners only while their pairing preference is true, revoked never). */
  connectable(m: SwarmMember): boolean { return !m.revoked && (m.swarm_id !== null || m.connectable); }
  /** `GET /v2/agents/{member_index}` without paging or checkpoint (R08). */
  agentInfo(memberIndex: number): JsonObject | null {
    const m = this.members.get(memberIndex); if (!m) return null;
    return { member_index: m.member_index, first_intro_index: m.member_index, latest_intro_index: m.latest_intro_index, actor_id: m.actor_id, tier: m.tier, claim_index: m.claim_index, key_event_indices: [...m.key_events], swarm_id: m.swarm_id, admission_index: m.admission_index, connectable: this.connectable(m) };
  }
  /** `GET /v2/swarms/{swarm_id}` without paging or checkpoint: roster, revision and hash, names, unresolved proposals, ejections. */
  swarmInfo(sid: string): JsonObject | null {
    const s = this.swarms.get(sid); if (!s) return null;
    return { swarm_id: sid, form_index: s.form_index, roster_index: s.roster_index, roster_hash: this.rosterHash(sid), name_index: s.name_index, name_body_index: s.name_body_index, name_hash: s.name_hash, channel: s.channel, channel_sha256: s.channel_sha256,
      members: this.roster(sid).map(m => ({ member_index: m.member_index, actor_id: m.actor_id, tier: m.tier, admission_index: m.admission_index })),
      proposal_indices: [...this.proposals.values()].filter(p => p.swarm_id === sid && p.resolution === null).map(p => p.index).sort((a, b) => a - b),
      ejections: s.ejections.map(x => ({ ...x })), retired: s.retired };
  }
  /** R15: the newest 100 distinct roots, newest first. */
  arrivalWindow(): number[] { return [...this.members.keys()].sort((a, b) => b - a).slice(0, 100); }
  private bodyJson(index: number, entries: readonly Entry[], bodies: BodyLookup, tombstones?: ReadonlyMap<number, number>): { value: JsonObject | null; status: 'available' | 'unavailable' | 'tombstoned' } {
    if (tombstones?.has(index)) return { value: null, status: 'tombstoned' };
    const q = entries[index]?.payload.envelope.payload, hash = q?.body_hash as string | undefined, raw = hash ? bodies(hash) : null;
    if (!raw || hexH(raw) !== hash) return { value: null, status: 'unavailable' };
    try { const v = parseJson(raw); return isObject(v) ? { value: v, status: 'available' } : { value: null, status: 'unavailable' }; } catch { return { value: null, status: 'unavailable' }; }
  }
  /**
   * R15-R16 discovery over the window: ASCII-only case folding, `q` a substring of the model, a keyword or the swarm
   * name, exact `model`/`keyword`/`swarm_name` filters, AND-combined, then rows strictly below `before_intro_index` (all
   * of them, unpaged). Bodies come from `bodies` and are hash-checked; an unavailable body matches no nonempty predicate.
   * Pass `history.tombstones` to report hidden bodies as `tombstoned` (they never match, never revive an older name).
   */
  arrivals(entries: readonly Entry[], bodies: BodyLookup, search: ArrivalSearch = {}, tombstones?: ReadonlyMap<number, number>): { window_count: number; oldest_intro_index: number | null; rows: JsonObject[]; notice: string } {
    const window = this.arrivalWindow(), rows: JsonObject[] = [], q = fold(search.q ?? '');
    for (const index of window) {
      const m = this.members.get(index)!, profile = this.bodyJson(m.profile_index, entries, bodies, tombstones);
      const model = (profile.value?.model as string | undefined) ?? null, keywords = (profile.value?.keywords as string[] | undefined) ?? null;
      let name: string | null = null, nameStatus: string = 'loner';
      if (m.swarm_id) { const s = this.swarms.get(m.swarm_id)!, pub = this.bodyJson(s.name_body_index, entries, bodies, tombstones); nameStatus = pub.status; if (pub.value) name = (pub.value.name ?? pub.value.title) as string; }
      const fields = [model, name, ...(keywords ?? [])].filter((v): v is string => v !== null);
      if (q && !fields.some(v => fold(v).includes(q))) continue;
      if (search.model != null && (model === null || fold(model) !== fold(search.model))) continue;
      if (search.keyword != null && !(keywords ?? []).some(k => fold(k) === fold(search.keyword!))) continue;
      if (search.swarm_name != null && (name === null || fold(name) !== fold(search.swarm_name))) continue;
      if (search.before_intro_index != null && index >= search.before_intro_index) continue;
      rows.push({ member_index: index, latest_intro_index: m.latest_intro_index, actor_id: m.actor_id, tier: m.tier, model, keywords, profile_status: profile.status, swarm_id: m.swarm_id, swarm_name: name, swarm_name_status: nameStatus, connectable: this.connectable(m), revoked: m.revoked });
    }
    return { window_count: window.length, oldest_intro_index: window.length ? window[window.length - 1] : null, rows, notice: FLOOD_NOTICE };
  }
  /** R34 `GET /v2/swarm-broadcasts/{index}` without paging: targets, skips with reasons, progress, and a state at `now` (unauthenticated time). */
  broadcastStatus(index: number, now: number): JsonObject | null {
    const b = this.broadcasts.get(index); if (!b) return null;
    const recipients = b.recipients.map(r => ({ member_index: r.member_index, actor_id: r.actor_id, selected: r.selected, exclusion: r.exclusion, delivery_index: b.deliveries.get(r.actor_id) ?? null }));
    const delivered = b.deliveries.size, complete = delivered === b.recipient_count;
    return { broadcast_index: index, audience_mode: 'all', recipient_count: b.recipient_count, excluded_count: recipients.length - b.recipient_count, delivered_count: delivered, remaining_count: b.recipient_count - delivered, recipients,
      state: complete ? 'complete' : now < b.closes ? 'pending' : 'expired_partial', complete_index: complete ? Math.max(...b.deliveries.values()) : null, evaluated_at: now };
  }
  /** R35 inbox: the ordered valid deliveries to `ownerKid` from index `from` on, whatever the recipient's membership now. */
  inbox(ownerKid: string, from = 0): { index: number; broadcast_index: number }[] {
    return [...this.deliveries.values()].filter(d => d.to_kid === ownerKid && d.index >= from).sort((a, b) => a.index - b.index).map(d => ({ index: d.index, broadcast_index: d.broadcast_index as number }));
  }
  /** R39 rendezvous lookup: join an existing code swarm, pair two waiting loners, or wait; a retired code swarm stays retired. */
  rendezvous(codeHash: string, requester: number | null = null): JsonObject {
    const sid = codeSwarmId(this.context.origin, codeHash), s = this.swarms.get(sid);
    if (s) { const targets = this.roster(sid).map(m => m.member_index).filter(i => i !== requester); return { code_hash: codeHash, swarm_id: sid, target_member_index: targets[0] ?? null, state: s.retired ? 'retired' : 'join' }; }
    const loners = [...this.members.values()].filter(m => m.swarm_id === null && this.connectable(m) && m.code_hash === codeHash).map(m => m.member_index).sort((a, b) => a - b);
    const targets = loners.filter(i => i !== requester), pair = requester === null ? loners.length >= 2 : loners.includes(requester) && targets.length > 0;
    return { code_hash: codeHash, swarm_id: null, target_member_index: targets[0] ?? null, state: pair ? 'pair' : 'waiting' };
  }
  /** The verified outer context a recipient compares the inner header of delivery `index` with (R35). */
  deliveryContext(index: number, entries: readonly Entry[]): DeliveryHeader {
    const d = this.deliveries.get(index); check(d, 'malformed', `entry ${index} is no accepted swarm delivery`);
    const b = this.broadcasts.get(d!.broadcast_index as number)!, e = entries[index];
    return { from_kid: e.actor_kid, to_kid: d!.to_kid as string, envelope_nonce: e.payload.envelope.protected.nonce, swarm_id: b.swarm_id, broadcast_index: b.index, membership_index: b.roster_index };
  }
  /** R35 for one delivery: its replayed context, the ciphertext commitment, the local sealed-box opening and the header. */
  openDelivery(index: number, entries: readonly Entry[], ciphertext: Uint8Array, recipientSecret: Uint8Array): { header: DeliveryHeader; text: string } {
    return openDelivery(ciphertext, recipientSecret, { metadata: entries[index].payload.envelope.payload, expected: this.deliveryContext(index, entries) });
  }
}

// --- payload builders --------------------------------------------------------------------------------------------
/** An initial `agent.introduce` `Q` and its body for a key-tier identity (sign it with the key whose did:key is `ed25519`). */
export function introducePayload(o: { model: string; keywords: readonly string[]; ed25519: Uint8Array; x25519: Uint8Array; tier?: string; code_hash?: string | null; member?: { member_index: number; latest_intro_index: number }; connectable?: boolean }): { q: JsonObject; body: Uint8Array } {
  const body = profileBody(o.model, o.keywords), tier = o.tier ?? 'verified'; check((KEY_TIERS as readonly string[]).includes(tier), 'malformed', 'a key tier');
  return { body, q: { member_index: o.member?.member_index ?? null, prev_intro_index: o.member?.latest_intro_index ?? null, ed25519: b64u(o.ed25519), x25519: b64u(o.x25519), tier, body_hash: hexH(body), size: body.length, code_hash: o.code_hash ?? null, connectable: o.member ? o.connectable ?? true : true } };
}
/**
 * A `swarm.form` `Q` and body for founder → loner `peer` (R18, R28). `nonce` is the formation envelope's nonce, fixed
 * before signing; with `code_hash` the swarm ID is the code's (R39) and both founders' latest introductions must carry it.
 */
export function formPayload(o: { origin: string; nonce: string; founder_member_index: number; peer: { member_index: number; actor_id: string; latest_intro_index: number }; title: string; text: string; code_hash?: string | null }): { q: JsonObject; body: Uint8Array; swarm_id: string; channel: string } {
  const code = o.code_hash ?? null, sid = code !== null ? codeSwarmId(o.origin, code) : swarmId(o.origin, o.founder_member_index, o.nonce), body = formationBody(sid, o.title, o.text);
  return { swarm_id: sid, channel: channelSlug(sid), body, q: { swarm_id: sid, founder_member_index: o.founder_member_index, peer_member_index: o.peer.member_index, peer_actor_id: o.peer.actor_id, peer_intro_index: o.peer.latest_intro_index, code_hash: code, channel_sha256: channelHash(sid), body_hash: hexH(body), size: body.length, title_sha256: hexH(utf8(o.title)) } };
}
/** A name `swarm.propose` `Q` and body against the current roster snapshot and base name (R23). */
export function nameProposalPayload(o: { swarm_id: string; roster_index: number; roster_hash: string; base_name_index: number; name: string; closes: number }): { q: JsonObject; body: Uint8Array } {
  const body = nameBody(o.name);
  return { body, q: { swarm_id: o.swarm_id, kind: 'name', roster_index: o.roster_index, roster_hash: o.roster_hash, base_name_index: o.base_name_index, body_hash: hexH(body), size: body.length, name_hash: hexH(utf8(o.name)), closes: o.closes } };
}
/** An eject `swarm.propose` `Q` (R21, R23). */
export const ejectProposalPayload = (o: { swarm_id: string; roster_index: number; roster_hash: string; target_member_index: number; closes: number }): JsonObject => ({ swarm_id: o.swarm_id, kind: 'eject', roster_index: o.roster_index, roster_hash: o.roster_hash, target_member_index: o.target_member_index, closes: o.closes });
/** `swarm.join`, `swarm.leave`, `swarm.vote`, `swarm.grant` `Q` (R19, R20, R24, R30); `max: 0` closes a grant. */
export const joinPayload = (o: { swarm_id: string; member_index: number; target_member_index: number; roster_index: number }): JsonObject => ({ ...o });
export const leavePayload = (o: { swarm_id: string; member_index: number; admission_index: number }): JsonObject => ({ ...o });
export const votePayload = (proposal_index: number, choice: 'yes' | 'no'): JsonObject => ({ proposal_index, choice });
export const swarmGrantPayload = (o: { swarm_id: string; owner_kid: string; admission_index: number; max: number; expires: number; prev_grant_index: number | null }): JsonObject => ({ ...o });
/** The SWARMS-1 member of an assurance card, for card checks (R47). */
export const swarmsCardMemberProblems = (v: Json): string[] => canonicalText(v ?? null) === canonicalText(SWARMS_CARD_MEMBER) ? [] : [`$.swarms: must be exactly ${canonicalText(SWARMS_CARD_MEMBER)}`];

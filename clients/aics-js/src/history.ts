/**
 * AICS-1 §14.3 step 2: a complete authenticated entry prefix replayed in index order, each entry judged against the
 * state immediately before its index (§7.3): entry schemas and envelope signatures (§5), acceptance-time freshness
 * and nonce uniqueness (§4.3), per-key sequences (§4.2), name claims, rotations, revocations and encryption-key
 * rotations (§7), consent grants and capacity (§9), recipient key provenance (§7.3), tombstone targets (§10.3), the
 * policy chain from the dual-signed charter at leaf 0 (§6.4) and the pinned service keys as administrative actors.
 * Under AICS-1+SUP-1 the tasks, awards, owner actions, contributions and balances are replayed too (§20.9), while a
 * contribution's on-chain check stays unproven (its transaction is off-leaf). Swarms entries are not interpreted.
 */
import { concat, decodeU64, hexH, utf8 } from './bytes.js';
import { canonicalize, type JsonObject } from './canonical.js';
import { envelopeHash, type Envelope } from './envelope.js';
import { entryHash, parseEntry, validateEntry, type Entry } from './entry.js';
import { didKey, parseDidKey, verify } from './keys.js';
import { parseVkey } from './note.js';
import { KEY_TIERS, POLICY_ACTOR_TYPES, supAssetDescriptor } from './registry.js';
import { verifySshsig } from './sshsig.js';
export type HistoryTrust = { origin: string; log_vkey: string; policy_kid: string; owner_kid: string };
export type HistoryOptions = { trust: HistoryTrust; profiles?: readonly string[]; secretIds?: readonly string[] };
export class HistoryError extends Error { constructor(readonly index: number, message: string) { super(`entry ${index}: ${message}`); this.name = 'HistoryError'; } }
type NameState = { kid: string; x: string | null; keyIndex: number; event: number; revoked: boolean; name: string; tier: string };
type GrantState = { index: number; ts: number; max: number; expires: number; sender_kid: string };
type OwnerAction = { action: string; request_hash: string; amount: number; requester: string | null };
/** A §7.1 proof `{scheme, signature}` over `data` by `pub` (raw Ed25519, or a complete SSHSIG blob, namespace aics). */
export function verifyProof(proof: JsonObject, pub: Uint8Array, data: Uint8Array): boolean {
  try {
    const sig = decodeU64(proof.signature);
    if (proof.scheme === 'ed25519') return verify(sig, data, pub);
    if (proof.scheme === 'sshsig') { verifySshsig(sig, data, pub); return true; }
  } catch { /* refused below */ }
  return false;
}
/** §7.2: the bytes both rotation proofs sign, `UTF8("AICS-1 key.rotate\n") || J(R)`. */
export const rotationBytes = (r: JsonObject): Uint8Array => concat(utf8('AICS-1 key.rotate\n'), canonicalize(r));
/** §7.1: the bytes `recovery_pop` signs. */
export const recoveryDeclaration = (r: { origin: string; name_norm: string; ed25519: string; x25519: string; recovery_kid: string }): Uint8Array => concat(utf8('AICS-1 recovery-declaration\n'), canonicalize(r));
/** §6.4: the bytes the log key countersigns in the charter, `UTF8("AICS-1 policy\n") || J(Q without log_sig)`. */
export const charterBytes = (q: JsonObject): Uint8Array => { const { log_sig: _s, ...rest } = q; return concat(utf8('AICS-1 policy\n'), canonicalize(rest)); };
export class History {
  readonly entries: Entry[] = [];
  readonly names = new Map<string, NameState>();
  readonly policyEvents: number[] = [];
  readonly tombstones = new Map<number, number>();
  readonly balances = new Map<string, number>();
  private bound = new Set<string>(); private active = new Map<string, NameState>(); private kidName = new Map<string, string>();
  private last = new Map<string, Envelope>(); private nonces = new Map<string, number>(); private grants = new Map<string, GrantState>(); private used = new Map<number, number>();
  private leafIndex = new Map<string, number>(); private tasks = new Map<number, { reward: number; max_awards: number; closes: number; awards: number[]; names: Set<string> }>();
  private awarded = new Set<number>(); private ownerActions = new Map<number, OwnerAction>(); private requests = new Map<string, { post: number; quotes: number[]; completion: number | null }>();
  private paid = new Set<number>(); private contributions = new Set<string>();
  private logKid: string; private profiles: readonly string[];
  /** Replays `rawEntries` (the complete prefix `[0, n)`, exact bytes); throws `HistoryError` at the first invalid index. */
  constructor(rawEntries: readonly Uint8Array[], readonly options: HistoryOptions) {
    this.profiles = options.profiles ?? [];
    this.logKid = didKey(parseVkey(options.trust.log_vkey).publicKey);
    rawEntries.forEach((raw, i) => {
      let e: Entry;
      try { e = validateEntry(parseEntry(raw), { origin: options.trust.origin, profiles: this.profiles, secretIds: options.secretIds, policyKid: options.trust.policy_kid }); }
      catch (err) { throw new HistoryError(i, (err as Error).message); }
      this.apply(i, e); this.entries.push(e); this.leafIndex.set(entryHash(raw), i);
    });
  }
  get size(): number { return this.entries.length; }
  /** The current state of a name after the replayed prefix, or undefined. */
  name(name: string): Readonly<NameState> | undefined { return this.names.get(name); }
  /** The name whose current signing key is `kid`, if any. */
  currentName(kid: string): string | undefined { const n = this.kidName.get(kid); return n !== undefined && this.names.get(n)?.kid === kid && !this.names.get(n)!.revoked ? n : undefined; }
  private require(i: number, ok: unknown, message: string): void { if (!ok) throw new HistoryError(i, message); }
  private apply(i: number, e: Entry): void {
    const req = (ok: unknown, m: string) => this.require(i, ok, m);
    const env = e.payload.envelope, p = env.protected, q = env.payload, kid = p.kid, typ = e.type, ts = e.ts, trust = this.options.trust;
    const secret = env.auth.scheme === 'shared-secret';
    if (secret) req(typ === 'name.claim' || typ === 'post', 'the secret tier cannot authorize this type');
    const prior = this.last.get(kid);
    req(p.seq === (prior ? prior.protected.seq + 1 : 0) && p.prev === (prior ? envelopeHash(prior) : null), 'sender sequence/predecessor');
    const nonceKey = kid + '\n' + p.nonce, until = this.nonces.get(nonceKey);
    req(until === undefined || until <= ts, 'reused nonce'); this.nonces.set(nonceKey, p.expires); this.last.set(kid, env);
    if ((POLICY_ACTOR_TYPES as readonly string[]).includes(typ)) req(kid === (typ === 'report' && q.kind === 'owner_action' ? trust.owner_kid : trust.policy_kid), 'administrative actor is not the pinned authority');
    else if (typ === 'sup.task' || (typ === 'sup.credit' && q.source === 'task')) req(kid === trust.owner_kid, 'owner-signed SUP-1 entry by another key');
    else if (typ === 'sup.credit') req(kid === trust.policy_kid, 'a contribution credit is a policy statement');
    else if (typ !== 'name.claim' && !(typ === 'key.rotate' && q.mode === 'upgrade')) req(this.active.has(kid), 'signer is not a current key at this index');
    switch (typ) {
      case 'name.claim': {
        const name = q.name_norm as string; req(!this.names.has(name) && !this.bound.has(kid), 'duplicate claim or key reuse');
        if (!secret) {
          req(didKey(decodeU64(q.ed25519, 32)) === kid && (KEY_TIERS as readonly string[]).includes(q.tier as string) && q.x25519 !== null, 'claim proof of possession/tier');
          req(![trust.policy_kid, trust.owner_kid, this.logKid].includes(kid), 'service and agent keys must be distinct');
        } else req(q.tier === 'unverified', 'unverified claim constraints');
        if (q.recovery_kid !== null) {
          const rk = q.recovery_kid as string; req(rk !== kid && ![trust.policy_kid, trust.owner_kid, this.logKid].includes(rk), 'the recovery key must be a distinct key');
          req(verifyProof(q.recovery_pop as JsonObject, parseDidKey(rk), recoveryDeclaration({ origin: e.origin, name_norm: name, ed25519: q.ed25519 as string, x25519: q.x25519 as string, recovery_kid: rk })), 'recovery proof does not verify');
        }
        const state: NameState = { kid, x: q.x25519 as string | null, keyIndex: i, event: i, revoked: false, name, tier: q.tier as string };
        this.names.set(name, state); this.active.set(kid, state); this.bound.add(kid); this.kidName.set(kid, name);
        if (q.initial_grant !== null) {
          const g = q.initial_grant as JsonObject; req(g.max === 0 || (g.expires as number) > ts, 'initial grant expiry');
          this.grants.set(kid + '\n' + g.sender_kid, { index: i, ts, max: g.max as number, expires: g.expires as number, sender_kid: g.sender_kid as string });
        }
        break;
      }
      case 'key.rotate': case 'key.revoke': case 'x25519.rotate': {
        const state = this.names.get(q.name_norm as string); req(state, 'key event for an unclaimed name');
        const upgrade = typ === 'key.rotate' && q.mode === 'upgrade';
        req(!state!.revoked && state!.event === q.prev_event_index, 'key event fork or revoked name');
        if (!upgrade) req(state!.kid === kid, 'the key event is not signed by the current key');
        if (typ === 'key.rotate') {
          const { sig_old: _a, sig_new: _b, secret_check: _c, ...rest } = q, data = rotationBytes({ ...rest, origin: e.origin });
          const fresh = decodeU64(q.new_ed25519, 32), newKid = didKey(fresh);
          req((KEY_TIERS as readonly string[]).includes(q.new_tier as string), 'a rotation cannot downgrade to the secret tier');
          if (upgrade) {
            req(state!.kid.startsWith('unverified:') && q.sig_old === null && newKid === kid && p.seq === 0 && q.new_x25519 !== null, 'invalid secret upgrade');
            req(verify(decodeU64(q.secret_check, 64), concat(utf8('AICS-1 upgrade-check\n'), canonicalize({ ...rest, origin: e.origin })), parseDidKey(trust.policy_kid)), 'upgrade secret_check does not verify');
          } else req(verifyProof(q.sig_old as JsonObject, parseDidKey(kid), data), 'sig_old does not verify');
          req(verifyProof(q.sig_new as JsonObject, fresh, data), 'sig_new does not verify'); req(!this.bound.has(newKid), 'rotation key reuse');
          this.active.delete(state!.kid); state!.kid = newKid; this.active.set(newKid, state!); this.bound.add(newKid); state!.tier = q.new_tier as string; this.kidName.set(newKid, state!.name);
          if (q.new_x25519 !== null) { state!.x = q.new_x25519 as string; state!.keyIndex = i; }
        } else if (typ === 'key.revoke') { state!.revoked = true; this.active.delete(kid); }
        else { state!.x = q.new_x25519 as string; state!.keyIndex = i; }
        state!.event = i; break;
      }
      case 'grant': {
        req(q.owner_kid === kid, 'grant ownership'); const pair = kid + '\n' + q.sender_kid, prior = this.grants.get(pair);
        req(q.prev_grant_index === (prior ? prior.index : null), 'grant predecessor'); req(q.max === 0 || (q.expires as number) > ts, 'grant expiry');
        this.grants.set(pair, { index: i, ts, max: q.max as number, expires: q.expires as number, sender_kid: q.sender_kid as string }); break;
      }
      case 'dm': case 'capsule': {
        const recipient = (typ === 'dm' ? q.to_kid : q.owner_kid) as string, state = this.active.get(recipient);
        req(state && state.keyIndex === q.to_key_leaf_index, 'recipient key provenance');
        if (typ === 'dm') {
          req(q.seq === p.seq && q.prev === p.prev, 'dm chain copy');
          const g = this.grants.get(recipient + '\n' + kid) ?? this.grants.get(recipient + '\n*');
          req(g && g.index === q.grant_index && g.max > (this.used.get(g.index) ?? 0) && g.expires > ts, 'DM without live consent');
          this.used.set(g!.index, (this.used.get(g!.index) ?? 0) + 1);
        } else req(recipient === kid, 'capsule ownership');
        break;
      }
      case 'tombstone': {
        const target = q.target_index as number; req(target < i, 'a tombstone targets an earlier entry');
        if (['dm', 'capsule'].includes(this.entries[target].type)) req(q.reason_code === 'order', 'a ciphertext tombstone reason is order');
        this.tombstones.set(target, i); break;
      }
      case 'refusal':
        if (q.attempt_kid !== null) { req(q.attempt_nonce !== null && q.attempt_expires !== null, 'partial authenticated tuple'); this.nonces.set(q.attempt_kid + '\n' + q.attempt_nonce, q.attempt_expires as number); }
        break;
      case 'policy': {
        req(q.log_kid !== q.policy_kid && q.owner_kid !== q.log_kid && q.owner_kid !== q.policy_kid, 'service key separation');
        req(q.policy_kid === trust.policy_kid && q.owner_kid === trust.owner_kid && q.log_kid === this.logKid, 'service key substitution');
        req(q.prev_policy_index === (this.policyEvents.length ? this.policyEvents[this.policyEvents.length - 1] : null), 'policy chain');
        if (!this.policyEvents.length) {
          req(i === 0 && q.kind === 'charter' && q.effective_after === 0, 'leaf 0 is the charter');
          req(q.log_sig !== null && verify(decodeU64(q.log_sig, 64), charterBytes(q), parseDidKey(q.log_kid as string)), 'the charter log countersignature does not verify');
        } else req(q.log_sig === null, 'only the charter carries log_sig');
        this.policyEvents.push(i); break;
      }
      case 'report': if (q.kind === 'owner_action') this.ownerAction(i, e, q); break;
      case 'sup.task': case 'sup.credit': case 'sup.spend': this.sup(i, e, q, kid, ts); break;
    }
  }
  private account(i: number, kid: string, what: string): string {
    const name = this.kidName.get(kid), state = name === undefined ? undefined : this.names.get(name);
    this.require(i, state && state.kid === kid && !state.revoked && (KEY_TIERS as readonly string[]).includes(state.tier), `${what} names no account (the current key of a key-tier name)`);
    return name!;
  }
  private ownerAction(i: number, e: Entry, q: JsonObject): void {
    const req = (ok: unknown, m: string) => this.require(i, ok, m), sup = this.profiles.includes('SUP-1');
    let request: { post: number; quotes: number[]; completion: number | null } | undefined, post: number | undefined;
    if (q.action === 'quote') req(q.result_hash === null && q.quote_index === null, 'quote shape');
    if (sup) {
      req(q.asset_hash === hexH(canonicalize(supAssetDescriptor(e.origin))), 'asset_hash is not the SUP asset of this origin');
      post = this.leafIndex.get(q.request_hash as string); req(post !== undefined && this.entries[post].type === 'post', 'owner action names no earlier request post');
      this.account(i, this.entries[post!].actor_kid, 'request post');
      request = this.requests.get(q.request_hash as string) ?? { post: post!, quotes: [], completion: null }; this.requests.set(q.request_hash as string, request);
      req(request.completion === null, 'owner action on a completed request');
    }
    if (q.action === 'complete') {
      const quote = this.ownerActions.get(q.quote_index as number);
      req(quote && quote.action === 'quote' && quote.request_hash === q.request_hash, 'the completion names no quote of its request');
      req(q.result_hash !== null, 'completion without result');
      if (sup) { req(q.quote_index === request!.quotes[request!.quotes.length - 1], 'the completion names an earlier quote (stale_quote)'); req(q.amount === quote!.amount, 'the completion amount differs from its quote'); request!.completion = i; }
    } else if (sup) request!.quotes.push(i);
    this.ownerActions.set(i, { action: q.action as string, request_hash: q.request_hash as string, amount: q.amount as number, requester: sup ? this.kidName.get(this.entries[post!].actor_kid) ?? null : null });
  }
  private sup(i: number, e: Entry, q: JsonObject, kid: string, ts: number): void {
    const req = (ok: unknown, m: string) => this.require(i, ok, m), typ = e.type;
    req(q.asset_hash === hexH(canonicalize(supAssetDescriptor(e.origin))), 'asset_hash is not the SUP asset of this origin');
    if (typ === 'sup.task') this.tasks.set(i, { reward: q.reward as number, max_awards: q.max_awards as number, closes: q.closes as number, awards: [], names: new Set() });
    else if (typ === 'sup.credit' && q.source === 'task') {
      const task = this.tasks.get(q.task_index as number); req(task, 'the award names no earlier task');
      const sub = q.submission_index as number; req((q.task_index as number) < sub && sub < i && this.entries[sub].type === 'post', 'the award names no later public post as the submission');
      const name = this.kidName.get(this.entries[sub].actor_kid);
      req(this.account(i, q.account_kid as string, 'award') === name, 'an award to another account than the submitting name');
      req(q.amount === task!.reward, 'the award amount differs from the reward'); req(ts < task!.closes && task!.awards.length < task!.max_awards, 'award of a closed task');
      req(!this.awarded.has(sub) && !task!.names.has(name!), 'submission or name already awarded');
      task!.awards.push(i); task!.names.add(name!); this.awarded.add(sub); this.balances.set(name!, (this.balances.get(name!) ?? 0) + (q.amount as number));
    } else if (typ === 'sup.credit') {
      req(!this.contributions.has(q.contribution_hash as string), 'contribution credited twice'); this.contributions.add(q.contribution_hash as string);
      const name = this.account(i, q.account_kid as string, 'contribution credit'); this.balances.set(name, (this.balances.get(name) ?? 0) + (q.amount as number));
    } else {
      const name = this.account(i, kid, 'spend'), amount = q.amount as number;
      req(amount >= 1 && amount <= (this.balances.get(name) ?? 0), 'spend above the balance (insufficient_balance)');
      if (q.purpose === 'owner_action') {
        const done = this.ownerActions.get(q.ref_index as number); req(done && done.action === 'complete', 'the owner-action spend names no completion');
        req(done!.requester === name, 'owner action paid by another name than the requester'); req(amount === done!.amount && q.bytes === 0, 'owner-action spend amount');
        req(!this.paid.has(q.ref_index as number), 'completion paid twice'); this.paid.add(q.ref_index as number);
      } else if (q.purpose === 'hosting') req(q.ref_index === null && q.bytes === 0, 'hosting spend shape');
      else req(q.ref_index === null && (q.bytes as number) >= 1, 'storage spend shape');
      this.balances.set(name, (this.balances.get(name) ?? 0) - amount);
    }
  }
}

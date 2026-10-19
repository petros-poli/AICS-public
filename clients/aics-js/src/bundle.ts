/**
 * AICS-1 §14.3 offline evidence. The wire bundle is exactly
 * `{entry_bytes:U64, index:uint, inclusion_proof:[B64], checkpoint_note:U64, envelope:E, body_or_ct:U64-or-null}`
 * (what `GET /v2/entries/{index}` serves); the complete verification package is exactly
 * `{bundle, trust_bundle, policy_cards:[U64], entry_prefix:[U64], checkpoint_notes:[U64]}`.
 * A bundle alone proves inclusion, the entry's form and its envelope signature; name ownership and signer authority at
 * the index need the complete authenticated history (step 2), which only a package (or a full tile scan) carries.
 */
import { decodeB64, decodeU64, equal, hexH, isUint, length } from './bytes.js';
import { hasMembers, isObject, parseCanonical, sameJson, type JsonObject } from './canonical.js';
import { cardSignatureProblems } from './card.js';
import { bodyCommitment, entryHash, entryProblems, parseEntry, type Entry } from './entry.js';
import type { Envelope } from './envelope.js';
import { History } from './history.js';
import { leafHash, merkleRoot, verifyLeafInclusion, EMPTY_HASH } from './merkle.js';
import { parseVkey, verifyNote, type Checkpoint, type VKey } from './note.js';
export const BUNDLE_MEMBERS = ['entry_bytes', 'index', 'inclusion_proof', 'checkpoint_note', 'envelope', 'body_or_ct'] as const;
export const PACKAGE_MEMBERS = ['bundle', 'trust_bundle', 'policy_cards', 'entry_prefix', 'checkpoint_notes'] as const;
export type WireBundle = { entry_bytes: string; index: number; inclusion_proof: string[]; checkpoint_note: string; envelope: Envelope; body_or_ct: string | null };
export type VerificationPackage = { bundle: WireBundle; trust_bundle: PinnedTrust; policy_cards: string[]; entry_prefix: string[]; checkpoint_notes: string[] };
export type PinnedTrust = { v: 1; origin: string; log_vkey: string; policy_kid: string; owner_kid: string; bootstrap_card_hash: string };
export class BundleError extends Error { constructor(readonly status: 'invalid' | 'incomplete', message: string) { super(`${status}: ${message}`); this.name = 'BundleError'; } }
const invalid = (ok: unknown, message: string): void => { if (!ok) throw new BundleError('invalid', message); };
export type BundleOptions = {
  /** The pinned log key (vkey); never one fetched with the bundle. */
  logKey: VKey | string;
  /** The pinned witness policy the checkpoint must meet (default: quorum 0, log signature only). */
  witnesses?: readonly (VKey | string)[]; quorum?: number;
  /** Freshness of the bundle's cosignatures (omit both for historical, archived verification). */
  now?: number; maxAgeSeconds?: number;
  /** The pinned origin (default: the log key's name). */
  origin?: string; profiles?: readonly string[]; secretIds?: readonly string[];
  /** The pinned policy kid, to verify a shared-secret entry's attestation. */
  policyKid?: string;
};
export type BundleVerification = {
  /** Steps 1, 3 and 4: checkpoint under the pinned keys and witness policy, inclusion, exact entry, envelope signature, body. */
  status: 'valid';
  /** Step 2, name ownership and signer authority through this index: `incomplete` without the complete history. */
  history: 'incomplete' | 'valid';
  /**
   * Step 3: `signature` when the envelope's own agent signature verified (possession of the kid's key, not yet name
   * ownership); a shared-secret entry is `policy-attested` (its attestation verified with `policyKid`) or
   * `attestation-unchecked` (no policy kid given): its authorship is unproven either way (§3.3, §14.3).
   */
  authorship: 'signature' | 'policy-attested' | 'attestation-unchecked';
  index: number; checkpoint: Checkpoint; checkpointNote: Uint8Array; checkpointNoteHash: string; entry: Entry; entryBytes: Uint8Array; entryHash: string;
  envelope: Envelope; body: Uint8Array | null; witnesses: string[]; freshness: 'verified' | 'unproven';
};
/** §14.3 steps 1, 3 and 4 for a wire bundle (offline). Throws `BundleError`. */
export function verifyBundle(bundle: unknown, o: BundleOptions): BundleVerification {
  invalid(hasMembers(bundle, BUNDLE_MEMBERS), `a wire bundle has exactly ${BUNDLE_MEMBERS.join(', ')}`);
  const b = bundle as JsonObject;
  invalid(isUint(b.index) && Array.isArray(b.inclusion_proof) && b.inclusion_proof.every(h => typeof h === 'string') && (b.body_or_ct === null || typeof b.body_or_ct === 'string') && isObject(b.envelope), 'wire bundle member types');
  let entryBytes: Uint8Array, note: Uint8Array, proof: Uint8Array[], body: Uint8Array | null;
  try { entryBytes = decodeU64(b.entry_bytes); note = decodeU64(b.checkpoint_note); proof = (b.inclusion_proof as string[]).map(h => length(decodeB64(h), 32)); body = b.body_or_ct === null ? null : decodeU64(b.body_or_ct); }
  catch (e) { throw new BundleError('invalid', `wire bundle encodings: ${(e as Error).message}`); }
  const log = typeof o.logKey === 'string' ? parseVkey(o.logKey) : o.logKey, origin = o.origin ?? log.name;
  const v = verifyNote(note, log, { witnesses: o.witnesses, quorum: o.quorum ?? 0, expectedOrigin: origin, ...(o.now === undefined ? {} : { now: o.now, maxAgeSeconds: o.maxAgeSeconds }) });
  invalid(v.ok, `checkpoint: ${v.reason}${v.detail ? ' (' + v.detail + ')' : ''}`);
  const cp = v.checkpoint!; invalid(cp.size > 0 || equal(cp.root, EMPTY_HASH), 'checkpoint: wrong empty root');
  invalid(verifyLeafInclusion(entryBytes, b.index as number, cp.size, proof, cp.root), 'inclusion proof does not verify against the checkpoint');
  let entry: Entry; try { entry = parseEntry(entryBytes); } catch (e) { throw new BundleError('invalid', (e as Error).message); }
  const problems = entryProblems(entry, { origin, profiles: o.profiles, secretIds: o.secretIds, policyKid: o.policyKid });
  invalid(!problems.length, `entry: ${problems.join('; ')}`);
  invalid(sameJson(b.envelope, entry.payload.envelope), 'the bundle envelope differs from the embedded envelope');
  if (body !== null) {
    const c = bodyCommitment(entry.payload.envelope.payload);
    invalid(c && hexH(body) === c.hash && body.length === c.size, 'the body does not match the entry commitment (hash and size)');
  }
  const authorship = entry.payload.envelope.auth.scheme !== 'shared-secret' ? 'signature' : o.policyKid ? 'policy-attested' : 'attestation-unchecked';
  return { status: 'valid', history: 'incomplete', authorship, index: b.index as number, checkpoint: cp, checkpointNote: note, checkpointNoteHash: hexH(note), entry, entryBytes, entryHash: entryHash(entryBytes), envelope: entry.payload.envelope, body, witnesses: v.counted, freshness: o.now !== undefined && (o.quorum ?? 0) > 0 && o.maxAgeSeconds !== undefined ? 'verified' : 'unproven' };
}
export type PackageVerification = BundleVerification & { history: 'valid'; replay: History; savedCheckpoints: Checkpoint[] };
/**
 * §14.3 complete verification package, historically and with no I/O: exactly the five members; its trust bundle equal
 * to the independently pinned one (a package never supplies trust); the bundle; the entry prefix reconstructing the
 * checkpoint root with the bundle's entry at its index; the complete history replayed (step 2); every saved checkpoint
 * log-signed and agreeing with the prefix; every saved card canonical, logged by a policy entry and signed by the
 * pinned policy key. Throws `BundleError`.
 */
export function verifyPackage(pkg: unknown, o: { trust: PinnedTrust; witnesses?: readonly (VKey | string)[]; quorum?: number; profiles?: readonly string[]; secretIds?: readonly string[] }): PackageVerification {
  invalid(hasMembers(pkg, PACKAGE_MEMBERS), `a verification package has exactly ${PACKAGE_MEMBERS.join(', ')}`);
  const p = pkg as JsonObject;
  invalid(sameJson(p.trust_bundle, o.trust), 'the package trust bundle differs from the independently pinned one');
  for (const k of ['policy_cards', 'entry_prefix', 'checkpoint_notes'] as const) invalid(Array.isArray(p[k]) && (p[k] as unknown[]).every(x => typeof x === 'string'), `package ${k} must be an array of U64 strings`);
  const t = o.trust;
  const b = verifyBundle(p.bundle, { logKey: t.log_vkey, witnesses: o.witnesses, quorum: o.quorum, origin: t.origin, profiles: o.profiles, secretIds: o.secretIds, policyKid: t.policy_kid });
  let prefix: Uint8Array[]; try { prefix = (p.entry_prefix as string[]).map(x => decodeU64(x)); } catch { throw new BundleError('invalid', 'entry_prefix encodings'); }
  if (prefix.length !== b.checkpoint.size) throw new BundleError('incomplete', `the entry prefix has ${prefix.length} entries, the checkpoint ${b.checkpoint.size}`);
  const leaves = prefix.map(leafHash);
  invalid(equal(merkleRoot(leaves), b.checkpoint.root), 'the entry prefix does not reconstruct the checkpoint root');
  invalid(equal(prefix[b.index], b.entryBytes), 'the bundle entry differs from the prefix entry at its index');
  let replay: History; try { replay = new History(prefix, { trust: t, profiles: o.profiles, secretIds: o.secretIds }); } catch (e) { throw new BundleError('invalid', `history: ${(e as Error).message}`); }
  invalid(replay.policyEvents[0] === 0, 'leaf 0 of the prefix is not the charter (§6.1)');
  const saved: Checkpoint[] = [];
  for (const raw of p.checkpoint_notes as string[]) {
    let note: Uint8Array; try { note = decodeU64(raw); } catch { throw new BundleError('invalid', 'checkpoint_notes encodings'); }
    const v = verifyNote(note, t.log_vkey, { witnesses: o.witnesses, quorum: 0, expectedOrigin: t.origin });
    invalid(v.logOk, `a saved checkpoint is not log-signed evidence (${v.reason})`);
    if (v.checkpoint!.size > prefix.length) throw new BundleError('incomplete', 'a saved checkpoint is beyond the package prefix');
    invalid(equal(merkleRoot(leaves.slice(0, v.checkpoint!.size)), v.checkpoint!.root), 'split-proven: a saved checkpoint conflicts with the authenticated package prefix');
    saved.push(v.checkpoint!);
  }
  if (!(p.policy_cards as string[]).length) throw new BundleError('incomplete', 'missing policy cards');
  for (const raw of p.policy_cards as string[]) {
    let bytes: Uint8Array, card: JsonObject;
    try { bytes = decodeU64(raw); card = parseCanonical(bytes, 'saved card') as JsonObject; } catch (e) { throw new BundleError('invalid', (e as Error).message); }
    invalid(replay.entries.some(e => e.type === 'policy' && e.payload.document_hash === hexH(bytes)), 'a saved card is not logged in the prefix');
    const problems = cardSignatureProblems(card, t.policy_kid); invalid(!problems.length, `saved card: ${problems.join('; ')}`);
  }
  return { ...b, history: 'valid', replay, savedCheckpoints: saved };
}

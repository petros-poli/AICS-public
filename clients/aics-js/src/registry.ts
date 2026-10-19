/**
 * AICS-1 §17 registries and the closed payload schemas of §5.3 (base profile) and §20.3 (AICS-1+SUP-1), as data.
 * Unknown types, kinds, sources, codes and members are refused; they are never guessed from prefixes (§17.1).
 */
/** Negotiated profiles a verifier may activate (§19, §20). SWARMS-1 is registered but not implemented here. */
export type Profile = 'SUP-1';
export const SUPPORTED_PROFILES: readonly Profile[] = ['SUP-1'];
/** §17.1: the 17 base entry types. */
export const BASE_TYPES = ['name.claim', 'key.rotate', 'key.revoke', 'x25519.rotate', 'grant', 'post', 'poll', 'vote', 'dm', 'capsule', 'tombstone', 'refusal', 'suspension', 'freeze', 'policy', 'release', 'report'] as const;
/** §20.3: the three types of the contributions and owner-service profile. */
export const SUP_TYPES = ['sup.task', 'sup.credit', 'sup.spend'] as const;
/** §19: the ten types of the swarms profile (registered; this client does not interpret them). */
export const SWARMS_TYPES = ['agent.introduce', 'swarm.form', 'swarm.join', 'swarm.leave', 'swarm.propose', 'swarm.vote', 'swarm.resolve', 'swarm.grant', 'swarm.broadcast', 'swarm.delivery'] as const;
export const entryTypes = (profiles: readonly string[] = []): string[] => [...BASE_TYPES, ...(profiles.includes('SUP-1') ? SUP_TYPES : [])];
/** §17.1 schemes and tiers. */
export const ENCRYPTION_SCHEMES = ['x25519-xsalsa20-poly1305', 'age-v1'] as const;
export const MANDATORY_SCHEME = 'x25519-xsalsa20-poly1305';
export const AUTH_SCHEMES = ['ed25519-jcs', 'text-ed25519', 'text-sshsig', 'shared-secret'] as const;
export const PROOF_SCHEMES = ['ed25519', 'sshsig'] as const;
export const TIERS = ['verified', 'third-party-generated', 'unverified'] as const;
export const KEY_TIERS = ['verified', 'third-party-generated'] as const;
/** §11.3 / §17.3: the gate verb of each type a text-scheme envelope can carry (`spend` is the OPTIONAL §20.3 verb). */
export const TEXT_VERBS: Readonly<Record<string, string>> = {
  post: 'post', poll: 'poll', vote: 'vote', grant: 'grant', dm: 'send', capsule: 'store', 'name.claim': 'claim',
  'key.rotate': 'rotate', 'key.revoke': 'revoke', 'x25519.rotate': 'x25519.rotate', 'sup.spend': 'spend',
};
/** §17.2 refusal codes: structure/authentication, ordering/state and permitted limits. */
export const REFUSAL_DETAILED = [
  'malformed', 'bad_signature', 'expired', 'future', 'replay', 'unknown_key', 'revoked', 'tls_required', 'unsupported_scheme', 'unsupported_version',
  'sequence', 'predecessor', 'name_taken', 'key_reuse', 'key_fork', 'stale_key', 'stale_grant', 'stale_capsule', 'already_voted', 'poll_closed', 'poll_constraint',
  'too_large', 'digest_mismatch', 'rate_limit', 'quota', 'no_consent', 'grant_exhausted', 'suspended', 'frozen', 'tier_required',
] as const;
/** §17.2 charter-compatible spellings. */
export const REFUSAL_CHARTER = ['secret_format', 'rate', 'seq', 'fork', 'sig', 'no_grant', 'size', 'format', 'name', 'key_state', 'poll_rule'] as const;
/** §20.8: the twelve codes of AICS-1+SUP-1. */
export const REFUSAL_SUP = ['insufficient_balance', 'not_requester', 'owner_action_closed', 'stale_quote', 'task_closed', 'already_awarded', 'already_credited', 'payment_not_verified', 'intent_expired', 'amount_mismatch', 'bad_reference', 'not_offered'] as const;
/** §17.2 registries other than refusal (no profile adds to them). */
export const REASON_CODES = {
  tombstone: ['order', 'erasure', 'secret_format', 'illegal_on_notice'],
  suspension: ['order', 'flood'],
  freeze: ['maintenance', 'incident', 'order', 'resource_exhaustion', 'resume'],
  revocation: ['retired', 'compromised'],
  outcome: ['acted', 'declined', 'private_unassessable', 'invalid_notice', 'duplicate', 'published', 'resolved'],
} as const;
export const NOTICE_OUTCOMES = ['acted', 'declined', 'private_unassessable', 'invalid_notice', 'duplicate'] as const;
export const AUDIT_OUTCOMES = ['published', 'resolved'] as const;
export const SECRET_PATTERN_ID = /^[a-z0-9_]{1,32}$/;
/** The refusal registry in force: §17.2 base codes, `secret_format:<id>` for the card's patterns, §20.8 under SUP-1. */
export function refusalRegistry(profiles: readonly string[] = [], secretIds: readonly string[] = []): Set<string> {
  return new Set<string>([...REFUSAL_DETAILED, ...REFUSAL_CHARTER, ...secretIds.map(i => `secret_format:${i}`), ...(profiles.includes('SUP-1') ? REFUSAL_SUP : [])]);
}
/** Member type names of the closed schemas; `?` marks a nullable member (the member stays required). */
export type FieldType = string;
/** §5.3: the exact payload object `Q` of every base type except `report` (see REPORT_SCHEMAS). */
export const ENTRY_SCHEMAS: Readonly<Record<string, Readonly<Record<string, FieldType>>>> = {
  'name.claim': { name_norm: 'name', prev_event_index: 'null', ed25519: 'key32?', x25519: 'key32?', tier: 'tier', recovery_kid: 'kid?', recovery_pop: 'proof?', initial_grant: 'grant_spec?' },
  'key.rotate': { mode: 'mode', name_norm: 'name', prev_event_index: 'uint', new_ed25519: 'key32', new_x25519: 'key32?', new_tier: 'key_tier', sig_old: 'proof?', sig_new: 'proof' },
  'key.revoke': { name_norm: 'name', prev_event_index: 'uint', reason_code: 'revocation' },
  'x25519.rotate': { name_norm: 'name', prev_event_index: 'uint', new_x25519: 'key32' },
  grant: { owner_kid: 'kid', sender_kid: 'sender', max: 'uint', expires: 'uint', prev_grant_index: 'uint?' },
  post: { channel_sha256: 'hash', parent_index: 'uint?', body_hash: 'hash', size: 'uint', title_sha256: 'hash?' },
  poll: { channel_sha256: 'hash', body_hash: 'hash', size: 'uint', title_sha256: 'hash', options_sha256: 'options', closes: 'uint', min_key_age_seconds: 'uint', pow_bits: 'uint' },
  vote: { poll_index: 'uint', option: 'uint', pow_nonce: 'hash?', reason_sha256: 'hash?', body_hash: 'hash?', size: 'uint' },
  dm: { to_kid: 'kid', to_key_leaf_index: 'uint', encryption: 'scheme', eph_pk: 'key32?', ct_hash: 'hash', size: 'uint', seq: 'uint', prev: 'hash?', grant_index: 'uint' },
  capsule: { owner_kid: 'kid', to_key_leaf_index: 'uint', key_hash: 'hash', encryption: 'scheme', eph_pk: 'key32?', ct_hash: 'hash', size: 'uint', expires: 'uint', prev_capsule_index: 'uint?' },
  tombstone: { target_index: 'uint', reason_code: 'tombstone', evidence_hash: 'hash?', receipt_hash: 'hash?' },
  refusal: { envelope_hash: 'hash', request_hash: 'hash?', attempt_kid: 'actor?', attempt_nonce: 'nonce?', attempt_expires: 'uint?', reason_code: 'refusal', conflict_index: 'uint?', receipt_hash: 'hash?' },
  suspension: { target_kid: 'actor', reason_code: 'suspension', until: 'uint?', evidence_hash: 'hash?' },
  freeze: { state: 'freeze_state', reason_code: 'freeze', report_hash: 'hash', prev_freeze_index: 'uint?' },
  policy: { kind: 'policy_kind', document_hash: 'hash', size: 'uint', prev_policy_index: 'uint?', effective_after: 'uint', not_before: 'uint', log_kid: 'kid', policy_kid: 'kid', owner_kid: 'kid', log_sig: 'sig64?' },
  release: { artifact_hash: 'hash', source_hash: 'hash', provenance_hash: 'hash', version_hash: 'hash', size: 'uint' },
};
/** §5.3 `report`: four disjoint variants chosen by `kind`. */
export const REPORT_SCHEMAS: Readonly<Record<string, Readonly<Record<string, FieldType>>>> = {
  notice: { kind: 'kind', notice_hash: 'hash', target_index: 'uint?', outcome_code: 'notice_outcome', evidence_hash: 'hash?' },
  daily: { kind: 'kind', day: 'uint', counts: 'counts' },
  audit: { kind: 'kind', report_hash: 'hash', size: 'uint', outcome_code: 'audit_outcome' },
  owner_action: { kind: 'kind', action: 'owner_action', request_hash: 'hash', result_hash: 'hash?', asset_hash: 'hash', amount: 'uint', quote_index: 'uint?' },
};
/** §20.3: `sup.task` and `sup.spend`; `sup.credit` has two variants chosen by `source` (CREDIT_SCHEMAS). */
export const SUP_SCHEMAS: Readonly<Record<string, Readonly<Record<string, FieldType>>>> = {
  'sup.task': { body_hash: 'hash', size: 'uint', asset_hash: 'hash', reward: 'uint', max_awards: 'uint', closes: 'uint' },
  'sup.spend': { purpose: 'purpose', ref_index: 'uint?', asset_hash: 'hash', amount: 'uint', bytes: 'uint' },
};
export const CREDIT_SCHEMAS: Readonly<Record<string, Readonly<Record<string, FieldType>>>> = {
  task: { source: 'source', account_kid: 'kid', task_index: 'uint', submission_index: 'uint', asset_hash: 'hash', amount: 'uint' },
  contribution: { source: 'source', account_kid: 'kid', contribution_hash: 'hash', asset_hash: 'hash', amount: 'uint' },
};
/** Closed string enumerations used by the schemas. */
export const ENUM_VALUES: Readonly<Record<string, readonly string[]>> = {
  tier: TIERS, key_tier: KEY_TIERS, mode: ['rotate', 'upgrade'], scheme: ENCRYPTION_SCHEMES,
  revocation: REASON_CODES.revocation, tombstone: REASON_CODES.tombstone, suspension: REASON_CODES.suspension,
  freeze: REASON_CODES.freeze, freeze_state: ['frozen', 'open'], policy_kind: ['charter', 'card', 'change'],
  notice_outcome: NOTICE_OUTCOMES, audit_outcome: AUDIT_OUTCOMES, owner_action: ['quote', 'complete'],
  purpose: ['owner_action', 'hosting', 'storage'], source: ['task', 'contribution'],
};
/** Types whose actor is the policy key (§5.1, §5.3); `report/owner_action` and owner SUP-1 writes use the owner key. */
export const POLICY_ACTOR_TYPES = ['tombstone', 'refusal', 'suspension', 'freeze', 'policy', 'release', 'report'] as const;
/** §20.2: the SUP asset descriptor of an origin and its hash. */
export const supAssetDescriptor = (origin: string) => ({ asset: 'SUP', buys: ['owner_action', 'hosting', 'storage'], decimals: 0, origin, refundable: false, transferable: false });

// A test log made with the library's own signers and public test seeds (never service code: the client holds no
// log or policy key in production). It writes AICS-1 entries, a dual-signed charter, receipts and checkpoint notes.
import { b64, b64u, concat, hexH, utf8 } from '../dist/bytes.js';
import { canonicalize } from '../dist/canonical.js';
import { signEnvelope, nextChain } from '../dist/envelope.js';
import { buildEntry, entryBytes, entryHash } from '../dist/entry.js';
import { charterBytes, rotationBytes } from '../dist/history.js';
import { didKey, publicKey, sign, x25519PublicKey } from '../dist/keys.js';
import { formatVkey, noteKeyHash } from '../dist/note.js';
import { leafHash, merkleRoot } from '../dist/merkle.js';
import { receiptText } from '../dist/receipt.js';
import { ciphertextMetadata, seal } from '../dist/sealed.js';
export const seed = b => new Uint8Array(32).fill(b);
export const kidOf = s => didKey(publicKey(s));
export const T = 1792281600;
export const vkeyOf = (name, s, type = 1) => formatVkey({ name, keyId: noteKeyHash(name, type, publicKey(s)), keyType: type, publicKey: publicKey(s) });
export const noteLine = (name, s, type, blob) => `— ${name} ${b64(concat(noteKeyHash(name, type, publicKey(s)), blob))}\n`;
export class TestLog {
  constructor(origin = 'log.test/aics', profiles = []) {
    Object.assign(this, { origin, profiles, raw: [], entries: [], last: new Map(), log: seed(0xa1), policy: seed(0xa2), owner: seed(0xa3), clock: T, nonceCounter: 0 });
  }
  get trust() { return { v: 1, origin: this.origin, log_vkey: vkeyOf(this.origin, this.log), policy_kid: kidOf(this.policy), owner_kid: kidOf(this.owner), bootstrap_card_hash: '0'.repeat(64) }; }
  get size() { return this.raw.length; }
  nonce() { return b64u(utf8(String(this.nonceCounter++).padStart(16, '0'))); }
  /** The next native envelope of `s` (its chain continues), accepted at `ts` (default: one second per entry). */
  envelope(s, type, q, o = {}) {
    const ts = o.ts ?? this.clock + this.size, prev = o.chainFrom !== undefined ? o.chainFrom : this.last.get(kidOf(s)) ?? null;
    return signEnvelope(q, s, { origin: this.origin, type, created: o.created ?? ts, nonce: o.nonce ?? this.nonce(), ...nextChain(prev), seen: null, profiles: this.profiles });
  }
  append(s, type, q, o = {}) {
    const ts = o.ts ?? this.clock + this.size, e = o.envelope ?? this.envelope(s, type, q, { ...o, ts }), entry = buildEntry(e, ts);
    if (o.mutate) o.mutate(entry);
    const bytes = entryBytes(entry); this.raw.push(bytes); this.entries.push(entry); this.last.set(e.protected.kid, e);
    return { index: this.size - 1, envelope: e, entry, bytes };
  }
  charter(document = utf8('test charter')) {
    const q = { kind: 'charter', document_hash: hexH(document), size: document.length, prev_policy_index: null, effective_after: 0, not_before: T, log_kid: kidOf(this.log), policy_kid: kidOf(this.policy), owner_kid: kidOf(this.owner) };
    q.log_sig = b64u(sign(charterBytes(q), this.log));
    return this.append(this.policy, 'policy', q);
  }
  claim(s, xs, name, grant = null, o = {}) {
    return this.append(s, 'name.claim', { name_norm: name, prev_event_index: null, ed25519: b64u(publicKey(s)), x25519: b64u(x25519PublicKey(xs)), tier: 'verified', recovery_kid: null, recovery_pop: null, initial_grant: grant }, o);
  }
  post(s, text, channel = 'test', o = {}) {
    const body = canonicalize({ channel, title: null, text });
    return { ...this.append(s, 'post', { channel_sha256: hexH(utf8(channel)), parent_index: null, body_hash: hexH(body), size: body.length, title_sha256: null }, o), body };
  }
  grant(owner, senderKid, max, expires, prevGrantIndex = null) { return this.append(owner, 'grant', { owner_kid: kidOf(owner), sender_kid: senderKid, max, expires, prev_grant_index: prevGrantIndex }); }
  dm(from, toKid, toX25519Public, toKeyLeafIndex, grantIndex, text = 'hello', o = {}) {
    const nonce = this.nonce(), prev = this.last.get(kidOf(from)) ?? null, chain = nextChain(prev);
    const ct = seal({ from_kid: kidOf(from), to_kid: toKid, envelope_nonce: nonce }, text, toX25519Public);
    const q = { to_kid: toKid, to_key_leaf_index: toKeyLeafIndex, ...ciphertextMetadata(ct), grant_index: grantIndex, ...chain };
    return { ...this.append(from, 'dm', q, { ...o, nonce }), ciphertext: ct };
  }
  rotate(oldSeed, newSeed, name, prevEventIndex, newX = null) {
    const r = { origin: this.origin, name_norm: name, prev_event_index: prevEventIndex, new_ed25519: b64u(publicKey(newSeed)), new_x25519: newX, new_tier: 'verified', mode: 'rotate' };
    const data = rotationBytes(r), proof = s => ({ scheme: 'ed25519', signature: b64u(sign(data, s)) });
    const { origin: _o, ...q } = r; return this.append(oldSeed, 'key.rotate', { ...q, sig_old: proof(oldSeed), sig_new: proof(newSeed) });
  }
  revoke(s, name, prevEventIndex, reason = 'retired') { return this.append(s, 'key.revoke', { name_norm: name, prev_event_index: prevEventIndex, reason_code: reason }); }
  root(size = this.size) { return merkleRoot(this.raw.slice(0, size).map(leafHash)); }
  /** A log-signed checkpoint note (optionally with a cosignature by `witness` at `time`). */
  note(size = this.size, witness) {
    const text = `${this.origin}\n${size}\n${b64(this.root(size))}\n`;
    let note = text + '\n' + noteLine(this.origin, this.log, 1, sign(utf8(text), this.log));
    if (witness) { const ts = new Uint8Array(8); new DataView(ts.buffer).setBigUint64(0, BigInt(witness.time)); note += noteLine(witness.name, witness.seed, 4, concat(ts, sign(utf8(`cosignature/v1\ntime ${witness.time}\n${text}`), witness.seed))); }
    return utf8(note);
  }
  /** The §10.1 receipt note for an entry. */
  receipt(entry) { const text = receiptText(this.origin, entryHash(entryBytes(entry)), entry.ts); return utf8(text + '\n' + noteLine(this.origin, this.log, 1, sign(utf8(text), this.log))); }
  /** A policy-signed refusal entry naming `refused` (an envelope). */
  refusal(refused, reason, conflictIndex = null, o = {}) {
    const { envelopeHash } = o; return this.append(this.policy, 'refusal', { envelope_hash: envelopeHash ?? hexH(canonicalize(refused)), request_hash: null, attempt_kid: refused.protected.kid, attempt_nonce: refused.protected.nonce, attempt_expires: refused.protected.expires, reason_code: reason, conflict_index: conflictIndex, receipt_hash: null });
  }
}

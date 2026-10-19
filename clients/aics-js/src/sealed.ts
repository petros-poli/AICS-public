/**
 * AICS-1 §8.1 private bodies: libsodium `crypto_box_seal` (X25519 + XSalsa20-Poly1305, a fresh ephemeral key per
 * ciphertext, 48 bytes of overhead) over the framed plaintext `uint32be(len(header)) || header || content`, where
 * `header = J({from_kid, to_kid, envelope_nonce})` names the signing kids and the envelope nonce (Appendix A.4).
 * Sealed boxes do not authenticate the sender; the verified outer envelope does, and the inner header stops a
 * ciphertext being re-wrapped in another envelope. There is no other framing and no cleartext fallback.
 */
import nacl from 'tweetnacl';
import { blake2b } from '@noble/hashes/blake2b';
import { b64u, concat, equal, hexH, isU64Of, random, text, uint32be } from './bytes.js';
import { canonicalText, canonicalize, hasMembers, parseJson, type JsonObject } from './canonical.js';
import { isKid, validateX25519PublicKey, x25519PublicKey } from './keys.js';
import type { Envelope } from './envelope.js';
export const SCHEME = 'x25519-xsalsa20-poly1305';
export const SEAL_OVERHEAD = 48;
export const MAX_CIPHERTEXT_BYTES = 65536;
export const MAX_HEADER_BYTES = 4096;
export type InnerHeader = { from_kid: string; to_kid: string; envelope_nonce: string };
export class SealedError extends Error { constructor(message: string) { super(message); this.name = 'SealedError'; } }
const check = (ok: unknown, message: string): void => { if (!ok) throw new SealedError(message); };
/** `J(header)`: exactly the three members, signing kids (did:key) and the envelope nonce (U64 of 16 bytes). */
export function innerHeaderBytes(h: InnerHeader): Uint8Array {
  check(hasMembers(h, ['envelope_nonce', 'from_kid', 'to_kid']), 'The inner header has exactly from_kid, to_kid, envelope_nonce');
  check(isKid(h.from_kid) && isKid(h.to_kid), 'from_kid and to_kid are signing kids (Ed25519 did:key)');
  check(isU64Of(h.envelope_nonce, 16), 'envelope_nonce is the envelope nonce: U64 of 16 bytes');
  return canonicalize({ envelope_nonce: h.envelope_nonce, from_kid: h.from_kid, to_kid: h.to_kid });
}
/** The header an envelope promises: `protected.kid`, the recipient (`to_kid`, or a capsule's `owner_kid`), `protected.nonce`. */
export function headerFromEnvelope(e: Envelope): InnerHeader {
  const recipient = e?.protected?.type === 'dm' ? 'to_kid' : e?.protected?.type === 'capsule' ? 'owner_kid' : null;
  check(recipient, 'Only dm and capsule envelopes carry sealed bodies');
  return { from_kid: e.protected.kid, to_kid: e.payload[recipient!] as string, envelope_nonce: e.protected.nonce };
}
/** `uint32be(len(header)) || header || content` (§8.1). */
export function framePlaintext(headerBytes: Uint8Array, content: Uint8Array): Uint8Array {
  check(headerBytes.length > 0 && headerBytes.length <= MAX_HEADER_BYTES, `The inner header is 1 to ${MAX_HEADER_BYTES} bytes`);
  return concat(uint32be(headerBytes.length), headerBytes, content);
}
/** `[header, content]` of a framed plaintext; the length must be 1 to 4096 and fully contained. */
export function splitPlaintext(plaintext: Uint8Array): [Uint8Array, Uint8Array] {
  check(plaintext.length >= 4, 'No inner header length');
  const n = ((plaintext[0] << 24) >>> 0) + (plaintext[1] << 16) + (plaintext[2] << 8) + plaintext[3];
  check(n > 0 && n <= MAX_HEADER_BYTES && n <= plaintext.length - 4, 'Inner header length out of range');
  return [plaintext.slice(4, 4 + n), plaintext.slice(4 + n)];
}
/** `{encryption, eph_pk, ct_hash, size}`: the ciphertext members of a dm or capsule `Q` (§5.3, §8.1). */
export function ciphertextMetadata(ct: Uint8Array): { encryption: string; eph_pk: string; ct_hash: string; size: number } {
  check(ct.length >= SEAL_OVERHEAD, 'Truncated sealed box');
  return { encryption: SCHEME, eph_pk: b64u(ct.slice(0, 32)), ct_hash: hexH(ct), size: ct.length };
}
const boxNonce = (ephemeralPublic: Uint8Array, recipient: Uint8Array): Uint8Array => blake2b(concat(ephemeralPublic, recipient), { dkLen: 24 });
const utf8Content = (content: Uint8Array | string): Uint8Array => {
  const bytes = typeof content === 'string' ? new TextEncoder().encode(content) : content;
  try { text(bytes); } catch { throw new SealedError('Content must be UTF-8 text (§8.1)'); }
  if (typeof content === 'string') check(text(bytes) === content, 'Content must be valid Unicode');
  return bytes;
};
/**
 * Seal `content` (UTF-8 text) to the recipient's logged X25519 key under the inner header. Choose the envelope nonce
 * first (`newNonce()`), take the recipient key from verified history, then sign an envelope committing to
 * `ciphertextMetadata(ct)`. A fresh ephemeral key is generated for every call and erased afterwards.
 */
export function seal(header: InnerHeader, content: Uint8Array | string, recipientPublic: Uint8Array, o: { maxCiphertextBytes?: number } = {}): Uint8Array {
  validateX25519PublicKey(recipientPublic);
  const plaintext = framePlaintext(innerHeaderBytes(header), utf8Content(content));
  check(plaintext.length + SEAL_OVERHEAD <= (o.maxCiphertextBytes ?? MAX_CIPHERTEXT_BYTES), 'Ciphertext exceeds the limit');
  const ephemeral = random(32), pub = x25519PublicKey(ephemeral);
  try { return concat(pub, nacl.box(plaintext, boxNonce(pub, recipientPublic), recipientPublic, ephemeral)); } finally { ephemeral.fill(0); }
}
/** `crypto_box_seal` of already framed bytes (a fresh ephemeral key, erased afterwards); profile framings build on it. */
export function sealFramed(plaintext: Uint8Array, recipientPublic: Uint8Array, o: { maxCiphertextBytes?: number } = {}): Uint8Array {
  validateX25519PublicKey(recipientPublic);
  check(plaintext.length + SEAL_OVERHEAD <= (o.maxCiphertextBytes ?? MAX_CIPHERTEXT_BYTES), 'Ciphertext exceeds the limit');
  const ephemeral = random(32), pub = x25519PublicKey(ephemeral);
  try { return concat(pub, nacl.box(plaintext, boxNonce(pub, recipientPublic), recipientPublic, ephemeral)); } finally { ephemeral.fill(0); }
}
/** `crypto_box_seal_open` with the recipient's X25519 secret: the framed plaintext, or a SealedError. */
export function openFramed(ct: Uint8Array, recipientSecret: Uint8Array): Uint8Array {
  check(recipientSecret.length === 32, 'X25519 secret must be 32 bytes');
  check(ct.length >= SEAL_OVERHEAD && ct.length <= MAX_CIPHERTEXT_BYTES, 'Invalid ciphertext size');
  const epk = ct.slice(0, 32); validateX25519PublicKey(epk);
  const plain = nacl.box.open(ct.slice(32), boxNonce(epk, x25519PublicKey(recipientSecret)), epk, recipientSecret);
  check(plain, 'Sealed box does not open with this key');
  return plain!;
}
/** Content bytes that must be UTF-8 text (§8.1). */
export const contentBytes = (content: Uint8Array | string): Uint8Array => utf8Content(content);
export type OpenedMessage = { header: InnerHeader; body: Uint8Array; readonly text: string };
/**
 * Open a sealed body and require its inner header to equal what the (already verified) outer envelope promises.
 * With `envelope`, its payload must first commit to exactly this ciphertext (encryption, ct_hash, eph_pk, size).
 * Pass exactly one of `envelope` or `expected`. Nothing of the plaintext is returned on any failure.
 */
export function openSealed(ct: Uint8Array, recipientSecret: Uint8Array, o: { envelope?: Envelope; expected?: InnerHeader; recipientKid?: string }): OpenedMessage {
  check(!!o.envelope !== !!o.expected, 'Pass exactly one of envelope or expected');
  check(recipientSecret.length === 32, 'X25519 secret must be 32 bytes');
  check(ct.length >= SEAL_OVERHEAD && ct.length <= MAX_CIPHERTEXT_BYTES, 'Invalid ciphertext size');
  let want: InnerHeader;
  if (o.envelope) {
    want = headerFromEnvelope(o.envelope); const q = o.envelope.payload as JsonObject, m = ciphertextMetadata(ct);
    check(q.encryption === SCHEME, `encryption is not ${SCHEME}`);
    check(q.ct_hash === m.ct_hash && q.eph_pk === m.eph_pk && q.size === m.size, 'The envelope does not commit to this ciphertext');
  } else want = o.expected!;
  const wantBytes = innerHeaderBytes(want);
  if (o.recipientKid !== undefined) check(want.to_kid === o.recipientKid, 'The message is addressed to another kid');
  const epk = ct.slice(0, 32); validateX25519PublicKey(epk);
  const plain = nacl.box.open(ct.slice(32), boxNonce(epk, x25519PublicKey(recipientSecret)), epk, recipientSecret);
  check(plain, 'Sealed box does not open with this key');
  const [hb, body] = splitPlaintext(plain!);
  let got: InnerHeader;
  try { got = parseJson(hb) as unknown as InnerHeader; } catch { throw new SealedError('The inner header is not JSON'); }
  check(canonicalText(got) === text(hb), 'The inner header is not canonical JCS');
  check(equal(innerHeaderBytes(got), hb), 'Malformed inner header');
  check(equal(hb, wantBytes), 'The inner header does not match the envelope');
  try { text(body); } catch { throw new SealedError('Content is not UTF-8 text (§8.1)'); }
  return { header: { from_kid: got.from_kid, to_kid: got.to_kid, envelope_nonce: got.envelope_nonce }, body, get text() { return text(body); } };
}

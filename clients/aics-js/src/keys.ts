import { createPrivateKey, createPublicKey } from 'node:crypto';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 as hash } from '@noble/hashes/sha256';
import { assert, b64, b64u, concat, decodeBase64, equal, isU64Of, length, random, sha256, text, utf8 } from './bytes.js';
export type KeyPair = { privateKey: Uint8Array; publicKey: Uint8Array };
/** The 32-byte Ed25519 public key of a 32-byte seed. */
export const publicKey = (seed: Uint8Array): Uint8Array => ed25519.getPublicKey(length(seed, 32));
/** A fresh Ed25519 signing key, generated locally (AICS-1 §3.1: the service never generates agent keys). */
export const generateKeypair = (): KeyPair => { const privateKey = random(32); return { privateKey, publicKey: publicKey(privateKey) }; };
/** A fresh, independent X25519 encryption key (AICS-1 §3.1). */
export const generateX25519Keypair = (): KeyPair => { const privateKey = random(32); return { privateKey, publicKey: x25519.getPublicKey(privateKey) }; };
export const x25519PublicKey = (secret: Uint8Array): Uint8Array => x25519.getPublicKey(length(secret, 32));
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function base58Encode(b: Uint8Array): string {
  let n = 0n; for (const x of b) n = n * 256n + BigInt(x); let out = '';
  while (n) { out = alphabet[Number(n % 58n)] + out; n /= 58n; }
  for (const x of b) { if (x) break; out = '1' + out; } return out;
}
export function base58Decode(s: string): Uint8Array {
  let n = 0n; for (const c of s) { const i = alphabet.indexOf(c); assert(i >= 0, 'Invalid base58'); n = n * 58n + BigInt(i); }
  const out: number[] = []; while (n) { out.unshift(Number(n % 256n)); n /= 256n; }
  for (const c of s) { if (c !== '1') break; out.unshift(0); } return Uint8Array.from(out);
}
// Key validation is pure and costly (a torsion check is a full scalar multiplication), so verdicts are memoized.
const MEMO_LIMIT = 4096;
function memo<V>(cache: Map<string, V>, key: string, compute: () => V): V {
  const hit = cache.get(key); if (hit !== undefined) return hit;
  const value = compute(); if (cache.size >= MEMO_LIMIT) cache.delete(cache.keys().next().value as string); cache.set(key, value); return value;
}
const validPoints = new Map<string, true>(), didKeys = new Map<string, string>();
/** A canonical, prime-order Ed25519 point (small-order and non-canonical encodings are refused). */
export function validatePublicKey(raw: Uint8Array): Uint8Array {
  length(raw, 32);
  memo(validPoints, Buffer.from(raw).toString('hex'), () => {
    const p = ed25519.ExtendedPoint.fromHex(raw, false);
    assert(!p.isSmallOrder() && p.isTorsionFree() && equal(p.toRawBytes(), raw), 'Invalid Ed25519 point'); return true as const;
  });
  return raw;
}
/** 32 bytes that do not yield an all-zero shared secret (AICS-1 §3.1, RFC 7748 §6.1). */
export function validateX25519PublicKey(raw: Uint8Array): Uint8Array { length(raw, 32); x25519.getSharedSecret(sha256(utf8('aics-identity/x25519-small-order-probe')), raw); return raw; }
/** AICS-1 §3.1: the signing `kid`, `did:key:z` + base58btc(0xed 0x01 || ed25519 public key). */
export const didKey = (pub: Uint8Array): string => 'did:key:z' + base58Encode(concat(Uint8Array.of(0xed, 1), length(pub, 32)));
/** The displayed encryption DID, multicodec 0xec 0x01 (AICS-1 §3.1). */
export const x25519DidKey = (pub: Uint8Array): string => 'did:key:z' + base58Encode(concat(Uint8Array.of(0xec, 1), validateX25519PublicKey(pub)));
/** Decode a did:key locally (AICS-1 §3.1); only the canonical encoding of a valid key is accepted. */
export function parseDidKey(did: string, kind: 'ed25519' | 'x25519' = 'ed25519'): Uint8Array {
  assert(typeof did === 'string' && did.startsWith('did:key:z') && did.length <= 128, 'Expected did:key:z');
  const pubHex = memo(didKeys, kind + ':' + did, () => {
    const b = base58Decode(did.slice(9));
    assert(b.length === 34 && b[0] === (kind === 'ed25519' ? 0xed : 0xec) && b[1] === 1, 'Wrong did:key multicodec');
    const pub = kind === 'ed25519' ? validatePublicKey(b.slice(2)) : validateX25519PublicKey(b.slice(2));
    assert((kind === 'ed25519' ? didKey(pub) : x25519DidKey(pub)) === did, 'Noncanonical did:key');
    return Buffer.from(pub).toString('hex');
  });
  return new Uint8Array(Buffer.from(pubHex, 'hex'));
}
/** Whether a value is an AICS-1 signing kid: a bare, canonical Ed25519 did:key. */
export const isKid = (v: unknown): v is string => { try { parseDidKey(v as string); return true; } catch { return false; } };
/** AICS-1 §3.3: the fallback tier's identifier, `unverified:` + U64 of 16 random bytes (never a key). */
export const isUnverifiedId = (v: unknown): v is string => typeof v === 'string' && v.startsWith('unverified:') && isU64Of(v.slice(11), 16);
function derive(secret: Uint8Array, label: string, salt: Uint8Array | undefined, prefix: string): Uint8Array {
  assert(secret.length && label && (salt === undefined || salt.length), 'Empty HKDF input');
  return hkdf(hash, secret, salt, utf8(prefix + label), 32);
}
/** HKDF-SHA256 key derivation from a secret the agent keeps outside the service (an agent arrangement, AICS-1 §3.1). */
export const deriveAgentKey = (secret: Uint8Array, label: string, salt?: Uint8Array): Uint8Array => derive(secret, label, salt, 'aics-identity/v1/');
export const deriveX25519Key = (secret: Uint8Array, label: string, salt?: Uint8Array): Uint8Array => derive(secret, label, salt, 'aics-identity/v1-x25519/');
/** `{ kid, did, public_key }`: the AICS-1 kid is the did:key itself; `public_key` is U64 of the 32 bytes. */
export const agentIdentity = (seed: Uint8Array) => { const pub = publicKey(seed), did = didKey(pub); return { kid: did, did, public_key: b64u(pub) }; };
export const sign = (message: Uint8Array, seed: Uint8Array): Uint8Array => ed25519.sign(message, length(seed, 32));
/** Pure Ed25519 verification (RFC 8032 §5.1.7, cofactorless, canonical encodings only). */
export function verify(signature: Uint8Array, message: Uint8Array, pub: Uint8Array): boolean {
  try { return signature.length === 64 && ed25519.verify(signature, message, validatePublicKey(pub), { zip215: false }); } catch { return false; }
}
function sshReader(bytes: Uint8Array) {
  let offset = 0; const raw = (n: number) => { assert(offset + n <= bytes.length, 'Truncated SSH key'); const b = bytes.slice(offset, offset + n); offset += n; return b; };
  const u32 = () => Buffer.from(raw(4)).readUInt32BE();
  return { raw, u32, field: () => raw(u32()), remaining: () => bytes.length - offset };
}
/** A public key from raw bytes, a did:key, an `ssh-ed25519 <base64> [comment]` line, PEM, or base64 of 32 bytes. */
export function parsePublicKey(input: string | Uint8Array): Uint8Array {
  if (input instanceof Uint8Array) return validatePublicKey(input);
  const s = input.trim();
  if (s.startsWith('did:')) return parseDidKey(s);
  if (s.startsWith('ssh-ed25519 ')) {
    const r = sshReader(decodeBase64(s.split(/\s+/)[1])); assert(text(r.field()) === 'ssh-ed25519', 'Wrong SSH algorithm'); const pub = r.field(); assert(!r.remaining(), 'Trailing SSH key data'); return validatePublicKey(pub);
  }
  if (s.startsWith('-----BEGIN')) { const key = createPublicKey(s); assert(key.asymmetricKeyType === 'ed25519', 'Expected Ed25519 key'); return validatePublicKey(decodeBase64(key.export({ format: 'jwk' }).x!)); }
  return validatePublicKey(decodeBase64(s));
}
/** PKCS#8 PEM/DER, raw seed, or unencrypted OpenSSH Ed25519 private key. */
export function importPrivateKey(input: string | Uint8Array, passphrase?: string): Uint8Array {
  if (input instanceof Uint8Array && input.length === 32) return input.slice();
  const s = typeof input === 'string' ? input.trim() : '';
  if (s.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----')) {
    const bytes = decodeBase64(s.replace(/-----[^\n]+-----/g, '').replace(/\s+/g, '')); const r = sshReader(bytes);
    assert(text(r.raw(15)) === 'openssh-key-v1\0', 'Invalid OpenSSH magic');
    assert(text(r.field()) === 'none' && text(r.field()) === 'none', 'Encrypted OpenSSH keys unsupported; export an unencrypted key locally');
    assert(!r.field().length && r.u32() === 1, 'Unsupported OpenSSH key container'); const outerPub = r.field(); const privateBlock = r.field(); assert(!r.remaining(), 'Trailing OpenSSH data');
    const p = sshReader(privateBlock); assert(p.u32() === p.u32(), 'OpenSSH checkints differ'); assert(text(p.field()) === 'ssh-ed25519', 'Expected Ed25519');
    const pub = p.field(), privateBytes = p.field(); length(privateBytes, 64); p.field(); const padding = p.raw(p.remaining());
    assert(padding.every((v, i) => v === i + 1), 'Invalid OpenSSH padding'); const seed = privateBytes.slice(0, 32);
    assert(equal(pub, publicKey(seed)) && equal(pub, privateBytes.slice(32)), 'OpenSSH public/private mismatch');
    const o = sshReader(outerPub); assert(text(o.field()) === 'ssh-ed25519' && equal(o.field(), pub) && !o.remaining(), 'OpenSSH outer public mismatch'); return seed;
  }
  const key = s.startsWith('-----BEGIN') ? createPrivateKey({ key: s, passphrase }) : input instanceof Uint8Array ? createPrivateKey({ key: Buffer.from(input), format: 'der', type: 'pkcs8', passphrase }) : null;
  if (key) { assert(key.asymmetricKeyType === 'ed25519', 'Expected Ed25519 private key'); return length(decodeBase64(key.export({ format: 'jwk' }).d!), 32); }
  return length(decodeBase64(s), 32);
}
export function exportPrivateKey(seed: Uint8Array): string {
  const key = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: b64u(length(seed, 32)), x: b64u(publicKey(seed)) }, format: 'jwk' });
  return key.export({ format: 'pem', type: 'pkcs8' }).toString();
}
export function exportPublicKey(pub: Uint8Array): string {
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64u(validatePublicKey(pub)) }, format: 'jwk' }).export({ format: 'pem', type: 'spki' }).toString();
}
/** The SSH wire blob of an Ed25519 public key: string "ssh-ed25519" || string key. */
export function sshPublicKeyBlob(pub: Uint8Array): Uint8Array {
  const field = (b: Uint8Array) => { const n = Buffer.alloc(4); n.writeUInt32BE(b.length); return concat(n, b); };
  return concat(field(utf8('ssh-ed25519')), field(validatePublicKey(pub)));
}
export const opensshPublicKey = (pub: Uint8Array): string => 'ssh-ed25519 ' + b64(sshPublicKeyBlob(pub));

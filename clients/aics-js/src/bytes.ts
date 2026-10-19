import { randomBytes, timingSafeEqual } from 'node:crypto';
import { sha256 as hash } from '@noble/hashes/sha256';
/** AICS-1 §2: `uint` is a JSON integer from 0 through 2^53 - 1. */
export const MAX_UINT = Number.MAX_SAFE_INTEGER;
export const text = (b: Uint8Array): string => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b);
export const utf8 = (s: string): Uint8Array => {
  const encoded = new TextEncoder().encode(s);
  assert(text(encoded) === s, 'Invalid Unicode string');
  return encoded;
};
export const concat = (...parts: Uint8Array[]): Uint8Array => new Uint8Array(Buffer.concat(parts));
export const sha256 = (b: Uint8Array): Uint8Array => hash(b);
export const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
/** AICS-1 `hexH(b)`: the 64 lowercase hexadecimal characters of SHA-256(b). */
export const hexH = (b: Uint8Array): string => hex(sha256(b));
/** AICS-1 `B64(b)`: canonical padded standard base64. */
export const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64');
/** AICS-1 `U64(b)`: canonical unpadded base64url. */
export const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
export const equal = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && timingSafeEqual(a, b);
export const random = (size: number): Uint8Array => new Uint8Array(randomBytes(size));
export const uint32be = (n: number): Uint8Array => { uint(n); assert(n <= 0xffffffff, 'Value exceeds uint32'); const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
export function assert(ok: unknown, message: string): asserts ok { if (!ok) throw new Error(message); }
export const isUint = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
export function uint(n: unknown, name = 'integer'): asserts n is number { assert(isUint(n), `Invalid ${name}`); }
export const isHex64 = (s: unknown): s is string => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
export function length(b: Uint8Array, n: number): Uint8Array { assert(b instanceof Uint8Array && b.length === n, `Expected ${n} bytes`); return b; }
/**
 * Gate input leeway only (AICS-1 §11.2): either alphabet, padded or unpadded, surrounding ASCII whitespace.
 * Mixed alphabets, wrong padding and nonzero pad bits are errors.
 */
export function decodeBase64(s: string): Uint8Array {
  assert(typeof s === 'string', 'Expected base64 text');
  const c = s.replace(/^[ \t\r\n\v\f]+|[ \t\r\n\v\f]+$/g, '').replace(/\r?\n/g, '');
  assert(!(/[+/]/.test(c) && /[-_]/.test(c)), 'Mixed base64 alphabets');
  assert(/^[A-Za-z0-9+/_-]*={0,2}$/.test(c), 'Invalid base64');
  const raw = c.replace(/=+$/, ''), pads = c.length - raw.length;
  assert(raw.length % 4 !== 1, 'Invalid base64 length');
  assert(pads === 0 || (raw.length + pads) % 4 === 0, 'Invalid base64 padding');
  const bytes = new Uint8Array(Buffer.from(raw, 'base64'));
  const again = Buffer.from(bytes).toString(/[-_]/.test(raw) ? 'base64url' : 'base64').replace(/=+$/, '');
  assert(again === raw, 'Noncanonical base64 pad bits');
  return bytes;
}
/** Strict `B64` decoder: anything but the canonical padded standard form is refused. */
export function decodeB64(s: string): Uint8Array { assert(typeof s === 'string' && s.length > 0, 'Expected base64 text'); const b = decodeBase64(s); assert(b64(b) === s, 'Noncanonical base64'); return b; }
/** Strict `U64` decoder: anything but the canonical unpadded base64url form is refused. */
export function decodeB64u(s: string): Uint8Array { assert(typeof s === 'string', 'Expected base64url text'); const b = decodeBase64(s); assert(b64u(b) === s, 'Noncanonical base64url'); return b; }
/** Strict `U64` decoder with an optional exact decoded length. */
export function decodeU64(s: unknown, n?: number): Uint8Array {
  assert(typeof s === 'string', 'Expected U64 text'); const b = decodeB64u(s);
  if (n !== undefined) assert(b.length === n, `Expected U64 of ${n} bytes`); return b;
}
export function isU64Of(s: unknown, n?: number): s is string { try { decodeU64(s, n); return true; } catch { return false; } }
export function fromHex(s: string): Uint8Array { assert(typeof s === 'string' && /^(?:[0-9a-f]{2})*$/.test(s), 'Invalid hex'); return new Uint8Array(Buffer.from(s, 'hex')); }

import jcs from 'canonicalize';
import { assert, text, utf8 } from './bytes.js';
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type JsonObject = { [key: string]: Json };
/** AICS-1 §15: implementations MUST bound JSON depth. */
export const MAX_JSON_DEPTH = 64;
function validString(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) { const d = s.charCodeAt(++i); assert(d >= 0xdc00 && d <= 0xdfff, 'Lone Unicode surrogate'); }
    else assert(c < 0xdc00 || c > 0xdfff, 'Lone Unicode surrogate');
  }
}
function validate(v: unknown, seen = new Set<object>(), depth = 0): void {
  assert(depth <= MAX_JSON_DEPTH, 'JSON nesting too deep');
  if (v === null || typeof v === 'boolean') return;
  if (typeof v === 'string') { validString(v); return; }
  if (typeof v === 'number') { assert(Number.isFinite(v), 'Nonfinite JSON number'); return; }
  assert(typeof v === 'object' && !seen.has(v), 'Not a JSON value or cyclic object');
  assert(Array.isArray(v) || Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null, 'Expected plain JSON object');
  seen.add(v);
  if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) { assert(i in v, 'Sparse array'); validate(v[i], seen, depth + 1); } }
  else for (const [k, x] of Object.entries(v)) { validString(k); assert(x !== undefined, 'Undefined JSON member'); validate(x, seen, depth + 1); }
  seen.delete(v);
}
// canonicalize 2.x is CommonJS; NodeNext sees a namespace in its bundled types.
const serialize = jcs as unknown as (input: unknown) => string | undefined;
/** RFC 8785 JCS text of a JSON value (AICS-1 `J(x)` before UTF-8 encoding). */
export function canonicalText(v: unknown): string { validate(v); const s = serialize(v); assert(typeof s === 'string', 'Not a JSON value'); return s; }
/** AICS-1 `J(x)`: the UTF-8 bytes of the RFC 8785 serialization. */
export const canonicalize = (v: unknown): Uint8Array => utf8(canonicalText(v));
/** Byte equality of two JSON values under JCS (no member order, prototype or number-form differences). */
export const sameJson = (a: unknown, b: unknown): boolean => { try { return canonicalText(a) === canonicalText(b); } catch { return false; } };
export const isObject = (v: unknown): v is JsonObject => typeof v === 'object' && v !== null && !Array.isArray(v);
/** Exactly these member names, no others (AICS-1 §2). */
export const hasMembers = (v: unknown, names: readonly string[]): v is JsonObject => isObject(v) && Object.keys(v).length === names.length && names.every(n => Object.prototype.hasOwnProperty.call(v, n));
/**
 * Strict JSON (AICS-1 §2): duplicate member names, invalid UTF-8, lone surrogates, nonfinite numbers, trailing data
 * and nesting deeper than MAX_JSON_DEPTH are rejected. Objects have a null prototype.
 */
export function parseJson(input: string | Uint8Array): Json {
  const s = typeof input === 'string' ? input : text(input); let i = 0;
  const ws = () => { while (i < s.length && (s[i] === ' ' || s[i] === '\t' || s[i] === '\r' || s[i] === '\n')) i++; };
  function string(): string {
    const start = i++; let escaped = false;
    while (i < s.length) {
      const c = s[i++];
      if (!escaped && c === '"') { const v = JSON.parse(s.slice(start, i)); validString(v); return v; }
      if (!escaped && c < ' ') throw new Error('Control character in JSON string');
      escaped = !escaped && c === '\\';
    }
    throw new Error('Unterminated JSON string');
  }
  function value(depth: number): Json {
    assert(depth <= MAX_JSON_DEPTH, 'JSON nesting too deep');
    ws(); const c = s[i];
    if (c === '"') return string();
    if (c === '{') {
      i++; ws(); const out: Record<string, Json> = Object.create(null); const keys = new Set<string>();
      if (s[i] === '}') { i++; return out; }
      for (;;) {
        ws(); assert(s[i] === '"', 'Expected JSON key'); const k = string(); assert(!keys.has(k), 'Duplicate JSON key'); keys.add(k);
        ws(); assert(s[i++] === ':', 'Expected colon'); out[k] = value(depth + 1); ws();
        const end = s[i++]; if (end === '}') return out; assert(end === ',', 'Expected comma');
      }
    }
    if (c === '[') {
      i++; ws(); const out: Json[] = []; if (s[i] === ']') { i++; return out; }
      for (;;) { out.push(value(depth + 1)); ws(); const end = s[i++]; if (end === ']') return out; assert(end === ',', 'Expected comma'); }
    }
    const m = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(s.slice(i, i + 400));
    assert(m, 'Invalid JSON value'); i += m[0].length; const v = JSON.parse(m[0]); validate(v); return v;
  }
  const result = value(0); ws(); assert(i === s.length, 'Trailing JSON data'); return result;
}
/** Strict JSON whose bytes are exactly its own JCS serialization (AICS-1 entries, cards, bundles, headers). */
export function parseCanonical(input: Uint8Array | string, what = 'value'): Json {
  const s = typeof input === 'string' ? input : text(input), v = parseJson(s);
  assert(canonicalText(v) === s, `${what} is not canonical JCS`); return v;
}

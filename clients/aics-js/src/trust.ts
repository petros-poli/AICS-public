/**
 * AICS-1 §6.4 — the out-of-band trust bundle.
 *
 * The instance publishes exactly one JSON object
 * `{v:1, origin, log_vkey, policy_kid, owner_kid, bootstrap_card_hash}` whose
 * exact bytes are its JCS (RFC 8785) serialization, `J(bundle)`. The bundle is
 * published out of band: as a single DNS TXT record `aics1=<U64(J(bundle))>`
 * at `_aics.<domain>`, and as a labelled README block (mirrored on PyPI) that
 * carries the same bytes plus their SHA-256 digest `hexH`. DNS without
 * authenticated resolution is not a secure root (AICS-1 §6.4): a bootstrap
 * tool MUST compare the DNS copy with the README and PyPI copies and MUST stop
 * on any disagreement. Two distinct bundles published at the same epoch are an
 * error.
 *
 * Every refusal in this module throws {@link TrustBundleError} with a one-line
 * message.
 */

import { resolveTxt } from 'node:dns/promises';
import { assert, b64u, decodeB64u, hex, sha256, utf8 } from './bytes.js';
import { canonicalize, parseJson, type Json } from './canonical.js';
import { parseDidKey } from './keys.js';
import { parseVkey } from './note.js';

/** The published trust bundle object; its exact bytes are J(bundle) (AICS-1 §6.4). */
export type TrustBundle = {
  v: 1;
  origin: string;
  log_vkey: string;
  policy_kid: string;
  owner_kid: string;
  bootstrap_card_hash: string;
};

/** Raised for every refused bundle, TXT payload, README block or DNS response. */
export class TrustBundleError extends Error {}

/** TXT record prefix: the record value is `aics1=<U64(J(bundle))>` (AICS-1 §6.4). */
export const TXT_PREFIX = 'aics1=';

/** First line of the README trust-bundle block (AICS-1 §6.4). */
const README_HEADER = 'AICS trust bundle (AICS-1 §6.4):';

/** The exact member set of the trust bundle object (AICS-1 §6.4). */
const MEMBERS = ['v', 'origin', 'log_vkey', 'policy_kid', 'owner_kid', 'bootstrap_card_hash'];

/** Upper bound on DNS compression-pointer jumps inside one name (loop guard). */
const MAX_POINTER_JUMPS = 32;

function fail(message: string): never {
  throw new TrustBundleError(message);
}

/** Byte-for-byte equality of two byte strings. */
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

/** Coerces any error raised while handling a bundle into a TrustBundleError. */
function toBundleError(e: unknown): TrustBundleError {
  if (e instanceof TrustBundleError) return e;
  return new TrustBundleError(`Invalid trust bundle: ${e instanceof Error ? e.message : String(e)}`);
}

function stringMember(value: unknown, name: string): string {
  assert(typeof value === 'string', `member ${name} must be a string (AICS-1 §6.4)`);
  return value;
}

/** Applies every MUST of AICS-1 §6.4 (and the §3.1 key-distinctness rule) to a parsed bundle object. */
function checkBundle(value: unknown): TrustBundle {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail('Trust bundle must be a JSON object');
  const obj = value as { [key: string]: Json };
  const names = Object.keys(obj);
  assert(names.length === MEMBERS.length && MEMBERS.every((m) => names.includes(m)),
    'Trust bundle must have exactly the members v, origin, log_vkey, policy_kid, owner_kid, bootstrap_card_hash (AICS-1 §6.4)');
  assert(obj.v === 1, 'Trust bundle member v must be the JSON integer 1 (AICS-1 §6.4)');
  const origin = stringMember(obj.origin, 'origin');
  assert(/^[\x21-\x7e]+$/.test(origin), 'member origin must be non-empty printable ASCII without whitespace (AICS-1 §2, §6.4)');
  assert(!origin.includes('://'), 'member origin must not carry a "://" scheme (AICS-1 §6.4)');
  assert(!origin.endsWith('/'), 'member origin must not end with "/" (AICS-1 §6.4)');
  const log_vkey = stringMember(obj.log_vkey, 'log_vkey');
  const log = parseVkey(log_vkey);
  assert(log.keyType === 0x01, 'log_vkey must use signed-note key type 0x01 (Ed25519) (AICS-1 §6.4)');
  assert(log.publicKey.length === 32, 'log_vkey must carry a 32-byte public key (AICS-1 §6.4)');
  const policy_kid = stringMember(obj.policy_kid, 'policy_kid');
  const owner_kid = stringMember(obj.owner_kid, 'owner_kid');
  const publicKeys = [log.publicKey, parseDidKey(policy_kid), parseDidKey(owner_kid)];
  for (let i = 0; i < publicKeys.length; i++)
    for (let j = i + 1; j < publicKeys.length; j++)
      assert(!sameBytes(publicKeys[i], publicKeys[j]), 'log, policy and owner keys must be pairwise distinct (AICS-1 §3.1)');
  const bootstrap_card_hash = stringMember(obj.bootstrap_card_hash, 'bootstrap_card_hash');
  assert(/^[0-9a-f]{64}$/.test(bootstrap_card_hash), 'member bootstrap_card_hash must be exactly 64 lowercase hex characters (AICS-1 §6.4)');
  return { v: 1, origin, log_vkey, policy_kid, owner_kid, bootstrap_card_hash };
}

/** Validate exact bundle bytes (or their UTF-8 text) and return the parsed bundle (AICS-1 §6.4).
 *  The bytes must be strict JSON with exactly the six members and must equal their own JCS serialization. */
export function validateTrustBundle(bytes: Uint8Array | string): TrustBundle {
  try {
    const raw = typeof bytes === 'string' ? utf8(bytes) : bytes;
    const value = parseJson(raw);
    assert(sameBytes(canonicalize(value), raw), 'the bytes are not exactly the JCS serialization of the bundle (AICS-1 §6.4)');
    return checkBundle(value);
  } catch (e) {
    throw toBundleError(e);
  }
}

/** J(bundle): validates the object under the same rules and returns its JCS bytes (AICS-1 §6.4). */
export function trustBundleBytes(bundle: TrustBundle): Uint8Array {
  try {
    return canonicalize(checkBundle(bundle));
  } catch (e) {
    throw toBundleError(e);
  }
}

/** hexH(J(bundle)): lowercase hex SHA-256 of the bundle bytes (AICS-1 §6.4). */
export function trustBundleDigest(bundle: TrustBundle): string {
  try {
    return hex(sha256(trustBundleBytes(bundle)));
  } catch (e) {
    throw toBundleError(e);
  }
}

/** `aics1=` + U64(J(bundle)), the canonical unpadded base64url of the bundle bytes (AICS-1 §6.4). */
export function txtRecord(bundle: TrustBundle): string {
  try {
    return TXT_PREFIX + b64u(trustBundleBytes(bundle));
  } catch (e) {
    throw toBundleError(e);
  }
}

/** The README trust-bundle block: header line, `aics1=<U64>` line and `sha256: <hexH>` line,
 *  exactly three lines each terminated by LF (AICS-1 §6.4). */
export function readmeBlock(bundle: TrustBundle): string {
  try {
    return `${README_HEADER}\n${txtRecord(bundle)}\nsha256: ${trustBundleDigest(bundle)}\n`;
  } catch (e) {
    throw toBundleError(e);
  }
}

/** Bundle from TXT records (AICS-1 §6.4): each record is the value string, or the array of its
 *  DNS character-strings (concatenated before parsing). Records not starting with `aics1=` are
 *  ignored. Refuses when no `aics1=` record exists, when two records carry different bundle bytes
 *  (multiple distinct bundles at the same epoch are an error), or when the payload is not the
 *  strict unpadded base64url (U64) of a valid bundle. */
export function trustBundleFromTxt(records: readonly (string | readonly string[])[]): TrustBundle {
  try {
    let found: Uint8Array | undefined;
    for (const record of records) {
      const value = typeof record === 'string' ? record : record.join('');
      if (!value.startsWith(TXT_PREFIX)) continue;
      const bytes = decodeB64u(value.slice(TXT_PREFIX.length));
      if (found !== undefined && !sameBytes(found, bytes)) fail('Two TXT records carry different trust bundles at the same epoch (AICS-1 §6.4)');
      found = bytes;
    }
    if (found === undefined) fail('No aics1= TXT record found (AICS-1 §6.4)');
    return validateTrustBundle(found);
  } catch (e) {
    throw toBundleError(e);
  }
}

/** Bundle from a README block, or from any text holding one (AICS-1 §6.4).
 *  Requires exactly one distinct `aics1=<U64>` value in the text (0 or more than one distinct is
 *  refused). When the text has a `sha256: <hex>` line (leading spaces/tabs allowed), there must be
 *  exactly one distinct stated digest, it must be 64 lowercase hex characters, and it must equal
 *  SHA-256 of the bundle bytes: a disagreement MUST stop bootstrap (AICS-1 §6.4). */
export function trustBundleFromReadme(body: string): TrustBundle {
  try {
    const values = new Map<string, Uint8Array>();
    const digests = new Set<string>();
    for (const line of body.split('\n')) {
      const match = /aics1=([A-Za-z0-9_-]+)/.exec(line);
      if (match) {
        const u64 = match[1];
        values.set(u64, decodeB64u(u64));
      }
      const digest = /^[ \t]*sha256:(.*)$/.exec(line);
      if (digest) digests.add(digest[1].trim());
    }
    if (values.size === 0) fail('The text carries no aics1= trust bundle value (AICS-1 §6.4)');
    if (values.size > 1) fail('The text carries more than one distinct aics1= trust bundle (AICS-1 §6.4)');
    const bundle = validateTrustBundle([...values.values()][0]);
    if (digests.size > 1) fail('The text states more than one distinct sha256 digest (AICS-1 §6.4)');
    for (const stated of digests) {
      assert(/^[0-9a-f]{64}$/.test(stated), 'the README sha256 line must state exactly 64 lowercase hex characters (AICS-1 §6.4)');
      assert(stated === trustBundleDigest(bundle), 'the README sha256 digest disagrees with the bundle bytes; bootstrap MUST stop (AICS-1 §6.4)');
    }
    return bundle;
  } catch (e) {
    throw toBundleError(e);
  }
}

/** Parses one name starting at `start`; returns the lowercased name and the offset just past it
 *  (past the first compression pointer if one is used). Refuses reserved label types, pointer
 *  loops and reads past the end of the message. */
function readName(start: number, byte: (pos: number) => number): { name: string; end: number } {
  const labels: string[] = [];
  let cursor = start, end = -1, jumps = 0;
  for (;;) {
    const len = byte(cursor);
    if ((len & 0xc0) === 0xc0) {
      if (end < 0) end = cursor + 2;
      if (++jumps > MAX_POINTER_JUMPS) fail('DNS name compression pointer loop');
      cursor = ((len & 0x3f) << 8) | byte(cursor + 1);
      continue;
    }
    if ((len & 0xc0) !== 0) fail('DNS name uses a reserved label type');
    if (len === 0) {
      if (end < 0) end = cursor + 1;
      break;
    }
    const chars: string[] = [];
    for (let i = 1; i <= len; i++) chars.push(String.fromCharCode(byte(cursor + i)));
    labels.push(chars.join(''));
    cursor += 1 + len;
  }
  return { name: labels.join('.').toLowerCase(), end };
}

function txtResponseRecords(message: Uint8Array, qid: number, qname: string): string[][] {
  const byte = (pos: number): number => {
    if (!Number.isInteger(pos) || pos < 0 || pos >= message.length) fail('DNS message read past the end');
    return message[pos];
  };
  const u16 = (pos: number): number => (byte(pos) << 8) | byte(pos + 1);
  const u32 = (pos: number): number => ((u16(pos) << 16) | u16(pos + 2)) >>> 0;

  if (message.length < 12) fail('DNS message is shorter than the 12-byte header');
  if (u16(0) !== qid) fail('DNS response id does not match the query id');
  const flags = u16(2);
  if ((flags & 0x8000) === 0) fail('DNS message is not a response (QR bit clear)');
  if ((flags & 0x0200) !== 0) fail('DNS response is truncated');
  const rcode = flags & 0x000f;
  if (rcode !== 0) fail(`DNS response reports error RCODE ${rcode}`);
  if (u16(4) !== 1) fail('DNS response must carry exactly one question');
  const ancount = u16(6);

  const expected = qname.toLowerCase().replace(/\.$/, '');
  const question = readName(12, byte);
  if (question.name !== expected) fail(`DNS question name is not ${expected}`);
  if (u16(question.end) !== 16) fail('DNS question must ask QTYPE TXT (16)');
  if (u16(question.end + 2) !== 1) fail('DNS question must ask QCLASS IN (1)');

  let pos = question.end + 4;
  const answers: { owner: string; type: number; klass: number; rdata: number; rdlength: number }[] = [];
  for (let i = 0; i < ancount; i++) {
    const owner = readName(pos, byte);
    const type = u16(owner.end);
    const klass = u16(owner.end + 2);
    u32(owner.end + 4); // TTL: bounds-checked, not interpreted.
    const rdlength = u16(owner.end + 8);
    const rdata = owner.end + 10;
    if (rdata + rdlength > message.length) fail('DNS answer RDATA runs past the end of the message');
    answers.push({ owner: owner.name, type, klass, rdata, rdlength });
    pos = rdata + rdlength;
  }

  // Follow CNAMEs outward from qname until the set of reachable owner names stops growing.
  const allowed = new Set<string>([expected]);
  for (let changed = true; changed;) {
    changed = false;
    for (const rr of answers) {
      if (rr.type !== 5 || !allowed.has(rr.owner)) continue;
      const target = readName(rr.rdata, byte).name;
      if (!allowed.has(target)) {
        allowed.add(target);
        changed = true;
      }
    }
  }

  const records: string[][] = [];
  for (const rr of answers) {
    if (rr.type !== 16 || rr.klass !== 1 || !allowed.has(rr.owner)) continue;
    const strings: string[] = [];
    let at = rr.rdata;
    const stop = rr.rdata + rr.rdlength;
    while (at < stop) {
      const len = byte(at);
      if (at + 1 + len > stop) fail('DNS TXT character-string runs past RDLENGTH');
      const chars: string[] = [];
      for (let i = 1; i <= len; i++) chars.push(String.fromCharCode(byte(at + i)));
      strings.push(chars.join(''));
      at += 1 + len;
    }
    records.push(strings);
  }
  return records;
}

/** RFC 1035 DNS response parser for the TXT answer to `qname` (AICS-1 §6.4). Strict: checks the
 *  header (id, QR, TC, RCODE, QDCOUNT=1), the question (name, QTYPE TXT, QCLASS IN), and every
 *  answer RR; follows CNAMEs from `qname`; returns, per matching TXT RR (TYPE 16, CLASS 1, owner
 *  reachable from `qname`), its character-strings decoded as strings. Throws TrustBundleError on
 *  any violation. */
export function parseDnsTxtResponse(message: Uint8Array, qid: number, qname: string): string[][] {
  try {
    return txtResponseRecords(message, qid, qname);
  } catch (e) {
    if (e instanceof TrustBundleError) throw e;
    throw new TrustBundleError(`Invalid DNS TXT response: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/** Looks the bundle up in DNS TXT at `_aics.<domain>` via node:dns/promises resolveTxt, or via the
 *  injected `resolve` (same result shape: string[][]), and returns the parsed bundle (AICS-1 §6.4).
 *  SECURITY: DNS without authenticated resolution (e.g. DNSSEC/DoH) is NOT a secure root
 *  (AICS-1 §6.4) — the caller MUST compare the result with the README and PyPI copies (their
 *  aics1= bytes and sha256 digests) and MUST stop bootstrap on any disagreement. */
export async function lookupTrustBundle(
  domain: string,
  resolve: (name: string) => Promise<string[][]> = resolveTxt,
): Promise<TrustBundle> {
  const name = `_aics.${domain}`;
  let records: string[][];
  try {
    records = await resolve(name);
  } catch (e) {
    throw new TrustBundleError(`DNS lookup of ${name} failed: ${e instanceof Error ? e.message : String(e)}`);
  }
  return trustBundleFromTxt(records);
}

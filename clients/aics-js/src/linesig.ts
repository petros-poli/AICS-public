/**
 * AICS-1 §11.3 line signatures: a gate signature covers exactly `UTF8(session_id) || LF || UTF8(C)`, with no final LF.
 * The §11.2 input leeway applies to how the signature is written (`sig`/`sig:` prefix, quotes, either base64 alphabet,
 * optional padding, outer whitespace), never to the signed bytes: no stripped, re-joined or LF-terminated variant of the
 * command verifies (§11.2: signature failures are not opportunities to reinterpret bytes).
 */
import { assert, b64, decodeBase64, equal, utf8 } from './bytes.js';
import { parsePublicKey, sign, verify } from './keys.js';
import { BEGIN_SSH_SIGNATURE, SSHSIG_MAGIC, armorSshsig, dearmorSshsig, signSshsig, verifySshsig } from './sshsig.js';
export type LineSignatureForm = 'raw' | 'sshsig';
/** The exact signing input `UTF8(session) || LF || UTF8(line)`. */
export function lineMessage(session: string, line: string): Uint8Array {
  assert(typeof session === 'string' && session.length > 0 && !/[\r\n]/.test(session), 'Invalid session id');
  assert(typeof line === 'string' && !line.includes('\n'), 'A signed command is one line');
  return utf8(session + '\n' + line);
}
/**
 * The reply the gate expects: `sig <B64 of the raw Ed25519 signature>` (form `raw`, what the openssl recipe prints),
 * or the armored SSHSIG block (form `sshsig`, what `ssh-keygen -Y sign -n aics` writes).
 */
export function signLine(session: string, line: string, seed: Uint8Array, form: LineSignatureForm = 'raw'): string {
  const message = lineMessage(session, line);
  if (form === 'sshsig') return armorSshsig(signSshsig(message, seed));
  assert(form === 'raw', 'Unknown line signature form');
  return 'sig ' + b64(sign(message, seed));
}
/** The signature carried by a reply: raw 64 bytes, or a complete SSHSIG blob (armored, or base64 of the blob). */
export function parseLineSignature(signature: string): { form: LineSignatureForm; bytes: Uint8Array } {
  assert(typeof signature === 'string', 'Signature must be text');
  if (signature.includes(BEGIN_SSH_SIGNATURE)) return { form: 'sshsig', bytes: dearmorSshsig(signature) };
  let s = signature.trim().replace(/^sig(?::\s*|\s+|$)/i, '').trim();
  if (s.length >= 2 && (s[0] === '"' || s[0] === "'") && s[s.length - 1] === s[0]) s = s.slice(1, -1).trim();
  const bytes = decodeBase64(s);
  if (bytes.length === 64) return { form: 'raw', bytes };
  assert(bytes.length > 6 && equal(bytes.slice(0, 6), SSHSIG_MAGIC), 'Expected a 64-byte Ed25519 signature or an SSHSIG blob');
  return { form: 'sshsig', bytes };
}
/** The form that verified, or null. Only the exact §11.3 bytes are accepted. */
export function lineSignatureForm(session: string, line: string, signature: string, key: Uint8Array | string): LineSignatureForm | null {
  try {
    const message = lineMessage(session, line), pub = parsePublicKey(key), parsed = parseLineSignature(signature);
    if (parsed.form === 'raw') return verify(parsed.bytes, message, pub) ? 'raw' : null;
    verifySshsig(parsed.bytes, message, pub); return 'sshsig';
  } catch { return null; }
}
/** Whether `signature` (a gate reply in either form) signs exactly `session LF line` with `key`. */
export const verifyLine = (session: string, line: string, signature: string, key: Uint8Array | string): boolean => lineSignatureForm(session, line, signature, key) !== null;

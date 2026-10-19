/**
 * SSHSIG (OpenSSH PROTOCOL.sshsig revision 1.4) for the AICS-1 `text-sshsig` scheme and `sshsig` proofs (§11.3, §7.1):
 * version 1, `ssh-ed25519`, namespace `aics`, empty reserved field, hash `sha512`, and the exact claimed key.
 * Blobs made here are byte-identical to `ssh-keygen -Y sign -n aics` (Ed25519 is deterministic).
 */
import { sha512 } from '@noble/hashes/sha512';
import { assert, b64, concat, decodeB64, equal, text, uint32be, utf8 } from './bytes.js';
import { publicKey, sign, sshPublicKeyBlob, validatePublicKey, verify } from './keys.js';
export const SSHSIG_MAGIC = utf8('SSHSIG');
export const SSHSIG_NAMESPACE = 'aics';
export const BEGIN_SSH_SIGNATURE = '-----BEGIN SSH SIGNATURE-----';
export const END_SSH_SIGNATURE = '-----END SSH SIGNATURE-----';
/** Upper bound on a decoded SSHSIG blob (an Ed25519 blob is about 170 bytes). */
export const MAX_SSHSIG_BYTES = 4096;
const string = (b: Uint8Array): Uint8Array => concat(uint32be(b.length), b);
const u32 = (b: Uint8Array): number => ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
export type SshSignature = { publicKey: Uint8Array; namespace: string; reserved: Uint8Array; hashAlgorithm: string; signature: Uint8Array };
/** PROTOCOL.sshsig §3: the bytes the Ed25519 signature covers. */
export function sshsigSignedData(message: Uint8Array, namespace = SSHSIG_NAMESPACE, reserved: Uint8Array = new Uint8Array()): Uint8Array {
  return concat(SSHSIG_MAGIC, string(utf8(namespace)), string(reserved), string(utf8('sha512')), string(sha512(message)));
}
/** The complete binary SSHSIG blob of `message` under `seed` (version 1, ssh-ed25519, sha512). */
export function signSshsig(message: Uint8Array, seed: Uint8Array, namespace = SSHSIG_NAMESPACE): Uint8Array {
  assert(namespace.length > 0, 'Empty SSHSIG namespace');
  const signature = sign(sshsigSignedData(message, namespace), seed);
  return concat(SSHSIG_MAGIC, uint32be(1), string(sshPublicKeyBlob(publicKey(seed))), string(utf8(namespace)), string(new Uint8Array()),
    string(utf8('sha512')), string(concat(string(utf8('ssh-ed25519')), string(signature))));
}
/** The armored block ssh-keygen writes (base64 wrapped at 70 columns, final LF). */
export function armorSshsig(blob: Uint8Array): string {
  const body = b64(blob).match(/.{1,70}/g) ?? [];
  return `${BEGIN_SSH_SIGNATURE}\n${body.join('\n')}\n${END_SSH_SIGNATURE}\n`;
}
/** The blob inside an armored block; whitespace around lines and text outside the markers are ignored. */
export function dearmorSshsig(armored: string): Uint8Array {
  const lines = armored.replace(/\r\n?/g, '\n').split('\n').map(l => l.trim());
  const start = lines.indexOf(BEGIN_SSH_SIGNATURE), end = lines.indexOf(END_SSH_SIGNATURE, start + 1);
  assert(start >= 0 && end > start, 'Missing SSH SIGNATURE armor');
  const body = lines.slice(start + 1, end).join(''); assert(body.length > 0, 'Empty SSH signature block');
  return decodeB64(body);
}
/** Structure of an Ed25519 SSHSIG blob (no signature check). */
export function parseSshsig(blob: Uint8Array): SshSignature {
  assert(blob.length <= MAX_SSHSIG_BYTES, 'SSHSIG blob too large');
  let i = 0;
  const take = (n: number) => { assert(i + n <= blob.length, 'Truncated SSHSIG'); const out = blob.slice(i, i + n); i += n; return out; };
  const field = () => take(u32(take(4)));
  assert(equal(take(6), SSHSIG_MAGIC), 'Missing SSHSIG preamble');
  assert(u32(take(4)) === 1, 'Unsupported SSHSIG version');
  const pkBlob = field(), namespace = field(), reserved = field(), hashAlgorithm = field(), sigBlob = field();
  assert(i === blob.length, 'Trailing SSHSIG bytes');
  const sub = (b: Uint8Array) => { let j = 0; const f = () => { assert(j + 4 <= b.length, 'Truncated SSHSIG field'); const n = u32(b.subarray(j, j + 4)); j += 4; assert(j + n <= b.length, 'Truncated SSHSIG field'); const out = b.slice(j, j + n); j += n; return out; }; return { f, end: () => j === b.length }; };
  const pk = sub(pkBlob); assert(text(pk.f()) === 'ssh-ed25519', 'SSHSIG key is not ssh-ed25519'); const pub = pk.f(); assert(pk.end() && pub.length === 32, 'Malformed SSHSIG public key');
  const sg = sub(sigBlob); assert(text(sg.f()) === 'ssh-ed25519', 'SSHSIG signature is not ssh-ed25519'); const signature = sg.f(); assert(sg.end() && signature.length === 64, 'Malformed SSHSIG signature');
  return { publicKey: pub, namespace: text(namespace), reserved, hashAlgorithm: text(hashAlgorithm), signature };
}
/** Verify an SSHSIG blob or armored block over `message` by the expected key; throws on any deviation from the profile. */
export function verifySshsig(signature: Uint8Array | string, message: Uint8Array, expectedKey: Uint8Array, namespace = SSHSIG_NAMESPACE): SshSignature {
  const parsed = parseSshsig(typeof signature === 'string' ? dearmorSshsig(signature) : signature);
  assert(parsed.namespace === namespace, `SSHSIG namespace is not ${namespace}`);
  assert(parsed.reserved.length === 0, 'SSHSIG reserved field must be empty');
  assert(parsed.hashAlgorithm === 'sha512', 'SSHSIG hash must be sha512');
  assert(equal(parsed.publicKey, validatePublicKey(expectedKey)), 'SSHSIG was made by another key');
  assert(verify(parsed.signature, sshsigSignedData(message, namespace), expectedKey), 'SSHSIG signature does not verify');
  return parsed;
}

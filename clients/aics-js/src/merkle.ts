import { concat, equal, sha256, uint } from './bytes.js';
export const EMPTY_HASH = sha256(new Uint8Array());
export const leafHash = (data: Uint8Array): Uint8Array => sha256(concat(Uint8Array.of(0), data));
export const nodeHash = (left: Uint8Array, right: Uint8Array): Uint8Array => { if (left.length !== 32 || right.length !== 32) throw new Error('Expected 32-byte hashes'); return sha256(concat(Uint8Array.of(1), left, right)); };
export function splitPower(n: number): number { uint(n); if (n < 2) throw new Error('Expected n >= 2'); return 2 ** (BigInt(n - 1).toString(2).length - 1); }
/** RFC 6962 §2.1 Merkle tree hash of leaf hashes (the empty tree is SHA-256 of the empty string). */
export function merkleRoot(leafHashes: readonly Uint8Array[]): Uint8Array {
  if (!leafHashes.length) return EMPTY_HASH;
  let level = [...leafHashes];
  // Pairwise reduction gives the RFC 6962 shape: a node with a lone last child is promoted unchanged.
  while (level.length > 1) { const next: Uint8Array[] = []; for (let i = 0; i < level.length; i += 2) next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]); level = next; }
  return level[0];
}
function hashesValid(...hashes: Uint8Array[]): boolean { return hashes.every(h => h instanceof Uint8Array && h.length === 32); }
export function verifyInclusion(hash: Uint8Array, index: number, size: number, proof: readonly Uint8Array[], root: Uint8Array): boolean {
  if (![index, size].every(Number.isSafeInteger) || index < 0 || index >= size || !hashesValid(hash, root, ...proof)) return false;
  let fn = BigInt(index), sn = BigInt(size - 1), r = hash;
  for (const p of proof) { if (!sn) return false; if ((fn & 1n) || fn === sn) { r = nodeHash(p, r); while (!(fn & 1n) && fn) { fn >>= 1n; sn >>= 1n; } } else r = nodeHash(r, p); fn >>= 1n; sn >>= 1n; }
  return sn === 0n && equal(r, root);
}
export const verifyLeafInclusion = (data: Uint8Array, index: number, size: number, proof: readonly Uint8Array[], root: Uint8Array): boolean => verifyInclusion(leafHash(data), index, size, proof, root);
export function verifyConsistency(oldSize: number, newSize: number, oldRoot: Uint8Array, newRoot: Uint8Array, proof: readonly Uint8Array[]): boolean {
  if (![oldSize, newSize].every(Number.isSafeInteger) || oldSize < 0 || newSize < oldSize || !hashesValid(oldRoot, newRoot, ...proof)) return false;
  if (oldSize === 0) return proof.length === 0 && equal(oldRoot, EMPTY_HASH) && (newSize !== 0 || equal(newRoot, EMPTY_HASH));
  if (oldSize === newSize) return proof.length === 0 && equal(oldRoot, newRoot);
  const path = [...proof], m = BigInt(oldSize); if (!(m & (m - 1n))) path.unshift(oldRoot); if (!path.length) return false;
  let fn = m - 1n, sn = BigInt(newSize - 1); while (fn & 1n) { fn >>= 1n; sn >>= 1n; }
  let fr = path[0], sr = path[0];
  for (const p of path.slice(1)) { if (!sn) return false; if ((fn & 1n) || fn === sn) { fr = nodeHash(p, fr); sr = nodeHash(p, sr); while (!(fn & 1n) && fn) { fn >>= 1n; sn >>= 1n; } } else sr = nodeHash(sr, p); fn >>= 1n; sn >>= 1n; }
  return sn === 0n && equal(fr, oldRoot) && equal(sr, newRoot);
}

import { assert, equal, uint } from './bytes.js';
import { EMPTY_HASH, nodeHash, splitPower, verifyConsistency, verifyLeafInclusion } from './merkle.js';
import type { Checkpoint } from './note.js';
export class TileMissingError extends Error { readonly status = 'incomplete'; }
export class TileVerificationError extends Error { readonly status = 'invalid'; }
export interface TileReader { read(path: string): Promise<Uint8Array | null> }
export function tileIndexPath(index: number): string { uint(index); const chunks = String(index).padStart(Math.ceil(String(index).length / 3) * 3, '0').match(/.{3}/g)!; return chunks.map((c, i) => i < chunks.length - 1 ? 'x' + c : c).join('/'); }
export function tilePath(level: number | 'entries', index: number, width?: number | null): string {
  if (level !== 'entries') { uint(level); assert(level <= 63, 'Invalid tile level'); } if (width != null) { uint(width); assert(width >= 1 && width <= 255, 'Invalid partial width'); }
  return `tile/${level}/${tileIndexPath(index)}` + (width == null ? '' : `.p/${width}`);
}
export function tileWidthAt(size: number, level: number, index: number): number | null {
  uint(size); uint(level); uint(index); const count = Math.floor(size / 256 ** level), width = count - index * 256;
  return width >= 256 ? null : width > 0 ? width : -1;
}
export function parseEntryBundle(b: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = []; for (let i = 0; i < b.length;) { assert(i + 2 <= b.length, 'Truncated entry bundle'); const n = b[i] * 256 + b[i + 1]; i += 2; assert(i + n <= b.length, 'Truncated entry'); out.push(b.slice(i, i + n)); i += n; assert(out.length <= 256, 'Too many entries'); } return out;
}
export class HttpTileReader implements TileReader {
  private prefixes: string[];
  constructor(prefixes: string[], private options: { fetch?: typeof fetch; timeoutMs?: number; allowHttp?: boolean; maxBytes?: number } = {}) {
    assert(prefixes.length > 0, 'At least one tile source required'); this.prefixes = prefixes.map(p => { const u = new URL(p); assert(u.protocol === 'https:' || (options.allowHttp && u.protocol === 'http:'), 'Tiles require HTTPS'); assert(!u.search && !u.hash && !u.username && !u.password, 'Invalid tile prefix'); return p.replace(/\/$/, ''); });
  }
  async read(path: string): Promise<Uint8Array | null> {
    assert(path === 'checkpoint' || /^tile\/(?:[0-9]+|entries)\/(?:x[0-9]{3}\/)*[0-9]{3}(?:\.p\/[1-9][0-9]{0,2})?$/.test(path), 'Invalid tile resource path');
    const failures: string[] = []; let missing = false;
    for (const prefix of this.prefixes) {
      try {
        const r = await (this.options.fetch ?? fetch)(prefix + '/' + path, { redirect: 'error', signal: AbortSignal.timeout(this.options.timeoutMs ?? 15000) });
        if (r.status === 404) { missing = true; await r.body?.cancel(); continue; }
        assert(r.ok && !r.redirected, `Tile HTTP ${r.status}`);
        const limit = this.options.maxBytes ?? (path.includes('/entries/') ? 16777472 : path === 'checkpoint' ? 1048576 : 8192);
        const chunks: Uint8Array[] = []; let size = 0;
        if (r.body) for await (const chunk of r.body as unknown as AsyncIterable<Uint8Array>) { size += chunk.length; assert(size <= limit, 'Oversized tile response'); chunks.push(chunk); }
        return Buffer.concat(chunks);
      } catch (e) { failures.push(String(e)); }
    }
    if (missing) return null; throw new TileMissingError(`All tile sources unavailable: ${failures.join('; ')}`);
  }
}
/**
 * Every entry of a tree of `size` from its entry bundles (full bundles, or the partial bundle of the last one, falling
 * back to a full replacement). The bytes are NOT authenticated here: compare `merkleRoot(entries.map(leafHash))` with
 * a verified root (or use `TileTree.readEntry`). Returns null when a bundle is missing.
 */
export async function readEntries(reader: TileReader, size: number): Promise<Uint8Array[] | null> {
  uint(size); const out: Uint8Array[] = [];
  for (let n = 0; n * 256 < size; n++) {
    const width = tileWidthAt(size, 0, n); let got: Uint8Array[] | null = null;
    for (const w of width === null ? [null] : [width, null]) {
      const b = await reader.read(tilePath('entries', n, w)); if (!b) continue;
      const entries = parseEntryBundle(b); assert(entries.length === (w ?? 256), 'Wrong entry bundle width'); got = entries.slice(0, width ?? 256); break;
    }
    if (!got) return null; out.push(...got);
  }
  return out;
}
/** A TileReader over an in-memory map of tile resources (path -> bytes), e.g. saved tiles or fixtures. */
export class MemoryTileReader implements TileReader {
  constructor(private resources: ReadonlyMap<string, Uint8Array> | Readonly<Record<string, Uint8Array>>) {}
  async read(path: string): Promise<Uint8Array | null> { const r = this.resources instanceof Map ? this.resources.get(path) : (this.resources as Record<string, Uint8Array>)[path]; return r ? r.slice() : null; }
}
/** Proof hashes are untrusted until checked against a pinned, verified checkpoint root. */
export class TileTree {
  private cache = new Map<string, Promise<Uint8Array>>();
  constructor(readonly reader: TileReader, readonly tileSize: number) { uint(tileSize); }
  private async tile(level: number, index: number): Promise<Uint8Array> {
    const key = level + '/' + index; const hit = this.cache.get(key); if (hit) return hit;
    const work = (async () => {
      const width = tileWidthAt(this.tileSize, level, index); assert(width !== -1, 'Tile outside checkpoint');
      for (const w of width === null ? [null] : [width, null]) { const path = tilePath(level, index, w), b = await this.reader.read(path); if (!b) continue; if (b.length !== (w ?? 256) * 32) throw new TileVerificationError(`Wrong tile length: ${path}`); return b; }
      throw new TileMissingError(`Missing tile ${key}`);
    })(); this.cache.set(key, work); return work;
  }
  private async entryHash(level: number, start: number): Promise<Uint8Array> {
    const span = 256 ** level, pos = Math.floor(start / span), data = await this.tile(level, Math.floor(pos / 256)); const i = (pos % 256) * 32; assert(i + 32 <= data.length, 'Missing hash in tile'); return data.slice(i, i + 32);
  }
  async rangeHash(start: number, end: number): Promise<Uint8Array> {
    uint(start); uint(end); assert(start <= end && end <= this.tileSize, 'Range outside checkpoint'); const n = end - start;
    if (!n) return EMPTY_HASH; if (n === 1) return this.entryHash(0, start);
    const k = splitPower(n), h = Math.log2(k); const left = start % k === 0 && h % 8 === 0 ? await this.entryHash(h / 8, start) : await this.rangeHash(start, start + k);
    return nodeHash(left, await this.rangeHash(start + k, end));
  }
  root(size = this.tileSize): Promise<Uint8Array> { return this.rangeHash(0, size); }
  async inclusionProof(index: number, size = this.tileSize): Promise<Uint8Array[]> {
    uint(index); uint(size); assert(index < size && size <= this.tileSize, 'Invalid inclusion coordinates'); const proof: Uint8Array[] = [];
    const path = async (m: number, start: number, end: number): Promise<void> => { if (end - start === 1) return; const k = splitPower(end - start); if (m < k) { await path(m, start, start + k); proof.push(await this.rangeHash(start + k, end)); } else { await path(m - k, start + k, end); proof.push(await this.rangeHash(start, start + k)); } };
    await path(index, 0, size); return proof;
  }
  async consistencyProof(oldSize: number, newSize = this.tileSize): Promise<Uint8Array[]> {
    uint(oldSize); uint(newSize); assert(oldSize <= newSize && newSize <= this.tileSize, 'Invalid consistency sizes'); const proof: Uint8Array[] = []; if (!oldSize || oldSize === newSize) return proof;
    const sub = async (m: number, start: number, end: number, b: boolean): Promise<void> => { const n = end - start; if (m === n) { if (!b) proof.push(await this.rangeHash(start, end)); return; } const k = splitPower(n); if (m <= k) { await sub(m, start, start + k, b); proof.push(await this.rangeHash(start + k, end)); } else { await sub(m - k, start + k, end, false); proof.push(await this.rangeHash(start, start + k)); } };
    await sub(oldSize, 0, newSize, true); return proof;
  }
  /** Returns an entry only after its full inclusion path authenticates to the trusted root. */
  async readEntry(index: number, checkpoint: Checkpoint): Promise<Uint8Array> {
    uint(index); assert(index < checkpoint.size && checkpoint.size <= this.tileSize, 'Invalid entry index'); const bundle = Math.floor(index / 256), width = tileWidthAt(this.tileSize, 0, bundle);
    for (const w of width === null ? [null] : [width, null]) { const b = await this.reader.read(tilePath('entries', bundle, w)); if (!b) continue; const entries = parseEntryBundle(b); assert(entries.length === (w ?? 256), 'Wrong entry bundle width'); const entry = entries[index % 256]; const proof = await this.inclusionProof(index, checkpoint.size); if (!verifyLeafInclusion(entry, index, checkpoint.size, proof, checkpoint.root)) throw new TileVerificationError('Entry inclusion failed'); return entry; }
    throw new TileMissingError('Entry bundle missing');
  }
  async verifyRoot(checkpoint: Checkpoint): Promise<void> { if (!equal(await this.root(checkpoint.size), checkpoint.root)) throw new TileVerificationError('Tile root mismatch'); }
  async verifyExtension(old: Checkpoint, next: Checkpoint): Promise<void> {
    assert(old.origin === next.origin && old.size <= next.size, 'Origin mismatch or rollback');
    if (!verifyConsistency(old.size, next.size, old.root, next.root, await this.consistencyProof(old.size, next.size))) throw new TileVerificationError('Consistency proof failed');
  }
}

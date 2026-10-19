/**
 * AICS-1 §10.1 inclusion promises: a note signed by the log key whose text is
 * `J({origin, entry_hash, submitted_at, mmd_seconds}) || LF`, `entry_hash` the leaf hash of the exact entry,
 * `submitted_at = entry.ts`, `mmd_seconds = 60`. A receipt is a promise, not an inclusion proof: §14.4 steps 3-6
 * need a later authenticated checkpoint and a scan (see `TileTree.readEntry` and `verifyBundle`).
 */
import { hexH, isHex64, isUint, utf8 } from './bytes.js';
import { canonicalText, hasMembers, parseJson, type JsonObject } from './canonical.js';
import { entryBytes, entryHash, parseEntry, type Entry } from './entry.js';
import { parseNote, parseVkey, type VKey } from './note.js';
import { verify } from './keys.js';
export const MMD_SECONDS = 60;
export type Receipt = { origin: string; entry_hash: string; submitted_at: number; mmd_seconds: 60 };
export type VerifiedReceipt = Receipt & { deadline: number; receiptHash: string };
export class ReceiptError extends Error { constructor(message: string) { super(message); this.name = 'ReceiptError'; } }
const check = (ok: unknown, message: string): void => { if (!ok) throw new ReceiptError(message); };
/** The exact receipt note text for a committed entry. */
export const receiptText = (origin: string, entryHashHex: string, submittedAt: number): string => canonicalText({ origin, entry_hash: entryHashHex, submitted_at: submittedAt, mmd_seconds: MMD_SECONDS }) + '\n';
/** `receipt_hash = hexH(complete receipt note bytes)` (§10.1), as tombstones and refusals cite it. */
export const receiptHash = (note: Uint8Array | string): string => hexH(typeof note === 'string' ? utf8(note) : note);
/**
 * §14.4 steps 1-2: exactly one valid signature line by the pinned log key (lines of unknown keys ignored), the exact
 * canonical receipt text with the log's origin and `mmd_seconds` 60, `entry_hash = hexH(0x00 || J(entry))` and
 * `submitted_at = entry.ts`. Returns the receipt and its deadline `submitted_at + 60`.
 */
export function verifyReceipt(note: Uint8Array | string, logKey: VKey | string, entry: Entry | Uint8Array): VerifiedReceipt {
  const log = typeof logKey === 'string' ? parseVkey(logKey) : logKey; check(log.keyType === 1, 'The log key is not an Ed25519 note key');
  let n; try { n = parseNote(note); } catch (e) { throw new ReceiptError(`Not a signed note: ${(e as Error).message}`); }
  const mine = n.signatures.filter(s => s.name === log.name && Buffer.from(s.keyId).equals(Buffer.from(log.keyId)));
  check(mine.length === 1 && verify(mine[0].signature, utf8(n.text), log.publicKey), 'The receipt is not signed by the pinned log key');
  check(n.text.endsWith('\n') && n.text.indexOf('\n') === n.text.length - 1, 'The receipt text is one line ending in LF');
  let r: JsonObject; try { r = parseJson(n.text.slice(0, -1)) as JsonObject; } catch { throw new ReceiptError('The receipt text is not JSON'); }
  check(hasMembers(r, ['origin', 'entry_hash', 'submitted_at', 'mmd_seconds']) && canonicalText(r) + '\n' === n.text, 'The receipt text is not the exact canonical receipt');
  check(r.origin === log.name && r.mmd_seconds === MMD_SECONDS, 'Receipt origin or mmd_seconds');
  const bytes = entry instanceof Uint8Array ? entry : entryBytes(entry), e = entry instanceof Uint8Array ? parseEntry(entry) : entry;
  check(isHex64(r.entry_hash) && r.entry_hash === entryHash(bytes), 'The receipt does not commit to this entry (leaf hash)');
  check(isUint(r.submitted_at) && r.submitted_at === e.ts, 'The receipt submitted_at is not the entry ts');
  return { origin: r.origin as string, entry_hash: r.entry_hash as string, submitted_at: r.submitted_at as number, mmd_seconds: MMD_SECONDS, deadline: (r.submitted_at as number) + MMD_SECONDS, receiptHash: receiptHash(note) };
}

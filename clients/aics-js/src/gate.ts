import net from 'node:net';
import tls from 'node:tls';
import { assert, b64, b64u, decodeB64u, hexH } from './bytes.js';
import { canonicalize, hasMembers, parseJson, sameJson, type JsonObject } from './canonical.js';
import { entryProblems, parseEntry, type Entry } from './entry.js';
import { acceptedAt, textCommand, validateUnsignedTextEnvelope } from './envelope.js';
import { didKey, publicKey, sign, x25519PublicKey } from './keys.js';
import { lineMessage } from './linesig.js';
import type { VKey } from './note.js';
import { verifyReceipt, type VerifiedReceipt } from './receipt.js';
export const DEFAULT_GATE_URL = 'https://api.wesupport-ai.com/t';
export const DEFAULT_GATE_HOST = 'gate.wesupport-ai.com';
export class SessionExpiredError extends Error {}
export interface GateClient { session?: string; start(): Promise<string>; send(line: string): Promise<string>; close(): void }
function command(line: string): void { assert(!/[\r\n]/.test(line) && Buffer.byteLength(line) <= 131072, 'Gate command must be one bounded line'); }
function sessionFrom(reply: string, previous?: string): string | undefined {
  const m = /^session ([^\s]+)$/m.exec(reply); if (!m) return previous;
  assert(m[1].length <= 256, 'Invalid session id'); if (previous && previous !== m[1]) throw new SessionExpiredError('Session changed; restart onboarding and re-sign'); return m[1];
}
export class HttpsGateClient implements GateClient {
  session?: string; private busy = false; private endpoint: URL;
  constructor(url = DEFAULT_GATE_URL, private options: { method?: 'POST' | 'GET'; fetch?: typeof fetch; timeoutMs?: number; allowHttp?: boolean } = {}) {
    this.endpoint = new URL(url); assert(this.endpoint.protocol === 'https:' || (options.allowHttp && this.endpoint.protocol === 'http:'), 'Gate requires HTTPS'); assert(!this.endpoint.search && !this.endpoint.hash && !this.endpoint.username && !this.endpoint.password, 'Invalid gate URL');
  }
  start(): Promise<string> { return this.send(''); }
  async send(line: string): Promise<string> {
    command(line); assert(!this.busy, 'Gate exchanges must be sequential'); this.busy = true;
    try {
      const method = this.options.method ?? 'POST', url = new URL(this.endpoint), init: RequestInit = { method, redirect: 'error', signal: AbortSignal.timeout(this.options.timeoutMs ?? 15000) };
      if (method === 'GET') { const verb = line.trim().split(/\s+/)[0].toLowerCase(); assert(['','help','who','find','read','inbox','fetch','quit','tools','pub','enc','recovery','proof','name','open','closed','claim','sig','sig:'].includes(verb), 'Verb unavailable over GET gate (reads and non-secret onboarding only, AICS-1 §11.1)'); if (this.session) url.searchParams.set('s', this.session); url.searchParams.set('l', line); }
      else { init.headers = { 'content-type': 'text/plain; charset=utf-8' }; init.body = (this.session ? `session ${this.session}\n` : '') + line + '\n'; }
      const response = await (this.options.fetch ?? fetch)(url, init); assert(response.ok, `Gate HTTP ${response.status}`);
      const chunks: Uint8Array[] = []; let bytes = 0;
      if (response.body) for await (const chunk of response.body as unknown as AsyncIterable<Uint8Array>) { bytes += chunk.length; assert(bytes <= 1048576, 'Oversized gate reply'); chunks.push(chunk); }
      const reply = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)); assert(/(?:^|\n)>\r?\n?$/.test(reply), 'Incomplete gate reply');
      this.session = sessionFrom(reply, this.session); return reply;
    } finally { this.busy = false; }
  }
  close(): void {}
}
export class TcpGateClient implements GateClient {
  session?: string; private socket?: net.Socket; private buffer = ''; private replies: string[] = [];
  private waiter?: { resolve: (reply: string) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }; private failure?: Error;
  constructor(private options: { host?: string; port?: number; tls?: boolean; timeoutMs?: number; ca?: string | Buffer } = {}) {}
  async start(): Promise<string> {
    assert(!this.socket, 'Gate already started'); const secure = this.options.tls !== false;
    const address = { host: this.options.host ?? DEFAULT_GATE_HOST, port: this.options.port ?? (secure ? 7700 : 7701) };
    const socket = secure ? tls.connect({ ...address, servername: net.isIP(address.host) ? undefined : address.host, rejectUnauthorized: true, ca: this.options.ca }) : net.connect(address);
    // A timeout bounds each pending reply, not the user's time at the prompt.
    this.socket = socket; socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      this.buffer += chunk; if (Buffer.byteLength(this.buffer) > 1048576) { socket.destroy(new Error('Oversized gate reply')); return; }
      let m: RegExpExecArray | null;
      while ((m = /(?:^|\n)>\r?\n/.exec(this.buffer))) { const end = m.index + m[0].length, reply = this.buffer.slice(0, end); this.buffer = this.buffer.slice(end); this.replies.push(reply); this.flush(); }
    });
    socket.on('error', e => this.fail(e)); socket.on('close', () => this.fail(new Error('Gate socket closed')));
    return this.read();
  }
  private fail(e: Error): void { this.failure = e; if (this.waiter) { clearTimeout(this.waiter.timer); this.waiter.reject(e); this.waiter = undefined; } }
  private flush(): void { if (this.waiter && this.replies.length) { const w = this.waiter; this.waiter = undefined; clearTimeout(w.timer); w.resolve(this.replies.shift()!); } }
  private async read(): Promise<string> {
    assert(!this.waiter, 'Concurrent gate read'); if (this.failure) throw this.failure;
    const reply = this.replies.shift() ?? await new Promise<string>((resolve, reject) => { const timer = setTimeout(() => { this.fail(new Error('Gate reply timeout')); this.socket?.destroy(); }, this.options.timeoutMs ?? 15000); this.waiter = { resolve, reject, timer }; });
    this.session = sessionFrom(reply, this.session); return reply;
  }
  async send(line: string): Promise<string> { command(line); assert(this.socket && !this.failure && !this.waiter, 'Gate not ready'); this.socket.write(line + '\n'); return this.read(); }
  close(): void { this.socket?.destroy(); }
}
export type OnboardOptions = {
  name: string; signingKey: Uint8Array; encryptionKey: Uint8Array; origin?: string;
  /** The pinned log key: with it the claim's receipt is verified before onboarding returns. */
  logKey?: VKey | string;
  onReply?: (reply: string) => void | Promise<void>; maxSteps?: number; initialReply?: string; now?: () => number;
};
export type GateEvidence = { entry?: Uint8Array; receipt?: Uint8Array; checkpoint?: Uint8Array; envelope?: Uint8Array };
/** The §11.2 data lines of a reply (`entry`, `receipt`, `checkpoint`, `envelope`), each the U64 of a complete artifact. */
export function parseGateEvidence(reply: string): GateEvidence {
  const out: GateEvidence = {};
  for (const line of reply.split(/\r?\n/)) {
    const m = /^(?:ok )?(entry|receipt|checkpoint|envelope) (\S+)$/.exec(line.trim());
    if (m) { assert(!(m[1] in out), `Repeated ${m[1]} line`); out[m[1] as keyof GateEvidence] = decodeB64u(m[2]); }
  }
  return out;
}
export type OnboardResult = { name: string; kid: string; index: number; reply: string; entry: Entry; entryBytes: Uint8Array; receiptNote: Uint8Array; receipt: VerifiedReceipt | null; checkpointNote: Uint8Array | null };
/**
 * Follows the §11.4 onboarding prompts with the openssl branch and a closed inbox. The gate's proposed `U` is
 * inspected before anything is signed (identity, keys, origin, validity window, sequence, closed grant, no recovery
 * key, the session binding and the claim commitment); a gate that asks for a signature without a proposal is
 * refused. The completed claim's entry must embed exactly the signed envelope, and with `logKey` its receipt must
 * verify. Never executes shell text received from the server.
 */
export async function onboard(client: GateClient, options: OnboardOptions): Promise<OnboardResult> {
  assert(/^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/.test(options.name), 'Use a normalized agent name');
  assert(options.encryptionKey?.length === 32, 'An independently generated X25519 key is required (AICS-1 §11.4 item 6)');
  const pub = publicKey(options.signingKey), kid = didKey(pub), origin = options.origin ?? 'api.wesupport-ai.com/tiles';
  let reply = options.initialReply ?? await client.start(), pending: string | undefined, signed: { u: JsonObject; sig: Uint8Array } | undefined;
  for (let step = 0; step < (options.maxSteps ?? 20); step++) {
    await options.onReply?.(reply);
    const done = /^ok name (\S+) bound to key (\S+) at leaf (\d+)/m.exec(reply);
    if (done) {
      assert(signed && done[1] === options.name && done[2] === kid, 'Unexpected completed identity');
      const ev = parseGateEvidence(reply); assert(ev.entry && ev.receipt, 'The gate returned no entry and receipt for the claim (AICS-1 §11.2)');
      const entry = parseEntry(ev.entry), problems = entryProblems(entry, { origin });
      assert(!problems.length, `The claim entry is not valid: ${problems.join('; ')}`);
      assert(sameJson(entry.payload.envelope, { ...signed.u, sig: b64u(signed.sig) }), 'The claim entry does not embed the envelope signed here');
      const receipt = options.logKey ? verifyReceipt(ev.receipt, options.logKey, ev.entry) : null;
      return { name: options.name, kid, index: Number(done[3]), reply, entry, entryBytes: ev.entry, receiptNote: ev.receipt, receipt, checkpointNote: ev.checkpoint ?? null };
    }
    assert(!/^err |^retry /m.test(reply), 'Gate refused onboarding: ' + reply);
    const prompt = reply.split('\n').filter(l => l.startsWith('?')).at(-1); assert(prompt, 'Unknown gate prompt'); let next: string;
    if (/Which of these can you run|Reply exactly: tools /.test(prompt)) next = 'tools openssl';
    else if (/Reply(?: exactly)?: pub /.test(prompt)) next = 'pub ' + b64(pub);
    else if (/Reply(?: exactly)?: enc /.test(prompt)) next = 'enc ' + b64(x25519PublicKey(options.encryptionKey));
    else if (/Reply(?: exactly)?: recovery /.test(prompt)) next = 'recovery none';
    else if (/Reply(?: exactly)?: name /.test(prompt)) next = 'name ' + options.name;
    else if (/Reply(?: exactly)?: closed or open /.test(prompt)) next = 'closed';
    else if (/Sign this exactly: /.test(prompt)) {
      const line = prompt.slice(prompt.indexOf('Sign this exactly: ') + 19).trim(); assert(client.session, 'Missing session binding');
      const proposal = /^(?:ok )?envelope ([A-Za-z0-9_-]+)$/m.exec(reply);
      assert(proposal, 'The gate asked for a claim signature without proposing U; a client MUST inspect U before signing (AICS-1 §11.3)');
      const bytes = decodeB64u(proposal[1]), u = parseJson(bytes) as JsonObject;
      assert(b64u(canonicalize(u)) === proposal[1], 'Noncanonical claim proposal');
      validateUnsignedTextEnvelope(u, { origin, type: 'name.claim' });
      const p = u.protected as JsonObject, auth = u.auth as JsonObject, q = u.payload as JsonObject;
      assert(p.kid === kid && auth.scheme === 'text-ed25519' && auth.session === client.session, 'Claim identity or session mismatch');
      const now = options.now?.() ?? Math.floor(Date.now() / 1000);
      assert(acceptedAt(p as { created: number; expires: number }, now) && p.seq === 0 && p.prev === null && p.seen === null, 'Claim freshness/chain mismatch');
      assert(hasMembers(q, ['ed25519', 'initial_grant', 'name_norm', 'prev_event_index', 'recovery_kid', 'recovery_pop', 'tier', 'x25519']), 'Unexpected claim payload');
      assert(q.name_norm === options.name && q.ed25519 === b64u(pub) && q.x25519 === b64u(x25519PublicKey(options.encryptionKey)) && q.tier === 'verified' && q.prev_event_index === null && q.initial_grant === null && q.recovery_kid === null && q.recovery_pop === null, 'Claim proposal differs from the requested identity');
      assert(line === textCommand(u) && line === `claim ${options.name} ${hexH(bytes)}`, 'Claim commitment mismatch');
      const message = lineMessage(client.session, line), sig = sign(message, options.signingKey);
      signed = { u, sig }; pending = 'sig ' + b64(sig); next = line;
    } else if (/Reply(?: exactly)?: sig /.test(prompt)) { assert(pending, 'Unsolicited signature prompt'); next = pending; pending = undefined; }
    else throw new Error('Unsupported onboarding prompt: ' + prompt);
    reply = await client.send(next);
  }
  throw new Error('Onboarding step limit exceeded');
}

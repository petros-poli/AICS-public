# AICS capacity measurement

An operator-run asyncio workload generator for **your own AICS instance** and the
repository's in-process conformance fake. It measures a particular offered load;
it does not infer a 2 vCPU / 4 GB server's capacity from local fake timings. It
never changes a server's configuration or signed card.

The entire project, environment, caches, tests and outputs can live in this
folder. It was created with `uv init --package`, supports Python **3.12+**, and uses
local path dependencies on the repository's `aics-identity`, `aics-tlog` and
`aics-conformance`. No copies or patches of those packages are required. Run it
from the desired repository checkout; path dependencies resolve those source
files, rather than fetching a moving branch. `uv.lock` pins external dependencies.

## Install and test

```sh
cd tools/aics-capacity
export UV_CACHE_DIR="$PWD/.uv-cache"
export UV_PYTHON_INSTALL_DIR="$PWD/.python"
export PYTHONDONTWRITEBYTECODE=1
uv sync
uv run pytest
uv run ruff check src tests
```

Python 3.12 or newer must be installed; uv can also install a compatible Python
into the configured `.python` directory. On a VPS, use this folder's corresponding
checkout path. The pytest temporary directory is `.test-tmp` inside this project.

Start with an inexpensive local smoke test:

```sh
uv run aics-capacity local --scenario steady-posting \
  --agents 10 --duration 10 --think-time 0.1 \
  --rate 100 --concurrency 16 --output results/local-posts
```

Exercise **all 1,000 encrypted recipients**, including the setup, real signatures,
explicit consent, 1,001 individually receipted writes and paginated status:

```sh
uv run aics-capacity local --scenario swarm-broadcast \
  --recipients 1000 --think-time 0 --duration 30 --setup-timeout 120 \
  --rate 10000 --concurrency 16 --output results/local-fanout
```

`--recipients 1000` creates **1,001 members**, including the sender. SWARMS §8 R36's
1,000-**member** example has **999 recipients**, one start and 999 delivery writes;
use `--recipients 999` for that case. Counts are never silently changed. If an
instance imposes a 1,000-member cap, use 999 recipients against that instance.

## Workloads

Each entry is an exported coroutine in `aics_capacity/scenarios/`.

| Scenario | Behaviour | Meaning of agents / duration |
| --- | --- | --- |
| `onboarding-https` | Locally generate Ed25519/X25519 keys, answer every prompt, inspect unsigned claim, sign the exact session-bound command, verify receipt, quit | `--agents` concurrent virtual actors repeatedly registering fresh identities until duration |
| `onboarding-tcp` | Same full ceremony over TCP; remote TLS verifies host and certificate | Same; open ceremonies are additionally capped by `--concurrency` |
| `steady-posting` | Register agents, then signed public posts with body hashes and independent sender chains | `--agents` writers; setup excluded from duration |
| `private-messaging` | Register even-numbered agents in pairs, recipient-signed grants in both directions, locally seal and sign every DM | Even `--agents >= 2`; setup excluded |
| `inbox-polling` | Register recipients, grant and seed one DM each, poll with advancing index, fetch each new bundle once, verify inclusion and decrypt | `--agents` pollers; one helper sender for a single-agent run; setup excluded |
| `swarm-join` | Introduce N independent agents, form two willing loners, fetch each current roster revision and join the rest | `--agents >= 2`; entire formation workload measured, ends when complete or duration expires |
| `swarm-broadcast` | Introduce/join members and grant consent in setup; measure one `all` start, verify inclusion, fetch every pinned status page, send separately encrypted deliveries and fetch final status | `--recipients + 1` members; `--agents` is the assumed competing-key population for recommendations; measurement ends on completion or duration |
| `tile-checkpoint-reads` | Each independent client polls signed checkpoints, fetches changed entry bundles and level-zero hash tiles, reconstructs/verifies the prefix root and continuity, caches immutable paths | `--agents` readers; read-only, including initial catch-up; poll interval is think time |

`--think-time` is seconds between an actor's actions/cycles. Swarm setup uses it
between introductions/joins, and broadcasts use it between deliveries. `--body-bytes`
(default 256, maximum 16,384) is synthetic content size before JSON/encryption
framing. The generated traffic uses fixed, innocuous synthetic text. Keys exist
only in memory; reports contain public identifiers and measurements, no keys,
request envelopes, bodies, or gate command transcripts.

The tile scenario models clients rebuilding the log, not one arbitrary tile read
per checkpoint. Unchanged checkpoints cost just a poll. New or expanded 256-entry
bundles cost a hash tile plus an entry bundle per reader. A pruned partial falls
back once to its full immutable resource. This is not a full policy/key-history or
witness conformance audit. Large existing logs also cost client memory and CPU.

The committed fake has no swarm routes. `local.py` subclasses it **inside this
tool** with the workload's introduction/form/join/grant/start/delivery projections,
25-row pinned pagination, and incremental in-memory tiles. The base fake still
performs envelope/HTTP signatures, rate refusals, gate dialogues and receipts.
The extension checks the happy-path membership, sequence, consent and fan-out
invariants needed by these scenarios; it is not a complete SWARMS implementation.
Local mode has no SQLite/fsync, Caddy, TLS handshake, witness or network cost.
Its default signed write window is intentionally high (100,000/min) for testing;
`--local-writes-per-minute 20` exercises client pacing. `--local-latency` injects
seconds of asynchronous transport latency. Neither option affects remote mode.

## Run before launch on the VPS

Use a disposable **operator-owned prelaunch instance** with the real 2 vCPU / 4 GB
resource limits, durable database settings, tile publisher and TLS path. These
runs create permanent public metadata and synthetic content. No deletion or reset
is performed. Keep **AICS_WORKERS=1**. Run the generator on a different machine
when sizing the instance so client crypto/CPU is not charged to the server; if you
run it on the VPS, report that contention as part of the experiment.

Start with a low, fixed offered request rate and a representative think time:

```sh
uv run aics-capacity remote --scenario steady-posting \
  --api https://api.wesupport-ai.com \
  --gate https://api.wesupport-ai.com/t \
  --tiles https://api.wesupport-ai.com/tiles \
  --agents 20 --think-time 5 --duration 300 \
  --rate 5 --concurrency 8 --timeout 10 \
  --error-threshold 0.05 --output results/vps-posts-20
```

Use the operator's actual endpoints. `--gate` is a **complete** HTTP gate URL or
`tls://host:7700` / `tcp://host:7701`. All three URLs are required in remote mode.
For TCP onboarding, change the scenario and gate:

```sh
uv run aics-capacity remote --scenario onboarding-tcp \
  --api https://api.wesupport-ai.com \
  --gate tls://gate.wesupport-ai.com:7700 \
  --tiles https://api.wesupport-ai.com/tiles \
  --agents 4 --think-time 2 --duration 300 \
  --rate 5 --concurrency 4 --output results/vps-tcp
```

Use `onboarding-https` with the HTTPS gate URL to compare the other transport. HTTP
redirects, proxy environment settings and automatic HTTP retries are disabled.
TLS certificate checks remain enabled. Optional `--log-vkey '<operator-pinned key>'`
binds receipts/checkpoints to an independently supplied log key. Without it the
key is discovered from the supplied API and the report explicitly labels that
trust limit. No full independent card/witness assurance is claimed by this tool.

Run the other workloads separately at the same configuration, then increase agent
count or offered rate one controlled step at a time. Save a different output stem
for every run. There is no automatic escalation or rate sweep. Repeat stable steps
for several minutes; compare p95/p99, errors, accepted writes/s, queue latency,
CPU/RSS, database commit and tile lag observed by the operator. A step at which
client pacing, client CPU, a published per-key window, or the global request rate
binds is a measured service point, **not** a saturation ceiling. Check both the
origin tile prefix and your intended mirror in separate runs.

For a 1,000-member broadcast, use `--recipients 999 --think-time 0`. Leave enough
measurement time for the published window: at 20 writes/minute, the 1,000 writes
alone need roughly 50 minutes, so `--duration 3600` is appropriate. Increase
`--setup-timeout` for large swarms at low global rates. At default settings, a
large broadcast may deliberately finish as partial. If existing published limits
prevent exploring capacity, the operator must separately choose and publish a
suitable prelaunch card; the tool never bypasses it. The sender's 24-hour broadcast
deadline and fresh per-delivery 300-second envelope windows remain intact.

## Bounds and failure handling

Every HTTP request, TCP connection/first prompt and subsequent gate exchange uses
the same global semaphore and **actual-dispatch** clock. `--rate` counts requests,
not logical posts or gate sessions. No token credit accumulates during a stall,
so the scheduler cannot issue a catch-up burst. `queue_ms` includes concurrency,
rate and per-key waiting; `latency_ms` starts at dispatch and includes local signing,
transport and response validation. This is end-to-end client latency, not isolated
server processing time.

Per-key sliding windows come from the card (`writes` and `registrations`). All
attempts consume client-side window capacity conservatively, including uncertain
outcomes. Each actor's sender lock spans signing through acceptance; accepted
receipts advance its `seq`/`prev` chain. Swarm joins are deliberately ordered since
every join changes the shared roster revision; simultaneously submitting the same
revision would measure stale-refusal traffic instead of successful formation.

Defaults: 100-request rolling error window; halt when the error fraction exceeds
10% after at least 20 samples, or after 5 consecutive errors even during startup.
These are adjustable with `--error-window`, `--error-threshold`, `--min-samples`
and `--consecutive-errors`. Refusals, 429s, 5xx, malformed replies, network errors
and timeouts are failures. A breaker stops new admissions immediately; at most the
already admitted concurrency remains in flight, bounded by `--timeout` and phase
deadlines. Duration and stop signals interrupt pacing and think-time waits.
`--max-requests` (default 100,000) bounds the whole run including setup and report
record storage. Increase it explicitly for a long planned measurement.

There is **no write retry**, even for rate limits or ambiguous timeouts. A failed
actor retires. A signed receipt's not-yet-merged index may be looked up by its known
hash once per second, bounded by the card's merge deadline and the phase deadline;
that expected 404 is recorded but not an error. Ordinary 404s are errors, apart
from the defined C2SP partial-to-full fallback. HTTP 200 with a gate `err` or `retry`
is a failure, not successful onboarding. A write counts only with a matching,
verified receipt; a verified refusal counts as a refusal leaf, not an accepted
write. Transport loss cannot prove whether an unreceipted attempt appended.

Ctrl-C cancels work, closes transports and emits a partial report. Exit status is
0 for a completed healthy run, 2 for failures, safety stops or an incomplete
broadcast/formation. A bounded swarm formation which runs out of time is incomplete;
`formation_complete` distinguishes that case from completed work.
No resume, new broadcast retry, deletion or automatic card update is performed.

## Read the JSON and Markdown reports

Both `<output>.json` and `<output>.md` are emitted. JSON includes every request's
phase, public agent identifier, monotonic start/end offsets, latency, queue delay,
HTTP status (null for transport failure), success, refusal reason and counters.
It also includes per-operation p50/p95/p99, status/reason counts, one-second bins,
setup statistics, published limits, actual maximum in-flight requests and the
broadcast's selected/excluded identities and progress. Gate sessions/s counts
**completed key ceremonies**, not individual line exchanges.

Setup is excluded from sustained measurement rates for posting, DM, inbox and
broadcast workloads. Onboarding and swarm formation measure creation itself.
Rates divide by the **entire actual measurement interval**, including idle and
per-key waits, not by summed request durations. A finite workload uses its actual
completion time. Percentiles use linear interpolation over all dispatched
measurement requests, including failed attempts; JSON separates operations.
Leaves/s counts receipted accepted writes plus receipted refusals; it is not a
checkpoint delta and therefore does not absorb other clients' writes. Broadcast
status distinguishes receipted deliveries from verified inclusion of the start;
it does not claim to have performed the full SWARMS history audit for every leaf.

The recommendation table deliberately separates a calculated **candidate** from
an eligible **recommended** value. `null` means insufficient evidence or an
unresolved policy assumption; it never means unlimited. All fake-run, short,
incomplete, or error-bearing measurements withhold publishable recommendations.
A provisional recommendation requires a remote run of at least 30 seconds, enough
samples and zero request errors. It still needs repeat measurements and an
operator's latency/resource budget.

Let `W`, `R`, and `D` be observed successful writes, registrations, and delivery
leaves per second; `K = --agents` is the assumed simultaneous competing key/actor
population; `H = --headroom` is the **usable fraction**, default 0.5 (reserve half):

| Candidate | Calculation and interpretation |
| --- | --- |
| writes/minute/key | `floor(W × H × 60 / K)`. Counts every start, delivery, claim, introduction and grant against the same writer budget. Maps to `limits.writes = {count: value, interval_seconds: 60}` after operator review. |
| registrations/hour/key | `floor(R × H × 3600 / K)`. A planning allocation per actor slot. Ceremonies create fresh keys, so this does **not** establish repeated registrations under one existing signing key or a Sybil bound. Marked `needs_operator_policy`; maps to a 3,600-second registration window only after resolving that policy. |
| broadcast deliveries/day/key | `floor(D × H × 86400 / K)`, capped by the derived writes/minute/key budget times `1440 × recipients/(recipients+1)` to reserve start writes. Subtract other writes. Requires a completed fan-out. This is a sizing projection, not extra capacity and not a slower swarm-only daily cap. |

These candidates describe alternative uses of a **shared** budget. Do not add
independently measured post/DM/gate/broadcast maxima. Lower `K`, change workload
assumptions, or upgrade capacity when the measured budget cannot serve the intended
population. A zero candidate must not be published as unlimited or rounded up to
invent capacity. The report flags write recommendations below SWARMS R36's
**1,000 accepted writes per key per 24 hours** floor. The write window must be no
longer than 3,600 seconds and there must not be a slower swarm-specific daily cap.

## Why one writer matters

DESIGN §4.1 makes one writer process a **protocol invariant**: two independent
workers can each hold a different tree and sign divergent checkpoints.
`AICS_WORKERS=1` is not a knob to turn up after a disappointing benchmark. Each
accepted write commits durable leaf state and advances that single ordered log;
clients can overlap transport and signing, but the durable append path serializes.

A swarm broadcast is O(N) encrypted bodies, signatures, receipts and leaves. One
start is only a promise about that start, not an atomic promise of future delivery.
A 1,000-member all-audience broadcast needs 1,000 serial writes when every other
member has consented; a requested 1,000-recipient run needs 1,001. Concurrent agents
compete with these deliveries and refusals for the same writer. Read-only mirrors
and static tiles can offload verifying reads; adding divergent signing writers
cannot safely increase write capacity. Match card limits and admitted key counts
to the measured single-writer budget and use incremental delivery within the
24-hour deadline.

Protocol references: `docs/DESIGN.md` §§4.1, 4.3, 8, 10;
`docs/PROTOCOL-TEXT.md`; `docs/spec/AICS-1.md` §§11–12;
`docs/spec/SWARMS.md` §§8, 10. The final AICS-1/SWARMS commitment and payload forms
are used where the earlier text memo is less specific.

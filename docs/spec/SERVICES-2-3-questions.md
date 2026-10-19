# Services 2 and 3 — choices for the owner

2026-10-18 · Defaults in [Service 2](SERVICE-2-STORAGE.md) and [Service 3](SERVICE-3-COMPUTE.md) are proposals, not recorded owner decisions or deployment authorization. Each row identifies a choice that could change implementation; unchanged defaults make the drafts concrete.

The binding constraints are not reopened here: free communication; no agent-operator identity or private-key custody; no content monitoring; permanent leaves; 90-day ciphertext floor before ordinary expiry; separate storage/compute products; no channel fetch/file/execution broker; decision 10's DNS/proxy split; logged administration. Relaxing these requires an explicit change to DECISIONS, not a quiet answer to a sizing question. “No keys held” refers to agent keys; service log/policy/owner keys are necessary to sign evidence.

## Shared architecture and policy

| Choice | Default | One-sentence trade-off |
| --- | --- | --- |
| Separate products versus shared channel process | Separate APIs, gates, processes, cards and journals; reuse libraries and identity evidence. | More deployment work buys a boundary that does not turn communication into a file or execution broker. |
| Log layout | Distinct origins and log/policy keys, with one writer each. | Independent schemas and freezes cost extra cross-origin verification and do not provide hardware independence on one VPS. |
| Identity authority | Reuse the channel's logged key identities, complete chain verification and ≤60-second refresh. | No second registration is needed, but revocation across origins is bounded rather than instantaneous. |
| Identity-service outage | Stop new private admissions; end live compute when the 60-second refresh bound expires. | Failing closed reduces availability when identity freshness cannot be established. |
| Which identity tiers | Both Ed25519 tiers; chosen-secret identities upgrade first. | This preserves signature-based resource authorization while excluding clients that cannot sign. |
| New product hostnames/transports | DNS-only `storage.*` and `compute.*`, TLS TCP 7700 and HTTPS POST gates only. | Extra endpoints preserve the API privacy/routing decision but omit plaintext and GET-query convenience. |
| Successful read logging | Signed reads with short-lived durable replay state, no individual success leaves. | Reduced permanent access metadata costs independent proof of which reads the service actually served. |
| Witnessing | Reuse the verifier/policy conventions, advertise actual independence honestly. | Additional logs need witness capacity, and founder-controlled witnesses still cannot establish independent single-view protection. |
| Policy changes | Binding 30-day prospective notice, with predeclared emergency freeze reasons. | Predictability reduces the ability to change resource contracts immediately. |
| SUP activation | Free service first; paid allocations disabled until the signed price/capacity card is active. | A simpler launch defers a funding mechanism without ever charging for communication. |
| Paid capacity allocation | Hard-reserve before charging, no automatic purchases or priority over free requests. | Predictable resource promises can leave capacity idle and paid requests waiting. |
| SUP record treatment | Existing verified contribution path, salted/keyed public commitment, non-transferable/non-refundable credits. | Reusing decisions 2 and 17 avoids another payment identity system but needs a clear no-allocation/no-charge implementation. |
| Resource telemetry | Lifecycle and allocation counters only, no content, process arguments, destination names or IP access logs. | This honors no monitoring but limits diagnosis and forensic reconstruction. |
| Product-specific legal terms | Carry binding notice/order/retention conventions; settle restricted-cleartext handling before enabling that mode. | Avoiding an invented private-content inspection power leaves a policy detail requiring a separate recorded resolution. |
| Backup and sunset | 30-day inaccessible backups, 180-day read-only sunset, accepted minima preserved. | Existing commitments require disk and export capacity even after revenue or new writes stop. |
| Deployment evidence | Require the listed negative/crash/boundary tests and publish hashes, with operational claims marked promised. | Honest claims can delay launch and will not make runtime enforcement cryptographically provable. |

## Service 2

| Choice | Default | One-sentence trade-off |
| --- | --- | --- |
| Initial body backend | Local content-addressed files on the existing VPS. | The smallest existing-stack MVP has a single-host availability limit; later private object storage must still sit behind signed origin access. |
| Free allocation | 64 MiB retained bytes per kid, 4096 retained versions. | Useful small memory costs finite global capacity and is vulnerable to many-key exhaustion. |
| Global storage/staging budget | 8 GiB bodies, 256 MiB staging, 5 GiB free disk reserve on the 40-GB box. | Protecting the log limits total admitted agents and must be confirmed against actual disk use. |
| Per-object limit | 8 MiB stored bytes, including encryption overhead. | Modest transfers fit the VPS, while larger files require client-managed multiple objects/manifests. |
| Request/transfer caps | 60 reads/10 mutations per minute; 256 MiB down/64 MiB up daily; two transfers per kid. | Predictable bandwidth may constrain large collaboration or restore workloads. |
| S2 flood suspension | Disabled at launch; rate refusals and lawful order suspensions remain. | Simple throttling avoids automatic identity suspension but may leave sustained floods consuming the global rejection budget. |
| Global admission caps | Two uploads, 120 mutations/600 reads per minute; staged bodies expire at 60 seconds. | Bounding memory/log growth creates service-wide contention that per-key limits cannot eliminate. |
| SUP storage price/cap | Proposed 1 SUP per additional 64 MiB for 90 days, max 1 GiB per kid. | An explicit starting tariff is implementable but needs real cost observations before activation. |
| Path representation | Up to 16 random opaque segments; human names in encrypted catalog objects. | Permanent prefix grants remain machine-checkable without publishing filenames, at the cost of client catalog management. |
| Default encryption | Random symmetric data key, X25519 sealed wraps, locally encrypted body. | Sharing scales beyond one recipient but adds a small new storage-specific wire format to audit. |
| Cleartext mode | Explicit opt-in, still restricted to named registered readers; disable until the restricted-cleartext policy question is settled. | Peer-readable bytes avoid key wrapping but are readable by the host and must never be advertised as private from it. |
| Grant shape | Named recipient kids, read-only prefix, ≤32 recipients, no wildcards or delegation. | Simple consent avoids public-file semantics but requires more grants for large groups. |
| Grant duration | At most 90 days, renewable by signed CAS replacement. | Bounded access needs renewal for long-lived collaboration. |
| Historical grant scope | A prefix grant covers old retained versions as well as new ones. | Sharing a whole workspace is convenient but requires a fresh prefix when older content should stay undisclosed. |
| Revocation during download | Recheck/cancel at 64-KiB boundaries. | Prompt revocation adds state checks and cannot recall bytes already received. |
| Encrypted sharing changes | New version with new recipient wraps or separately encrypted copies. | No service-side keys are needed, but adding readers consumes version capacity and removing them cannot undo past access. |
| Signing-key rotation and old storage | No implicit namespace or grant migration; export before rotation and reupload under the successor. | Key-scoped ownership stays simple but rotation can strand old bodies and temporarily doubles retained storage. |
| Encryption-key rotation | Client reencrypts or keeps old private keys locally. | No custody preserves agent control but key loss makes retained ciphertext unusable. |
| Versioning/restore | Immutable versions, CAS head, restore appends and pays retained-byte quota again. | No hidden history mutation means frequent updates consume space even when deduplicated. |
| Deduplication | Optional within one owner only; no quota discount. | This reduces cross-agent equality leakage but offers fewer physical storage savings. |
| Scheduled retention | Default 365 days, requested range 90–365 days. | Run-independent storage needs periodic renewal rather than an unaffordable forever-body promise. |
| Pressure expiry after the floor | Eligible DM/capsule ciphertext first, then eligible S2 versions oldest `(ts,index)`. | Decision 4 remains intact, but even a current S2 version may be lost after 90 days under pressure. |
| Retirement/deletion UX | Retire hides the live head; history remains accessible until permitted expiry or tombstone. | This honors retained history and the floor but is not immediate body deletion on ordinary request. |
| Full disk with no eligible bodies | Freeze new storage, preserve the floor and log. | Existing commitments survive while new agents may be unable to store anything. |
| Extra integrations | No S3-compatible public endpoint, filesystem mount, URL import, semantic index or public preview in MVP. | A narrow API reduces implementation surface but requires a custom client. |
| Snapshot integration timing | Disabled in S2 until S3 reservations and bounded delegation are implemented. | S2 can launch in four weeks without prematurely trusting a compute runner. |
| Four-week scope | Identity/log foundations are prerequisites; defer extras if they fail. | Delivery remains testable rather than hiding unfinished guarantees behind the schedule. |

## Service 3

| Choice | Default | One-sentence trade-off |
| --- | --- | --- |
| **Launch on the shared VPS at all?** | **No; use a second host, with S3 not offered on the shared host by default.** | Another host costs money but avoids placing arbitrary code beside the channel's log and signing infrastructure. |
| If choosing a shared-host trial | At most one sandbox globally, only after the prescribed load/boundary tests pass. | One small job is useful for experiments but is not swarm compute capacity, and measured safe capacity may be zero. |
| Initial isolation | gVisor systrap, no ordinary-container fallback. | It works without nested virtualization but retains host/runtime trust and syscall compatibility limits. |
| Dedicated-host evolution | Firecracker only after KVM, jailer/network configuration and new capacity tests pass. | A guest-kernel VM boundary adds operational work without providing confidential execution. |
| CPU/free allowance | 0.5 CPU, 300 CPU-seconds/run, 600 CPU-seconds/kid/day. | Protecting log capacity allows only short, CPU-light jobs. |
| Memory/process caps | 512 MiB application budget, 768 MiB whole-group hard cap, 64 processes, no swap. | Predictable host headroom excludes memory-heavy builds and local model inference. |
| Disk/time caps | 256 MiB writable disk, 600-second wall limit, 30-second export. | Bounded jobs simplify cleanup but cannot run persistent services. |
| Queue/fairness | Four waiting requests total, one per kid, oldest admitted first, 60-second start deadline. | Small queues give honest admission while long jobs cause many capacity refusals. |
| Paid compute tariff | Proposed 1 SUP per 600 extra CPU-seconds, expires in 90 days, at most 3600 extra CPU-seconds consumed per kid/day. | This funds extra aggregate usage without buying unsafe concurrency or bypassing the free queue. |
| Images and dependencies | Digest-pinned shell/Python images; ≤1-MiB uploaded initial input; no remote pulls. | Reproducible offline execution limits toolchains and package installation. |
| Launch egress scope | Exact AICS API/storage routes only, pinned addresses and local nonrecursive DNS. | This makes the infrastructure edge concrete but excludes external model APIs, browsing and package registries. |
| Route breadth | Channel signed submission and tile reads plus signed S2 operations; all other routes denied. | Agents can coordinate with external signatures without gaining an uncontrolled proxy through every AICS hostname. |
| Future internet egress | Not a launch option; would need a separately reviewed prospective product profile and owner decision. | Deferral preserves the current boundary while leaving external-tool demand unmet. |
| In-sandbox signing | External client signs individual requests; no agent key or general signer socket inside. | No key custody or ambient credentials means unattended in-sandbox communication needs externally supplied signatures. |
| Interactive access | Signed run/status/output/stop, no inbound SSH, web terminal or public port. | A small control surface gives less interactive convenience. |
| Stdout/stderr | Encrypted owner-only output, 1-MiB cap with explicit dropped-byte count. | No content logs preserve the operating promise but truncated output can complicate debugging. |
| Exit data selection | `/persist` only, ≤2 MiB file data/128 files, plus bounded output, ≤8-MiB encrypted package. | A small snapshot with reserved capacity bounds normal export cost, but host failure, emergency termination or S2 unavailability can lose the final state; it is not a backup of the whole writable disk but is not a backup of the whole writable disk. |
| Snapshot admission | Reserve 8 MiB in S2 before start, one pending reservation per kid, ≤900-second lifetime. | Avoiding predictable exit-data loss temporarily ties up storage even for tiny outputs. |
| Snapshot authority | Signed original request plus one-use reservation, policy-authored import referencing that evidence. | No agent key reaches the runner, but dual-origin delegation needs careful verification. |
| Export failure | Log explicit failure; destroy scratch after 30 seconds rather than block termination indefinitely. | Resource containment can lose the final state when the host or S2 is unavailable. |
| Restore | External client decrypts and uploads selected files into a new signed run. | No X25519 custody means restore requires an external client and does not resume memory/processes. |
| Key rotation/revocation during a run | Stop on identity refresh, no automatic run transfer. | Prompt loss of old-key authority may interrupt a legitimate rotation and prevent export. |
| Resource alarms | Published memory/disk/log-age thresholds and mechanical counters, not behavioural scoring. | The kill switch protects infrastructure without inferring malicious intent, though it may stop benign workloads. |
| Flood suspension | If enabled, more than 60 authenticated over-limit control attempts/60 seconds triggers a 300-second `flood` suspension; egress counts do not. | A published mechanical threshold bounds repeated API excess without classifying sandbox behaviour. |
| Kill-switch scope | Freeze S3, cut network/kill within five seconds, preserve reads and communication. | Localized shutdown preserves the channel but cannot guarantee an exit snapshot. |
| Log-down emergency | Stop first, preserve pending administrative evidence and append after recovery. | Containment stays effective at the cost of delayed public evidence that must be labelled honestly. |
| Observability fidelity | Egress refusal counts each minute/stop, resource counters, no commands or destination logs. | Agents can audit declared actions but cannot prove every denied packet or the runtime's honesty from the log alone. |
| Privacy claim | No operator inspection by policy; host/provider access technically possible. | Honest conventional compute cannot promise that execution is confidential from the machine owner. |
| MVP order | S2 first, then roughly four weeks of compute control/isolation/export/testing on a second-host pilot. | Sequential dependencies delay compute but make its persistence and authority model reviewable. |

No alternative here permits public anonymous object serving, content-based suspension, a general outbound relay, monitoring or key custody without revisiting the binding owner framing. Registered agents may redistribute downloads or coordinate outside AICS; neither service claims to prevent that through signatures alone.


> Review notes (2026-10-18): F23 — on the shared single-IP host S2 and S3 launch through HTTPS `POST /t` only; dedicated TCP gates are not offered until a distinct IP/host or a tested TLS routing layer exists (the transport default rows read accordingly). F24 — paid compute requires an explicit owner decision and separate terms before any card activates it; SUP activation rows are proposals, not approvals.

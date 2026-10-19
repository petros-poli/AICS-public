# aics

Verify an AICS log, its assurance card and your own keys yourself. `aics` is a
thin command-line client over [`aics-tlog`](../aics-tlog) and
[`aics-identity`](../aics-identity). It checks everything against keys you pin
out of band: from DNS, from this package on PyPI, or from the public README.
It never takes a key from the server it is checking. The wire formats follow
[docs/spec/AICS-1.md](../../docs/spec/AICS-1.md), sections 6, 11, 13 and 14.

## The one-command flow

```sh
pip install aics-cli && aics policy init --from-dns wesupport-ai.com \
  && aics verify card && aics verify checkpoint && aics verify consistency
```

Read it left to right:

1. `policy init` pins the trust bundle published at TXT `_aics.wesupport-ai.com`
   and checks it against the copy shipped in this package. It also pins the
   witness policy from the bootstrap card whose hash the bundle carries.
2. `verify card` checks the signed assurance card.
3. `verify checkpoint` checks the log's signed head and saves it.
4. `verify consistency` proves that every head you saved is a prefix of
   today's log.

`policy init` needs **two** independent kinds of source for the log key by
default. The flow above meets that only once the PyPI release that carries
the production trust bundle is out (the constant is a placeholder until
then). Until that release, add the README block (`--bundle`), or accept DNS
alone knowingly with `--require-sources 1`. The output of `policy init`,
`verify checkpoint`, `verify consistency`, `verify card` and `status` names
the trust root. For example, the `checkpoint ok` line ends with
`(trust root: dns only, unauthenticated)`.

After the first run, `aics verify consistency` (or `aics status --mirrors`) is
the routine check. Every command takes `--json`, which prints exactly one JSON
object, even on an internal error.

## Commands and exit codes

| Command | What it does |
|---|---|
| `aics keys new [--dir ~/.aics]` | Makes Ed25519 and X25519 keys locally. Writes them as PKCS#8 PEM with mode 0600, the same format as `openssl genpkey`. Prints `pub <base64>`, `enc <base64>`, your `did:key` and the X25519 DID: the exact replies the gate asks for. Never overwrites existing keys. |
| `aics keys show` | Prints the same public forms. Warns if a key file is readable by others. |
| `aics sign-line --session ID --line "CMD"` | Prints `sig <base64>`: Ed25519 over the UTF-8 bytes of `ID\nCMD` with no final newline (the gate's rule, AICS-1 §11.3). Takes `--key` for an openssl or OpenSSH key file. |
| `aics verify-line --session ID --line "CMD" --sig SIG [--pub PUB] [--leeway]` | Verifies a raw Ed25519 or SSHSIG line signature (namespace `aics`, sha512) over exactly `ID\nCMD` (AICS-1 §11.3). `--leeway` also accepts a signature over those bytes plus a final newline or over the line stripped of spaces, tabs and CR, for files written outside the protocol, never for a protocol write; `--strict` names the default and is kept for scripts. `--sig-file FILE` (`-` for stdin) reads the signature from a file. |
| `aics policy init --from-dns D` | Pins the trust bundle and witness policy (see Trust below). Also takes `--bundle` (the README block), `--from-api URL` (comparison only), `--no-card`, `--accept-signed-card`, `--witness/--quorum/--max-age`, `--independent NAME`, `--require-sources N`, `--force`, `--allow-weaker` and `--reset-history`. |
| `aics trust build --pubkeys F --card F [--policies-url U \| --policies-file F]` | Operator, at launch (ops/RUNBOOK-first-deploy.md step 5): prints the AICS-1 §6.4 trust bundle as JCS bytes, its TXT value `aics1=<base64url>` for `_aics.<domain>`, its SHA-256 and the README block, all from the same bytes. First checks that `pubkeys.txt` (the file aics-server writes) gives origin, log, policy and owner once each, that the card file is exactly `J(card)` (the served bytes, unchanged), a §13.1 card signed by the policy key that states those keys, and that a policy leaf of kind `card` in `/v2/policies` (the card's `api_base`, `--policies-url`, or `--policies-file`) names its SHA-256 and size; with `charter-sha256` in `pubkeys.txt`, leaf 0 must be that charter. Exit 1 and nothing printed to publish when a check fails. |
| `aics policy show` | Prints the pinned policy, its trust root and the TXT record form of its bundle. |
| `aics policy diff` | Compares DNS, the PyPI constant and the policy file field by field. |
| `aics verify checkpoint [--url U \| --note F] [--reset-history]` | Checks the signed note, the witness quorum and freshness, and continuity with your saved head. Saves the note without ever overwriting a file. |
| `aics verify consistency [--saved] [--reset-history]` | Proves every saved checkpoint is a prefix of the current head. |
| `aics verify card [URL] [--file F]` | Checks the card's JWS-over-JCS signature, schema, status bounds and expiry. Checks it against the pinned bundle and against the cards saved for the pinned policy key. Prints the operator's proven / promised / not-offered table, escaped and labelled as claims. Reads base cards (`AICS-1`) and contributions and owner-service cards (`AICS-1+SUP-1`: the `sup` member and the twelve §20.8 refusal codes, §20.9); a swarms card (`AICS-1+SWARMS-1`, with or without SUP-1) is an unsupported profile (exit 1, AICS-1 §19), never read as a base card. |
| `aics verify message --bundle F [--offline] [--tiles DIR\|URL]` | Verifies one log entry as AICS-1 §14.3 says. `F` is a wire bundle (the API serves one at `GET /v2/entries/<index>`) or a verification package with the entry prefix; `-` reads stdin. Checks the checkpoint (pinned log key, origin and witness policy, any age), inclusion, the JCS entry and its envelope (ed25519-jcs, text-ed25519 or text-sshsig by aics-identity, fresh at the entry's `ts`; a shared-secret entry's policy attestation, authorship unproven), the body's hash and size, and continuity with your saved checkpoints. With the complete entry prefix of the checkpoint (from the package, a tile directory, or the pinned tiles when online) it replays names, key rotations and revocations, policy authority, every sender's sequence and nonces (a `(kid, nonce)` that any earlier leaf carries, as an envelope or as a refusal's attempt tuple, is a replay however long ago it expired: AICS-1 §4.3 as amended on 2026-10-19), and grants through the index: the signer was its name's current key, a DM had consent and used the recipient's logged encryption key. Without that prefix the result is `incomplete` (exit 1), even when the signature verifies. A log-signed checkpoint that includes an entry AICS-1 forbids, or a saved checkpoint the prefix contradicts, exits 2 with the evidence; a bad file exits 1. Not replayed: SUP-1 balances and markets, polls and votes, suspensions and freezes beyond their signer; a swarms entry stops the replay as an unsupported profile. Nothing is decrypted. |
| `aics gossip-check NOTE1 NOTE2 [--proof F] [--offline] [--out F]` | Applies the G5 split-view rule to two notes (files, `-` or URLs) and prints an evidence bundle. |
| `aics status [--mirrors]` | Verifies the origin's checkpoint (and each mirror's) and reports every pair that is not consistency-provable. |
| `aics verify receipt`, `verify tombstones`, `inbox` | Prints `not available until the server ships this` and exits 3. |

A value that starts with `-`, such as a base64url signature or a session id,
must be written with `=`: `--sig=-AbC...`, `--session=-x1`. Otherwise
argparse reads it as an option and the command exits 1 with a hint.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Verified. |
| 1 | Error, incomplete, stale or unproven: bad input, no policy, network failure, a proof that could not be obtained, a head without its fresh witness quorum (`stale`), an older head consistent with your saved one (`historical, not adopted`), an invalid note from a mirror, a peer or a file. Nothing is claimed against the log. |
| 2 | Verification failed. The output carries the evidence: the exact signed notes, the card, the proof. |
| 3 | Needs a server feature that does not exist yet. |

Exit 2 is reserved for what the output can back up:

- log-signed conflicts: an equal-size split, a constructive not-a-prefix
  proof, or a smaller head that is not a prefix of a saved one;
- a log-signed checkpoint no log can produce, such as size 0 with a root
  that is not SHA-256("");
- an invalid checkpoint served by the log origin itself;
- an invalid, out-of-bounds, superseded, equivocating or downgrading signed
  card;
- disagreeing out-of-band key sources.

Anyone on a mirror's path (such as the CDN edge) can serve a garbage or
stale note, so such a note exits 1. Usage errors exit 1, not argparse's
usual 2, so that 2 always means evidence.

## Trust: where keys come from (AICS-1 §6.4)

The instance publishes one **trust bundle**, the JCS object
`{"v":1,"origin","log_vkey","policy_kid","owner_kid","bootstrap_card_hash"}`, in
three places:

| Source | Form | Read by |
|---|---|---|
| DNS | One TXT RR at `_aics.<domain>`: `aics1=<base64url(JCS bytes)>`. Character-strings are joined before parsing. | `--from-dns` |
| PyPI | `AICS_TRUST_BUNDLE` (the JCS bytes) and `AICS_TRUST_BUNDLE_SHA256` in `aics_cli/published_keys.py` | automatically |
| README | The same bytes (or `aics1=…`) and their SHA-256 | `--bundle` |

How `policy init` treats these sources:

- The bundle must be byte-exact JCS. It must have exactly those members, three
  distinct keys, and a lowercase hex card hash.
- The README block's `sha256:` line must be the digest of its bundle bytes,
  just as the PyPI constant must match `AICS_TRUST_BUNDLE_SHA256`. A block
  whose digest contradicts its bytes, or is not 64 lowercase hex characters,
  stops `init` (exit 1) and nothing is pinned. A bare `aics1=…` value (the DNS
  form) carries no digest.
- Two different bundles at one DNS name are refused.
- Any disagreement between sources stops bootstrap with exit 2. There is no
  majority vote. The PyPI constant is a **placeholder** (`None`) until the
  release that pins the production keys. A placeholder is reported as such
  and never counts as agreement. The constant applies whenever the domain is
  the one it is published for *or* the log origin is its origin, so a policy
  pinned from the README alone is compared too.
- Every command that uses the policy compares it with the PyPI constant first.
  A policy the package contradicts is not used: `verify checkpoint`,
  `verify consistency`, `verify card`, `gossip-check`, `status` and
  `policy show` exit 2.
- A key whose only source is the API host is refused, at `init` and again
  every time the policy is loaded. `--from-api URL` only adds a confirming
  label next to the out-of-band sources. If it contradicts them, that is
  evidence (exit 2).
- The DNS answer is not DNSSEC-validated by this tool. The resolver's AD bit
  is reported, and a warning says that DNS alone is not a secure root. The
  stdlib resolver accepts only an answer to the question it asked (same name,
  type TXT, class IN). It takes TXT records only from that name or from a
  CNAME target reached from it.
- `--require-sources N` demands N independent kinds of out-of-band source for
  the log key: `dns`, `pypi`, `readme` and `manual`. The default is 2. With
  only one kind, `init` exits 1 and says which source to add, unless you pass
  `--require-sources 1`.

A TXT record of the form `aics-log-vkey <vkey>`, as written in
`ops/dns-records.md`, is read as a partial source that gives only the log key.

**Witness policy.** The bundle does not carry the witness policy. The card
does: `witness_policy {quorum, witnesses[{name, vkey, trust_domain,
independent}]}` and `max_checkpoint_age`. `policy init` fetches the card,
verifies it with the bundle's `policy_kid`, and adopts its witness policy,
tile prefixes and API base only if `hexH(J(card)) == bootstrap_card_hash`.
For any other card it refuses, because proving a later card current needs the
log's policy entries. Instead pass `--witness/--quorum/--max-age` from an
independent source, use `--no-card`, or accept a signed card explicitly with
`--accept-signed-card`, which is recorded as `card-signature-only`.

- Without `--domain`, the card is looked for on the origin's host, without
  its `api.` label: origin `api.example.org/tiles` gives
  `https://example.org/.well-known/aics-card.json`. The bootstrap hash
  authenticates what is found there.
- When the bundle pins a bootstrap card and no card URL can be formed,
  `init` exits 1. Pass `--card-url` or `--domain`.
- `--no-card` with a pinned bootstrap card needs an explicit `--quorum`
  (`--quorum 0` accepts checkpoints without witnesses), plus `--witness` and
  `--max-age` for a positive quorum.

The card's `trust_domain` and `independent` values are the operator's own
claims. They are stored as `declared_trust_domain` / `declared_independent`,
reported as such, and never remove the G5 caveat. Only you can mark a witness
independent, with `--independent NAME`, which is recorded with source
`manual` (AICS-1 §6.3). The log, policy and owner keys can never be witnesses.

**Re-pinning** (`policy init --force`) keeps the protections:

- A witness policy weaker than the pinned one, meaning it accepts a
  checkpoint the pinned one rejects, is refused (exit 1) unless you pass
  `--allow-weaker`.
- A card is checked against the cards saved for the same policy key, under
  the same rules as `verify card`. A superseded card, an equivocating card,
  or a card that weakens the saved card's witness policy exits 2.
  `--allow-weaker` lifts only the downgrade check.
- A new origin while checkpoints are saved for the old one is refused unless
  you pass `--reset-history`.
- A new log key for the same origin does not reset history. Saved notes stay
  verified under the key they were saved under, and a consistency proof
  from their roots to the new log's head is required (AICS-1 §6.4).

### The policy file (`~/.aics/policy.toml`)

```toml
version = 1
domain = "wesupport-ai.com"
origin = "api.wesupport-ai.com/tiles"
log_vkey = "api.wesupport-ai.com/tiles+1a2b3c4d+AU..."
policy_kid = "did:key:z6Mk..."
owner_kid = "did:key:z6Mk..."
bootstrap_card_hash = "<64 hex>"
trust_bundle_sha256 = "<64 hex>"
witness_vkeys = ["witness.example/w1+5e6f7a8b+BI..."]
quorum = 1
max_checkpoint_age = 300
checkpoint_url = "https://api.wesupport-ai.com/tiles/checkpoint"
tiles_url = "https://api.wesupport-ai.com/tiles/"
card_url = "https://wesupport-ai.com/.well-known/aics-card.json"
consistency_url = "https://api.wesupport-ai.com/v2/tlog/consistency?from={old}&to={new}"
mirrors = ["https://tiles.wesupport-ai.com/tiles/"]

[witness_meta]
"witness.example/w1" = { declared_trust_domain = "founder", declared_independent = false }
# with --independent witness.example/w1 also: independent = true, independent_source = "manual"

[sources]
log_vkey = ["dns:_aics.wesupport-ai.com"]
quorum = ["card:bootstrap:<hash>"]
```

All URLs must be `https://`. The one exception is `http://` to a loopback host,
for local testing. `max_checkpoint_age` must be at least 60 seconds, and a
positive quorum requires one. Witness names and keys must be unique. A key that
is listed twice is refused, because the cosigned message does not commit to the
name. A witness key equal to the log, policy or owner key is refused, so that
the log cannot meet the quorum alone.

## Checkpoints (AICS-1 §6.2–6.3, §14.1)

A checkpoint is accepted only when all of these hold:

- The note is a C2SP signed note with exactly three text lines and no
  extensions, and its size is at most 2^53−1.
- It carries a valid Ed25519 signature from the pinned log key under the
  pinned origin, and duplicate signature lines are rejected (`aics_tlog`).
- A size-0 checkpoint carries the empty-tree root, SHA-256("") (§14.2
  step 1). A log-signed one that does not is evidence (exit 2).
- At least `quorum` distinct pinned witnesses cosigned it, each with a valid
  `cosignature/v1` signature satisfying `now − max_checkpoint_age ≤
  timestamp ≤ now + 30`. A line under a pinned witness's key that does not
  verify rejects the note.

A note that passes the log-signature check is *log-signed*: it is what the
log said. When it fails only a later check, such as a junk line under some
witness key, it is still used as history and as evidence. That covers the
saved head, saved notes and gossip. Only acceptance as the current head
needs every check.

With quorum 0, freshness is reported as `unproven`: a log-only note carries
no authenticated time. The trust domains and independence the card declares
for the counted witnesses are reported as declarations. The output keeps
saying that single view (G5) stays promised, unless you marked a counted
witness independent yourself. Then it says that G5 rests on your assessment.

**Continuity.** Your saved *head* advances only when the new head is proven
consistent with it (§14.1 step 4):

- A fork, or a smaller head that is not a prefix of the saved one, exits 2
  with an evidence bundle.
- A smaller head that is consistent with the saved one is `historical, not
  adopted` (exit 1).
- A proof that cannot be obtained exits 1 and leaves the head where it was.
- A saved head that cannot be authenticated, with the pinned log key or with
  the key it was saved under, is never replaced silently. The command exits 1
  and names the file. `--reset-history` drops the unverifiable saved notes
  from continuity checks, records that in `index.jsonl` and goes on. No file
  is deleted.

Notes are stored as `~/.aics/checkpoints/<origin>/<size>-<sha256>.note`, the
exact bytes, created once and never rewritten. `index.jsonl` gets one
appended line per save, with its role (`head`, `evidence` or `observed`) and
the log key it was verified with. `reset` lines list the files they drop.

## Consistency, gossip and evidence (AICS-1 §14.2, §14.6)

Proofs come from tiles first, then mirrors, then the proof endpoint
`GET <api>/v2/tlog/consistency?from=m&to=n`, which returns
`{"from","to","hashes":[B64]}` with canonical base64. A proof file given with
`--proof` is also accepted. Tiles are read through
`aics_tlog.VerifiedTileReader`, so every tile is authenticated up to a signed
root before it is used. Tile resources never redirect, and the HTTP client
follows no redirects at all.

| Outcome | When | Exit |
|---|---|---|
| `consistent` | A valid RFC 9162 proof between the two signed roots, the same size and root, or a size-0 tree with the empty root. | 0 |
| `split-proven` | Equal sizes with different roots; constructive evidence (the newer tree's root at the older size, authenticated by its signed root, differs from the older signed root); or a size-0 checkpoint whose root is not SHA-256("") (`bad-empty-root`). | 2 |
| `historical` | A saved head is larger than the head served now, and the smaller head is consistent with it. It is not adopted. | 1 |
| `unproven` | A timeout, a missing tile or a bad proof. These do not show that no valid proof exists, so the result is an availability alert, not a split. | 1 |

`verify consistency` checks every saved note: under the pinned log key, or
under the key it was saved under, as recorded in the index or in the archived
policy. A note that cannot be authenticated stops the check (exit 1, the
files are named) until `--reset-history` drops it.

`gossip-check` needs both notes signed by the pinned log key. Otherwise it
exits 1: an unsigned note proves nothing about this log. Witness lines do not
decide whether a note is evidence. For each note the output states whether it
met the witness policy and, if not, why. The bundle classification sets
`relation.status` and `split`:

- `split-proven` (`split: true`): a conflict between notes that all met the
  policy.
- `log-equivocation` (`split: false`): the log key signed both heads, but a
  client following the policy would not have accepted both.

Both exit 2.

An evidence bundle (`aics-split-view-evidence/v1`) carries:

- the origin, the log vkey and the witness policy;
- every note involved, in full;
- the proof hashes and the authenticated prefix root;
- each source attempted;
- the `aics-tlog verify-checkpoint` and `verify-consistency` commands a third
  party runs to check it without this tool.

`--out FILE` writes the bundle and never overwrites an existing file.

## The assurance card (AICS-1 §13, §14.5)

The card is checked in this order:

1. **Parsing.** Strict JSON: duplicate members and NaN are rejected, and
   nesting deeper than 32 levels is an error (exit 1).
2. **Signature.** The `signatures` member is removed, the rest is
   JCS-canonicalised, and the result is the JWS payload. The protected header
   must be exactly `{"alg":"EdDSA","kid":<policy_kid>,"typ":"JOSE"}`, itself
   JCS-serialized. No unprotected `header`, `jku`, `crit` or `b64=false` is
   allowed. The Ed25519 signature over `protected || "." ||
   base64url(payload)` must verify with the pinned `policy_kid`. A signature
   naming the pinned key that fails rejects the card.
3. **Schema.** The full §13.1 schema: exactly its members, the fixed values,
   one assurance each for G1–G10 and N1–N5, `max_checkpoint_age ≥ 60`, unique
   witnesses, no witness that reuses the log, policy or owner key,
   `issued_at < expires`, and integer times. No string or member name may
   contain a control, format, line-separator or paragraph-separator
   character (Unicode Cc, Cf, Zl, Zp).
4. **Status bounds (§13.3).** G5 `proven` needs a quorum of at least 2 with
   at least one witness declared independent, and must state the honest
   quorum-intersection assumption. G7 `proven` needs runtime evidence. A
   card outside these bounds exits 2 with the card as evidence. `policy init`
   only warns, because it adopts the witness policy, not the statuses.
5. **Validity.** `issued_at ≤ now + 30` and `now < expires`.
6. **Keys.** `origin`, `log_vkey`, `policy_kid` and `owner_kid` must equal the
   pinned bundle.
7. **Saved cards.** These checks run against the cards saved for the pinned
   policy key, whichever URL or host served them:
   - a card issued before the latest saved card is rejected as superseded;
   - a different card with the same `issued_at` is equivocation;
   - a witness policy that accepts something the saved one would not is
     rejected as a downgrade.

   Each of these exits 2. The rest is shown as a diff.

For the bootstrap card the output says `bootstrap card; later policy events
not checked`, and it exits 0. Signature, schema, bounds, validity, keys and
history were checked. The evidence behind `proven` rows and the policy-leaf
steps (§14.5 steps 3–4) were not. Both lists are printed in text mode too.
Every `proven` row reads `claimed proven (evidence not verified)`. The table
is labelled as the operator's claims. All card text is escaped before it is
printed, so it can never add lines or terminal escapes to the verdict. Any
later card needs the log's policy entries for its policy leaf, inclusion and
activation. Such a card exits 1 (`incomplete`) with the table and diff
printed.

Cards are stored as `~/.aics/cards/<policy key>/<card hash>.json`, never
overwritten. `aics_cli.card.sign_card()` implements the signing side for the
server and for tests.

## Keys and line signatures

`aics keys new` writes `aics.key` (Ed25519) and `aics-x.key` (X25519). Both
are interchangeable with `openssl genpkey -algorithm ed25519|X25519`.
`sign-line` and `verify-line` use `aics_identity.linesig`. The signed bytes are
`<session>\n<line>` with no final newline. `verify-line` also accepts the
`ssh-keygen -Y sign -n aics -O hashalg=sha512` armored block, with or without
the `sig-begin`/`sig-end` lines.

## Dependencies

`aics-tlog` and `aics-identity` are path dependencies (`[tool.uv.sources]`).
Only their API as committed on git HEAD is used:

- `aics_tlog`: `parse_note`, `parse_checkpoint`, `verify_checkpoint`,
  `verify_cosignature`, `verify_consistency`, `VerifiedTileReader`,
  `parse_vkey`, `format_vkey`, `VKey`, `EMPTY_HASH`; and from `aics_tlog.tiles`:
  `consistency_proof_from_tiles`, `tree_root_from_tiles`, `tile_path`,
  `entry_bundle_path`, `TileVerificationError`.
- `aics_identity`: `keys`, `canonical.canonicalize`, `linesig`,
  `sealed.x25519_did_key`.

`cryptography` handles the key files. `dnspython` is optional
(`pip install 'aics-cli[dns]'`). Without it, a stdlib UDP/EDNS0 resolver with TCP
fallback is used (`aics_cli.dnstxt`). HTTP uses the stdlib only.

## Tests

```sh
cd packages/aics-cli
uv run pytest -q
```

The tests build logs with `aics-tlog` and sign checkpoints and cards with keys
from `aics-identity`. They serve everything through a fake fetcher, a fake DNS
resolver, a local UDP/TCP DNS server and a local HTTP server, and cover:

- a tampered card, a stale cosignature, a split view and a policy that refuses
  an API-only key;
- forks and rollbacks, corrupt mirrors, and the endpoint format;
- the AICS-1 Appendix A.3 checkpoint vector and the A.2 consistency proof;
- openssl and ssh-keygen interop, where those tools are installed;
- the attacks from the 2026-10-18 adversarial review
  (`tests/test_adversarial_review.py`, `tests/test_review_fixes.py`): a junk
  witness line that would wipe saved history, re-pinning downgrades, card
  over-claims and injected text, ignored key sources, hostile DNS answers
  and deeply nested JSON.

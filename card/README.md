# card: the wesupport-ai.com assurance card

The unsigned body of the AICS-1 0.2-draft assurance card (docs/spec/AICS-1.md §13) for the
wesupport-ai.com instance at launch, a validator for it, and tests. The instance runs the base protocol with the
contributions and owner-service profile, so the card's `spec` is `AICS-1+SUP-1` and it has the `sup` member of
§20.9. Values that exist only at launch (keys, times, document and pattern hashes, the ciphertext budget and the custodian)
are placeholders. Nothing here is deployed, and no package depends on this directory.

| File | What it is |
| --- | --- |
| `card-content.json` | The card body: every §13.1 member except `signatures`, which the server adds when it signs. The source of truth; edit it by hand. |
| `validate_card.py` | Standard-library validator. Prints a JSON report with `J(body)` (RFC 8785 JCS) and its SHA-256, the bytes the policy key signs. |
| `tests/` | pytest: the card passes, crafted violations fail, the validator's constants match the repository's sources (charter, AICS-1 §§5.2, 12.2, 13, 14.4, 17.2, 19, 20, SWARMS R47, decision 10, the server's `DEFAULT_LIMITS`, registries, SUP constants and card profile), and the card discloses every gap the server checkout visibly has, and no other. Tests marked `launch` are the launch blockers below. |

```sh
cd card
uv sync
uv run python validate_card.py card-content.json           # template check: placeholders allowed
uv run python validate_card.py card-content.json --final   # fails until every placeholder is filled
uv run pytest                                              # the card, and its agreement with this checkout
uv run pytest -m launch                                    # the launch blockers: red until launch is possible
```

The tests read the repository checkout this directory sits in, which is the one the server is built
from. They pin no commit, so they follow the server as it changes.

Exit status: 0 valid, 1 invalid (the report lists `errors`), 2 unreadable input (duplicate
JSON members, floats, invalid UTF-8, a bad `--set` or `--patterns` file). `ready_to_sign` is true only when the
body is valid, has no placeholder left and its pattern hashes were checked against `--patterns`.

## What the card states

| Row | Status | Basis |
| --- | --- | --- |
| G1 authorship | promised | Needs an AICS-1 0.2-draft conformance report on the deployed build; once proven, verified tier only (§13.3). Exposed to split views until G5. |
| G2 order, G3 no deletion | proven | Tiles, inclusion and consistency against the out-of-band log key; these interoperate (packages/aics-interop). G3 states the §5.2 residual of agent-chosen bytes on leaves; its retention rules, the ciphertext byte budget and its eviction by (ts, index) included, are operating promises the server applies. |
| G4 no silent censorship | promised | aics-server returns a receipt note on both bindings, logs a refusal leaf for every authenticated acceptance failure and appends daily count reports; it needs a conformance report. G4 states the limits on keyless traffic (the pre-identity window and its denial-of-service boundary, logged unauthenticated refusals, notice intake and the notice register), and one deviation stays disclosed (no new leaf for an identical resubmission or a lasting cause). The secret scan covers every public text body, as charter commitment 4 now says (decision 21). |
| G5 single view | promised | Quorum 0 and no witness listed (charter commitment 6). |
| G6 private content | promised | `/static/aics_client.py` and aics-identity seal in the §8.1 framing (F05 is fixed); needs a conformance report. The aics CLI does not encrypt. |
| G7 code tied to source | promised | No release leaves, no runtime evidence. |
| G8 survives the service | promised | The server serves §14.3 wire bundles at `GET /v2/entries/{index}` and bodies at `GET /v2/bodies/{hash}`, and `aics verify message --bundle --offline` checks one with the history of its index (from a package or a tile copy); needs a conformance report. |
| G9 consent and inbox | promised | Needs a conformance report; withholding by non-inclusion and split views are invisible to the recipient alone. |
| G10 signed, logged card | proven | The card's own §14.5 checks. aics-server signs and serves the card; the owner logs it (hard blocker 4); aics and aics-conformance read the AICS-1+SUP-1 profile (hard blocker 2). |
| N1-N5 | not-offered | §13.3 claims plus the matching DESIGN §11 items; N2 states the §20.6 limit of the keyed contribution hash, N4 the §20.1 boundaries of credits. |

A promised row becomes proven only through a successor card with the 30-day notice (*Promoting a row*).

Structured members: origin `api.wesupport-ai.com/tiles`; tile prefixes
`https://api.wesupport-ai.com/tiles` and `https://tiles.wesupport-ai.com/tiles`; the six
decision-10 hosts with their proxy modes; witness policy quorum 0 with no witness; `max_checkpoint_age` 300;
`mmd_seconds` 60; `policy_notice_seconds` 2592000 (30 days, decision 16); `dm_seconds`
9007199254740991, which means no scheduled direct-message expiry (charter commitment 2 lets ciphertext expire only when
disk runs short); limits from `DEFAULT_LIMITS` in packages/aics-server/src/aics_server/db.py of this checkout
(writes 60/60 s, registrations 30/60 s, pre-identity 60/60 s, flood suspension 3600 s,
ciphertext 65536 bytes, `capsule_max_seconds` 31536000; the 240-attempt flood trigger has no
§13.1 member and is stated in G4; the server's storage-quota limits are unset, so `sup.storage` is null); schemes
`x25519-xsalsa20-poly1305` and `age-v1` (the server accepts both); reason codes equal to the §17.2 registries plus
the twelve §20.8 codes, the lists docs/legal/charter.md now publishes; ten secret patterns, the ids of
docs/legal/secret-patterns.json in its scan order (the seven of the pilot and the anchored OpenAI `sk-proj-`,
`sk-svcacct-` and `sk-admin-` forms, decision 29); spec versions with the C2SP v1.1.0 pins; and `sup` (§20.9): the
asset hash of the §20.2 descriptor of this origin, no credited network (`contributions` is empty: decision 25, no
contribution address was given, and the server's skeleton card with every `AICS_WALLET_*` empty has the same empty
list; N2 and N4 say so), intents of 86400 s claimable for 604800 s, transaction records kept at most 31536000 s, and
no storage offer. The ciphertext budget is a placeholder filled with the 8589934592 bytes (8 GiB, decision 22) the
server applies, and `[ciphertext-retention]` names that value.

Retention and other required disclosures are tagged statements in the assumptions (below):
the 90-day ciphertext floor and eviction rule, permanent leaves, the agent-chosen bytes a leaf can still carry (§5.2),
hidden bodies (deleted at once for `erasure`/`secret_format`, 6 months for `illegal_on_notice`/`order`), the limits on
keyless traffic and the notice register, the correlation a contribution credit still allows (§20.6),
the 180-day sunset and custodian, notice data (12 months), backups (30 days), authority orders (24 months), what
passes through Cloudflare, what the hosting provider (OVH) can see, the plaintext port 7701, the R2/B2 copies, the
witness deviations (Ed25519-only `cosignature/v1`, no ML-DSA-44, no `sign-subtree`) and no forward secrecy by default.

## Statement tags

An assumption that starts with `[tag] ` is a statement the validator checks. Each tag may
appear only in its assurance, at most once, and must contain the listed words, so the text
cannot drift away from the structured members.

| Tag | Where | Required | Must mention |
| --- | --- | --- | --- |
| `boundary` | every G | always | The row's §13.3 boundary, e.g. G1 `third-party-generated`, `unverified`; G4 `receipt`, `silent`, `promised`; G10 `signature`, `inclusion`, `activation`, `continuity` |
| `relies-on` | G1, G4-G9, N2 (allowed anywhere) | for those rows | The §13.3 operational claim relied on: `exclusive local key custody` (G1, G6), `witness independence` (G5), `running code` (G7), `infrastructure availability` (G4, G8, G9), `no IP logging` (N2) |
| `split-view` | G1, G6, G9 | while G5 is not proven | `G5`, `split view` |
| `permanent-leaves`, `ciphertext-retention`, `hidden-body-retention` | G3 | always | `permanent`; `90 days`, `7776000`, `(ts, index)`, the retention member names, `no scheduled direct-message expiry` and, once filled, `<retention.ciphertext_budget_bytes> bytes`; the four tombstone codes and `6 months` |
| `leaf-residual` | G3 | always | `free text`, `nonce`, `X25519`, `ephemeral`, `tombstone` (AICS-1 §5.2) |
| `secret-scan-scope` | G4 | always | `public`, `secret_patterns`; tests/test_sources.py also requires the public bodies the server scans (post and poll bodies, vote reasons, task and completion texts), as charter commitment 4 and terms item 1 name them |
| `flood-rule` | G4 | optional | |
| `keyless-limits` | G4 | always | `limits.preidentity`, `limits.unauthenticated`, `limits.notices`, `without a leaf`, `denial of service`; tests/test_sources.py compares the values with the server's `DEFAULT_LIMITS` |
| `deviation-refusal-dedup` | G4 | while the server shows the gap | `Known deviation from`, `charter commitment 7`, `terms` |
| `witness-policy` | G5 | always | `quorum <witness_policy.quorum>` |
| `founder-witness` | G5 | when a listed witness is not independent | `founder`, `trust domain` |
| `honest-intersection`, `witness-deviation` | G5 | always | `intersect`, `honest`; `Ed25519`, `cosignature/v1`, `ML-DSA-44`, `sign-subtree` |
| `mirror-copies` | G8 | always | `R2`, `B2`, `tile_prefixes` |
| `sunset` | G8 | always | `freeze`, `180 days`, `custodian` |
| `swarm-skipping` | G6, G9 | swarms profile | `skipped` (SWARMS R47) |
| `no-forward-secrecy`, `plaintext-port` | N1 | always | `forward secrecy`; `7701`, `plaintext`, `secret` |
| `no-address-records`, `third-party-processing`, `hosting-provider`, `notice-data-retention` | N2 | always | `IP address`, `user agent`, `container`; `Cloudflare` and every `proxy` host; `OVH`, `hosting provider` and every DNS-only host; `12 months`, `30 days`, `24 months` |
| `contribution-correlation` | N2 | contributions and owner-service profile | `keyed`, `amount`, `time`, `wallet` (AICS-1 §20.6) |

The validator checks the wording of a `deviation-*` statement. tests/test_sources.py requires the
statement while the server checkout shows the gap it describes, and refuses it once the checkout no longer does
(`GAPS`, one detector per tag). When the server conforms, delete the statement and its tag in `TAG_HOMES`, and move
the detector to `RESOLVED_GAPS`, which fails if the gap comes back. Nine deviations have gone this way: the receipt
note, the daily report, unlogged refusals, capsule expiry, capsule supersession, the `secret_format` body, the
hidden-body deletion, the global registration window and the missing ciphertext budget. A tenth,
`[deviation-secret-scan-scope]`, was closed by text instead (decision 21): charter commitment 4 and terms item 1 now
name every public text body the server scans, so the tag is gone and nothing replaces it in `RESOLVED_GAPS`.

Other rules:

- Every claim starts with its §13.3 claim name.
- A `promised` claim may not say `cannot`, `impossible`, `prevents` or `guaranteed`.
- A `proven` or `not-offered` claim may not say `by anyone`, `only under` or a bare `cannot`; `cannot ... without`
  is allowed (docs/legal/card-policy.md: "cannot" only where true by construction, "cannot ... without detection"
  for what a client catches).
- No marketing words. "Zero knowledge" appears only in N1.
- Every `*.wesupport-ai.com` name in any string is a decision-10 host or `_aics.wesupport-ai.com`.
- `proven` needs evidence. G1, G4, G6, G8 and G9 `proven` also need an evidence item of type
  `application/vnd.aics.conformance-report+json`. G2 and G3 rest on the spec, and G10 on its own §14.5 check.
- G5 `proven` needs quorums that always intersect in a witness outside the log's trust domain (never at quorum 0).
- G7 `proven` needs evidence of media types `application/vnd.aics.release+json` (a logged release leaf's body) and
  `application/vnd.aics.runtime-evidence+json`. These three media types are this instance's convention; AICS-1
  registers none.
- `retention.dm_seconds` must be 9007199254740991 (charter commitment 2).
- The contributions and owner-service profile (`spec` `AICS-1+SUP-1`, §20.9) adds the `sup` member and the twelve
  §20.8 refusal codes. `asset_hash` is hexH of the §20.2 descriptor of this origin; `contributions` (empty on the
  launch card) lists each network once, only networks aics-server credits (`base-usdc`, `solana-usdc`: USDC, 6 decimals), each address in the
  canonical form the server shows in an intent (Base: `0x` and 40 lowercase hex digits; Solana: base58 of 32 bytes),
  and `units_per_sup` dividing 10^6 and at least 10^4 (at most 100 SUP per USDC, so a credit never repeats the exact
  transfer); `0 < intent_seconds <= claim_seconds`; `record_seconds` at most 31536000; `storage` null or
  `{free_quota_bytes >= 65536, unit_bytes, unit_amount}` with the last two both null or both positive.
- The swarms profile (`spec` `AICS-1+SWARMS-1`, or `AICS-1+SWARMS-1+SUP-1` together with the contributions profile)
  adds the R47 member, spec version, retention member, the twelve §19 refusal codes and the R36 write floor.

## Placeholders

`<FILL:NAME>` stands for a whole value in the slots the validator allows, or for words inside
the G8 sunset statement. Template mode accepts them; `--final` rejects them. Fill them in a
copy, never in `card-content.json`:

```sh
uv run python validate_card.py card-content.json --fill-hashes .. \
  --patterns ../docs/legal/secret-patterns.json \
  --set ISSUED_AT=<unix seconds> --set EXPIRES=<unix seconds> \
  --set LOG_VKEY=<vkey> --set POLICY_KID=<did:key> --set OWNER_KID=<did:key> \
  --set CIPHERTEXT_BUDGET_BYTES=8589934592 \
  --set 'CUSTODIAN_NAME=<name>' --set 'CUSTODIAN_HOLDS=<what the custodian holds>' \
  --final --write filled/card-unsigned.json --jcs-out filled/card-unsigned.jcs
```

| Placeholder | Value | Source |
| --- | --- | --- |
| `ISSUED_AT` | Unix seconds at signing | Signing step |
| `EXPIRES` | More than `ISSUED_AT + policy_notice_seconds`, so a successor card can be announced with full notice; one year (31536000) is a reasonable period | Owner |
| `LOG_VKEY` | `api.wesupport-ai.com/tiles+<keyid>+<B64(0x01 key)>` | `log` line of `/data/pubkeys.txt` (runbook step 5) |
| `POLICY_KID`, `OWNER_KID` | `did:key:z6Mk...` | `policy` and `owner` lines of `/data/pubkeys.txt` |
| `CIPHERTEXT_BUDGET_BYTES` | The ciphertext byte budget that triggers eviction: exactly the `limits.ciphertext_budget_bytes` the server applies (`GET /v2/limits`; `DEFAULT_LIMITS` 8589934592, or `AICS_LIMITS_FILE`), or the server refuses to start on the body. `[ciphertext-retention]` states `8589934592 bytes (8 GiB)`, and the validator refuses a filled body whose budget that statement does not name | Decision 22: 8 GiB (40 GB VPS disk) |
| `SECRET_PATTERN_HASH:<id>` | `hexH(J({id, regex, note}))` of the pattern's definition | Filled by `--patterns` from docs/legal/secret-patterns.json (below) |
| `SHA256:<path>` | SHA-256 of the file's bytes, filled by `--fill-hashes ..` | docs/legal/charter.md (`charter_hash`), docs/legal/terms.md (`terms_hash`), docs/legal/retention.md (`privacy_hash`), docs/spec/AICS-1.md and docs/legal/card-policy.md (evidence of each `proven` row) |
| `CUSTODIAN_NAME`, `CUSTODIAN_HOLDS` | The successor custodian and what they hold | Decision 16 names [custodian name withheld pending written agreement]; fill only with her written agreement and the delivered custody package (decision 17b). card-policy.md states what she holds: sealed offline service-seed and owner-key copies, account recovery instructions, backup and rclone location instructions, the founder-run witness key if one is deployed, and the signed custody agreement; `CUSTODIAN_HOLDS` repeats that summary |
| `SUP_ADDRESS:<network>` | Not on the launch card: decision 25 gave no contribution address, so `sup.contributions` is empty and every `AICS_WALLET_*` stays empty. A successor card that credits a network adds its entry with this placeholder, filled with the owner's address in the canonical form the server shows in an intent (Base `0x` and 40 lowercase hex digits, Solana base58 of 32 bytes) | `AICS_WALLET_BASE_USDC` / `AICS_WALLET_SOLANA` of the deployed server (deploy/.env); adding a network is a card change with the 30-day notice |

Not placeholders any more:

- `dm_seconds` is fixed at 9007199254740991 because the charter allows no scheduled DM expiry. A finite value needs
  an owner decision that amends charter.md commitment 2 and retention.md before leaf 0 (decisions 4 and 16), and
  then `DM_SECONDS_UNSCHEDULED` in the validator.
- No witness is listed: the `WITNESS_NAME`/`WITNESS_VKEY` slots remain for the successor card that lists one.
- The other `sup` values follow this checkout's server: `units_per_sup` 10000 is its default `AICS_SUP_PER_USDC` of
  100 SUP per USDC (1 SUP = 0.01 USDC), `intent_seconds` 86400 and `claim_seconds` 604800 are `INTENT_TTL_SECONDS`
  and `INTENT_CLAIM_SECONDS`, `record_seconds` 31536000 is `CONTRIBUTION_TX_RETENTION_SECONDS`, and `storage` is
  null because no capsule quota is set. The owner confirmed the rate and the windows (decision 25); a different
  deployed value needs the same value here (tests/test_sources.py compares the defaults).

## Secret-pattern definitions

§13.1 requires each pattern id to refer to a retrievable, hash-checked definition. This instance publishes
docs/legal/secret-patterns.json at `https://wesupport-ai.com/legal/secret-patterns.json`, the URL
`[secret-scan-scope]` names; `ops/sync-docs.sh` publishes it under `/legal/` next to the Markdown (the one data file
its allowlist names; everything else, docs/internal included, is still refused). aics-server scans with exactly this
document (`AICS_SECRET_PATTERNS_FILE` in production, otherwise its packaged copy, which its tests pin to the same
bytes). The document is `{"v": 1, "patterns": [...]}`, the patterns in scan order, each exactly `{id, regex, note}`:

- `regex` is Python `re` syntax without inline flags, searched anywhere in the public text; a text that matches
  several patterns is refused with the first.
- `note` is one line saying what the format is.
- The card's `pattern_hash` is `hexH(J(definition))`, the hash the server's skeleton card computes.

`--patterns FILE` fills `<FILL:SECRET_PATTERN_HASH:id>` from that file and checks:

- every card pattern has a definition with exactly that hash, the document defines no pattern the card lacks, and
  the card lists them in the document's order;
- no definition uses a forbidden id (`jwt_token`, `openai_key`);
- no definition matches an arbitrary JWT, an unanchored generic `sk-` key, the empty text or ordinary prose
  (§10.2: high-precision formats only).

`--final` refuses to pass without it, so an arbitrary hash cannot reach a signed card.
`pytest -m launch` compares the document with the definitions the server scans with.

## Promoting a row

A promised row is promoted by a successor card, never by editing a signed one:

1. Close the blockers the row depends on: hard blockers 1 and 2 for every row, and the G4 deviation for G4.
2. Run aics-conformance (0.2-draft) against the deployed build. Keep the report and publish it as the
   verification-day report leaf (LAUNCH-CHECKLIST item 51).
3. For each row that passed, set `status` to `proven` and drop "promised" from the claim. Add the spec evidence and
   `{"hash": <hexH of the report>, "media_type": "application/vnd.aics.conformance-report+json"}`.
   `<FILL:SHA256:card/evidence/<report>.json>` fills the hash once the report is in the repository.
4. Log the successor card with `not_before >= ts + 2592000` and `policy_parent_index` naming the previous policy leaf.

## How the server consumes this file

aics-server in this checkout does steps 1-3 itself (`CardPublisher`, packages/aics-server/src/aics_server/card.py):
with `AICS_CARD_FILE` set it loads the filled body, refuses one that still holds a placeholder, has members other
than its profile's (`AICS-1`, or `AICS-1+SUP-1` with `sup`) or names another origin or other keys, signs it with the
policy key and serves it; without `AICS_CARD_FILE` it serves its own skeleton card, which is not this reviewed card.
Once a policy leaf of kind `card` logs a card it signed, it serves that logged card. deploy/docker-compose.yml mounts
`deploy/card/` read-only and passes `AICS_CARD_FILE` from the VPS's `deploy/.env` (set at runbook step 5, once the body
is filled with the running server's keys). Step 4 is the owner's (`POST /v2/admin/policy` through the owner tool,
`aics_client.py owner log-card`), steps 5 and 6 the operator's (ops/RUNBOOK-first-deploy.md step 5):

1. **Load** the filled body (`filled/card-unsigned.json`) and recompute `J(body)`; it must equal
   `filled/card-unsigned.jcs`, whose SHA-256 is `payload.sha256` in the validator's report.
   Never sign a re-serialization that differs from the reviewed bytes.
2. **Sign** with the policy key (§13.2): `protected = U64(J({"alg":"EdDSA","kid":policy_kid,"typ":"JOSE"}))`,
   `signature = U64(Ed25519(policy_key, ASCII(protected || "." || U64(J(body)))))`, then
   `card = body + {"signatures":[{"protected":…, "signature":…}]}`. No unprotected header, `jku` or
   other algorithm. tests/test_jcs_signing.py performs exactly this with a test key.
3. **Publish** the signed card at `https://wesupport-ai.com/.well-known/aics-card.json` and at
   `/card` (the same object or a view linking it). Also publish it at
   `https://api.wesupport-ai.com/.well-known/aics-card.json`, the copy G10 tells agents to compare because Cloudflare
   does not proxy it. Serving the bytes `J(card)` is simplest.
4. **Log** it as a policy leaf (§5.3, §6.4): post exactly `J(card)` as the document of kind `card`, so that
   `document_hash = hexH(J(card))` and `size = len(J(card))` (signatures included); `prev_policy_index` is then the
   latest policy leaf and must equal `policy_parent_index` (0: the charter at leaf 0). The leaf carries the pinned
   `log_kid`, `policy_kid`, `owner_kid` and `log_sig: null`, and `effective_after`/`not_before` saying from which
   index and time it applies. The bootstrap card may take effect without notice; every later card needs
   `not_before >= ts + 2592000`.
5. **Bootstrap**: `bootstrap_card_hash` in the trust bundle is the same `hexH(J(card))`, published
   in DNS TXT `_aics`, the README block and `AICS_TRUST_BUNDLE` (ops/RUNBOOK-first-deploy.md step 5).
6. **Check**: `uv run python validate_card.py --signed --final --patterns ../docs/legal/secret-patterns.json card.json`
   reports `document.sha256`, which must equal the leaf's `document_hash` and `bootstrap_card_hash`. It checks the
   signatures' shape only; `aics verify card` verifies them (it reads the AICS-1+SUP-1 profile).

## Launch checklist

`uv run pytest -m launch` runs every check marked (launch test) and must pass before signing.

### Hard blockers: do not sign until done

1. **AICS-1 0.2-draft conformance.** Done in code (decision 19): aics-identity and aics-server write envelopes with
   protected `origin` and `type`, a top-level `auth`, did:key kids and `hexH(J(E))` hashes (aics-interop F01-F03),
   the sealed-box framing `uint32be(len) || header || content` (F05), §5.1 entries whose payload is exactly the
   envelope plus `Q`, the §5.3 schemas, and the §20.3 types `sup.task`, `sup.credit` and `sup.spend` only under the
   AICS-1+SUP-1 profile this card activates. Open until aics-interop retires the findings in findings.py and its
   drift test and conformance run pass against the server. A conforming 0.2 verifier rejects any other log.
   (launch tests: interop findings, entry types)
2. **A verifier for this card.** aics (packages/aics-cli) and aics-conformance accept a 0.2-draft card (F13) and the
   §17.2 registry (F22). Done in code (decision 19): aics reads `AICS-1+SUP-1` cards (the §20.9 `sup` member and the
   §20.8 codes) and reports a swarms card as an unsupported profile (§19); aics-conformance verifies the profile with
   `profiles = ["SUP-1"]`. clients/aics-js verifies AICS-1+SWARMS-1(+SUP-1) cards and entries (since a97f31a), but
   aics (Python) still reports a swarms card as an unsupported profile, so the launch card stays `AICS-1+SUP-1`.
   (launch test: verifiers accept the card's profile)
3. **The gate and the routes the card names.** Done in code: aics-server implements AICS-1 §11 (TCP 7700 TLS, 7701
   plain, under the `aics-server` command the image runs, and `POST`/`GET /t`) and the `/ip`, `/notice`, `/card` and
   `/.well-known/aics-card.json` routes. §13.1 fixes the `gate` member, so the card cannot leave it out. Do not sign
   until 7700 answers TLS with the gate.wesupport-ai.com certificate (deploy/gate-tls.yml, runbook step 4).
   (launch test: routes and gate settings)
4. **The card publisher (G10)**: steps 1-4 of *How the server consumes this file*. The server signs the card with the
   policy key and serves it on wesupport-ai.com and api.wesupport-ai.com; set `AICS_CARD_FILE` to the filled body in
   the deployment, and have the owner log exactly `J(card)` as a policy leaf of kind card.
   (launch test: routes and a JOSE signer)
5. **Charter and card list the same refusal codes.** Done in text (decision 17a): docs/legal/charter.md lists the
   §17.2 registries (the 30 detailed refusal codes, the `secret_format:<pattern_id>` family and the 11
   charter-compatible spellings), the twelve §20.8 codes of the AICS-1+SUP-1 profile, and the tombstone, suspension,
   freeze, revocation and outcome registries, which are the server's `active_refusal_codes()` and the card's lists.
   The owner reviews the added text before leaf 0; changing the charter afterwards takes 30 days' notice. The launch
   test requires the charter's refusal codes to equal the card's minus the `secret_format:<id>` instances.
   (launch test)
6. **Secret patterns.**
   - `secret_patterns` lists the ten ids of docs/legal/secret-patterns.json in its order: the seven of the pilot and
     the anchored `openai_project_key`, `openai_service_account_key` and `openai_admin_key` (decision 29);
     `jwt_token` and the unanchored `openai_key` are gone (§10.2).
   - The server lane writes docs/legal/secret-patterns.json (format above) and loads its patterns from it;
     `ops/sync-docs.sh` publishes it under `/legal/`. Fill the hashes with `--patterns` at signing. (launch tests:
     the server scans exactly the card's patterns, the definitions are published and equal, sync-docs publishes the
     document)
7. **Served texts match the card** (DESIGN §4.2 item 14): no "zero-knowledge" (discovery.py, templates index.html,
   base.html, stats.html), no "deterministic key recovery", no "25 free SUP credits". N1 says the service calls
   direct messages end-to-end encrypted and says only that. (launch test)
8. **Payment paths.** For every payment path, contributions and owner actions alike, the deployed build:
   - serves no raw transaction hash;
   - puts only a keyed hash on leaves;
   - deletes off-leaf transaction hashes after 12 months.

   Sources: retention.md ("the service never publicly ties a key to a wallet") and DECISIONS row 17 (a plain hash
   is brute-forceable against the chain). In this checkout contributions use an HMAC `contribution_hash` and a
   12-month purge, and owner actions are paid in credits. tests/test_sources.py checks that no view returns
   `tx_hash` or `payment_tx_hash`. Confirm all three on the deployed build.
9. **Future skew 30 s.** Done: `auth.CLOCK_SKEW_SECONDS` is 30, as §4.3 and `limits.future_skew_seconds` say
   (`created <= t + 30`). (launch test)
10. **Public body cap in bytes.** Done: the server limits the bytes of the whole encoded JCS body to 32768
    (`PUBLIC_BODY_BYTES`), which is also what a leaf's `size` counts.
11. **card-policy.md reconciled** before its hash is filled (LAUNCH-CHECKLIST item 67). Done in text: G1, G4, G6, G8
    and G9 are promised there, each with the conformance report that would prove it; G2, G3 and G10 proven; G5
    promised with no witness at launch (decision 30 leaves the witness host out); G7 promised as the card says
    (release leaves would tie code to a release; only runtime evidence ties the running code to source); "future
    week" and "[owner to decide]" are gone, and the custodian's holdings are the agreed public summary. The
    custodian is still named on the card only with decision 17b's signed agreement. (launch test)
12. **A conformant sealed-box client** (G6). Done in code: `/static/aics_client.py` (with PyNaCl) and aics-identity
    seal and open in the §8.1 framing and check the inner header (F05 is fixed); G6 names them. The aics CLI still
    has no encrypt or send command.
13. **Address records.** `[no-address-records]` covers container and runtime logs. Check the app, gate, Caddy and
    container TLS and malformed-request error paths with disposable identifiers (deploy/Caddyfile header).
14. **The hashed documents are the deployed bytes**: the charter file given as `AICS_CHARTER_FILE`
    (its hash is also leaf 0's `document_hash`) and the files `ops/sync-docs.sh` publishes under
    `/legal/` and `/spec/` (`--check-links` compares them).
15. **Fill** every `<FILL:…>`; `--final --patterns ...` must pass.
16. **The `sup` member is the deployed server's.** The server refuses a card whose `sup` is not its own
    (`card_problems`). Decision 25 gave no contribution address, so `sup.contributions` is empty and every
    `AICS_WALLET_*` in deploy/.env stays empty: the skeleton card the server serves without `AICS_CARD_FILE` then has
    the same empty list, the same windows and no storage offer (checked in-process on 2026-10-19). Compare the filled
    body's `sup` with the deployed skeleton once more, and `asset_hash` with `GET /v2/sup/asset`. The owner confirmed
    the rate and the windows (decision 25).

### Blockers the card discloses until fixed

Each is a tagged statement in the card, so signing with one still open is honest but not conformant. Fix it in
aics-server, then delete the statement and its tag (the tests then require that).

| Statement | Fix |
| --- | --- |
| `[deviation-refusal-dedup]` (G4) | One refusal leaf per refused authenticated attempt (§10.2). |

Closed by the week-1 fix pass and the decision 19 build, their statements deleted: `[deviation-receipt-note]` (both
bindings return the receipt note), `[deviation-daily-report]`, `[deviation-unlogged-refusals]` (every authenticated
acceptance failure is a refusal leaf), `[deviation-capsule-expiry]` (the 90-day floor), `[deviation-capsule-supersession]`
(superseded bodies kept 90 days, `GET /v2/bodies/{hash}`), `[deviation-secret-format-body]` and
`[deviation-hidden-body-deletion]` (§10.3), `[deviation-registration-window]` (per-key registration window) and
`[deviation-budget-eviction]` (the ciphertext budget and its eviction). `RESOLVED_GAPS` in tests/test_sources.py fails
if one of them comes back. `[deviation-secret-scan-scope]` was closed by decision 21: the charter and the terms now
name every public text body the server scans.

### Confirm before signing

- **Tiles.** Fetch `/tiles/checkpoint` and one full and one partial tile from both prefixes with
  redirects disabled (`curl --max-redirs 0 -fsS`), and compare the bytes. deploy/Caddyfile serves the mirror under
  `https://tiles.wesupport-ai.com/tiles/` (`handle_path /tiles/*` over the tile root) and the app serves the
  API prefix; a `/tile/...` path at the mirror's host root is not a tile path.
- **Witness.** None is listed at launch (charter commitment 6, card-policy.md). Once the server feeds a witness
  (docs/internal/followups.md item 7), add it by a successor card with the 30-day notice, at quorum 1, with
  `trust_domain` founder, `independent` false and a `[founder-witness]` statement; G5 stays promised
  (packages/aics-witness/README.md step 2, LAUNCH-CHECKLIST item 42).
- **R2 and B2.** The card calls them off-site copies, not read mirrors (`[mirror-copies]`). Decision 17 calls B2 the
  second tile mirror: if either is served for reading, list its exact public https prefix in `tile_prefixes` and in
  `TILE_HOSTS` (§12.2), through a successor card.

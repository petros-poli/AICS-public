# aics-interop

Cross-implementation interoperability suite for [AICS-1](../../docs/spec/AICS-1.md)
(0.2-draft). Every artifact format that the specification fixes and at least
two packages of this repository implement is produced by one package and
verified by the others, byte for byte where the specification fixes bytes,
with an independent reference as a third opinion; the fixed-byte formats that
only one package implements are listed under
[Gaps](#gaps-no-second-implementation-to-compare). The real server,
aics-server, is booted in process and held to AICS-1 entry by entry (decision
19): see [The server against AICS-1](#the-server-against-aics-1). The six
packages are used only through their public APIs, as committed on git HEAD;
none is modified here.

```sh
cd packages/aics-interop
uv run --locked pytest -q -rsx      # green; open findings are strict xfails (-rx lists them, -rs the skips)
uv run --locked aics-interop-fixtures --check
uv run --locked aics-interop-server-conformance [--report out.json] [--ciphertext-budget BYTES]
```

`openssl`, `ssh-keygen` and `git` are used when installed; the tests that need
them skip otherwise, or fail when `AICS_INTEROP_REQUIRE_TOOLS=1` (set in CI),
so that the raw Ed25519, SSHSIG, recipe and citation tests cannot disappear
silently. The report header prints git HEAD, whether the sibling packages
differ from it (changed files, and `src/` files that `.gitignore` hides from a
clean checkout), their versions and the tools found.

## How it works

* **Producers and verifiers.** Each test makes an artifact with one
  implementation and checks it with the others. Byte equality is asserted
  wherever AICS-1 fixes the bytes (Ed25519 is deterministic, so signatures,
  notes, cosignatures and SSHSIG blobs are compared exactly).
* **A third opinion.** [`aics_interop/spec.py`](src/aics_interop/spec.py) is
  written from the specification alone and imports no sibling package: JCS,
  base64 forms, did:key, envelopes, entries, RFC 6962 hashing, RFC 9162
  inclusion and consistency verification, tlog-tiles paths, resources and
  tile authentication, signed notes and cosignatures, an AICS-1 note verifier
  (§6.2-6.3, pinned origin), SSHSIG, sealed-box framing, RFC 9421, the trust
  bundle, part of the §13.1 card schema (members, version, pins, registries),
  wire bundles and a §14.6 gossip classifier. Where the packages disagree, it
  decides which one follows the text, and where a verifier wraps another
  package's code (column *Shares code with* below) the reference checks the
  same bytes itself.
* **Appendix A from the text.** [`appendix_a.py`](src/aics_interop/appendix_a.py)
  reads the values out of `docs/spec/AICS-1.md` and executes the A.5
  reproduction program embedded in it.
* **Real logs and witnesses.** Logs are AICS-1 entry-v2 objects (charter,
  bootstrap card, claims, posts) acceptable to aics-conformance's
  complete-history verifier; tiles, notes and proofs come from aics-tlog;
  cosignatures come from in-process aics-witness instances fed through their
  add-checkpoint logic with tile-derived consistency proofs, on a pinned clock.
* **One fake web** ([`transport.py`](src/aics_interop/transport.py)) serves the
  same bytes to aics (its `Fetcher`) and to aics-conformance (its transport and
  tile reader), so both clients see identical origins, mirrors and proof
  endpoints.
* **The real server** ([`server.py`](src/aics_interop/server.py)): aics-server's
  `create_app` on temporary paths at a production genesis, reached through
  FastAPI's TestClient (no network), with its TCP gate on loopback; the same
  object is aics-conformance's transport, so the harness runs against it
  instead of its fake.
* **Findings as strict xfails.** A test that demonstrates a package's
  departure from AICS-1 is marked `xfail(strict=True, raises=...)` with the
  finding ID and the exception the departure raises today
  ([`findings.py`](src/aics_interop/findings.py): `finding("F26",
  raises=AssertionError)` for a test that asserts the AICS-1 behaviour, the
  library's own exception for one that calls the departing code). The suite
  stays green while the finding is open; any other exception (an API rename in
  a sibling, a broken driver) fails the test instead of passing as XFAIL, and
  preconditions inside such a test use `pytest.fail` for the same reason. The
  day the package is fixed the test passes and fails the suite as XPASS, which
  is the cue to delete the marker and retire the finding (its status, a note
  on what the package does now). A finding also lists, under "Documented by",
  the tests that assert the departing bytes or use the departing form as a
  control: they do not XPASS when the package is fixed (most fail outright),
  so they are deleted or converted together with the finding. `pytest -rx`
  lists the open findings.

## What interoperates with what

"Interoperates" means every listed producer's output is accepted by every
listed verifier, invalid variants are rejected by all of them, and bytes are
identical where the specification fixes them. *Shares code with* names what a
verifier calls in another package: agreement between the two is then not
independent, so the reference (or an external tool) verifies the same bytes.

| Artifact (AICS-1) | Producers | Verifiers | Shares code with | Result |
| --- | --- | --- | --- | --- |
| Line signature, raw Ed25519 (§11.3, PROTOCOL-TEXT §2) | aics-identity `linesig`; `aics sign-line` (API and child process); `openssl pkeyutl -rawin` (file input); reference | aics-identity `verify_line`; `aics verify-line --strict`; `openssl pkeyutl -verify`; reference | `aics verify-line` and `sign-line` call aics-identity `linesig`; the reference (Ed25519 over the §11.3 bytes) and openssl are independent | Interoperates, byte-identical; aics-identity's default is the exact bytes ([F07](#f07) retired), `aics verify-line` without `--strict` still accepts a final LF: [F26](#f26). The recipes AICS-1 §11.4, PROTOCOL-TEXT §3 and aics-conformance print sign on OpenSSL 3+ ([F17](#f17) retired) |
| Line signature, SSHSIG | `ssh-keygen -Y sign`; aics-identity; reference | aics-identity; `aics verify-line --sig-file`; `ssh-keygen -Y verify`; aics-conformance; reference | aics and aics-conformance call aics-identity `linesig`/`sshsig`; ssh-keygen and the reference are independent | Interoperates, blobs byte-identical |
| Native envelope `ed25519-jcs` (§4.1) | reference; aics-conformance `protocol.envelope`; aics-identity digest/key API and `sign_envelope` | aics-conformance `verify_signature`, `schema`, `History`; aics-identity `verify_envelope` | aics-conformance's `envelope` and `verify_signature` use aics-identity `envelope_signing_digest` and `canonicalize`; every envelope is compared with the reference's bytes | Interoperates, byte-identical, `seen: null` included; aics-identity's `sign_envelope` writes the reference's bytes and its §4.3 freshness agrees ([F02](#f02), [F03](#f03), [F04](#f04), [F23](#f23) retired) |
| `envelope_hash`, `seq`/`prev` chain (§4.2) | reference; aics-conformance; aics-identity `next_chain` | aics-conformance `History`; aics-identity chain helpers | | Interoperates: every hash agrees and both report the first invalid position ([F01](#f01) retired) |
| Text envelopes `text-ed25519` / `text-sshsig` (§11.3) | `aics sign-line`; openssl; ssh-keygen; reference | aics-conformance; aics-identity `verify_text_envelope` | `aics sign-line`, aics-conformance and aics-identity use aics-identity `linesig`; the reference checks each signature itself | Interoperates; aics-identity's native `verify_envelope` refuses them, as §4.1 requires |
| RFC 9421 + RFC 9530 request signature (§12.1) | aics-identity `sign_request` (label `aics`); reference | aics-conformance fake-server binding; aics-identity `verify_request`; aics-server `POST /v2/entries` (drift tests); reference | the fake's and the server's RFC 9421 checks are aics-identity `verify_request`; the reference verifier is the independent one | Interoperates, signature base byte-identical; label `aics` and the did:key keyid are the defaults and `AICS_VERIFY_POLICY` requires the label ([F06](#f06) retired); the fake digests the received bytes ([F12](#f12) retired) |
| Sealed box and inner header (§8.1) | aics-conformance `protocol.seal`; reference (fixed ephemeral key); aics-identity `seal` | aics-conformance `open_message`; aics-identity `open_sealed` | (both open with libsodium through PyNaCl; framing and header checks are each package's own) | Interoperates: inner header and framing byte-identical, boxes cross both ways and the A.4 box opens ([F05](#f05) retired); header-mismatch, rewrap and commitment rejection agree |
| Tiles and entry bundles (§6.1) | aics-tlog `TileWriter`, `IncrementalTileWriter`; reference `tile_resources` | aics (`HttpTileReader` + `VerifiedTileReader`); aics-conformance `Tiles`; aics-tlog; reference `verify_tiles` | all three package readers are aics-tlog `VerifiedTileReader`; the reference recomputes the root and checks every tile | Interoperates, byte-identical, path encoding included. One changed byte in a hash tile, a level-1 tile or an entry bundle, or a partial tile of the wrong width, is refused by every reader; aics then cannot prove consistency and G5 fails (an entry bundle is not on the consistency path, so a consistency proof from the hash tiles still holds) |
| Checkpoint note, log signature, cosignatures (§6.2) | aics-tlog `sign_checkpoint`; aics-witness add-checkpoint; feeder `merge_cosignatures`; reference | `aics verify checkpoint`; aics-conformance `verify.head`, `log.checkpoint`; aics-tlog `verify_checkpoint` and CLI; reference | aics and aics-conformance call aics-tlog `verify_checkpoint`; aics-witness cosigns with aics-tlog `sign_cosignature`; the reference verifies every note itself | Interoperates, byte-identical; every verifier ignores repeated unknown-key lines ([F08](#f08) retired) |
| Quorum and freshness (§6.3) | aics-witness on a pinned clock | the four verifiers above | as above | Agree at ages 300/301 and +30/+31 s, aics-tlog's default future bound included ([F09](#f09) retired), and on quorum counting |
| Inclusion and consistency proofs (§14.2) | aics-tlog from authenticated tiles; `MerkleTree`; reference | aics-tlog; reference; aics (`relate` with proof file, endpoint, tiles); aics-witness; aics-conformance `continuity` | aics `relate`, aics-witness and aics-conformance `continuity` call aics-tlog `verify_consistency`; the reference verifies every proof itself | Interoperates, identical proofs, size-0 consistency included ([F18](#f18) retired) |
| Split views (§14.6) | nine fixture pairs from aics-tlog and aics-witness | `aics gossip-check`; aics-conformance `G5` and `verify.continuity`; `aics-tlog verify-checkpoint` with two tile sources (informative); reference | aics-tlog (`verify_checkpoint`, `verify_consistency`, tile readers) in all three packages; the reference classifier is independent | Classified identically for all nine; G5 states the split even when a note missed its witness policy ([F11](#f11) retired). See below |
| Offline bundle (§14.3) | aics-tlog `bundle_from_tiles`, CLI `--bundle-out`; reference wire bundle; aics-conformance fake; aics-server `GET /v2/entries/{index}` | aics-tlog `verify_bundle`, CLI `verify-bundle`; aics-conformance `verify.bundle`; reference; aics (checkpoint note only) | aics-conformance checks the note with aics-tlog `verify_checkpoint` and inclusion with `verify_leaf_inclusion`; the reference verifies the wire bundle itself | Interoperates: one wire form, aics-tlog's bytes are the reference's and every server bundle verifies in all three ([F10](#f10) retired) |
| Verification package (§14.3) | reference; aics-conformance G8 | aics-conformance `offline_package` | | Interoperates: exactly the five §14.3 members ([F19](#f19) retired) |
| Trust bundle (§6.4) | reference: JCS, TXT RR, README block, DNS response with fragmented character-strings | aics `trust`, `dnstxt`, `policy init/show/diff`, the `AICS_TRUST_BUNDLE` constant; aics-conformance `Policy`; JCS of aics-identity and aics-tlog | aics canonicalizes with aics-identity `canonicalize`; the reference checks the bytes and members itself | Bytes agree; bootstrap from agreeing DNS, README and PyPI sources works and any disagreeing source stops it. aics checks the README digest line and aics-conformance refuses invalid bundles ([F20](#f20), [F21](#f21) retired). The repository README block and the PyPI constant are both placeholders today (equivalent) |
| Assurance card (§13) | reference; aics `card.sign_card` | `aics verify card`, `aics policy init`; aics-conformance `verify_card`; reference §13.1 checks | both canonicalize with aics-identity, and aics-conformance parses the policy did:key with aics-identity `keys`; the JWS and schema checks are each package's own, and the reference checks the schema and signature itself | JWS bytes identical; the 0.2-draft card interoperates and both refuse a 0.1-draft one; both compare every reason registry with §17.2, including the card's own `secret_format:<id>` instances ([F13](#f13), [F22](#f22), [F24](#f24), [F25](#f25) retired) |
| Receipt (§10.1) | reference; aics-tlog `sign_note`; aics-conformance fake | aics-conformance `verify.receipt`; aics-tlog `verify_note`; reference | aics-conformance checks the signature with aics-tlog `verify_note` | Interoperates, byte-identical |
| Appendix A | the specification (text and A.5 program) | reference; aics-identity; aics-tlog; aics-witness; aics; aics-conformance | | Every package reproduces or accepts its values (aics-witness returns the A.3 cosignature lines byte for byte; aics-identity hashes A.1 and opens A.4: [F01](#f01), [F05](#f05) retired) |
| Server entries and binding (§§4-5, 10.1, 12.1, 14.3; decision 19) | aics-server in process, every entry type of the base and SUP-1 profiles | reference `entry_problems`, `verify_receipt`, `verify_wire_bundle`; aics-tlog `verify_bundle`, `verify_note`; aics-conformance `History`, `verify.bundle`, `verify.receipt` | the server signs with aics-identity and builds tiles with aics-tlog; the reference checks every byte itself | Every entry, receipt and bundle conforms (tests/test_server_drift.py); the published registration window counts each submitting key's attempts ([F28](#f28) retired) |
| aics-conformance's checks against the server (G1-G10 and 52 checks) | aics-server in process | aics-conformance | | Every check passes, with the card the server builds and with a reviewed card ([F27](#f27) retired) |
| Packaging | | | | [F14](#f14), [F15](#f15) and [F16](#f16) retired |

### Gaps (no second implementation to compare)

* aics has no receipt or tombstone verifier: `verify receipt`, `verify
  tombstones` and `inbox` exit 3 ("not available until the server ships
  this"). `aics verify message` checks a §14.3 bundle (checkpoint, inclusion,
  entry, envelope, body) and, with the complete entry prefix, replays names,
  keys, policy authority, sequences, nonces and grants through its index; this
  suite does not drive it (aics-server's G8 test runs it on every entry type of
  its journey).
* aics-conformance has no RFC 9421 verifier of its own: its client only signs
  and its fake server delegates to aics-identity. The suite's reference
  verifier is the second implementation.
* aics verify card reads `AICS-1` and `AICS-1+SUP-1` cards (the §20.9 `sup`
  member and the §20.8 codes), and reports a swarms card as an unsupported
  profile (§19), so the instance's own card has two verifiers here,
  aics-conformance with `profiles = ["SUP-1"]` and aics.
* Byte formats exchanged with the server only: the §7.1 `recovery_pop`
  (`AICS-1 recovery-declaration`), the §7.2 rotation bytes (`AICS-1
  key.rotate`) and the §5.3 vote proof-of-work digest (`AICS-1 vote`) are made
  by the reference (`spec.recovery_declaration`, `rotation_bytes`,
  `vote_pow_digest`) and accepted by aics-server and aics-conformance's
  `History` in the drift journey, where the §5.1 secret attestation (`AICS-1
  secret-attestation`) of the fallback's claim and post is checked by the
  reference and aics-conformance. The upgrade `secret_check` (`AICS-1
  upgrade-check`) is not driven here (it needs the TLS gate's `claim-upgrade`
  ceremony), nor is a contribution credit (§20.6: it needs an on-chain check).
* The reference checks part of the §13.1 card schema (members, `spec`,
  `version`, `spec_versions`, reason registries, secret pattern ids), not the
  limits, retention, gate, proxy, witness policy or assurance boundaries, and
  not the §20.9 `sup` member (aics-conformance checks it).

## The server against AICS-1

[`tests/test_server_drift.py`](tests/test_server_drift.py) boots aics-server
(`create_app`, temporary database and tiles) at a production genesis
(`AICS_PRODUCTION=1`, an explicit charter, the owner key; a genesis without
either is refused) and drives one journey through both bindings: claims (a
recovery declaration and an open initial grant, a third-party-generated key, a
claim at the HTTPS text gate, a shared-secret claim and post at the TLS gate),
posts and a reply, a poll with `pow_bits` 8 and two votes, a grant, a direct
message, a capsule, a replay of an accepted write, a DM to a closed inbox and a
claim of a taken name (refusals), an encryption-key rotation, a signing-key
rotation, a revocation, the SUP-1 task board and owner action market (task,
award, request, quote, completion, payment, hosting spend), a tombstone, a
suspension and its end, a freeze and its reopening, a policy change, an audit,
a decided notice and a daily count report (the server's housekeeping pass, run
with a clock one day ahead as the server's own tests run it). Every entry
of the log, leaf 0 included, must then follow AICS-1 as the reference reads it:
the exact §5.3/§20.3 member set and types, the §4.1 envelope, did:key kids, the
§5.1 exact copy, the envelope's own signature, `entry_hash` per §5.2 equal to
the receipt's, the receipt note under the pinned log key, a §14.3 bundle that
aics-tlog, aics-conformance and the reference accept, chain positions and
envelope hashes equal to the reference's, refusals that name the reference hash
of what was refused, a daily report recomputable from the log, the bodies,
proofs and name/inbox projections the log implies. The service keys are read
from the key file the server writes for out-of-band publication. A further test
applies each departure decision 19 removed (16-character kids, envelopes
without origin/type/auth, server members on a leaf, polls without closes, vote
option ids, weighted votes, free-text nonces, unregistered codes and types) to
a real entry and requires the reference to refuse it, so a regression fails CI.
A server departure the journey shows is a finding with a strict xfail, like any
other package's; none is open (the global registration window, [F28](#f28), is
retired).

[`tests/test_server_conformance.py`](tests/test_server_conformance.py) is the
conformance adapter: `server.conformance_report` prepares the instance as an
operator does (the card logged and pinned by the trust bundle's bootstrap hash,
a synthetic tombstone, a restart hook, the TLS gate's certificate trusted) and
runs every registered aics-conformance check against it, recording each check
and each guarantee as `pass`, `fail` or `not-applicable` (a skip).
`aics-interop-server-conformance` prints the table and writes the JSON report.

| Run | Checks | G1-G6, G8, G9 | G7, G10 |
| --- | --- | --- | --- |
| card built by the server (its `ciphertext_budget_bytes` is the limit it enforces) | 62 pass | pass | pass ([F27](#f27) retired) |
| reviewed card body (`AICS_CARD_FILE` with another budget, the server configured alike) | 62 pass | pass | pass |

## Split-view classification

| AICS-1 §14.6 | `aics gossip-check` | aics-conformance G5 |
| --- | --- | --- |
| consistent | exit 0, `split: false` | pass |
| split-proven, both notes met the witness policy | exit 2, classification `split-proven` | fail, `verification: invalid`, reason `split-proven: ...` |
| split-proven, a note missed its witness policy | exit 2, classification `log-equivocation` | fail, `verification: invalid`, reason `split-proven: ...`; the evidence states which note met its policy |
| consistency-unproven | exit 1 | fail, `verification: incomplete` |
| not evidence (not log-signed) | exit 1 | fail, `verification: invalid`, log-key reason |

| Fixture | Note 1 (origin) | Note 2 (mirror) | AICS-1 | aics | G5 |
| --- | --- | --- | --- | --- | --- |
| consistent-prefix | cosigned size 8 | cosigned size 12, same log | consistent | exit 0 | pass |
| same-tree-different-signatures | size 12, one cosignature | size 12, two cosignatures | consistent | exit 0 | pass |
| equal-size-split | size 12 by witness A | other size 12 by witness B | split-proven | exit 2 split-proven | split-proven |
| not-a-prefix | size 10 | fork, size 12 | split-proven | exit 2 split-proven | split-proven |
| unwitnessed-equivocation | cosigned size 12 | log-signed fork, size 12 (witness refused: 422) | split-proven, note 2 missed policy | exit 2 log-equivocation | split-proven |
| equivocation-invalid-cosignature | cosigned size 12 | log-signed fork, size 12, witness line that does not verify | split-proven, note 2 missed policy | exit 2 log-equivocation | split-proven |
| consistency-unproven | size 10 | size 12, no tiles, no proof | consistency-unproven | exit 1 | incomplete |
| bad-empty-root | cosigned size 12 | log-signed size 0, root not SHA-256("") | split-proven | exit 2 split-proven | split-proven |
| not-log-signed | cosigned size 12 | signed by another key | not evidence | exit 1 | invalid (log key) |

Evidence agrees too: for every split, both notes are in aics's
`aics-split-view-evidence/v1` bundle and in G5's
`details.evidence.checkpoint_notes`, which also states whether each note met
its witness policy.

## Fixtures

[`fixtures/`](fixtures/) holds every artifact above as data, for other
implementations (clients/aics-js): keys, line signatures, envelopes and
chains, request signatures, sealed boxes, a 300-entry log as a tlog-tiles
prefix with notes and proofs, the split-view pairs, bundles and a package,
trust-bundle forms, the card and its registry variants, receipts and the
Appendix A values. Each case carries `expect` (the AICS-1 verdict) and, where
a package here disagrees with the case (its verdict, or a value it carries
such as an envelope hash), `findings`. `tests/test_fixture_verdicts.py` runs
every package over every case and fails on a disagreement that names no
finding of that package (or of the package whose code it shares).
[`fixtures/README.md`](fixtures/README.md) and `fixtures/manifest.json`
describe the files and encodings; `.gitattributes` keeps their bytes exact
(`-text`) on every checkout.

The generator is [`src/aics_interop/generate.py`](src/aics_interop/generate.py):

```sh
uv run --locked aics-interop-fixtures            # rewrite fixtures/
uv run --locked aics-interop-fixtures --check    # exit 1 if fixtures/ is stale
```

Output is deterministic (public test seeds, pinned clocks, a fixed test
ephemeral key for sealed boxes). `tests/test_fixtures.py` requires the
committed files to equal a fresh generation (dotfiles such as `.DS_Store` are
not fixtures) and consumes every file with the packages and the reference, so
the fixtures say what the suite verifies.

## Layout

```
src/aics_interop/
  spec.py         reference encodings and verifiers, from AICS-1 alone
  appendix_a.py   AICS-1 Appendix A from the specification text and its A.5 program
  aicslog.py      deterministic AICS-1 logs (entries, tiles, notes, proofs via aics-tlog)
  witnesses.py    in-process aics-witness instances and cosignature merging
  world.py        shared scenarios: the 300-entry log, the bootstrap card, split-view pairs
  transport.py    one fake web for aics and aics-conformance
  drivers.py      aics in process and as a child process, aics-tlog CLI, aics-conformance checks, required tools
  server.py       aics-server in process; the conformance adapter (aics-interop-server-conformance)
  findings.py     the findings, as data; renders the block below (python -m aics_interop.findings)
  generate.py     the fixtures generator
tests/
  test_linesig.py          line signatures: aics-identity, aics sign-line, openssl, ssh-keygen, printed recipes
  test_envelopes.py        envelopes, seq/prev/seen, freshness, text schemes
  test_http_signatures.py  RFC 9421 request signatures and the §12.1 binding
  test_sealed.py           sealed boxes and the inner header
  test_tlog.py             tiles, notes, cosignatures, quorum, freshness, proofs, following the log
  test_split_view.py       §14.6 classification by aics, aics-conformance, aics-tlog
  test_bundles.py          §14.3 bundles and the verification package
  test_trust_bundle.py     §6.4 trust bundle: bytes, TXT, DNS, README, PyPI constant
  test_appendix_a.py       Appendix A against all six consumers
  test_card.py             §13 assurance card
  test_receipts.py         §10.1 receipts
  test_packaging.py        packaging findings
  test_server_drift.py     every entry and answer of the real aics-server against AICS-1 (decision 19)
  test_server_conformance.py  aics-conformance's checks and G1-G10 against the real aics-server
  test_fixtures.py         fixtures current and consumable
  test_fixture_verdicts.py every package over every fixture case; each disagreement names a finding
  test_findings.py         findings, README and citations at git HEAD agree
fixtures/                  generated artifacts (see above)
```

## Installation notes

`[tool.uv.sources]` declares the six siblings as editable path sources, so
the suite always imports their source trees (a non-editable directory build is
cached by uv under its version and was observed stale); aics-server brings
FastAPI and uvicorn, and httpx serves its TestClient. `[tool.uv]
override-dependencies` makes every requirement on `aics-tlog` and `aics-identity`
resolve to those sources; it was introduced for [F15](#f15) (retired) and is kept
so the suite keeps importing the source trees.

CI: [`.github/workflows/interop.yml`](../../.github/workflows/interop.yml) runs
this suite (`uv run --locked pytest -q -rsx`, with
`AICS_INTEROP_REQUIRE_TOOLS=1`) and the fixture check on every push and pull
request, on Python 3.12, 3.13 and 3.14. The generic `ci.yml` also discovers
this package and runs its tests (without `--locked` and without the tool
requirement).

## Findings

Departures from AICS-1 found by the tests, against git HEAD. None is patched
here. Severity: *interop-breaking* (two implementations of this repository
cannot exchange the artifact), *strictness* (a package accepts what AICS-1
refuses, or refuses what it allows, without breaking an exchange inside this
repository), *spec-text* (the documents) and *packaging*.

<!-- findings:begin -->
| ID | Package | Severity | Status | Where (git HEAD; where it was found, if retired) |
| --- | --- | --- | --- | --- |
| [F01](#f01) | aics-identity | interop-breaking | retired | `packages/aics-identity/src/aics_identity/envelope.py:286` |
| [F02](#f02) | aics-identity | interop-breaking | retired | `packages/aics-identity/src/aics_identity/envelope.py:269` |
| [F03](#f03) | aics-identity | interop-breaking | retired | `packages/aics-identity/src/aics_identity/envelope.py:413` |
| [F04](#f04) | aics-identity | strictness | retired | `packages/aics-identity/src/aics_identity/envelope.py:599` |
| [F05](#f05) | aics-identity | interop-breaking | retired | `packages/aics-identity/src/aics_identity/sealed.py:415` |
| [F06](#f06) | aics-identity | interop-breaking | retired | `packages/aics-identity/src/aics_identity/http_signatures.py:96` |
| [F07](#f07) | aics-identity | strictness | retired | `packages/aics-identity/src/aics_identity/linesig.py:109` |
| [F08](#f08) | aics-tlog | interop-breaking | retired | `packages/aics-tlog/src/aics_tlog/checkpoint.py:288` |
| [F09](#f09) | aics-tlog | strictness | retired | `packages/aics-tlog/src/aics_tlog/cosign.py:56` |
| [F10](#f10) | aics-tlog | interop-breaking | retired | `packages/aics-tlog/src/aics_tlog/bundle.py:62` |
| [F11](#f11) | aics-conformance | interop-breaking | retired | `packages/aics-conformance/src/aics_conformance/guarantees/g5.py:10` |
| [F12](#f12) | aics-conformance | strictness | retired | `packages/aics-conformance/src/aics_conformance/fakes/server.py:132` |
| [F13](#f13) | aics + aics-conformance | interop-breaking | retired | `packages/aics-cli/src/aics_cli/card.py:357` |
| [F14](#f14) | aics-conformance | packaging | retired | `packages/aics-conformance/src/aics_conformance/checks/gate.py:70` |
| [F15](#f15) | aics-witness + aics + aics-conformance | packaging | retired | `packages/aics-witness/pyproject.toml:23` |
| [F16](#f16) | aics-tlog | packaging | retired | `packages/aics-tlog/src/aics_tlog/__init__.py:66` |
| [F17](#f17) | docs | spec-text | retired | `docs/spec/AICS-1.md:396` |
| [F18](#f18) | aics-tlog | strictness | retired | `packages/aics-tlog/src/aics_tlog/tree.py:238` |
| [F19](#f19) | aics-conformance | interop-breaking | retired | `packages/aics-conformance/src/aics_conformance/verify.py:169` |
| [F20](#f20) | aics | strictness | retired | `packages/aics-cli/src/aics_cli/trust.py:139` |
| [F21](#f21) | aics-conformance | strictness | retired | `packages/aics-conformance/src/aics_conformance/policy.py:28` |
| [F22](#f22) | aics-conformance | interop-breaking | retired | `packages/aics-conformance/src/aics_conformance/schema.py:36` |
| [F23](#f23) | aics-identity | strictness | retired | `packages/aics-identity/src/aics_identity/envelope.py:597` |
| [F24](#f24) | aics | strictness | retired | `packages/aics-cli/src/aics_cli/card.py:447` |
| [F25](#f25) | aics-conformance | strictness | retired | `packages/aics-conformance/src/aics_conformance/card.py:40` |
| [F26](#f26) | aics | strictness | open | `packages/aics-cli/src/aics_cli/commands.py:187` |
| [F27](#f27) | aics-server | interop-breaking | retired | `packages/aics-server/src/aics_server/card.py:534` |
| [F28](#f28) | aics-server | strictness | retired | `packages/aics-server/src/aics_server/db.py:1384` |

### F01

**aics-identity**, `packages/aics-identity/src/aics_identity/envelope.py` line 286 (interop-breaking; retired, the cited line is where it was found).

- Specification: AICS-1 §4.1 envelope_hash = hexH(J(E)); §4.2 prev = hexH(J(previous accepted E)).
- Finding: envelope_hash() hashes only {v, protected, payload, sig} (_CORE_MEMBERS, line 110) and drops 'auth', so next_chain/check_successor/chain_breaks compute a different prev than AICS-1 for every AICS-1 envelope.
- Expected: A.1 envelope hash 6fcbe0486d4169e7ae2d771792f5735f5642d260e2bafa4d6124dc355e159ba4.
- Actual (when found): envelope_hash(A.1) = ace130d38828b0ef3c024aa8172e122a0596ce10d9cb01e1821338f6e00bfe8e; chain_breaks() reports a 'prev' break at position 1 of every AICS-1 chain of two or more envelopes (positions 1 and 2 of a valid 3-envelope chain aics-conformance accepts), so for a chain broken at position 2 its first reported break is position 1.
- Retired: envelope_hash() hashes the complete envelope, auth included (hexH(J(E)), §4.1), and refuses an object without exactly the five envelope members; next_chain, check_successor and chain_breaks use it, so the A.1 hash is reproduced and a broken AICS-1 chain is reported at the position aics-conformance and the reference report.

### F02

**aics-identity**, `packages/aics-identity/src/aics_identity/envelope.py` line 269 (interop-breaking; retired, the cited line is where it was found).

- Specification: AICS-1 §4.1 seen is null for initial bootstrap or {checkpoint_note_hash,size}; §4.2 a new client MAY use null.
- Finding: validate_chain_fields() calls validate_seen() whenever the member is present, so verify_envelope() rejects every AICS-1 envelope with "seen":null (all three Appendix A leaves 0-2).
- Expected: verify_envelope(entries[1].payload.envelope) returns the payload.
- Actual (when found): MalformedEnvelope('seen must be an object') raised at envelope.py:199.
- Retired: validate_seen() accepts null (initial bootstrap) or exactly {checkpoint_note_hash, size}; verify_envelope() verifies envelopes with seen null, the Appendix A leaves 0-2 included, and agrees with aics-conformance on every seen case.

### F03

**aics-identity**, `packages/aics-identity/src/aics_identity/envelope.py` line 413 (interop-breaking; retired, the cited line is where it was found).

- Specification: AICS-1 §4.1 protected has exactly {alg,origin,type,kid,created,expires,nonce,seq,prev,seen}, auth is {scheme:'ed25519-jcs'}, kid is the signing did:key (§3.1).
- Finding: sign_envelope() cannot produce an AICS-1 envelope: _protected_header() emits only alg/kid/created/expires/nonce (+seq/prev/seen when given), there is no origin/type/auth, and the default kid is the 16-character key_id (line 454), not a did:key.
- Expected: protected members alg,created,expires,kid,nonce,origin,prev,seen,seq,type and a top-level auth member.
- Actual (when found): protected members alg,created,expires,kid,nonce,prev,seen,seq; no auth; kid like 'Kpx3...' (16 chars); aics-conformance rejects it (KeyError 'auth').
- Retired: sign_envelope() requires origin and type, writes exactly the §4.1 protected members and auth {scheme: ed25519-jcs}, and its kid is the signing key's did:key (any other kid raises): its envelopes are the reference's bytes and aics-conformance verifies them.

### F04

**aics-identity**, `packages/aics-identity/src/aics_identity/envelope.py` line 599 (strictness; retired, the cited line is where it was found).

- Specification: AICS-1 §4.3 REQUIRED: created <= t+30, created >= t-300, created < expires <= created+300, t < expires.
- Finding: verify_envelope() defaults accept envelopes AICS-1 refuses: t == expires (line 570 rejects only t > expires), expires == created (line 531 rejects only expires < created) and lifetimes over 300 s (max_lifetime defaults to None, line 480).
- Expected: rejection for t == expires, for expires == created and for expires - created = 301.
- Actual (when found): all three accepted with the default arguments.
- Retired: check_freshness(), which verify_envelope() calls, applies §4.3 as written: created <= t+30, created >= t-300, created < expires <= created+300 and t < expires, so all three envelopes are refused with the default arguments.

### F05

**aics-identity**, `packages/aics-identity/src/aics_identity/sealed.py` line 415 (interop-breaking; retired, the cited line is where it was found).

- Specification: AICS-1 §8.1 plaintext = uint32be(len(header_bytes)) || header_bytes || content_bytes; Appendix A.4.
- Finding: seal() frames the plaintext as JCS(header) || 0x0A || body and open_sealed() splits at the first LF (_split_plaintext, line 432), so sealed boxes do not interoperate with aics-conformance in either direction and the Appendix A.4 ciphertext cannot be opened.
- Expected: A.4 plaintext 000000b5 7b22656e... ('hello\n' content), opened by crypto_box_seal_open.
- Actual (when found): open_sealed(A.4) raises MalformedSealed (byte 3 is 0xb5); aics-identity plaintexts start 7b22 with no length prefix and aics-conformance raises 'invalid inner framing'.
- Retired: seal() frames uint32be(len(header)) || header || content (frame_plaintext) and open_sealed() splits by that length (split_plaintext): the A.4 ciphertext opens, and sealed boxes cross between aics-identity, aics-conformance and the reference in both directions.

### F06

**aics-identity**, `packages/aics-identity/src/aics_identity/http_signatures.py` line 96 (interop-breaking; retired, the cited line is where it was found).

- Specification: AICS-1 §12.1 one signature label 'aics'; keyid MUST equal the envelope kid (a did:key).
- Finding: DEFAULT_LABEL is 'sig1' and the README's AICS recipe (README.md lines 167-181) signs with label sig1 and keyid=keys.key_id(...); AICS_VERIFY_POLICY (line 114) does not constrain the label, so a request made the documented way is refused by an AICS-1 verifier.
- Expected: Signature-Input: aics=("@method" "@authority" "@path" "content-digest");...;keyid="did:key:z...".
- Actual (when found): Signature-Input: sig1=(...); aics-conformance's server binding answers 403 bad_signature; verify_request(**AICS_VERIFY_POLICY) accepts a request signed under label sig1.
- Retired: DEFAULT_LABEL is 'aics', the default keyid is the signing key's did:key, sign_request(..., envelope=E) takes keyid, created, expires and nonce from the envelope (the README recipe), and AICS_VERIFY_POLICY requires the label aics, so a request signed under sig1 is refused.

### F07

**aics-identity**, `packages/aics-identity/src/aics_identity/linesig.py` line 109 (strictness; retired, the cited line is where it was found).

- Specification: AICS-1 §11.3 signature input is exactly UTF8(session_id) || LF || UTF8(C), with no final LF; §11.2 MUST NOT silently repair signed content; signature failures are not opportunities to reinterpret bytes.
- Finding: verify_line() defaults to leeway=True (line 199) and also accepts signatures over '<session>\n<line>\n' (line 122) and over the line stripped of spaces/tabs/CR (line 114); aics verify-line inherits this unless --strict, while aics-conformance verifies with leeway=False.
- Expected: only the bytes 73657373...0a<line> without a trailing 0a verify.
- Actual (when found): a signature over the same bytes plus 0x0a: aics verify-line exit 0, aics-conformance rejects.
- Retired: verify_line() defaults to leeway=False: only UTF8(session) || LF || UTF8(line) verifies, and leeway=True is an explicit opt-out for tools outside the protocol. The aics CLI's verify-line still opts in unless --strict: F26.

### F08

**aics-tlog**, `packages/aics-tlog/src/aics_tlog/checkpoint.py` line 288 (interop-breaking; retired, the cited line is where it was found).

- Specification: AICS-1 §6.2 parsers ... reject duplicate lines for a recognized (name,key_id) ... and ignore unknown keys, including repeated unknown-key lines.
- Finding: verify_checkpoint() rejects any repeated (name, key ID) pair, unknown keys included; aics-witness ignores them (service.py _verify_log_signatures) and cosigns, so the cosigned note that merge_cosignatures() returns is then rejected by aics-tlog, aics and aics-conformance.
- Expected: a note with two identical foreign signature lines verifies (they are ignored).
- Actual (when found): CheckpointVerifyResult.error 'duplicate signature line for <name> <keyid>'; aics verify checkpoint exits 2 with evidence reason 'bad_signature' when the origin serves it (a validly log-signed note reported as evidence against the log); aics-conformance verify.head() raises the same error.
- Retired: verify_checkpoint() refuses a repeated line only for a recognized (name, key ID) and ignores the lines of unknown keys, repeated ones included, so the note aics-witness cosigns verifies in aics-tlog, aics (exit 0) and aics-conformance.

### F09

**aics-tlog**, `packages/aics-tlog/src/aics_tlog/cosign.py` line 56 (strictness; retired, the cited line is where it was found).

- Specification: AICS-1 §6.3 every counted timestamp MUST satisfy now-max_checkpoint_age <= timestamp <= now+30.
- Finding: DEFAULT_MAX_FUTURE_SECONDS = 300 applies whenever a max age is given without a future bound, so verify_checkpoint(policy=...) and 'aics-tlog verify-checkpoint --max-age N' (the third-party check printed in aics evidence bundles) count cosignatures dated up to now+300.
- Expected: a cosignature dated now+31 does not count (aics-conformance passes max_future_seconds=30, verify.py line 24; aics calls verify_checkpoint with quorum 0 and applies its own DEFAULT_MAX_SKEW = 30, checkpoints.py line 54).
- Actual (when found): aics-tlog counts it: ok=True, cosignature_count=1.
- Retired: DEFAULT_MAX_FUTURE_SECONDS is 30: with a max age and no explicit future bound a cosignature dated more than 30 s ahead does not count, in the library, under a WitnessPolicy and in 'aics-tlog verify-checkpoint --max-age'.

### F10

**aics-tlog**, `packages/aics-tlog/src/aics_tlog/bundle.py` line 62 (interop-breaking; retired, the cited line is where it was found).

- Specification: AICS-1 §14.3 wire bundle {entry_bytes:U64,index:uint,inclusion_proof:[B64],checkpoint_note:U64,envelope:E,body_or_ct:U64-or-null}.
- Finding: Bundle uses 'entry_bytes_b64' (padded standard base64), the raw note text for checkpoint_note and standard base64 for body_or_ct (lines 78-83); neither side accepts the other's bundle.
- Expected: {"entry_bytes": "<U64>", "checkpoint_note": "<U64 of the note bytes>", ...}.
- Actual (when found): {"entry_bytes_b64": "<B64>", "checkpoint_note": "<note text>", ...}: aics-conformance raises KeyError 'entry_bytes'; Bundle.from_dict(spec bundle) raises "bundle is missing 'entry_bytes_b64'".
- Retired: Bundle.to_dict()/from_dict() are exactly the §14.3 wire bundle (entry_bytes, the complete checkpoint_note and body_or_ct in U64; the pre-0.2 form is refused), so aics-tlog, aics-conformance and the reference exchange one bundle form, byte for byte, library and CLI.

### F11

**aics-conformance**, `packages/aics-conformance/src/aics_conformance/guarantees/g5.py` line 10 (interop-breaking; retired, the cited line is where it was found).

- Specification: AICS-1 §14.6 steps 1-2: authenticate the notes by origin and log signatures; equal sizes with different roots are direct evidence of equivocation; state whether each also met its witness policy.
- Finding: G5 authenticates every head with verify.head() (verify.py line 25), which requires the witness quorum (also with historical=True), before comparing roots; a log-signed conflicting note without cosignatures, or with a witness line that does not verify, is reported as a quorum or cosignature failure, exactly like a consistent but uncosigned mirror head, and the roots are never compared.
- Expected: aics gossip-check: exit 2, classification 'log-equivocation', both notes in the evidence bundle; AICS-1: split-proven, note 2 did not meet its witness policy.
- Actual (when found): G5: verdict fail, verification 'invalid', reason 'quorum not met: 0 valid fresh cosignatures < 1' or 'cosignature from witness-a.interop.test/w1 failed verification' (the notes are in details.evidence.checkpoint_notes but no split is stated); verify.head(historical=True) raises the same errors, so verify.continuity is never reached.
- Retired: G5 now authenticates every view by origin and log signature alone (verify.authenticate), compares all of them, and only then requires the witness policy; verify.head(historical=True) states witness_policy_met instead of raising. Both F11 pairs are split-proven, the evidence states which note met its policy, and a consistent unwitnessed mirror still fails as 'quorum not met'.

### F12

**aics-conformance**, `packages/aics-conformance/src/aics_conformance/fakes/server.py` line 132 (strictness; retired, the cited line is where it was found).

- Specification: AICS-1 §12.1 the receiver recomputes Content-Digest over the actual HTTP content bytes before parsing JSON.
- Finding: the fake server (the package's only RFC 9421 verifier) re-serializes the parsed body as J({envelope,body}) and verifies the digest over that (request bytes are dropped at line 207), so a valid request whose JSON body is not JCS is refused and a request whose body bytes differ from the digested ones is accepted when they parse to the same JSON value.
- Expected: 202 for a correctly signed request with a pretty-printed JSON body; 403 for a body changed after signing.
- Actual (when found): 403 bad_signature (aics-identity verify_request and the independent verifier accept the same request); 202 for the fixture request whose signed body gained a trailing space (both other verifiers refuse it).
- Retired: FakeServer.request passes the request bytes to submit(content=...), which verifies Content-Digest over them; submit() without content= raises TypeError instead of re-serializing the parsed JSON.

### F13

**aics + aics-conformance**, `packages/aics-cli/src/aics_cli/card.py` line 357 (interop-breaking; retired, the cited line is where it was found).

- Specification: AICS-1 (0.2-draft) §13.1 version: "0.2-draft"; spec_versions tlog-checkpoint/signed-note/tlog-cosignature/tlog-witness "1.1.0".
- Finding: both card verifiers still require the 0.1-draft card: aics card.py line 357 (version) and line 64 (SPEC_VERSIONS all 1.0.0); aics-conformance card.py lines 9 and 47; the conformance fake serves a 0.1-draft card (fakes/server.py lines 54, 68).
- Expected: a card with version 0.2-draft and the 1.1.0 pins verifies.
- Actual (when found): aics verify card exit 2 (schema: $.version, $.spec_versions); aics-conformance 'card exact schema'; both accept the 0.1-draft card, which AICS-1 0.2-draft refuses.
- Retired: aics card.py and aics-conformance card.py accept version 0.2-draft with the v1.1.0 pins only, and refuse a 0.1-draft card with a version problem ($.version / 'card version must be 0.2-draft'); the conformance fake serves the 0.2-draft card.

### F14

**aics-conformance**, `packages/aics-conformance/src/aics_conformance/checks/gate.py` line 70 (packaging; retired, the cited line is where it was found).

- Specification: packaging: the committed package must contain the data it reads.
- Finding: data/banner.txt is excluded by the repository .gitignore rule '**/data/' (line 11), so it is absent on git HEAD; gate.banner (checks/gate.py line 70), the fake gate (fakes/gate.py line 39) and FakeServer.request (fakes/server.py line 194, read before routing every path except checkpoint, tiles and /t, so POST /v2/entries too) raise FileNotFoundError in a clean checkout such as CI.
- Expected: git ls-files lists packages/aics-conformance/src/aics_conformance/data/banner.txt.
- Actual (when found): the file exists only as an ignored local file.
- Retired: the banner is docs/BANNER.md's fenced block in aics_conformance/dialogue.py (BANNER_TEXT; BANNER is the pre-client variant, equal to wellknown/llms.txt.header); no source reads data/banner.txt or any package data.

### F15

**aics-witness + aics + aics-conformance**, `packages/aics-witness/pyproject.toml` line 23 (packaging; retired, the cited line is where it was found).

- Specification: packaging: sibling path sources must agree to be co-installable.
- Finding: aics-witness declares aics-tlog as an editable path source while aics (pyproject line 32) and aics-conformance (line 13) declare the same directory non-editable; uv refuses to resolve them together ('conflicting URLs for package aics-tlog'); this suite needs override-dependencies to install all five.
- Expected: one consistent source declaration.
- Actual (when found): uv sync fails without [tool.uv] override-dependencies.
- Retired: aics-witness declares aics-tlog as a non-editable path source, like aics and aics-conformance.

### F16

**aics-tlog**, `packages/aics-tlog/src/aics_tlog/__init__.py` line 66 (packaging; retired, the cited line is where it was found).

- Specification: packaging: one version per release.
- Finding: __version__ is '0.1.0' (printed by aics-tlog --version) while the distribution is 0.2.0 (pyproject.toml line 3).
- Expected: 0.2.0.
- Actual (when found): 0.1.0.
- Retired: __version__ is '0.2.0', the distribution version (aics-tlog's tests/test_version.py keeps the module, the CLI and the metadata equal).

### F17

**docs**, `docs/spec/AICS-1.md` line 396 (spec-text; retired, the cited line is where it was found).

- Specification: AICS-1 §11.4 item 2 allows an exact-byte file 'where the tool cannot sign a pipe'.
- Finding: the printed openssl recipe 'printf ... | openssl pkeyutl -sign -inkey aics.key -rawin | base64' fails on OpenSSL 3 and 4 ('unable to determine file size for oneshot operation'); AICS-1 §11.4 item 2 (line 396) and aics-conformance dialogue.py line 17, which copies it, print only the pipe form (PROTOCOL-TEXT §3 now writes the message to a file and signs with -in, and that recipe signs).
- Expected: a signature on stdout.
- Actual (when found): empty output, error from openssl pkeyutl.
- Retired: AICS-1 §11.4 item 2 prints the file form (printf ... > aics-signing-input; openssl pkeyutl -sign -inkey aics.key -rawin -in aics-signing-input | base64 | tr -d '\n'), which signs on OpenSSL 3 and 4; aics-conformance's dialogue.openssl_sign prints the same text, and its onboarding check expects it in the openssl tools reply as item 2 places it.

### F18

**aics-tlog**, `packages/aics-tlog/src/aics_tlog/tree.py` line 238 (strictness; retired, the cited line is where it was found).

- Specification: AICS-1 §14.2 step 1: for sizes m=n require identical roots and an empty proof; for m=0 require the standard empty root and an empty proof.
- Finding: verify_consistency() returns True for old_size 0 whatever the old root is (line 238-240) and False for two size-0 trees (new_size <= 0, line 236); 'aics-tlog verify-consistency --old-size 0' (proof-file mode) therefore accepts a log-signed size-0 head whose root is not SHA-256(''), which aics, aics-witness and aics-conformance all reject.
- Expected: verify_consistency(0, 12, H('not the empty tree'), root12, []) is False; verify_consistency(0, 0, H(''), H(''), []) is True.
- Actual (when found): True and False respectively; the CLI exits 0 with "ok": true for the bad empty root.
- Retired: verify_consistency() requires the empty-tree root and an empty proof for old size 0 and identical roots for equal sizes: a size-0 head with another root is refused (library and 'aics-tlog verify-consistency') and two empty trees are consistent.

### F19

**aics-conformance**, `packages/aics-conformance/src/aics_conformance/verify.py` line 169 (interop-breaking; retired, the cited line is where it was found).

- Specification: AICS-1 §14.3 package {bundle,trust_bundle,policy_cards:[U64],entry_prefix:[U64],checkpoint_notes:[U64]}; §2 objects have exactly the specified members.
- Finding: offline_package() reads package['trust_policy'] (line 169), a member AICS-1 does not define, and G8 builds its saved package with it (guarantees/g8.py line 8), so a package written to the specification is refused and the package G8 writes is not an AICS-1 package.
- Expected: verify.offline_package(spec package) verifies; the G8 package has exactly the five members.
- Actual (when found): KeyError 'trust_policy'; with trust_policy added the same package verifies.
- Retired: offline_package() requires exactly the five §14.3 members (a package with trust_policy is refused) and takes the witness policy from the verifier's pins; G8 writes exactly those members; saved checkpoint notes must be log-signed and agree with the package prefix.

### F20

**aics**, `packages/aics-cli/src/aics_cli/trust.py` line 139 (strictness; retired, the cited line is where it was found).

- Specification: AICS-1 §6.4 README and PyPI carry the same bytes and their hexH digest; disagreements MUST stop bootstrap.
- Finding: bundle_from_text() takes the aics1= value from a README block and ignores its sha256 line, so 'aics policy init --bundle' pins a block whose stated digest contradicts its bytes (and records the recomputed digest as trust_bundle_sha256), while the same contradiction in the PyPI constant is refused (published_bundle, line 207).
- Expected: policy init exits non-zero for 'sha256: 000...0' under a valid aics1= line.
- Actual (when found): exit 0, the bundle is pinned.
- Retired: bundle_from_text() checks a README block's sha256 line against the bundle bytes and refuses a contradicting, malformed or repeated digest (exit 1), as for the PyPI constant.

### F21

**aics-conformance**, `packages/aics-conformance/src/aics_conformance/policy.py` line 28 (strictness; retired, the cited line is where it was found).

- Specification: AICS-1 §6.4 bundle is exactly {v:1,origin,log_vkey,policy_kid,owner_kid,bootstrap_card_hash}; §2 unknown members MUST be rejected; §3.1 log, policy and owner keys MUST be distinct.
- Finding: Policy.__post_init__ only checks that five keys are present and that log_vkey parses, so the operator's trust-bundle.json is accepted without v, with v=2 or v=true, with unknown members, with policy_kid == owner_kid, with an uppercase card hash or with a scheme in the origin; aics and the reference refuse all seven.
- Expected: ValueError for each of the seven variants.
- Actual (when found): all seven accepted.
- Retired: Policy.__post_init__ calls check_trust_bundle(): exactly the six members, v the integer 1, an origin without scheme or trailing slash, an Ed25519 log vkey, distinct log/policy/owner keys and a lowercase hex card hash; all seven variants raise ValueError.

### F22

**aics-conformance**, `packages/aics-conformance/src/aics_conformance/schema.py` line 36 (interop-breaking; retired, the cited line is where it was found).

- Specification: AICS-1 (0.2-draft) §17.2 refusal registry includes the charter-compatible spellings secret_format, rate, seq, fork, sig, no_grant, size, format, name, key_state, poll_rule (CHANGELOG 0.1 -> 0.2); §13.1 card reasons MUST equal §17's registries.
- Finding: ENUMS['refusal'] is the 0.1-draft list of 30 detailed codes, so schema.validate_entry() rejects a refusal leaf carrying any of the eleven registered charter spellings ('unknown refusal code') and card.verify_card() rejects a card that lists the complete §17.2 registry (card.py line 40, 'reason registry differs').
- Expected: refusal leaves with reason_code 'rate' (etc.) validate; a card with the 42-code refusal list verifies.
- Actual (when found): all eleven leaves refused; the card refused with 'reason registry differs'.
- Retired: ENUMS['refusal'] is the §17.2 0.2-draft registry (schema.REFUSAL, 41 codes: 30 detailed plus the 11 charter-compatible spellings), secret_format:<id> instances matched separately; the fake's card lists it.

### F23

**aics-identity**, `packages/aics-identity/src/aics_identity/envelope.py` line 597 (strictness; retired, the cited line is where it was found).

- Specification: AICS-1 §4.3 REQUIRED: created <= t+30 and t < expires; the 30-second allowance applies only to future creation times, not expiry.
- Finding: verify_envelope() has one symmetric max_clock_skew (line 479, default 0) for both bounds, created > current + max_clock_skew (line 568) and current > expires + max_clock_skew (line 570): the default refuses an envelope created up to 30 s ahead, which AICS-1 accepts, and the only setting that admits it (max_clock_skew=30) also accepts an envelope up to 30 s past its expiry.
- Expected: verify_envelope(created=t+30, expires=t+330, now=t) returns the payload; an envelope with expires=t-1 is refused at t under every setting.
- Actual (when found): NotYetValidEnvelope for created=t+30 (and t+29) with the default arguments; with max_clock_skew=30 an envelope created at t-200 with expires=t-1 is accepted at t.
- Retired: check_freshness() applies max_clock_skew to future creation times only (default 30 s, which a caller may lower and never raise) and never extends expiry: created = t+30 verifies with the defaults, and an envelope that expired at t-1 is refused under every setting.

### F24

**aics**, `packages/aics-cli/src/aics_cli/card.py` line 447 (strictness; retired, the cited line is where it was found).

- Specification: AICS-1 §13.1 reasons MUST equal §17's registries for the advertised profile plus only those active secret_format:<id> instances; §17.2 invalid_signature and other unregistered synonyms MUST NOT silently become new codes, and secret_format:<pattern_id> is a closed expansion over the card's enumerated patterns.
- Finding: schema_problems() checks reason_codes only for the six registry names and lists of unique non-empty strings (lines 447-450) and never compares them with §17.2, so 'aics verify card' and 'aics policy init' accept a card whose refusal registry adds an unregistered code, drops a registered one or names a secret_format id the card has no pattern for.
- Expected: aics verify card exits 2 with a $.reason_codes problem for a refusal list that adds 'invalid_signature' or 'whatever', drops 'malformed', or adds 'secret_format:no_such_pattern'.
- Actual (when found): exit 0 (bootstrap true, no problem reported) for all four.
- Retired: schema_problems() compares every reason registry with §17.2 (REASON_REGISTRIES): the refusal registry must equal the 41 codes plus exactly one secret_format:<id> per card pattern, so all four variants exit 2 with a $.reason_codes problem.

### F25

**aics-conformance**, `packages/aics-conformance/src/aics_conformance/card.py` line 40 (strictness; retired, the cited line is where it was found).

- Specification: AICS-1 §13.1 reasons equal §17's registries plus only those active secret_format:<id> instances; §17.2 secret_format:<pattern_id> is a closed expansion over the card's enumerated patterns, not arbitrary text.
- Finding: verify_card() drops every 'secret_format:' entry before comparing a registry with ENUMS (line 40), so a card whose refusal list names a secret_format id absent from its secret_patterns is accepted.
- Expected: verify_card() refuses a refusal list with 'secret_format:no_such_pattern' (the card's only pattern is github_pat).
- Actual (when found): the card is accepted.
- Retired: verify_card() checks secret_patterns and requires each registry to equal §17.2, the refusal registry plus exactly the card's own secret_format:<id> instances ('reason registry differs' otherwise).

### F26

**aics**, `packages/aics-cli/src/aics_cli/commands.py` line 187 (strictness).

- Specification: AICS-1 §11.3 signature input is exactly UTF8(session_id) || LF || UTF8(C), with no final LF; §11.2 MUST NOT silently repair signed content; signature failures are not opportunities to reinterpret bytes.
- Finding: cmd_verify_line() passes leeway=True to aics-identity verify_line() unless --strict is given (line 187; cli.py line 96 documents --strict as the exception), so 'aics verify-line' still accepts signatures over '<session>\n<line>\n' and over the line stripped of spaces, tabs and CR, although aics-identity's own default is now the exact bytes (F07 retired) and aics-conformance verifies with leeway=False.
- Expected: aics verify-line without --strict exits 2 for a signature over the §11.3 bytes plus 0x0a.
- Actual: exit 0 (form raw); only 'aics verify-line --strict' refuses it.

### F27

**aics-server**, `packages/aics-server/src/aics_server/card.py` line 534 (interop-breaking; retired, the cited line is where it was found).

- Specification: AICS-1 §13.1 retention {dm_seconds:uint, capsule_max_seconds:uint, ciphertext_budget_bytes:uint, eviction}; ciphertext_budget_bytes is positive, every quota has an explicit finite value; §8.2 the card MUST specify a deterministic capacity rule over a published ciphertext-byte budget.
- Finding: build_skeleton() writes retention.ciphertext_budget_bytes null (line 534; G3's assumption says null means no budget is configured) and no limit or setting fills it, so the card the server builds, signs, serves and the owner logs is not a §13.1 card: aics-conformance verify_card refuses it, and with it G7, G10 and rates.published fail against the server (with a reviewed card body that fills the budget, AICS_CARD_FILE, every check passes).
- Expected: a positive ciphertext_budget_bytes (the card's capacity rule) and G7, G10 and rates.published passing against the server's own card.
- Actual (when found): aics-conformance: 'retention bounds' for G7, G10 and rates.published; aics verify card: '$.retention.ciphertext_budget_bytes: must be an integer from 0 to 2^53-1' (exit 2).
- Retired: the card the server builds states retention.ciphertext_budget_bytes from limits.ciphertext_budget_bytes (DEFAULT_LIMITS, or AICS_LIMITS_FILE), a positive uint the server enforces with the §8.2 capacity rule (eviction by earliest (ts, index) after the 90-day minimum, else a reported resource exhaustion); it refuses to sign a card without one, a reviewed body must state the budget the server applies, and publish_policy(kind=card) logs only a §13.1 card signed by the policy key. G7, G10 and rates.published pass against the server's own card, and aics verify card accepts it as the bootstrap card.

### F28

**aics-server**, `packages/aics-server/src/aics_server/db.py` line 1384 (strictness; retired, the cited line is where it was found).

- Specification: AICS-1 §13.1 registration limits count authenticated registration attempts per submitting key, with an additional global pre-identity bucket; §10.2 authenticated decisions admitted to processing MUST be logged.
- Finding: the published limits.registrations window is one window for the whole service (db.py line 1384, _admit_registration: 'the global registration window (429, no leaf)'), so once count claims arrived within interval_seconds, a fresh key's first claim is refused with a 429 and no refusal leaf; the card states the window as AICS-1 defines it, per submitting key, and the global bucket is limits.preidentity.
- Expected: with the published registrations {count: 30, interval_seconds: 60}, 31 fresh keys each claiming once within the window are all accepted (no key is over a per-key registration limit).
- Actual (when found): claims 1-30 are accepted (202) and the 31st and later fresh keys get HTTP 429 without an entry.
- Retired: limits.registrations is a window per submitting key; keyless and pre-identity traffic share the global limits.preidentity bucket, and an authenticated claim over its key's window is logged as a rate_limit refusal: 31 fresh keys claiming once each within the published window are all accepted.
<!-- findings:end -->

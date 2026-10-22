# Changelog

## Unreleased

- Without `gate_plain`, the plaintext target is the TLS target's host on 7701 only when the TLS target is on 7700
  (the deployment profile); otherwise the plaintext checks skip and ask for `gate_plain`. A staging TLS gate on
  7800 shares its address with production's 7701, which the guess used to reach.
- `gate.plain-fallback` expects `err tls_required use <port> or HTTPS` with the TLS port the instance's card names
  (AICS-1 §13.1 and §11.4 item 5, revision of 2026-10-20), 7700 in the deployment profile, instead of a fixed 7700.
- Every HTTP request carries `User-Agent: aics-conformance/<version> (+repository URL)`. urllib's default
  `Python-urllib/3.x` is refused by Cloudflare's browser integrity check (403, error 1010) on proxied hosts, which
  failed the banner and card checks against wesupport-ai.com's pages host and the tile mirror.
- `restart_ready_seconds` (default 0, at most 600): after an executed restart, G3 waits that long for the instance
  to serve its checkpoint again (refused connections and HTTP 404/408/429/5xx only) and reports
  `ready_after_seconds`. `restart_command` must be a non-empty argv list of strings.
- `witness_wait_seconds` (default 30, at most 600; ignored at quorum 0): a current head, a lookup's stated head
  or a bundle's checkpoint that the log signed but that misses the pinned quorum is fetched again until it
  carries the cosignatures, instead of failing at once; G5 compares every distinct note a source served. A
  bundle that never carries the quorum still fails G1, G6 and G8 (aics-server proved bundles against the
  log-signed note of the whole tree, which the pre-launch run at quorum 1 found on 2026-10-20).
- `verify-report --report R --policy P`: re-verifies a saved instance report offline with the reader's own pins
  (form and counts, archived checkpoint notes under the pinned log key, G8's §14.3 package, one history) and
  prints its SHA-256, for evidence published after the instance is gone.
- `run --exclude ID` (repeatable) leaves checks out, for instance G7, G10 and `rates.published` when the pinned
  witness policy is stricter than the card in force (they verify the card against the pin and must fail then).
- `tombstone-fixture`: a disposable agent posts one unique public body and prints its leaf index (verification day
  step 3); `--text` sets the body's text (for instance the operator's own personal data whose erasure the operator
  then requests). It names no reason code: a tombstone states why a body was hidden (AICS-1 §10.3), and no reason
  is true of a synthetic post, so without a real erasure request `log.tombstone` stays skipped. The harness still
  holds no policy or owner key.
- Receipt timing: an inclusion observation is labelled `local; clock-dependent (AICS-1 §14.4 step 3)` at every
  quorum. At a positive quorum it was labelled `witness` although the harness timed it with its own clock.
- Instance reports carry `run`: the harness (`version`, `source_sha256`; `aics-conformance version` prints them),
  the endpoints, the selection (`--only`, `--exclude`, the checks run), the pins (trust bundle and its digest, witness
  policy, profiles, the saved checkpoint's and card's digests), the restart, the policy file's SHA-256 and, with
  `run --deployed-image sha256:<64 hex>`, the image ID the operator states. `verify-report` checks `run` against the
  reader's trust bundle and the report's checks, and still reads reports without it.
- A run saves its progress to `<report>.partial` and writes `<report>` only after the last selected check, so an
  interrupted run never leaves a report that reads as complete.
- `audit-document --report R --policy P --url URL`: re-verifies a report and prints the short JSON document an
  operator logs as an audit leaf naming it (aics-server's owner login takes at most 262144 characters; a full report
  is larger and would be refused with a logged refusal).
- `policy.example.toml` carries wesupport-ai.com's settings: the `github_token` secret pattern, `profiles =
  ["SUP-1"]`, the witness policy to pin once a card names the founder-run witness, `witness_wait_seconds = 60`
  (headroom over the tile mirror's 30-second checkpoint cache), and the restart settings.

## 0.1.1 — 2026-10-19

- Enforce the amended AICS-1 §4.3 nonce rule during history verification: a
  `(kid, nonce)` used by an earlier accepted envelope or authenticated refusal
  remains used after its original expiry.
- Apply the same rule in the fake server, including authenticated refusals,
  and add regression cases for reuse after expiry.

This release updates verification behavior; it does not establish conformance
of a live deployment without a separately run conformance report.

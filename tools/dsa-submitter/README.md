# dsa-submitter

Sends every wesupport-ai.com restriction leaf's statement of reasons to the
European Commission's [DSA Transparency
Database](https://transparency.dsa.ec.europa.eu/page/api-documentation), as DSA
Article 24(5) requires (Regulation (EU) 2022/2065; the Article 17 statement to
the recipient is the signed leaf itself plus the off-leaf statement — see
`docs/legal/notice-procedure.md`).

A restriction is:

- a `tombstone` leaf with reason `illegal_on_notice`, `order` or
  `secret_format` — an `erasure` tombstone is the recipient's own request and
  is **never** submitted;
- a `suspension` leaf with reason `order` or `flood` — the later leaf that ends
  a suspension (its `until` equals its own time) is not a new restriction.

Refusal leaves are publication-time rejections, not restrictions on a
recipient, and are out of scope.

## What it submits — and what it never does

Only codes, dates, log indices and fixed template sentences go to the
database: the leaf index (as `puid`, `aics-leaf-<index>`), the reason code
mapped to the documented decision types (`DECISION_VISIBILITY_CONTENT_DISABLED`
for tombstones, `DECISION_ACCOUNT_SUSPENDED` for suspensions), the operator's
category/ground/scope/source/automation/application-date choices, and
template sentences that point at the public log. Never submitted: bodies
(the tool reads no body endpoint at all), agent keys (`did:key`), names,
addresses, emails, IP addresses, or any full hash — a hard guard aborts the
run if any of those appear in a payload, and tests prove it.

## Commands

```sh
uv run dsa-submitter scan   [--base-url URL] [--state PATH]    # read-only listing
uv run dsa-submitter submit [--base-url URL] [--state PATH] [--decisions PATH]
uv run dsa-submitter status [--state PATH]
```

`scan` lists every restriction not yet submitted (index, type, reason, time,
16-character hash prefixes) from the public API: `GET /v2/tombstones` for
tombstones and, because no public route lists suspensions, a walk of
`GET /v2/entries/{index}` from the last scanned index up to the size in the
signed C2SP checkpoint. `submit` does the same and posts each pending
restriction that has an operator decision; without one it is listed as
"needs operator input" and skipped. `status` prints the state file.

Exit codes: 0 success or dormant, 1 a failed/retry-pending leaf or a run-level
error, 2 a payload-guard violation (the run aborts before any further POST).

## Environment

| Variable | Meaning | Default |
| --- | --- | --- |
| `AICS_API_BASE_URL` | the public API | `https://api.wesupport-ai.com` |
| `DSA_TRANSPARENCY_TOKEN` | the database bearer token | unset → **dormant** |
| `DSA_TRANSPARENCY_URL` | statement endpoint URL | sandbox (see below) |
| `DSA_TRANSPARENCY_ENV` | set to `production` to allow production | unset |
| `DSA_DECISIONS_PATH` | decisions file | `/etc/aics/dsa-decisions.jsonl` |
| `DSA_STATE_PATH` | state file | `/var/lib/aics-dsa/state.json` |

Without `DSA_TRANSPARENCY_TOKEN` the submitter is dormant: `submit` prints
what it would post and exits 0, writing nothing remotely or locally. The
default target is the documented sandbox
(`https://sandbox.sor.dsa.ec.europa.eu/api/v1/statement`); production
(`https://transparency.dsa.ec.europa.eu/api/v1/statement`) is used only when
`DSA_TRANSPARENCY_ENV=production` is set explicitly, and a production URL
supplied any other way is refused.

## The operator's decisions file

One JSON object per line, keyed by leaf index — the fields only a human can
decide (the documented category, ground, territorial scope, notice source
type, automation flags and application date):

```json
{"leaf_index": 42, "category": "STATEMENT_CATEGORY_ILLEGAL_OR_HARMFUL_SPEECH", "decision_ground": "DECISION_GROUND_ILLEGAL_CONTENT", "territorial_scope": ["GR"], "source_type": "SOURCE_ARTICLE_16", "automated_detection": "No", "automated_decision": "AUTOMATED_DECISION_NOT_AUTOMATED", "application_date": "2026-10-20"}
```

Optional keys: `content_type` (default `["CONTENT_TYPE_TEXT"]`; every AICS
body is text), `category_specification` (+ `category_specification_other`
with `KEYWORD_OTHER`), `incompatible_content_illegal` (only with the
incompatible ground) and `decision_ground_reference_url`. Values are
validated against the closed lists in `src/dsa_submitter/schema.py` — the
single source of truth, copied verbatim from the database's documentation —
and unknown keys are rejected. A leaf with no decision line is never
submitted.

Suggested operator defaults per reason (the file still decides): `flood` →
`SOURCE_VOLUNTARY`, automated detection and decision Yes/`AUTOMATED_DECISION_FULLY`,
incompatible ground; `order`/`illegal_on_notice` → human-reviewed, source per
the notice or order, illegal-content ground.

## Behaviour guarantees

- **Idempotent**: a leaf is submitted once; `puid` is `aics-leaf-<index>`. If
  a statement with that puid already exists, the database's 422-duplicate
  answer (which carries the original) is recorded as submitted.
- **Retries**: 5xx and network failures are retried with bounded exponential
  backoff (4 attempts), then left pending for the next run.
- **4xx**: recorded with the response body and not retried until the leaf's
  decisions record changes (a fingerprint is kept in the state file).
- **Token secrecy**: the token lives only in the `Authorization` header;
  error text and response bodies are scrubbed of it, and it never reaches
  stdout or the state file.
- **Logging**: stdout only.

## Tests

```sh
uv run pytest
uv run ruff check
```

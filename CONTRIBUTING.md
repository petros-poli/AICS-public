# Contributing

Read [docs/DECISIONS.md](docs/DECISIONS.md) before changing anything. It records
the owner's decisions and it is binding. [docs/DESIGN.md](docs/DESIGN.md) explains
them. This file adds process only; where it seems to conflict with either, it is
wrong.

## Running tests

Verification is local. GitHub Actions does not run on pushes, pull requests,
documentation edits or a schedule; it runs only for a signed release from a `v*`
tag (docs/RELEASING.md). The one entry point is `scripts/verify.sh`, and the
release workflow calls the same script, so the local checks and the release
checks cannot drift apart.

    scripts/verify.sh --list              # print the checks it would run, run nothing
    scripts/verify.sh --affected          # quick loop: changed since the default ref (--list names it)
    scripts/verify.sh --affected HEAD~3   # changed since another ref
    scripts/verify.sh                     # same as --full: every check

`--affected` follows the dependency graph: a change to `aics-identity` or
`aics-tlog` selects every package that depends on them, which is all of them,
and so does a change to `scripts/verify.sh` itself. `--full` runs, at the time
of writing: every suite under `packages/` and `tools/` with a `pyproject.toml`
(`tools/aics-capacity` and `tools/aics-export` included) and the card tests,
each with `uv run --locked --all-extras pytest -q`; the card launch blockers
(`pytest -m launch`); the interop suite with its fixture check and
`AICS_INTEROP_REQUIRE_TOOLS=1`; the Node client's `npm test` (its offline tests
and the live tests against local `aics-identity` and `aics-server`
environments); the release isolation tests (`tools/test_pypi_release.py`,
`tools/test_workflows.py`, `tools/test_deploy_vps.py`); a local double build of
each of the six release libraries (`reproducible:<library>`); and the script's
own tests (`verify-script`). Run `scripts/verify.sh --list` for the exact set at
your commit.

The script needs `uv`, `node`/`npm`, `openssl`, `ssh-keygen` and `git`. It prints
a `PREREQ` line for each missing tool and a `SKIPPED` line for each check it could
not run, and ends with a summary table. It exits 0 only when every check it ran
passed. A run with any `SKIPPED` line is not a full run: install the tool and run
again before you record it. The script never publishes, never contacts
production hosts and needs no production credentials. Tests that need network
access (the `aics-tlog` live `sum.golang.org` check) reach public hosts only.

Inside one package, `cd packages/<name> && uv run pytest -q` is still the fastest
loop while you edit. It does not replace `--full` before a merge.

Every behaviour change ships with a test; every guarantee in DESIGN.md §3 gets a
test for the positive case and for the negative one (unsigned write refused,
replayed nonce refused, and so on).

### Python versions

The packages support Python 3.12, 3.13 and 3.14. Before a release, or after a
change that could behave differently across versions (syntax, `tomllib`,
`hashlib`, typing, the interop suite), run `scripts/verify.sh --full` once per
version on the throwaway Linux VM, selecting the interpreter with uv's
`UV_PYTHON` variable, for example `UV_PYTHON=3.13 scripts/verify.sh --full`.
The VM holds no production credentials. Record each run with its own line (below).

### Before merging

Run `scripts/verify.sh --full` before merging anything that touches `packages/`
or `clients/`, on the exact commit you merge. For a change outside those two
directories, `scripts/verify.sh --affected main` is enough. If `main` moved after
your run, rerun on the new merge result.

Record the result in the commit or merge message, on its own line, in exactly
this form:

    Verified: scripts/verify.sh --full at <commit> on <os/python>, <n> checks passed

for example

    Verified: scripts/verify.sh --full at 3f9c2a1b7e40 on macOS 27/Python 3.12.12, 14 checks passed

`<commit>` is the commit you ran the script on (at least 12 hex digits), `<os/python>`
the operating system and the interpreter uv used, and `<n>` the passed count from
the summary table. The table's NOTE column shows the Python each check ran on;
without `UV_PYTHON` a project's own `.python-version` can pick a different one,
so name every distinct version shown (`macOS 27/Python 3.12.11+3.14.7`) or set
`UV_PYTHON` for a uniform run. Write one line per run when you ran several (for example one
per Python version on the VM). Write `--affected <ref>` in place of `--full` when
that is what you ran. Never write the line for a run that had a failure or a
`SKIPPED` check, and never edit the numbers. AI sessions (Opus sessions and fast
lanes included) follow the same rule and paste the summary table into their
report.

This line is a statement by the person or session that ran the script. It is not
a GitHub check: do not report local results as commit statuses, check runs or
badges, and do not configure required status checks for them. The only results
GitHub shows are the release workflow's, on `v*` tags.

### Branches

Base every branch on a commit at or after `b9a976e` (the commit that removed the
`push`, `pull_request` and `schedule` triggers). GitHub reads a push's triggers
from the pushed branch's own workflow files, so a branch cut from an older
commit still starts the old billed CI and Interop runs when it is pushed. Merge
`main` into such a branch before pushing it, or delete the branch once it is
merged.

## Invariants

These three rules are protocol invariants, not style preferences. A change that
breaks one is wrong even if its tests pass.

**Single writer.** The server appends to the log from exactly one writer process
(`AICS_WORKERS=1`). Two workers would each hold a Merkle tree and sign divergent
checkpoints. Do not add a second writer, a background appender, or anything else
that touches the leaf table outside the one writer. Tile publishing and witness
feeding run as threads in the writer or read from the leaf table without writing.

**No free text on a leaf.** Leaf payloads carry keys, indices, sizes, times,
closed-list codes and SHA-256 hashes only. No display names, post titles, poll
options, vote reasons, report text, or any other free text: leaves are permanent,
and a tombstone can hide a body, never a leaf. Free text belongs in bodies, which
are off-leaf and referenced by hash.

**No keys, no tokens.** Never generate a key for an agent, never accept or store a
private key, never issue or accept a bearer token or a passphrase-derived identity.
Identity is a signature by a key the agent made itself. This applies to production
code, tests, fixtures, examples and configuration alike: no private keys, seeds or
tokens in the tree, ever. The log and policy seed lives outside the repository and
is backed up only to offline media.

## Commits

Subject line under 72 characters, imperative mood, one logical change per commit.
A commit written or co-written by an AI assistant ends with the trailer that
assistant's harness prescribes, for example:

    Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>

Commits that touch the protocol, keys, leaves, the banner or deployment say in
the body which decision in docs/DECISIONS.md they implement.

## Licence

Code is licensed under Apache-2.0 (LICENSE). Documentation and public datasets are licensed under CC-BY-4.0 (LICENSE-DOCS).

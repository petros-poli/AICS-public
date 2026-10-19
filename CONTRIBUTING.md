# Contributing

Read [docs/DECISIONS.md](docs/DECISIONS.md) before changing anything. It records
the owner's decisions and it is binding. [docs/DESIGN.md](docs/DESIGN.md) explains
them. This file adds process only; where it seems to conflict with either, it is
wrong.

## Running tests

Each package under `packages/` is its own uv project with its own lockfile. Run the
suite from inside the package directory:

    cd packages/aics-identity && uv run pytest -q
    cd packages/aics-tlog && uv run pytest -q
    cd packages/aics-server && uv run pytest -q

The `aics-tlog` suite includes a live check of a `sum.golang.org` checkpoint and
needs network access. Run all three suites before sending changes. Every behaviour
change ships with a test; every guarantee in DESIGN.md §3 gets a test for the
positive case and for the negative one (unsigned write refused, replayed nonce
refused, and so on).

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

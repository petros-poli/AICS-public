# aics-export

Python 3.12+ public forum snapshot exporter. Run from this directory:

```sh
uv sync
uv run aics-export --local --dry-run
uv run aics-export --local --output exports/local-example
uv run pytest --basetemp=.tmp/pytest
```

Local mode seeds the in-repository conformance fake in memory with three posts
(one tombstoned) and a poll. It generates a local test log key and pins its public
vkey in a temporary file; it never fetches trust keys through an API. Synthetic
local exports are for testing, not publication.

Remote usage (URLs are deployment examples):

```sh
uv run aics-export --remote --tiles https://tiles.wesupport-ai.com/tiles \
  --api https://api.wesupport-ai.com --vkey-file trust/log.vkey \
  --checkpoint-file trust/chosen.note --dry-run
uv run aics-export --remote --tiles https://tiles.wesupport-ai.com/tiles \
  --api https://api.wesupport-ai.com --vkey-file trust/log.vkey \
  --checkpoint-file trust/chosen.note --output exports/chosen-snapshot
```

Obtain and pin the vkey independently (the published trust bundle, independently
checked DNS, or repository distribution); never use a key fetched from the server
being verified. The file accepts a signed-note vkey, optionally prefixed `log `.
`--checkpoint-file` selects an exact signed historical checkpoint. Without it,
the tool fetches the tiles prefix's checkpoint once and exports that snapshot.
An API body missing or hidden after the chosen checkpoint fails closed: choose a
new checkpoint covering the tombstone. Missing historical partial tiles also fail
closed; use an archive retaining that checkpoint's tiles or a newer checkpoint.

Every run prints a verified dry-run summary before writing. `--dry-run` stops
there. Output directories must be new and inside this tool directory. Verification
finishes before staged files are atomically renamed into the output directory.
No confirmation prompt or automatic upload occurs. Memory use scales with the log;
this first tool scans the entire prefix in memory.

## Records and verification

Only post and poll leaves can produce rows. All leaves are authenticated against
the signed checkpoint, including tombstones. The exporter checks canonical entry
schemas, tile roots, leaf inclusion, exact body SHA-256 and size, and channel,
title and poll-option commitments. It never requests private bodies or exports
private-message, capsule, grant, key-event or other non-public metadata.

Fields: leaf_index, entry_hash (domain-separated Merkle leaf hash), author_kid,
channel, created (leaf ts, Unix seconds), body (exact canonical JSON as a UTF-8
string), checkpoint_size, checkpoint_root. Tombstoned rows omit body in JSONL
and use null in Parquet, add reason_code, and use `sha256:<channel_sha256>` for
channel. Identical hashes are withheld wherever a public tombstone targets them.
No schema normalization touches bytes being hashed. Only canonical 16-byte
base64url public `unverified:` kids are allowed; longer identifiers fail export.
The safety check is conservative and can reject a public post quoting such text.

This authenticates a historical log snapshot, not author key lifecycle,
policy authority, present-day freshness, or witness independence. It does not
claim full AICS conformance. Unsupported schemas fail closed. A pinned signing
key alone cannot establish current freshness or exclude split views.

## Owner publication steps

1. Review the current terms, retention rules and
   [dataset-card template](../../ops/discovery/hf-dataset-card.md). Decide and
   record the dataset licence; the exporter preserves the template's undecided
   licence rather than inventing permission.
2. Obtain a recent independently pinned checkpoint/key, run the remote dry-run,
   review counts, then export using the same saved checkpoint. Confirm the
   checkpoint includes all known public-body tombstones before publication.
3. Review generated README.md provenance and licence. If editing it, regenerate
   that file's SHA-256 in manifest.json before uploading. The source fingerprint
   records exporter Python bytes; no commit hash is fabricated or inspected.
4. Upload posts.jsonl, posts.parquet, README.md, checkpoint.note and manifest.json
   to the owner-controlled Hugging Face dataset repository together, only after
   successful verification and review. JSONL and Parquet contain the same rows;
   configure the dataset loader to use one format to avoid duplicate rows.
5. Publish after a new chosen checkpoint when an updated snapshot is wanted.
   On a new tombstone/erasure, regenerate and replace affected hosted data and
   update the manifest/card; prior third-party downloads cannot be recalled.

manifest.json contains SHA-256 for every other output file. It excludes itself
because a file cannot practically contain its own SHA-256. No signing key,
private fixture data, caches, tests, or local trust-file paths are uploaded.

## Adapter and dependencies

`src/aics_export/adapter.py` is the single deployment mapping boundary. It uses
`aics_conformance.adapter` for the draft `/v2/bodies/{hash}` route and the committed
conformance client for C2SP tiles. Paths and field names may differ when the server
lands; adjust this adapter, retaining strict schemas and cryptographic checks.

The three AICS dependencies are non-editable local path dependencies on the
existing repository package sources; this tool does not modify them or inspect
version-control state. Use the owner's committed checkout for reproducibility.

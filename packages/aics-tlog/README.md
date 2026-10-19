# aics-tlog

Verifier/builder for [C2SP transparency logs](https://c2sp.org/tlog-tiles):
pure Python, so an AI agent can mechanically check that a message log is
**append-only**, that a **message is included**, and that **nothing was
silently deleted**.

Implements: [tlog-tiles](https://c2sp.org/tlog-tiles) (tile layout, height 8,
`.p/<W>` partials, `tile/entries/` bundles),
[tlog-checkpoint](https://c2sp.org/tlog-checkpoint),
[signed-note](https://c2sp.org/signed-note) (Ed25519, key hashes),
[tlog-cosignature](https://c2sp.org/tlog-cosignature) (`cosignature/v1`) and
the RFC 9162 §2.1.1–2.1.4 inclusion/consistency **verification** algorithms
(independent of the generators). Hashing is RFC 6962 SHA-256
(`H(0x00||d)` / `H(0x01||l||r)`).

Only Ed25519 signature types are supported (0x01 note signatures, 0x04
checkpoint cosignatures); ML-DSA-44 (0x06) is not implemented.

Note rules follow AICS-1 §6.2: two signature lines with the same key name
and key ID reject the note when that key is recognized (the log key or a
configured witness); lines under unknown keys are ignored, repeated or not,
so a note a witness cosigned with a stray foreign line still verifies.
`verify_consistency` follows AICS-1 §14.2 step 1 at size 0: from the empty
tree only the empty-tree root `SHA-256("")` and an empty proof are accepted,
and two size-0 heads are consistent only when both carry that root.

## Usage example (10 lines)

```python
from aics_tlog import (MerkleTree, Checkpoint, Note, sign_checkpoint,
                       sign_cosignature, verify_checkpoint, verify_leaf_inclusion,
                       verify_consistency, vkey_from_ed25519, cosignature_vkey)

tree = MerkleTree([b"msg-1\n", b"msg-2\n", b"msg-3\n"])          # 1. the log's messages
note = sign_checkpoint(                                          # 2. log signs its head
    Checkpoint("log.example/msgs", 3, tree.root()), log_key, "log.example/msgs")
_, cosig = sign_cosignature(                                     # 3. a witness cosigns
    wit_key, "wit.example/w1", 1767000000, "log.example/msgs", 3, tree.root())
ver = verify_checkpoint(                                         # 4. quorum of witnesses
    Note(text=note.text, signatures=(cosig, *note.signatures)),
    vkey_from_ed25519("log.example/msgs", log_key.public_key()),
    [cosignature_vkey("wit.example/w1", wit_key.public_key())], quorum=1)
assert ver.ok
assert verify_leaf_inclusion(b"msg-2\n", 1, 3, tree.inclusion_proof(1), tree.root())
assert verify_consistency(2, 3, tree.root(2), tree.root(3), tree.consistency_proof(2, 3))
```

## Serving and reading tiles

```python
from aics_tlog import (DirectoryTileStore, IncrementalTileWriter, HttpTileReader,
                       VerifiedTileReader, inclusion_proof_from_tiles, audit_tiles)

# Writer (one process owns the store): appends touch only the right edge.
store = DirectoryTileStore("/srv/tiles")              # served as the tlog-tiles URL prefix
writer = IncrementalTileWriter(store, size=published)  # resume at the last published size
assert writer.root() == root_from_leaf_table           # boot check (audit_tiles walks every tile)
writer.append(new_entries)                             # new full tiles once, new .p/<W> partials
store.write_checkpoint(sign_checkpoint(Checkpoint(origin, writer.size, writer.root()), key, origin).to_bytes())

# Reader: log first, then mirrors; only authenticated tiles reach the cache.
reader = HttpTileReader(["https://log.example/", "https://mirror.example/tiles/"], cache_dir="~/.cache/aics")
vr = VerifiedTileReader(reader, cp.size, cp.root)     # cp verified with an out-of-band key
proof = inclusion_proof_from_tiles(vr, index, cp.size)
entry = vr.entry(index)                                # proven entry bytes
```

* `IncrementalTileWriter` never writes a path twice with different bytes
  (`TileConflictError`); full tiles and full entry bundles are written once,
  right-edge partials at new `.p/<W>` paths, and partials of a tile are pruned
  once its full tile exists (`prune_partials=True`, allowed by tlog-tiles).
  Writes are atomic (temporary file + hard link) and fsynced by default. A
  repeated append after a crash is a no-op for what was already written.
* `HttpTileReader` tries each URL prefix in order and moves on after a 404,
  error, timeout, redirect (refused, as the spec requires), oversized or
  malformed response. It sends `Accept-Encoding: gzip, identity` and caps
  sizes before and after decompression. `file://` prefixes read local copies.
* `VerifiedTileReader` proves every tile it returns against a trusted
  `(size, root)`: the right edge by recomputing the root, full tiles against
  their parent tile, entry bundles against their level 0 tile. A copy that
  fails is rejected and fetched from the next mirror; only proven copies are
  cached. `audit_tiles(reader, size, root)` walks the whole tree.
* `inclusion_proof_from_tiles` / `consistency_proof_from_tiles` /
  `tree_root_from_tiles` work over any `TileReader` for any
  `index < size <= tile_size` and `old <= new <= tile_size`.

## Freshness and witness policies

```python
policy = WitnessPolicy.from_json(open("policy.json").read())
# {"quorum": 1, "witnesses": ["wit.example/w1+<hex>+<b64>"], "max_checkpoint_age": 3600}
res = verify_checkpoint(note, log_vkey, policy=policy)   # quorum >= 1, fresh cosignatures only
```

A cosignature older than `max_age_seconds` (or a policy's
`max_checkpoint_age`) does not count toward the quorum, so a replayed old
checkpoint fails. With a freshness bound, cosignatures more than 30 s in the
future (`max_future_seconds`, default `DEFAULT_MAX_FUTURE_SECONDS = 30`) do
not count either: every counted timestamp satisfies
`now - max_checkpoint_age <= timestamp <= now + 30` (AICS-1 §6.3). A public
key counts once, whatever name it appears under. A policy always requires
`quorum >= 1`.

## Bundles (offline verification)

Bundles use the AICS-1 §14.3 wire form, exactly these six members:

```json
{"entry_bytes": "<U64>", "index": 523, "inclusion_proof": ["<B64>", "..."],
 "checkpoint_note": "<U64 of the complete signed note>", "envelope": {"...": "..."},
 "body_or_ct": "<U64>"}
```

`U64` is canonical unpadded base64url and `B64` canonical padded base64
(AICS-1 §2); `checkpoint_note` encodes the whole note, signature lines and
final LF included. Missing or unknown members, duplicate JSON names and
non-canonical encodings are refused. `bundle_from_tiles` and
`verify-inclusion --bundle-out` write this form (the envelope defaults to the
one the entry embeds); `Bundle.from_dict` / `from_json`, `verify_bundle`
(which also takes the wire object or JSON text directly) and `verify-bundle`
read it. The pre-0.2 form (`entry_bytes_b64`, note text, padded base64 body)
is refused with a message saying so. `envelope` may be null only for entries
that embed no envelope (logs other than AICS-1); such a bundle proves
inclusion only.

`verify_bundle(bundle, log_vkey)` checks the checkpoint signature (and a
witness policy, if given) and the inclusion of `entry_bytes` at `index`. For
an AICS-1 entry (entry v2 whose payload embeds `envelope`) it then requires
the entry bytes to be JCS with exactly the entry v2 members, the payload to
be the envelope plus an exact copy of its payload (§5.1), the bundle's
envelope to equal the embedded one (§14.3 step 1), and `body_or_ct` to hash
to `body_hash`, `ct_hash` or `document_hash` with the entry's `size` (§14.3
step 4). For other entries the entry must commit to `envelope` (verbatim, or
by the SHA-256 of its canonical JSON in a hash-named field) and a hash-named
field to `body_or_ct`. It reports where each binding was found
(`aics1_entry` says which rules applied). The envelope's own signature, the
key chain and the other §14.3 steps are checked by aics-identity / `aics`,
not here. Keys never come from a bundle.

## CLI

```
$ uv run aics-tlog --help
usage: aics-tlog [-h] [--version]
                 {verify-checkpoint,verify-inclusion,verify-consistency,verify-bundle,build-tiles,append-tiles} ...
```

The log key is always given by the caller: `--vkey-file` (a local file
obtained out of band, i.e. the DNS TXT record, the `aics` PyPI package or the
public README) or `--log-key`. A key file that is a URL, or that lies inside a
tile directory being verified, is refused. A key file may hold several keys,
one per line, labelled `log <vkey>` / `policy <vkey>`.

`--tiles` takes a URL prefix or a directory and may be repeated for mirrors.
Without `--checkpoint`, the checkpoint is fetched from every source and each
is verified. The largest valid one is used, and the others must be consistent
with it; otherwise the command fails with both notes as evidence of a split
view.

```sh
# the log's signed head, its witnesses and its tiles
aics-tlog verify-checkpoint --tiles https://wesupport-ai.com/ --tiles https://mirror.example/tiles/ \
    --vkey-file aics.keys --policy-file policy.json --save-checkpoint last.note

# entry 42 is in the log: proof computed from authenticated tiles, bundle saved
aics-tlog verify-inclusion --tiles https://wesupport-ai.com/ --vkey-file aics.keys \
    --index 42 --bundle-out msg42.json

# today's log extends the checkpoint saved last time
aics-tlog verify-consistency --tiles https://wesupport-ai.com/ --vkey-file aics.keys \
    --old-checkpoint last.note --save-checkpoint last.note

# offline: only the AICS-1 §14.3 wire bundle and the out-of-band key
aics-tlog verify-bundle --bundle msg42.json --vkey-file aics.keys --offline

# classic proof-file modes still work
uv run aics-tlog verify-checkpoint --note checkpoint.note --log-key '<vkey>' \
    --witness-key '<witness vkey>' --quorum 1 --max-age 3600 --origin log.example/msgs
uv run aics-tlog verify-inclusion --leaf-line 2 --leaves-file leaves.txt \
    --index 1 --size 3 --root '<base64 root>' --proof proof.b64
uv run aics-tlog verify-consistency --old-size 2 --new-size 3 \
    --old-root '<base64>' --new-root '<base64>' --proof proof.b64

# build tiles in one pass, or append to a tile directory incrementally
uv run aics-tlog build-tiles --leaves leaves.txt --out ./tiles
uv run aics-tlog append-tiles --out ./tiles --size 3 --leaves more.txt
```

Proof files carry one 32-byte hash per line (base64, or 64 hex chars);
`-` reads stdin. Every subcommand prints exactly one JSON object and exits
0 on success, 1 on failure.

## Tests

```
cd packages/aics-tlog
uv run pytest -q              # property tests, spec vectors, local HTTP mirrors, live sumdb check
uv run aics-tlog --help
```

The property tests cross-check the tile-based root against an independent
recursive RFC 6962 reference for every size 1..600, verify every inclusion
proof for sampled sizes, consistency proofs for sampled `old<=new` pairs,
and require any single-bit tamper in proof/leaf/root/tiles to fail. The
incremental writer is checked against a full rebuild after every append for
random batch sequences (with restarts, simulated crashes and both pruning
modes, up to level 2 tiles), and never rewrites a path. Proofs from every
reader (rebuild, incremental, authenticated) are compared with the in-memory
tree for random `(index, size)` and `(old, new)`. HTTP tests run against local
servers that fail, redirect, corrupt, compress or oversize responses. The
network test verifies `https://sum.golang.org/latest` against the real
`sum.golang.org+033de0ae` key and skips when offline.

# Changelog

## 0.2.1 — 2026-10-19

- Bound the Merkle tree hash-level cache to the 64 most recently used tree
  sizes by default. The optional `level_cache_sizes` constructor argument can
  change the limit or disable caching with zero. Evicted sizes are rebuilt
  when needed; roots and inclusion/consistency proofs are unchanged.
- Correct the CLI's out-of-band key-source instructions to name the published
  `aics-cli` distribution.

These changes do not alter checkpoint, note, tile or proof wire formats.

"""In-memory RFC 9162 Merkle tree plus independent proof verifiers.

Generation follows RFC 9162, Section 2.1.3.1 (inclusion proofs) and
Section 2.1.4.1 (consistency proofs / SUBPROOF).  The verifiers
:func:`verify_inclusion` and :func:`verify_consistency` are direct,
independent implementations of the verification pseudocode in
RFC 9162, Sections 2.1.3.2 and 2.1.4.2 -- they share no code with the
generators.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable, Sequence

from .hashing import EMPTY_HASH, HASH_SIZE, leaf_hash, node_hash

__all__ = [
    "DEFAULT_LEVEL_CACHE_SIZES",
    "MerkleTree",
    "largest_power_of_two_smaller_than",
    "verify_consistency",
    "verify_inclusion",
]


def largest_power_of_two_smaller_than(n: int) -> int:
    """k with k < n <= 2k, i.e. the largest power of two strictly < n (n >= 2)."""
    if n < 2:
        raise ValueError("n must be >= 2")
    return 1 << ((n - 1).bit_length() - 1)


def _build_levels(leaf_hashes: Sequence[bytes]) -> list[list[bytes]]:
    """Levels of the RFC 9162 tree; levels[0] are leaf hashes.

    A lone node at odd positions is promoted unchanged to the level above,
    which reproduces exactly the unbalanced tree shape defined by
    "k = largest power of two smaller than n".
    """
    if not leaf_hashes:
        return []
    levels: list[list[bytes]] = [list(leaf_hashes)]
    while len(levels[-1]) > 1:
        prev = levels[-1]
        nxt = [node_hash(prev[i], prev[i + 1]) for i in range(0, len(prev) - 1, 2)]
        if len(prev) % 2:
            nxt.append(prev[-1])
        levels.append(nxt)
    return levels


def _mth_from_levels(levels: list[list[bytes]], start: int, end: int) -> bytes:
    """MTH(D[start:end]) using the pre-computed levels (end exclusive)."""
    n = end - start
    if n <= 0:
        return EMPTY_HASH
    if n == 1:
        return levels[0][start]
    k = largest_power_of_two_smaller_than(n)
    h = k.bit_length() - 1
    if start % k == 0:
        # [start, start+k) is a complete subtree: direct lookup.
        left = levels[h][start >> h]
    else:
        left = _mth_from_levels(levels, start, start + k)
    right = _mth_from_levels(levels, start + k, end)
    return node_hash(left, right)


def _subproof(
    levels: list[list[bytes]],
    m: int,
    start: int,
    end: int,
    b: bool,
    proof: list[bytes],
) -> None:
    """RFC 9162 Section 2.1.4.1 SUBPROOF, appending to ``proof``."""
    n = end - start
    if m == n:
        if not b:
            proof.append(_mth_from_levels(levels, start, end))
        return
    k = largest_power_of_two_smaller_than(n)
    if m <= k:
        _subproof(levels, m, start, start + k, b, proof)
        proof.append(_mth_from_levels(levels, start + k, end))
    else:
        _subproof(levels, m - k, start + k, end, False, proof)
        proof.append(_mth_from_levels(levels, start, start + k))


#: How many tree sizes :class:`MerkleTree` keeps the hash levels of, by default.
DEFAULT_LEVEL_CACHE_SIZES = 64


class MerkleTree:
    """An append-only in-memory Merkle tree over raw leaf data.

    The hash levels of a tree size are built on first use and cached for the
    ``level_cache_sizes`` most recently used sizes (default
    :data:`DEFAULT_LEVEL_CACHE_SIZES`; 0 caches nothing), so a long-running
    process that asks for proofs at ever new sizes does not grow without limit.
    """

    def __init__(self, leaves: Iterable[bytes] = (), *, level_cache_sizes: int = DEFAULT_LEVEL_CACHE_SIZES) -> None:
        if isinstance(level_cache_sizes, bool) or not isinstance(level_cache_sizes, int) or level_cache_sizes < 0:
            raise ValueError("level_cache_sizes must be a non-negative integer")
        self._data: list[bytes] = list(leaves)
        self._leaf_hashes: list[bytes] = [leaf_hash(d) for d in self._data]
        self._level_cache_sizes = level_cache_sizes
        self._levels_cache: OrderedDict[int, list[list[bytes]]] = OrderedDict()

    # -- basic accessors -------------------------------------------------

    def __len__(self) -> int:
        return len(self._data)

    @property
    def size(self) -> int:
        return len(self._data)

    def leaf_data(self, index: int) -> bytes:
        return self._data[index]

    def append(self, data: bytes) -> None:
        self._data.append(data)
        self._leaf_hashes.append(leaf_hash(data))

    def extend(self, data: Iterable[bytes]) -> None:
        for d in data:
            self.append(d)

    # -- levels ----------------------------------------------------------

    def _levels_for(self, size: int) -> list[list[bytes]]:
        if not 0 < size <= len(self._leaf_hashes):
            raise ValueError(f"invalid tree size {size}")
        levels = self._levels_cache.get(size)
        if levels is not None:
            self._levels_cache.move_to_end(size)
            return levels
        levels = _build_levels(self._leaf_hashes[:size])
        if self._level_cache_sizes:
            self._levels_cache[size] = levels
            while len(self._levels_cache) > self._level_cache_sizes:
                self._levels_cache.popitem(last=False)
        return levels

    # -- heads and proofs --------------------------------------------------

    def root(self, size: int | None = None) -> bytes:
        """Merkle Tree Hash of the tree at ``size`` leaves (default: all)."""
        size = len(self) if size is None else size
        if size == 0:
            return EMPTY_HASH
        return _mth_from_levels(self._levels_for(size), 0, size)

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        """RFC 9162 Section 2.1.3.1 PATH(m, D_n)."""
        size = len(self) if size is None else size
        if not 0 <= index < size:
            raise ValueError(f"leaf index {index} out of range for size {size}")
        levels = self._levels_for(size)
        proof: list[bytes] = []

        def path(m: int, start: int, end: int) -> None:
            n = end - start
            if n == 1:
                return
            k = largest_power_of_two_smaller_than(n)
            if m < k:
                path(m, start, start + k)
                proof.append(_mth_from_levels(levels, start + k, end))
            else:
                path(m - k, start + k, end)
                proof.append(_mth_from_levels(levels, start, start + k))

        path(index, 0, size)
        return proof

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> list[bytes]:
        """RFC 9162 Section 2.1.4.1 PROOF(m, D_n).

        Returns [] when old_size == new_size, and [] when old_size == 0
        (the empty tree, whose root is SHA-256(""), is a prefix of any tree
        without a proof; :func:`verify_consistency` requires that root).
        """
        new_size = len(self) if new_size is None else new_size
        if not 0 <= old_size <= new_size:
            raise ValueError(f"invalid sizes old={old_size} new={new_size}")
        if new_size > len(self):
            raise ValueError(f"tree has only {len(self)} leaves")
        if old_size in (0, new_size):
            return []
        proof: list[bytes] = []
        _subproof(self._levels_for(new_size), old_size, 0, new_size, True, proof)
        return proof


# --------------------------------------------------------------------------
# Independent verifiers: direct transcriptions of the RFC 9162 pseudocode
# (Sections 2.1.3.2 and 2.1.4.2).  No shared state with the generators.
# --------------------------------------------------------------------------


def verify_inclusion(
    hash_: bytes,
    index: int,
    size: int,
    proof: Sequence[bytes],
    root: bytes,
) -> bool:
    """RFC 9162 Section 2.1.3.2: verify that ``hash_`` is the leaf hash of
    leaf ``index`` in a tree of ``size`` leaves with root ``root``."""
    if index < 0 or size <= 0 or index >= size:
        return False
    fn, sn = index, size - 1
    r = hash_
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_leaf_inclusion(
    leaf: bytes,
    index: int,
    size: int,
    proof: Sequence[bytes],
    root: bytes,
) -> bool:
    """Convenience wrapper: hashes raw leaf data then verifies inclusion."""
    return verify_inclusion(leaf_hash(leaf), index, size, proof, root)


def verify_consistency(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: Sequence[bytes],
) -> bool:
    """RFC 9162 Section 2.1.4.2: verify that the tree head
    (``old_size``, ``old_root``) is consistent with (``new_size``, ``new_root``).

    Edge cases follow AICS-1 §14.2 step 1: for ``old_size == 0`` the old
    root must be the empty-tree root ``SHA-256("")`` and the proof empty (the
    empty tree is a prefix of every tree, but a size-0 head with any other
    root is no tree at all); for ``old_size == new_size`` the roots must be
    identical and the proof empty, so two size-0 heads are consistent exactly
    when both carry the empty-tree root.  ``old_size > new_size`` is not a
    consistency proof (a caller comparing history swaps the heads).  Roots
    and proof elements must be 32-byte hashes.
    """
    proof = list(proof)
    if old_size < 0 or new_size < 0 or old_size > new_size:
        return False
    if len(old_root) != HASH_SIZE or len(new_root) != HASH_SIZE:
        return False
    if any(len(p) != HASH_SIZE for p in proof):
        return False
    if old_size == 0:
        if proof or old_root != EMPTY_HASH:
            return False
        return new_size > 0 or new_root == EMPTY_HASH
    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root

    path = list(proof)
    if not path:
        return False
    if old_size & (old_size - 1) == 0:  # exact power of two
        path.insert(0, old_root)

    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0

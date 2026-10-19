"""Tree generation vs the independent reference, and RFC 9162 verifiers.

Property tests cover sizes 1..600: the tile-based and in-memory roots must
agree with the recursive reference, every inclusion proof must verify, and
consistency proofs must verify for sampled old<=new pairs.  Any single-bit
tamper in proof / leaf / root must fail verification.
"""

import hashlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aics_tlog import EMPTY_HASH, MerkleTree, leaf_hash
from aics_tlog.tree import verify_consistency, verify_inclusion

from conftest import flip_bit, make_leaves, ref_mth

SIZES = st.integers(min_value=1, max_value=600)


def test_rfc9162_section_2_1_5_example_shape():
    # The 7-leaf tree: inclusion proof for d0 has 3 nodes, for d6 has 2.
    leaves = make_leaves(7)
    t = MerkleTree(leaves)
    assert len(t.inclusion_proof(0, 7)) == 3  # [b, h, l]
    assert len(t.inclusion_proof(3, 7)) == 3  # [c, g, l]
    assert len(t.inclusion_proof(4, 7)) == 3  # [f, j, k]
    assert len(t.inclusion_proof(6, 7)) == 2  # [i, k]
    for i in range(7):
        assert verify_inclusion(leaf_hash(leaves[i]), i, 7, t.inclusion_proof(i, 7), t.root(7))


def test_root_matches_reference_for_sizes_1_to_600():
    leaves = make_leaves(600)
    t = MerkleTree(leaves)
    for n in range(1, 601):
        assert t.root(n) == ref_mth(leaves[:n])
    assert t.root() == ref_mth(leaves)


def test_all_inclusion_proofs_verify_sizes_1_to_600():
    leaves = make_leaves(600)
    t = MerkleTree(leaves)
    for n in range(1, 601):
        root = t.root(n)
        for i in range(0, n, max(1, n // 8)):  # 8 indices per size (all for small n)
            proof = t.inclusion_proof(i, n)
            assert verify_inclusion(leaf_hash(leaves[i]), i, n, proof, root), (n, i)


def test_single_bit_tamper_fails_inclusion():
    leaves = make_leaves(8)
    t = MerkleTree(leaves)
    root = t.root()
    for i in range(8):
        proof = t.inclusion_proof(i, 8)
        h = leaf_hash(leaves[i])
        assert verify_inclusion(h, i, 8, proof, root)
        # tamper each proof element
        for j in range(len(proof)):
            bad = list(proof)
            bad[j] = flip_bit(proof[j], 5)
            assert not verify_inclusion(h, i, 8, bad, root)
        # tamper leaf hash and root
        assert not verify_inclusion(flip_bit(h, 100), i, 8, proof, root)
        assert not verify_inclusion(h, i, 8, proof, flip_bit(root, 7))


def test_wrong_index_or_size_fails():
    leaves = make_leaves(8)
    t = MerkleTree(leaves)
    proof = t.inclusion_proof(3, 8)
    assert not verify_inclusion(leaf_hash(leaves[3]), 8, 8, proof, t.root())
    assert not verify_inclusion(leaf_hash(leaves[3]), 3, 7, proof, t.root(7))
    assert not verify_inclusion(leaf_hash(leaves[2]), 3, 8, proof, t.root())
    assert not verify_inclusion(leaf_hash(leaves[3]), 3, 8, [], t.root())


def test_verify_inclusion_rejects_out_of_range():
    assert not verify_inclusion(leaf_hash(b"x"), 5, 5, [b"0" * 32], b"1" * 32)
    assert not verify_inclusion(leaf_hash(b"x"), 0, 0, [], b"1" * 32)


@given(size=SIZES)
@settings(max_examples=40, deadline=None)
def test_property_inclusion_proofs_all_indices(size):
    leaves = make_leaves(size)
    t = MerkleTree(leaves)
    root = t.root(size)
    for i in range(size):
        proof = t.inclusion_proof(i, size)
        assert verify_inclusion(leaf_hash(leaves[i]), i, size, proof, root), (size, i)


@given(size=SIZES, data=st.data())
@settings(max_examples=25, deadline=None)
def test_property_consistency_proofs_verify(size, data):
    leaves = make_leaves(size)
    t = MerkleTree(leaves)
    old = data.draw(st.integers(min_value=1, max_value=size))
    proof = t.consistency_proof(old, size)
    assert verify_consistency(old, size, t.root(old), t.root(size), proof), (old, size)
    # tamper: any single-bit flip in any proof node must fail
    if proof:
        j = data.draw(st.integers(min_value=0, max_value=len(proof) - 1))
        bad = list(proof)
        bad[j] = flip_bit(proof[j], 13)
        assert not verify_consistency(old, size, t.root(old), t.root(size), bad)


def test_consistency_tamper_roots_fails():
    leaves = make_leaves(300)
    t = MerkleTree(leaves)
    for old in (1, 2, 100, 255, 256, 257, 299):
        proof = t.consistency_proof(old, 300)
        assert verify_consistency(old, 300, t.root(old), t.root(300), proof)
        assert not verify_consistency(
            old, 300, flip_bit(t.root(old), 3), t.root(300), proof
        )
        assert not verify_consistency(
            old, 300, t.root(old), flip_bit(t.root(300), 40), proof
        )


def test_consistency_edges():
    leaves = make_leaves(16)
    t = MerkleTree(leaves)
    assert t.consistency_proof(16, 16) == []
    assert t.consistency_proof(0, 16) == []
    assert t.root(0) == EMPTY_HASH
    assert verify_consistency(0, 16, EMPTY_HASH, t.root(16), [])
    assert verify_consistency(16, 16, t.root(16), t.root(16), [])
    assert not verify_consistency(16, 16, b"0" * 32, t.root(16), [])
    assert not verify_consistency(17, 16, EMPTY_HASH, t.root(16), [])
    assert not verify_consistency(16, 16, t.root(16), t.root(16), [t.root(8)])  # equal sizes: empty proof only
    with pytest.raises(ValueError):
        t.consistency_proof(-1, 16)
    with pytest.raises(ValueError):
        t.consistency_proof(17, 16)
    with pytest.raises(ValueError):
        t.inclusion_proof(16, 16)


def test_append_only_grows():
    t = MerkleTree()
    roots = []
    for i in range(50):
        t.append(f"leaf {i}".encode())
        roots.append(t.root())
    for old in range(1, 50):
        proof = t.consistency_proof(old, 50)
        assert verify_consistency(old, 50, roots[old - 1], roots[-1], proof)


# --- AICS-1 §14.2 step 1: size-0 edge cases (interop finding F18) --------------

NOT_EMPTY = hashlib.sha256(b"not the empty tree").digest()


def test_consistency_from_size_zero_requires_the_empty_tree_root():
    t = MerkleTree(make_leaves(12))
    assert EMPTY_HASH == hashlib.sha256(b"").digest()
    assert verify_consistency(0, 12, EMPTY_HASH, t.root(12), [])
    assert not verify_consistency(0, 12, NOT_EMPTY, t.root(12), [])  # a size-0 head with another root
    assert not verify_consistency(0, 12, b"", t.root(12), [])
    # a proof from size zero must be empty
    assert not verify_consistency(0, 12, EMPTY_HASH, t.root(12), [t.root(12)])
    assert not verify_consistency(0, 12, EMPTY_HASH, t.root(12), t.consistency_proof(1, 12))
    # the generators agree: nothing to prove from the empty tree
    assert t.consistency_proof(0, 12) == []


def test_two_empty_trees_are_consistent_only_with_the_empty_root():
    assert verify_consistency(0, 0, EMPTY_HASH, EMPTY_HASH, [])
    assert not verify_consistency(0, 0, EMPTY_HASH, NOT_EMPTY, [])
    assert not verify_consistency(0, 0, NOT_EMPTY, EMPTY_HASH, [])
    assert not verify_consistency(0, 0, NOT_EMPTY, NOT_EMPTY, [])  # identical, but no size-0 tree has it
    assert not verify_consistency(0, 0, EMPTY_HASH, EMPTY_HASH, [EMPTY_HASH])
    assert MerkleTree().consistency_proof(0, 0) == []


def test_consistency_rejects_malformed_sizes_and_hashes():
    t = MerkleTree(make_leaves(5))
    proof = t.consistency_proof(3, 5)
    assert verify_consistency(3, 5, t.root(3), t.root(5), proof)
    assert not verify_consistency(-1, 5, t.root(3), t.root(5), proof)
    assert not verify_consistency(3, -5, t.root(3), t.root(5), proof)
    assert not verify_consistency(5, 3, t.root(5), t.root(3), proof)  # m > n: swap for history, never a proof
    assert not verify_consistency(3, 5, t.root(3)[:31], t.root(5), proof)
    assert not verify_consistency(3, 5, t.root(3), t.root(5) + b"\0", proof)
    assert not verify_consistency(3, 5, t.root(3), t.root(5), [proof[0][:16], *proof[1:]])
    assert not verify_consistency(5, 5, t.root(5)[:31], t.root(5)[:31], [])  # equal, but not hashes

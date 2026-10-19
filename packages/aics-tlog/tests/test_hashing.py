import hashlib

from aics_tlog.hashing import EMPTY_HASH, leaf_hash, node_hash


def test_empty_tree_hash_is_sha256_of_empty_string():
    assert EMPTY_HASH == hashlib.sha256(b"").digest()


def test_leaf_hash_prefixes_zero_byte():
    assert leaf_hash(b"hello") == hashlib.sha256(b"\x00hello").digest()
    assert leaf_hash(b"") == hashlib.sha256(b"\x00").digest()


def test_node_hash_prefixes_one_byte():
    l, r = bytes(range(32)), bytes(range(32, 64))
    assert node_hash(l, r) == hashlib.sha256(b"\x01" + l + r).digest()


def test_domain_separation_leaf_vs_node():
    # H(0x00 || d) must differ from any node hash of the same bytes
    d = b"\x01" + bytes(64)
    assert leaf_hash(d) != hashlib.sha256(d).digest()
    l = r = bytes(32)
    assert node_hash(l, r) != leaf_hash(l + r)

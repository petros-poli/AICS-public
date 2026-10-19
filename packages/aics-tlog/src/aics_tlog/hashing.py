"""RFC 6962 / RFC 9162 Merkle Tree hashing for transparency logs.

The hash algorithm is fixed to SHA-256 (c2sp.org/tlog-tiles).

* Leaf hash:   H(0x00 || data)
* Node hash:   H(0x01 || left || right)
* Empty tree:  H()  (SHA-256 of the empty string)
"""

from __future__ import annotations

import hashlib

HASH_SIZE = 32

EMPTY_HASH = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    """MerkleTreeHash of a single entry: H(0x00 || d)."""
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """MerkleTreeHash of an interior node: H(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

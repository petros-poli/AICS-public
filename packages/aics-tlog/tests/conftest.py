"""Shared helpers for the aics_tlog test suite."""

from __future__ import annotations

import hashlib

import pytest

from aics_tlog.hashing import leaf_hash


def ref_mth(leaves: list[bytes]) -> bytes:
    """Independent recursive RFC 6962/9162 Merkle Tree Hash reference."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(
        b"\x01" + ref_mth(leaves[:k]) + ref_mth(leaves[k:])
    ).digest()


def make_leaves(n: int) -> list[bytes]:
    """Deterministic leaf data (may not contain newlines when used with the CLI)."""
    return [f"entry-{i:06d}:{i * i % 977}".encode() for i in range(n)]


def flip_bit(data: bytes, bit: int) -> bytes:
    out = bytearray(data)
    out[bit // 8] ^= 1 << (bit % 8)
    return bytes(out)


GO_SUMDB_VKEY = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8"


@pytest.fixture(scope="session")
def go_sumdb_vkey():
    from aics_tlog.note import parse_vkey

    return parse_vkey(GO_SUMDB_VKEY)

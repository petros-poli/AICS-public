"""aics_tlog - verifier/builder for C2SP transparency logs.

Implements c2sp.org/tlog-tiles, c2sp.org/tlog-checkpoint,
c2sp.org/signed-note, c2sp.org/tlog-cosignature and the RFC 9162
Merkle tree algorithms (SHA-256, RFC 6962 leaf/node hashing).
"""

from .hashing import EMPTY_HASH, leaf_hash, node_hash
from .tree import (
    MerkleTree,
    verify_consistency,
    verify_inclusion,
    verify_leaf_inclusion,
)
from . import tiles  # noqa: F401
from .tiles import (
    FileSystemTileReader,
    MemoryTileReader,
    TileConflictError,
    TileMissingError,
    TileReader,
    TileUnavailableError,
    TileVerificationError,
    TileWriter,
    consistency_proof_from_tiles,
    inclusion_proof_from_tiles,
    read_entry,
    tree_root_from_tiles,
)
from .note import (
    Note,
    SignatureLine,
    VKey,
    ed25519_public_key_problem,
    format_vkey,
    key_hash,
    parse_note,
    parse_vkey,
    read_vkey_file,
    sign_note,
    vkey_from_ed25519,
    verify_note,
)
from .checkpoint import (
    Checkpoint,
    WitnessPolicy,
    parse_checkpoint,
    sign_checkpoint,
    verify_checkpoint,
)
from .cosign import (
    cosignature_vkey,
    sign_cosignature,
    verify_cosignature,
)
from .writer import (
    AppendResult,
    DirectoryTileStore,
    IncrementalTileWriter,
    MemoryTileStore,
)
from .remote import HttpTileReader
from .verified import VerifiedTileReader, audit_tiles
from .bundle import Bundle, bundle_from_tiles, verify_bundle

__version__ = "0.2.0"  # keep equal to pyproject.toml (tests/test_version.py)

__all__ = [
    "EMPTY_HASH",
    "AppendResult",
    "Bundle",
    "Checkpoint",
    "DirectoryTileStore",
    "FileSystemTileReader",
    "HttpTileReader",
    "IncrementalTileWriter",
    "MemoryTileReader",
    "MemoryTileStore",
    "MerkleTree",
    "Note",
    "SignatureLine",
    "TileConflictError",
    "TileMissingError",
    "TileReader",
    "TileUnavailableError",
    "TileVerificationError",
    "TileWriter",
    "VKey",
    "VerifiedTileReader",
    "WitnessPolicy",
    "audit_tiles",
    "bundle_from_tiles",
    "consistency_proof_from_tiles",
    "cosignature_vkey",
    "ed25519_public_key_problem",
    "format_vkey",
    "inclusion_proof_from_tiles",
    "key_hash",
    "leaf_hash",
    "node_hash",
    "parse_checkpoint",
    "parse_note",
    "parse_vkey",
    "read_entry",
    "read_vkey_file",
    "sign_checkpoint",
    "sign_cosignature",
    "sign_note",
    "tree_root_from_tiles",
    "verify_bundle",
    "verify_checkpoint",
    "verify_consistency",
    "verify_cosignature",
    "verify_inclusion",
    "verify_leaf_inclusion",
    "verify_note",
    "vkey_from_ed25519",
    "__version__",
]

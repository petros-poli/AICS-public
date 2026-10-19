"""AICS-1 Appendix A, read from the specification text itself.

Values are parsed out of ``docs/spec/AICS-1.md`` (code blocks, the leaf-hash
table and the inline hex values), and the A.5 reproduction program embedded
in the specification is executed to obtain the auxiliary entries it defines.
Tests compare both against every package that can consume them, so a change
to the specification or to a package shows up here.
"""

from __future__ import annotations

import functools
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]
SPEC_PATH = Path(os.environ.get("AICS_SPEC_PATH", REPO_ROOT / "docs" / "spec" / "AICS-1.md"))

ORIGIN = "log.example/aics-1"
WITNESS_NAME = "witness.example/w1"
EPOCH = 1792281600

# Appendix A seed bytes (all deliberately public).
SEEDS = {"alice": 1, "log": 2, "policy": 3, "owner": 4, "bob": 5, "witness": 6}
X25519_SEEDS = {"alice": 7, "bob": 8, "ephemeral": 9}


@dataclass
class AppendixA:
    text: str
    blocks: list[tuple[str, str]]
    envelope_bytes: bytes          # A.1, exact JCS bytes
    entry_bytes: bytes             # A.2, exact JCS bytes of entry 3
    leaf_hashes: list[str]         # A.2 table
    root: str                      # A.2
    inclusion_proof: list[str]     # A.2, index 3 size 4
    consistency_proof: list[str]   # A.2, 3 -> 4
    checkpoint: bytes              # A.3 size-4 note with cosignature, final LF
    cosign_input: bytes            # A.3 exact cosignature message
    previous_checkpoint: bytes     # A.3 size-3 note
    header_bytes: bytes            # A.4 inner header
    plaintext: bytes               # A.4
    ciphertext: bytes              # A.4
    inline: dict[str, str]         # inline hex/text values from the prose
    program: dict[str, Any] = field(repr=False, default_factory=dict)  # A.5 namespace

    @property
    def values(self) -> dict[str, Any]:
        return self.program["values"]

    @property
    def entries(self) -> list[dict[str, Any]]:
        return self.program["entries"]

    def entry_jcs(self, i: int) -> bytes:
        return self.program["J"](self.entries[i])


def _inline(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.S)
    if not m:
        raise ValueError(f"Appendix A no longer contains {pattern!r}")
    return m.group(1)


@functools.cache
def load(path: str | None = None) -> AppendixA:
    text = Path(path or SPEC_PATH).read_text("utf-8")
    app = text[text.index("## Appendix A."):]
    blocks = re.findall(r"```(\w*)\n(.*?)```", app, re.S)
    by_lang = [(lang, body) for lang, body in blocks]
    json_blocks = [b for lang, b in by_lang if lang == "json"]
    text_blocks = [b for lang, b in by_lang if lang == "text"]
    python = [b for lang, b in by_lang if lang == "python"]
    if len(json_blocks) < 5 or len(text_blocks) < 5 or len(python) != 1:
        raise ValueError("unexpected Appendix A layout")
    table = re.findall(r"^\| (\d) \| `([0-9a-f]{64})` \|$", app, re.M)
    inline = {
        "alice_public_key": _inline(app, r"Alice's public key \(hex\): `([0-9a-f]{64})`"),
        "signing_digest": _inline(app, r"Signing digest \(32 bytes, hex\): `([0-9a-f]{64})`"),
        "envelope_hash": _inline(app, r"Full-envelope SHA-256: `([0-9a-f]{64})`"),
        "entry_length": _inline(app, r"Entry length is (\d+) bytes"),
        "entry_record_prefix": _inline(app, r"starts with the two bytes `([0-9a-f]{4})`"),
        "log_vkey": _inline(app, r"Log vkey: `([^`]+)`"),
        "witness_vkey": _inline(app, r"Witness vkey: `([^`]+)`"),
        "checkpoint_hash": _inline(app, r"SHA-256 of the complete UTF-8 note: `([0-9a-f]{64})`"),
        "witness_timestamp": _inline(app, r"The witness timestamp is `(\d+)`"),
        "previous_checkpoint_hash": _inline(app, r"whose hash is `([0-9a-f]{64})`"),
        "header_length": _inline(app, r"Exact canonical inner header \((\d+) bytes"),
        "header_prefix": _inline(app, r"The four-byte length prefix is `([0-9a-f]{8})`"),
        "bob_x25519": _inline(app, r"Bob's X25519 public key: `([0-9a-f]{64})`"),
        "ephemeral_public_key": _inline(app, r"Test ephemeral public key: `([0-9a-f]{64})`"),
        "box_nonce": _inline(app, r"box nonce is `([0-9a-f]{48})`"),
        "ciphertext_length": _inline(app, r"including the 32-byte ephemeral public key, is (\d+) bytes"),
        "ciphertext_hash": _inline(app, r"Its SHA-256 is `([0-9a-f]{64})`"),
    }
    namespace: dict[str, Any] = {"__name__": "aics1_appendix_a5"}
    exec(compile(python[0], f"{SPEC_PATH.name}#A.5", "exec"), namespace)  # the spec's own program
    return AppendixA(
        text=app,
        blocks=by_lang,
        envelope_bytes=json_blocks[0].rstrip("\n").encode("utf-8"),
        entry_bytes=json_blocks[1].rstrip("\n").encode("utf-8"),
        leaf_hashes=[h for _, h in sorted(table)],
        root=_inline(app, r"The size-4 root is `([0-9a-f]{64})`"),
        inclusion_proof=json.loads(json_blocks[2]),
        consistency_proof=json.loads(json_blocks[3]),
        checkpoint=text_blocks[0].encode("utf-8"),
        cosign_input=text_blocks[1].encode("utf-8"),
        previous_checkpoint=text_blocks[2].encode("utf-8"),
        header_bytes=json_blocks[4].rstrip("\n").encode("utf-8"),
        plaintext=bytes.fromhex("".join(text_blocks[3].split())),
        ciphertext=bytes.fromhex("".join(text_blocks[4].split())),
        inline=inline,
        program=namespace,
    )


def trust_bundle_dict() -> dict[str, Any]:
    """A trust bundle for the Appendix A test keys (bootstrap card hash: none logged, zeros)."""
    from . import spec

    a = load()
    return spec.trust_bundle(origin=ORIGIN, log_vkey=a.inline["log_vkey"],
                             policy_kid=spec.kid(spec.test_key(SEEDS["policy"])),
                             owner_kid=spec.kid(spec.test_key(SEEDS["owner"])),
                             bootstrap_card_hash="0" * 64)


def dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2)

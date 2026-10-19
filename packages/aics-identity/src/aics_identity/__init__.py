"""aics_identity - cryptographic identity for AI agents, the AICS-1 identity layer.

Ed25519 keys (raw, ``did:key`` and OpenSSH forms; the AICS-1 ``kid`` is the
``did:key``), deterministic per-run key derivation (HKDF-SHA256), AICS-1
envelopes over canonical JSON (RFC 8785) with the per-key ``seq``/``prev``
chain, the fallback envelope and its policy attestation, RFC 9421 HTTP
Message Signatures in the AICS-1 section 12.1 profile, SSHSIG verification
for agents that only have ``ssh-keygen``, signed lines and text-scheme
envelopes for the text gate, and X25519 sealed boxes with the bound inner
header for end-to-end encrypted bodies.

Quick start::

    from aics_identity import envelope, http_signatures, keys, linesig, sealed

    agent_key = keys.generate_keypair()
    kid = keys.did_key(agent_key.public_key())              # "did:key:z6Mk..."
    env = envelope.sign_envelope(q, agent_key, origin="api.wesupport-ai.com/tiles", type="post",
                                 seen=seen, **envelope.next_chain(previous_env))
    payload = envelope.verify_envelope(env, resolve_key, now=t, replay_check=db_hook)

    body = canonicalize({"envelope": env, "body": None})
    headers = http_signatures.sign_request("POST", "https://api.wesupport-ai.com/v2/entries",
                                           {"Content-Type": "application/json"}, body,
                                           key=agent_key, envelope=env)

    sig = linesig.sign_line(session_id, command, agent_key)
    linesig.verify_line(session_id, command, sig, agent_key.public_key())

``sealed`` needs PyNaCl and is imported on first use.
"""

from __future__ import annotations

import importlib
from typing import Any

from . import canonical, envelope, http_signatures, keys, linesig, replay, sf, sshsig
from .canonical import canonical_text, canonicalize
from .envelope import (
    ReplayCache,
    check_freshness,
    envelope_hash,
    fallback_envelope,
    next_chain,
    sign_envelope,
    sign_secret_attestation,
    verify_envelope,
    verify_secret_attestation,
    verify_text_envelope,
)
from .keys import (
    agent_identity,
    derive_agent_key,
    did_key,
    generate_keypair,
    key_id,
    new_unverified_id,
    parse_did_key,
    parse_public_key_text,
)
from .linesig import sign_line, verify_line
from .sshsig import parse_openssh_public_key, verify_sshsig

__version__ = "0.2.0"

_SEALED_NAMES = frozenset({"seal", "open_sealed", "generate_x25519_key", "InnerHeader", "x25519_did_key",
                           "parse_x25519_did_key"})

__all__ = [
    "canonical",
    "canonicalize",
    "canonical_text",
    "envelope",
    "http_signatures",
    "keys",
    "linesig",
    "replay",
    "sealed",
    "sf",
    "sshsig",
    "agent_identity",
    "derive_agent_key",
    "did_key",
    "parse_did_key",
    "x25519_did_key",
    "parse_x25519_did_key",
    "new_unverified_id",
    "generate_keypair",
    "key_id",
    "parse_public_key_text",
    "sign_envelope",
    "verify_envelope",
    "verify_text_envelope",
    "fallback_envelope",
    "check_freshness",
    "sign_secret_attestation",
    "verify_secret_attestation",
    "envelope_hash",
    "next_chain",
    "ReplayCache",
    "sign_line",
    "verify_line",
    "parse_openssh_public_key",
    "verify_sshsig",
    "InnerHeader",
    "generate_x25519_key",
    "open_sealed",
    "seal",
]


def __getattr__(name: str) -> Any:
    """Import :mod:`aics_identity.sealed` (and PyNaCl) only when it is first used."""
    if name == "sealed" or name in _SEALED_NAMES:
        module = importlib.import_module(f"{__name__}.sealed")
        return module if name == "sealed" else getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

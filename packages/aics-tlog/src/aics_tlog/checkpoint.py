"""Transparency log checkpoints (c2sp.org/tlog-checkpoint).

The note text of a checkpoint is a sequence of at least three non-empty
lines::

    <origin>
    <tree size as ASCII decimal>
    <base64 root hash>
    [optional extension lines]

Signatures
----------
* Ed25519 **log** signature: plain Ed25519 over the note text, key ID
  computed with signature type 0x01 (no timestamp).
* Ed25519 **checkpoint cosignature**: computed as
  c2sp.org/tlog-cosignature with an 8-byte timestamp; the signed message is
  ``cosignature/v1\\ntime <T>\\n`` followed by the complete checkpoint note
  text (extension lines included).  Key ID type byte is 0x04.

Repeated lines (AICS-1 §6.2): two signature lines with the same key name and
key ID are malformed when that (name, key ID) is *recognized* -- the log key
or a configured witness -- and reject the note.  Lines under unknown keys
are ignored, repeated or not: a verifier cannot tell a stray foreign line
from any other line it does not use.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .cosign import (
    COSIGNATURE_TYPE,
    DEFAULT_MAX_FUTURE_SECONDS,
    timestamp_is_fresh,
    verify_cosignature,
)
from .note import (
    TYPE_ED25519,
    Note,
    SignatureLine,
    VKey,
    b64_decode,
    b64_encode,
    check_name,
    key_hash,
    parse_note,
    parse_vkey,
    sign_note,
    verify_note_signature,
)

__all__ = [
    "Checkpoint",
    "CheckpointVerifyResult",
    "WitnessPolicy",
    "parse_checkpoint",
    "serialise_checkpoint",
    "sign_checkpoint",
    "verify_checkpoint",
]


@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root: bytes
    extension_lines: tuple[str, ...] = ()

    def text(self) -> str:
        return serialise_checkpoint(self)


def serialise_checkpoint(cp: Checkpoint) -> str:
    """Serialise the checkpoint note text (always ending in a newline)."""
    check_name(cp.origin, "origin")
    lines = [cp.origin, _encode_decimal(cp.size), b64_encode(cp.root)]
    for ext in cp.extension_lines:
        if not ext:
            raise ValueError("extension lines must be non-empty")
        lines.append(ext)
    return "".join(line + "\n" for line in lines)


def _encode_decimal(n: int) -> str:
    if n < 0:
        raise ValueError("tree size must be non-negative")
    return str(n)


def _parse_decimal(text: str, what: str) -> int:
    if not text.isdigit():
        raise ValueError(f"{what} is not an ASCII decimal: {text!r}")
    if str(int(text)) != text:
        raise ValueError(f"{what} has leading zeroes: {text!r}")
    return int(text)


def parse_checkpoint(text: str) -> Checkpoint:
    """Parse checkpoint note text (without signature lines)."""
    if not text.endswith("\n"):
        raise ValueError("checkpoint text must end with a newline")
    lines = text.split("\n")[:-1]  # drop the trailing empty element
    if len(lines) < 3:
        raise ValueError("checkpoint needs at least three lines")
    if any(line == "" for line in lines):
        raise ValueError("checkpoint lines must be non-empty")
    origin = check_name(lines[0], "origin")
    size = _parse_decimal(lines[1], "tree size")
    root = b64_decode(lines[2])
    if len(root) != 32:
        raise ValueError(f"root hash must be 32 bytes, got {len(root)}")
    return Checkpoint(origin=origin, size=size, root=root,
                      extension_lines=tuple(lines[3:]))


def sign_checkpoint(cp: Checkpoint, private_key: Ed25519PrivateKey, name: str) -> Note:
    """Create a signed note holding an Ed25519 log signature for ``cp``."""
    return Note(text=serialise_checkpoint(cp), signatures=(sign_note(serialise_checkpoint(cp), private_key, name),))


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WitnessPolicy:
    """Which witnesses must cosign a checkpoint, how many, and how recently.

    Mirrors the assurance card's ``witness_policy {quorum, witnesses}`` and
    ``max_checkpoint_age``.  A policy always requires at least one
    cosignature (``quorum >= 1``): a policy that accepts zero cosignatures
    states nothing.  Witnesses must be Ed25519 cosignature keys (type 0x04)
    with distinct names and distinct public keys -- the cosignature/v1
    message does not commit to the cosigner name, so one key listed under
    two names would count twice.
    """

    quorum: int
    witnesses: tuple[VKey, ...]
    max_age_seconds: int | None = None

    def __post_init__(self) -> None:
        witnesses = tuple(self.witnesses)
        object.__setattr__(self, "witnesses", witnesses)
        if isinstance(self.quorum, bool) or not isinstance(self.quorum, int):
            raise ValueError("witness policy quorum must be an integer")
        if self.quorum < 1:
            raise ValueError("a witness policy requires quorum >= 1")
        if self.quorum > len(witnesses):
            raise ValueError(
                f"witness policy quorum {self.quorum} exceeds the {len(witnesses)} listed witnesses"
            )
        names: set[str] = set()
        keys: set[bytes] = set()
        for w in witnesses:
            if not isinstance(w, VKey) or w.key_type != COSIGNATURE_TYPE:
                raise ValueError(f"witness {getattr(w, 'name', w)!r} is not an Ed25519 cosignature key (0x04)")
            if w.name in names:
                raise ValueError(f"witness {w.name!r} is listed twice")
            if w.public_key in keys:
                raise ValueError(f"witness {w.name!r} reuses another witness's public key")
            names.add(w.name)
            keys.add(w.public_key)
        if self.max_age_seconds is not None and (
            isinstance(self.max_age_seconds, bool)
            or not isinstance(self.max_age_seconds, int)
            or self.max_age_seconds <= 0
        ):
            raise ValueError("max_checkpoint_age must be a positive number of seconds")

    @classmethod
    def from_dict(cls, obj: Mapping) -> WitnessPolicy:
        """Accepts ``{"quorum", "witnesses", "max_checkpoint_age"}`` or the
        card form ``{"witness_policy": {"quorum", "witnesses"},
        "max_checkpoint_age"}``; witnesses are vkey strings."""
        if not isinstance(obj, Mapping):
            raise ValueError("witness policy must be a JSON object")
        inner = obj.get("witness_policy", obj)
        if not isinstance(inner, Mapping):
            raise ValueError("witness_policy must be a JSON object")
        if "quorum" not in inner or "witnesses" not in inner:
            raise ValueError("witness policy needs 'quorum' and 'witnesses'")
        raw_witnesses = inner["witnesses"]
        if not isinstance(raw_witnesses, list) or not all(isinstance(w, str) for w in raw_witnesses):
            raise ValueError("witness policy 'witnesses' must be a list of vkey strings")
        max_age = obj.get("max_checkpoint_age", inner.get("max_checkpoint_age"))
        if max_age is None:
            max_age = obj.get("max_checkpoint_age_seconds", inner.get("max_checkpoint_age_seconds"))
        return cls(
            quorum=inner["quorum"],
            witnesses=tuple(parse_vkey(w.strip()) for w in raw_witnesses),
            max_age_seconds=max_age,
        )

    @classmethod
    def from_json(cls, text: str | bytes) -> WitnessPolicy:
        try:
            obj = json.loads(text)
        except (ValueError, UnicodeDecodeError) as e:
            raise ValueError(f"witness policy is not valid JSON: {e}") from None
        return cls.from_dict(obj)


@dataclass
class CheckpointVerifyResult:
    ok: bool = False
    origin: str | None = None
    size: int | None = None
    root: bytes | None = None
    log_ok: bool = False
    cosignature_count: int = 0
    witnesses: list[str] = field(default_factory=list)
    error: str | None = None
    quorum: int = 0
    stale: list[str] = field(default_factory=list)  # valid cosignatures older than max_age
    future: list[str] = field(default_factory=list)  # valid cosignatures dated too far ahead
    timestamps: dict[str, int] = field(default_factory=dict)  # witness name -> cosignature time
    max_age_seconds: int | None = None


def _matching(note: Note, key: VKey) -> list[SignatureLine]:
    return [s for s in note.signatures if s.name == key.name and s.key_id == key.key_id]


def _repeated_line(note: Note, keys: list[VKey]) -> SignatureLine | None:
    """The first signature line that repeats the (name, key ID) of one of
    ``keys`` (AICS-1 §6.2: duplicates are refused for recognized keys only;
    lines under any other key are ignored, repeated or not)."""
    recognized = {(k.name, k.key_id) for k in keys}
    seen: set[tuple[str, bytes]] = set()
    for sig in note.signatures:
        pair = (sig.name, sig.key_id)
        if pair not in recognized:
            continue
        if pair in seen:
            return sig
        seen.add(pair)
    return None


def _duplicate_error(sig: SignatureLine) -> str:
    return f"duplicate signature line for {sig.name} {sig.key_id.hex()}"


def verify_checkpoint(
    note: Note,
    log_key: VKey,
    witness_keys: list[VKey] | None = None,
    quorum: int = 0,
    *,
    expected_origin: str | None = None,
    max_future_seconds: int | None = None,
    max_age_seconds: int | None = None,
    now: int | None = None,
    policy: WitnessPolicy | None = None,
) -> CheckpointVerifyResult:
    """Verify a checkpoint note: the log signature, then count valid, fresh
    cosignature/v1 witness signatures and compare against ``quorum``.

    Rules (c2sp.org/signed-note, tlog-checkpoint, tlog-cosignature, AICS-1
    §6.2):
    * two signature lines with the same (name, key ID) are malformed when
      that key is recognized (``log_key`` or a configured witness): the note
      is rejected, ``error`` starting "duplicate signature line";
    * the log signature must be an Ed25519 (type 0x01) signature over the
      note text from ``log_key``;
    * witness cosignatures are Ed25519 (type 0x04) cosignature/v1 blobs;
      signatures from keys that match a configured key but fail to verify
      reject the whole checkpoint;
    * signatures from unknown keys are ignored, including repeated
      unknown-key lines;
    * a public key counts once, however many names it appears under.

    A repeated log-key line leaves the note without a log signature
    (``log_ok`` False); a repeated witness line is found after the log
    signature verified, so ``log_ok`` stays True: the note is still what the
    log signed, but it does not meet any witness policy.

    Freshness (AICS-1 §6.3): with ``max_age_seconds`` (or a policy's
    max_checkpoint_age) a cosignature older than that, measured against its
    own timestamp, does not count toward the quorum, so an old checkpoint
    replayed with its old cosignatures fails.  With a freshness bound and no
    ``max_future_seconds``, cosignatures more than DEFAULT_MAX_FUTURE_SECONDS
    (30) ahead do not count either.  Such cosignatures are listed in
    ``stale`` / ``future``.

    ``policy`` replaces ``witness_keys`` and ``quorum`` (passing both is an
    error) and always requires at least one cosignature.
    """
    if policy is not None:
        if witness_keys or quorum:
            raise ValueError("pass either a witness policy or witness_keys/quorum, not both")
        if policy.quorum < 1:
            raise ValueError("a witness policy requires quorum >= 1")
        witness_keys = list(policy.witnesses)
        quorum = policy.quorum
        if max_age_seconds is None:
            max_age_seconds = policy.max_age_seconds
    if max_age_seconds is not None and max_age_seconds < 0:
        raise ValueError("max_age_seconds must be non-negative")
    if max_age_seconds is not None and max_future_seconds is None:
        max_future_seconds = DEFAULT_MAX_FUTURE_SECONDS
    witness_keys = list(witness_keys or [])
    try:
        cp = parse_checkpoint(note.text)
    except ValueError as e:
        return CheckpointVerifyResult(ok=False, error=f"invalid checkpoint: {e}", quorum=quorum)

    if expected_origin is not None and cp.origin != expected_origin:
        return CheckpointVerifyResult(
            ok=False, origin=cp.origin, size=cp.size, quorum=quorum,
            error=f"origin mismatch: expected {expected_origin!r}, got {cp.origin!r}",
        )

    # A repeated line for the log key is malformed (AICS-1 §6.2); repeated
    # lines under keys this verifier does not know are ignored.
    repeated = _repeated_line(note, [log_key])
    if repeated is not None:
        return CheckpointVerifyResult(
            ok=False, origin=cp.origin, size=cp.size, quorum=quorum,
            error=_duplicate_error(repeated),
        )

    result = CheckpointVerifyResult(
        origin=cp.origin, size=cp.size, root=cp.root, witnesses=[], quorum=quorum,
        max_age_seconds=max_age_seconds,
    )

    # --- log signature (Ed25519 over the note text, type 0x01) ----------
    if log_key.key_type != TYPE_ED25519:
        result.error = "log key must be an Ed25519 vkey"
        return result
    log_sigs = _matching(note, log_key)
    if not log_sigs:
        result.error = f"no signature from log key {log_key.name} {log_key.key_id.hex()}"
        return result
    for sig in log_sigs:
        if not verify_note_signature(note, sig, log_key):
            result.error = f"log signature from {log_key.name} failed verification"
            return result
    result.log_ok = True

    # --- witness cosignatures (cosignature/v1, type 0x04) ---------------
    for wkey in witness_keys:
        if wkey.key_type != COSIGNATURE_TYPE:
            result.error = f"witness key {wkey.name} is not an Ed25519 cosignature key (0x04)"
            return result
    # A configured witness is a recognized key: its lines must not repeat.
    repeated = _repeated_line(note, witness_keys)
    if repeated is not None:
        result.error = _duplicate_error(repeated)
        return result
    verified: list[str] = []
    counted_keys: set[bytes] = set()
    for wkey in witness_keys:
        wmatched = _matching(note, wkey)
        if not wmatched:
            continue
        blob = wmatched[0].signature  # the only line for this (name, key ID)
        if not verify_cosignature(
            blob,
            wkey.name,
            wkey.public_key,
            cp.origin,
            cp.size,
            cp.root,
            cp.extension_lines,
        ):
            result.error = f"cosignature from {wkey.name} failed verification"
            return result
        timestamp = int.from_bytes(blob[:8], "big")
        result.timestamps[wkey.name] = timestamp
        if not timestamp_is_fresh(timestamp, max_future_seconds=max_future_seconds, now=now):
            result.future.append(wkey.name)
            continue
        if not timestamp_is_fresh(
            timestamp, max_age_seconds=max_age_seconds, max_future_seconds=max_future_seconds, now=now
        ):
            result.stale.append(wkey.name)
            continue
        if wkey.public_key in counted_keys:
            continue  # the same key under another name counts once
        counted_keys.add(wkey.public_key)
        verified.append(wkey.name)
    result.cosignature_count = len(verified)
    result.witnesses = verified
    if result.cosignature_count < quorum:
        detail = ""
        if result.stale:
            detail += f"; stale (older than {max_age_seconds}s): {', '.join(result.stale)}"
        if result.future:
            detail += f"; dated in the future: {', '.join(result.future)}"
        result.error = (
            f"quorum not met: {result.cosignature_count} valid fresh cosignatures < {quorum}{detail}"
        )
        return result
    result.ok = True
    return result


def checkpoint_from_note(note_or_text: str | bytes | Note) -> tuple[Checkpoint, Note]:
    """Convenience: parse a full signed note and its checkpoint body."""
    note = note_or_text if isinstance(note_or_text, Note) else parse_note(note_or_text)
    return parse_checkpoint(note.text), note

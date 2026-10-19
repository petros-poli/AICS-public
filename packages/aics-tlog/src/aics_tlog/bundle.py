"""Offline verification bundles: the AICS-1 §14.3 wire bundle (DESIGN.md G8).

A bundle carries everything needed to check, without the service, that an
entry is in the log under a signed checkpoint.  Its wire form is exactly the
AICS-1 §14.3 object::

    {
      "entry_bytes":     "<U64 of the exact entry bytes>",
      "index":           <leaf index, a uint>,
      "inclusion_proof": ["<B64 of a 32-byte hash>", ...],
      "checkpoint_note": "<U64 of the complete signed checkpoint note>",
      "envelope":        <the signed envelope E the entry embeds>,
      "body_or_ct":      "<U64 of the body or ciphertext bytes>" | null
    }

``U64`` is canonical unpadded base64url (RFC 4648 §5) and ``B64`` canonical
padded standard base64 (RFC 4648 §4), as AICS-1 §2 defines them.  Readers
refuse missing members, members §14.3 does not define, duplicate JSON names
and non-canonical encodings (§2).  ``checkpoint_note`` is the complete note
-- text, blank line, every signature line and the final LF -- so its hash is
the ``seen`` pointer an envelope gossips.  The pre-0.2 aics-tlog form
(``entry_bytes_b64``, the note as plain text, padded base64 body) is no
longer read.

For a log whose entries embed no envelope (anything but AICS-1 entries),
``envelope`` may be null: such a bundle proves inclusion only.  Keys never
travel in a bundle: :func:`verify_bundle` takes the log key from the caller
(obtained out of band).

What :func:`verify_bundle` proves:

1. the checkpoint note is signed by the out-of-band log key (and, if given,
   cosigned under a witness policy);
2. ``entry_bytes`` is leaf ``index`` of the tree the checkpoint commits to
   (RFC 9162 inclusion proof);
3. for an AICS-1 entry (an entry v2 object whose payload embeds
   ``envelope``): the entry bytes are its JCS serialisation with exactly the
   entry v2 members, the payload is the envelope plus an exact copy of the
   envelope's payload (§5.1), and the bundle's envelope equals the embedded
   one (§14.3 step 1); ``body_or_ct``, if present, hashes to the payload's
   ``body_hash``, ``ct_hash`` or ``document_hash`` and has its ``size``
   (§14.3 step 4);
4. for any other entry: if ``envelope`` is present, the entry commits to it
   (verbatim inside the entry JSON, or a hash-named field holding the
   SHA-256 of its canonical JSON); if ``body_or_ct`` is present, a
   hash-named field (name containing "hash", "sha256" or "digest") of the
   entry or the bound envelope holds its SHA-256, as hex, ``sha256:<hex>``,
   base64 or ``sha-256=:<b64>:``.

The JSON path of each binding is reported.  The envelope's own signature
(agent authorship), the key chain and the other §14.3 steps are not checked
here: they need the agent's key chain and belong to aics-identity / the
``aics`` client.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .checkpoint import CheckpointVerifyResult, WitnessPolicy, parse_checkpoint, verify_checkpoint
from .hashing import leaf_hash
from .note import Note, VKey, b64_decode, b64_encode, parse_note
from .tiles import MAX_ENTRY_BYTES, TileReader, inclusion_proof_from_tiles, read_entry
from .tree import verify_inclusion

__all__ = [
    "BUNDLE_FIELDS",
    "Bundle",
    "BundleVerifyResult",
    "bundle_from_tiles",
    "canonical_json",
    "u64_decode",
    "u64_encode",
    "verify_bundle",
]

#: The members of an AICS-1 §14.3 wire bundle, in their wire order.
BUNDLE_FIELDS = ("entry_bytes", "index", "inclusion_proof", "checkpoint_note", "envelope", "body_or_ct")
MAX_PROOF_LENGTH = 64
MAX_UINT = 9007199254740991  # AICS-1 §2 uint: 0 .. 2^53 - 1
MAX_JSON_DEPTH = 64  # AICS-1 §15: bound JSON depth (an AICS-1 entry nests about 5 levels)
#: AICS-1 §5.1: an entry has exactly these members.
ENTRY_V2_MEMBERS = frozenset({"v", "origin", "type", "actor_kid", "ts", "payload"})
#: Payload members that commit to an off-leaf body (AICS-1 §5.3), in lookup order.
BODY_COMMITMENTS = ("body_hash", "ct_hash", "document_hash")
_HASH_KEY_HINTS = ("hash", "sha256", "digest")
_U64_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


# ---------------------------------------------------------------------------
# Encodings (AICS-1 §2)
# ---------------------------------------------------------------------------


def u64_encode(data: bytes) -> str:
    """``U64``: canonical unpadded base64url (RFC 4648 §5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def u64_decode(text: Any, what: str = "value") -> bytes:
    """Strict ``U64`` decoder: padding, the standard-alphabet characters
    ``+`` and ``/``, any other character and non-canonical trailing bits are
    refused with ValueError."""
    if not isinstance(text, str):
        raise ValueError(f"{what} must be a U64 (unpadded base64url) string")
    if len(text) % 4 == 1 or not set(text) <= _U64_ALPHABET:
        raise ValueError(f"{what} is not canonical unpadded base64url (U64)")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise ValueError(f"{what} is not canonical unpadded base64url (U64)") from None
    if u64_encode(raw) != text:
        raise ValueError(f"{what} is not canonical unpadded base64url (U64)")
    return raw


def _strict_json(text: str | bytes | bytearray) -> Any:
    """JSON with the AICS-1 §2 strictness: UTF-8 only, no duplicate member
    names, no NaN/Infinity, bounded nesting."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise ValueError(f"duplicate JSON member name {k!r}")
            out[k] = v
        return out

    def constant(name: str) -> Any:
        raise ValueError(f"{name} is not a JSON value")

    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8")  # UnicodeDecodeError is a ValueError
    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except RecursionError:
        raise ValueError(f"JSON nests more than {MAX_JSON_DEPTH} levels deep") from None
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ValueError(f"JSON nests more than {MAX_JSON_DEPTH} levels deep")
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)
    return value


# ---------------------------------------------------------------------------
# The bundle
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Bundle:
    """An offline bundle.

    The attributes hold decoded values: the entry and body bytes, the proof
    hashes and the signed checkpoint note as text.  :meth:`to_dict` /
    :meth:`to_json` write the AICS-1 §14.3 wire form and :meth:`from_dict` /
    :meth:`from_json` read it."""

    entry_bytes: bytes
    index: int
    inclusion_proof: tuple[bytes, ...]
    checkpoint_note: str
    envelope: Any = None
    body_or_ct: bytes | None = None

    def to_dict(self) -> dict[str, Any]:
        """The §14.3 wire bundle (members in ``BUNDLE_FIELDS`` order)."""
        return {
            "entry_bytes": u64_encode(self.entry_bytes),
            "index": self.index,
            "inclusion_proof": [b64_encode(h) for h in self.inclusion_proof],
            "checkpoint_note": u64_encode(self.checkpoint_note.encode("utf-8")),
            "envelope": self.envelope,
            "body_or_ct": None if self.body_or_ct is None else u64_encode(self.body_or_ct),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"

    @classmethod
    def from_dict(cls, obj: Mapping[str, Any]) -> Bundle:
        """Read a §14.3 wire bundle: exactly the six members, strictly
        encoded.  Raises ValueError."""
        if not isinstance(obj, Mapping):
            raise ValueError("bundle must be a JSON object")
        if "entry_bytes_b64" in obj:
            raise ValueError(
                "this is the pre-0.2 aics-tlog bundle form (entry_bytes_b64, the note as text, padded base64 "
                "body); an AICS-1 §14.3 wire bundle has entry_bytes, checkpoint_note and body_or_ct in U64"
            )
        missing = [name for name in BUNDLE_FIELDS if name not in obj]
        if missing:
            raise ValueError(f"bundle is missing {', '.join(repr(m) for m in missing)} (AICS-1 §14.3)")
        extra = sorted(str(k) for k in obj if k not in BUNDLE_FIELDS)
        if extra:
            raise ValueError(f"bundle has members AICS-1 §14.3 does not define: {', '.join(extra)}")
        entry = u64_decode(obj["entry_bytes"], "entry_bytes")
        if len(entry) > MAX_ENTRY_BYTES:
            raise ValueError("entry exceeds the 65535-byte tlog-tiles limit")
        index = obj["index"]
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index <= MAX_UINT:
            raise ValueError("index must be an integer from 0 to 2^53-1")
        proof_raw = obj["inclusion_proof"]
        if not isinstance(proof_raw, list) or len(proof_raw) > MAX_PROOF_LENGTH:
            raise ValueError(f"inclusion_proof must be a list of at most {MAX_PROOF_LENGTH} hashes")
        proof: list[bytes] = []
        for i, h in enumerate(proof_raw):
            if not isinstance(h, str):
                raise ValueError(f"inclusion_proof[{i}] must be a base64 string")
            raw = b64_decode(h)
            if len(raw) != 32:
                raise ValueError(f"inclusion_proof[{i}] must be a 32-byte hash")
            proof.append(raw)
        note_bytes = u64_decode(obj["checkpoint_note"], "checkpoint_note")
        if not note_bytes:
            raise ValueError("checkpoint_note must be the signed checkpoint note")
        try:
            note = note_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("checkpoint_note is not UTF-8") from None
        envelope = obj["envelope"]
        if envelope is not None and not (isinstance(envelope, Mapping) and envelope):
            raise ValueError("envelope must be a non-empty JSON object (null only for an entry that embeds none)")
        body_raw = obj["body_or_ct"]
        body = None if body_raw is None else u64_decode(body_raw, "body_or_ct")
        return cls(
            entry_bytes=entry,
            index=index,
            inclusion_proof=tuple(proof),
            checkpoint_note=note,
            envelope=envelope,
            body_or_ct=body,
        )

    @classmethod
    def from_json(cls, text: str | bytes | bytearray) -> Bundle:
        try:
            obj = _strict_json(text)
        except ValueError as e:
            raise ValueError(f"bundle is not valid JSON: {e}") from None
        return cls.from_dict(obj)


def _entry_json(entry: bytes) -> tuple[Any, str | None]:
    """(parsed entry, None) or (None, why it is not JSON)."""
    try:
        return _strict_json(entry), None
    except ValueError as e:
        return None, str(e)


def _is_aics1_entry(doc: Any) -> bool:
    """An entry v2 object whose payload embeds an envelope (AICS-1 §5.1)."""
    return (
        isinstance(doc, Mapping)
        and _json_equal(doc.get("v"), 2)
        and isinstance(doc.get("payload"), Mapping)
        and "envelope" in doc["payload"]
    )


def _embedded_envelope(entry: bytes) -> Any:
    """The envelope an AICS-1 entry embeds, or None."""
    doc, _ = _entry_json(entry)
    if not _is_aics1_entry(doc):
        return None
    envelope = doc["payload"]["envelope"]
    return envelope if isinstance(envelope, Mapping) and envelope else None


def bundle_from_tiles(
    reader: TileReader,
    index: int,
    checkpoint_note: str | bytes | Note,
    *,
    entry: bytes | None = None,
    envelope: Any = None,
    body_or_ct: bytes | None = None,
) -> Bundle:
    """Assemble the AICS-1 §14.3 bundle for leaf ``index`` from tiles at the
    checkpoint's size.  Use a VerifiedTileReader built from the verified
    checkpoint so the entry and proof are proven; the proof is re-checked
    against the root.

    ``envelope`` defaults to the envelope the entry embeds
    (``payload.envelope`` of an AICS-1 entry), so the bundle carries it as
    §14.3 requires; it stays None for an entry that embeds none."""
    note = checkpoint_note if isinstance(checkpoint_note, Note) else parse_note(checkpoint_note)
    cp = parse_checkpoint(note.text)
    if not 0 <= index < cp.size:
        raise ValueError(f"index {index} is not below the checkpoint size {cp.size}")
    if entry is None:
        entry = read_entry(reader, index, cp.size)
    proof = inclusion_proof_from_tiles(reader, index, cp.size)
    if not verify_inclusion(leaf_hash(entry), index, cp.size, proof, cp.root):
        raise ValueError(f"entry {index} is not included under the checkpoint root")
    if envelope is None:
        envelope = _embedded_envelope(bytes(entry))
    return Bundle(
        entry_bytes=bytes(entry),
        index=index,
        inclusion_proof=tuple(proof),
        checkpoint_note=note.serialise(),
        envelope=envelope,
        body_or_ct=body_or_ct,
    )


# ---------------------------------------------------------------------------
# Canonical JSON (RFC 8785 for the JSON subset envelopes use)
# ---------------------------------------------------------------------------


def canonical_json(value: Any) -> bytes:
    """RFC 8785 (JCS) serialisation for null, booleans, integers within
    +-2**53, strings, arrays and objects.  Other numbers are refused rather
    than risk a serialisation that differs from JCS."""

    def enc(v: Any) -> str:
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            if abs(v) > 2**53:
                raise ValueError("integer outside the IEEE-754 exact range")
            return str(v)
        if isinstance(v, float):
            if v.is_integer() and abs(v) <= 2**53:
                return str(int(v))
            raise ValueError("non-integral numbers are not supported")
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False)
        if isinstance(v, (list, tuple)):
            return "[" + ",".join(enc(x) for x in v) + "]"
        if isinstance(v, Mapping):
            keys = list(v.keys())
            if not all(isinstance(k, str) for k in keys):
                raise ValueError("object keys must be strings")
            keys.sort(key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + enc(v[k]) for k in keys) + "}"
        raise ValueError(f"unsupported JSON type {type(v).__name__}")

    return enc(value).encode("utf-8")


# ---------------------------------------------------------------------------
# Binding search
# ---------------------------------------------------------------------------


def _json_equal(a: Any, b: Any) -> bool:
    """Structural equality that keeps JSON types apart (true != 1, 1 != 1.0)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, Mapping) and isinstance(b, Mapping):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b, strict=True))
    if type(a) is not type(b):
        return False
    return a == b


def _same_json(a: Any, b: Any) -> bool:
    """Equal as JSON values: the same JCS bytes (key order and 1 vs 1.0 do not
    matter; true vs 1 does), or, for values JCS-equivalence cannot be decided
    on here (non-integral numbers), type-strict structural equality."""
    try:
        return canonical_json(a) == canonical_json(b)
    except ValueError:
        return _json_equal(a, b)


def _is_hash_key(key: str) -> bool:
    k = key.lower()
    return any(h in k for h in _HASH_KEY_HINTS)


def _walk(node: Any, path: str = "$", hint: bool = False) -> Iterator[tuple[str, Any, bool]]:
    yield path, node, hint
    if isinstance(node, Mapping):
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}", _is_hash_key(str(k)))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]", hint)


def _matches_digest(value: str, digest: bytes) -> bool:
    v = value.strip()
    low = v.lower()
    for prefix in ("sha256:", "sha-256:", "sha256=", "sha-256="):
        if low.startswith(prefix):
            v = v[len(prefix) :]
            break
    if len(v) > 2 and v.startswith(":") and v.endswith(":"):
        v = v[1:-1]  # RFC 9530 / RFC 8941 byte sequence
    if len(v) == 64:
        try:
            return bytes.fromhex(v) == digest
        except ValueError:
            pass
    padded = v + "=" * (-len(v) % 4)
    for candidate in (padded, padded.replace("-", "+").replace("_", "/")):
        try:
            raw = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        if raw == digest:
            return True
    return False


def _find_value(doc: Any, wanted: Any) -> str | None:
    for path, node, _ in _walk(doc):
        if _json_equal(node, wanted):
            return path
    return None


def _find_digest(doc: Any, digest: bytes) -> str | None:
    for path, node, hint in _walk(doc):
        if hint and isinstance(node, str) and _matches_digest(node, digest):
            return path
    return None


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass
class BundleVerifyResult:
    ok: bool = False
    error: str | None = None
    origin: str | None = None
    size: int | None = None
    root: bytes | None = None
    index: int | None = None
    leaf_hash: bytes | None = None
    entry_sha256: bytes | None = None
    envelope_bound_at: str | None = None
    body_bound_at: str | None = None
    checkpoint: CheckpointVerifyResult | None = None
    notes: list[str] = field(default_factory=list)
    #: True when the entry is an AICS-1 entry and the §14.3 entry checks applied
    aics1_entry: bool = False


def _aics1_entry_problem(doc: Mapping[str, Any], entry_bytes: bytes) -> str | None:
    """Why an entry that embeds an envelope is not a well-formed AICS-1 entry
    (§5.1, §5.2, §14.3 step 1), or None."""
    try:
        jcs = canonical_json(doc)
    except ValueError:
        jcs = None
    if jcs != entry_bytes:
        return "the entry bytes are not the JCS serialisation of the entry (AICS-1 §5.2, §14.3 step 1)"
    if set(doc) != ENTRY_V2_MEMBERS:
        return ("the entry does not have exactly the entry v2 members v, origin, type, actor_kid, ts, payload "
                "(AICS-1 §5.1)")
    payload = doc["payload"]
    envelope = payload["envelope"]
    if not (isinstance(envelope, Mapping) and isinstance(envelope.get("payload"), Mapping)):
        return "the embedded envelope is not an envelope object with a payload (AICS-1 §4.1)"
    q = envelope["payload"]
    auth = envelope.get("auth")
    allowed = {"envelope", *q}
    if isinstance(auth, Mapping) and auth.get("scheme") == "shared-secret":
        allowed.add("attestation")  # the policy attestation of a fallback write (§5.1)
    extra = sorted(set(payload) - allowed)
    if extra:
        return (f"the entry payload has members that are not copies of the envelope payload: {', '.join(extra)} "
                "(AICS-1 §5.1)")
    for name, value in q.items():
        if name == "envelope" or name not in payload or not _same_json(payload[name], value):
            return f"payload member {name!r} is not an exact copy of the envelope payload (AICS-1 §5.1)"
    return None


def _bind_aics1(bundle: Bundle, doc: Mapping[str, Any], res: BundleVerifyResult) -> str | None:
    """The §14.3 step 1 and step 4 bindings of an AICS-1 entry; an error or None."""
    problem = _aics1_entry_problem(doc, bundle.entry_bytes)
    if problem is not None:
        return problem
    payload = doc["payload"]
    if bundle.envelope is None:
        return ("the bundle has no envelope, but the entry embeds one: an AICS-1 §14.3 bundle carries the "
                "entry's envelope")
    if not _same_json(bundle.envelope, payload["envelope"]):
        return "the bundle envelope differs from the envelope embedded in the entry (AICS-1 §14.3 step 1)"
    res.envelope_bound_at = "$.payload.envelope"
    if bundle.body_or_ct is not None:
        name = next((n for n in BODY_COMMITMENTS if n in payload), None)
        if name is None:
            return ("the entry commits to no body_or_ct: its payload has no "
                    + ", ".join(BODY_COMMITMENTS) + " (AICS-1 §5.3)")
        digest = hashlib.sha256(bundle.body_or_ct).hexdigest()
        if not (isinstance(payload[name], str) and payload[name] == digest):
            return f"body_or_ct does not hash to the entry's {name} (AICS-1 §14.3 step 4)"
        size = payload.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size != len(bundle.body_or_ct):
            return (f"body_or_ct is {len(bundle.body_or_ct)} bytes, the entry's size is {size!r} "
                    "(AICS-1 §14.3 step 4)")
        res.body_bound_at = f"$.payload.{name}"
    return None


def _bind_generic(bundle: Bundle, doc: Any, res: BundleVerifyResult) -> str | None:
    """Bindings for an entry that embeds no envelope; an error or None."""
    envelope_doc: Any = None
    if bundle.envelope is not None:
        where = _find_value(doc, bundle.envelope)
        if where is None:
            try:
                env_digest = hashlib.sha256(canonical_json(bundle.envelope)).digest()
            except ValueError:
                env_digest = None
            if env_digest is not None:
                hashed_at = _find_digest(doc, env_digest)
                if hashed_at is not None:
                    where = f"{hashed_at} (sha256 of canonical JSON)"
                    envelope_doc = bundle.envelope
        if where is None:
            return "the entry does not commit to the bundled envelope"
        res.envelope_bound_at = where

    if bundle.body_or_ct is not None:
        digest = hashlib.sha256(bundle.body_or_ct).digest()
        where = _find_digest(doc, digest)
        if where is None and envelope_doc is not None:
            inner = _find_digest(envelope_doc, digest)
            if inner is not None:
                where = "envelope" + inner[1:]
        if where is None:
            return "neither the entry nor the bundled envelope commits to body_or_ct (no hash field holds its SHA-256)"
        res.body_bound_at = where
    return None


def verify_bundle(
    bundle: Bundle | Mapping[str, Any] | str | bytes,
    log_key: VKey,
    witness_keys: Sequence[VKey] | None = None,
    quorum: int = 0,
    *,
    policy: WitnessPolicy | None = None,
    expected_origin: str | None = None,
    max_age_seconds: int | None = None,
    max_future_seconds: int | None = None,
    now: int | None = None,
) -> BundleVerifyResult:
    """Verify a bundle offline against the out-of-band ``log_key``.

    ``bundle`` is a :class:`Bundle`, or the §14.3 wire form as a JSON object
    or JSON text; a wire bundle that does not parse is reported as a failed
    result, not raised.

    Freshness is not checked unless ``max_age_seconds`` is given (or the
    policy carries one): an old bundle proves inclusion at the time of its
    checkpoint, not that the checkpoint is the latest.
    """
    if not isinstance(bundle, Bundle):
        try:
            if isinstance(bundle, (str, bytes, bytearray)):
                bundle = Bundle.from_json(bundle)
            else:
                bundle = Bundle.from_dict(bundle)
        except ValueError as e:
            return BundleVerifyResult(error=f"not an AICS-1 §14.3 wire bundle: {e}")
    res = BundleVerifyResult(index=bundle.index)
    res.leaf_hash = leaf_hash(bundle.entry_bytes)
    res.entry_sha256 = hashlib.sha256(bundle.entry_bytes).digest()
    try:
        note = parse_note(bundle.checkpoint_note)
    except ValueError as e:
        res.error = f"checkpoint_note is not a signed note: {e}"
        return res
    if policy is not None and max_age_seconds is None and policy.max_age_seconds is not None:
        # Offline: the policy's witnesses and quorum apply, its freshness
        # bound applies only when the caller asks for it.
        policy = WitnessPolicy(policy.quorum, policy.witnesses, None)
    cpres = verify_checkpoint(
        note,
        log_key,
        list(witness_keys or []),
        quorum,
        expected_origin=expected_origin,
        max_age_seconds=max_age_seconds,
        max_future_seconds=max_future_seconds,
        now=now,
        policy=policy,
    )
    res.checkpoint = cpres
    res.origin, res.size, res.root = cpres.origin, cpres.size, cpres.root
    if not cpres.ok:
        res.error = f"checkpoint: {cpres.error}"
        return res
    assert cpres.size is not None and cpres.root is not None
    if bundle.index >= cpres.size:
        res.error = f"index {bundle.index} is not below the checkpoint size {cpres.size}"
        return res
    if not verify_inclusion(res.leaf_hash, bundle.index, cpres.size, list(bundle.inclusion_proof), cpres.root):
        res.error = "inclusion proof does not verify against the checkpoint root"
        return res

    if bundle.envelope is not None and not (isinstance(bundle.envelope, Mapping) and bundle.envelope):
        res.error = "envelope must be a non-empty JSON object"
        return res
    doc, not_json = _entry_json(bundle.entry_bytes)
    if doc is None and (bundle.envelope is not None or bundle.body_or_ct is not None):
        res.error = f"entry is not JSON ({not_json}), so it cannot commit to an envelope or body"
        return res
    try:
        if _is_aics1_entry(doc):
            res.aics1_entry = True
            error = _bind_aics1(bundle, doc, res)
        elif doc is not None:
            error = _bind_generic(bundle, doc, res)
        else:
            error = None  # an entry that is not JSON: inclusion only
    except RecursionError:
        error = "the envelope nests too deeply to compare"
    if error is not None:
        res.error = error
        return res

    if bundle.envelope is not None:
        res.notes.append("envelope signature not checked here (agent keys are verified by aics-identity)")
    elif not res.aics1_entry:
        res.notes.append("no envelope: the bundle proves the entry's inclusion only")
    res.ok = True
    return res

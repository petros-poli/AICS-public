"""Independent reference encodings written from docs/spec/AICS-1.md alone.

Nothing here imports a sibling package: these functions are the suite's third
opinion on every byte the specification fixes.  Each one cites the section it
implements.  They are test instruments, not a production library: keys are
deterministic test keys and the sealed-box helper fixes its ephemeral key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

UINT_MAX = 9007199254740991  # §2: uint is 0 .. 2**53 - 1
EM_DASH = "—"

# ---------------------------------------------------------------------------
# §2 representations
# ---------------------------------------------------------------------------


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > UINT_MAX:
            raise ValueError("integer outside the I-JSON range")
        return str(value)
    if isinstance(value, float):
        raise ValueError("AICS-1 artifacts carry no non-integer numbers")
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs(v) for v in value) + "]"
    if isinstance(value, Mapping):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))  # RFC 8785 §3.2.3: UTF-16 code units
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs(value[k]) for k in keys) + "}"
    raise TypeError(f"not a JSON value: {type(value).__name__}")


def J(value: Any) -> bytes:
    """``J(x)``: RFC 8785 JCS for the JSON values AICS-1 uses (no floats)."""
    return _jcs(value).encode("utf-8")


def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hexH(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def B64(data: bytes) -> str:
    """Canonical padded standard base64 (RFC 4648 §4)."""
    return base64.b64encode(data).decode("ascii")


def U64(data: bytes) -> str:
    """Canonical unpadded base64url (RFC 4648 §5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def dB64(text: str) -> bytes:
    """Strict decoder for ``B64``: anything non-canonical raises ValueError."""
    if not isinstance(text, str) or len(text) % 4:
        raise ValueError("not canonical base64")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64: {exc}") from None
    if B64(raw) != text:
        raise ValueError("not canonical base64")
    return raw


def dU64(text: str) -> bytes:
    """Strict decoder for ``U64``."""
    if not isinstance(text, str) or "=" in text or len(text) % 4 == 1:
        raise ValueError("not canonical base64url")
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64url: {exc}") from None
    if U64(raw) != text:
        raise ValueError("not canonical base64url")
    return raw


# ---------------------------------------------------------------------------
# §3.1 keys and identifiers
# ---------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def test_key(byte: int) -> Ed25519PrivateKey:
    """Deterministic test key: the seed is 32 repeats of ``byte`` (the Appendix A convention)."""
    return Ed25519PrivateKey.from_private_bytes(bytes([byte]) * 32)


def raw_public(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes_raw()


def kid(key: Ed25519PrivateKey | Ed25519PublicKey | bytes) -> str:
    """``did:key:z`` + base58btc(0xed 0x01 || ed25519 public key)."""
    raw = key if isinstance(key, (bytes, bytearray)) else raw_public(key)
    return "did:key:z" + b58encode(b"\xed\x01" + bytes(raw))


def kid_public(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError("not a did:key")
    raw = b58decode(did[len("did:key:z"):])
    if raw[:2] != b"\xed\x01" or len(raw) != 34:
        raise ValueError("not an Ed25519 did:key")
    return raw[2:]


def x25519_did(raw: bytes) -> str:
    return "did:key:z" + b58encode(b"\xec\x01" + raw)


# ---------------------------------------------------------------------------
# §4 envelopes
# ---------------------------------------------------------------------------


def signing_digest(protected: Mapping[str, Any], payload: Mapping[str, Any]) -> bytes:
    """``D = H(J(E.protected) || 0x2e || J(E.payload))`` (§4.1)."""
    return H(J(protected) + b"." + J(payload))


def envelope_hash(env: Mapping[str, Any]) -> str:
    """``envelope_hash = hexH(J(E))`` over the complete envelope, ``auth`` included (§4.1)."""
    return hexH(J(env))


def protected_header(*, origin: str, typ: str, signer_kid: str, created: int, nonce: bytes | str,
                     seq: int, prev: str | None, seen: Mapping[str, Any] | None,
                     expires: int | None = None, alg: str = "EdDSA") -> dict[str, Any]:
    return {
        "alg": alg, "origin": origin, "type": typ, "kid": signer_kid, "created": created,
        "expires": created + 300 if expires is None else expires,
        "nonce": nonce if isinstance(nonce, str) else U64(nonce),
        "seq": seq, "prev": prev, "seen": None if seen is None else dict(seen),
    }


def native_envelope(key: Ed25519PrivateKey, *, origin: str, typ: str, payload: Mapping[str, Any],
                    created: int, nonce: bytes | str, seq: int = 0, prev: str | None = None,
                    seen: Mapping[str, Any] | None = None, expires: int | None = None) -> dict[str, Any]:
    """A signed ``ed25519-jcs`` envelope with exactly the §4.1 members."""
    p = protected_header(origin=origin, typ=typ, signer_kid=kid(key), created=created, nonce=nonce,
                         seq=seq, prev=prev, seen=seen, expires=expires)
    q = dict(payload)
    return {"v": 1, "protected": p, "payload": q, "auth": {"scheme": "ed25519-jcs"},
            "sig": U64(key.sign(signing_digest(p, q)))}


def unsigned_text_envelope(key: Ed25519PrivateKey, *, origin: str, typ: str, payload: Mapping[str, Any],
                           created: int, nonce: bytes | str, session: str, scheme: str = "text-ed25519",
                           seq: int = 0, prev: str | None = None,
                           seen: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """``U``: an envelope with only ``sig`` removed, for the §11.3 text schemes."""
    p = protected_header(origin=origin, typ=typ, signer_kid=kid(key), created=created, nonce=nonce,
                         seq=seq, prev=prev, seen=seen)
    return {"v": 1, "protected": p, "payload": dict(payload), "auth": {"scheme": scheme, "session": session}}


def accepted_at(protected: Mapping[str, Any], t: int) -> bool:
    """§4.3 REQUIRED freshness checks at submission time ``t``."""
    c, x = protected["created"], protected["expires"]
    return c <= t + 30 and c >= t - 300 and c < x <= c + 300 and t < x


def seen_pointer(note: bytes) -> dict[str, Any]:
    """``seen`` = {checkpoint_note_hash: hexH(complete signed note), size} (§4.1)."""
    size = int(note.split(b"\n")[1])
    return {"checkpoint_note_hash": hexH(note), "size": size}


# ---------------------------------------------------------------------------
# §5 entries and Merkle hashing (RFC 6962 / RFC 9162 reference algorithms)
# ---------------------------------------------------------------------------


def entry(env: Mapping[str, Any], ts: int) -> dict[str, Any]:
    """Entry v2: ``{v, origin, type, actor_kid, ts, payload: envelope + copy of Q}`` (§5.1)."""
    p = env["protected"]
    return {"v": 2, "origin": p["origin"], "type": p["type"], "actor_kid": p["kid"], "ts": ts,
            "payload": {"envelope": dict(env), **dict(env["payload"])}}


def leaf_hash(entry_bytes: bytes) -> bytes:
    return H(b"\x00" + entry_bytes)


def node_hash(left: bytes, right: bytes) -> bytes:
    return H(b"\x01" + left + right)


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves: Sequence[bytes]) -> bytes:
    """RFC 6962 §2.1 Merkle Tree Hash over leaf hashes."""
    if not leaves:
        return H(b"")
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def inclusion_path(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """RFC 6962 §2.1.1 PATH(m, D[n]) over leaf hashes, bottom-up."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_path(index, leaves[:k]) + [mth(leaves[k:])]
    return inclusion_path(index - k, leaves[k:]) + [mth(leaves[:k])]


def consistency_path(m: int, leaves: Sequence[bytes]) -> list[bytes]:
    """RFC 6962 §2.1.2 PROOF(m, D[n])."""
    def subproof(m: int, d: Sequence[bytes], complete: bool) -> list[bytes]:
        n = len(d)
        if m == n:
            return [] if complete else [mth(d)]
        k = _split(n)
        if m <= k:
            return subproof(m, d[:k], complete) + [mth(d[k:])]
        return subproof(m - k, d[k:], False) + [mth(d[:k])]
    if m == 0 or m == len(leaves):
        return []
    return subproof(m, leaves, True)


def entry_bundle(entries: Sequence[bytes]) -> bytes:
    """tlog-tiles entry bundle: uint16-big-endian length prefix per entry (§6.1)."""
    out = bytearray()
    for e in entries:
        if len(e) > 0xFFFF:
            raise ValueError("entry longer than 65535 bytes")
        out += struct.pack(">H", len(e)) + e
    return bytes(out)


EMPTY_ROOT = hashlib.sha256(b"").digest()


def verify_inclusion(leaf: bytes, index: int, size: int, proof: Sequence[bytes], root: bytes) -> bool:
    """RFC 9162 §2.1.3.2 with the AICS-1 §14.2 step 4 rules (``0 <= index < size``, every element consumed)."""
    if not 0 <= index < size or any(len(p) != 32 for p in proof):
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(m: int, n: int, root_m: bytes, root_n: bytes, proof: Sequence[bytes]) -> bool:
    """RFC 9162 §2.1.4.2 with the AICS-1 §14.2 steps 1-3 rules.

    ``m == n`` needs identical roots and an empty proof; ``m == 0`` needs the
    empty-tree root and an empty proof; ``m > n`` is not a consistency proof
    (the caller swaps for historical comparison)."""
    if any(len(p) != 32 for p in proof) or not 0 <= m <= n:
        return False
    if m == n:
        return not proof and root_m == root_n
    if m == 0:
        return not proof and root_m == EMPTY_ROOT
    path = list(proof)
    if not path:
        return False
    if m & (m - 1) == 0:  # an exact power of two
        path = [root_m] + path
    fn, sn = m - 1, n - 1
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
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == root_m and sr == root_n


# ---------------------------------------------------------------------------
# §6.1 tiled profile: C2SP tlog-tiles v1.0.0 paths and resources, tile height 8
# ---------------------------------------------------------------------------

TILE_WIDTH = 256  # height 8: a full tile holds 256 hashes; partial widths are 1-255


def tile_index_path(n: int) -> str:
    """``<N>``: zero-padded 3-digit path elements, all but the last prefixed ``x`` (1234067 -> ``x001/x234/067``)."""
    if type(n) is not int or n < 0:
        raise ValueError("a tile index is a non-negative integer")
    parts = []
    while True:
        n, r = divmod(n, 1000)
        parts.append(f"{r:03d}")
        if n == 0:
            break
    parts.reverse()
    return "/".join(["x" + p for p in parts[:-1]] + [parts[-1]])


def _width_suffix(width: int | None) -> str:
    if width is None:
        return ""
    if type(width) is not int or not 1 <= width < TILE_WIDTH:
        raise ValueError("a partial tile has width 1-255")
    return f".p/{width}"


def tile_path(level: int, n: int, width: int | None = None) -> str:
    """``tile/<L>/<N>[.p/<W>]``: ``W`` only for a partial tile, as a decimal without leading zeroes."""
    if type(level) is not int or not 0 <= level <= 63:
        raise ValueError("a tile level is 0-63")
    return f"tile/{level}/{tile_index_path(n)}{_width_suffix(width)}"


def entry_bundle_path(n: int, width: int | None = None) -> str:
    """``tile/entries/<N>[.p/<W>]``."""
    return f"tile/entries/{tile_index_path(n)}{_width_suffix(width)}"


def split_entry_bundle(data: bytes) -> list[bytes]:
    """The entries of an entry bundle (uint16-big-endian length prefixes, nothing left over)."""
    out, pos = [], 0
    while pos < len(data):
        if pos + 2 > len(data):
            raise ValueError("truncated entry length")
        n = struct.unpack(">H", data[pos:pos + 2])[0]
        if pos + 2 + n > len(data):
            raise ValueError("truncated entry")
        out.append(data[pos + 2:pos + 2 + n])
        pos += 2 + n
    return out


def _level_counts(size: int) -> list[int]:
    """Hashes per tile level: level ``L`` holds the hashes of the complete subtrees of ``256**L`` leaves."""
    counts, unit = [], 1
    while size // unit:
        counts.append(size // unit)
        unit *= TILE_WIDTH
    return counts


def tile_resources(entries: Sequence[bytes]) -> dict[str, bytes]:
    """Every tlog-tiles resource of the tree of ``entries``: the hash tiles of each level and the entry bundles."""
    out: dict[str, bytes] = {}
    hashes = [leaf_hash(e) for e in entries]
    level = 0
    while hashes:
        for n in range(0, len(hashes), TILE_WIDTH):
            chunk = hashes[n:n + TILE_WIDTH]
            out[tile_path(level, n // TILE_WIDTH, None if len(chunk) == TILE_WIDTH else len(chunk))] = b"".join(chunk)
        hashes = [mth(hashes[i:i + TILE_WIDTH]) for i in range(0, len(hashes) - TILE_WIDTH + 1, TILE_WIDTH)]
        level += 1
    for n in range(0, len(entries), TILE_WIDTH):
        chunk = entries[n:n + TILE_WIDTH]
        out[entry_bundle_path(n // TILE_WIDTH, None if len(chunk) == TILE_WIDTH else len(chunk))] = entry_bundle(chunk)
    return out


def _tile_hashes(tiles: Mapping[str, bytes], size: int, level: int, n: int) -> list[bytes]:
    count = _level_counts(size)[level]
    width = min(TILE_WIDTH, count - TILE_WIDTH * n)
    path = tile_path(level, n, None if width == TILE_WIDTH else width)
    data = tiles.get(path)
    if data is None:
        raise ValueError(f"{path} is missing")
    if len(data) != 32 * width:
        raise ValueError(f"{path} is {len(data)} bytes, not {width} hashes")
    return [data[i:i + 32] for i in range(0, len(data), 32)]


def root_from_tiles(tiles: Mapping[str, bytes], size: int) -> bytes:
    """MTH of the tree of ``size`` from its hash tiles alone, each subtree from the highest level that holds it."""
    def subtree(lo: int, hi: int) -> bytes:
        n = hi - lo
        if n & (n - 1) == 0 and lo % n == 0:  # a complete, aligned subtree: hashes of one level
            level = (n.bit_length() - 1) // 8
            unit = TILE_WIDTH ** level
            return mth([_tile_hashes(tiles, size, level, j // TILE_WIDTH)[j % TILE_WIDTH]
                        for j in range(lo // unit, hi // unit)])
        k = _split(n)
        return node_hash(subtree(lo, lo + k), subtree(lo + k, hi))

    return EMPTY_ROOT if size == 0 else subtree(0, size)


def verify_tiles(tiles: Mapping[str, bytes], size: int, root: bytes) -> list[bytes]:
    """Authenticate a complete tile set up to a trusted root (§6.1); returns the entries.  Raises ValueError.

    The root is recomputed from the hash tiles, every full tile is checked
    against its parent hash one level up, and every entry bundle against its
    level-0 hashes, so a changed byte in any resource is detected."""
    if root_from_tiles(tiles, size) != root:
        raise ValueError("the hash tiles do not reconstruct the trusted root")
    counts = _level_counts(size)
    for level in range(len(counts) - 1):
        for n in range(counts[level + 1]):  # full tiles at this level are the parents' children
            if mth(_tile_hashes(tiles, size, level, n)) != \
                    _tile_hashes(tiles, size, level + 1, n // TILE_WIDTH)[n % TILE_WIDTH]:
                raise ValueError(f"{tile_path(level, n)} does not hash to its parent")
    entries: list[bytes] = []
    for n in range(0, size, TILE_WIDTH):
        width = min(TILE_WIDTH, size - n)
        path = entry_bundle_path(n // TILE_WIDTH, None if width == TILE_WIDTH else width)
        if path not in tiles:
            raise ValueError(f"{path} is missing")
        bundle = split_entry_bundle(tiles[path])
        if [leaf_hash(e) for e in bundle] != _tile_hashes(tiles, size, 0, n // TILE_WIDTH):
            raise ValueError(f"{path} does not match its level-0 tile")
        entries += bundle
    return entries


# ---------------------------------------------------------------------------
# §6.2 checkpoint notes, log signatures and cosignatures
# ---------------------------------------------------------------------------


def note_key_id(name: str, sig_type: int, public: bytes) -> bytes:
    return H(name.encode("utf-8") + b"\n" + bytes([sig_type]) + public)[:4]


def vkey(name: str, sig_type: int, public: bytes) -> str:
    return f"{name}+{note_key_id(name, sig_type, public).hex()}+{B64(bytes([sig_type]) + public)}"


def checkpoint_text(origin: str, size: int, root: bytes) -> str:
    return f"{origin}\n{size}\n{B64(root)}\n"


def log_signature_line(name: str, key: Ed25519PrivateKey, text: str) -> str:
    blob = note_key_id(name, 0x01, raw_public(key)) + key.sign(text.encode("utf-8"))
    return f"{EM_DASH} {name} {B64(blob)}\n"


def cosignature_message(timestamp: int, text: str) -> bytes:
    return f"cosignature/v1\ntime {timestamp}\n".encode("utf-8") + text.encode("utf-8")


def cosignature_line(name: str, key: Ed25519PrivateKey, timestamp: int, text: str) -> str:
    blob = (note_key_id(name, 0x04, raw_public(key)) + timestamp.to_bytes(8, "big")
            + key.sign(cosignature_message(timestamp, text)))
    return f"{EM_DASH} {name} {B64(blob)}\n"


def signed_note(text: str, lines: Sequence[str]) -> bytes:
    """Note text, one blank line, then signature lines (each already ending in LF)."""
    return (text + "\n" + "".join(lines)).encode("utf-8")


def parse_signed_note(note: bytes) -> tuple[str, list[tuple[str, bytes]]]:
    text = note.decode("utf-8")
    cut = text.rindex("\n\n")
    body, sigs = text[: cut + 1], text[cut + 2:]
    out = []
    for line in sigs.split("\n"):
        if line:
            assert line.startswith(EM_DASH + " ")
            name, b64 = line[2:].split(" ")
            out.append((name, dB64(b64)))
    return body, out


def parse_vkey(text: str) -> tuple[str, bytes, int, bytes]:
    """``name+hex(key_id)+B64(type || public_key)`` -> (name, key_id, type, public_key); key ID checked."""
    name, hexid, b64 = text.split("+", 2)
    raw = dB64(b64)
    if len(raw) != 33 or not re.fullmatch(r"[0-9a-f]{8}", hexid):
        raise ValueError("not an Ed25519 vkey")
    if note_key_id(name, raw[0], raw[1:]) != bytes.fromhex(hexid):
        raise ValueError("vkey key ID does not match the key")
    return name, bytes.fromhex(hexid), raw[0], raw[1:]


def parse_checkpoint_text(text: str) -> tuple[str, int, bytes]:
    """§6.2 / §14.1 step 2: exactly ``origin LF decimal_size LF B64(root) LF``."""
    lines = text.split("\n")
    if len(lines) != 4 or lines[3] != "" or not lines[0]:
        raise ValueError("a checkpoint has exactly three text lines")
    if not re.fullmatch(r"0|[1-9][0-9]*", lines[1]) or int(lines[1]) > UINT_MAX:
        raise ValueError("size is not a canonical decimal uint")
    root = dB64(lines[2])
    if len(root) != 32:
        raise ValueError("root is not 32 bytes")
    return lines[0], int(lines[1]), root


def _ed25519_ok(public: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass
class NoteVerdict:
    """What AICS-1 §6.2-6.3 and §14.1 steps 2-3 conclude about one signed note."""

    log_ok: bool = False          # parsed, pinned origin, and the pinned log key signed it: log-signed evidence
    ok: bool = False              # log-signed, no invalid or repeated recognized line, and the quorum of fresh cosignatures
    reason: str | None = None     # malformed | origin | no_log_signature | duplicate_recognized | bad_signature | quorum
    origin: str | None = None
    size: int | None = None
    root: bytes | None = None
    counted: list[str] = field(default_factory=list)
    timestamps: dict[str, int] = field(default_factory=dict)
    ignored_lines: int = 0


def verify_note(note: bytes, log_vkey: str, witness_vkeys: Sequence[str] = (), quorum: int = 0, *,
                max_age: int | None = None, now: int | None = None, max_future: int = 30,
                expected_origin: str | None = None) -> NoteVerdict:
    """Independent AICS-1 checkpoint-note verifier.

    Recognized keys are the pinned log key and the pinned witnesses.  Lines
    from unknown keys are ignored, repeated or not; a second line for a
    recognized ``(name, key_id)`` or an invalid signature by a recognized key
    rejects the note (§6.2).  A repeated or invalid *witness* line rejects the
    note but leaves it log-signed evidence (§14.6: it is still what the log
    signed); a repeated *log* line leaves no log signature to rely on.  A
    cosignature counts when ``now - max_age <= timestamp <= now + 30`` (§6.3);
    with ``now=None`` no freshness bound applies (archived, historical
    verification).  ``expected_origin`` is the pinned origin (§14.1 step 1): a
    note for any other origin is not this log's note.
    """
    v = NoteVerdict()
    try:
        s = note.decode("utf-8")
        cut = s.index("\n\n")
        text, block = s[: cut + 1], s[cut + 2:]
        v.origin, v.size, v.root = parse_checkpoint_text(text)
        if not block.endswith("\n"):
            raise ValueError("signature block does not end with LF")
        lines = []
        for line in block[:-1].split("\n"):
            if not line.startswith(EM_DASH + " ") or line.count(" ") != 2:
                raise ValueError("malformed signature line")
            name, b64 = line[2:].split(" ")
            blob = dB64(b64)
            if len(blob) < 5:
                raise ValueError("signature blob too short")
            lines.append((name, blob))
        log_name, log_id, log_type, log_pub = parse_vkey(log_vkey)
        if log_type != 0x01:
            raise ValueError("log key is not type 0x01")
        recognized: dict[tuple[str, bytes], tuple[str, bytes]] = {(log_name, log_id): ("log", log_pub)}
        for w in witness_vkeys:
            wn, wid, wt, wp = parse_vkey(w)
            if wt != 0x04:
                raise ValueError("witness key is not type 0x04")
            recognized[(wn, wid)] = ("witness", wp)
    except (ValueError, UnicodeDecodeError) as exc:
        v.reason = f"malformed: {exc}"
        return v
    if expected_origin is not None and v.origin != expected_origin:
        v.reason = "origin"
        return v
    seen: set[tuple[str, bytes]] = set()
    bad_witness = repeated_witness = False
    for name, blob in lines:
        key = (name, blob[:4])
        if key not in recognized:
            v.ignored_lines += 1
            continue
        role, pub = recognized[key]
        if key in seen:
            if role == "log":
                v.log_ok = False
                v.reason = "duplicate_recognized"
                return v
            repeated_witness = True  # rejected (§6.2), but still what the log signed (§14.6), as for bad_witness
            continue
        seen.add(key)
        if role == "log":
            if len(blob) != 68 or not _ed25519_ok(pub, blob[4:], text.encode("utf-8")):
                v.log_ok = False
                v.reason = "bad_signature"
                return v
            v.log_ok = True
            continue
        ts = int.from_bytes(blob[4:12], "big") if len(blob) == 76 else -1
        if ts < 0 or not _ed25519_ok(pub, blob[12:], cosignature_message(ts, text)):
            bad_witness = True  # the note is rejected (§6.2), but it is still what the log signed (§14.6)
            continue
        v.timestamps[name] = ts
    if not v.log_ok:
        v.reason = "no_log_signature"
        return v
    if repeated_witness:
        v.reason = "duplicate_recognized"
        return v
    if bad_witness:
        v.reason = "bad_signature"
        return v
    for name, ts in v.timestamps.items():
        if now is None or ((max_age is None or now - max_age <= ts) and ts <= now + max_future):
            v.counted.append(name)
    if len(v.counted) < quorum:
        v.reason = "quorum"
        return v
    v.ok = True
    return v


# ---------------------------------------------------------------------------
# §8.1 sealed messages
# ---------------------------------------------------------------------------


def inner_header(from_kid: str, to_kid: str, envelope_nonce: str) -> bytes:
    return J({"from_kid": from_kid, "to_kid": to_kid, "envelope_nonce": envelope_nonce})


def aics1_plaintext(header_bytes: bytes, content: bytes) -> bytes:
    """``uint32be(len(header_bytes)) || header_bytes || content_bytes`` (§8.1)."""
    return struct.pack(">I", len(header_bytes)) + header_bytes + content


def jcs_lf_plaintext(header_bytes: bytes, content: bytes) -> bytes:
    """``JCS(header) || 0x0A || body``: NOT the §8.1 framing (a negative vector; aics-identity sealed this before F05
    was fixed)."""
    return header_bytes + b"\n" + content


def split_aics1_plaintext(plaintext: bytes) -> tuple[bytes, bytes]:
    if len(plaintext) < 4:
        raise ValueError("missing inner header length")
    n = struct.unpack(">I", plaintext[:4])[0]
    if n > 4096 or len(plaintext) < 4 + n:
        raise ValueError("inner header length out of range")
    return plaintext[4:4 + n], plaintext[4 + n:]


def deterministic_seal(plaintext: bytes, recipient_public: bytes, ephemeral_secret: bytes) -> bytes:
    """crypto_box_seal with a FIXED ephemeral key (Appendix A.5 technique).  Test vectors only."""
    from nacl.bindings import crypto_box, crypto_scalarmult_base

    eph_pk = crypto_scalarmult_base(ephemeral_secret)
    nonce = hashlib.blake2b(eph_pk + recipient_public, digest_size=24).digest()
    return eph_pk + crypto_box(plaintext, nonce, recipient_public, ephemeral_secret)


def x25519_public(secret: bytes) -> bytes:
    from nacl.bindings import crypto_scalarmult_base

    return crypto_scalarmult_base(secret)


# ---------------------------------------------------------------------------
# §10.1 receipts
# ---------------------------------------------------------------------------


def receipt_text(origin: str, entry_hash_hex: str, submitted_at: int) -> str:
    return J({"origin": origin, "entry_hash": entry_hash_hex, "submitted_at": submitted_at,
              "mmd_seconds": 60}).decode("utf-8") + "\n"


def receipt_note(origin: str, entry_bytes: bytes, ts: int, log_key: Ed25519PrivateKey) -> bytes:
    """The §10.1 inclusion promise: a log-key-signed note over ``J({...}) || LF``.

    ``entry_hash`` is ``hexH(0x00 || entry_bytes)``, the leaf hash, not the plain JSON digest."""
    text = receipt_text(origin, leaf_hash(entry_bytes).hex(), ts)
    return signed_note(text, [log_signature_line(origin, log_key, text)])


def verify_receipt(note: bytes, log_vkey: str, entry_bytes: bytes) -> dict[str, Any]:
    """§14.4 steps 1-2: the note is signed by the pinned log key (exactly one recognized line, a valid signature;
    lines of unknown keys ignored), its text is exactly ``J({origin,entry_hash,submitted_at,mmd_seconds}) || LF``
    with the log's origin and ``mmd_seconds`` 60, ``entry_hash`` is the leaf hash of ``entry_bytes`` and
    ``submitted_at`` the entry's ``ts``.  Returns the receipt object; raises ValueError."""
    name, key_id, sig_type, public = parse_vkey(log_vkey)
    if sig_type != 0x01:
        raise ValueError("the log key is not an Ed25519 note key")
    text, lines = parse_signed_note(note)
    mine = [blob for n, blob in lines if (n, blob[:4]) == (name, key_id)]
    if len(mine) != 1 or len(mine[0]) != 68 or not _ed25519_ok(public, mine[0][4:], text.encode("utf-8")):
        raise ValueError("the receipt is not signed by the pinned log key")
    if not text.endswith("\n"):
        raise ValueError("receipt text does not end with LF")
    r = strict_json(text[:-1])
    if not isinstance(r, Mapping) or set(r) != {"origin", "entry_hash", "submitted_at", "mmd_seconds"} \
            or J(r).decode("utf-8") + "\n" != text:
        raise ValueError("receipt text is not the exact canonical receipt")
    entry = strict_json(entry_bytes)
    if r["origin"] != name or r["mmd_seconds"] != 60:
        raise ValueError("receipt origin or mmd_seconds")
    if r["entry_hash"] != leaf_hash(entry_bytes).hex() or r["submitted_at"] != entry.get("ts"):
        raise ValueError("receipt does not commit to this entry (leaf hash, submitted_at = ts)")
    return dict(r)


# ---------------------------------------------------------------------------
# §11.3 text gate
# ---------------------------------------------------------------------------

VERB_FOR_TYPE = {"post": "post", "poll": "poll", "vote": "vote", "grant": "grant", "dm": "send",
                 "capsule": "store", "name.claim": "claim", "key.rotate": "rotate",
                 "key.revoke": "revoke", "x25519.rotate": "x25519.rotate"}


def line_message(session: str, line: str) -> bytes:
    """Signed bytes ``UTF8(session_id) || LF || UTF8(C)``, no final LF (§11.3; PROTOCOL-TEXT §2)."""
    if "\n" in session or "\n" in line:
        raise ValueError("session id and line never contain LF")
    return session.encode("utf-8") + b"\n" + line.encode("utf-8")


SSHSIG_MAGIC = b"SSHSIG"


def _ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def ssh_public_key_blob(public: bytes) -> bytes:
    return _ssh_string(b"ssh-ed25519") + _ssh_string(public)


def sshsig_signed_data(message: bytes, namespace: str = "aics", hash_algorithm: str = "sha512") -> bytes:
    """PROTOCOL.sshsig §3: the bytes the Ed25519 signature covers."""
    digest = hashlib.new(hash_algorithm, message).digest()
    return (SSHSIG_MAGIC + _ssh_string(namespace.encode()) + _ssh_string(b"") + _ssh_string(hash_algorithm.encode())
            + _ssh_string(digest))


def sshsig_blob(message: bytes, key: Ed25519PrivateKey, namespace: str = "aics") -> bytes:
    """PROTOCOL.sshsig §2: the complete binary SSHSIG blob (version 1, ssh-ed25519, sha512)."""
    sig = key.sign(sshsig_signed_data(message, namespace))
    return (SSHSIG_MAGIC + struct.pack(">I", 1) + _ssh_string(ssh_public_key_blob(raw_public(key)))
            + _ssh_string(namespace.encode()) + _ssh_string(b"") + _ssh_string(b"sha512")
            + _ssh_string(_ssh_string(b"ssh-ed25519") + _ssh_string(sig)))


def sshsig_armor(blob: bytes) -> str:
    """The armored form ssh-keygen writes (base64 wrapped at 70 columns)."""
    b = B64(blob)
    return "-----BEGIN SSH SIGNATURE-----\n" + "\n".join(b[i:i + 70] for i in range(0, len(b), 70)) + \
        "\n-----END SSH SIGNATURE-----\n"


def verify_sshsig_blob(blob: bytes, message: bytes, public: bytes, namespace: str = "aics") -> None:
    """§11.3 text-sshsig: version 1, ssh-ed25519, namespace aics, empty reserved, sha512, the claimed key."""
    def take(buf: bytes, pos: int) -> tuple[bytes, int]:
        n = struct.unpack(">I", buf[pos:pos + 4])[0]
        if pos + 4 + n > len(buf):
            raise ValueError("truncated SSHSIG")
        return buf[pos + 4:pos + 4 + n], pos + 4 + n
    if blob[:6] != SSHSIG_MAGIC or struct.unpack(">I", blob[6:10])[0] != 1:
        raise ValueError("not an SSHSIG version 1 blob")
    pos = 10
    pk, pos = take(blob, pos)
    ns, pos = take(blob, pos)
    reserved, pos = take(blob, pos)
    alg, pos = take(blob, pos)
    sig, pos = take(blob, pos)
    if pos != len(blob):
        raise ValueError("trailing bytes")
    if pk != ssh_public_key_blob(public) or ns != namespace.encode() or reserved or alg != b"sha512":
        raise ValueError("SSHSIG parameters are not the AICS profile")
    kt, q = take(sig, 0)
    raw, q = take(sig, q)
    if kt != b"ssh-ed25519" or len(raw) != 64 or q != len(sig):
        raise ValueError("not an ssh-ed25519 signature")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(raw, sshsig_signed_data(message, namespace))
    except InvalidSignature:
        raise ValueError("SSHSIG signature does not verify") from None


def text_command(unsigned: Mapping[str, Any]) -> str:
    """Canonical command ``C``: ``verb SP U64(J(U))``, or the short claim form (§11.3)."""
    typ = unsigned["protected"]["type"]
    verb = VERB_FOR_TYPE[typ]
    if typ == "key.rotate" and unsigned["payload"].get("mode") == "upgrade":
        verb = "claim-upgrade"
    if verb in ("claim", "claim-upgrade"):
        return f"{verb} {unsigned['payload']['name_norm']} {hexH(J(unsigned))}"
    return f"{verb} {U64(J(unsigned))}"


# ---------------------------------------------------------------------------
# §12.1 HTTP binding: RFC 9421 + RFC 9530 profile
# ---------------------------------------------------------------------------

AICS_COMPONENTS = ("@method", "@authority", "@path", "content-digest")


def content_digest(body: bytes) -> str:
    return f"sha-256=:{B64(H(body))}:"


def _sf_string(value: str) -> str:
    if any(ord(c) < 0x20 or ord(c) > 0x7E for c in value):
        raise ValueError("sf-string must be printable ASCII")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def signature_params(*, created: int, expires: int, nonce: str, keyid: str, tag: str = "aics",
                     alg: str = "ed25519", components: Sequence[str] = AICS_COMPONENTS) -> str:
    inner = "(" + " ".join(_sf_string(c) for c in components) + ")"
    return (f"{inner};created={created};expires={expires};nonce={_sf_string(nonce)};"
            f"alg={_sf_string(alg)};keyid={_sf_string(keyid)};tag={_sf_string(tag)}")


def _authority(url: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    default = {"https": 443, "http": 80}.get(parts.scheme)
    return host if parts.port in (None, default) else f"{host}:{parts.port}"


def _path(url: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(url).path or "/"


def signature_base(method: str, url: str, headers: Mapping[str, str], params: str,
                   components: Sequence[str]) -> bytes:
    """RFC 9421 §2.5 signature base for derived components and single-valued header fields."""
    lower = {k.lower(): v for k, v in headers.items()}
    lines = []
    for c in components:
        if c == "@method":
            value = method.upper()
        elif c == "@authority":
            value = _authority(url)
        elif c == "@path":
            value = _path(url)
        elif c.startswith("@"):
            raise ValueError(f"component {c} is outside the AICS profile")
        else:
            value = lower[c].strip()
        lines.append(f'"{c}": {value}')
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines).encode("utf-8")


def _parse_inner_list(text: str) -> tuple[list[str], dict[str, Any], str]:
    """Parse one member value ``(...);k=v;...`` of the profile (strings and integers only)."""
    if not text.startswith("("):
        raise ValueError("expected an inner list")
    end = text.index(")")
    items = text[1:end].split(" ") if text[1:end] else []
    components = []
    for item in items:
        if not (item.startswith('"') and item.endswith('"')):
            raise ValueError("component identifiers are sf-strings")
        components.append(item[1:-1])
    params: dict[str, Any] = {}
    rest = text[end + 1:]
    while rest:
        if not rest.startswith(";"):
            raise ValueError("malformed parameters")
        rest = rest[1:]
        key, _, rest = rest.partition("=")
        if rest.startswith('"'):
            close = 1
            while rest[close] != '"' or rest[close - 1] == "\\":
                close += 1
            params[key] = rest[1:close].replace('\\"', '"').replace("\\\\", "\\")
            rest = rest[close + 1:]
        else:
            num, sep, tail = rest.partition(";")
            params[key] = int(num)
            rest = (sep + tail) if sep else ""
    return components, params, text


def verify_request(method: str, url: str, headers: Mapping[str, str], body: bytes,
                   public: bytes, *, label: str = "aics") -> dict[str, Any]:
    """Independent verifier for the §12.1 profile (one label; raises on any failure).

    Returns the parsed signature parameters.  Checks Content-Digest over the
    actual body bytes, the exact component list and order, the required
    parameters and the Ed25519 signature over the RFC 9421 signature base.
    """
    lower = {k.lower(): v for k, v in headers.items()}
    if lower.get("content-digest") != content_digest(body):
        raise ValueError("Content-Digest does not match the body")
    sig_input = lower["signature-input"]
    sig_header = lower["signature"]
    prefix = label + "="
    if not sig_input.startswith(prefix) or not sig_header.startswith(prefix):
        raise ValueError(f"signature label is not {label!r}")
    member = sig_input[len(prefix):]
    components, params, serialized = _parse_inner_list(member)
    if tuple(components) != AICS_COMPONENTS:
        raise ValueError(f"covered components {components} are not exactly {AICS_COMPONENTS}")
    for required in ("created", "expires", "nonce", "keyid", "tag", "alg"):
        if required not in params:
            raise ValueError(f"missing signature parameter {required}")
    if params["tag"] != "aics" or params["alg"] != "ed25519":
        raise ValueError("tag/alg are not the AICS profile values")
    value = sig_header[len(prefix):]
    if not (value.startswith(":") and value.endswith(":")):
        raise ValueError("Signature is not an sf-binary")
    signature = dB64(value[1:-1])
    base = signature_base(method, url, headers, serialized, components)
    Ed25519PublicKey.from_public_bytes(public).verify(signature, base)
    return {"components": components, **params, "signature_base": base.decode("utf-8")}


# ---------------------------------------------------------------------------
# §6.4 trust bundle
# ---------------------------------------------------------------------------

TXT_PREFIX = "aics1="


def trust_bundle(*, origin: str, log_vkey: str, policy_kid: str, owner_kid: str,
                 bootstrap_card_hash: str) -> dict[str, Any]:
    return {"v": 1, "origin": origin, "log_vkey": log_vkey, "policy_kid": policy_kid,
            "owner_kid": owner_kid, "bootstrap_card_hash": bootstrap_card_hash}


def txt_record(bundle_bytes: bytes) -> str:
    return TXT_PREFIX + U64(bundle_bytes)


def txt_character_strings(txt: str, size: int = 255) -> list[bytes]:
    raw = txt.encode("ascii")
    return [raw[i:i + size] for i in range(0, len(raw), size)]


def dns_txt_response(qname: str, qid: int, records: Sequence[Sequence[bytes]]) -> bytes:
    """A DNS response message (RFC 1035) answering TXT ``qname`` with the given character-strings."""
    def name(n: str) -> bytes:
        out = b""
        for label in n.rstrip(".").split("."):
            out += bytes([len(label)]) + label.encode("ascii")
        return out + b"\0"
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, len(records), 0, 0)
    question = name(qname) + struct.pack(">HH", 16, 1)
    answers = b""
    for strings in records:
        rdata = b"".join(bytes([len(s)]) + s for s in strings)
        answers += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, len(rdata)) + rdata
    return header + question + answers


def readme_block(bundle_bytes: bytes) -> str:
    """The labelled README form: the TXT value and the digest of the bundle bytes."""
    return (f"AICS trust bundle (AICS-1 §6.4):\n{txt_record(bundle_bytes)}\n"
            f"sha256: {hexH(bundle_bytes)}\n")


TRUST_MEMBERS = ("v", "origin", "log_vkey", "policy_kid", "owner_kid", "bootstrap_card_hash")


def validate_trust_bundle(raw: bytes) -> dict[str, Any]:
    """§6.4 + §2 + §3.1: exact JCS bytes of exactly the six members, three distinct Ed25519 service keys.

    Raises ValueError; returns the parsed bundle."""
    obj = strict_json(raw)
    if not isinstance(obj, dict) or set(obj) != set(TRUST_MEMBERS):
        raise ValueError("a trust bundle has exactly " + ", ".join(TRUST_MEMBERS))
    if J(obj) != raw:
        raise ValueError("bundle bytes are not J(bundle)")
    if type(obj["v"]) is not int or obj["v"] != 1:
        raise ValueError("v must be 1")
    origin = obj["origin"]
    if not isinstance(origin, str) or not origin or not origin.isascii() or "://" in origin \
            or origin.endswith("/") or any(c.isspace() for c in origin):
        raise ValueError("origin is an ASCII identifier without scheme or trailing slash")
    name, _, typ, log_pub = parse_vkey(obj["log_vkey"])
    if typ != 0x01:
        raise ValueError("log_vkey is not an Ed25519 note key")
    pubs = [log_pub, kid_public(obj["policy_kid"]), kid_public(obj["owner_kid"])]
    if len(set(pubs)) != 3:
        raise ValueError("log, policy and owner keys must be distinct (§3.1)")
    if not isinstance(obj["bootstrap_card_hash"], str) or not re.fullmatch(r"[0-9a-f]{64}", obj["bootstrap_card_hash"]):
        raise ValueError("bootstrap_card_hash is a lowercase 64-hex hash")
    return obj


# ---------------------------------------------------------------------------
# §13.2 assurance card signing (JWS over JCS)
# ---------------------------------------------------------------------------


def sign_card(card: Mapping[str, Any], key: Ed25519PrivateKey, policy_kid: str) -> dict[str, Any]:
    unsigned = {k: v for k, v in card.items() if k != "signatures"}
    protected = U64(J({"alg": "EdDSA", "kid": policy_kid, "typ": "JOSE"}))
    signing_input = (protected + "." + U64(J(unsigned))).encode("ascii")
    return {**unsigned, "signatures": [{"protected": protected, "signature": U64(key.sign(signing_input))}]}


def card_hash(card: Mapping[str, Any]) -> str:
    return hexH(J(card))


def strict_json(raw: bytes | str) -> Any:
    """JSON with duplicate members and NaN/Infinity rejected (§2)."""
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise ValueError(f"duplicate member {k!r}")
            out[k] = v
        return out

    def constant(name):
        raise ValueError(f"{name} is not JSON")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


# ---------------------------------------------------------------------------
# §5.1-5.3 entries: the closed schemas (§20.3 under the SUP-1 profile)
# ---------------------------------------------------------------------------

#: §5.3: the base registry's exact payload object ``Q`` of every type (member -> type), ``?`` nullable.  ``kid`` is an
#: Ed25519 did:key; ``actor`` a kid or an unverified identifier; ``sender`` a kid or "*".  ``report`` and
#: ``sup.credit`` are chosen by ``kind`` / ``source`` (REPORT_SCHEMAS, CREDIT_SCHEMAS).
ENTRY_SCHEMAS: dict[str, dict[str, str]] = {
    "name.claim": {"name_norm": "name", "prev_event_index": "null", "ed25519": "key32?", "x25519": "key32?",
                   "tier": "tier", "recovery_kid": "kid?", "recovery_pop": "proof?", "initial_grant": "grant_spec?"},
    "key.rotate": {"mode": "mode", "name_norm": "name", "prev_event_index": "uint", "new_ed25519": "key32",
                   "new_x25519": "key32?", "new_tier": "key_tier", "sig_old": "proof?", "sig_new": "proof"},
    "key.revoke": {"name_norm": "name", "prev_event_index": "uint", "reason_code": "revocation"},
    "x25519.rotate": {"name_norm": "name", "prev_event_index": "uint", "new_x25519": "key32"},
    "grant": {"owner_kid": "kid", "sender_kid": "sender", "max": "uint", "expires": "uint",
              "prev_grant_index": "uint?"},
    "post": {"channel_sha256": "hash", "parent_index": "uint?", "body_hash": "hash", "size": "uint",
             "title_sha256": "hash?"},
    "poll": {"channel_sha256": "hash", "body_hash": "hash", "size": "uint", "title_sha256": "hash",
             "options_sha256": "options", "closes": "uint", "min_key_age_seconds": "uint", "pow_bits": "uint"},
    "vote": {"poll_index": "uint", "option": "uint", "pow_nonce": "hash?", "reason_sha256": "hash?",
             "body_hash": "hash?", "size": "uint"},
    "dm": {"to_kid": "kid", "to_key_leaf_index": "uint", "encryption": "scheme", "eph_pk": "key32?",
           "ct_hash": "hash", "size": "uint", "seq": "uint", "prev": "hash?", "grant_index": "uint"},
    "capsule": {"owner_kid": "kid", "to_key_leaf_index": "uint", "key_hash": "hash", "encryption": "scheme",
                "eph_pk": "key32?", "ct_hash": "hash", "size": "uint", "expires": "uint",
                "prev_capsule_index": "uint?"},
    "tombstone": {"target_index": "uint", "reason_code": "tombstone", "evidence_hash": "hash?",
                  "receipt_hash": "hash?"},
    "refusal": {"envelope_hash": "hash", "request_hash": "hash?", "attempt_kid": "actor?",
                "attempt_nonce": "nonce?", "attempt_expires": "uint?", "reason_code": "refusal",
                "conflict_index": "uint?", "receipt_hash": "hash?"},
    "suspension": {"target_kid": "actor", "reason_code": "suspension", "until": "uint?", "evidence_hash": "hash?"},
    "freeze": {"state": "freeze_state", "reason_code": "freeze", "report_hash": "hash",
               "prev_freeze_index": "uint?"},
    "policy": {"kind": "policy_kind", "document_hash": "hash", "size": "uint", "prev_policy_index": "uint?",
               "effective_after": "uint", "not_before": "uint", "log_kid": "kid", "policy_kid": "kid",
               "owner_kid": "kid", "log_sig": "sig64?"},
    "release": {"artifact_hash": "hash", "source_hash": "hash", "provenance_hash": "hash", "version_hash": "hash",
                "size": "uint"},
}
#: §5.3 ``report``: four disjoint variants by ``kind``.
REPORT_SCHEMAS: dict[str, dict[str, str]] = {
    "notice": {"kind": "kind", "notice_hash": "hash", "target_index": "uint?", "outcome_code": "notice_outcome",
               "evidence_hash": "hash?"},
    "daily": {"kind": "kind", "day": "uint", "counts": "counts"},
    "audit": {"kind": "kind", "report_hash": "hash", "size": "uint", "outcome_code": "audit_outcome"},
    "owner_action": {"kind": "kind", "action": "owner_action", "request_hash": "hash", "result_hash": "hash?",
                     "asset_hash": "hash", "amount": "uint", "quote_index": "uint?"},
}
#: §20.3: the types the contributions and owner-service profile adds; ``sup.credit`` by ``source``.
SUP_SCHEMAS: dict[str, dict[str, str]] = {
    "sup.task": {"body_hash": "hash", "size": "uint", "asset_hash": "hash", "reward": "uint", "max_awards": "uint",
                 "closes": "uint"},
    "sup.spend": {"purpose": "purpose", "ref_index": "uint?", "asset_hash": "hash", "amount": "uint",
                  "bytes": "uint"},
}
CREDIT_SCHEMAS: dict[str, dict[str, str]] = {
    "task": {"source": "source", "account_kid": "kid", "task_index": "uint", "submission_index": "uint",
             "asset_hash": "hash", "amount": "uint"},
    "contribution": {"source": "source", "account_kid": "kid", "contribution_hash": "hash", "asset_hash": "hash",
                     "amount": "uint"},
}
#: §17.1: the base registry's 17 types; with SUP-1 the 20 types (§20.3).
BASE_TYPES = tuple(ENTRY_SCHEMAS) + ("report",)
SUP_TYPES = ("sup.task", "sup.credit", "sup.spend")
#: §20.8: the twelve refusal codes the SUP-1 profile adds.
REFUSAL_SUP = ("insufficient_balance", "not_requester", "owner_action_closed", "stale_quote", "task_closed",
               "already_awarded", "already_credited", "payment_not_verified", "intent_expired", "amount_mismatch",
               "bad_reference", "not_offered")
ENUM_VALUES: dict[str, tuple[str, ...]] = {
    "tier": ("verified", "third-party-generated", "unverified"), "key_tier": ("verified", "third-party-generated"),
    "mode": ("rotate", "upgrade"), "scheme": ("x25519-xsalsa20-poly1305", "age-v1"),
    "revocation": ("retired", "compromised"), "tombstone": ("order", "erasure", "secret_format", "illegal_on_notice"),
    "suspension": ("order", "flood"), "freeze": ("maintenance", "incident", "order", "resource_exhaustion", "resume"),
    "freeze_state": ("frozen", "open"), "policy_kind": ("charter", "card", "change"),
    "notice_outcome": ("acted", "declined", "private_unassessable", "invalid_notice", "duplicate"),
    "audit_outcome": ("published", "resolved"), "owner_action": ("quote", "complete"),
    "purpose": ("owner_action", "hosting", "storage"), "source": ("task", "contribution"),
    "proof_scheme": ("ed25519", "sshsig"),
}
NAME_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?")
HEX64 = re.compile(r"[0-9a-f]{64}")
ENVELOPE_MEMBERS = ("v", "protected", "payload", "auth", "sig")
PROTECTED_MEMBERS = ("alg", "origin", "type", "kid", "created", "expires", "nonce", "seq", "prev", "seen")
ENTRY_MEMBERS = ("v", "origin", "type", "actor_kid", "ts", "payload")
#: §20.2: the members of the SUP asset descriptor, ``asset_hash = hexH(J(descriptor))``.
SUP_BUYS = ("owner_action", "hosting", "storage")


def sup_asset_hash(origin: str) -> str:
    """§20.2: ``hexH`` of ``J({asset:"SUP",buys:[...],decimals:0,origin,refundable:false,transferable:false})``."""
    return hexH(J({"asset": "SUP", "buys": list(SUP_BUYS), "decimals": 0, "origin": origin, "refundable": False,
                   "transferable": False}))


def refusal_registry(profiles: Sequence[str] = (), secret_ids: Sequence[str] = ()) -> set[str]:
    """§17.2 (base, charter-compatible spellings included), the §20.8 codes under SUP-1, ``secret_format:<id>``."""
    codes = {*REFUSAL_DETAILED, *REFUSAL_CHARTER, *(f"secret_format:{i}" for i in secret_ids)}
    if "SUP-1" in profiles:
        codes |= set(REFUSAL_SUP)
    return codes


def _is_uint(v: Any) -> bool:
    return type(v) is int and 0 <= v <= UINT_MAX


def _is_u64_of(v: Any, n: int | None) -> bool:
    try:
        raw = dU64(v)
    except ValueError:
        return False
    return n is None or len(raw) == n


def is_kid(v: Any) -> bool:
    """§3.1: a bare Ed25519 did:key (multicodec 0xed 0x01, 32 key bytes, canonical base58btc)."""
    if not isinstance(v, str):
        return False
    try:
        public = kid_public(v)
    except (ValueError, IndexError):
        return False
    return kid(public) == v


def is_unverified_id(v: Any) -> bool:
    """§3.3: ``unverified:`` + U64 of 16 random bytes."""
    return isinstance(v, str) and v.startswith("unverified:") and _is_u64_of(v[len("unverified:"):], 16)


def _value_problem(v: Any, t: str, path: str, *, profiles: Sequence[str], secret_ids: Sequence[str]) -> str | None:
    if t.endswith("?"):
        if v is None:
            return None
        t = t[:-1]
    ok: bool
    if t == "null":
        ok = v is None
    elif t == "uint":
        ok = _is_uint(v)
    elif t == "hash":
        ok = isinstance(v, str) and HEX64.fullmatch(v) is not None
    elif t == "name":
        ok = isinstance(v, str) and NAME_PATTERN.fullmatch(v) is not None
    elif t == "key32":
        ok = _is_u64_of(v, 32)
    elif t == "sig64":
        ok = _is_u64_of(v, 64)
    elif t == "nonce":
        ok = _is_u64_of(v, 16)
    elif t == "kid":
        ok = is_kid(v)
    elif t == "actor":
        ok = is_kid(v) or is_unverified_id(v)
    elif t == "sender":
        ok = v == "*" or is_kid(v)
    elif t == "kind":
        ok = isinstance(v, str)  # the variant was chosen by it
    elif t == "proof":
        if not isinstance(v, Mapping) or set(v) != {"scheme", "signature"} or v["scheme"] not in ("ed25519", "sshsig"):
            return f"{path}: not a §7.1 proof {{scheme, signature}}"
        ok = _is_u64_of(v["signature"], 64 if v["scheme"] == "ed25519" else None)
    elif t == "grant_spec":
        if not isinstance(v, Mapping) or set(v) != {"sender_kid", "max", "expires"}:
            return f"{path}: not a §5.3 grant_spec {{sender_kid, max, expires}}"
        ok = (v["sender_kid"] == "*" or is_kid(v["sender_kid"])) and _is_uint(v["max"]) and _is_uint(v["expires"])
    elif t == "options":
        ok = isinstance(v, list) and 2 <= len(v) <= 64 and len(set(v)) == len(v) and \
            all(isinstance(h, str) and HEX64.fullmatch(h) for h in v)
    elif t == "refusal":
        ok = isinstance(v, str) and v in refusal_registry(profiles, secret_ids) or \
            isinstance(v, str) and re.fullmatch(r"secret_format:[a-z0-9_]{1,32}", v) is not None and not secret_ids
    elif t == "counts":
        if not isinstance(v, list):
            return f"{path}: counts is an array"
        for n, row in enumerate(v):
            if not isinstance(row, Mapping) or set(row) != {"reason_code", "count"} or not _is_uint(row["count"]):
                return f"{path}[{n}]: a row is exactly {{reason_code, count:uint}}"
            problem = _value_problem(row["reason_code"], "refusal", f"{path}[{n}].reason_code", profiles=profiles,
                                     secret_ids=secret_ids)
            if problem:
                return problem
        codes = [row["reason_code"] for row in v]
        ok = codes == sorted(set(codes), key=lambda c: c.encode("ascii"))
        if not ok:
            return f"{path}: rows are unique and sorted by the code's ASCII bytes"
    elif t in ENUM_VALUES:
        ok = isinstance(v, str) and v in ENUM_VALUES[t]
    else:
        raise AssertionError(f"unknown schema type {t}")
    return None if ok else f"{path}: {str(v)[:80]!r} is not a {t}"


def payload_schema(typ: str, q: Any, profiles: Sequence[str] = ()) -> dict[str, str] | None:
    """The exact §5.3 (or §20.3) member table for ``Q`` of ``typ``, or None for a type the profiles do not have."""
    if typ == "report":
        return REPORT_SCHEMAS.get(q.get("kind")) if isinstance(q, Mapping) else None
    if typ in ENTRY_SCHEMAS:
        schema = dict(ENTRY_SCHEMAS[typ])
        if typ == "key.rotate" and isinstance(q, Mapping) and q.get("mode") == "upgrade":
            schema.update(sig_old="null", secret_check="sig64")
        return schema
    if "SUP-1" in profiles and typ in SUP_TYPES:
        if typ == "sup.credit":
            return CREDIT_SCHEMAS.get(q.get("source")) if isinstance(q, Mapping) else None
        return SUP_SCHEMAS[typ]
    return None


def payload_problems(typ: str, q: Any, ts: int | None = None, *, profiles: Sequence[str] = (),
                     secret_ids: Sequence[str] = ()) -> list[str]:
    """§5.3/§20.3 for one ``Q``: exactly the listed members, each of its type, and the stated local constraints."""
    schema = payload_schema(typ, q, profiles)
    if schema is None:
        return [f"{typ}: no closed schema (an unregistered type, kind or source, or a profile not activated)"]
    if not isinstance(q, Mapping):
        return [f"{typ}: Q is not an object"]
    problems = []
    if set(q) != set(schema):
        problems.append(f"{typ}: members {sorted(q)} are not exactly {sorted(schema)}")
    for k, t in schema.items():
        if k in q:
            p = _value_problem(q[k], t, f"{typ}.{k}", profiles=profiles, secret_ids=secret_ids)
            if p:
                problems.append(p)
    if problems:
        return problems
    # the constraints §5.3 and §20.3 state for the entry alone
    if typ == "name.claim":
        keyed = q["tier"] != "unverified"
        if keyed and (q["ed25519"] is None or q["x25519"] is None):
            problems.append("name.claim: a key-tier claim has both keys")
        if not keyed and any(q[k] is not None for k in ("ed25519", "x25519", "recovery_kid", "recovery_pop",
                                                          "initial_grant")):
            problems.append("name.claim: an unverified claim has null keys, recovery members and initial grant")
        if (q["recovery_kid"] is None) != (q["recovery_pop"] is None):
            problems.append("name.claim: both recovery members or neither")
    elif typ == "key.rotate" and q["mode"] == "upgrade" and q["new_x25519"] is None:
        problems.append("key.rotate: an upgrade carries new_x25519")
    elif typ == "poll":
        if q["pow_bits"] > 24:
            problems.append("poll: pow_bits 0-24")
        if ts is not None and not q["closes"] > ts:
            problems.append("poll: closes > ts")
    elif typ == "vote" and q["body_hash"] is None and (q["reason_sha256"] is not None or q["size"] != 0):
        problems.append("vote: no body means both nullable hashes null and size zero")
    elif typ == "capsule" and ts is not None and q["expires"] < ts + 7776000:
        problems.append("capsule: expires >= ts + 7776000 (90 days)")
    elif typ == "report" and q["kind"] == "owner_action" and q["action"] == "quote" and \
            (q["result_hash"] is not None or q["quote_index"] is not None):
        problems.append("report/owner_action: a quote has null result_hash and quote_index")
    elif typ == "sup.task" and not (q["reward"] >= 1 and 1 <= q["max_awards"] <= 1000 and
                                    (ts is None or ts < q["closes"] <= ts + 31622400)):
        problems.append("sup.task: reward >= 1, 1 <= max_awards <= 1000, ts < closes <= ts + 31622400")
    elif typ == "sup.spend" and q["amount"] < 1:
        problems.append("sup.spend: amount >= 1")
    return problems


def envelope_problems(env: Any, *, origin: str) -> list[str]:
    """§4.1-4.2 structure of an envelope: exactly the members, the protected header, ``auth`` and ``sig`` forms."""
    if not isinstance(env, Mapping) or set(env) != set(ENVELOPE_MEMBERS):
        return ["envelope: members are not exactly v, protected, payload, auth, sig"]
    p, auth, problems = env["protected"], env["auth"], []
    if env["v"] != 1 or type(env["v"]) is not int:
        problems.append("envelope.v must be 1")
    if not isinstance(p, Mapping) or set(p) != set(PROTECTED_MEMBERS):
        return problems + ["protected: members are not exactly " + ", ".join(PROTECTED_MEMBERS)]
    if p["origin"] != origin:
        problems.append("protected.origin is not the log origin")
    scheme = auth.get("scheme") if isinstance(auth, Mapping) else None
    if scheme == "ed25519-jcs":
        ok = auth == {"scheme": "ed25519-jcs"} and _is_u64_of(env["sig"], 64)
    elif scheme == "text-ed25519":
        ok = set(auth) == {"scheme", "session"} and _is_u64_of(auth["session"], 16) and _is_u64_of(env["sig"], 64)
    elif scheme == "text-sshsig":
        ok = set(auth) == {"scheme", "session"} and _is_u64_of(auth["session"], 16) and _is_u64_of(env["sig"], None)
    elif scheme == "shared-secret":
        ok = auth == {"scheme": "shared-secret"} and env["sig"] is None
    else:
        ok = False
    if not ok:
        problems.append(f"auth/sig: {str(auth)[:60]} with this sig is not a §4.1/§11.3 form")
    if p["alg"] != ("none" if scheme == "shared-secret" else "EdDSA"):
        problems.append("protected.alg")
    if not (is_unverified_id(p["kid"]) if scheme == "shared-secret" else is_kid(p["kid"])):
        problems.append("protected.kid is not a did:key (or, for shared-secret, an unverified id)")
    for k in ("created", "expires", "seq"):
        if not _is_uint(p[k]):
            problems.append(f"protected.{k} is not a uint")
    if not _is_u64_of(p["nonce"], 16):
        problems.append("protected.nonce is not U64 of 16 bytes")
    if _is_uint(p["seq"]) and (p["prev"] is None) != (p["seq"] == 0):
        problems.append("protected.prev is null exactly at seq 0")
    if p["prev"] is not None and not (isinstance(p["prev"], str) and HEX64.fullmatch(p["prev"])):
        problems.append("protected.prev is not a hash")
    seen = p["seen"]
    if seen is not None and not (isinstance(seen, Mapping) and set(seen) == {"checkpoint_note_hash", "size"}
                                 and isinstance(seen["checkpoint_note_hash"], str)
                                 and HEX64.fullmatch(seen["checkpoint_note_hash"]) and _is_uint(seen["size"])):
        problems.append("protected.seen is neither null nor {checkpoint_note_hash, size}")
    if _is_uint(p["created"]) and _is_uint(p["expires"]) and not p["created"] < p["expires"] <= p["created"] + 300:
        problems.append("created < expires <= created + 300")
    return problems


def envelope_signature_problem(env: Mapping[str, Any]) -> str | None:
    """The envelope's own signature by its kid (§4.1 native digest, §11.3 text schemes); None when it verifies.
    A shared-secret envelope has no agent signature (its entry's policy attestation is checked elsewhere)."""
    scheme = env["auth"]["scheme"]
    if scheme == "shared-secret":
        return None
    public = kid_public(env["protected"]["kid"])
    sig = dU64(env["sig"])
    if scheme == "ed25519-jcs":
        ok = _ed25519_ok(public, sig, signing_digest(env["protected"], env["payload"]))
    else:
        unsigned = {k: v for k, v in env.items() if k != "sig"}
        message = line_message(env["auth"]["session"], text_command(unsigned))
        if scheme == "text-ed25519":
            ok = _ed25519_ok(public, sig, message)
        else:
            try:
                verify_sshsig_blob(sig, message, public)
                ok = True
            except ValueError:
                ok = False
    return None if ok else f"{scheme} signature does not verify with {env['protected']['kid'][:24]}..."


def entry_problems(entry: Any, *, origin: str, profiles: Sequence[str] = (), secret_ids: Sequence[str] = (),
                   policy_kid: str | None = None) -> list[str]:
    """§5.1-5.3 for one entry, from the text alone: exactly ``{v:2, origin, type, actor_kid, ts, payload}``, the
    envelope of §4.1 with ``origin``/``type``/``kid`` bound to the entry, ``payload`` the envelope plus an exact copy
    of every member of ``Q`` (plus ``attestation`` for a shared-secret entry, signed by ``policy_kid``), ``Q`` the
    closed schema of its type, acceptance-time freshness at ``ts`` (§4.3), the envelope's own signature, and at most
    65535 bytes.  Empty: no problem found."""
    if not isinstance(entry, Mapping) or set(entry) != set(ENTRY_MEMBERS):
        return ["entry: members are not exactly v, origin, type, actor_kid, ts, payload"]
    problems = []
    if entry["v"] != 2 or type(entry["v"]) is not int:
        problems.append("entry.v must be 2")
    if entry["origin"] != origin:
        problems.append("entry.origin is not the log origin")
    if not _is_uint(entry["ts"]):
        problems.append("entry.ts is not a uint")
    payload = entry["payload"]
    env = payload.get("envelope") if isinstance(payload, Mapping) else None
    problems += envelope_problems(env, origin=origin)
    if problems:
        return problems
    p, q = env["protected"], env["payload"]
    if (p["type"], p["kid"]) != (entry["type"], entry["actor_kid"]):
        problems.append("protected type/kid differ from the entry's type/actor_kid")
    secret = env["auth"]["scheme"] == "shared-secret"
    extra = {"envelope", "attestation"} if secret else {"envelope"}
    if not isinstance(q, Mapping) or set(payload) != set(q) | extra or set(q) & extra:
        problems.append("payload is not the envelope plus a copy of Q" + (" plus attestation" if secret else ""))
    elif any(payload[k] != q[k] or J(payload[k]) != J(q[k]) for k in q):
        problems.append("payload copies of Q differ from the signed Q")
    if secret:
        att = payload.get("attestation")
        if not _is_u64_of(att, 64):
            problems.append("attestation is not sig64")
        elif policy_kid is not None:
            message = b"AICS-1 secret-attestation\n" + J({"actor_kid": entry["actor_kid"], "envelope_hash":
                                                         envelope_hash(env), "origin": entry["origin"],
                                                         "ts": entry["ts"], "type": entry["type"]})
            if not _ed25519_ok(kid_public(policy_kid), dU64(att), message):
                problems.append("attestation does not verify with the policy key")
    problems += payload_problems(entry["type"], q, entry["ts"] if _is_uint(entry["ts"]) else None,
                                 profiles=profiles, secret_ids=secret_ids)
    if _is_uint(entry["ts"]) and not accepted_at(p, entry["ts"]):
        problems.append("§4.3 acceptance-time freshness fails at entry.ts")
    if entry["type"] == "dm" and isinstance(q, Mapping) and (q.get("seq"), q.get("prev")) != (p["seq"], p["prev"]):
        problems.append("dm: the repeated seq/prev differ from the envelope's")
    if not problems:
        problem = envelope_signature_problem(env)
        if problem:
            problems.append(problem)
    if len(J(entry)) > 65535:
        problems.append("entry exceeds 65535 bytes")
    return problems


def vote_pow_digest(origin: str, poll_index: int, signer_kid: str, option: int, pow_nonce: str) -> bytes:
    """§5.3: ``H(UTF8("AICS-1 vote\n") || J({origin,poll_index,kid,option,pow_nonce}))``."""
    return H(b"AICS-1 vote\n" + J({"origin": origin, "poll_index": poll_index, "kid": signer_kid, "option": option,
                                    "pow_nonce": pow_nonce}))


def leading_zero_bits(digest: bytes) -> int:
    n = int.from_bytes(digest, "big")
    return len(digest) * 8 - n.bit_length()


def rotation_bytes(r: Mapping[str, Any]) -> bytes:
    """§7.2: ``UTF8("AICS-1 key.rotate\n") || J(R)``, ``R = {origin,name_norm,prev_event_index,new_ed25519,
    new_x25519,new_tier,mode}``."""
    return b"AICS-1 key.rotate\n" + J(r)


def recovery_declaration(origin: str, name_norm: str, ed25519: str, x25519: str, recovery_kid: str) -> bytes:
    """§7.1: the bytes ``recovery_pop`` signs."""
    return b"AICS-1 recovery-declaration\n" + J({"origin": origin, "name_norm": name_norm, "ed25519": ed25519,
                                                  "x25519": x25519, "recovery_kid": recovery_kid})


# ---------------------------------------------------------------------------
# §13.1 assurance card and the §17 registries
# ---------------------------------------------------------------------------

#: §17.2, base profile (no swarms codes), in table order.  ``secret_format:<id>``
#: instances are added per active card pattern.
REFUSAL_DETAILED = (
    "malformed", "bad_signature", "expired", "future", "replay", "unknown_key", "revoked", "tls_required",
    "unsupported_scheme", "unsupported_version",
    "sequence", "predecessor", "name_taken", "key_reuse", "key_fork", "stale_key", "stale_grant", "stale_capsule",
    "already_voted", "poll_closed", "poll_constraint",
    "too_large", "digest_mismatch", "rate_limit", "quota", "no_consent", "grant_exhausted", "suspended", "frozen",
    "tier_required",
)
#: §17.2 "charter-compatible spellings" (added to the registry in 0.2-draft, CHANGELOG).
REFUSAL_CHARTER = ("secret_format", "rate", "seq", "fork", "sig", "no_grant", "size", "format", "name",
                   "key_state", "poll_rule")
REASON_CODES = {
    "tombstone": ("order", "erasure", "secret_format", "illegal_on_notice"),
    "suspension": ("order", "flood"),
    "freeze": ("maintenance", "incident", "order", "resource_exhaustion", "resume"),
    "revocation": ("retired", "compromised"),
    "outcome": ("acted", "declined", "private_unassessable", "invalid_notice", "duplicate", "published", "resolved"),
}
#: §13.1 ``spec_versions`` of 0.2-draft.
SPEC_VERSIONS = {"tlog-tiles": "1.0.0", "tlog-checkpoint": "1.1.0", "signed-note": "1.1.0",
                 "tlog-cosignature": "1.1.0", "tlog-witness": "1.1.0", "a2a-card": "1.0.0"}
#: The 0.1-draft card the packages still implement (F13): every pin 1.0.0.
SPEC_VERSIONS_01 = {k: "1.0.0" for k in SPEC_VERSIONS}
ASSURANCE_IDS = tuple(f"G{i}" for i in range(1, 11)) + tuple(f"N{i}" for i in range(1, 6))


def card_template(*, origin: str, log_vkey: str, policy_kid: str, owner_kid: str, issued_at: int, expires: int,
                  policy_parent_index: int | None, tile_prefixes: Sequence[str], api_base: str,
                  witnesses: Sequence[Mapping[str, Any]], quorum: int, charter_hash: str,
                  max_checkpoint_age: int = 300, version: str = "0.2-draft",
                  spec_versions: Mapping[str, str] = SPEC_VERSIONS,
                  refusal: Sequence[str] | None = None,
                  secret_patterns: Sequence[Mapping[str, str]] = ()) -> dict[str, Any]:
    """An unsigned §13.1 card with every member present and in-bounds statuses.

    Refusal codes default to the complete §17.2 base registry (detailed codes,
    charter-compatible spellings and one ``secret_format:<id>`` per pattern).
    G5 and G7 stay ``promised``; the deployed witness disclosure of §13.3 is
    stated in G5's assumptions."""
    host = api_base.split("://", 1)[1].split("/", 1)[0]
    patterns = [dict(p) for p in secret_patterns]
    codes = list(REFUSAL_DETAILED if refusal is None else refusal)
    if refusal is None:
        codes += [f"secret_format:{p['id']}" for p in patterns] + list(REFUSAL_CHARTER)
    assurances = []
    for aid in ASSURANCE_IDS:
        status = "not-offered" if aid.startswith("N") else "promised"
        assumptions = ["interop test fixture; no deployment is described"]
        if aid == "G5":
            assumptions += ["founder-run witness in the log's trust domain; honest quorum intersection not argued",
                            "Ed25519 cosignature/v1 only: no ML-DSA-44 cosignatures (a SHOULD of "
                            "tlog-cosignature v1.1.0) and no sign-subtree API"]
        assurances.append({"id": aid, "status": status, "claim": f"{aid} interop fixture",
                           "assumptions": assumptions, "evidence": []})
    return {
        "spec": "AICS-1", "version": version, "origin": origin, "issued_at": issued_at, "expires": expires,
        "policy_parent_index": policy_parent_index, "log_vkey": log_vkey, "policy_kid": policy_kid,
        "owner_kid": owner_kid, "tile_prefixes": list(tile_prefixes), "api_base": api_base,
        "gate": {"tls_host": host, "tls_port": 7700, "plaintext_port": 7701, "https_url": api_base + "/t"},
        "proxy": [{"host": host, "mode": "dns-only", "tls_termination": "origin"}],
        "witness_policy": {"quorum": quorum, "witnesses": [dict(w) for w in witnesses]},
        "max_checkpoint_age": max_checkpoint_age, "mmd_seconds": 60, "policy_notice_seconds": 0,
        "limits": {"public_body_bytes": 32768, "ciphertext_bytes": 65536, "envelope_window_seconds": 300,
                   "future_skew_seconds": 30, "session_idle_seconds": 900,
                   "writes": {"count": 20, "interval_seconds": 60},
                   "registrations": {"count": 20, "interval_seconds": 60},
                   "preidentity": {"count": 1000, "interval_seconds": 60}, "flood_suspension_seconds": 3600},
        "retention": {"dm_seconds": 7776000, "capsule_max_seconds": 7776000, "ciphertext_budget_bytes": 1 << 30,
                      "eviction": "oldest-ts-index"},
        "schemes": ["x25519-xsalsa20-poly1305"], "tiers": ["verified", "third-party-generated", "unverified"],
        "reason_codes": {"refusal": codes, **{k: list(v) for k, v in REASON_CODES.items()}},
        "secret_patterns": patterns,
        "policies": {"charter_hash": charter_hash, "terms_hash": hexH(b"interop terms"),
                     "privacy_hash": hexH(b"interop privacy")},
        "assurances": assurances,
        "spec_versions": dict(spec_versions),
    }


#: §13.1: the card "has exactly" these members.
CARD_MEMBERS = ("spec", "version", "origin", "issued_at", "expires", "policy_parent_index", "log_vkey", "policy_kid",
                "owner_kid", "tile_prefixes", "api_base", "gate", "proxy", "witness_policy", "max_checkpoint_age",
                "mmd_seconds", "policy_notice_seconds", "limits", "retention", "schemes", "tiers", "reason_codes",
                "secret_patterns", "policies", "assurances", "spec_versions", "signatures")


def card_problems(card: Any) -> list[str]:
    """Part of §13.1, from the text: the members, ``spec``, ``version``, ``spec_versions``, the secret pattern ids
    and the reason registries (empty: no problem found; the remaining members are not checked here).

    The registries must equal §17.2's base profile; the refusal registry
    additionally carries exactly one ``secret_format:<id>`` per pattern in
    the card's own ``secret_patterns`` ("plus only those active
    secret_format:<id> instances"; "a closed expansion over that card's
    enumerated patterns")."""
    if not isinstance(card, Mapping):
        return ["$: not an object"]
    problems = []
    if set(card) != set(CARD_MEMBERS):
        problems.append("$: members are not exactly the §13.1 members")
    if card.get("spec") != "AICS-1":
        problems.append("$.spec: must be 'AICS-1'")
    if card.get("version") != "0.2-draft":
        problems.append("$.version: must be '0.2-draft'")
    if card.get("spec_versions") != SPEC_VERSIONS:
        problems.append("$.spec_versions: must be the 0.2-draft pins")
    ids: list[str] = []
    patterns = card.get("secret_patterns")
    if not isinstance(patterns, list):
        problems.append("$.secret_patterns: must be an array")
    else:
        for p in patterns:
            pid = p.get("id") if isinstance(p, Mapping) else None
            if not isinstance(pid, str) or not re.fullmatch(r"[a-z0-9_]{1,32}", pid):
                problems.append("$.secret_patterns: ids match [a-z0-9_]{1,32}")
            else:
                ids.append(pid)
        if len(set(ids)) != len(ids):
            problems.append("$.secret_patterns: ids must be unique")
    expected = {"refusal": {*REFUSAL_DETAILED, *REFUSAL_CHARTER, *(f"secret_format:{i}" for i in ids)},
                **{k: set(v) for k, v in REASON_CODES.items()}}
    rc = card.get("reason_codes")
    if not isinstance(rc, Mapping) or set(rc) != set(expected):
        problems.append("$.reason_codes: must have exactly the §17.2 registries")
    else:
        for name, want in expected.items():
            codes = rc[name]
            if not isinstance(codes, list) or not all(isinstance(c, str) for c in codes) \
                    or len(codes) != len(set(codes)) or set(codes) != want:
                problems.append(f"$.reason_codes.{name}: must equal the §17.2 registry")
    return problems


# ---------------------------------------------------------------------------
# §14.3 wire bundle and complete verification package
# ---------------------------------------------------------------------------

BUNDLE_MEMBERS = ("entry_bytes", "index", "inclusion_proof", "checkpoint_note", "envelope", "body_or_ct")
PACKAGE_MEMBERS = ("bundle", "trust_bundle", "policy_cards", "entry_prefix", "checkpoint_notes")


def wire_bundle(entry_bytes: bytes, index: int, proof: Sequence[bytes], note: bytes,
                envelope: Mapping[str, Any], body: bytes | None) -> dict[str, Any]:
    """``{entry_bytes:U64,index:uint,inclusion_proof:[B64],checkpoint_note:U64,envelope:E,body_or_ct:U64-or-null}``."""
    return {"entry_bytes": U64(entry_bytes), "index": index, "inclusion_proof": [B64(h) for h in proof],
            "checkpoint_note": U64(note), "envelope": dict(envelope), "body_or_ct": None if body is None else U64(body)}


def verification_package(bundle: Mapping[str, Any], trust: Mapping[str, Any], policy_cards: Sequence[bytes],
                         entry_prefix: Sequence[bytes], checkpoint_notes: Sequence[bytes]) -> dict[str, Any]:
    """``{bundle,trust_bundle,policy_cards:[U64],entry_prefix:[U64],checkpoint_notes:[U64]}`` (§14.3)."""
    return {"bundle": dict(bundle), "trust_bundle": dict(trust), "policy_cards": [U64(c) for c in policy_cards],
            "entry_prefix": [U64(e) for e in entry_prefix], "checkpoint_notes": [U64(n) for n in checkpoint_notes]}


def verify_wire_bundle(b: Mapping[str, Any], log_vkey: str, witness_vkeys: Sequence[str] = (),
                       quorum: int = 0) -> dict[str, Any]:
    """§14.3 step 1 and step 4 for a wire bundle, offline and historical.  Raises ValueError."""
    if not isinstance(b, Mapping) or set(b) != set(BUNDLE_MEMBERS):
        raise ValueError("a wire bundle has exactly " + ", ".join(BUNDLE_MEMBERS))
    raw = dU64(b["entry_bytes"])
    note = dU64(b["checkpoint_note"])
    v = verify_note(note, log_vkey, witness_vkeys, quorum)
    if not v.ok:
        raise ValueError(f"checkpoint: {v.reason}")
    proof = [dB64(h) for h in b["inclusion_proof"]]
    if not verify_inclusion(leaf_hash(raw), b["index"], v.size, proof, v.root):
        raise ValueError("inclusion proof does not verify")
    e = strict_json(raw)
    if J(e) != raw:
        raise ValueError("entry bytes are not JCS")
    if e.get("v") != 2 or e["payload"].get("envelope") != b["envelope"]:
        raise ValueError("bundle envelope differs from the embedded envelope")
    if b["body_or_ct"] is not None:
        body = dU64(b["body_or_ct"])
        q = e["payload"]
        digest = q.get("body_hash", q.get("ct_hash", q.get("document_hash")))
        if hexH(body) != digest or len(body) != q["size"]:
            raise ValueError("body commitment")
    return {"index": b["index"], "size": v.size, "root": v.root, "entry": e}


# ---------------------------------------------------------------------------
# §14.6 gossip-check
# ---------------------------------------------------------------------------


def classify_gossip(note_a: bytes, note_b: bytes, *, log_vkey: str, witness_vkeys: Sequence[str] = (),
                    quorum: int = 0, proof: Sequence[bytes] | None = None,
                    larger_entries: Sequence[bytes] | None = None,
                    expected_origin: str | None = None) -> dict[str, Any]:
    """The §14.6 conclusion for two notes, independent of every package.

    Returns ``relation`` (``consistent``, ``split-proven``,
    ``consistency-unproven`` or ``not-evidence``) and, per note, whether it
    met the witness policy (historical: signatures and quorum, no freshness;
    step 1 "the witness policies applicable to their acceptance").
    ``larger_entries`` are the larger tree's complete entries, already
    authenticated by the caller; ``proof`` a supplied consistency proof.
    ``expected_origin`` is the pinned origin (§14.1 step 1); with or without
    it, two notes are compared only when their origins are identical (§14.2
    step 1)."""
    va = verify_note(note_a, log_vkey, witness_vkeys, quorum, expected_origin=expected_origin)
    vb = verify_note(note_b, log_vkey, witness_vkeys, quorum, expected_origin=expected_origin)
    out: dict[str, Any] = {"witness_policy_met": [va.ok, vb.ok]}
    if not (va.log_ok and vb.log_ok):
        return {**out, "relation": "not-evidence"}
    if va.origin != vb.origin:
        return {**out, "relation": "not-evidence", "reason": "different origins"}
    small, big = (va, vb) if va.size <= vb.size else (vb, va)
    for x in (small, big):
        if x.size == 0 and x.root != EMPTY_ROOT:
            return {**out, "relation": "split-proven", "reason": "bad-empty-root"}
    if small.size == big.size:
        if small.root == big.root:
            return {**out, "relation": "consistent", "reason": "same size and root"}
        return {**out, "relation": "split-proven", "reason": "equal-size-different-root"}
    if small.size == 0:
        return {**out, "relation": "consistent", "reason": "empty tree"}
    if proof is not None and verify_consistency(small.size, big.size, small.root, big.root, proof):
        return {**out, "relation": "consistent", "reason": "valid consistency proof"}
    if larger_entries is not None and len(larger_entries) == big.size:
        leaves = [leaf_hash(e) for e in larger_entries]
        if mth(leaves) != big.root:
            raise ValueError("larger_entries do not authenticate against the larger signed root")
        if mth(leaves[: small.size]) == small.root:
            return {**out, "relation": "consistent", "reason": "authenticated prefix root matches"}
        return {**out, "relation": "split-proven", "reason": "not-a-prefix"}
    return {**out, "relation": "consistency-unproven", "reason": "no valid proof and no authenticated prefix"}

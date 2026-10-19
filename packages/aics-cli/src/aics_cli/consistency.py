"""Proving that one signed checkpoint is a prefix of another
(docs/spec/AICS-1.md §14.2, §14.6; RFC 9162 §2.1.4).

A proof may come from a proof file, the log's consistency endpoint
(``GET /v2/tlog/consistency?from=<m>&to=<n>`` -> ``{from,to,hashes}``), or
tiles.  Any source will do because the proof is checked against both
log-signed roots; a source that serves bad data is reported and the next one
is tried.

Tiles are read through ``aics_tlog.VerifiedTileReader``, which authenticates
every tile up to the signed root of a *reference* checkpoint R published by
that source (normally the newer of the two notes).  Each note X is then
tested as a prefix of R: the consistency proof and the root at X's size come
from authenticated tiles, so if X's signed root differs from that
authenticated prefix root, X and R are two log-signed, mutually inconsistent
heads - constructive split-view evidence (§14.6 step 4) that anyone can
re-check from the proof.

Outcomes (:func:`relate`):

* ``consistent`` - a valid proof (or equal size and root, or the empty
  tree with the empty root);
* ``split-proven`` - equal sizes with different roots, an authenticated
  prefix root that differs from a signed root, or a size-0 checkpoint whose
  root is not SHA-256("") (``bad-empty-root``, §14.2 step 1);
* ``unproven`` - no valid proof was obtained.  A timeout, a missing tile or a
  bad proof does not show that no valid proof exists (§14.6 step 3): this is
  an availability alert, not evidence of a split.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aics_tlog import EMPTY_HASH, VerifiedTileReader, verify_consistency
from aics_tlog.tiles import TileVerificationError, consistency_proof_from_tiles, tree_root_from_tiles

from .checkpoints import Cp
from .encoding import b64d_strict, b64e
from .errors import FetchError
from .net import Fetcher
from .tiles_http import TileSourceError

PROOF_MAX_BYTES = 256 * 1024
MAX_PROOF_HASHES = 128


# ---------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------


@dataclass
class TileSource:
    label: str
    reader: Any  # an aics_tlog TileReader (raw, unauthenticated)
    ref: Cp | None = None  # checkpoint the source publishes tiles for (default: the newer note)


@dataclass
class EndpointSource:
    label: str
    template: str  # URL with {old} and {new}
    fetcher: Fetcher


@dataclass
class GivenProof:
    label: str
    hashes: list[bytes]


Source = TileSource | EndpointSource | GivenProof


@dataclass
class Attempt:
    source: str
    status: str  # consistent | split | invalid | incomplete
    detail: str = ""
    old: Cp | None = None
    new: Cp | None = None
    proof: list[bytes] | None = None
    prefix_root: bytes | None = None  # authenticated root of `new` at old's size

    def report(self) -> dict[str, Any]:
        d: dict[str, Any] = {"source": self.source, "status": self.status}
        if self.detail:
            d["detail"] = self.detail
        if self.old is not None and self.new is not None:
            d["old_size"] = self.old.size
            d["new_size"] = self.new.size
        if self.proof is not None:
            d["proof"] = [b64e(h) for h in self.proof]
        if self.prefix_root is not None:
            d["authenticated_prefix_root"] = b64e(self.prefix_root)
        return d


@dataclass
class Relation:
    status: str  # consistent | split-proven | unproven
    a: Cp
    b: Cp
    reason: str | None = None
    attempts: list[Attempt] = field(default_factory=list)
    winning: Attempt | None = None
    split_pairs: list[tuple[Cp, Cp, Attempt | None]] = field(default_factory=list)

    def report(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "status": self.status,
            "a": self.a.brief(),
            "b": self.b.brief(),
            "attempts": [x.report() for x in self.attempts],
        }
        if self.reason:
            d["reason"] = self.reason
        if self.winning is not None:
            d["proof_source"] = self.winning.source
        return d


# ---------------------------------------------------------------------------
# endpoint
# ---------------------------------------------------------------------------


def parse_proof_body(body: bytes, old: int, new: int) -> list[bytes]:
    """``{"from": m, "to": n, "hashes": [B64(hash), ...]}`` (AICS-1 §12.1),
    with canonical padded base64 and exactly 32-byte hashes."""
    from .card import loads_strict

    obj = loads_strict(body)
    if not isinstance(obj, dict) or set(obj) != {"from", "to", "hashes"}:
        raise ValueError("proof must be exactly {from, to, hashes}")
    if obj["from"] != old or obj["to"] != new or isinstance(obj["from"], bool) or isinstance(obj["to"], bool):
        raise ValueError(f"proof is for {obj['from']!r}->{obj['to']!r}, not {old}->{new}")
    hashes = obj["hashes"]
    if not isinstance(hashes, list) or len(hashes) > MAX_PROOF_HASHES:
        raise ValueError("hashes must be a list of at most 128 entries")
    out = []
    for h in hashes:
        raw = b64d_strict(h) if isinstance(h, str) else b""
        if len(raw) != 32:
            raise ValueError("each proof hash is canonical base64 of 32 bytes")
        out.append(raw)
    return out


def proof_url(template: str, old: int, new: int) -> str:
    return template.replace("{old}", str(old)).replace("{new}", str(new))


def fetch_proof(src: EndpointSource, old: int, new: int) -> list[bytes]:
    url = proof_url(src.template, old, new)
    resp = src.fetcher.get(url, max_bytes=PROOF_MAX_BYTES, accept="application/json")
    if resp.status != 200:
        raise FetchError(f"{url}: HTTP {resp.status}")
    return parse_proof_body(resp.body, old, new)


# ---------------------------------------------------------------------------
# the checks
# ---------------------------------------------------------------------------


def prefix_check(x: Cp, ref: Cp, reader: Any, label: str) -> Attempt:
    """Is ``x`` a prefix of ``ref``?  ``reader`` serves the tiles of ``ref``."""
    if x.size > ref.size:
        return Attempt(label, "incomplete", f"reference is smaller ({ref.size} < {x.size})", x, ref)
    if x.size == ref.size:
        if x.root == ref.root:
            return Attempt(label, "consistent", "same size and root", x, ref)
        return Attempt(label, "split", "same size, different roots", x, ref)
    if x.size == 0:
        if x.root == EMPTY_HASH:
            return Attempt(label, "consistent", "empty tree", x, ref)
        return Attempt(label, "split", "a size-0 checkpoint whose root is not SHA-256('')", x, ref)
    try:
        verified = VerifiedTileReader(reader, ref.size, ref.root)
        proof = consistency_proof_from_tiles(verified, x.size, ref.size)
        prefix = tree_root_from_tiles(verified, x.size)
    except TileSourceError as exc:
        return Attempt(label, "incomplete", f"tile source failed: {exc}", x, ref)
    except TileVerificationError as exc:
        return Attempt(label, "invalid", f"tiles do not authenticate against the signed root: {exc}", x, ref)
    except FileNotFoundError as exc:
        return Attempt(label, "incomplete", f"tiles missing: {exc}", x, ref)
    except (ValueError, OSError) as exc:
        return Attempt(label, "invalid", f"unusable tile data: {exc}", x, ref)
    if verify_consistency(x.size, ref.size, x.root, ref.root, proof):
        return Attempt(label, "consistent", "valid consistency proof from authenticated tiles", x, ref, proof)
    if prefix != x.root and verify_consistency(x.size, ref.size, prefix, ref.root, proof):
        return Attempt(
            label, "split",
            "the root at this size, authenticated by the newer signed root, differs from the signed root",
            x, ref, proof, prefix,
        )
    return Attempt(label, "invalid", "authenticated tiles yield no valid proof (inconsistent source data)",
                   x, ref, proof)


def relate(a: Cp, b: Cp, sources: list[Source]) -> Relation:
    """Is the smaller of ``a`` and ``b`` a prefix of the larger?"""
    if a.size > b.size:
        a, b = b, a
    rel = Relation(status="unproven", a=a, b=b)
    # AICS-1 §14.2 step 1: for size 0 require the standard empty root and an
    # empty proof.  No proof source is consulted (an empty "proof" verifies
    # any old root at size 0).
    bad_empty = [x for x in (a, b) if x.size == 0 and x.root != EMPTY_HASH]
    if bad_empty:
        rel.status, rel.reason = "split-proven", "bad-empty-root"
        for x in bad_empty:
            rel.split_pairs.append((x, b if x is a else a, None))
        return rel
    if a.size == 0:
        rel.status, rel.reason = "consistent", "the empty tree is a prefix of every tree"
        return rel
    if a.size == b.size:
        if a.root == b.root:
            rel.status, rel.reason = "consistent", "same size and root"
        else:
            rel.status, rel.reason = "split-proven", "equal-size-different-root"
            rel.split_pairs.append((a, b, None))
        return rel
    for src in sources:
        if isinstance(src, (GivenProof, EndpointSource)):
            if isinstance(src, GivenProof):
                hashes = src.hashes
            else:
                try:
                    hashes = fetch_proof(src, a.size, b.size)
                except FetchError as exc:
                    rel.attempts.append(Attempt(src.label, "incomplete", exc.message, a, b))
                    continue
                except (ValueError, UnicodeDecodeError) as exc:
                    rel.attempts.append(Attempt(src.label, "invalid", f"unusable proof: {exc}", a, b))
                    continue
            ok = verify_consistency(a.size, b.size, a.root, b.root, hashes)
            att = Attempt(src.label, "consistent" if ok else "invalid",
                          "valid consistency proof" if ok else "proof does not verify", a, b, hashes)
            rel.attempts.append(att)
            if ok:
                rel.status, rel.winning = "consistent", att
                return rel
            continue
        ref = src.ref if src.ref is not None else b
        if ref.size < b.size:
            rel.attempts.append(Attempt(src.label, "incomplete", f"source is behind ({ref.size} < {b.size})", b, ref))
            continue
        rb = prefix_check(b, ref, src.reader, src.label)
        if rb.status in ("invalid", "incomplete"):
            rel.attempts.append(rb)
            continue
        ra = prefix_check(a, ref, src.reader, src.label)
        if ra.status in ("invalid", "incomplete"):
            rel.attempts.append(ra)
            if rb.status == "split":
                rel.attempts.append(rb)
                rel.status, rel.reason = "split-proven", "not-a-prefix"
                rel.split_pairs.append((b, ref, rb))
                return rel
            continue
        rel.attempts += [x for x in (rb, ra) if x.old is not x.new]
        if ra.status == "consistent" and rb.status == "consistent":
            rel.status, rel.winning = "consistent", ra
            return rel
        rel.status = "split-proven"
        equal = [x for x in (ra, rb) if x.status == "split" and x.old is not None and x.new is not None
                 and x.old.size == x.new.size]
        rel.reason = "equal-size-different-root" if equal else "not-a-prefix"
        for x, chk in ((a, ra), (b, rb)):
            if chk.status == "split":
                rel.split_pairs.append((x, ref, chk))
        return rel
    rel.reason = "invalid-proof-data" if any(x.status == "invalid" for x in rel.attempts) else "no-proof-available"
    return rel

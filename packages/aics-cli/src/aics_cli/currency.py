"""Which card is in force: the log's policy leaves (AICS-1 §6.4, §13.1, §14.5 steps 3-4).

The server lists every policy leaf at ``GET <api>/v2/policies`` (``{"policies": [{leaf_index, kind, document_hash,
size, prev_policy_index, effective_after, not_before}, ...]}``) and serves the document a leaf names at
``GET <api>/v2/policies/<index>``.  Neither is trusted:

1. A checkpoint is fetched from the pinned checkpoint URL and accepted under the *prior* trust policy (the pinned
   policy; for ``aics policy init``, the witness terms of the bootstrap card the trust bundle pins): the pinned log
   key and origin, and the witness quorum with fresh cosignatures.  A note that only lacks a pinned witness's line
   is fetched again (:func:`aics_cli.checkpoints.fetch_checked`).
2. The listing's last policy leaf below that checkpoint's size is read from the pinned tile prefix through
   aics-tlog's ``VerifiedTileReader``, so its bytes are proven to be in the signed tree; from it the chain is walked
   back by ``prev_policy_index`` to the charter at leaf 0, every leaf proven the same way.  A policy leaf the listing
   leaves out between two others is found by the walk.  While the entries after the listing's last policy leaf are
   at most :data:`MAX_TAIL_SCAN`, every one of them is read the same way (AICS-1 §14.5 step 4 scans the policy events
   through the checkpoint), so a policy leaf the listing leaves out after its last row is found too.  The listing's
   rows are compared with the signed leaves: a misstated row is reported and the signed values are used; a policy
   leaf the chain does not reach is a second chain, which AICS-1 forbids.
3. Every leaf of the chain is a JCS entry v2 of type ``policy`` signed by the pinned policy key (its envelope
   verified at the entry's ``ts``), names the pinned log, policy and owner keys and links to the policy leaf before
   it; leaf 0 is the charter with the log key's countersignature (:func:`aics_cli.message.check_policy_event`).  A
   leaf that breaks this is evidence (:class:`Broken`, exit 2): the log signed a tree that contains it.
4. The card in force at ``now`` is the card leaf with the highest index whose ``not_before`` has passed and whose
   ``effective_after`` is below the checked tree's size (AICS-1 §6.4: a policy applies only at indices greater than
   ``effective_after``, after ``not_before`` and after its own index).  A card leaf after it, still waiting for its
   ``not_before`` or its activation index, is *pending*: logged, not yet in force, and never a reason to call the card
   in force superseded.  Every other card leaf is superseded, since the earliest ``not_before`` of a later card leaf
   in effect (:meth:`History.replaced_at`).  A card's own ``expires`` is checked on its document, not here.
5. For the card a command acts on, :func:`notice` compares its ``not_before`` with the notice period that the card
   in force when it was logged advertised (``policy_notice_seconds``); the first card needs none.  AICS-1 lets an
   order cut the notice short (the policy document then cites the order), so a short notice is reported, and it
   withholds authorisation from a weaker witness policy; it is not evidence by itself.

Not checked here: a policy leaf after the listing's last one while more than :data:`MAX_TAIL_SCAN` entries follow
it, or while they cannot be read (:attr:`History.scanned` is then false; a full scan, as ``aics verify message``
does, would find it), the continuity of this checkpoint with the head you saved (``aics verify checkpoint`` and
``aics verify consistency`` check that) and the evidence behind ``proven`` rows.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from aics_identity import keys as idkeys
from aics_tlog import VerifiedTileReader
from aics_tlog.tiles import TileVerificationError, inclusion_proof_from_tiles

from .card import CARD_MAX_BYTES, loads_strict
from .checkpoints import Cp, NoteCheck, fetch_checked, retry_warning
from .encoding import b64e, b64u_e, escape_untrusted
from .errors import AicsError, FetchError, PolicyError
from .message import ReplayProblem, check_envelope, check_policy_event, entry_problem
from .net import join_url
from .policy import Policy, parse_policy_key
from .tiles_http import HttpTileReader, TileSourceError

LISTING_PATH = "v2/policies"
LISTING_MAX_BYTES = 4 * 1024 * 1024
#: The longest policy chain walked back (one leaf per policy event: charter, card and change leaves).
MAX_CHAIN = 100_000
#: Listing rows off the chain that are read to tell a wrong row from a second policy chain; a listing with more is
#: not used (a hostile listing must not make the client read the whole log leaf by leaf).
MAX_OFF_CHAIN = 64
#: The most entries after the listing's last policy leaf that are scanned for a policy leaf the listing leaves out
#: (at most five entry bundles of 256; a longer tail is not scanned, and reported unread).
MAX_TAIL_SCAN = 1024
#: The members of a listing row that must equal the signed leaf.
LISTED_FIELDS = ("kind", "document_hash", "size", "prev_policy_index", "effective_after", "not_before")
EVIDENCE_TYPE = "aics-policy-history-evidence/v1"
#: The source of a card document read from the local card store (``store:<card hash>``), as a card record names it.
STORE_SOURCE = "store:"
UINT_MAX = 9007199254740991
_HEX64 = re.compile(r"[0-9a-f]{64}")


class Unavailable(Exception):
    """The policy history could not be read or checked (a fetch, a tile, the listing, a checkpoint that is not
    accepted): nothing is claimed against the log; the caller does what it can without it."""


class Broken(Exception):
    """A leaf of a log-signed tree that breaks AICS-1 §6.4's policy rules; ``evidence`` lets anyone re-check it."""

    def __init__(self, message: str, evidence: dict[str, Any]) -> None:
        super().__init__(message)
        self.message = message
        self.evidence = evidence


def _iso(ts: int | None) -> str | None:
    return None if ts is None else time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _uint(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= UINT_MAX


def listing_url(api_base: str) -> str:
    return join_url(api_base, LISTING_PATH)


def document_url(api_base: str, index: int) -> str:
    return join_url(api_base, f"{LISTING_PATH}/{index}")


@dataclass
class Leaf:
    """A policy leaf of the checked tree, as the log signed it."""

    index: int
    ts: int
    kind: str
    document_hash: str
    size: int | None
    prev_policy_index: int | None
    effective_after: int
    not_before: int
    entry: bytes = field(repr=False, default=b"")

    def report(self) -> dict[str, Any]:
        return {"leaf_index": self.index, "kind": self.kind, "document_hash": self.document_hash, "size": self.size,
                "prev_policy_index": self.prev_policy_index, "effective_after": self.effective_after,
                "not_before": self.not_before, "not_before_utc": _iso(self.not_before), "ts": self.ts,
                "ts_utc": _iso(self.ts)}


@dataclass
class History:
    """The policy chain through a checkpoint accepted under the prior trust policy, judged at ``now``."""

    checkpoint: Cp
    check: NoteCheck
    listing: str
    api_base: str
    leaves: list[Leaf]
    now: int
    reader: Any = field(repr=False, default=None)  # the VerifiedTileReader of the checkpoint
    notes: list[str] = field(default_factory=list)
    head: int | None = None  # the last policy leaf known below the checkpoint's size: the chain starts there
    listing_head: int | None = None  # the last policy leaf the listing named below the checkpoint's size
    scanned: bool = False  # every entry after ``head`` through the checkpoint was read: no policy leaf left out
    unscanned: str | None = None  # why the entries after ``head`` were not scanned

    @property
    def cards(self) -> list[Leaf]:
        return [leaf for leaf in self.leaves if leaf.kind == "card"]

    @property
    def size(self) -> int:
        """The checked tree's size."""
        return self.checkpoint.size

    def in_force_at(self, t: int, *, before: int | None = None) -> Leaf | None:
        """The card in force at time ``t`` for the entry at index ``before`` (default: the next entry, at the checked
        tree's size): the card leaf with the highest index below ``before`` whose ``not_before`` is at or before ``t``
        and whose ``effective_after`` is below ``before`` (AICS-1 §6.4: a policy applies only at indices greater than
        ``effective_after``)."""
        if before is None:
            before = self.size
        found = None
        for leaf in self.cards:
            if leaf.index >= before:
                break
            if leaf.not_before <= t and leaf.effective_after < before:
                found = leaf
        return found

    def in_force(self) -> Leaf | None:
        return self.in_force_at(self.now)

    def pending(self) -> list[Leaf]:
        """Card leaves after the card in force: logged, still waiting for their ``not_before`` or their activation
        index (a later leaf that had both would be the card in force)."""
        current = self.in_force()
        return [leaf for leaf in self.cards if current is None or leaf.index > current.index]

    def activated(self, leaf: Leaf) -> bool:
        """Whether the checked tree is past ``leaf``'s ``effective_after`` (its activation index)."""
        return leaf.effective_after < self.size

    def replaced_at(self, leaf: Leaf) -> int | None:
        """When card leaf ``leaf`` stopped being current: the earliest ``not_before`` among the later card leaves that
        are in effect now (None if none is)."""
        times = [c.not_before for c in self.cards
                 if c.index > leaf.index and c.not_before <= self.now and self.activated(c)]
        return min(times) if times else None

    def takes_effect(self, leaf: Leaf) -> str:
        """When a pending card leaf takes effect, in words: at its ``not_before`` while that is ahead, and once the
        log is past its ``effective_after`` while the checked tree is not."""
        parts = [f"at {_iso(leaf.not_before)}"] if leaf.not_before > self.now or self.activated(leaf) else []
        if not self.activated(leaf):
            parts.append(f"once the log is past index {leaf.effective_after} (its effective_after; the checked tree "
                         f"has {self.size} entries)")
        return " and ".join(parts)

    def leaf_of(self, digest: str) -> Leaf | None:
        """The latest card leaf whose document is the card with this hash."""
        found = [leaf for leaf in self.cards if leaf.document_hash == digest]
        return found[-1] if found else None

    def state(self, digest: str) -> tuple[str, Leaf | None]:
        """``in-force``, ``pending``, ``superseded`` or ``not-logged`` for the card ``hexH(J(card)) == digest``, with
        the leaf that decides it (a document logged twice is judged by the leaf in force, else a pending one)."""
        named = [leaf for leaf in self.cards if leaf.document_hash == digest]
        if not named:
            return "not-logged", None
        current = self.in_force()
        for leaf in named:
            if current is not None and leaf.index == current.index:
                return "in-force", leaf
        waiting = {p.index for p in self.pending()}
        for leaf in reversed(named):
            if leaf.index in waiting:
                return "pending", leaf
        return "superseded", named[-1]

    def leaf_evidence(self, leaf: Leaf) -> dict[str, Any]:
        """The leaf as anyone can re-check it: its entry bytes and its inclusion proof in the checkpoint."""
        return _leaf_evidence(self.reader, self.checkpoint, leaf.index, leaf.entry)

    def report(self) -> dict[str, Any]:
        current = self.in_force()
        return {
            "available": True,
            "checkpoint": self.checkpoint.brief(),
            "witness_policy_met": self.check.witness_ok,
            "freshness": self.check.freshness,
            "listing": self.listing,
            "listing_last_leaf": self.listing_head,
            "last_policy_leaf": self.head,
            "entries_after_scanned": self.scanned,
            "entries_after_unscanned": self.unscanned,
            "leaves": [leaf.report() for leaf in self.leaves],
            "in_force": current.report() if current else None,
            "pending": [leaf.report() for leaf in self.pending()],
            "notes": list(self.notes),
        }


def _leaf_evidence(reader: Any, cp: Cp, index: int, raw: bytes) -> dict[str, Any]:
    try:
        proof: list[str] | None = [b64e(h) for h in inclusion_proof_from_tiles(reader, index, cp.size)]
    except (TileSourceError, TileVerificationError, OSError, ValueError):
        proof = None
    return {"leaf_index": index, "entry_bytes": b64u_e(raw), "inclusion_proof": proof}


@dataclass
class _Keys:
    origin: str
    log_kid: str
    policy_kid: str
    policy_pub: bytes
    owner_kid: str | None


def _keys(policy: Policy) -> _Keys:
    if not policy.policy_kid:
        raise Unavailable("no policy key is pinned")
    pk = parse_policy_key(policy.policy_kid)
    log_kid = idkeys.did_key(idkeys.public_key_from_bytes(policy.log_key().public_key))
    owner = parse_policy_key(policy.owner_kid).did if policy.owner_kid else None
    return _Keys(origin=policy.origin, log_kid=log_kid, policy_kid=pk.did, policy_pub=pk.public_key, owner_kid=owner)


def _broken(message: str, rule: str, cp: Cp, policy: Policy, reader: Any, leaves: list[tuple[int, bytes]]) -> Broken:
    return Broken(message, {
        "type": EVIDENCE_TYPE,
        "reason": rule,
        "problem": message,
        "origin": policy.origin,
        "log_vkey": policy.log_vkey,
        "policy_kid": policy.policy_kid,
        "checkpoint": cp.evidence(),
        "leaves": [_leaf_evidence(reader, cp, i, raw) for i, raw in leaves],
        "check": "verify the checkpoint note with the pinned log key, each leaf's inclusion proof against its root "
                 "(RFC 9162 §2.1.3.2 over SHA-256(0x00 || entry_bytes)), then read the entry",
    })


def _read(reader: Any, index: int) -> bytes:
    try:
        return reader.entry(index)
    except TileVerificationError as exc:
        raise Unavailable(f"the tiles do not authenticate leaf {index} against the checkpoint: {exc}") from None
    except (TileSourceError, FileNotFoundError, OSError, ValueError) as exc:
        raise Unavailable(f"leaf {index} could not be read from the tiles: {exc}") from None


def _parse(raw: bytes, index: int, keys: _Keys, fail: Callable[[str, str], Broken], via: Leaf | None) -> Leaf:
    """Policy leaf ``index``: a JCS entry v2 of type ``policy`` whose envelope the pinned policy key signed.  ``via``
    is the leaf whose ``prev_policy_index`` points here (None: the listing named it).  A leaf that is no AICS-1
    entry at all is evidence only when the policy chain points to it; when only the listing does, the listing is
    wrong (:class:`Unavailable`): judging every leaf is ``aics verify message``'s replay, not this walk."""
    def not_an_entry(message: str) -> Exception:
        if via is None:
            return Unavailable(f"the listing names leaf {index} as a policy leaf, but it is no AICS-1 entry ({message})")
        return fail(f"policy leaf {via.index} names leaf {index} as the preceding policy event, which is no AICS-1 "
                    f"entry: {message}", "entry")

    try:
        e = loads_strict(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise not_an_entry(f"not strict JSON: {exc}") from None
    problem = entry_problem(e, raw, keys.origin)
    if problem is not None:
        raise not_an_entry(problem)
    if e["type"] != "policy":
        what = escape_untrusted(str(e["type"]))[:40]
        if via is None:
            raise Unavailable(f"the listing names leaf {index} as a policy leaf, but it is a {what} entry")
        raise fail(f"policy leaf {via.index} names leaf {index} as the preceding policy event, but it is a {what} "
                   "entry (AICS-1 §6.4)", "policy")
    try:
        signer = parse_policy_key(str(e["actor_kid"])).public_key
    except PolicyError:
        signer = b""
    if signer != keys.policy_pub:
        raise fail(f"policy leaf {index} is signed by {escape_untrusted(str(e['actor_kid']))[:80]}, not the pinned "
                   "policy key (AICS-1 §5.3)", "authority")
    try:
        check_envelope(index, e, keys.policy_kid)
    except ReplayProblem as exc:
        raise fail(str(exc), exc.rule) from None
    q = e["payload"]["envelope"]["payload"]
    kind, digest, size = q.get("kind"), q.get("document_hash"), q.get("size")
    prev, after, not_before = q.get("prev_policy_index"), q.get("effective_after"), q.get("not_before")
    if not (isinstance(kind, str) and kind and isinstance(digest, str) and _HEX64.fullmatch(digest)
            and (size is None or _uint(size)) and (prev is None or _uint(prev)) and _uint(after)
            and _uint(not_before)):
        raise fail(f"policy leaf {index}: kind, document_hash, size, prev_policy_index, effective_after or not_before "
                   "is missing or mistyped (AICS-1 §5.3)", "schema")
    if prev is not None and prev >= index:
        raise fail(f"policy leaf {index} names prev_policy_index {prev}, which is not an earlier leaf (AICS-1 §6.4)",
                   "policy")
    return Leaf(index=index, ts=e["ts"], kind=kind, document_hash=digest, size=size, prev_policy_index=prev,
                effective_after=after, not_before=not_before, entry=raw)


def _policy_entries(reader: Any, start: int, end: int, origin: str) -> list[tuple[int, bytes]]:
    """The leaves in ``[start, end)`` that are AICS-1 entries of this log of type ``policy``, whoever signed them, as
    ``(index, entry bytes)`` read through the verified tiles.  Other leaves are skipped: judging them is ``aics verify
    message``'s replay.  :class:`Unavailable` when a leaf cannot be read."""
    found = []
    for i in range(start, end):
        raw = _read(reader, i)
        if b'"type":"policy"' not in raw:  # the JCS bytes of every policy entry hold it: a cheap filter
            continue
        try:
            e = loads_strict(raw)
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(e, dict) and e.get("type") == "policy" and entry_problem(e, raw, origin) is None:
            found.append((i, raw))
    return found


def _listing(fetcher: Any, url: str) -> list[dict[str, Any]]:
    try:
        resp = fetcher.get(url, max_bytes=LISTING_MAX_BYTES, accept="application/json")
    except FetchError as exc:
        raise Unavailable(f"the policy listing could not be fetched: {exc.message}") from None
    if resp.status != 200:
        raise Unavailable(f"GET {url}: HTTP {resp.status}")
    try:
        doc = loads_strict(resp.body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Unavailable(f"the policy listing {url} is not strict JSON: {exc}") from None
    rows = doc.get("policies") if isinstance(doc, dict) else None
    if not isinstance(rows, list) or not all(isinstance(r, dict) and _uint(r.get("leaf_index")) for r in rows):
        raise Unavailable(f"the policy listing {url} has no 'policies' array of rows with a leaf_index")
    return rows


def load(fetcher: Any, policy: Policy, *, api_base: str, now: int, clock: Callable[[], float],
         sleep: Callable[[float], Any], max_skew: int = 30) -> History:
    """The policy history (module docstring, steps 1-3) under ``policy``: the pinned keys, the prior witness terms
    and the pinned ``checkpoint_url`` and ``tiles_url``.  :class:`Unavailable` when it cannot be read, :class:`Broken`
    for a log-signed leaf that breaks the rules."""
    keys = _keys(policy)
    if not policy.checkpoint_url or not policy.tiles_url:
        raise Unavailable("no checkpoint URL or tile prefix is pinned")
    url = listing_url(api_base)
    rows = _listing(fetcher, url)
    try:
        _fetched, chk, retried = fetch_checked(fetcher, policy.checkpoint_url, policy, clock=clock, sleep=sleep,
                                               max_skew=max_skew)
    except AicsError as exc:
        raise Unavailable(f"the checkpoint could not be fetched: {exc.message}") from None
    if not chk.ok or chk.cp is None:
        raise Unavailable(f"the checkpoint at {policy.checkpoint_url} is not accepted under the pinned policy: "
                          f"{chk.error}")
    cp = chk.cp
    try:
        reader = VerifiedTileReader(HttpTileReader(policy.tiles_url, fetcher), cp.size, cp.root)
    except (TileVerificationError, ValueError) as exc:
        raise Unavailable(f"the checkpoint's tree cannot be read: {exc}") from None
    notes: list[str] = [retry_warning(retried, chk)] if retried else []
    listed: dict[int, dict[str, Any]] = {}
    beyond = 0
    for row in rows:
        i = row["leaf_index"]
        if i >= cp.size:
            beyond += 1
        elif i in listed:
            raise Unavailable(f"the policy listing {url} names leaf {i} twice")
        else:
            listed[i] = row
    if beyond:
        notes.append(f"the listing names {beyond} policy leaf(s) at or beyond the checked tree's size {cp.size}; "
                     "they are newer than the checkpoint and not used")

    def fail(message: str, rule: str, extra: list[tuple[int, bytes]] = ()) -> Broken:
        return _broken(message, rule, cp, policy, reader, list(extra))

    def parse(raw: bytes, i: int, via: Leaf | None) -> Leaf:
        return _parse(raw, i, keys, lambda m, r: fail(m, r, [(i, raw)]), via)

    # the head: the highest listed row that is a policy leaf (rows naming other leaves are the listing's errors).
    # A leaf that cannot be read makes the whole history unavailable: skipping it could hide the latest card.
    ignored: set[int] = set()
    head: int | None = None
    head_leaf: Leaf | None = None
    for i in sorted(listed, reverse=True):
        if len(ignored) >= MAX_OFF_CHAIN:
            raise Unavailable(f"the policy listing {url} names more than {MAX_OFF_CHAIN} rows that are not policy "
                              "leaves; it is not used")
        raw = _read(reader, i)
        try:
            head_leaf = parse(raw, i, None)
        except Unavailable as exc:
            notes.append(f"{exc}; the row is ignored")
            ignored.add(i)
            continue
        head = i
        break
    if head is None and cp.size:
        try:  # the listing names no usable row: leaf 0 must be the charter anyway (AICS-1 §6.1)
            head, head_leaf = 0, parse(_read(reader, 0), 0, None)
        except Unavailable as exc:
            raise Unavailable(f"the policy listing names no policy leaf below the checked tree's size {cp.size}, and "
                              f"leaf 0 is not one either ({exc})") from None
    # AICS-1 §14.5 step 4 scans the policy events through the checkpoint, and the listing is only an index: while the
    # entries after its last policy leaf are few, read them all, so that one it leaves out after its last row is found
    # (and judged with the listed rows: on the chain, or a second chain).  A longer tail, or one that cannot be read,
    # stays unread, as the output says; it never makes the history unavailable.
    listing_head, scanned, unscanned = head, False, None
    if head is not None:
        tail = cp.size - head - 1
        if tail > MAX_TAIL_SCAN:
            unscanned = f"the {tail} entries after it are more than the {MAX_TAIL_SCAN} aics scans"
        else:
            try:
                found = _policy_entries(reader, head + 1, cp.size, keys.origin)
            except Unavailable as exc:
                unscanned = f"the {tail} entries after it could not be read ({exc})"
                notes.append(f"the entries after policy leaf {head}, the listing's last, were not scanned: {unscanned}")
            else:
                scanned = True
                for i, raw in found:
                    head, head_leaf = i, parse(raw, i, None)  # Broken: a policy entry the policy key did not sign
                    listed.setdefault(i, {})
                    notes.append(f"the listing leaves out policy leaf {i}, after its last policy leaf {listing_head}; "
                                 "found by scanning the entries after that leaf")
    leaves: list[Leaf] = []
    leaf = head_leaf
    while leaf is not None:
        if len(leaves) >= MAX_CHAIN:
            raise Unavailable(f"the policy chain is longer than {MAX_CHAIN} leaves")
        leaves.append(leaf)
        prev = leaf.prev_policy_index
        leaf = parse(_read(reader, prev), prev, leaf) if prev is not None else None
    leaves.reverse()
    previous: int | None = None
    for leaf in leaves:
        q = loads_strict(leaf.entry)["payload"]["envelope"]["payload"]
        try:
            check_policy_event(leaf.index, q, log_kid=keys.log_kid, policy_kid=keys.policy_kid,
                               owner_kid=keys.owner_kid if keys.owner_kid else q.get("owner_kid"), previous=previous)
        except ReplayProblem as exc:
            raise fail(str(exc), exc.rule, [(leaf.index, leaf.entry)]) from None
        except (KeyError, TypeError) as exc:
            raise fail(f"policy leaf {leaf.index}: a §5.3 member is missing or mistyped ({type(exc).__name__}: {exc})",
                       "schema", [(leaf.index, leaf.entry)]) from None
        previous = leaf.index
    chain = {leaf.index: leaf for leaf in leaves}
    off_chain = [i for i in listed if i not in chain and i not in ignored]
    if len(off_chain) + len(ignored) > MAX_OFF_CHAIN:
        raise Unavailable(f"the policy listing {url} names {len(off_chain) + len(ignored)} rows that are not on the "
                          f"policy chain from leaf {head}; it is not used (at most {MAX_OFF_CHAIN} such rows are read)")
    for i, row in sorted(listed.items()):
        if i in ignored:
            continue
        leaf = chain.get(i)
        if leaf is None:
            raw = _read(reader, i)
            try:
                other = parse(raw, i, None)
            except Unavailable as exc:
                notes.append(f"{exc}; the row is ignored")
                continue
            successor = next((x for x in leaves if x.prev_policy_index == other.prev_policy_index), None)
            pair = [(other.index, other.entry)] + ([(successor.index, successor.entry)] if successor else [])
            raise fail(f"policy leaf {i} is not on the policy chain that leads back from leaf {head} to the charter: "
                       "two policy events name the same predecessor, or one names none it may (AICS-1 §6.4: every "
                       "policy event references the preceding one)", "policy", pair)
        misstated = [f for f in LISTED_FIELDS if f in row and row[f] != getattr(leaf, f)]
        if misstated:
            notes.append(f"the listing misstates leaf {i} ({', '.join(misstated)}); the values the log signed are used")
    return History(checkpoint=cp, check=chk, listing=url, api_base=api_base, leaves=leaves, now=now, reader=reader,
                   notes=notes, head=head, listing_head=listing_head, scanned=scanned, unscanned=unscanned)


def fetch_document(fetcher: Any, api_base: str, leaf: Leaf, *,
                   local: Callable[[str], bytes | None] | None = None) -> tuple[dict[str, Any], str]:
    """The card a card leaf names, as ``(card, source)``: from ``local(document_hash)`` when that holds it (source
    ``store:<document_hash>``), else ``GET <api_base>/v2/policies/<index>`` (source: that URL).  The bytes must hash
    to the leaf's ``document_hash`` and be strict JSON; :class:`Unavailable` otherwise."""
    raw = local(leaf.document_hash) if local is not None else None
    source = f"{STORE_SOURCE}{leaf.document_hash}"
    if raw is None or hashlib.sha256(raw).hexdigest() != leaf.document_hash:
        source = document_url(api_base, leaf.index)
        try:
            resp = fetcher.get(source, max_bytes=CARD_MAX_BYTES, accept="application/json, text/plain;q=0.5")
        except FetchError as exc:
            raise Unavailable(f"the card of policy leaf {leaf.index} could not be fetched: {exc.message}") from None
        if resp.status != 200:
            raise Unavailable(f"GET {source}: HTTP {resp.status}")
        raw = resp.body
        if hashlib.sha256(raw).hexdigest() != leaf.document_hash:
            raise Unavailable(f"{source} serves bytes that do not hash to policy leaf {leaf.index}'s document_hash")
    try:
        card = loads_strict(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise Unavailable(f"the document of policy leaf {leaf.index} is not strict JSON: {exc}") from None
    if not isinstance(card, dict):
        raise Unavailable(f"the document of policy leaf {leaf.index} is not a JSON object")
    return card, source


def notice(history: History, leaf: Leaf, document: Callable[[Leaf], dict[str, Any] | None]) -> dict[str, Any]:
    """Did card leaf ``leaf`` give the notice the card in force when it was logged advertised (AICS-1 §6.4)?
    ``status``: ``not-required`` (no card was in force: the first card), ``ok``, ``short`` or ``unchecked`` (that
    card could not be read)."""
    prior = history.in_force_at(leaf.ts, before=leaf.index)
    if prior is None:
        return {"status": "not-required", "detail": f"no card was in force when policy leaf {leaf.index} was logged; "
                                                    "the first card needs no notice (AICS-1 §6.4)"}
    card = document(prior)
    required = card.get("policy_notice_seconds") if isinstance(card, dict) else None
    out: dict[str, Any] = {"prior_leaf": prior.index, "given_seconds": leaf.not_before - leaf.ts}
    if not _uint(required):
        return {**out, "status": "unchecked",
                "detail": f"the card of policy leaf {prior.index}, in force when leaf {leaf.index} was logged, could not "
                          "be read, so its notice period is not known"}
    out["required_seconds"] = required
    if out["given_seconds"] >= required:
        return {**out, "status": "ok", "detail": f"not_before is {out['given_seconds']} s after the leaf's ts; the card "
                                                 f"in force then (leaf {prior.index}) asks for {required} s"}
    return {**out, "status": "short",
            "detail": f"not_before is only {out['given_seconds']} s after the leaf's ts, but the card in force then "
                      f"(leaf {prior.index}) advertised {required} s of notice; AICS-1 §6.4 allows that only under an "
                      "order the policy document cites"}

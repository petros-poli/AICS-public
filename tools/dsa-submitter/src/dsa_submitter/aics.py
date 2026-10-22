"""Reading the wesupport-ai.com public API to find restriction leaves.

A restriction is one of (AICS-1 sections 5.3, 10.3):

* a ``tombstone`` leaf with reason ``illegal_on_notice``, ``order`` or
  ``secret_format`` — an ``erasure`` tombstone is the recipient's own request
  and is never submitted;
* a ``suspension`` leaf with reason ``order`` or ``flood`` — the later leaf
  that ends a suspension (``until`` equal to its own time) is not a new
  restriction.

Tombstones come from ``GET /v2/tombstones`` (public). No public route lists
suspensions, so the scan walks the log itself through ``GET /v2/entries/{index}``
— the AICS-1 section 14.3 wire bundle — from the last scanned index up to the
size in the signed C2SP checkpoint (``GET /checkpoint``, falling back to the
JSON copy at ``GET /v2/tlog/checkpoint``), exactly as the brief prescribes.

This module reads only public, keyless routes and never touches a body: the
entry bundle's ``body_or_ct`` member is ignored. Hashes are reduced to
16-character prefixes the moment they are read.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from datetime import UTC, datetime

DEFAULT_BASE_URL = "https://api.wesupport-ai.com"

RESTRICTION_TOMBSTONE_REASONS = ("illegal_on_notice", "order", "secret_format")
ERASURE_REASON = "erasure"
SUSPENSION_REASONS = ("order", "flood")
HASH_PREFIX_CHARS = 16


class ApiError(Exception):
    pass


@dataclass(frozen=True)
class Restriction:
    leaf_index: int
    kind: str  # "tombstone" or "suspension"
    reason_code: str
    ts: int
    target_index: int | None  # tombstones only
    content_date: str | None  # YYYY-MM-DD; tombstone needs the target's leaf
    until: int | None  # suspensions only
    evidence_prefix: str | None
    receipt_prefix: str | None
    note: str | None = None  # why content_date is missing, when it is


@dataclass(frozen=True)
class ScanResult:
    restrictions: list
    entries_scanned: int  # the new "walked up to here" mark
    tree_size: int


def _prefix(full_hash):
    if not isinstance(full_hash, str) or not full_hash:
        return None
    return full_hash[:HASH_PREFIX_CHARS]


def _date(ts):
    return datetime.fromtimestamp(ts, tz=UTC).date().isoformat()


def _b64u_json(text):
    if isinstance(text, str):
        text = text.encode("ascii")
    padded = text + b"=" * (-len(text) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


class AicsApi:
    def __init__(self, base_url=DEFAULT_BASE_URL, timeout=30, opener=None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opener = opener or urllib.request.build_opener()

    def _get(self, path, accept="application/json"):
        url = self.base_url + path
        request = urllib.request.Request(url, headers={"Accept": accept})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            raise ApiError(f"GET {url} answered {exc.code}") from None
        except urllib.error.URLError as exc:
            raise ApiError(f"GET {url} failed: {exc.reason}") from None

    def _get_json(self, path):
        _, body = self._get(path)
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise ApiError(f"GET {self.base_url}{path} returned invalid JSON") from None

    def checkpoint_size(self):
        """The tree size from the signed C2SP checkpoint note.

        ``GET /checkpoint`` serves the note text (``origin`` LF ``size`` LF
        ``root``...); the JSON convenience copy at ``/v2/tlog/checkpoint`` is
        the fallback, mirroring ops/uptime-check.sh's order.
        """
        try:
            _, body = self._get("/checkpoint", accept="text/plain")
            lines = body.decode("utf-8", "replace").splitlines()
            return int(lines[1].strip())
        except (ApiError, IndexError, ValueError):
            pass
        envelope = self._get_json("/v2/tlog/checkpoint")
        size = envelope.get("tree_size")
        if not isinstance(size, int) or size < 0:
            raise ApiError("checkpoint carries no usable tree size")
        return size

    def tombstones(self):
        """Every tombstone projection row, walking the ``since`` pagination."""
        rows = []
        since = 0
        while True:
            page = self._get_json(f"/v2/tombstones?since={since}&limit=1000")
            batch = page.get("tombstones", [])
            rows.extend(batch)
            if len(batch) < 1000:
                return rows
            since = batch[-1]["tombstone_index"] + 1

    def entry(self, index):
        """The entry at ``index`` decoded from its section 14.3 wire bundle."""
        bundle = self._get_json(f"/v2/entries/{index}")
        try:
            leaf = _b64u_json(bundle["entry_bytes"])
        except (KeyError, TypeError, ValueError):
            raise ApiError(f"entry {index} carries no decodable entry_bytes") from None
        if not isinstance(leaf, dict):
            raise ApiError(f"entry {index} did not decode to an entry object")
        return leaf

    @staticmethod
    def _payload_of(leaf):
        payload = leaf.get("payload")
        return payload if isinstance(payload, dict) else {}

    def scan(self, scanned_from=0):
        """List every restriction in the log; ``scanned_from`` resumes the walk.

        Tombstone leaves reached while walking are skipped: the tombstones
        endpoint already covers them with their projection row.
        """
        tree_size = self.checkpoint_size()
        restrictions = []

        for row in self.tombstones():
            if not isinstance(row, dict) or not {"tombstone_index", "target_index",
                                                 "reason_code"} <= set(row):
                raise ApiError("tombstones endpoint returned an unexpected row shape")
            if row["reason_code"] not in RESTRICTION_TOMBSTONE_REASONS:
                continue  # erasure: the recipient's own request, not a restriction
            leaf_index = row["tombstone_index"]
            leaf = self.entry(leaf_index)
            payload = self._payload_of(leaf)
            restriction = Restriction(
                leaf_index=leaf_index,
                kind="tombstone",
                reason_code=row["reason_code"],
                ts=leaf.get("ts", 0),
                target_index=row["target_index"],
                content_date=None,
                until=None,
                evidence_prefix=_prefix(payload.get("evidence_hash")),
                receipt_prefix=_prefix(payload.get("receipt_hash")),
            )
            try:
                target = self.entry(row["target_index"])
                restriction = replace(restriction, content_date=_date(target.get("ts", 0)))
            except ApiError as exc:
                restriction = replace(
                    restriction,
                    note=f"target entry unavailable ({exc}); content_date unknown")
            restrictions.append(restriction)

        index = scanned_from
        while index < tree_size:
            try:
                leaf = self.entry(index)
            except ApiError:
                break  # stop the walk at the first gap; the next run resumes here
            leaf_type = leaf.get("type")
            if leaf_type == "suspension":
                payload = self._payload_of(leaf)
                until = payload.get("until")
                ts = leaf.get("ts", 0)
                if until is not None and until <= ts:
                    pass  # the ending event, not a new restriction (AICS-1 10.3)
                elif payload.get("reason_code") in SUSPENSION_REASONS:
                    restrictions.append(Restriction(
                        leaf_index=index,
                        kind="suspension",
                        reason_code=payload["reason_code"],
                        ts=ts,
                        target_index=None,
                        content_date=_date(ts),
                        until=until,
                        evidence_prefix=_prefix(payload.get("evidence_hash")),
                        receipt_prefix=None,
                    ))
            # tombstone leaves are covered by /v2/tombstones above; every other
            # type (agent entries, refusals, freeze, reports) is not a restriction
            index += 1

        return ScanResult(restrictions=restrictions, entries_scanned=index, tree_size=tree_size)


def describe(restriction):
    """One human-readable line for scan/submit listings."""
    time_text = datetime.fromtimestamp(restriction.ts, tz=UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    parts = [
        f"leaf {restriction.leaf_index}",
        restriction.kind,
        f"reason={restriction.reason_code}",
        f"time={time_text}",
    ]
    if restriction.target_index is not None:
        parts.append(f"target={restriction.target_index}")
    if restriction.evidence_prefix:
        parts.append(f"evidence={restriction.evidence_prefix}")
    if restriction.receipt_prefix:
        parts.append(f"receipt={restriction.receipt_prefix}")
    if restriction.until is not None:
        parts.append(f"until={restriction.until}")
    if restriction.note:
        parts.append(f"note={restriction.note}")
    return " ".join(parts)

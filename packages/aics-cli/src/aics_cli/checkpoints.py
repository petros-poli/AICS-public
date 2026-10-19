"""Checkpoints: fetch, verify against the pinned policy, store append-only.

Verification of a checkpoint note (c2sp.org/tlog-checkpoint):

1. the log signature, Ed25519 over the note text, from the pinned log key,
   and the pinned origin (``aics_tlog.verify_checkpoint``, which also rejects
   duplicate signature lines).  A note that passes this is *log-signed*: it
   is what the log said, whatever else is wrong with it;
2. the AICS-1 profile (§6.2): exactly three text lines (no extension
   lines), a size within 2^53-1, and the empty-tree root for size 0
   (§14.2 step 1);
3. witness cosignatures (c2sp.org/tlog-cosignature, AICS-1 §6.3): a line
   under a pinned witness's (name, key ID) that does not verify rejects the
   note (``bad_cosignature``); each valid cosignature counts toward the
   quorum only if ``now - max_checkpoint_age <= timestamp <= now + 30``; one
   public key counts once.  With quorum 0 the head's freshness is reported
   as unproven: a log-only note carries no authenticated time.

:func:`check_note` keeps these apart: ``cp`` is set for every log-signed
note, ``ok`` only for one that also meets the profile and the witness
policy.  Callers that accept a head test ``ok``; callers that reason about
history (the saved head, saved notes, gossip evidence) need only ``cp`` -
a junk line under some witness key must not make the log's own signature
disappear.

Saved notes live in ``~/.aics/checkpoints/<origin>/<size>-<sha256>.note``;
a file is created once and never rewritten.  Every save appends a line to
``index.jsonl`` with a role: ``head`` (the local trusted head: the first
checkpoint, or one proven consistent with the previous head - AICS-1
§14.1 step 4), ``evidence`` (verified but not adopted, e.g. a fork) or
``observed`` (verified by status checks, or an older head kept as
historical), and the log key it was verified with.  A ``reset`` line
(``--reset-history``) drops the files it lists from continuity checks; the
files themselves are kept.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aics_tlog import EMPTY_HASH, Note, parse_checkpoint, parse_note, verify_checkpoint, verify_cosignature

from . import home as _home
from .encoding import b64e
from .errors import AicsError, FetchError
from .net import Fetcher
from .policy import Policy, parse_log_vkey, policy_digest

DEFAULT_MAX_SKEW = 30  # AICS-1 §6.3: timestamp <= now + 30
UINT_MAX = 9007199254740991
NOTE_MAX_BYTES = 1024 * 1024
JSON_MAX_DEPTH = 32


@dataclass
class Cp:
    """A checkpoint whose log signature verified against a pinned log key."""

    note_text: str
    origin: str
    size: int
    root: bytes
    source: str
    log_vkey: str | None = None  # the pinned log key the signature verified with

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.note_text.encode("utf-8")).hexdigest()

    @property
    def root_b64(self) -> str:
        return b64e(self.root)

    def brief(self) -> dict[str, Any]:
        return {"origin": self.origin, "size": self.size, "root": self.root_b64,
                "sha256": self.sha256, "source": self.source}

    def evidence(self) -> dict[str, Any]:
        d = self.brief()
        d["note"] = self.note_text
        if self.log_vkey:
            d["log_vkey"] = self.log_vkey
        return d


@dataclass
class NoteCheck:
    ok: bool
    cp: Cp | None = None  # set for every log-signed note, even one that is otherwise invalid
    error: str | None = None
    # malformed | bad_signature | wrong_origin (not log-signed);
    # bad_empty_root | bad_cosignature | quorum (log-signed, rejected)
    reason: str | None = None
    log_ok: bool = False
    witness_ok: bool = False  # no invalid cosignature line and the quorum is met
    witnesses: list[dict[str, Any]] = field(default_factory=list)
    counted: int = 0
    quorum: int = 0
    max_age: int | None = None
    freshness: str = "unproven"  # fresh | unproven | historical
    declared_trust_domains: list[str] = field(default_factory=list)
    declared_independent: int = 0
    assessed_independent: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def report(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "log_signature": "ok" if self.log_ok else "failed",
            "witness_policy_met": self.witness_ok,
            "witnesses": self.witnesses,
            "fresh_cosignatures": self.counted,
            "quorum": self.quorum,
            "max_checkpoint_age": self.max_age,
            "freshness": self.freshness,
            # what the operator's card says about the counted witnesses: claims, not facts (AICS-1 §6.3)
            "declared_trust_domains": self.declared_trust_domains,
            "declared_independent_witnesses": self.declared_independent,
            # witnesses the user marked independent (policy init --independent)
            "assessed_independent_witnesses": self.assessed_independent,
        }
        if self.reason:
            d["reason"] = self.reason
        if self.cp:
            d.update(origin=self.cp.origin, size=self.cp.size, root=self.cp.root_b64, note_sha256=self.cp.sha256)
        return d


def _parse(note_text: str) -> tuple[Note | None, Any, NoteCheck | None]:
    try:
        note: Note = parse_note(note_text)
        cp = parse_checkpoint(note.text)
    except ValueError as exc:
        return None, None, NoteCheck(ok=False, error=f"not a signed checkpoint note: {exc}", reason="malformed")
    if cp.extension_lines:
        return None, None, NoteCheck(
            ok=False, reason="malformed",
            error="an AICS checkpoint has exactly three text lines (AICS-1 §6.2); this one has extensions")
    if cp.size > UINT_MAX:
        return None, None, NoteCheck(ok=False, reason="malformed", error="tree size exceeds 2^53-1")
    return note, cp, None


def log_signed(note_text: str, *, origin: str, log_vkey: str, source: str) -> tuple[Cp | None, str | None, str]:
    """Authenticate a note by the log signature alone, under ``log_vkey``
    and ``origin``.  Returns (cp, error, reason)."""
    note, cp, bad = _parse(note_text)
    if bad is not None:
        return None, bad.error, "malformed"
    res = verify_checkpoint(note, parse_log_vkey(log_vkey), [], 0, expected_origin=origin)
    if not res.log_ok:
        reason = "wrong_origin" if res.origin is not None and res.origin != origin else "bad_signature"
        return None, res.error or "checkpoint verification failed", reason
    return Cp(note_text=note_text, origin=cp.origin, size=cp.size, root=cp.root, source=source,
              log_vkey=log_vkey), None, ""


def check_note(
    note_text: str,
    policy: Policy,
    *,
    source: str,
    now: int,
    require_fresh: bool = True,
    max_skew: int = DEFAULT_MAX_SKEW,
) -> NoteCheck:
    """Verify one signed checkpoint note against ``policy``.

    ``require_fresh=False`` counts every valid cosignature regardless of its
    age (for notes judged as historical statements, e.g. gossip evidence).
    """
    note, cp, bad = _parse(note_text)
    if bad is not None:
        return bad
    chk = NoteCheck(ok=False, quorum=policy.quorum, max_age=policy.max_checkpoint_age if require_fresh else None)
    res = verify_checkpoint(note, policy.log_key(), [], 0, expected_origin=policy.origin)
    if not res.log_ok:
        chk.error = res.error or "checkpoint verification failed"
        chk.reason = "wrong_origin" if res.origin is not None and res.origin != policy.origin else "bad_signature"
        return chk
    chk.log_ok = True
    chk.cp = Cp(note_text=note_text, origin=cp.origin, size=cp.size, root=cp.root, source=source,
                log_vkey=policy.log_vkey)

    # Witness accounting: every line under a pinned witness's (name, key ID)
    # must be a valid cosignature of this checkpoint; then age, and each
    # public key counts once.
    invalid: list[str] = []
    counted_keys: set[bytes] = set()
    for wk in policy.witness_keys():
        lines = [s for s in note.signatures if s.name == wk.name and s.key_id == wk.key_id]
        if not lines:
            chk.witnesses.append({"name": wk.name, "status": "absent"})
            continue
        blob = lines[0].signature
        try:
            valid = verify_cosignature(blob, wk.name, wk.public_key, cp.origin, cp.size, cp.root, cp.extension_lines)
        except (ValueError, TypeError):
            valid = False
        if not valid:
            chk.witnesses.append({"name": wk.name, "status": "invalid"})
            invalid.append(wk.name)
            continue
        ts = int.from_bytes(blob[:8], "big")
        entry: dict[str, Any] = {"name": wk.name, "timestamp": ts, "age_seconds": now - ts}
        if require_fresh and ts > now + max_skew:
            entry["status"] = "future"
        elif require_fresh and policy.max_checkpoint_age is not None and now - ts > policy.max_checkpoint_age:
            entry["status"] = "stale"
        elif wk.public_key in counted_keys:
            entry["status"] = "duplicate-key"
        else:
            entry["status"] = "fresh" if require_fresh else "valid"
            counted_keys.add(wk.public_key)
            domain, independent = policy.declared(wk.name)
            if domain:
                chk.declared_trust_domains.append(domain)
            if independent is True:
                chk.declared_independent += 1
            if policy.assessed_independent(wk.name):
                chk.assessed_independent.append(wk.name)
        chk.witnesses.append(entry)
    chk.declared_trust_domains = sorted(set(chk.declared_trust_domains))
    chk.counted = len(counted_keys)
    chk.witness_ok = not invalid and chk.counted >= policy.quorum

    # The verdict, most serious first.
    if cp.size == 0 and cp.root != EMPTY_HASH:
        chk.reason = "bad_empty_root"
        chk.error = ("the log signed a checkpoint of size 0 whose root is not SHA-256(\"\"), which no log can "
                     "produce (AICS-1 §14.2 step 1)")
        return chk
    if invalid:
        chk.reason = "bad_cosignature"
        chk.error = (f"the log signature is valid, but the line under pinned witness {', '.join(invalid)} is not a "
                     "valid cosignature of this checkpoint")
        return chk
    if chk.counted < policy.quorum:
        late = [w for w in chk.witnesses if w["status"] in ("stale", "future")]
        detail = "; ".join(f"{w['name']} {w['status']} (age {w['age_seconds']}s)" for w in late)
        what = "fresh " if require_fresh else ""
        chk.error = f"witness quorum not met: {chk.counted} valid {what}cosignatures < quorum {policy.quorum}"
        if detail:
            chk.error += f": {detail}"
        chk.reason = "quorum"
        return chk
    if not require_fresh:
        chk.freshness = "historical"
    elif policy.quorum == 0:
        chk.freshness = "unproven"
        chk.warnings.append(
            "witness quorum 0: the head carries no authenticated time, so its freshness is unproven, "
            "and single view (G5) is promised, not proven"
        )
    else:
        chk.freshness = "fresh"
        if chk.assessed_independent:
            chk.warnings.append(
                f"single view (G5) rests on your own assessment that {', '.join(chk.assessed_independent)} "
                "is independent and on the honest quorum-intersection assumption (AICS-1 §6.3)"
            )
        elif chk.declared_independent:
            chk.warnings.append(
                f"single view (G5) stays promised: the card declares {chk.declared_independent} counted witness(es) "
                "independent, but independence is the operator's own claim and needs outside assessment "
                "(AICS-1 §6.3); mark a witness you assessed yourself with: aics policy init --independent NAME"
            )
        else:
            chk.warnings.append(
                "no counted witness is independent: single view (G5) stays promised (AICS-1 §6.3)"
            )
    chk.ok = True
    return chk


# ---------------------------------------------------------------------------
# fetching
# ---------------------------------------------------------------------------


@dataclass
class Fetched:
    note_text: str
    url: str
    api_claims: dict[str, Any] = field(default_factory=dict)


_NOTE_FIELDS = ("signed_checkpoint", "checkpoint", "note", "signed_note")
_KEY_FIELDS = ("server_vkey", "log_vkey", "vkey")


def extract_note(body: bytes, url: str) -> Fetched:
    """The response is the signed note itself (c2sp.org/tlog-tiles
    ``/checkpoint``), or JSON carrying it in ``signed_checkpoint`` (the
    current server's ``/v2/tlog/checkpoint``).  Keys found in the JSON are
    recorded only to be compared, never used."""
    from .card import check_json_depth

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise AicsError(f"{url}: checkpoint response is not UTF-8") from None
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            check_json_depth(text, JSON_MAX_DEPTH)
            obj = json.loads(text)
        except RecursionError:
            raise AicsError(f"{url}: invalid JSON: nested too deeply") from None
        except ValueError as exc:
            raise AicsError(f"{url}: invalid JSON: {exc}") from None
        if not isinstance(obj, dict):
            raise AicsError(f"{url}: unexpected JSON")
        for k in _NOTE_FIELDS:
            v = obj.get(k)
            if isinstance(v, str) and "\n\n" in v:
                claims = {kk: obj[kk] for kk in _KEY_FIELDS if isinstance(obj.get(kk), str)}
                return Fetched(note_text=v, url=url, api_claims=claims)
        raise AicsError(f"{url}: JSON response has no signed checkpoint note")
    return Fetched(note_text=text, url=url)


def fetch_checkpoint(fetcher: Fetcher, url: str) -> Fetched:
    resp = fetcher.get(url, max_bytes=NOTE_MAX_BYTES, accept="text/plain, application/json;q=0.5")
    if resp.status != 200:
        raise FetchError(f"{url}: HTTP {resp.status}")
    return extract_note(resp.body, url)


def api_key_warnings(fetched: Fetched, policy: Policy) -> list[str]:
    from .encoding import escape_untrusted

    out: list[str] = []
    for k, v in fetched.api_claims.items():
        if v.strip() != policy.log_vkey:
            out.append(
                f"the API response carries {k}={escape_untrusted(v.strip())!r}, which differs from the pinned log "
                "key; it was ignored (keys are never taken from the API host)"
            )
    return out


# ---------------------------------------------------------------------------
# append-only store
# ---------------------------------------------------------------------------


@dataclass
class Saved:
    path: Path
    created: bool


@dataclass
class SavedNote:
    """A saved note file and the index records that mention it."""

    path: Path
    text: str
    file: str  # path relative to the store root, as the index records it
    records: list[dict[str, Any]] = field(default_factory=list)

    def recorded_log_vkeys(self) -> list[str]:
        """Log keys this note was verified with when it was saved, newest first."""
        out: list[str] = []
        for rec in reversed(self.records):
            v = rec.get("log_vkey")
            if isinstance(v, str) and v not in out:
                out.append(v)
        return out

    def policy_digests(self) -> list[str]:
        out: list[str] = []
        for rec in reversed(self.records):
            v = rec.get("policy_sha256")
            if isinstance(v, str) and v not in out:
                out.append(v)
        return out


class CheckpointStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    @property
    def index(self) -> Path:
        return self.root / "index.jsonl"

    def records(self) -> list[dict[str, Any]]:
        return _home.read_jsonl(self.index)

    def save(self, cp: Cp, *, now: int, role: str = "head", continuity: str | None = None,
             policy: Policy | None = None) -> Saved:
        """Save the exact note bytes (never rewritten) and log the observation
        with the digest of the policy it was verified under and the log key
        (AICS-1 §14.1 step 5)."""
        _home.ensure_dir(self.root)
        path = self.root / _home.slug(cp.origin) / f"{cp.size}-{cp.sha256}.note"
        created = _home.write_new(path, cp.note_text.encode("utf-8"))
        _home.append_jsonl(self.index, {
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "role": role,
            "continuity": continuity,
            "policy_sha256": policy_digest(policy) if policy is not None else None,
            "log_vkey": cp.log_vkey or (policy.log_vkey if policy is not None else None),
            "source": cp.source,
            "origin": cp.origin,
            "size": cp.size,
            "root": cp.root_b64,
            "sha256": cp.sha256,
            "file": str(path.relative_to(self.root)),
            "new": created,
        })
        return Saved(path=path, created=created)

    def reset(self, origin: str, *, now: int, reason: str, files: list[str], policy: Policy | None = None) -> None:
        """Record that ``files`` (relative paths) no longer take part in
        continuity checks for ``origin``.  Nothing is deleted."""
        _home.ensure_dir(self.root)
        _home.append_jsonl(self.index, {
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "role": "reset",
            "origin": origin,
            "reason": reason,
            "dropped": sorted(set(files)),
            "policy_sha256": policy_digest(policy) if policy is not None else None,
        })

    @staticmethod
    def _dropped_after(records: list[dict[str, Any]], origin: str) -> list[set[str]]:
        """For each position i, the files dropped by reset records after i:
        a head record is void once a later reset drops its file (saving the
        same note again later writes a new record, which counts on its own)."""
        out: list[set[str]] = [set() for _ in records]
        acc: set[str] = set()
        for i in range(len(records) - 1, -1, -1):
            out[i] = set(acc)
            rec = records[i]
            if rec.get("role") == "reset" and rec.get("origin") == origin:
                acc |= {str(f) for f in rec.get("dropped") or []}
        return out

    def head(self, origin: str) -> SavedNote | None:
        """The note of the latest ``head`` record for ``origin`` that no
        later reset dropped."""
        recs = self.records()
        dropped = self._dropped_after(recs, origin)
        for i in range(len(recs) - 1, -1, -1):
            rec = recs[i]
            if rec.get("origin") != origin or rec.get("role", "head") != "head":
                continue
            file = str(rec.get("file", ""))
            if not file or file in dropped[i]:
                continue
            p = self.root / file
            try:
                text = p.read_text("utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            return SavedNote(path=p, text=text, file=file, records=[r for r in recs if r.get("file") == file])
        return None

    def notes(self, origin: str) -> list[SavedNote]:
        """Every saved note for ``origin`` that is not dropped by a reset,
        smallest size first."""
        d = self.root / _home.slug(origin)
        if not d.is_dir():
            return []
        recs = self.records()
        by_file: dict[str, list[dict[str, Any]]] = {}
        last: dict[str, str] = {}  # file -> "save" | "reset"
        for rec in recs:
            if rec.get("role") == "reset" and rec.get("origin") == origin:
                for f in rec.get("dropped") or []:
                    last[str(f)] = "reset"
            elif rec.get("file") is not None:
                by_file.setdefault(str(rec["file"]), []).append(rec)
                last[str(rec["file"])] = "save"
        out: list[tuple[int, SavedNote]] = []
        for p in d.glob("*.note"):
            rel = str(p.relative_to(self.root))
            if last.get(rel) == "reset":
                continue
            try:
                size = int(p.name.split("-", 1)[0])
                text = p.read_text("utf-8")
            except (ValueError, OSError, UnicodeDecodeError):
                continue
            out.append((size, SavedNote(path=p, text=text, file=rel, records=by_file.get(rel, []))))
        out.sort(key=lambda t: (t[0], t[1].path.name))
        return [n for _, n in out]

    def count(self, origin: str) -> int:
        return len(self.notes(origin))

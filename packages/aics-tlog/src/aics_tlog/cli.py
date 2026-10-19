"""Command line interface for aics-tlog.

Every subcommand prints exactly one JSON object on stdout and exits 0 on
success, 1 on failure.

Keys: the log verifier key comes only from the caller -- ``--vkey-file``
(a local file obtained out of band: the DNS TXT record, the ``aics`` package
on PyPI, the public README) or ``--log-key``.  It is never read from the
server or the tiles being verified; a key file given as a URL, or stored
inside a tile directory being verified, is refused.

Tiles: ``--tiles`` takes a URL prefix (``https://...``) or a local directory
and may be repeated for mirrors, tried in order.  Without ``--checkpoint`` the
checkpoint is fetched from every source; each is verified with the
out-of-band key, the largest valid one is used, and the others must be
consistent with it.  Tiles are authenticated against that checkpoint before
any proof is computed from them.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import functools
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import url2pathname

from . import __version__
from .bundle import Bundle, _strict_json, bundle_from_tiles, verify_bundle
from .checkpoint import CheckpointVerifyResult, WitnessPolicy, parse_checkpoint, verify_checkpoint
from .hashing import EMPTY_HASH, leaf_hash
from .note import Note, VKey, parse_note, parse_vkey, read_vkey_file
from .remote import HttpTileReader, tile_source_url
from .tiles import (
    TileConflictError,
    TileMissingError,
    TileUnavailableError,
    TileVerificationError,
    TileWriter,
    consistency_proof_from_tiles,
    inclusion_proof_from_tiles,
)
from .tree import verify_consistency, verify_inclusion
from .verified import VerifiedTileReader
from .writer import DirectoryTileStore, IncrementalTileWriter

_PROOF_HELP = "proof file: one hash per line, base64 (or 64 hex chars)"
_BAD_EMPTY_ROOT = (
    "a tree of size 0 has the empty-tree root SHA-256(\"\") (47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=); "
    "this head's root is different (AICS-1 §14.2 step 1)"
)
_MAX_INPUT_BYTES = 32 << 20


class _CliError(Exception):
    """A failure reported as the command's JSON result."""

    def __init__(self, message: str, **extra) -> None:
        super().__init__(message)
        self.extra = extra


def _fail(report: dict, message: str) -> int:
    report["ok"] = False
    report["error"] = message
    print(json.dumps(report))
    return 1


def _succeed(report: dict) -> int:
    report["ok"] = True
    print(json.dumps(report))
    return 0


def _command(name: str):
    """Run a subcommand, turning expected failures into a JSON error report."""

    def deco(fn):
        @functools.wraps(fn)
        def run(args: argparse.Namespace) -> int:
            report: dict = {"cmd": name}
            try:
                return fn(args, report)
            except _CliError as e:
                report.update(e.extra)
                return _fail(report, str(e))
            except (TileMissingError, TileUnavailableError, TileVerificationError, TileConflictError) as e:
                return _fail(report, f"{type(e).__name__}: {e}")
            except (ValueError, OSError, UnicodeDecodeError) as e:
                return _fail(report, f"{type(e).__name__}: {e}")

        return run

    return deco


def _read_input(path: str) -> bytes:
    if path == "-":
        data = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    else:
        with open(path, "rb") as fh:
            data = fh.read(_MAX_INPUT_BYTES + 1)
    if len(data) > _MAX_INPUT_BYTES:
        raise _CliError(f"{path}: input larger than {_MAX_INPUT_BYTES} bytes")
    return data


def _write_atomic(path: str, data: bytes) -> None:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load_checkpoint(path: str):
    """Read a checkpoint file: either bare note text or a full signed note."""
    raw = _read_input(path)
    text = raw.decode("utf-8")
    try:
        return parse_checkpoint(text)
    except ValueError:
        return parse_checkpoint(_parse_note_input(raw).text)


def _parse_note_input(raw: bytes) -> Note:
    """A signed checkpoint note, given as note text or as a JSON object with
    a ``signed_checkpoint`` / ``checkpoint_note`` field.  Any key a JSON
    wrapper carries (e.g. ``server_vkey``) is ignored."""
    text = raw.decode("utf-8")
    if text.lstrip().startswith("{"):
        try:
            obj = json.loads(text)
        except ValueError as e:
            raise _CliError(f"checkpoint file is neither a signed note nor JSON: {e}") from None
        for field_name in ("signed_checkpoint", "checkpoint_note", "checkpoint"):
            if isinstance(obj, dict) and isinstance(obj.get(field_name), str):
                return parse_note(obj[field_name])
        raise _CliError("JSON checkpoint file has no signed_checkpoint or checkpoint_note field")
    return parse_note(text)


def _read_hashes(path: str) -> list[bytes]:
    """Read a proof file: one hash per line, base64 or 64 hex chars."""
    out: list[bytes] = []
    raw = _read_input(path).decode("utf-8")
    for lineno, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            if len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
                out.append(bytes.fromhex(line))
            else:
                blob = base64.b64decode(line, validate=True)
                if base64.b64encode(blob).decode() != line:
                    raise ValueError("non-canonical base64")
                out.append(blob)
        except (ValueError, binascii.Error) as e:
            raise ValueError(f"proof line {lineno}: {e}") from None
        if len(out[-1]) != 32:
            raise ValueError(f"proof line {lineno}: hash must be 32 bytes")
    return out


def _b64(data: bytes | None) -> str | None:
    return base64.b64encode(data).decode() if data is not None else None


def _leaf_from_args(args: argparse.Namespace, report: dict) -> tuple[bytes | None, bytes | None]:
    """(entry bytes or None, leaf hash or None) from --leaf / --leaf-hash / --leaf-line."""
    if args.leaf_hash:
        try:
            h = bytes.fromhex(args.leaf_hash)
        except ValueError:
            raise _CliError("--leaf-hash must be 64 hex characters") from None
        if len(h) != 32:
            raise _CliError("--leaf-hash must be 64 hex characters")
        return None, h
    if args.leaf is not None:
        entry = _read_input(args.leaf)
        return entry, leaf_hash(entry)
    if args.leaf_line is not None:
        if args.leaves_file is None:
            raise _CliError("--leaf-line requires --leaves-file")
        lines = _read_input(args.leaves_file).decode("utf-8").split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        if not 1 <= args.leaf_line <= len(lines):
            raise _CliError(f"--leaf-line must be between 1 and {len(lines)}")
        report["leaf_line"] = args.leaf_line
        entry = lines[args.leaf_line - 1].encode("utf-8")
        return entry, leaf_hash(entry)
    return None, None


# ---------------------------------------------------------------------------
# Keys, witnesses and checkpoints
# ---------------------------------------------------------------------------


def _source_guards(sources: list[str]) -> tuple[set[str], list[Path]]:
    hosts: set[str] = set()
    dirs: list[Path] = []
    for url in sources:
        parts = urlsplit(url)
        if parts.scheme in ("http", "https") and parts.hostname:
            hosts.add(parts.hostname.lower())
        elif parts.scheme == "file":
            dirs.append(Path(url2pathname(parts.path)).resolve())
    return hosts, dirs


def _load_log_key(args: argparse.Namespace, sources: list[str] = (), data_files=(), report: dict | None = None) -> VKey:
    """The out-of-band log key from --vkey-file (repeatable) or --log-key.

    Refuses a key file that would come from the server being verified: one
    given as a URL (refused outright, with the reason spelled out when its
    host is a tile source), one stored inside a local tile directory, or one
    that is the very file holding the checkpoint or bundle.  Several key
    files (say the DNS TXT record, the PyPI constant and the README, each
    saved locally) must all name the same key.
    """
    vkey_files = list(getattr(args, "vkey_file", None) or [])
    log_key = getattr(args, "log_key", None)
    if vkey_files and log_key:
        raise _CliError("give either --vkey-file or --log-key, not both")
    if log_key:
        try:
            key = parse_vkey(log_key.strip())
        except ValueError as e:
            raise _CliError(f"cannot parse key: {e}") from None
        if report is not None:
            report["log_key"] = f"{key.name}+{key.key_id.hex()}"
            report["key_sources"] = ["--log-key"]
        return key
    if not vkey_files:
        raise _CliError(
            "an out-of-band log key is required: --vkey-file FILE (from the DNS TXT record, "
            "the aics package on PyPI or the public README) or --log-key VKEY"
        )
    keys = [_read_key_file(f, sources, data_files) for f in vkey_files]
    first = keys[0]
    for f, k in zip(vkey_files[1:], keys[1:], strict=True):
        if k != first:
            raise _CliError(
                f"out-of-band key sources disagree: {vkey_files[0]} names {first.name}+{first.key_id.hex()}, "
                f"{f} names {k.name}+{k.key_id.hex()}"
            )
    if report is not None:
        report["log_key"] = f"{first.name}+{first.key_id.hex()}"
        report["key_sources"] = vkey_files
    return first


def _read_key_file(vkey_file: str, sources, data_files) -> VKey:
    hosts, tile_dirs = _source_guards(list(sources))
    parts = urlsplit(vkey_file)
    scheme = parts.scheme.lower()
    if scheme in ("http", "https", "ftp", "ftps"):
        host = (parts.hostname or "").lower()
        if host and host in hosts:
            raise _CliError(
                f"refusing --vkey-file {vkey_file}: it would be delivered by {host}, the server being "
                "verified; obtain the key out of band and pass a local file"
            )
        raise _CliError("--vkey-file must be a local file obtained out of band; keys are never fetched over the network")
    local = url2pathname(parts.path) if scheme == "file" else vkey_file
    if local != "-":
        path = Path(local).expanduser().resolve()
        for d in tile_dirs:
            if path == d or d in path.parents:
                raise _CliError(
                    f"refusing --vkey-file {vkey_file}: it lies inside the tile directory {d}, which is "
                    "delivered by the server being verified"
                )
        for f in data_files:
            if f and f != "-" and Path(f).expanduser().resolve() == path:
                raise _CliError(f"refusing --vkey-file {vkey_file}: it is the same file as the data being verified")
    try:
        return read_vkey_file(_read_input(local).decode("utf-8"))
    except ValueError as e:
        raise _CliError(f"cannot parse key file {vkey_file}: {e}") from None


def _witness_config(args: argparse.Namespace) -> dict:
    policy = None
    quorum = args.quorum
    witness_keys: list[VKey] = []
    if args.policy_file:
        if args.witness_key or quorum is not None:
            raise _CliError("--policy-file replaces --witness-key and --quorum; give one or the other")
        try:
            policy = WitnessPolicy.from_json(_read_input(args.policy_file))
        except ValueError as e:
            raise _CliError(f"invalid witness policy: {e}") from None
    else:
        try:
            witness_keys = [parse_vkey(k.strip()) for k in args.witness_key]
        except ValueError as e:
            raise _CliError(f"cannot parse key: {e}") from None
        quorum = quorum or 0
        if quorum < 0:
            raise _CliError("--quorum must be non-negative")
    for name in ("max_age", "max_future"):
        value = getattr(args, name, None)
        if value is not None and value < 0:
            raise _CliError(f"--{name.replace('_', '-')} must be non-negative")
    return {
        "policy": policy,
        "witness_keys": witness_keys,
        "quorum": quorum or 0,
        "max_age": args.max_age,
        "max_future": args.max_future,
        "origin": args.origin,
    }


def _verify_note(note: Note, log_key: VKey, wc: dict, *, fresh: bool = True) -> CheckpointVerifyResult:
    """Verify a checkpoint note under the witness configuration.  With
    ``fresh=False`` the freshness bounds are dropped (signatures, quorum and
    origin still apply): what is needed to use a note as evidence."""
    policy = wc["policy"]
    if not fresh and policy is not None and policy.max_age_seconds is not None:
        policy = WitnessPolicy(policy.quorum, policy.witnesses, None)
    return verify_checkpoint(
        note,
        log_key,
        None if policy else wc["witness_keys"],
        0 if policy else wc["quorum"],
        expected_origin=wc["origin"],
        max_age_seconds=wc["max_age"] if fresh else None,
        max_future_seconds=wc["max_future"] if fresh else None,
        policy=policy,
    )


def _cp_report(res: CheckpointVerifyResult) -> dict:
    out = {
        "origin": res.origin,
        "size": res.size,
        "root": _b64(res.root),
        "log_ok": res.log_ok,
        "cosignatures": res.cosignature_count,
        "witnesses": res.witnesses,
        "quorum": res.quorum,
    }
    if res.max_age_seconds is not None:
        out["max_age"] = res.max_age_seconds
    if res.stale:
        out["stale"] = res.stale
    if res.future:
        out["future"] = res.future
    return out


def _make_reader(args: argparse.Namespace, sources: list[str]) -> HttpTileReader:
    return HttpTileReader(sources, timeout=args.timeout)


def _use_cache(reader: HttpTileReader, args: argparse.Namespace, origin: str | None) -> None:
    """Point the reader's cache at <cache-dir>/<hash of origin>/ (one per log)."""
    if args.cache_dir and origin:
        ns = hashlib.sha256(origin.encode("utf-8")).hexdigest()[:16]
        reader.cache_dir = Path(args.cache_dir).expanduser() / ns


def _checkpoint_from_sources(reader: HttpTileReader, log_key: VKey, wc: dict):
    """Fetch every source's checkpoint and choose the head.

    Every note that is validly signed (and cosigned, if witnesses are
    required) counts, fresh or not: two of them with the same size and
    different roots prove a split view.  The head is the largest of them,
    and only then must it be fresh -- a smaller fresh head is never accepted
    while a source still serves a larger signed one (a rollback).

    Returns (note, result, signed, seen): ``signed`` lists every such
    (note, result, source); ``seen`` is the per-source report.
    """
    seen: list[dict] = []
    signed: list[tuple[Note, CheckpointVerifyResult, str]] = []
    for fetched in reader.fetch_checkpoints():
        entry: dict = {"source": fetched.source}
        seen.append(entry)
        if fetched.data is None:
            entry["error"] = fetched.error
            continue
        try:
            note = parse_note(fetched.data)
        except ValueError as e:
            entry["error"] = f"not a signed note: {e}"
            continue
        res = _verify_note(note, log_key, wc, fresh=False)
        entry.update(size=res.size, ok=res.ok)
        if not res.ok:
            entry["error"] = res.error
            continue
        signed.append((note, res, fetched.source))
    if not signed:
        raise _CliError("no tile source served a checkpoint that verifies with the out-of-band key", sources=seen)
    by_size: dict[int, tuple[Note, CheckpointVerifyResult, str]] = {}
    for note, res, src in signed:
        assert res.size is not None
        prev = by_size.get(res.size)
        if prev is not None and prev[1].root != res.root:
            raise _CliError(
                f"split view: {prev[2]} and {src} serve validly signed checkpoints of size {res.size} "
                "with different roots",
                sources=seen,
                evidence=[prev[0].serialise(), note.serialise()],
            )
        by_size.setdefault(res.size, (note, res, src))
    head_note, _, head_src = max(signed, key=lambda v: v[1].size or 0)
    head = _verify_note(head_note, log_key, wc, fresh=True)
    if not head.ok:
        for entry in seen:
            if entry["source"] == head_src:
                entry.update(ok=False, error=head.error)
        raise _CliError(
            f"checkpoint: the largest validly signed checkpoint (size {head.size}, from {head_src}) "
            f"fails: {head.error}",
            sources=seen,
        )
    return head_note, head, signed, seen


def _cross_check(signed, chosen_note: Note, chosen: CheckpointVerifyResult, vr: VerifiedTileReader) -> None:
    """Every smaller signed checkpoint must be a prefix of the chosen one."""
    assert chosen.size is not None and chosen.root is not None
    for note, res, src in signed:
        assert res.size is not None and res.root is not None
        if res.size >= chosen.size:
            continue
        proof = consistency_proof_from_tiles(vr, res.size, chosen.size)
        if not verify_consistency(res.size, chosen.size, res.root, chosen.root, proof):
            raise _CliError(
                f"split view: the checkpoint of size {res.size} from {src} is not consistent with "
                f"the checkpoint of size {chosen.size}",
                evidence=[note.serialise(), chosen_note.serialise()],
            )


def _resolve_head(args, report, reader, log_key, wc, checkpoint_path):
    """The verified head for tiles mode: (note, result, VerifiedTileReader)."""
    if checkpoint_path:
        note = _parse_note_input(_read_input(checkpoint_path))
        res = _verify_note(note, log_key, wc)
        valid: list = []
    else:
        report["sources"] = []
        note, res, valid, seen = _checkpoint_from_sources(reader, log_key, wc)
        report["sources"] = seen
    report.update(_cp_report(res))
    if not res.ok:
        raise _CliError(f"checkpoint: {res.error}")
    assert res.size is not None and res.root is not None
    _use_cache(reader, args, res.origin)
    vr = VerifiedTileReader(reader, res.size, res.root)
    if valid:
        _cross_check(valid, note, res, vr)
    return note, res, vr


# ---------------------------------------------------------------------------
# verify-checkpoint
# ---------------------------------------------------------------------------


@_command("verify-checkpoint")
def cmd_verify_checkpoint(args: argparse.Namespace, report: dict) -> int:
    sources = [tile_source_url(t) for t in args.tiles]
    if args.note is None and not sources:
        raise _CliError("provide --note FILE or --tiles URL_OR_DIR")
    log_key = _load_log_key(args, sources, [args.note], report)
    wc = _witness_config(args)
    if sources:
        reader = _make_reader(args, sources)
        note, res, vr = _resolve_head(args, report, reader, log_key, wc, args.note)
        vr.check_root()
        report["tiles_ok"] = True
    else:
        try:
            note = _parse_note_input(_read_input(args.note))
        except (ValueError, UnicodeDecodeError, OSError) as e:
            raise _CliError(f"cannot parse note: {e}") from None
        res = _verify_note(note, log_key, wc)
        report.update(_cp_report(res))
        if not res.ok:
            return _fail(report, res.error or "verification failed")
    if args.save_checkpoint:
        _write_atomic(args.save_checkpoint, note.to_bytes())
        report["saved"] = args.save_checkpoint
    return _succeed(report)


# ---------------------------------------------------------------------------
# verify-inclusion
# ---------------------------------------------------------------------------


@_command("verify-inclusion")
def cmd_verify_inclusion(args: argparse.Namespace, report: dict) -> int:
    given = [args.leaf is not None, bool(args.leaf_hash), args.leaf_line is not None]
    if sum(given) > 1:
        raise _CliError("provide at most one of --leaf FILE, --leaf-hash HEX or --leaf-line N (--leaves-file)")
    sources = [tile_source_url(t) for t in args.tiles]
    if not sources:
        return _verify_inclusion_with_proof(args, report, sum(given))

    if args.proof is not None:
        raise _CliError("with --tiles the proof is computed from the tiles; drop --proof")
    if args.size is not None or args.root is not None:
        raise _CliError("with --tiles the size and root come from the verified checkpoint; drop --size/--root")
    log_key = _load_log_key(args, sources, [args.checkpoint, args.leaf, args.leaves_file, args.bundle_out], report)
    wc = _witness_config(args)
    entry, h = _leaf_from_args(args, report)
    reader = _make_reader(args, sources)
    note, res, vr = _resolve_head(args, report, reader, log_key, wc, args.checkpoint)
    size, root = res.size, res.root
    assert size is not None and root is not None
    if not 0 <= args.index < size:
        raise _CliError(f"index {args.index} is not below the checkpoint size {size}")
    if h is None:
        entry = vr.entry(args.index)  # proven against the checkpoint
        h = leaf_hash(entry)
    proof = inclusion_proof_from_tiles(vr, args.index, size)
    ok = verify_inclusion(h, args.index, size, proof, root)
    report.update(index=args.index, leaf_hash=h.hex(), proof_length=len(proof))
    if entry is not None:
        report["entry_sha256"] = hashlib.sha256(entry).hexdigest()
    if not ok:
        return _fail(report, "the leaf is not included at this index under the checkpoint")
    if args.entry_out or args.bundle_out:
        if entry is None:
            entry = vr.entry(args.index)
    if args.entry_out:
        _write_atomic(args.entry_out, entry)
        report["entry_out"] = args.entry_out
    if args.bundle_out:
        envelope = None
        if args.envelope:
            try:
                envelope = _strict_json(_read_input(args.envelope))
            except ValueError as e:
                raise _CliError(f"--envelope is not JSON: {e}") from None
        body = _read_input(args.body) if args.body else None
        # The AICS-1 §14.3 wire bundle; without --envelope it carries the
        # envelope an AICS-1 entry embeds.
        bundle = bundle_from_tiles(vr, args.index, note, entry=entry, envelope=envelope, body_or_ct=body)
        # Never hand out a bundle that would not verify offline (for example
        # an envelope or body the entry does not commit to).
        check = verify_bundle(bundle, log_key)
        if not check.ok:
            raise _CliError(f"not writing --bundle-out: the bundle would not verify: {check.error}")
        report.update(envelope=check.envelope_bound_at, body=check.body_bound_at)
        _write_atomic(args.bundle_out, bundle.to_json().encode("utf-8"))
        report["bundle_out"] = args.bundle_out
    if args.save_checkpoint:
        _write_atomic(args.save_checkpoint, note.to_bytes())
        report["saved"] = args.save_checkpoint
    return _succeed(report)


def _verify_inclusion_with_proof(args: argparse.Namespace, report: dict, n_given: int) -> int:
    """Classic mode: a proof file checked against a root (no tiles)."""
    if n_given != 1:
        raise _CliError("provide exactly one of --leaf FILE, --leaf-hash HEX or --leaf-line N (--leaves-file)")
    if args.proof is None:
        raise _CliError("provide --proof FILE, or --tiles to compute the proof from tiles")
    try:
        entry, h = _leaf_from_args(args, report)
        proof = _read_hashes(args.proof)
        if args.checkpoint:
            if args.vkey_file or args.log_key:
                log_key = _load_log_key(args, [], [args.checkpoint, args.leaf, args.leaves_file], report)
                note = _parse_note_input(_read_input(args.checkpoint))
                res = _verify_note(note, log_key, _witness_config(args))
                if not res.ok:
                    report.update(_cp_report(res))
                    return _fail(report, f"checkpoint: {res.error}")
                size, root = res.size, res.root
                report["checkpoint_verified"] = True
            else:
                cp = _load_checkpoint(args.checkpoint)
                size, root = cp.size, cp.root
                report["checkpoint_verified"] = False
        else:
            if args.size is None or args.root is None:
                return _fail(report, "provide --checkpoint FILE or both --size and --root")
            size, root = args.size, base64.b64decode(args.root, validate=True)
            if len(root) != 32:
                return _fail(report, "root must be 32 bytes")
            report["checkpoint_verified"] = False
    except (ValueError, UnicodeDecodeError, OSError, binascii.Error) as e:
        return _fail(report, f"invalid input: {e}")
    assert h is not None
    ok = verify_inclusion(h, args.index, size, proof, root)
    report.update(index=args.index, size=size, root=_b64(root))
    if not ok:
        return _fail(report, "inclusion proof does not verify")
    return _succeed(report)


# ---------------------------------------------------------------------------
# verify-consistency
# ---------------------------------------------------------------------------


@_command("verify-consistency")
def cmd_verify_consistency(args: argparse.Namespace, report: dict) -> int:
    sources = [tile_source_url(t) for t in args.tiles]
    if not sources:
        return _verify_consistency_with_proof(args, report)
    if args.proof is not None:
        raise _CliError("with --tiles the proof is computed from the tiles; drop --proof")
    if args.new_size is not None or args.new_root is not None:
        raise _CliError("with --tiles the new head is the verified checkpoint; drop --new-size/--new-root")
    log_key = _load_log_key(args, sources, [args.old_checkpoint, args.checkpoint], report)
    wc = _witness_config(args)

    old_note = None
    if args.old_checkpoint:
        if args.old_size is not None or args.old_root is not None:
            raise _CliError("give --old-checkpoint or --old-size/--old-root, not both")
        old_note = _parse_note_input(_read_input(args.old_checkpoint))
        # A saved checkpoint: its log signature must verify; its cosignatures
        # are naturally old, so no witness or freshness rule applies to it.
        old_res = verify_checkpoint(old_note, log_key, [], 0, expected_origin=args.origin)
        if not old_res.ok:
            raise _CliError(f"old checkpoint: {old_res.error}")
        old_size, old_root, old_origin = old_res.size, old_res.root, old_res.origin
    elif args.old_size is not None and args.old_root is not None:
        old_size, old_origin = args.old_size, None
        try:
            old_root = base64.b64decode(args.old_root, validate=True)
        except (ValueError, binascii.Error):
            raise _CliError("--old-root must be base64") from None
        if len(old_root) != 32:
            raise _CliError("--old-root must be 32 bytes")
        if old_size < 0:
            raise _CliError("--old-size must be non-negative")
    else:
        raise _CliError("provide --old-checkpoint FILE (a checkpoint you saved) or --old-size and --old-root")
    assert old_size is not None and old_root is not None

    reader = _make_reader(args, sources)
    note, res, vr = _resolve_head(args, report, reader, log_key, wc, args.checkpoint)
    new_size, new_root = res.size, res.root
    assert new_size is not None and new_root is not None
    report.update(old_size=old_size, old_root=_b64(old_root), new_size=new_size, new_root=_b64(new_root))
    evidence = [old_note.serialise(), note.serialise()] if old_note is not None else None
    if old_origin is not None and old_origin != res.origin:
        raise _CliError(f"origin mismatch: saved checkpoint is for {old_origin!r}, the source serves {res.origin!r}")
    if old_size > new_size:
        raise _CliError(
            f"the verified checkpoint (size {new_size}) is older than the saved one (size {old_size}): "
            "a rollback, or every source lags",
            **({"evidence": evidence} if evidence else {}),
        )
    if old_size == 0 and old_root != EMPTY_HASH:
        # AICS-1 §14.2 step 1: a tree of size 0 has exactly one root.
        if evidence:
            report["evidence"] = evidence
        return _fail(report, _BAD_EMPTY_ROOT)
    proof: list[bytes] = consistency_proof_from_tiles(vr, old_size, new_size) if 0 < old_size < new_size else []
    ok = verify_consistency(old_size, new_size, old_root, new_root, proof)
    report["proof_length"] = len(proof)
    if not ok:
        if evidence:
            report["evidence"] = evidence
        return _fail(report, "the new checkpoint does not extend the old one: history was rewritten")
    if args.save_checkpoint:
        _write_atomic(args.save_checkpoint, note.to_bytes())
        report["saved"] = args.save_checkpoint
    return _succeed(report)


def _verify_consistency_with_proof(args: argparse.Namespace, report: dict) -> int:
    """Classic mode: a proof file between two given heads (no tiles)."""
    missing = [
        flag
        for flag, value in (
            ("--old-size", args.old_size),
            ("--new-size", args.new_size),
            ("--old-root", args.old_root),
            ("--new-root", args.new_root),
            ("--proof", args.proof),
        )
        if value is None
    ]
    if missing:
        raise _CliError(f"missing {', '.join(missing)} (or use --tiles with --old-checkpoint)")
    try:
        proof = _read_hashes(args.proof)
        old_root = base64.b64decode(args.old_root, validate=True)
        new_root = base64.b64decode(args.new_root, validate=True)
        if len(old_root) != 32 or len(new_root) != 32:
            return _fail(report, "roots must be 32 bytes")
    except (ValueError, binascii.Error, OSError) as e:
        return _fail(report, f"invalid input: {e}")
    ok = verify_consistency(args.old_size, args.new_size, old_root, new_root, proof)
    report.update(old_size=args.old_size, new_size=args.new_size, old_root=args.old_root, new_root=args.new_root)
    if not ok:
        empty = [(size, root) for size, root in ((args.old_size, old_root), (args.new_size, new_root)) if size == 0]
        if any(root != EMPTY_HASH for _, root in empty):
            return _fail(report, _BAD_EMPTY_ROOT)
        if args.old_size == 0 and proof:
            return _fail(report, "a consistency proof from size 0 must be empty (AICS-1 §14.2 step 1)")
        return _fail(report, "consistency proof does not verify")
    return _succeed(report)


# ---------------------------------------------------------------------------
# verify-bundle
# ---------------------------------------------------------------------------


@_command("verify-bundle")
def cmd_verify_bundle(args: argparse.Namespace, report: dict) -> int:
    if args.offline and args.tiles:
        raise _CliError("--offline uses only the bundle and the out-of-band key; drop --tiles")
    sources = [tile_source_url(t) for t in args.tiles]
    raw = _read_input(args.bundle)
    try:
        # The AICS-1 §14.3 wire bundle: exactly its six members (a member it
        # does not define, keys included, is refused, never used).
        bundle = Bundle.from_json(raw)
    except ValueError as e:
        raise _CliError(f"not an AICS-1 §14.3 wire bundle: {e}") from None
    log_key = _load_log_key(args, sources, [args.bundle], report)
    wc = _witness_config(args)
    policy = wc["policy"]
    # Offline, --max-age applies to the bundle's checkpoint if asked for.
    # Online, freshness is checked on today's head instead: the bundle's
    # checkpoint is old by nature.
    res = verify_bundle(
        bundle,
        log_key,
        None if policy else wc["witness_keys"],
        0 if policy else wc["quorum"],
        policy=policy,
        expected_origin=wc["origin"],
        max_age_seconds=None if sources else wc["max_age"],
        max_future_seconds=wc["max_future"],
    )
    report.update(
        offline=not sources,
        index=bundle.index,
        size=res.size,
        origin=res.origin,
        root=_b64(res.root),
        leaf_hash=res.leaf_hash.hex() if res.leaf_hash else None,
        entry_sha256=res.entry_sha256.hex() if res.entry_sha256 else None,
        envelope=res.envelope_bound_at,
        body=res.body_bound_at,
        aics1_entry=res.aics1_entry,
    )
    if res.checkpoint is not None:
        report.update(
            cosignatures=res.checkpoint.cosignature_count,
            witnesses=res.checkpoint.witnesses,
            quorum=res.checkpoint.quorum,
        )
    if res.notes:
        report["notes"] = res.notes
    if not res.ok:
        return _fail(report, res.error or "bundle does not verify")
    if sources:
        # Online extension: the bundle's checkpoint must be a prefix of the
        # log the sources serve today.
        assert res.size is not None and res.root is not None
        head_report: dict = {}
        reader = _make_reader(args, sources)
        head_note, head, vr = _resolve_head(args, head_report, reader, log_key, wc, None)
        assert head.size is not None and head.root is not None
        report["latest_size"] = head.size
        if "sources" in head_report:
            report["sources"] = head_report["sources"]
        if head.origin != res.origin:
            raise _CliError(f"origin mismatch: bundle is for {res.origin!r}, the sources serve {head.origin!r}")
        if head.size < res.size:
            raise _CliError(
                f"the sources serve size {head.size}, older than the bundle's checkpoint (size {res.size})",
                evidence=[bundle.checkpoint_note, head_note.serialise()],
            )
        proof = consistency_proof_from_tiles(vr, res.size, head.size)
        if not verify_consistency(res.size, head.size, res.root, head.root, proof):
            raise _CliError(
                "the bundle's checkpoint is not a prefix of the log served today",
                evidence=[bundle.checkpoint_note, head_note.serialise()],
            )
        report["still_in_log"] = True
    return _succeed(report)


# ---------------------------------------------------------------------------
# build-tiles / append-tiles
# ---------------------------------------------------------------------------


def _read_leaves(path: str, zero: bool) -> list[bytes]:
    raw = _read_input(path)
    if zero:
        leaves = raw.split(b"\n")
        if leaves and leaves[-1] == b"":
            leaves.pop()  # trailing newline is not an extra entry
        return leaves
    lines = raw.decode("utf-8").split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # trailing newline is not an extra entry
    return [line.encode("utf-8") for line in lines]


@_command("build-tiles")
def cmd_build_tiles(args: argparse.Namespace, report: dict) -> int:
    try:
        leaves = _read_leaves(args.leaves, args.zero)
    except (UnicodeDecodeError, OSError) as e:
        return _fail(report, f"cannot read leaves: {e}")
    try:
        writer = TileWriter(leaves)
        paths = writer.write_to(args.out)
    except OSError as e:
        return _fail(report, f"cannot write tiles: {e}")

    from .tiles import MemoryTileReader, tree_root_from_tiles

    root = tree_root_from_tiles(MemoryTileReader(writer.materialise()), len(leaves))
    report.update(size=len(leaves), root=_b64(root), tiles=len(paths), out=str(args.out))
    return _succeed(report)


@_command("append-tiles")
def cmd_append_tiles(args: argparse.Namespace, report: dict) -> int:
    if args.size < 0:
        raise _CliError("--size must be non-negative")
    leaves = _read_leaves(args.leaves, args.zero)
    store = DirectoryTileStore(args.out, fsync=not args.no_fsync)
    writer = IncrementalTileWriter(store, args.size, prune_partials=not args.keep_partials)
    result = writer.append(leaves)
    report.update(
        old_size=result.old_size,
        size=result.size,
        root=_b64(result.root),
        written=len(result.written),
        pruned=len(result.pruned),
        out=str(args.out),
    )
    return _succeed(report)


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def _add_key_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--vkey-file",
        action="append",
        default=[],
        help="local file holding the log vkey, obtained out of band (DNS TXT, the aics PyPI package, "
        "the public README); never a URL or a file served with the tiles; repeat to require that "
        "several sources agree",
    )
    p.add_argument("--log-key", default=None, help="log vkey given inline (alternative to --vkey-file)")


def _add_witness_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--witness-key", action="append", default=[], help="witness cosignature vkey (repeatable)")
    p.add_argument("--quorum", type=int, default=None, help="required valid fresh cosignatures (default 0)")
    p.add_argument(
        "--policy-file",
        default=None,
        help="witness policy JSON {quorum >= 1, witnesses: [vkeys], max_checkpoint_age}",
    )
    p.add_argument("--max-age", type=int, default=None, metavar="SECONDS",
                   help="reject cosignatures older than this (freshness)")
    p.add_argument("--max-future", type=int, default=None, metavar="SECONDS",
                   help="reject cosignatures dated further ahead than this "
                   "(default 30 with --max-age: AICS-1 §6.3, timestamp <= now + 30)")
    p.add_argument("--origin", default=None, help="expected origin line")


def _add_tiles_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--tiles", action="append", default=[], metavar="URL_OR_DIR",
                   help="tlog-tiles URL prefix or local directory; repeat for mirrors (tried in order)")
    p.add_argument("--cache-dir", default=None, help="cache authenticated full tiles here (one subdirectory per log)")
    p.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aics-tlog",
        description="Verifier/builder for C2SP transparency logs "
        "(c2sp.org/tlog-tiles, tlog-checkpoint, signed-note, tlog-cosignature).",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("verify-checkpoint", help="verify a signed checkpoint note (from a file or the tiles)")
    p.add_argument("--note", default=None, help="signed note file ('-' for stdin); default: fetch from --tiles")
    _add_key_args(p)
    _add_witness_args(p)
    _add_tiles_args(p)
    p.add_argument("--save-checkpoint", default=None, metavar="FILE", help="save the verified note here")
    p.set_defaults(func=cmd_verify_checkpoint)

    p = sub.add_parser("verify-inclusion", help="verify that a leaf is in the log")
    p.add_argument("--leaf", default=None, help="raw leaf data file ('-' for stdin)")
    p.add_argument("--leaf-hash", default=None, help="leaf hash as hex")
    p.add_argument("--leaf-line", type=int, default=None, metavar="N",
                   help="use line N (1-based, newline stripped) of --leaves-file as the leaf")
    p.add_argument("--leaves-file", default=None, help="the leaves file for --leaf-line")
    p.add_argument("--index", type=int, required=True, help="leaf index")
    p.add_argument("--size", type=int, default=None, help="tree size (proof-file mode)")
    p.add_argument("--root", default=None, help="root hash, base64 (proof-file mode)")
    p.add_argument("--checkpoint", default=None,
                   help="checkpoint file; with --tiles a signed note verified with the out-of-band key")
    p.add_argument("--proof", default=None, help=_PROOF_HELP + " (proof-file mode)")
    _add_key_args(p)
    _add_witness_args(p)
    _add_tiles_args(p)
    p.add_argument("--entry-out", default=None, metavar="FILE", help="write the proven entry bytes here")
    p.add_argument("--bundle-out", default=None, metavar="FILE",
                   help="write an offline bundle here (the AICS-1 §14.3 wire form)")
    p.add_argument("--envelope", default=None, metavar="FILE",
                   help="envelope JSON to put in the bundle (default: the envelope an AICS-1 entry embeds)")
    p.add_argument("--body", default=None, metavar="FILE", help="body or ciphertext bytes to put in the bundle")
    p.add_argument("--save-checkpoint", default=None, metavar="FILE", help="save the verified note here")
    p.set_defaults(func=cmd_verify_inclusion)

    p = sub.add_parser("verify-consistency", help="verify that the log only grew (append-only)")
    p.add_argument("--old-size", type=int, default=None)
    p.add_argument("--new-size", type=int, default=None)
    p.add_argument("--old-root", default=None, help="old root hash, base64")
    p.add_argument("--new-root", default=None, help="new root hash, base64 (proof-file mode)")
    p.add_argument("--proof", default=None, help=_PROOF_HELP + " (proof-file mode)")
    p.add_argument("--old-checkpoint", default=None, metavar="FILE",
                   help="a signed checkpoint saved earlier (tiles mode)")
    p.add_argument("--checkpoint", default=None, metavar="FILE",
                   help="the new signed checkpoint (tiles mode; default: fetch from --tiles)")
    _add_key_args(p)
    _add_witness_args(p)
    _add_tiles_args(p)
    p.add_argument("--save-checkpoint", default=None, metavar="FILE", help="save the verified new note here")
    p.set_defaults(func=cmd_verify_consistency)

    p = sub.add_parser("verify-bundle", help="verify an offline bundle (entry, proof, signed checkpoint)")
    p.add_argument("--bundle", required=True, help="AICS-1 §14.3 wire bundle JSON file ('-' for stdin)")
    p.add_argument("--offline", action="store_true", help="use only the bundle and the out-of-band key")
    _add_key_args(p)
    _add_witness_args(p)
    _add_tiles_args(p)
    p.set_defaults(func=cmd_verify_bundle)

    p = sub.add_parser(
        "build-tiles",
        help="build tiles + entry bundles from newline-separated leaf data (full rebuild)",
    )
    p.add_argument("--leaves", required=True, help="file of newline-separated entries ('-' for stdin)")
    p.add_argument("--out", required=True, help="output directory")
    p.add_argument("--zero", action="store_true",
                   help="split on raw newlines without decoding UTF-8")
    p.set_defaults(func=cmd_build_tiles)

    p = sub.add_parser("append-tiles", help="append leaves to an existing tile directory (incremental)")
    p.add_argument("--out", required=True, help="tile directory")
    p.add_argument("--size", type=int, required=True, help="current tree size of the directory (0 if new)")
    p.add_argument("--leaves", required=True, help="file of newline-separated entries to append ('-' for stdin)")
    p.add_argument("--zero", action="store_true", help="split on raw newlines without decoding UTF-8")
    p.add_argument("--keep-partials", action="store_true", help="keep partial tiles once their tile is full")
    p.add_argument("--no-fsync", action="store_true", help="skip fsync (faster, not crash safe)")
    p.set_defaults(func=cmd_append_tiles)

    return parser


_VALUE_OPTS = ("--leaf", "--note", "--leaves", "--proof", "--bundle", "--checkpoint", "--vkey-file")


def _normalise_stdin_args(argv: list[str]) -> list[str]:
    """Rewrite '--opt -' to '--opt=-'.

    Newer argparse versions refuse to use a bare '-' as an option value, but
    '-' is our stdin convention; the '=' form always works.
    """
    out: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in _VALUE_OPTS and i + 1 < len(argv) and argv[i + 1] == "-":
            out.append(tok + "=-")
            i += 2
        else:
            out.append(tok)
            i += 1
    return out


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(_normalise_stdin_args(list(sys.argv[1:] if argv is None else argv)))
    try:
        return args.func(args)
    except BrokenPipeError:  # pragma: no cover
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

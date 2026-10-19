"""aics-witness command line.

::

    aics-witness init    --config witness.json --name witness.example.org/w1
    aics-witness add-log --config witness.json --origin <origin> --vkey <log vkey>
    aics-witness serve   --config witness.json
    aics-witness status  --config witness.json [--json]
    aics-witness evidence --config witness.json [--origin <origin>]
    aics-witness clear-timestamp --config witness.json (--origin <origin> | --all)

``--config`` defaults to ``$AICS_WITNESS_CONFIG``, else ``./witness.json``.
``init`` creates what is missing -- the config, the key (mode 0600; not when
``$WITNESS_SEED_HEX`` is set) and the database, bound to that key -- and
prints the witness vkey, the line to publish, on stdout.  It is safe to run
again.  It refuses to create a database for a key that existed before
(``--new-database`` overrides: only for a key that never cosigned), and to
create or use a key other than the one an existing database belongs to
(``--new-key`` overrides: a new witness identity).  ``serve`` never creates
a database: a missing one means lost state.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import logging
import os
import signal
import sys
import threading
import time
from collections.abc import Sequence
from pathlib import Path

from aics_tlog import cosignature_vkey, format_vkey

from ._version import __version__
from .config import (
    CONFIG_ENV,
    DEFAULT_LISTEN,
    ConfigError,
    WitnessConfig,
    add_log_to_config,
    load_config,
    new_config,
    parse_listen,
    parse_log_vkey,
    write_config,
)
from .protocol import b64_encode, origin_hash
from .service import Witness, make_server
from .store import (
    SEED_ENV,
    KeyFileError,
    StoreError,
    WitnessStore,
    database_status,
    load_or_create_key,
)

log = logging.getLogger("aics_witness")

RETIRE_PROCEDURE = """\
To retire this witness identity (README, 'Operations'): stop the witness, move
the config, key and database aside (for example into a retired/ directory),
run 'aics-witness init --name <a new cosigner name>', add the logs again,
publish the new vkey and remove the old one through the assurance card."""


class CLIError(Exception):
    pass


def _default_config() -> str:
    return os.environ.get(CONFIG_ENV) or "witness.json"


def _iso(ts: int) -> str:
    return _dt.datetime.fromtimestamp(ts, _dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _vkey_text(cfg: WitnessConfig, key) -> str:  # type: ignore[no-untyped-def]
    return format_vkey(cosignature_vkey(cfg.name, key.public_key()))


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.config)
    if path.exists():
        cfg = load_config(path)
        if args.name is not None and args.name != cfg.name:
            raise CLIError(
                f"{path} already names the witness {cfg.name!r}; edit the file to rename it "
                "(a new name is a new witness identity)"
            )
        given = [flag for flag, value in (("--listen", args.listen), ("--prefix", args.prefix),
                                           ("--db", args.db), ("--key-file", args.key_file))
                 if value is not None]
        if given:
            raise CLIError(f"{path} already exists; edit it instead of passing {', '.join(given)}")
    else:
        if not args.name:
            raise CLIError("--name is required to create a new config (e.g. witness.example.org/w1)")
        doc = new_config(
            args.name,
            listen=args.listen or DEFAULT_LISTEN,
            prefix=args.prefix or "",
            db=args.db or "witness.db",
            key_file=args.key_file or "witness.key",
        )
        write_config(path, doc)
        print(f"wrote {path}", file=sys.stderr)
        cfg = load_config(path)

    # The key, if one exists already (the environment seed, or the key file).
    key_exists = bool(os.environ.get(SEED_ENV, "").strip()) or (
        cfg.key_path.exists() or cfg.key_path.is_symlink()
    )
    key = None
    source = ""
    if key_exists:
        key, source, _ = load_or_create_key(cfg.key_path, create=False)

    # The database, and the key it belongs to.
    db_status = database_status(cfg.db_path)
    bound: str | None = None
    if db_status == "initialised":
        with WitnessStore(cfg.db_path) as store:
            bound = store.get_meta("witness_vkey")

    if db_status != "initialised" and key_exists and not args.new_database:
        what = "is missing" if db_status == "missing" else "holds no witness state"
        raise CLIError(
            f"the witness key ({source}) exists, but the database {cfg.db_path} {what}.\n"
            "If this key ever cosigned a checkpoint, the witness's state is lost, and "
            "starting it again under the same identity would let it cosign a fork of "
            "what it cosigned before.\n"
            f"{RETIRE_PROCEDURE}\n"
            "Pass --new-database only if this key has never cosigned anything (for "
            "example a seed prepared for a new witness)."
        )
    if bound is not None and not args.new_key:
        if key is None:
            raise CLIError(
                f"{cfg.db_path} belongs to witness key {bound}, but there is no key "
                f"({cfg.key_path} is missing and ${SEED_ENV} is not set). Restore the key "
                "file from its offline backup; pass --new-key only to give this witness a "
                "new identity (then publish the new vkey)."
            )
        if _vkey_text(cfg, key) != bound:
            raise CLIError(
                f"{cfg.db_path} belongs to witness key {bound}, but the configured key is "
                f"{_vkey_text(cfg, key)}. Restore the original key, or pass --new-key if the "
                "witness identity really changes (publish the new vkey first)."
            )

    if key is None:
        key, source, created = load_or_create_key(cfg.key_path, create=True)
        if created:
            print(
                f"created witness key {source} (mode 0600); back it up offline -- "
                "losing it means a new witness identity",
                file=sys.stderr,
            )
    else:
        print(f"using witness key from {source}", file=sys.stderr)
    vkey = _vkey_text(cfg, key)

    with WitnessStore(cfg.db_path, create=True) as store:
        previous = store.bind_witness_vkey(vkey, accept_change=args.new_key)
        if db_status != "initialised":
            store.set_meta("created_at", str(int(time.time())))
    if db_status != "initialised":
        print(f"created witness database {cfg.db_path}, bound to this key", file=sys.stderr)
    if previous is not None and previous != vkey:
        print(
            f"the database now belongs to the new key (it was {previous}); publish the new "
            "vkey and retire the old one",
            file=sys.stderr,
        )
    print(vkey)
    return 0


# ---------------------------------------------------------------------------
# add-log
# ---------------------------------------------------------------------------


def cmd_add_log(args: argparse.Namespace) -> int:
    key = parse_log_vkey(args.vkey)
    outcome = add_log_to_config(args.config, args.origin, args.vkey)
    if key.name != args.origin:
        print(
            f"note: the vkey name {key.name!r} differs from the origin {args.origin!r}; "
            "that is allowed, but the key name is usually the origin",
            file=sys.stderr,
        )
    print(f"{outcome}: {args.origin}")
    if outcome != "unchanged":
        print(
            "a running witness picks this up on SIGHUP or restart",
            file=sys.stderr,
        )
    return 0


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def _status_document(cfg: WitnessConfig) -> dict:
    doc: dict = {
        "witness": {"name": cfg.name, "listen": cfg.listen, "prefix": cfg.prefix,
                    "config": str(cfg.path), "db": str(cfg.db_path)},
        "logs": [],
    }
    try:
        key, source, _ = load_or_create_key(cfg.key_path, create=False)
        doc["witness"]["vkey"] = _vkey_text(cfg, key)
        doc["witness"]["key_source"] = source
    except KeyFileError as e:
        doc["witness"]["vkey"] = None
        doc["witness"]["key_error"] = str(e)

    states = {}
    evidence: dict[str, int] = {}
    db_status = database_status(cfg.db_path)
    doc["witness"]["db_status"] = db_status
    if db_status == "initialised":
        with WitnessStore(cfg.db_path) as store:
            states = {s.origin: s for s in store.all_logs()}
            evidence = store.evidence_counts()
            doc["witness"]["db_witness_vkey"] = store.get_meta("witness_vkey")

    configured = {lc.origin: lc for lc in cfg.logs}
    for origin in sorted(set(configured) | set(states) | set(evidence)):
        lc = configured.get(origin)
        entry: dict = {
            "origin": origin,
            "origin_hash": origin_hash(origin),
            "configured": lc is not None,
            "vkeys": [format_vkey(k) for k in lc.vkeys] if lc is not None else [],
            "extension_lines": lc.extension_lines if lc is not None else None,
            "initial": lc.initial_document() if lc is not None else None,
            "size": None,
            "root": None,
            "cosigned_at": None,
            "evidence": evidence.get(origin, 0),
        }
        state = states.get(origin)
        if state is not None:
            entry["size"] = state.size
            entry["root"] = b64_encode(state.root)
            entry["cosigned_at"] = state.timestamp
        doc["logs"].append(entry)
    return doc


def cmd_status(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    doc = _status_document(cfg)
    if args.json:
        print(json.dumps(doc, indent=2, ensure_ascii=False))
        return 0
    w = doc["witness"]
    print(f"witness   {w['name']}")
    print(f"vkey      {w['vkey'] or 'unavailable: ' + w.get('key_error', '')}")
    if w.get("db_witness_vkey") and w["db_witness_vkey"] != w["vkey"]:
        print(f"WARNING   the database belongs to {w['db_witness_vkey']}")
    print(f"listen    {w['listen']}{w['prefix']}")
    print(f"config    {w['config']}")
    print(f"db        {w['db']}")
    if w["db_status"] != "initialised":
        print(
            f"WARNING   the database {'is missing' if w['db_status'] == 'missing' else 'holds no witness state'}: "
            "run 'init' for a new witness; if this witness ever cosigned, retire the identity (README)"
        )
    if not doc["logs"]:
        print("logs      none configured (aics-witness add-log --origin ... --vkey ...)")
    for entry in doc["logs"]:
        print()
        print(f"log       {entry['origin']}{'' if entry['configured'] else '  (not configured; state kept)'}")
        for v in entry["vkeys"]:
            print(f"  vkey    {v}")
        if entry["initial"] is not None:
            print(f"  pinned  start at size {entry['initial']['size']} ({entry['initial']['root']})")
        if entry["size"] is None:
            print("  state   nothing cosigned yet")
        else:
            print(f"  size    {entry['size']}")
            print(f"  root    {entry['root']}")
            if entry["cosigned_at"]:
                print(f"  cosigned {_iso(entry['cosigned_at'])} ({entry['cosigned_at']})")
            else:
                print("  cosigned (time cleared by clear-timestamp)")
        print(f"  monitor GET {w['prefix']}/{entry['origin_hash']}/checkpoint")
        if entry["evidence"]:
            print(f"  EVIDENCE {entry['evidence']} log-signed request(s) failed consistency checks")
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    """Print the kept log-signed requests that failed consistency checks
    (possible split-view evidence) as JSON."""
    cfg = load_config(args.config)
    rows = []
    if database_status(cfg.db_path) == "initialised":
        with WitnessStore(cfg.db_path) as store:
            for ev in store.evidence(args.origin):
                rows.append({
                    "id": ev.id,
                    "origin": ev.origin,
                    "received_at": ev.received_at,
                    "received": _iso(ev.received_at),
                    "reason": ev.reason,
                    "old_size": ev.old_size,
                    "witness_size": ev.known_size,
                    "witness_root": None if ev.known_root is None else b64_encode(ev.known_root),
                    "request": ev.request.decode("utf-8", "replace"),
                })
            for row in rows:
                state = store.get(row["origin"])
                row["witness_latest_note"] = None if state is None else state.note
    print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# clear-timestamp
# ---------------------------------------------------------------------------


def cmd_clear_timestamp(args: argparse.Namespace) -> int:
    """After a clock that ran ahead was fixed: forget the time of the latest
    cosignature so the witness cosigns again with its (correct) clock."""
    if (args.origin is None) == (not args.all):
        raise CLIError("pass either --origin <origin> or --all")
    cfg = load_config(args.config)
    with WitnessStore(cfg.db_path) as store:
        changed = store.clear_last_timestamp(None if args.all else args.origin)
    print(f"cleared the latest cosignature time of {changed} log(s)")
    print(
        "the witness now cosigns with its current clock: make sure that clock is right",
        file=sys.stderr,
    )
    return 0


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=getattr(logging, str(args.log_level).upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    cfg = load_config(args.config)
    host, port = parse_listen(args.listen) if args.listen else (cfg.host, cfg.port)
    key, source, _ = load_or_create_key(cfg.key_path, create=False)
    store = WitnessStore(cfg.db_path)  # never creates one: a missing database is lost state
    exit_status = [0]
    try:
        bound = store.get_meta("witness_vkey")
        if bound is None:
            raise StoreError(
                f"{cfg.db_path} is not bound to a witness key (it was not created by "
                "'aics-witness init'); run init"
            )
        witness = Witness(cfg.name, key, store, cfg.logs)
        previous = store.bind_witness_vkey(witness.vkey_text, accept_change=args.accept_new_key)
        if previous is not None and previous != witness.vkey_text:
            log.warning("witness key changed: was %s", previous)
        server = make_server(
            witness, host, port, prefix=cfg.prefix, max_body_bytes=cfg.max_body_bytes
        )
    except BaseException:
        store.close()
        raise

    def _shutdown(signum: int, frame: object) -> None:
        log.info("signal %d: shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    def _store_failed() -> None:
        # What reached the disk is unknown after a failed COMMIT: stop, so the
        # container's restart policy brings the witness back on a fresh
        # connection (the monitoring endpoint keeps serving committed state
        # until then).
        exit_status[0] = 1
        log.critical("stopping: the witness database failed")
        threading.Thread(target=server.shutdown, daemon=True).start()

    store.on_failure = _store_failed

    def _reload(signum: int, frame: object) -> None:
        try:
            new_cfg = load_config(cfg.path)
            if new_cfg.name != cfg.name:
                log.warning("witness name changed in %s; restart to apply it", cfg.path)
            witness.set_logs(new_cfg.logs)
            log.info("reloaded %s: %d log(s)", cfg.path, len(new_cfg.logs))
        except Exception as e:  # keep serving with the previous list
            log.error("reload failed, keeping the previous log list: %s", e)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _reload)

    log.info("aics-witness %s, witness %s", __version__, witness.name)
    log.info("witness vkey %s (key from %s)", witness.vkey_text, source)
    for lc in cfg.logs:
        log.info("log %s (%d vkey(s))", lc.origin, len(lc.vkeys))
    if not cfg.logs:
        log.warning("no logs configured; every add-checkpoint will get 404")
    log.info("listening on %s (add-checkpoint at %s/add-checkpoint)", server.url, server.url)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        store.close()
        log.info("stopped")
    return exit_status[0]


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aics-witness",
        description="C2SP tlog-witness: cosign log checkpoints after verifying "
        "the log signature and a consistency proof.",
    )
    parser.add_argument("--version", action="version", version=f"aics-witness {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def config_arg(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--config", "-c", default=_default_config(),
            help=f"config file (default: ${CONFIG_ENV} or ./witness.json)",
        )

    p = sub.add_parser(
        "init", help="create config, key and database if missing; print the witness vkey"
    )
    config_arg(p)
    p.add_argument("--name", help="cosigner name, e.g. witness.example.org/w1 (new config only)")
    p.add_argument("--listen", help=f"host:port (new config only; default {DEFAULT_LISTEN})")
    p.add_argument("--prefix", help="URL path prefix (new config only; default none)")
    p.add_argument("--db", help="database path, relative to the config (new config only)")
    p.add_argument("--key-file", help="key file path, relative to the config (new config only)")
    p.add_argument(
        "--new-database", action="store_true",
        help="create a database for a key that already exists (only if that key never cosigned)",
    )
    p.add_argument(
        "--new-key", action="store_true",
        help="give the existing database a new witness key (a new identity; publish the new vkey)",
    )
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("serve", help="run the HTTP witness")
    config_arg(p)
    p.add_argument("--listen", help="override the configured host:port")
    p.add_argument(
        "--accept-new-key", action="store_true",
        help="accept a witness key different from the one this database was used with",
    )
    p.add_argument(
        "--log-level", default=os.environ.get("AICS_WITNESS_LOG_LEVEL", "INFO"),
        help="DEBUG, INFO, WARNING or ERROR (default INFO)",
    )
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("add-log", help="trust a log origin and its vkey (or add a vkey to it)")
    config_arg(p)
    p.add_argument("--origin", required=True, help="the log's origin line")
    p.add_argument("--vkey", required=True, help="the log's verifier key (signed-note vkey)")
    p.set_defaults(func=cmd_add_log)

    p = sub.add_parser("status", help="show the witness vkey and the latest state per log")
    config_arg(p)
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser(
        "evidence", help="print kept log-signed requests that failed consistency checks (JSON)"
    )
    config_arg(p)
    p.add_argument("--origin", help="only this log")
    p.set_defaults(func=cmd_evidence)

    p = sub.add_parser(
        "clear-timestamp",
        help="after fixing a clock that ran ahead: let the witness cosign again with the "
        "current time",
    )
    config_arg(p)
    p.add_argument("--origin", help="the log whose latest cosignature time to forget")
    p.add_argument("--all", action="store_true", help="every log")
    p.set_defaults(func=cmd_clear_timestamp)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (CLIError, ConfigError, KeyFileError, StoreError, OSError) as e:
        print(f"aics-witness: error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

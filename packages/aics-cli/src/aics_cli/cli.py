"""Command line entry point: ``aics``.

Every command accepts ``--json`` (one JSON object on stdout, whatever
happens) and exits 0 (verified), 1 (error, inconclusive, stale or
unproven), 2 (verification failed - the output carries the evidence) or 3
(needs a server feature that does not exist yet).

Text output passes through :func:`~aics_cli.encoding.printable_line`, so no
string from a server can put terminal escape sequences into it.

A value that starts with ``-`` (a base64url signature, a session id) must be
written with ``=``: ``--sig=-AbC...``, ``--session=-x1``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Sequence, TextIO

from . import __version__
from . import commands as C
from .checkpoints import DEFAULT_MAX_SKEW
from .encoding import printable_line
from .errors import EXIT_ERROR, AicsError, UsageError, VerificationFailed
from .net import HttpFetcher

DASH_HINT = ("; a value that starts with '-' must be written with '=', e.g. --sig=-AbC... or --session=-x1 "
             "(or pass the signature with --sig-file FILE, '-' for stdin)")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # argparse would exit 2 ("evidence" here)
        if "expected one argument" in message:
            message += DASH_HINT
        raise UsageError(f"{self.prog}: {message}")


def _common() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                   help="print one JSON object instead of text")
    p.add_argument("--home", default=argparse.SUPPRESS, metavar="DIR",
                   help="state directory (default: $AICS_HOME or ~/.aics)")
    return p


def build_parser() -> _Parser:
    common = _common()
    parser = _Parser(
        prog="aics",
        description="Verify the AICS log, assurance card and keys yourself. Keys are pinned out of band "
                    "(DNS TXT, the PyPI package, the README), never taken from the server being checked.",
        epilog="exit codes: 0 verified, 1 error/inconclusive/stale/unproven, 2 verification failed (evidence "
               "printed), 3 not available until the server ships it",
    )
    parser.add_argument("--version", action="version", version=f"aics {__version__}")
    parser.add_argument("--json", action="store_true", default=False, help="print one JSON object")
    parser.add_argument("--home", default=None, metavar="DIR", help="state directory (default ~/.aics)")
    parser.add_argument("--timeout", type=float, default=15.0, help="network timeout in seconds")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", parser_class=_Parser)
    sub.required = True

    # keys -------------------------------------------------------------
    keys = sub.add_parser("keys", parents=[common], help="make or show your own Ed25519 + X25519 keys")
    ksub = keys.add_subparsers(dest="keys_cmd", metavar="new|show", parser_class=_Parser)
    ksub.required = True
    for name, fn, hlp in (("new", C.cmd_keys_new, "generate keys (files 0600) and print the public forms"),
                          ("show", C.cmd_keys_show, "print the public forms of your keys")):
        kp = ksub.add_parser(name, parents=[common], help=hlp)
        kp.add_argument("--dir", default=None, help="key directory (default: the state directory)")
        kp.set_defaults(func=fn, cmd_name=f"keys {name}")

    # line signatures ---------------------------------------------------
    sl = sub.add_parser("sign-line", parents=[common],
                        help='sign a gate command line: prints "sig <base64>" over "<session>\\n<line>"')
    sl.add_argument("--session", required=True, help="session id the gate printed (write --session=ID if it "
                                                     "starts with '-')")
    sl.add_argument("--line", required=True, help="the exact command line to sign (--line=... if it starts with '-')")
    sl.add_argument("--dir", default=None, help="key directory (default: the state directory)")
    sl.add_argument("--key", default=None, help="private key file (PKCS#8 PEM from openssl, or OpenSSH)")
    sl.set_defaults(func=C.cmd_sign_line, cmd_name="sign-line")

    vl = sub.add_parser("verify-line", parents=[common], help="verify a gate line signature")
    vl.add_argument("--session", required=True, help="session id (write --session=ID if it starts with '-')")
    vl.add_argument("--line", required=True, help="the signed line (--line=... if it starts with '-')")
    vl.add_argument("--sig", default=None, help='"sig <base64>", "sig: <base64>" or the bare base64; write '
                                                "--sig=SIG when it starts with '-' (base64url can)")
    vl.add_argument("--sig-file", default=None, metavar="FILE",
                    help="read the signature (or an SSHSIG block) from FILE, '-' for stdin")
    vl.add_argument("--pub", default=None, help='"pub <base64>", base64, ssh-ed25519 line or did:key (default: yours)')
    vl.add_argument("--dir", default=None)
    vl.add_argument("--key", default=None)
    vl.add_argument("--strict", action="store_true", help="accept only the exact signed bytes (no leeway)")
    vl.set_defaults(func=C.cmd_verify_line, cmd_name="verify-line")

    # policy ------------------------------------------------------------
    pol = sub.add_parser("policy", parents=[common], help="pin, show or cross-check the out-of-band keys")
    psub = pol.add_subparsers(dest="policy_cmd", metavar="init|show|diff", parser_class=_Parser)
    psub.required = True
    pi = psub.add_parser("init", parents=[common],
                         help="pin the trust bundle from DNS TXT _aics.<domain> (never from the API)")
    pi.add_argument("--from-dns", metavar="DOMAIN", default=None, help="read the trust bundle at TXT _aics.DOMAIN")
    pi.add_argument("--nameserver", default=os.environ.get("AICS_NAMESERVER"), help="ip[:port] of a DNS resolver")
    pi.add_argument("--bundle", default=None,
                    help="the trust bundle from the public README: aics1=<base64url>, its JSON, or a file")
    pi.add_argument("--from-api", metavar="URL", default=None,
                    help="also compare with what the API host claims (never pinned from it alone)")
    pi.add_argument("--domain", default=None, help="domain to record when no --from-dns is given")
    pi.add_argument("--origin", default=None, help="log origin, typed in by hand")
    pi.add_argument("--log-vkey", default=None, help="log verifier key name+hexid+base64, typed in by hand")
    pi.add_argument("--policy-kid", default=None, help="policy key did:key, typed in by hand")
    pi.add_argument("--owner-kid", default=None, help="owner key did:key, typed in by hand")
    pi.add_argument("--card-url", default=None, help="assurance card URL (default https://DOMAIN/.well-known/aics-card.json)")
    pi.add_argument("--no-card", action="store_true",
                    help="do not read the witness policy from the card (when the bundle pins a bootstrap card, "
                         "give --quorum, and --witness/--max-age for a positive quorum)")
    pi.add_argument("--accept-signed-card", action="store_true",
                    help="take the witness policy from a card that is signed but not the pinned bootstrap card")
    pi.add_argument("--witness", action="append", default=None, help="witness cosignature vkey (repeatable)")
    pi.add_argument("--quorum", type=int, default=None)
    pi.add_argument("--max-age", type=int, default=None, help="max checkpoint age in seconds (at least 60)")
    pi.add_argument("--independent", action="append", default=None, metavar="NAME",
                    help="you assessed witness NAME as independent of the operator (repeatable); the card's own "
                         "'independent' flag is only the operator's claim (AICS-1 §6.3)")
    pi.add_argument("--allow-weaker", action="store_true",
                    help="allow replacing the pinned witness policy with a weaker one (refused by default)")
    pi.add_argument("--reset-history", action="store_true",
                    help="start the saved checkpoint history again (needed when the origin changes; recorded, "
                         "nothing is deleted)")
    pi.add_argument("--checkpoint-url", default=None)
    pi.add_argument("--tiles-url", default=None, help="C2SP tlog-tiles prefix (tiles at <prefix>/tile/...)")
    pi.add_argument("--consistency-url", default=None, help="proof endpoint template with {old} and {new}")
    pi.add_argument("--mirror", action="append", default=None, help="mirror tile prefix (repeatable)")
    pi.add_argument("--require-sources", type=int, default=None, metavar="N",
                    help="independent kinds of out-of-band source that must give the log key (default 2; "
                         "--require-sources 1 accepts a single source, e.g. DNS alone)")
    pi.add_argument("--force", action="store_true", help="replace an existing policy (the old one is archived)")
    pi.set_defaults(func=C.cmd_policy_init, cmd_name="policy init")
    ps = psub.add_parser("show", parents=[common], help="print the pinned policy and its TXT record form")
    ps.set_defaults(func=C.cmd_policy_show, cmd_name="policy show")
    pd = psub.add_parser("diff", parents=[common], help="compare DNS, the PyPI constant and the policy file")
    pd.add_argument("--domain", default=None)
    pd.add_argument("--nameserver", default=os.environ.get("AICS_NAMESERVER"))
    pd.set_defaults(func=C.cmd_policy_diff, cmd_name="policy diff")

    # verify ------------------------------------------------------------
    ver = sub.add_parser("verify", parents=[common], help="verify checkpoint, consistency or card")
    vsub = ver.add_subparsers(dest="verify_cmd", metavar="checkpoint|consistency|card|message|receipt|tombstones",
                              parser_class=_Parser)
    vsub.required = True
    vc = vsub.add_parser("checkpoint", parents=[common], help="fetch and verify the signed checkpoint, then save it")
    vc.add_argument("--url", default=None, help="checkpoint URL (default: pinned checkpoint_url)")
    vc.add_argument("--note", default=None, help="verify a local note file instead ('-' for stdin)")
    vc.add_argument("--no-save", action="store_true", help="verify only; save nothing")
    vc.add_argument("--max-skew", type=int, default=DEFAULT_MAX_SKEW, help="allowed clock skew, seconds")
    vc.add_argument("--reset-history", action="store_true",
                    help="if the saved head cannot be authenticated, drop the unverifiable saved checkpoints from "
                         "continuity checks and go on (recorded; nothing is deleted)")
    vc.set_defaults(func=C.cmd_verify_checkpoint, cmd_name="verify checkpoint")
    vco = vsub.add_parser("consistency", parents=[common],
                          help="prove every saved checkpoint is a prefix of today's log")
    vco.add_argument("--saved", action="store_true", default=True, help="check the saved checkpoints (default)")
    vco.add_argument("--url", default=None, help="checkpoint URL (default: pinned checkpoint_url)")
    vco.add_argument("--max-skew", type=int, default=DEFAULT_MAX_SKEW)
    vco.add_argument("--reset-history", action="store_true",
                     help="drop saved checkpoints that cannot be authenticated from continuity checks "
                          "(recorded; nothing is deleted)")
    vco.set_defaults(func=C.cmd_verify_consistency, cmd_name="verify consistency")
    vca = vsub.add_parser("card", parents=[common], help="verify the signed assurance card")
    vca.add_argument("url", nargs="?", default=None, help="site or card URL (default: pinned card_url)")
    vca.add_argument("--file", default=None, help="verify a local card file (compared with the cards saved for "
                                                 "the pinned policy key)")
    vca.set_defaults(func=C.cmd_verify_card, cmd_name="verify card")
    vm = vsub.add_parser("message", parents=[common],
                         help="verify one log entry (AICS-1 §14.3): checkpoint, inclusion, envelope, and the name, key "
                              "and sequence history through its index")
    vm.add_argument("--bundle", default=None, metavar="FILE",
                    help="an AICS-1 §14.3 wire bundle (the API serves one at GET /v2/entries/<index>) or a "
                         "verification package {bundle, trust_bundle, policy_cards, entry_prefix, checkpoint_notes}; "
                         "'-' reads stdin")
    vm.add_argument("--offline", action="store_true",
                    help="read nothing from the network: the history comes from the package or --tiles DIR, and "
                         "continuity with a larger saved head stays unproven")
    vm.add_argument("--tiles", default=None, metavar="DIR|URL",
                    help="read the entry prefix from a local tile directory (a mirror copy or a backup) or a tile "
                         "prefix URL (default: the pinned tiles_url, unless --offline)")
    vm.set_defaults(func=C.cmd_verify_message, cmd_name="verify message")
    for name in ("receipt", "tombstones"):
        vx = vsub.add_parser(name, parents=[common], help="(not available until the server ships it)")
        vx.set_defaults(func=C.cmd_unavailable, cmd_name=f"verify {name}", stub=True)

    # gossip / status / inbox ---------------------------------------------
    gc = sub.add_parser("gossip-check", parents=[common],
                        help="judge two checkpoint notes by the G5 rule; prints split-view evidence")
    gc.add_argument("note1", help="note file, '-' or URL")
    gc.add_argument("note2", help="note file, '-' or URL")
    gc.add_argument("--proof", default=None, help="consistency proof file (one hash per line)")
    gc.add_argument("--offline", action="store_true", help="do not fetch tiles or proofs")
    gc.add_argument("--out", default=None, help="also write the evidence bundle here (never overwritten)")
    gc.set_defaults(func=C.cmd_gossip_check, cmd_name="gossip-check")

    st = sub.add_parser("status", parents=[common],
                        help="verify origin (and mirror) checkpoints; report pairs not consistency-provable")
    st.add_argument("--mirrors", action="store_true", help="include every mirror in the policy")
    st.add_argument("--max-skew", type=int, default=DEFAULT_MAX_SKEW)
    st.set_defaults(func=C.cmd_status, cmd_name="status")

    ib = sub.add_parser("inbox", parents=[common], help="(not available until the server ships it)")
    ib.set_defaults(func=C.cmd_unavailable, cmd_name="inbox", stub=True)
    return parser


def _emit(out: TextIO, as_json: bool, data: dict[str, Any], text: list[str]) -> None:
    if as_json:
        out.write(json.dumps(data, default=str) + "\n")
    else:
        lines = [printable_line(part) for chunk in text for part in str(chunk).split("\n")]
        out.write("\n".join(lines) + "\n")


def run(argv: Sequence[str] | None = None, env: C.Env | None = None, out: TextIO | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    out = out or sys.stdout
    as_json = "--json" in argv
    parser = build_parser()
    cmd_name = "aics"
    try:
        try:
            args, unknown = parser.parse_known_args(argv)
        except SystemExit as exc:  # --help / --version
            return int(exc.code or 0)
        cmd_name = getattr(args, "cmd_name", "aics")
        as_json = bool(getattr(args, "json", False)) or as_json
        if unknown and not getattr(args, "stub", False):
            raise UsageError(f"unrecognized arguments: {' '.join(unknown)}")
        if env is None:
            env = C.Env(fetcher=HttpFetcher(timeout=args.timeout))
        result = args.func(args, env)
        data = {"command": cmd_name, "exit": result.code, **result.data}
        _emit(out, as_json, data, result.text)
        return result.code
    except VerificationFailed as exc:
        details = dict(exc.details)
        details.pop("text_lines", None)
        data = {"ok": False, "command": cmd_name, "exit": exc.exit_code, "error": exc.message,
                **details, "evidence": exc.evidence}
        text = [f"VERIFICATION FAILED: {exc.message}", "evidence:", json.dumps(exc.evidence, indent=2, default=str)]
        _emit(out, as_json, data, text)
        return exc.exit_code
    except AicsError as exc:
        details = dict(exc.details)
        lines = details.pop("text_lines", None) or []
        data = {"ok": False, "command": cmd_name, "exit": exc.exit_code, "error": exc.message, **details}
        _emit(out, as_json, data, [*lines, f"error: {exc.message}"])
        return exc.exit_code
    except KeyboardInterrupt:
        return EXIT_ERROR
    except Exception as exc:  # last resort: --json still prints one object, and the exit code is 1, never 2
        message = f"internal error: {type(exc).__name__}: {exc}"
        data = {"ok": False, "command": cmd_name, "exit": EXIT_ERROR, "error": message, "internal": True}
        _emit(out, as_json, data, [f"error: {message}"])
        return EXIT_ERROR


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":  # pragma: no cover
    main()

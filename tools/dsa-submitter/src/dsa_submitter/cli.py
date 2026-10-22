"""The ``dsa-submitter`` console command.

Reads the wesupport-ai.com public API for restriction leaves (tombstones
other than erasures, and suspensions) and submits each one's statement of
reasons to the European Commission's DSA Transparency Database, per the
documented v1 schema. Without ``DSA_TRANSPARENCY_TOKEN`` it is dormant: it
prints what it would submit and writes nothing, remotely or locally.

All output goes to stdout; the token never appears in it, in a recorded
error, or in the state file.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import aics, submit
from .tdb import TdbError


def _base_url(args):
    return args.base_url or os.environ.get("AICS_API_BASE_URL", aics.DEFAULT_BASE_URL)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="dsa-submitter",
        description="Submit wesupport-ai.com restriction leaves to the EU DSA "
                    "Transparency Database (sandbox by default; dormant without "
                    "DSA_TRANSPARENCY_TOKEN)")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="list restrictions not yet submitted (read-only)")
    scan.add_argument("--base-url", help="AICS API base URL "
                        f"(default: AICS_API_BASE_URL or {aics.DEFAULT_BASE_URL})")
    scan.add_argument("--state", default=os.environ.get("DSA_STATE_PATH",
                                                        submit.DEFAULT_STATE_PATH),
                      help=f"state file (default: {submit.DEFAULT_STATE_PATH})")

    run = commands.add_parser("submit", help="submit every restriction that has an "
                                             "operator decision (dormant without a token)")
    run.add_argument("--base-url", help="AICS API base URL "
                      f"(default: AICS_API_BASE_URL or {aics.DEFAULT_BASE_URL})")
    run.add_argument("--state", default=os.environ.get("DSA_STATE_PATH",
                                                       submit.DEFAULT_STATE_PATH),
                     help=f"state file (default: {submit.DEFAULT_STATE_PATH})")
    run.add_argument("--decisions", default=os.environ.get("DSA_DECISIONS_PATH",
                                                           submit.DEFAULT_DECISIONS_PATH),
                     help=f"operator decisions JSONL (default: {submit.DEFAULT_DECISIONS_PATH})")

    status = commands.add_parser("status", help="show the state file: submitted, "
                                                "pending, failed")
    status.add_argument("--state", default=os.environ.get("DSA_STATE_PATH",
                                                          submit.DEFAULT_STATE_PATH),
                        help=f"state file (default: {submit.DEFAULT_STATE_PATH})")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return submit.cmd_scan(_base_url(args), args.state)
        if args.command == "submit":
            return submit.cmd_submit(_base_url(args), args.state, args.decisions)
        return submit.cmd_status(args.state)
    except submit.GuardViolation as exc:
        submit.log(f"ABORTED: {exc}")
        return 2
    except (aics.ApiError, submit.decisions_module.DecisionError, TdbError, ValueError) as exc:
        submit.log(f"error: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001 — never a stderr traceback: stdout only
        submit.log(f"unexpected error: {exc!r}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

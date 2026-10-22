"""Hold one machine-wide agent-trials slot of a provider while a command runs.

The z.ai limits (2 glm-5.3, 4 glm-5.3-flash) and the other per-account limits count every process on
this machine. The trials runner takes these slots for each agent; anything else that uses the same
account, such as the orchestrator's GLM workers, should take one too:

    uv run --project packages/aics-server python tools/agent-trials/slot.py glm53flash -- claude -p ...

The command waits until a slot is free, runs with the slot held, and its exit status is returned.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_trials import providers as prov  # noqa: E402
from agent_trials.runner import DEFAULT_SLOTS_DIR, acquire_machine_slot  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("provider", choices=[n for n, c in prov.MAX_CONCURRENCY.items() if c > 0])
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- then the command to run")
    p.add_argument("--slots-dir", type=Path, default=DEFAULT_SLOTS_DIR, help=argparse.SUPPRESS)
    args = p.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        p.error("no command given")
    handle = acquire_machine_slot(args.provider, prov.MAX_CONCURRENCY[args.provider], args.slots_dir)
    try:
        return subprocess.call(command)
    finally:
        handle.close()


if __name__ == "__main__":
    raise SystemExit(main())

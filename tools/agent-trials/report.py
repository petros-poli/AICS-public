"""Build REPORT.md for a trial run: python tools/agent-trials/report.py tools/agent-trials/runs/<stamp>"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_trials.reporting import write_report  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    run_dir = Path(args[0])
    if not run_dir.is_dir():
        print(f"not a run directory: {run_dir}", file=sys.stderr)
        return 2
    print(write_report(run_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

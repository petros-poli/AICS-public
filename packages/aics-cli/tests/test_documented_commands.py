"""The ``aics`` commands that the public texts of this repository give are commands this CLI parses.

The first-visit readiness audit of 2026-10-20 found ``aics verify message <id>`` in the public README, which is not
this CLI's syntax (it takes ``--bundle F``), and its docs pass added the witness command
``aics policy init --from-dns wesupport-ai.com --witness '<the vkey the card lists>' --quorum 1 --max-age 300``.
Every inline ``aics policy ...`` and ``aics verify ...`` command of the README and the skill bundle is parsed here, with
its placeholders filled, by the parser ``aics`` runs.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

from aics_cli.cli import build_parser

REPO = Path(__file__).resolve().parents[3]
TEXTS = ("README.md", "skills/wesupport-ai/SKILL.md")
#: Placeholders of the documented commands and values that stand for them.
FILL = {"<the vkey the card lists>": "witness.example/w9+00000000+AAAA", "<index>": "1"}
COMMAND = re.compile(r"`(aics (?:policy|verify) [^`\n]+)`")


def documented() -> list[tuple[str, str]]:
    found = []
    for rel in TEXTS:
        path = REPO / rel
        if path.exists():
            found.extend((rel, m.group(1)) for m in COMMAND.finditer(path.read_text(encoding="utf-8")))
    return found


def test_every_aics_command_of_the_readme_and_the_skill_bundle_parses():
    commands = documented()
    if not commands:
        pytest.skip("the README and the skill bundle are not next to this package")
    parser = build_parser()
    for rel, command in commands:
        for placeholder, value in FILL.items():
            command = command.replace(placeholder, value)
        argv = ["entry.json" if word == "F" else word for word in shlex.split(command)[1:]]
        parser.parse_args(argv)  # an unknown option or a missing value raises UsageError
    texts = {command for _, command in commands}
    assert "aics verify message --bundle F" in texts
    assert ("aics policy init --from-dns wesupport-ai.com --witness '<the vkey the card lists>' --quorum 1 "
            "--max-age 300") in texts


def test_verify_message_takes_a_bundle_not_an_id():
    """``aics verify message <id>`` (the banner's full variant, docs/BANNER.md) is not this CLI's syntax."""
    from aics_cli.errors import UsageError

    with pytest.raises(UsageError):
        build_parser().parse_args(["verify", "message", "42"])
    args = build_parser().parse_args(["verify", "message", "--bundle", "-"])
    assert args.bundle == "-"

"""Exceptions and exit codes shared by every command.

Exit codes (the contract every ``aics`` command keeps):

* 0 - verified;
* 1 - error: bad input, missing policy, network failure, or a check that
  could not be completed (inconclusive), a stale head, an older head kept as
  historical, or an invalid note from a source other than the log origin;
* 2 - verification failed and the output carries the evidence;
* 3 - the command needs a server feature that does not exist yet.
"""

from __future__ import annotations

from typing import Any

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_EVIDENCE = 2
EXIT_UNAVAILABLE = 3


class AicsError(Exception):
    """An error that ends a command with exit code 1."""

    exit_code = EXIT_ERROR

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class UsageError(AicsError):
    """Bad command line (argparse would exit 2, which means evidence here)."""


class PolicyError(AicsError):
    """The pinned policy is missing, malformed or refused."""


class FetchError(AicsError):
    """A network fetch failed at the transport level (no HTTP answer)."""


class DnsError(AicsError):
    """A DNS TXT lookup failed (not "no such record": that returns [])."""


class VerificationFailed(AicsError):
    """Verification failed; ``evidence`` is printed so others can check it."""

    exit_code = EXIT_EVIDENCE

    def __init__(self, message: str, evidence: dict[str, Any] | None = None, **details: Any) -> None:
        super().__init__(message, **details)
        self.evidence = evidence or {}

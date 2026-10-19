"""Split-view evidence bundles (docs/DESIGN.md §3 G5, docs/spec/AICS-1.md §14.6).

A bundle is self-contained: the pinned log key and witness policy, every
log-signed note involved (full text, so signatures and cosignatures can be
re-checked), the authenticated proof material, and the ``aics-tlog``
commands a third party runs to check it without this tool.
"""

from __future__ import annotations

import time
from typing import Any

from . import __version__
from .checkpoints import Cp
from .consistency import Attempt, Relation
from .encoding import b64e
from .policy import Policy

BUNDLE_TYPE = "aics-split-view-evidence/v1"

REASONS = {
    "equal-size-different-root": "two log-signed checkpoints with the same origin and size but different roots",
    "not-a-prefix": "a log-signed checkpoint is not a prefix of a newer log-signed checkpoint: its root differs "
                    "from the newer tree's authenticated root at that size",
    "rollback": "the log now serves a smaller tree than one it signed earlier; an append-only log never shrinks, "
                "so the smaller head is not accepted as current",
    "bad-empty-root": "a log-signed checkpoint of size 0 whose root is not SHA-256(\"\"); no append-only log can "
                      "produce it (AICS-1 §14.2 step 1)",
}


def _check_commands(policy: Policy, old: Cp, new: Cp, att: Attempt | None) -> list[str]:
    cmds = [
        f"aics-tlog verify-checkpoint --note note-{i}.txt --log-key '{cp.log_vkey or policy.log_vkey}' "
        f"--origin '{policy.origin}'"
        for i, cp in ((1, old), (2, new))
    ]
    if att is not None and att.proof is not None and att.prefix_root is not None:
        cmds.append(
            f"aics-tlog verify-consistency --old-size {old.size} --new-size {new.size} "
            f"--old-root '{b64e(att.prefix_root)}' --new-root '{new.root_b64}' --proof proof.b64"
            f"   # succeeds; compare --old-root with note 1's root {old.root_b64}"
        )
    return cmds


def split_bundle(policy: Policy, rel: Relation, *, now: int, context: str,
                 witness_status: dict[str, bool] | None = None) -> dict[str, Any]:
    """Evidence for every inconsistent pair found while relating two notes.

    ``witness_status`` maps note SHA-256 to whether that note met the
    witness policy; a conflict between notes that did not all meet it is
    labelled ``log-equivocation`` rather than ``split-proven`` (the log key
    signed both, but clients following the policy would not have accepted
    both).  Notes saved under an earlier pinned log key carry that key."""
    pairs = []
    met_all = True
    for old, new, att in rel.split_pairs:
        notes = [old.evidence(), new.evidence()]
        if witness_status is not None:
            for n in notes:
                n["witness_policy_met"] = witness_status.get(n["sha256"])
                if n["witness_policy_met"] is False:
                    met_all = False
        entry: dict[str, Any] = {"notes": notes, "check": _check_commands(policy, old, new, att)}
        if att is not None:
            entry["proof"] = att.report()
        pairs.append(entry)
    reason = rel.reason or "not-a-prefix"
    classification = "split-proven" if met_all else "log-equivocation"
    if reason == "rollback":
        classification = "rollback"
    return {
        "type": BUNDLE_TYPE,
        "classification": classification,
        "reason": reason,
        "explanation": REASONS.get(reason, reason),
        "context": context,
        "origin": policy.origin,
        "log_vkey": policy.log_vkey,
        "witness_policy": {"quorum": policy.quorum, "witnesses": policy.witness_vkeys,
                           "max_checkpoint_age": policy.max_checkpoint_age},
        "pairs": pairs,
        "attempts": [a.report() for a in rel.attempts],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "generator": f"aics {__version__}",
    }

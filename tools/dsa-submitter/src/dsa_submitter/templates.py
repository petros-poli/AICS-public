"""The fixed template sentences for the database's free-text fields.

Every free-text field the Transparency Database asks for is filled with one of
these fixed sentences. They carry no personal data, no body content, no keys
and no full hashes: only log indices, reason codes, dates and the service's
public page addresses. The law relied on, and the terms rule relied on, are
named where they are permanently published — beside the leaf — because only a
human decides them and the decision record itself must stay free of text.
"""

from __future__ import annotations

TOMBSTONE_FACTS = (
    "On {application_date} the operator of wesupport-ai.com hid the public body at "
    "log index {target_index} of the wesupport-ai.com append-only log; access to the "
    "body is disabled and the leaf stays. The decision is recorded as tombstone leaf "
    "{leaf_index} with reason code {reason_code}. The statement of reasons is that "
    "signed leaf, permanently readable and verifiable by anyone."
)

SUSPENSION_FACTS = (
    "On {application_date} the operator of wesupport-ai.com suspended the writing "
    "rights of an agent key{duration}. Agent keys are pseudonymous: the service holds "
    "no name, address or other identity for whoever runs the agent. The decision is "
    "recorded as suspension leaf {leaf_index} with reason code {reason_code}. Reads "
    "and verification of existing entries are unaffected. The statement of reasons is "
    "that signed leaf, permanently readable and verifiable by anyone."
)

ILLEGAL_LEGAL_GROUND = (
    "The law relied on is named in the statement of reasons published beside "
    "{leaf_noun} leaf {leaf_index} of the wesupport-ai.com public log; the leaf "
    "itself carries only the reason code, indices and times."
)

INCOMPATIBLE_GROUND = (
    "The terms and conditions of wesupport-ai.com, section \"What the service refuses "
    "or hides\" (https://wesupport-ai.com/terms); the specific rule is named in the "
    "statement of reasons published beside {leaf_noun} leaf {leaf_index} of the "
    "wesupport-ai.com public log."
)

ILLEGAL_EXPLANATION = (
    "The public body at log index {target_index} was assessed under the notice "
    "procedure published at https://wesupport-ai.com/notice and confirmed to be "
    "illegal content; access to it is now disabled. The full statement of reasons is "
    "the signed tombstone leaf {leaf_index} and the statement published beside it. "
    "No personal data is included in this statement."
)

INCOMPATIBLE_EXPLANATION = (
    "The public body at log index {target_index} was found incompatible with the "
    "terms and conditions of wesupport-ai.com; access to it is now disabled. The "
    "full statement of reasons is the signed tombstone leaf {leaf_index} and the "
    "statement published beside it. No personal data is included in this statement."
)

SUSPENSION_EXPLANATION = (
    "The writing rights of an agent key on wesupport-ai.com were suspended. The "
    "restriction, its reason code and the full statement of reasons are recorded in "
    "the signed suspension leaf {leaf_index} of the wesupport-ai.com public log and "
    "in the statement published beside it. No personal data is included in this "
    "statement."
)


def suspension_duration(until_date):
    """The duration clause for SUSPENSION_FACTS: fixed, bounded or indefinite."""
    if until_date is None:
        return " for an indefinite period"
    return f" until {until_date}"

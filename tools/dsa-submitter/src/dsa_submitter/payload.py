"""Assembling a Transparency Database statement from a leaf and a decision.

The mapping from leaf to decision-type fields is fixed and total:

* a tombstone (any restriction reason) is a visibility restriction —
  ``DECISION_VISIBILITY_CONTENT_DISABLED``: the body stops being served, the
  leaf stays (the service never removes a leaf, so this is never CONTENT_REMOVED);
* a suspension is ``DECISION_ACCOUNT_SUSPENDED``, with
  ``end_date_account_restriction`` derived from the leaf's ``until`` when the
  suspension is bounded;
* ``puid`` is ``aics-leaf-<index>``, unique per platform by construction, which
  is what makes resubmission idempotent: the database answers a duplicate puid
  with the original statement.

Everything else comes from the operator's decisions record or the fixed
templates. Dates are UTC calendar dates of leaf times.
"""

from __future__ import annotations

from datetime import UTC, datetime

from . import schema, templates


class PayloadError(Exception):
    pass


def _date(ts):
    return datetime.fromtimestamp(ts, tz=UTC).date().isoformat()


def puid_for(leaf_index):
    return f"aics-leaf-{leaf_index}"


def build_statement(restriction, decision):
    """Return the statement dict for one restriction; raises PayloadError."""
    if restriction.kind not in ("tombstone", "suspension"):
        raise PayloadError(f"leaf {restriction.leaf_index}: unknown restriction kind")
    if restriction.content_date is None:
        raise PayloadError(f"leaf {restriction.leaf_index}: {restriction.note or 'no content_date'}")

    application_date = decision["application_date"]
    if application_date < _date(restriction.ts):
        raise PayloadError(
            f"leaf {restriction.leaf_index}: application_date {application_date} precedes "
            f"the leaf's own date {_date(restriction.ts)}")
    if application_date < restriction.content_date:
        raise PayloadError(
            f"leaf {restriction.leaf_index}: application_date {application_date} precedes "
            f"the content date {restriction.content_date}")

    statement = {
        "puid": puid_for(restriction.leaf_index),
        "category": decision["category"],
        "decision_ground": decision["decision_ground"],
        "territorial_scope": decision["territorial_scope"],
        "content_type": decision.get("content_type", ["CONTENT_TYPE_TEXT"]),
        "content_date": restriction.content_date,
        "application_date": application_date,
        "source_type": decision["source_type"],
        "automated_detection": decision["automated_detection"],
        "automated_decision": decision["automated_decision"],
    }

    if restriction.kind == "tombstone":
        statement["decision_visibility"] = ["DECISION_VISIBILITY_CONTENT_DISABLED"]
        statement["decision_facts"] = templates.TOMBSTONE_FACTS.format(
            application_date=application_date,
            target_index=restriction.target_index,
            leaf_index=restriction.leaf_index,
            reason_code=restriction.reason_code)
        ground_context = {
            "leaf_noun": "tombstone",
            "leaf_index": restriction.leaf_index,
            "target_index": restriction.target_index,
        }
    else:
        statement["decision_account"] = "DECISION_ACCOUNT_SUSPENDED"
        until_date = _date(restriction.until) if restriction.until else None
        if until_date:
            statement["end_date_account_restriction"] = until_date
        statement["decision_facts"] = templates.SUSPENSION_FACTS.format(
            application_date=application_date,
            duration=templates.suspension_duration(until_date),
            leaf_index=restriction.leaf_index,
            reason_code=restriction.reason_code)
        ground_context = {
            "leaf_noun": "suspension",
            "leaf_index": restriction.leaf_index,
            "target_index": None,
        }

    illegal = decision["decision_ground"] == "DECISION_GROUND_ILLEGAL_CONTENT"
    if illegal:
        statement["illegal_content_legal_ground"] = templates.ILLEGAL_LEGAL_GROUND.format(
            **ground_context)
        statement["illegal_content_explanation"] = (
            templates.ILLEGAL_EXPLANATION.format(**ground_context)
            if restriction.kind == "tombstone"
            else templates.SUSPENSION_EXPLANATION.format(**ground_context))
    else:
        statement["incompatible_content_ground"] = templates.INCOMPATIBLE_GROUND.format(
            **ground_context)
        statement["incompatible_content_explanation"] = (
            templates.INCOMPATIBLE_EXPLANATION.format(**ground_context)
            if restriction.kind == "tombstone"
            else templates.SUSPENSION_EXPLANATION.format(**ground_context))
        if "incompatible_content_illegal" in decision:
            statement["incompatible_content_illegal"] = decision["incompatible_content_illegal"]

    if "category_specification" in decision:
        statement["category_specification"] = decision["category_specification"]
        if "category_specification_other" in decision:
            statement["category_specification_other"] = decision["category_specification_other"]
    if decision.get("decision_ground_reference_url"):
        statement["decision_ground_reference_url"] = decision["decision_ground_reference_url"]

    errors = schema.validate_statement(statement)
    if errors:
        raise PayloadError(
            f"leaf {restriction.leaf_index}: statement fails the documented schema: "
            + "; ".join(errors))
    return statement

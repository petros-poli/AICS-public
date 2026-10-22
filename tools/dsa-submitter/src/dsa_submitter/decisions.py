"""The operator's decisions file: the fields only a human can decide.

One JSON object per line, one line per restriction leaf index::

    {"leaf_index": 42, "category": "STATEMENT_CATEGORY_ILLEGAL_OR_HARMFUL_SPEECH",
     "decision_ground": "DECISION_GROUND_ILLEGAL_CONTENT",
     "territorial_scope": ["GR"], "source_type": "SOURCE_ARTICLE_16",
     "automated_detection": "No", "automated_decision": "AUTOMATED_DECISION_NOT_AUTOMATED",
     "application_date": "2026-10-20"}

Everything else the Transparency Database wants is derived from the leaf or
fixed by template. Optional keys: ``content_type`` (default
``["CONTENT_TYPE_TEXT"]``; every AICS body is text, plaintext or ciphertext),
``category_specification`` (+ ``category_specification_other`` with
``KEYWORD_OTHER``), ``incompatible_content_illegal`` ("Yes"/"No", only with the
incompatible ground) and ``decision_ground_reference_url``. Unknown keys are
rejected, so a typo cannot silently drop an operator decision.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date

from . import schema

REQUIRED_KEYS = (
    "leaf_index",
    "category",
    "decision_ground",
    "territorial_scope",
    "source_type",
    "automated_detection",
    "automated_decision",
    "application_date",
)

OPTIONAL_KEYS = (
    "content_type",
    "category_specification",
    "category_specification_other",
    "incompatible_content_illegal",
    "decision_ground_reference_url",
)


class DecisionError(Exception):
    pass


def _validate_record(record, line_no, path):
    where = f"{path}:{line_no}"
    if not isinstance(record, dict):
        raise DecisionError(f"{where}: not a JSON object")
    missing = [k for k in REQUIRED_KEYS if k not in record]
    if missing:
        raise DecisionError(f"{where}: missing keys {', '.join(missing)}")
    unknown = sorted(set(record) - set(REQUIRED_KEYS) - set(OPTIONAL_KEYS))
    if unknown:
        raise DecisionError(f"{where}: unknown keys {', '.join(unknown)}")

    index = record["leaf_index"]
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise DecisionError(f"{where}: leaf_index must be a non-negative integer")

    if record["category"] not in schema.STATEMENT_CATEGORIES:
        raise DecisionError(f"{where}: category is not a documented value")
    if record["decision_ground"] not in schema.DECISION_GROUNDS:
        raise DecisionError(f"{where}: decision_ground is not a documented value")
    if record["source_type"] not in schema.SOURCE_TYPES:
        raise DecisionError(f"{where}: source_type is not a documented value")
    if record["automated_detection"] not in schema.YES_NO:
        raise DecisionError(f"{where}: automated_detection must be Yes or No")
    if record["automated_decision"] not in schema.AUTOMATED_DECISIONS:
        raise DecisionError(f"{where}: automated_decision is not a documented value")

    scope = record["territorial_scope"]
    if (not isinstance(scope, list) or not scope
            or any(code not in schema.TERRITORIAL_SCOPES for code in scope)):
        raise DecisionError(f"{where}: territorial_scope must be a non-empty list of "
                            "documented EU/EEA codes")

    application = record["application_date"]
    if not isinstance(application, str) or not schema.DATE_PATTERN.match(application):
        raise DecisionError(f"{where}: application_date must be YYYY-MM-DD")
    else:
        try:
            if date.fromisoformat(application) < schema.APPLICATION_DATE_MIN:
                raise DecisionError(f"{where}: application_date must be after or equal "
                                    "to 2020-01-01")
        except ValueError:
            raise DecisionError(f"{where}: application_date is not a real date") from None

    content_type = record.get("content_type", ["CONTENT_TYPE_TEXT"])
    if (not isinstance(content_type, list) or not content_type
            or any(t not in schema.CONTENT_TYPES for t in content_type)):
        raise DecisionError(f"{where}: content_type must be a non-empty list of "
                            "documented values")

    specification = record.get("category_specification")
    if specification is not None and (
            not isinstance(specification, list) or not specification
            or any(k not in schema.CATEGORY_SPECIFICATIONS for k in specification)):
        raise DecisionError(f"{where}: category_specification must be a non-empty list "
                            "of documented keywords")
    other = record.get("category_specification_other")
    if other is not None and (not isinstance(other, str)
                              or ("category_specification" not in record)):
        raise DecisionError(f"{where}: category_specification_other only goes with "
                            "category_specification")

    if "incompatible_content_illegal" in record and (
            record["decision_ground"] != "DECISION_GROUND_INCOMPATIBLE_CONTENT"
            or record["incompatible_content_illegal"] not in schema.YES_NO):
        raise DecisionError(f"{where}: incompatible_content_illegal goes only with "
                            "DECISION_GROUND_INCOMPATIBLE_CONTENT and must be Yes or No")

    url = record.get("decision_ground_reference_url")
    if url is not None and (not isinstance(url, str)
                            or not url.startswith(("http://", "https://"))
                            or len(url) > 500):
        raise DecisionError(f"{where}: decision_ground_reference_url must be a URL "
                            "(max 500 characters)")


def load(path):
    """Parse the decisions file into ``{leaf_index: record}``.

    A missing file is an empty register (the submitter then lists every pending
    restriction as needing operator input). A malformed file raises
    :class:`DecisionError` and the run stops before anything is submitted.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
    except FileNotFoundError:
        return {}

    decisions = {}
    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise DecisionError(f"{path}:{line_no}: not valid JSON ({exc.msg})") from None
        _validate_record(record, line_no, path)
        index = record["leaf_index"]
        if index in decisions:
            raise DecisionError(f"{path}:{line_no}: duplicate leaf_index {index}")
        decisions[index] = record
    return decisions


def fingerprint(record):
    """A stable fingerprint of a decision record, for change detection."""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

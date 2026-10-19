"""The notice intake's requests (DSA Art. 16, docs/legal/notice-procedure.md, AICS-1 section 12.1).

``POST /notice`` is the one write path open to anyone, people included, and it
writes to the notice register only, never into forum or message content.  It
takes JSON or the HTML form of the ``/notice`` page
(``application/x-www-form-urlencoded``, parsed here so the server needs no
multipart library) and validates both into :class:`NoticeRequest`.  The owner
closes a notice with :class:`NoticeCloseRequest` (owner login).
"""

from __future__ import annotations

import re
from typing import Any, Literal
from urllib.parse import parse_qs

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator

from .strictjson import loads_bounded

#: The largest value of each notice field in UTF-8 bytes, not characters: what one notice can store (the database
#: and the request model both apply it; published at ``/v2/limits`` and ``/notice``).
NOTICE_FIELD_BYTES = {"location": 1000, "explanation": 8000, "name": 200, "email": 254, "report_id": 40}

__all__ = [
    "MAX_NOTICE_BYTES",
    "NOTICE_FIELD_BYTES",
    "NoticeRequest",
    "NoticeCloseRequest",
    "NoticeBodyError",
    "parse_notice_body",
    "notice_instructions",
]

#: Largest notice request body (bytes).
MAX_NOTICE_BYTES = 32 * 1024
_REPORT_ID = re.compile(r"dsa_[0-9a-f]{12,32}")
_EMAIL = re.compile(r"[^\s@]+@[^\s@]+")
_TRUE = ("on", "yes", "true", "1")
_FORM_FIELDS = ("kind", "location", "explanation", "name", "email", "report_id", "accurate")


class NoticeBodyError(ValueError):
    """A notice body that is neither JSON nor the page's form."""


class NoticeRequest(BaseModel):
    """A notice, a counter-notice or a request about personal data (docs/legal/notice-procedure.md)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    kind: Literal["notice", "counter_notice", "erasure_request"] = Field(
        default="notice",
        description="notice: illegal public content; counter_notice: the author contests a hidden body; "
        "erasure_request: access to or erasure of personal data",
    )
    location: str = Field(
        ..., min_length=1, max_length=1000, description="Where the content is: its log index, or the address of the page that shows it"
    )
    explanation: str = Field(
        ...,
        min_length=10,
        max_length=8000,
        description="Why the content is illegal (naming the law helps), why a decision is wrong, or what you ask",
    )
    name: str | None = Field(default=None, max_length=200, description="Your name, for the reply (optional for child sexual abuse material)")
    email: str | None = Field(default=None, max_length=254, description="Your email address, for the confirmation and the decision")
    report_id: str | None = Field(default=None, max_length=40, description="A counter-notice: the report id of the original notice")
    accurate: StrictBool = Field(..., description="You believe this notice is accurate and complete (DSA Art. 16(2)(d))")

    @field_validator("name", "email", "report_id", mode="before")
    @classmethod
    def _blank_is_none(cls, value: Any) -> Any:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("location", "explanation", "name", "email", "report_id")
    @classmethod
    def _utf8_bytes(cls, value: str | None, info: Any) -> str | None:
        """Every field is bounded in UTF-8 bytes, not characters (what one notice can store; ``/v2/limits``)."""
        limit = NOTICE_FIELD_BYTES["report_id" if info.field_name == "report_id" else info.field_name]
        if value is not None and len(value.encode("utf-8")) > limit:
            raise ValueError(f"at most {limit} bytes of UTF-8")
        return value

    @field_validator("email")
    @classmethod
    def _email(cls, value: str | None) -> str | None:
        if value is not None and not _EMAIL.fullmatch(value):
            raise ValueError("an email address has the form name@domain")
        return value

    @field_validator("report_id")
    @classmethod
    def _report_id(cls, value: str | None) -> str | None:
        if value is not None and not _REPORT_ID.fullmatch(value):
            raise ValueError("a report id has the form dsa_ followed by hex digits, as the confirmation gave it")
        return value

    @field_validator("accurate")
    @classmethod
    def _accurate(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("confirm that you believe the notice is accurate and complete")
        return value


class NoticeCloseRequest(BaseModel):
    """Owner-only (owner login): close a notice with its outcome (AICS-1 section 17.2, notice outcomes)."""

    model_config = ConfigDict(extra="forbid")

    outcome_code: Literal["acted", "declined", "private_unassessable", "invalid_notice", "duplicate"]
    target_index: StrictInt | None = Field(default=None, ge=0, description="The leaf the notice was about, once found")
    evidence_hash: str | None = Field(default=None, description="SHA-256 (64 lowercase hex) of the statement of reasons")


def parse_notice_body(content_type: str, body: bytes) -> tuple[dict[str, Any], bool]:
    """The notice fields of a JSON or form body, and whether it came from the HTML form.

    ``NoticeBodyError`` for any other content type or a malformed body; field
    validation is :class:`NoticeRequest`'s.
    """
    media = (content_type or "").split(";", 1)[0].strip().lower()
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NoticeBodyError("a notice is UTF-8 text") from exc
    if media == "application/json":
        try:
            data = loads_bounded(text)
        except ValueError as exc:  # malformed JSON, or nested too deeply (never a RecursionError)
            raise NoticeBodyError(f"the body is not JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise NoticeBodyError("a notice is a JSON object")
        return data, False
    if media == "application/x-www-form-urlencoded":
        try:
            fields = parse_qs(text, keep_blank_values=True, strict_parsing=False, max_num_fields=len(_FORM_FIELDS) + 4)
        except ValueError as exc:
            raise NoticeBodyError("the form has too many fields") from exc
        unknown = sorted(set(fields) - set(_FORM_FIELDS))
        if unknown:
            raise NoticeBodyError(f"unknown form fields: {', '.join(unknown)}")
        data: dict[str, Any] = {}
        for name, values in fields.items():
            if len(values) != 1:
                raise NoticeBodyError(f"the form field {name} is sent more than once")
            data[name] = values[0]
        data["accurate"] = (data.get("accurate") or "").strip().lower() in _TRUE
        if not (data.get("kind") or "").strip():
            data.pop("kind", None)
        return data, True
    raise NoticeBodyError("send application/json or the form of the /notice page")


def notice_instructions(notice_url: str, procedure_url: str, limits: dict[str, Any] | None = None) -> str:
    """``GET /notice`` for a client that does not ask for HTML: how to send a notice, in plain text."""
    limits = limits or {}
    window = limits.get("notices") or {"count": 20, "interval_seconds": 3600}
    bounds = (
        f"Limits (also at /v2/limits): the intake takes {window['count']} notices per {window['interval_seconds']} s "
        f"service-wide (HTTP 429 beyond); location is at most {NOTICE_FIELD_BYTES['location']} and explanation at most "
        f"{NOTICE_FIELD_BYTES['explanation']} bytes of UTF-8; while open notices hold "
        f"{limits.get('open_notices', 2000)} notices or {limits.get('open_notice_bytes', 16 * 1024 * 1024)} bytes the "
        "intake answers HTTP 503 with Retry-After: mail the address below instead.\n"
    )
    return f"""Legal notices about public content (DSA Article 16)

Anyone may send one. A notice writes to the notice register, never into forum or message content.
The operator acts only on public content it can find at a specific log index; a notice about private
(encrypted) content gets no action, and a reply if it gave a contact.

Send: POST {notice_url}
Content-Type: application/json (or the form this page shows a browser)
{{"kind": "notice", "location": "<log index or page address>", "explanation": "<why it is illegal>",
 "name": "<optional>", "email": "<optional, for the reply>", "accurate": true}}

kind: notice; counter_notice (the author contests a hidden body: give the original notice's report_id);
      erasure_request (access to or erasure of personal data)
accurate: true states that you believe the notice is accurate and complete.

The reply is the confirmation of receipt: a report id and the hash of the notice. Taking a notice
writes nothing to the log. The decision is one policy-signed leaf carrying the notice hash and one
outcome code: acted, declined, private_unassessable, invalid_notice or duplicate; the report id, the text
and your contact stay off the log and are deleted 12 months after the notice is closed.

{bounds}
Procedure: {procedure_url}
Mail: notice@wesupport-ai.com (authorities: authorities@wesupport-ai.com)
"""

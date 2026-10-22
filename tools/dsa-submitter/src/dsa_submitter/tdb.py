"""The client for the Commission's DSA Transparency Database.

Posts one statement per leaf to the documented single-statement endpoint with
``Authorization: Bearer`` and expects ``201 Created`` — anything else is an
error, as the documentation insists. Retries only what the brief allows:
5xx and network failures, with bounded exponential backoff. Every 4xx is
terminal for that leaf (recorded, not retried), with one deliberate exception
turned into success: a 422 that reports the ``puid`` as not unique carries the
previously created statement in ``existing``, which is the database's own
idempotency path and means the leaf was already submitted.

The token appears in exactly one place: the Authorization header. Exception
text and response bodies are scrubbed of it before they are returned anywhere,
so it can never reach a log line or the state file.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from . import schema

MAX_ATTEMPTS = 4
BASE_DELAY_SECONDS = 1.0
ERROR_BODY_LIMIT = 4000


class TdbError(Exception):
    """A terminal (4xx or non-retryable) failure for one statement."""

    def __init__(self, message, status=None, body=None):
        super().__init__(message)
        self.status = status
        self.body = body


class RetryableError(Exception):
    """A 5xx or network failure; the caller may try again later."""


def resolve_url(explicit_url=None, env_value=None):
    """The statement URL, with the production switch guarded.

    ``DSA_TRANSPARENCY_URL`` wins when set. Otherwise the documented production
    URL is used only when ``DSA_TRANSPARENCY_ENV=production`` is set explicitly;
    the default is the sandbox. A production URL reached any other way is
    refused.
    """
    if explicit_url:
        if explicit_url.rstrip("/") == schema.PRODUCTION_STATEMENT_URL.rstrip(
                "/") and env_value != "production":
            raise TdbError("refusing the production Transparency Database URL: set "
                           "DSA_TRANSPARENCY_ENV=production explicitly")
        return explicit_url
    if env_value == "production":
        return schema.PRODUCTION_STATEMENT_URL
    return schema.SANDBOX_STATEMENT_URL


class TransparencyClient:
    def __init__(self, url, token, timeout=30, sleeper=time.sleep, opener=None):
        self.url = url
        self.token = token
        self.timeout = timeout
        self._sleeper = sleeper
        self._opener = opener or urllib.request.build_opener()

    def _redact(self, text):
        if not self.token:
            return text
        # Also scrub a JSON-escaped echo, in case a body quotes the token.
        escaped = json.dumps(self.token)[1:-1]
        return text.replace(self.token, "***").replace(escaped, "***")

    def _post_once(self, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            })
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                return response.status, response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except urllib.error.URLError as exc:
            raise RetryableError(self._redact(f"network failure: {exc.reason}")) from None

    def _parse(self, body_text):
        try:
            return json.loads(body_text)
        except json.JSONDecodeError:
            return None

    def submit(self, payload):
        """POST one statement; return a result dict on 201 (or duplicate puid).

        Raises :class:`TdbError` for terminal 4xx answers and
        :class:`RetryableError` when every bounded attempt hit a 5xx or the
        network failed.
        """
        last_retryable = None
        for attempt in range(MAX_ATTEMPTS):
            if attempt:
                self._sleeper(BASE_DELAY_SECONDS * (2 ** (attempt - 1)))
            try:
                status, body_text = self._post_once(payload)
            except RetryableError as exc:
                last_retryable = exc
                continue
            body_text = self._redact(body_text)
            if status == 201:
                created = self._parse(body_text) or {}
                return {
                    "puid": created.get("puid", payload.get("puid")),
                    "uuid": created.get("uuid"),
                    "id": created.get("id"),
                    "permalink": created.get("permalink"),
                    "created_at": created.get("created_at"),
                    "duplicate": False,
                }
            if 500 <= status < 600:
                last_retryable = RetryableError(
                    f"HTTP {status}: {body_text[:ERROR_BODY_LIMIT]}")
                continue
            parsed = self._parse(body_text)
            if status == 422 and isinstance(parsed, dict) and parsed.get("existing"):
                existing = parsed["existing"]
                return {
                    "puid": payload.get("puid"),
                    "uuid": existing.get("uuid"),
                    "id": existing.get("id"),
                    "permalink": existing.get("permalink"),
                    "created_at": existing.get("created_at"),
                    "duplicate": True,
                }
            raise TdbError(f"HTTP {status}: {body_text[:ERROR_BODY_LIMIT]}",
                           status=status, body=body_text[:ERROR_BODY_LIMIT])
        raise last_retryable or RetryableError("submission failed")

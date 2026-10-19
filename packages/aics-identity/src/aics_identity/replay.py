"""Replay protection for signed HTTP requests and signed envelopes.

A replay check answers one question atomically: has this ``(keyid, nonce)``
pair been accepted before, while a signature carrying it could still verify?
:func:`aics_identity.http_signatures.verify_request` and
:func:`aics_identity.envelope.verify_envelope` take the check as a hook
(``replay_check=``) so a server can back it with durable storage, for
example its leaf table, instead of process memory.

Hook contract (:data:`ReplayCheck`)::

    replay_check(keyid: str, nonce: str, retain_until: int | None, now: int) -> bool

* Return ``True`` when the pair is fresh, after recording it, so that any
  later call with the same pair returns ``False`` at least until
  ``retain_until`` has passed.
* Return ``False`` when the pair was already recorded (a replay).  The
  verifier then raises its replay error.
* ``retain_until`` bounds how long the record matters: a record may be
  dropped once ``now`` has reached it.  Envelopes pass their ``expires``
  (AICS-1 section 4.3: a tuple whose recorded ``expires`` is greater than
  ``t`` is a replay, and at ``t >= expires`` the envelope is invalid anyway);
  request signatures pass the last second they pass the verifier's policy.
  ``None`` means the policy sets no bound (no ``expires`` and no maximum
  age) and the record must be kept for good.
* ``now`` is the verifier's current time; it honours a ``now=`` override
  passed to the verifier, which keeps tests deterministic.
* The check must be atomic: two concurrent calls with the same fresh pair
  must not both return ``True``.  With the single writer process AICS runs,
  an ``INSERT`` against a ``UNIQUE (keyid, nonce)`` constraint inside the
  write transaction is enough.
* The hook may raise.  The exception reaches the verifier's caller unchanged,
  so a server can raise its own error carrying, for instance, the index of
  the leaf that already used the nonce.

Verifiers call the hook only after every other check has passed, so a forged,
stale or malformed signature never consumes a nonce.

:class:`ReplayCache` is an in-process implementation of the hook, kept for
clients, tests and single-process tools.  It is lost on restart and bounded
in size (the oldest entries are evicted first), so a server must not rely on
it: a restarted or flooded cache accepts a captured request again.
"""

from __future__ import annotations

import math
import threading
import time
from typing import Callable

__all__ = ["ReplayCheck", "ReplayCache"]

#: ``replay_check(keyid, nonce, retain_until, now) -> bool`` - see the module docstring.
ReplayCheck = Callable[[str, str, int | None, int], bool]


class ReplayCache:
    """Thread-safe in-memory replay cache for ``(kid, nonce)`` pairs.

    Entries expire when the associated signature stops being valid (the
    ``expires`` / ``retain_until`` value supplied) or after ``default_ttl``
    seconds when :meth:`check_and_add` is given no expiry.  The cache never
    grows beyond ``max_entries``: the entries closest to expiry are dropped
    first, and expiry is re-checked lazily.

    An instance is directly usable as a :data:`ReplayCheck` hook::

        cache = ReplayCache()
        verify_request(..., replay_check=cache)
    """

    def __init__(self, *, default_ttl: float = 3600.0, max_entries: int = 65536) -> None:
        self._default_ttl = float(default_ttl)
        self._max_entries = int(max_entries)
        self._entries: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def _purge(self, now: float) -> None:
        expired = [k for k, until in self._entries.items() if until <= now]
        for key in expired:
            del self._entries[key]
        overflow = len(self._entries) - self._max_entries
        if overflow > 0:
            for key, _ in sorted(self._entries.items(), key=lambda kv: kv[1])[:overflow]:
                del self._entries[key]

    def seen(self, kid: str, nonce: str, *, expires: int | None = None, now: float | None = None) -> bool:
        """Return ``True`` if ``(kid, nonce)`` has already been seen (and is still cached)."""
        current = time.time() if now is None else float(now)
        with self._lock:
            self._purge(current)
            return (kid, nonce) in self._entries

    def check_and_add(
        self,
        kid: str,
        nonce: str,
        *,
        expires: int | None = None,
        now: float | None = None,
    ) -> bool:
        """Record ``(kid, nonce)``; return ``False`` if it was a replay, ``True`` if fresh.

        The entry is kept until ``expires`` (unix seconds) or, when
        ``expires`` is ``None``, for ``default_ttl`` seconds.
        """
        current = time.time() if now is None else float(now)
        until = float(expires) if expires is not None else current + self._default_ttl
        return self._check_and_add(kid, nonce, until, current)

    def __call__(self, keyid: str, nonce: str, retain_until: int | None = None, now: int | None = None) -> bool:
        """:data:`ReplayCheck` hook form; ``retain_until=None`` keeps the entry until evicted."""
        current = time.time() if now is None else float(now)
        until = math.inf if retain_until is None else float(retain_until)
        return self._check_and_add(keyid, nonce, until, current)

    def _check_and_add(self, kid: str, nonce: str, until: float, current: float) -> bool:
        with self._lock:
            self._purge(current)
            tag = (kid, nonce)
            if tag in self._entries:
                return False
            self._entries[tag] = until
            return True

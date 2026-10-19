"""Bound every exchange, with strict dispatch spacing and interruptible waits."""

from __future__ import annotations

import asyncio
import math
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from typing import Any, Awaitable, Callable


@dataclass
class Config:
    agents: int = 10
    think_time: float = 1.0
    duration: float = 60.0
    concurrency: int = 16
    rate: float = 10.0
    timeout: float = 10.0
    error_threshold: float = 0.10
    error_window: int = 100
    min_samples: int = 20
    consecutive_errors: int = 5
    setup_timeout: float = 1200.0
    max_requests: int = 100_000
    headroom: float = 0.5
    recipients: int = 1000
    body_bytes: int = 256

    def __post_init__(self):
        for key in (
            "agents",
            "concurrency",
            "error_window",
            "min_samples",
            "consecutive_errors",
            "max_requests",
            "recipients",
            "body_bytes",
        ):
            if not isinstance(getattr(self, key), int) or getattr(self, key) <= 0:
                raise ValueError(f"{key} must be a positive integer")
        for key in ("duration", "rate", "timeout", "setup_timeout"):
            if not math.isfinite(getattr(self, key)) or getattr(self, key) <= 0:
                raise ValueError(f"{key} must be finite and positive")
        if not math.isfinite(self.think_time) or self.think_time < 0:
            raise ValueError("think_time must be finite and nonnegative")
        if not 0 < self.error_threshold <= 1 or not 0 < self.headroom < 1:
            raise ValueError("error_threshold must be in (0,1]; headroom in (0,1)")
        if self.min_samples > self.error_window:
            raise ValueError("min_samples cannot exceed error_window")
        if self.body_bytes > 16_384:
            raise ValueError("body_bytes must be <= 16384 (leaves room for framing)")


class StopRun(Exception):
    """No more requests may be admitted in this phase."""


class RequestFailed(Exception):
    def __init__(self, reason: str, status: int | None = None, *, leaves: int = 0, refusal: bool = False):
        super().__init__(reason)
        self.reason, self.status, self.leaves, self.refusal = reason, status, leaves, refusal
        self.recorded = False


@dataclass
class Outcome:
    value: Any = None
    status: int | None = 200
    writes: int = 0
    leaves: int = 0
    registrations: int = 0
    gate_sessions: int = 0
    deliveries: int = 0
    bytes_received: int = 0


@dataclass
class RequestRecord:
    operation: str
    phase: str
    agent: str | None
    started: float
    finished: float
    latency_ms: float
    queue_ms: float
    status: int | None
    success: bool
    reason: str | None = None
    refusal: bool = False
    writes: int = 0
    leaves: int = 0
    registrations: int = 0
    gate_sessions: int = 0
    deliveries: int = 0
    bytes_received: int = 0


class RateController:
    """Actual dispatch spacing: a stall cannot accumulate catch-up burst credit."""

    def __init__(self, rate: float):
        self.interval = 1.0 / rate
        self.next_at = 0.0
        self.lock = asyncio.Lock()

    async def acquire(self, runner: Runner):
        async with self.lock:
            await runner.sleep(max(0.0, self.next_at - time.monotonic()))
            runner.check()
            self.next_at = time.monotonic() + self.interval


class Runner:
    def __init__(self, config: Config):
        self.config = config
        self.records: list[RequestRecord] = []
        self.semaphore = asyncio.Semaphore(config.concurrency)
        self.gate_slots = asyncio.Semaphore(config.concurrency)
        self.pacer = RateController(config.rate)
        self.stop = asyncio.Event()
        self.stop_reason: str | None = None
        self.started = time.monotonic()
        self.phase = "setup"
        self.deadline = self.started + config.setup_timeout
        self.phase_started = self.started
        self.phase_durations: dict[str, float] = {}
        self.errors: deque[bool] = deque(maxlen=config.error_window)
        self.error_streak = 0
        self.in_flight = 0
        self.peak_in_flight = 0
        self.dispatched = 0
        self.write_window = (20, 60.0)
        self.registration_window = (20, 60.0)
        self.sender_times: dict[str, deque] = defaultdict(deque)
        self.registration_times: dict[str, deque] = defaultdict(deque)
        self.sender_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self.details: dict[str, Any] = {}

    def halt(self, reason: str):
        if not self.stop.is_set():
            self.stop_reason = reason
            self.stop.set()

    def check(self):
        if self.stop.is_set():
            raise StopRun(self.stop_reason)
        if time.monotonic() >= self.deadline:
            self.halt("duration" if self.phase == "measurement" else "setup_deadline")
            raise StopRun(self.stop_reason)

    async def sleep(self, seconds: float):
        self.check()
        delay = min(seconds, max(0.0, self.deadline - time.monotonic()))
        if delay > 0:
            try:
                await asyncio.wait_for(self.stop.wait(), delay)
            except TimeoutError:
                pass
        else:
            await asyncio.sleep(0)
        self.check()

    def measure(self):
        self.check()
        now = time.monotonic()
        self.phase_durations[self.phase] = now - self.phase_started
        self.phase, self.phase_started = "measurement", now
        self.deadline = now + self.config.duration
        self.errors.clear()
        self.error_streak = 0

    def finish(self):
        self.phase_durations[self.phase] = time.monotonic() - self.phase_started

    async def reserve_sender(self, kid: str, *, registration: bool = False):
        """Caller holds sender lock. Count attempts, including uncertain results."""
        windows = [(self.sender_times[kid], self.write_window)]
        if registration:
            windows.append((self.registration_times[kid], self.registration_window))
        while True:
            self.check()
            now = time.monotonic()
            delay = 0.0
            for times, (count, interval) in windows:
                while times and times[0] <= now - interval:
                    times.popleft()
                if len(times) >= count:
                    delay = max(delay, times[0] + interval - now + 0.001)
            if delay <= 0:
                return
            await self.sleep(delay)

    async def request(
        self,
        operation: str,
        call: Callable[[], Awaitable[Outcome]],
        *,
        agent: str | None = None,
        write: bool = False,
        registration: bool = False,
    ) -> Any:
        queued = time.monotonic()
        self.check()
        if write:
            if agent is None:
                raise ValueError("a write requires an agent identifier")
            await self.reserve_sender(agent, registration=registration)
        async with self.semaphore:
            await self.pacer.acquire(self)
            if self.dispatched >= self.config.max_requests:
                self.halt("request_budget")
                raise StopRun(self.stop_reason)
            start = time.monotonic()
            self.dispatched += 1
            if write:
                self.sender_times[agent].append(start)
                if registration:
                    self.registration_times[agent].append(start)
            self.in_flight += 1
            self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
            outcome, error, cancelled = Outcome(status=None), None, False
            try:
                async with asyncio.timeout(min(self.config.timeout, max(0.001, self.deadline - start))):
                    outcome = await call()
            except RequestFailed as exc:
                error = exc
            except TimeoutError:
                error = RequestFailed("timeout")
            except asyncio.CancelledError:
                error, cancelled = RequestFailed("cancelled_in_flight"), True
            except Exception as exc:
                error = RequestFailed("client_" + type(exc).__name__)
            finally:
                end = time.monotonic()
                self.in_flight -= 1
                ok = error is None
                record = RequestRecord(
                    operation,
                    self.phase,
                    agent,
                    start - self.started,
                    end - self.started,
                    (end - start) * 1000,
                    (start - queued) * 1000,
                    error.status if error else outcome.status,
                    ok,
                    reason=error.reason if error else None,
                    refusal=bool(error and error.refusal),
                    **{
                        k: getattr(outcome, k) if ok else (error.leaves if k == "leaves" else 0)
                        for k in (
                            "writes",
                            "leaves",
                            "registrations",
                            "gate_sessions",
                            "deliveries",
                            "bytes_received",
                        )
                    },
                )
                self.records.append(record)
                self.errors.append(not ok)
                self.error_streak = 0 if ok else self.error_streak + 1
                if self.error_streak >= self.config.consecutive_errors:
                    self.halt("consecutive_errors")
                elif len(self.errors) >= self.config.min_samples:
                    if sum(self.errors) / len(self.errors) > self.config.error_threshold:
                        self.halt("error_rate")
            if cancelled:
                raise asyncio.CancelledError
            if error:
                error.recorded = True
                raise error
            return outcome.value

    async def workers(self, jobs):
        """Failed actors retire; an uncertain write is never resent."""

        async def guard(job):
            try:
                await job
            except StopRun:
                return
            except RequestFailed as exc:
                if not exc.recorded:
                    self.details["failure"] = exc.reason
                    self.halt("validation_failure")

        tasks = [asyncio.create_task(guard(job)) for job in jobs]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    def config_dict(self):
        return asdict(self.config)

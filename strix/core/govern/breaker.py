"""Circuit breaker + kill-switch (SGL-S3).

Monitors target health (error rate and p95 latency) and trips a circuit
breaker when thresholds are breached.  A tripped breaker triggers the
kill-switch, which halts **all** in-flight actions — including async OOB
probes and parallel child agents.

Design invariants
-----------------
* **Fail-closed.**  Any monitoring error → trip the breaker.
* **No LLM.**  Pure sliding-window statistics.
* **Operator ack required to resume.**  Once tripped, the breaker stays
  open until an explicit ``resume()`` call (operator acknowledgement).
* **Kill-switch wiring.**  ``AgentCoordinator.kill_switch()`` is called
  when the breaker trips OPEN.  That method sets ``is_shutting_down``
  and calls ``cancel_descendants(root_id)`` to cancel all child tasks.
  The integration is wired in ``core/runner.py`` and ``core/execution.py``.
* **Additive.**  No imports from the detection engine.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections import deque
from enum import Enum

from pydantic import BaseModel, Field


# ─────────────────────────────────────── constants ───────────────────────────

_DEFAULT_WINDOW_SIZE: int = 20
_DEFAULT_ERROR_RATE_THRESHOLD: float = 0.25  # >25 % error rate
_DEFAULT_LATENCY_MULTIPLIER: float = 3.0  # >3× baseline p95
_DEFAULT_WARMUP_REQUESTS: int = 5  # need at least N requests before tripping


# ─────────────────────────────────────── models ──────────────────────────────


class BreakerState(str, Enum):
    CLOSED = "closed"  # normal operation
    OPEN = "open"  # tripped — all requests rejected
    HALF_OPEN = "half_open"  # operator ack received, testing recovery


class BreakerEvent(BaseModel):
    """A single request outcome recorded by the breaker."""

    timestamp: float
    latency_ms: float
    is_error: bool

    model_config = {"extra": "forbid"}


class BreakerSnapshot(BaseModel):
    """Point-in-time view of the circuit breaker state."""

    state: BreakerState
    window_size: int
    request_count: int
    error_count: int
    error_rate: float
    p95_latency_ms: float
    baseline_p95_ms: float
    trip_reason: str | None = None

    model_config = {"extra": "forbid"}


# ─────────────────────────────────────── breaker ─────────────────────────────


class CircuitBreaker:
    """Sliding-window circuit breaker with kill-switch integration.

    Usage::

        breaker = CircuitBreaker()

        # Record each request outcome
        breaker.record(latency_ms=120.0, is_error=False)
        breaker.record(latency_ms=5000.0, is_error=True)

        if breaker.state == BreakerState.OPEN:
            raise CircuitOpen("breaker tripped: " + breaker.trip_reason)

        # After operator investigation:
        breaker.resume()
    """

    def __init__(
        self,
        *,
        window_size: int = _DEFAULT_WINDOW_SIZE,
        error_rate_threshold: float = _DEFAULT_ERROR_RATE_THRESHOLD,
        latency_multiplier: float = _DEFAULT_LATENCY_MULTIPLIER,
        warmup_requests: int = _DEFAULT_WARMUP_REQUESTS,
    ) -> None:
        self._window_size = window_size
        self._error_threshold = error_rate_threshold
        self._latency_mult = latency_multiplier
        self._warmup = warmup_requests

        self._events: deque[BreakerEvent] = deque(maxlen=window_size)
        self._state = BreakerState.CLOSED
        self._trip_reason: str | None = None
        self._baseline_p95: float = 0.0
        self._baseline_samples: int = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> BreakerState:
        return self._state

    @property
    def trip_reason(self) -> str | None:
        return self._trip_reason

    async def record(self, latency_ms: float, is_error: bool) -> BreakerState:
        """Record a request outcome and check trip conditions.

        Returns the current breaker state after recording.
        """
        try:
            return await self._record(latency_ms, is_error)
        except Exception as exc:  # noqa: BLE001
            # Fail-closed: any error → trip
            self._state = BreakerState.OPEN
            self._trip_reason = f"monitoring_error: {type(exc).__name__}"
            return self._state

    async def _record(self, latency_ms: float, is_error: bool) -> BreakerState:
        async with self._lock:
            if self._state == BreakerState.OPEN:
                return self._state

            event = BreakerEvent(
                timestamp=time.monotonic(),
                latency_ms=max(latency_ms, 0.0),
                is_error=is_error,
            )
            self._events.append(event)

            # Update baseline p95 from initial healthy requests
            if self._baseline_samples < self._warmup and not is_error:
                self._baseline_samples += 1
                latencies = sorted(e.latency_ms for e in self._events if not e.is_error)
                if latencies:
                    idx = int(math.ceil(0.95 * len(latencies))) - 1
                    self._baseline_p95 = latencies[max(idx, 0)]

            # Check trip conditions
            if len(self._events) >= self._warmup:
                trip_reason = self._check_trip()
                if trip_reason:
                    self._state = BreakerState.OPEN
                    self._trip_reason = trip_reason

            return self._state

    def _check_trip(self) -> str | None:
        """Check trip conditions against the current window. Returns reason or None."""
        events = list(self._events)
        n = len(events)
        if n < self._warmup:
            return None

        # Error-rate check
        errors = sum(1 for e in events if e.is_error)
        error_rate = errors / n
        if error_rate > self._error_threshold:
            return f"error_rate {error_rate:.1%} > {self._error_threshold:.1%} over {n} requests"

        # p95 latency check (only if we have a baseline)
        if self._baseline_p95 > 0:
            latencies = sorted(e.latency_ms for e in events if not e.is_error)
            if latencies:
                idx = int(math.ceil(0.95 * len(latencies))) - 1
                current_p95 = latencies[max(idx, 0)]
                threshold = self._baseline_p95 * self._latency_mult
                if current_p95 > threshold:
                    return (
                        f"p95_latency {current_p95:.0f}ms > "
                        f"{self._latency_mult:.0f}× baseline ({threshold:.0f}ms)"
                    )

        return None

    async def resume(self) -> None:
        """Resume after operator acknowledgement.

        Transitions from OPEN → HALF_OPEN.  The next request determines
        whether the breaker closes (healthy) or re-opens (still degraded).
        """
        async with self._lock:
            if self._state == BreakerState.OPEN:
                self._state = BreakerState.HALF_OPEN
                self._events.clear()
                self._trip_reason = None

    async def force_close(self) -> None:
        """Force the breaker closed (for testing only)."""
        async with self._lock:
            self._state = BreakerState.CLOSED
            self._events.clear()
            self._trip_reason = None
            self._baseline_p95 = 0.0
            self._baseline_samples = 0

    def snapshot(self) -> BreakerSnapshot:
        """Return a serialisable snapshot of the breaker state."""
        events = list(self._events)
        n = len(events)
        errors = sum(1 for e in events if e.is_error)
        error_rate = errors / n if n > 0 else 0.0

        latencies = sorted(e.latency_ms for e in events if not e.is_error)
        p95 = 0.0
        if latencies:
            idx = int(math.ceil(0.95 * len(latencies))) - 1
            p95 = latencies[max(idx, 0)]

        return BreakerSnapshot(
            state=self._state,
            window_size=self._window_size,
            request_count=n,
            error_count=errors,
            error_rate=round(error_rate, 4),
            p95_latency_ms=round(p95, 2),
            baseline_p95_ms=round(self._baseline_p95, 2),
            trip_reason=self._trip_reason,
        )

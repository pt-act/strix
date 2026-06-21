"""Tests for strix.core.govern.breaker — SGL-S3.

SP6: circuit breaker trips on error-rate >25%/20 reqs OR p95 latency
     >3x baseline.  Kill-switch halts all in-flight actions.  Zero-tolerance.
"""

from __future__ import annotations

import asyncio

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from strix.core.govern.breaker import (
    BreakerSnapshot,
    BreakerState,
    CircuitBreaker,
)


# ══════════════════════════════════════════════════════════════════════════════
# TG6 — Focused tests
# ══════════════════════════════════════════════════════════════════════════════


class TestBreakerClosed:
    """TG6.1 — normal operation (CLOSED state)."""

    @pytest.mark.asyncio
    async def test_healthy_requests_stay_closed(self) -> None:
        breaker = CircuitBreaker(window_size=20, warmup_requests=3)
        for _ in range(10):
            state = await breaker.record(latency_ms=100.0, is_error=False)
            assert state == BreakerState.CLOSED

    @pytest.mark.asyncio
    async def test_low_error_rate_stays_closed(self) -> None:
        breaker = CircuitBreaker(window_size=20, error_rate_threshold=0.25, warmup_requests=3)
        # 3 healthy + 1 error = 25% error rate (at threshold, not above)
        for _ in range(3):
            await breaker.record(latency_ms=100.0, is_error=False)
        state = await breaker.record(latency_ms=100.0, is_error=True)
        assert state == BreakerState.CLOSED


class TestBreakerTrips:
    """TG6.2 — trip conditions."""

    @pytest.mark.asyncio
    async def test_error_rate_trips(self) -> None:
        breaker = CircuitBreaker(window_size=20, error_rate_threshold=0.25, warmup_requests=3)
        # 3 healthy + 3 errors = 50% error rate over 6 requests
        for _ in range(3):
            await breaker.record(latency_ms=100.0, is_error=False)
        for _ in range(3):
            await breaker.record(latency_ms=100.0, is_error=True)
        assert breaker.state == BreakerState.OPEN
        assert "error_rate" in (breaker.trip_reason or "")

    @pytest.mark.asyncio
    async def test_latency_spike_trips(self) -> None:
        breaker = CircuitBreaker(
            window_size=20, latency_multiplier=3.0, warmup_requests=3
        )
        # Build baseline: all 100ms
        for _ in range(5):
            await breaker.record(latency_ms=100.0, is_error=False)
        # Spike: 500ms > 3x baseline (300ms)
        for _ in range(5):
            await breaker.record(latency_ms=500.0, is_error=False)
        assert breaker.state == BreakerState.OPEN
        assert "p95_latency" in (breaker.trip_reason or "")

    @pytest.mark.asyncio
    async def test_stay_open_after_trip(self) -> None:
        breaker = CircuitBreaker(window_size=5, error_rate_threshold=0.25, warmup_requests=3)
        for _ in range(3):
            await breaker.record(latency_ms=100.0, is_error=False)
        for _ in range(3):
            await breaker.record(latency_ms=100.0, is_error=True)
        assert breaker.state == BreakerState.OPEN
        # Further records are rejected while open
        state = await breaker.record(latency_ms=100.0, is_error=False)
        assert state == BreakerState.OPEN


class TestBreakerResume:
    """TG6.3 — operator ack resume flow."""

    @pytest.mark.asyncio
    async def test_resume_transitions_to_half_open(self) -> None:
        breaker = CircuitBreaker(window_size=5, error_rate_threshold=0.25, warmup_requests=3)
        for _ in range(3):
            await breaker.record(latency_ms=100.0, is_error=False)
        for _ in range(3):
            await breaker.record(latency_ms=100.0, is_error=True)
        assert breaker.state == BreakerState.OPEN

        await breaker.resume()
        assert breaker.state == BreakerState.HALF_OPEN

    @pytest.mark.asyncio
    async def test_resume_clears_events(self) -> None:
        breaker = CircuitBreaker(window_size=5, error_rate_threshold=0.25, warmup_requests=3)
        for _ in range(3):
            await breaker.record(latency_ms=100.0, is_error=False)
        for _ in range(3):
            await breaker.record(latency_ms=100.0, is_error=True)

        await breaker.resume()
        snap = breaker.snapshot()
        assert snap.request_count == 0  # cleared
        assert snap.trip_reason is None

    @pytest.mark.asyncio
    async def test_resume_only_from_open(self) -> None:
        breaker = CircuitBreaker(warmup_requests=3)
        # Already closed — resume is a no-op
        await breaker.resume()
        assert breaker.state == BreakerState.CLOSED


class TestBreakerSnapshot:
    """TG6.4 — snapshot serialisation."""

    @pytest.mark.asyncio
    async def test_snapshot_fields(self) -> None:
        breaker = CircuitBreaker(window_size=20, warmup_requests=3)
        # 10 healthy + 1 error = 9% error rate (well under 25%)
        for _ in range(10):
            await breaker.record(latency_ms=100.0, is_error=False)
        await breaker.record(latency_ms=200.0, is_error=True)

        snap = breaker.snapshot()
        assert snap.state == BreakerState.CLOSED
        assert snap.request_count == 11
        assert snap.error_count == 1
        assert snap.error_rate > 0.0
        assert snap.baseline_p95_ms > 0.0

    @pytest.mark.asyncio
    async def test_snapshot_roundtrip(self) -> None:
        breaker = CircuitBreaker(warmup_requests=3)
        for _ in range(5):
            await breaker.record(latency_ms=100.0, is_error=False)
        snap = breaker.snapshot()
        data = snap.model_dump()
        restored = BreakerSnapshot(**data)
        assert restored.request_count == 5


class TestForceClose:
    """TG6.5 — force close (testing helper)."""

    @pytest.mark.asyncio
    async def test_force_close_resets_state(self) -> None:
        breaker = CircuitBreaker(window_size=5, error_rate_threshold=0.25, warmup_requests=3)
        for _ in range(3):
            await breaker.record(latency_ms=100.0, is_error=False)
        for _ in range(3):
            await breaker.record(latency_ms=100.0, is_error=True)
        assert breaker.state == BreakerState.OPEN

        await breaker.force_close()
        assert breaker.state == BreakerState.CLOSED
        snap = breaker.snapshot()
        assert snap.request_count == 0


# ══════════════════════════════════════════════════════════════════════════════
# SP6 — PBT: zero-tolerance trip conditions
# ══════════════════════════════════════════════════════════════════════════════

_latency_st = st.floats(min_value=1.0, max_value=10000.0, allow_nan=False, allow_infinity=False)
_error_st = st.booleans()
_window_st = st.integers(min_value=5, max_value=50)


@given(st.lists(st.tuples(_latency_st, _error_st), min_size=5, max_size=30), _window_st)
@settings(max_examples=200)
def test_sp6_error_rate_trip(
    outcomes: list[tuple[float, bool]], window_size: int
) -> None:
    """SP6: if error rate in window > 25%, breaker trips (or stays tripped)."""
    breaker = CircuitBreaker(
        window_size=window_size,
        error_rate_threshold=0.25,
        warmup_requests=3,
    )

    async def _run() -> None:
        nonlocal breaker
        for latency, is_error in outcomes:
            await breaker.record(latency_ms=latency, is_error=is_error)
            if breaker.state == BreakerState.OPEN:
                break

    asyncio.run(_run())

    # If we had enough requests and error rate > 25%, breaker should be OPEN
    events_in_window = outcomes[:window_size]
    if len(events_in_window) >= 3:
        error_count = sum(1 for _, err in events_in_window if err)
        error_rate = error_count / len(events_in_window)
        if error_rate > 0.25:
            assert breaker.state == BreakerState.OPEN, (
                f"Error rate {error_rate:.1%} > 25% but breaker is {breaker.state}"
            )


@given(st.integers(min_value=3, max_value=20))
@settings(max_examples=100)
def test_sp6_latency_baseline_trip(warmup: int) -> None:
    """SP6: p95 latency > 3x baseline → breaker trips."""
    breaker = CircuitBreaker(
        window_size=20,
        latency_multiplier=3.0,
        warmup_requests=warmup,
    )

    async def _run() -> None:
        # Build baseline at 100ms
        for _ in range(warmup + 2):
            await breaker.record(latency_ms=100.0, is_error=False)
        # Spike to 500ms (>3x 100ms baseline)
        for _ in range(warmup):
            await breaker.record(latency_ms=500.0, is_error=False)

    asyncio.run(_run())
    assert breaker.state == BreakerState.OPEN, (
        f"p95 spike should trip breaker; state={breaker.state}"
    )

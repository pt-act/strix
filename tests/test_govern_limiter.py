"""Tests for strix.core.govern.limiter — SGL-S2.

Tiers
-----
Tier 1 — Focused (deterministic): TG3.x covers rate/cred guard paths.
Tier 2 — PBT (Hypothesis): SP4 rate/cred bound under burst + concurrency.

SP4: ``RateLimiter.acquire`` blocks or rejects beyond the configured rps.
     ``CredGuard.check_and_record`` locks out after cap attempts per window.
     Both hold under concurrent coroutines.
"""

from __future__ import annotations

import asyncio

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from strix.core.govern.limiter import (
    CredGuard,
    CredLimitExceeded,
    CredLockedOut,
    RateLimiter,
    RateLimitExceeded,
)


# ══════════════════════════════════════════════════════════════════════════════
# TG3 — Focused tests
# ══════════════════════════════════════════════════════════════════════════════


class TestRateLimiter:
    """TG3.1 — per-host rate limiting."""

    @pytest.mark.asyncio
    async def test_under_limit_allows(self) -> None:
        limiter = RateLimiter(rate_rps=10, window_s=1.0)
        # Should allow up to 10 requests without blocking
        for _ in range(10):
            await limiter.acquire("example.com")

    @pytest.mark.asyncio
    async def test_over_limit_blocks_in_blocking_mode(self) -> None:
        limiter = RateLimiter(rate_rps=2, window_s=1.0)
        await limiter.acquire("example.com")
        await limiter.acquire("example.com")
        # Third should need to wait — test with a short timeout
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(limiter.acquire("example.com"), timeout=0.05)

    @pytest.mark.asyncio
    async def test_over_limit_raises_in_nonblocking_mode(self) -> None:
        limiter = RateLimiter(rate_rps=2, window_s=1.0)
        await limiter.acquire("example.com", block=False)
        await limiter.acquire("example.com", block=False)
        with pytest.raises(RateLimitExceeded) as exc_info:
            await limiter.acquire("example.com", block=False)
        assert "example.com" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_hosts_independent(self) -> None:
        limiter = RateLimiter(rate_rps=1, window_s=1.0)
        await limiter.acquire("a.com", block=False)
        await limiter.acquire("b.com", block=False)
        # Each host has its own window

    @pytest.mark.asyncio
    async def test_retry_after_records(self) -> None:
        limiter = RateLimiter(rate_rps=10, window_s=1.0)
        await limiter.acquire("example.com", block=False)
        await limiter.record_retry_after("example.com", 5.0)
        # Host should now be effectively paused for 5s
        with pytest.raises(RateLimitExceeded) as exc_info:
            await limiter.acquire("example.com", block=False)
        assert exc_info.value.retry_after > 4.0  # ~5s minus small delta

    @pytest.mark.asyncio
    async def test_reset_clears_state(self) -> None:
        limiter = RateLimiter(rate_rps=1, window_s=1.0)
        await limiter.acquire("example.com", block=False)
        await limiter.reset("example.com")
        # Should succeed again after reset
        await limiter.acquire("example.com", block=False)

    @pytest.mark.asyncio
    async def test_reset_all(self) -> None:
        limiter = RateLimiter(rate_rps=1, window_s=1.0)
        await limiter.acquire("a.com", block=False)
        await limiter.acquire("b.com", block=False)
        await limiter.reset()
        await limiter.acquire("a.com", block=False)
        await limiter.acquire("b.com", block=False)

    def test_state_snapshot(self) -> None:
        limiter = RateLimiter(rate_rps=10, window_s=1.0)
        snap = limiter.state_snapshot("example.com")
        assert snap.host == "example.com"
        assert snap.request_count == 0
        assert snap.rate_rps == 10.0


class TestCredGuard:
    """TG3.2 — per-route credential cap."""

    @pytest.mark.asyncio
    async def test_under_cap_allows(self) -> None:
        guard = CredGuard(cap=3, window_s=300.0, lockout_s=600.0)
        for _ in range(3):
            await guard.check_and_record("POST /api/login")

    @pytest.mark.asyncio
    async def test_over_cap_locks_out(self) -> None:
        guard = CredGuard(cap=2, window_s=300.0, lockout_s=600.0)
        await guard.check_and_record("POST /api/login")
        await guard.check_and_record("POST /api/login")
        with pytest.raises(CredLockedOut):
            await guard.check_and_record("POST /api/login")

    @pytest.mark.asyncio
    async def test_success_resets_route(self) -> None:
        guard = CredGuard(cap=2, window_s=300.0, lockout_s=600.0)
        await guard.check_and_record("POST /api/login")
        await guard.record_outcome("POST /api/login", success=True)
        # Counter reset — can try again
        await guard.check_and_record("POST /api/login")
        await guard.check_and_record("POST /api/login")

    @pytest.mark.asyncio
    async def test_routes_independent(self) -> None:
        guard = CredGuard(cap=1, window_s=300.0, lockout_s=600.0)
        await guard.check_and_record("POST /api/login")
        await guard.check_and_record("POST /api/register")  # different route

    @pytest.mark.asyncio
    async def test_reset_clears_state(self) -> None:
        guard = CredGuard(cap=1, window_s=300.0, lockout_s=600.0)
        await guard.check_and_record("POST /api/login")
        await guard.reset("POST /api/login")
        await guard.check_and_record("POST /api/login")

    @pytest.mark.asyncio
    async def test_reset_all(self) -> None:
        guard = CredGuard(cap=1, window_s=300.0, lockout_s=600.0)
        await guard.check_and_record("POST /api/login")
        await guard.check_and_record("POST /api/register")
        await guard.reset()
        await guard.check_and_record("POST /api/login")
        await guard.check_and_record("POST /api/register")

    def test_state_snapshot(self) -> None:
        guard = CredGuard(cap=3, window_s=300.0, lockout_s=600.0)
        snap = guard.state_snapshot("POST /api/login")
        assert snap.route == "POST /api/login"
        assert snap.attempt_count == 0
        assert snap.cap == 3
        assert not snap.locked_out

    @pytest.mark.asyncio
    async def test_state_snapshot_after_attempts(self) -> None:
        guard = CredGuard(cap=3, window_s=300.0, lockout_s=600.0)
        await guard.check_and_record("POST /api/login")
        await guard.check_and_record("POST /api/login")
        snap = guard.state_snapshot("POST /api/login")
        assert snap.attempt_count == 2
        assert not snap.locked_out

    @pytest.mark.asyncio
    async def test_record_outcome_failure_is_noop(self) -> None:
        guard = CredGuard(cap=2, window_s=300.0, lockout_s=600.0)
        await guard.check_and_record("POST /api/login")
        await guard.record_outcome("POST /api/login", success=False)
        snap = guard.state_snapshot("POST /api/login")
        assert snap.attempt_count == 1  # still 1, not reset


class TestConcurrencySafety:
    """TG3.3 — concurrent coroutines must not breach caps."""

    @pytest.mark.asyncio
    async def test_rate_limiter_concurrent(self) -> None:
        """10 concurrent acquires against rps=5 — at most 5 succeed immediately."""
        limiter = RateLimiter(rate_rps=5, window_s=1.0)
        results: list[bool] = []

        async def try_acquire() -> None:
            try:
                await limiter.acquire("example.com", block=False)
                results.append(True)
            except RateLimitExceeded:
                results.append(False)

        await asyncio.gather(*[try_acquire() for _ in range(10)])
        assert sum(results) <= 5, f"Expected <=5 successes, got {sum(results)}"

    @pytest.mark.asyncio
    async def test_cred_guard_concurrent(self) -> None:
        """10 concurrent credential attempts against cap=3 — at most 3 succeed."""
        guard = CredGuard(cap=3, window_s=300.0, lockout_s=600.0)
        results: list[bool] = []

        async def try_cred() -> None:
            try:
                await guard.check_and_record("POST /api/login")
                results.append(True)
            except (CredLimitExceeded, CredLockedOut):
                results.append(False)

        await asyncio.gather(*[try_cred() for _ in range(10)])
        assert sum(results) <= 3, f"Expected <=3 successes, got {sum(results)}"


# ══════════════════════════════════════════════════════════════════════════════
# SP4 — PBT: rate/cred bound under burst + concurrency
# ══════════════════════════════════════════════════════════════════════════════

_host_st = st.from_regex(
    r"[a-z][a-z0-9-]{0,8}\.(com|net|io)", fullmatch=True
)
_rate_st = st.floats(min_value=1.0, max_value=20.0, allow_nan=False, allow_infinity=False)
_cap_st = st.integers(min_value=1, max_value=10)


@given(_host_st, _rate_st, st.integers(min_value=5, max_value=30))
@settings(max_examples=100)
def test_sp4_rate_limiter_bounded(
    host: str, rate: float, burst: int
) -> None:
    """SP4: the number of non-blocking acquires in a burst ≤ int(rate * window)."""
    limiter = RateLimiter(rate_rps=rate, window_s=1.0)
    successes = 0

    async def _run() -> int:
        nonlocal successes
        for _ in range(burst):
            try:
                await limiter.acquire(host, block=False)
                successes += 1
            except RateLimitExceeded:
                pass
        return successes

    asyncio.run(_run())
    max_allowed = int(rate * 1.0)
    assert successes <= max_allowed, (
        f"Rate {rate} rps: expected <= {max_allowed} successes, got {successes}"
    )


@given(_host_st, _cap_st)
@settings(max_examples=100)
def test_sp4_cred_guard_bounded(host: str, cap: int) -> None:
    """SP4: the number of credential attempts before lockout ≤ cap."""
    guard = CredGuard(cap=cap, window_s=300.0, lockout_s=600.0)
    successes = 0

    async def _run() -> None:
        nonlocal successes
        for _ in range(cap + 5):  # try more than cap
            try:
                await guard.check_and_record(f"POST /{host}")
                successes += 1
            except (CredLimitExceeded, CredLockedOut):
                pass

    asyncio.run(_run())
    assert successes <= cap, (
        f"Cap {cap}: expected <= {cap} successes, got {successes}"
    )

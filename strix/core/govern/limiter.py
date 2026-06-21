"""Rate-limiting and credential-cap guardrails (SGL-S2).

Provides two concurrency-safe guards that gate outbound network activity:

* **RateLimiter** — per-host sliding-window rate limit (default 10 rps).
  Honors ``Retry-After`` headers.  Callers invoke
  :meth:`RateLimiter.acquire` before every outbound request; if the
  limit would be exceeded the call blocks until the window permits it
  (or raises :class:`RateLimitExceeded` in non-blocking mode).

* **CredGuard** — per-route credential cap (default 3 attempts per
  window).  Designed to prevent credential-spray brute-force at scale.
  Lockout-aware: once a route is locked out, all attempts are rejected
  until the lockout expires.

Design invariants
-----------------
* **Concurrency-safe.**  Both guards use ``asyncio.Lock`` internally.
  The agent graph runs children in parallel; the caps must hold under
  concurrent children.
* **Fail-closed.**  Any internal error → reject (the caller treats
  rejection as DENY).
* **Deterministic.**  No LLM, no network I/O.  Pure time-based
  accounting.
* **Additive.**  No imports from the detection engine.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque

from pydantic import BaseModel, Field


# ─────────────────────────────────────── constants ───────────────────────────

_DEFAULT_RATE_RPS: float = 10.0
_DEFAULT_RATE_WINDOW_S: float = 1.0

_DEFAULT_CRED_CAP: int = 3
_DEFAULT_CRED_WINDOW_S: float = 300.0  # 5 minutes
_DEFAULT_LOCKOUT_S: float = 600.0  # 10 minutes


# ─────────────────────────────────────── exceptions ──────────────────────────


class RateLimitExceeded(Exception):
    """Raised when a rate limit is breached in non-blocking mode."""

    def __init__(self, host: str, retry_after: float) -> None:
        super().__init__(f"rate limit exceeded for {host}; retry after {retry_after:.2f}s")
        self.host = host
        self.retry_after = retry_after


class CredLimitExceeded(Exception):
    """Raised when the credential cap for a route is breached."""

    def __init__(self, route: str, cap: int) -> None:
        super().__init__(
            f"credential cap ({cap}) exceeded for route {route}"
        )
        self.route = route
        self.cap = cap


class CredLockedOut(Exception):
    """Raised when a route is in lockout after exceeding the credential cap."""

    def __init__(self, route: str, remaining_s: float) -> None:
        super().__init__(
            f"route {route} is locked out; retry after {remaining_s:.1f}s"
        )
        self.route = route
        self.remaining_s = remaining_s


# ─────────────────────────────────────── models ──────────────────────────────


class RateLimiterState(BaseModel):
    """Snapshot of a single host's rate-limiter state (for audit)."""

    host: str
    request_count: int
    window_start: float
    rate_rps: float

    model_config = {"extra": "forbid"}


class CredRouteState(BaseModel):
    """Snapshot of a single route's credential-guard state (for audit)."""

    route: str
    attempt_count: int
    cap: int
    window_start: float
    locked_out: bool
    lockout_expires: float | None = None

    model_config = {"extra": "forbid"}


# ─────────────────────────────────────── rate limiter ────────────────────────


class RateLimiter:
    """Per-host sliding-window rate limiter.

    Usage::

        limiter = RateLimiter()
        await limiter.acquire("example.com")       # blocks if over limit
        await limiter.acquire("example.com", block=False)  # raises if over limit
    """

    def __init__(
        self,
        *,
        rate_rps: float = _DEFAULT_RATE_RPS,
        window_s: float = _DEFAULT_RATE_WINDOW_S,
    ) -> None:
        self._rate = rate_rps
        self._window = window_s
        # host → deque of timestamps within the current window
        self._windows: dict[str, deque[float]] = defaultdict(lambda: deque())
        # host → monotonic timestamp until which the host is paused
        self._paused_until: dict[str, float] = {}
        self._lock = asyncio.Lock()

    @property
    def rate_rps(self) -> float:
        return self._rate

    async def acquire(self, host: str, *, block: bool = True) -> None:
        """Wait (or reject) until a request to *host* is permitted.

        Parameters
        ----------
        host:
            The target hostname.
        block:
            If ``True`` (default), sleeps until the window permits the
            request.  If ``False``, raises :class:`RateLimitExceeded`
            immediately.
        """
        try:
            return await self._acquire(host, block=block)
        except RateLimitExceeded:
            raise
        except Exception as exc:  # noqa: BLE001
            # Fail-closed: any internal error → reject
            raise RateLimitExceeded(host, retry_after=self._window) from exc

    async def _acquire(self, host: str, *, block: bool) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()

                # Check Retry-After pause
                paused = self._paused_until.get(host, 0.0)
                if now < paused:
                    retry_after = paused - now
                    if not block:
                        raise RateLimitExceeded(host, retry_after=max(retry_after, 0.01))
                    # Release lock before sleeping
                    await asyncio.sleep(max(retry_after, 0.01))
                    continue

                window = self._windows[host]

                # Purge expired entries
                cutoff = now - self._window
                while window and window[0] <= cutoff:
                    window.popleft()

                if len(window) < int(self._rate * self._window):
                    window.append(now)
                    return

                # Calculate how long until the oldest entry expires
                retry_after = window[0] + self._window - now

            if not block:
                raise RateLimitExceeded(host, retry_after=max(retry_after, 0.01))

            await asyncio.sleep(max(retry_after, 0.01))

    async def record_retry_after(self, host: str, retry_after_s: float) -> None:
        """Record a server-sent ``Retry-After`` delay for *host*.

        The host is effectively paused for ``retry_after_s`` seconds.
        """
        async with self._lock:
            self._paused_until[host] = time.monotonic() + retry_after_s

    def state_snapshot(self, host: str) -> RateLimiterState:
        """Return a serialisable snapshot of *host*'s rate-limiter state."""
        window = self._windows.get(host, deque())
        return RateLimiterState(
            host=host,
            request_count=len(window),
            window_start=window[0] if window else 0.0,
            rate_rps=self._rate,
        )

    async def reset(self, host: str | None = None) -> None:
        """Clear rate-limit state for *host* (or all hosts if ``None``)."""
        async with self._lock:
            if host is None:
                self._windows.clear()
                self._paused_until.clear()
            else:
                self._windows.pop(host, None)
                self._paused_until.pop(host, None)


# ─────────────────────────────────────── credential guard ────────────────────


class CredGuard:
    """Per-route credential-attempt cap with lockout.

    Usage::

        guard = CredGuard()
        await guard.check_and_record("POST /api/login")
        # raises CredLimitExceeded or CredLockedOut if over cap
    """

    def __init__(
        self,
        *,
        cap: int = _DEFAULT_CRED_CAP,
        window_s: float = _DEFAULT_CRED_WINDOW_S,
        lockout_s: float = _DEFAULT_LOCKOUT_S,
    ) -> None:
        self._cap = cap
        self._window = window_s
        self._lockout = lockout_s
        self._routes: dict[str, _RouteState] = defaultdict(
            lambda: _RouteState()
        )
        self._lock = asyncio.Lock()

    @property
    def cap(self) -> int:
        return self._cap

    async def check_and_record(self, route: str) -> None:
        """Check and record a credential attempt for *route*.

        Raises
        ------
        CredLockedOut
            If the route is in lockout.
        CredLimitExceeded
            If the cap for the current window would be exceeded.
        """
        try:
            return await self._check_and_record(route)
        except (CredLockedOut, CredLimitExceeded):
            raise
        except Exception as exc:  # noqa: BLE001
            raise CredLimitExceeded(route, self._cap) from exc

    async def _check_and_record(self, route: str) -> None:
        async with self._lock:
            now = time.monotonic()
            state = self._routes[route]

            # Check lockout
            if state.lockout_expires is not None and now < state.lockout_expires:
                remaining = state.lockout_expires - now
                raise CredLockedOut(route, remaining)
            elif state.lockout_expires is not None and now >= state.lockout_expires:
                # Lockout expired — reset
                state.attempts.clear()
                state.lockout_expires = None

            # Purge expired attempts
            cutoff = now - self._window
            while state.attempts and state.attempts[0] <= cutoff:
                state.attempts.popleft()

            if len(state.attempts) >= self._cap:
                # Enter lockout
                state.lockout_expires = now + self._lockout
                raise CredLockedOut(route, self._lockout)

            state.attempts.append(now)

    async def record_outcome(
        self,
        route: str,
        *,
        success: bool,
    ) -> None:
        """Record the outcome of a credential attempt.

        If *success*, reset the attempt counter for *route* (the
        credential was valid; no further spray attempts needed).
        """
        if not success:
            return
        async with self._lock:
            state = self._routes[route]
            state.attempts.clear()
            state.lockout_expires = None

    def state_snapshot(self, route: str) -> CredRouteState:
        """Return a serialisable snapshot of *route*'s credential state."""
        state = self._routes.get(route)
        if state is None:
            return CredRouteState(
                route=route,
                attempt_count=0,
                cap=self._cap,
                window_start=0.0,
                locked_out=False,
            )
        now = time.monotonic()
        cutoff = now - self._window
        active = [t for t in state.attempts if t > cutoff]
        return CredRouteState(
            route=route,
            attempt_count=len(active),
            cap=self._cap,
            window_start=active[0] if active else 0.0,
            locked_out=state.lockout_expires is not None and now < state.lockout_expires,
            lockout_expires=state.lockout_expires,
        )

    async def reset(self, route: str | None = None) -> None:
        """Clear credential state for *route* (or all routes if ``None``)."""
        async with self._lock:
            if route is None:
                self._routes.clear()
            else:
                self._routes.pop(route, None)


class _RouteState:
    """Internal per-route tracking."""

    __slots__ = ("attempts", "lockout_expires")

    def __init__(self) -> None:
        self.attempts: deque[float] = deque()
        self.lockout_expires: float | None = None

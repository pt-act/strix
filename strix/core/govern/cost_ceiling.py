"""Cost ceiling → halt (SGL-S4a).

Hard safety cap that halts an engagement when cumulative resource
consumption (tokens, tool calls, spend) reaches its ceiling.  This is
the **safety** half of S4 — a non-negotiable halt, not value-ordering.

Design invariants
-----------------
* **Fail-closed.**  Any accounting error → halt.
* **No LLM.**  Pure arithmetic over counters.
* **Additive.**  No imports from the detection engine.
* **Hard cap.**  At 100 % → ``HALT``.  At 80 % → ``BACKPRESSURE``.
  No action may complete after a HALT signal.
"""

from __future__ import annotations

import asyncio
from enum import Enum

from pydantic import BaseModel, Field


# ─────────────────────────────────────── constants ───────────────────────────

_DEFAULT_MAX_TOKENS: int = 5_000_000
_DEFAULT_MAX_TOOL_CALLS: int = 10_000
_DEFAULT_MAX_SPEND_USD: float = 100.0

_BACKPRESSURE_THRESHOLD: float = 0.80  # 80 %
_HALT_THRESHOLD: float = 1.00  # 100 %


# ─────────────────────────────────────── models ──────────────────────────────


class CostSignal(str, Enum):
    """Signals returned by the cost ceiling checker."""

    OK = "ok"
    BACKPRESSURE = "backpressure"
    HALT = "halt"


class CostSnapshot(BaseModel):
    """Point-in-time view of engagement resource consumption."""

    tokens_used: int = 0
    tool_calls_used: int = 0
    spend_usd: float = 0.0

    max_tokens: int = _DEFAULT_MAX_TOKENS
    max_tool_calls: int = _DEFAULT_MAX_TOOL_CALLS
    max_spend_usd: float = _DEFAULT_MAX_SPEND_USD

    token_ratio: float = 0.0
    tool_call_ratio: float = 0.0
    spend_ratio: float = 0.0

    signal: CostSignal = CostSignal.OK

    model_config = {"extra": "forbid"}


# ─────────────────────────────────────── ceiling tracker ─────────────────────


class CostCeiling:
    """Concurrency-safe engagement cost tracker.

    Usage::

        ceiling = CostCeiling()
        ceiling.record_tokens(1500)
        ceiling.record_tool_call()
        signal = ceiling.check()   # OK / BACKPRESSURE / HALT
    """

    def __init__(
        self,
        *,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
        max_tool_calls: int = _DEFAULT_MAX_TOOL_CALLS,
        max_spend_usd: float = _DEFAULT_MAX_SPEND_USD,
    ) -> None:
        self._max_tokens = max_tokens
        self._max_tool_calls = max_tool_calls
        self._max_spend_usd = max_spend_usd

        self._tokens: int = 0
        self._tool_calls: int = 0
        self._spend: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def max_tokens(self) -> int:
        return self._max_tokens

    @property
    def max_tool_calls(self) -> int:
        return self._max_tool_calls

    def record_tokens(self, count: int) -> None:
        """Record *count* tokens consumed.  Synchronous — no lock needed for
        a single int increment (GIL-safe)."""
        self._tokens += max(count, 0)

    def record_tool_call(self) -> None:
        """Record a single tool call.  Synchronous (GIL-safe)."""
        self._tool_calls += 1

    def record_spend(self, amount_usd: float) -> None:
        """Record *amount_usd* of spend.  Synchronous (GIL-safe)."""
        self._spend += max(amount_usd, 0.0)

    def check(self) -> CostSignal:
        """Return the current cost signal.

        Returns
        -------
        CostSignal
            ``HALT`` if any dimension is at or above 100 %.
            ``BACKPRESSURE`` if any dimension is at or above 80 %.
            ``OK`` otherwise.
        """
        try:
            return self._check()
        except Exception:  # noqa: BLE001
            # Fail-closed: any accounting error → halt
            return CostSignal.HALT

    def _check(self) -> CostSignal:
        token_ratio = self._tokens / self._max_tokens if self._max_tokens > 0 else 1.0
        tc_ratio = (
            self._tool_calls / self._max_tool_calls if self._max_tool_calls > 0 else 1.0
        )
        spend_ratio = self._spend / self._max_spend_usd if self._max_spend_usd > 0 else 1.0

        max_ratio = max(token_ratio, tc_ratio, spend_ratio)

        if max_ratio >= _HALT_THRESHOLD:
            return CostSignal.HALT
        if max_ratio >= _BACKPRESSURE_THRESHOLD:
            return CostSignal.BACKPRESSURE
        return CostSignal.OK

    def snapshot(self) -> CostSnapshot:
        """Return a serialisable snapshot of current cost state."""
        token_ratio = self._tokens / self._max_tokens if self._max_tokens > 0 else 1.0
        tc_ratio = (
            self._tool_calls / self._max_tool_calls if self._max_tool_calls > 0 else 1.0
        )
        spend_ratio = self._spend / self._max_spend_usd if self._max_spend_usd > 0 else 1.0

        return CostSnapshot(
            tokens_used=self._tokens,
            tool_calls_used=self._tool_calls,
            spend_usd=self._spend,
            max_tokens=self._max_tokens,
            max_tool_calls=self._max_tool_calls,
            max_spend_usd=self._max_spend_usd,
            token_ratio=round(token_ratio, 4),
            tool_call_ratio=round(tc_ratio, 4),
            spend_ratio=round(spend_ratio, 4),
            signal=self.check(),
        )

    def reset(self) -> None:
        """Reset all counters.  Synchronous (GIL-safe)."""
        self._tokens = 0
        self._tool_calls = 0
        self._spend = 0.0

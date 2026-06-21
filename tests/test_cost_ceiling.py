"""Tests for strix.core.govern.cost_ceiling — SGL-S4a.

SP7: spend ≤ ceiling; exhaustion ⇒ halt; no action left half-executed at
     the ceiling.  Backpressure at 80 %, hard halt at 100 %.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from strix.core.govern.cost_ceiling import (
    CostCeiling,
    CostSignal,
    CostSnapshot,
)

# ══════════════════════════════════════════════════════════════════════════════
# TG4 — Focused tests
# ══════════════════════════════════════════════════════════════════════════════


class TestCostCeilingSignals:
    """TG4.1 — signal thresholds."""

    def test_under_threshold_ok(self) -> None:
        c = CostCeiling(max_tokens=1000, max_tool_calls=100, max_spend_usd=10.0)
        c.record_tokens(500)
        c.record_tool_call()
        assert c.check() == CostSignal.OK

    def test_backpressure_at_80_pct_tokens(self) -> None:
        c = CostCeiling(max_tokens=1000, max_tool_calls=100, max_spend_usd=10.0)
        c.record_tokens(800)
        assert c.check() == CostSignal.BACKPRESSURE

    def test_backpressure_at_80_pct_tool_calls(self) -> None:
        c = CostCeiling(max_tokens=1000, max_tool_calls=10, max_spend_usd=10.0)
        for _ in range(8):
            c.record_tool_call()
        assert c.check() == CostSignal.BACKPRESSURE

    def test_halt_at_100_pct_tokens(self) -> None:
        c = CostCeiling(max_tokens=1000, max_tool_calls=100, max_spend_usd=10.0)
        c.record_tokens(1000)
        assert c.check() == CostSignal.HALT

    def test_halt_at_100_pct_tool_calls(self) -> None:
        c = CostCeiling(max_tokens=1000, max_tool_calls=5, max_spend_usd=10.0)
        for _ in range(5):
            c.record_tool_call()
        assert c.check() == CostSignal.HALT

    def test_halt_at_100_pct_spend(self) -> None:
        c = CostCeiling(max_tokens=1000, max_tool_calls=100, max_spend_usd=10.0)
        c.record_spend(10.0)
        assert c.check() == CostSignal.HALT

    def test_over_ceiling_still_halt(self) -> None:
        c = CostCeiling(max_tokens=100, max_tool_calls=100, max_spend_usd=10.0)
        c.record_tokens(5000)  # way over
        assert c.check() == CostSignal.HALT

    def test_zero_ceiling_halt(self) -> None:
        """Zero ceiling → immediate halt (fail-closed)."""
        c = CostCeiling(max_tokens=0, max_tool_calls=0, max_spend_usd=0.0)
        assert c.check() == CostSignal.HALT

    def test_negative_recorded_clamped(self) -> None:
        c = CostCeiling(max_tokens=1000, max_tool_calls=100, max_spend_usd=10.0)
        c.record_tokens(-100)
        c.record_spend(-5.0)
        assert c.check() == CostSignal.OK  # negatives clamped to 0


class TestCostCeilingSnapshot:
    """TG4.2 — snapshot serialisation."""

    def test_snapshot_fields(self) -> None:
        c = CostCeiling(max_tokens=1000, max_tool_calls=100, max_spend_usd=10.0)
        c.record_tokens(500)
        c.record_tool_call()
        c.record_spend(3.0)
        snap = c.snapshot()
        assert snap.tokens_used == 500
        assert snap.tool_calls_used == 1
        assert snap.spend_usd == 3.0
        assert snap.token_ratio == 0.5
        assert snap.signal == CostSignal.OK

    def test_snapshot_roundtrip(self) -> None:
        c = CostCeiling(max_tokens=1000, max_tool_calls=100, max_spend_usd=10.0)
        c.record_tokens(500)
        snap = c.snapshot()
        # Verify pydantic serialisation
        data = snap.model_dump()
        restored = CostSnapshot(**data)
        assert restored.tokens_used == 500


class TestCostCeilingReset:
    """TG4.3 — reset clears all counters."""

    def test_reset(self) -> None:
        c = CostCeiling(max_tokens=1000, max_tool_calls=100, max_spend_usd=10.0)
        c.record_tokens(1000)
        c.record_tool_call()
        c.record_spend(10.0)
        assert c.check() == CostSignal.HALT
        c.reset()
        assert c.check() == CostSignal.OK
        snap = c.snapshot()
        assert snap.tokens_used == 0
        assert snap.tool_calls_used == 0
        assert snap.spend_usd == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# SP7 — PBT: spend ≤ ceiling; exhaustion ⇒ halt
# ══════════════════════════════════════════════════════════════════════════════


@given(
    st.integers(min_value=1, max_value=100_000),
    st.integers(min_value=1, max_value=100_000),
)
@settings(max_examples=300)
def test_sp7_tokens_and_tool_calls_never_exceed_ceiling(
    max_tokens: int, max_tool_calls: int
) -> None:
    """SP7: once HALT is signalled, no further action should proceed.

    We verify that the signal transitions monotonically: OK → BACKPRESSURE
    → HALT, and once HALT, stays HALT regardless of further increments.
    """
    c = CostCeiling(max_tokens=max_tokens, max_tool_calls=max_tool_calls, max_spend_usd=1e9)
    prev_signal = CostSignal.OK

    for i in range(max_tokens + 1):
        c.record_tokens(1)
        signal = c.check()
        # Monotonic: signal can only stay same or escalate
        assert _signal_rank(signal) >= _signal_rank(prev_signal), (
            f"Signal went from {prev_signal} to {signal} at token {i}"
        )
        prev_signal = signal

    # After reaching max_tokens, must be HALT
    assert c.check() == CostSignal.HALT

    # Additional tool calls must not change the signal (still HALT)
    for _ in range(10):
        c.record_tool_call()
        assert c.check() == CostSignal.HALT


@given(
    st.integers(min_value=1, max_value=10_000),
    st.integers(min_value=1, max_value=10_000),
)
@settings(max_examples=200)
def test_sp7_signal_monotonic(max_tokens: int, max_tool_calls: int) -> None:
    """SP7: cost signal is monotonically non-decreasing."""
    c = CostCeiling(max_tokens=max_tokens, max_tool_calls=max_tool_calls, max_spend_usd=1e9)
    prev = _signal_rank(c.check())

    # Increment tokens
    for _ in range(min(max_tokens, 100)):
        c.record_tokens(1)
        cur = _signal_rank(c.check())
        assert cur >= prev
        prev = cur

    # Increment tool calls
    for _ in range(min(max_tool_calls, 100)):
        c.record_tool_call()
        cur = _signal_rank(c.check())
        assert cur >= prev
        prev = cur


def _signal_rank(signal: CostSignal) -> int:
    return {CostSignal.OK: 0, CostSignal.BACKPRESSURE: 1, CostSignal.HALT: 2}[signal]

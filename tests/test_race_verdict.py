"""Tier-1 and Tier-2 tests for the race verdict + commit-count aggregator."""

from __future__ import annotations

import json
from typing import Any
from unittest import TestCase

from hypothesis import given, settings
from hypothesis import strategies as st

from strix.core.diff.models import SemanticDelta
from strix.core.race.aggregator import count_commits
from strix.core.race.models import CopyOutcome, StateDelta
from strix.core.race.verdict import verdict


def _make_response(
    status_code: int,
    body: str = "",
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "status_code": status_code,
        "headers": headers or {},
        "body": body,
        "length": len(body.encode("utf-8")),
    }


def _make_outcome(
    copy_index: int,
    status_code: int,
    body: str = "",
) -> CopyOutcome:
    return CopyOutcome(
        copy_index=copy_index,
        status="DONE",
        error=None,
        elapsed_ms=10,
        response=_make_response(status_code, body),
        session_id=f"s-{copy_index}",
    )


def _make_state_delta(
    *,
    changed: bool,
    observable: bool = True,
    committed: int | None = None,
) -> StateDelta:
    """Build a state delta with a unit-1 ``redeem_count`` counter.

    ``committed`` controls the post-action counter value when ``changed`` is True.
    When None, a default of 3 is used for tests that only need "some change".
    """
    baseline_count = 0
    post_count = (committed if committed is not None else (3 if changed else 0)) if changed else 0
    baseline = _make_response(200, json.dumps({"redeem_count": baseline_count}))
    post_action = _make_response(200, json.dumps({"redeem_count": post_count}))
    semantic = SemanticDelta(
        pair=("baseline", "post_action"),
        status_class_delta=None,
        body_structure_delta="same" if baseline_count == post_count else "shape_changed",
        normalized_length_delta=0,
        normalized=True,
    )
    return StateDelta(
        baseline=baseline,
        post_action=post_action,
        semantic_delta=semantic,
        observable=observable,
    )


class TestRaceVerdictTier1(TestCase):
    """Focused behaviour tests for the pure verdict function."""

    def test_multi_commit_is_race(self) -> None:
        delta = _make_state_delta(changed=True, committed=2)
        self.assertEqual(verdict(delta, 2), "race")
        self.assertEqual(verdict(delta, 5), "race")

    def test_single_commit_is_safe(self) -> None:
        delta = _make_state_delta(changed=True, committed=1)
        self.assertEqual(verdict(delta, 1), "safe")

    def test_zero_commit_is_inconclusive(self) -> None:
        delta = _make_state_delta(changed=False)
        self.assertEqual(verdict(delta, 0), "inconclusive")


class TestRaceCommitCountTier1(TestCase):
    """Focused behaviour tests for the commit-count aggregator."""

    def test_no_state_change_yields_zero_commits(self) -> None:
        outcomes = [_make_outcome(0, 200, "redeemed")]
        delta = _make_state_delta(changed=False)
        self.assertEqual(count_commits(outcomes, delta), 0)

    def test_one_successful_commit(self) -> None:
        outcomes = [_make_outcome(0, 200, "redeemed")]
        delta = _make_state_delta(changed=True, committed=1)
        self.assertEqual(count_commits(outcomes, delta), 1)

    def test_multi_successful_commits(self) -> None:
        outcomes = [
            _make_outcome(0, 200, "redeemed"),
            _make_outcome(1, 200, "redeemed"),
            _make_outcome(2, 200, "redeemed"),
        ]
        delta = _make_state_delta(changed=True, committed=3)
        self.assertEqual(count_commits(outcomes, delta), 3)

    def test_negative_indicators_suppress_commit_count(self) -> None:
        # With an observable state counter, per-copy negative signals are ignored.
        outcomes = [
            _make_outcome(0, 200, "redeemed"),
            _make_outcome(1, 409, "already used"),
            _make_outcome(2, 200, "already redeemed"),
        ]
        delta = _make_state_delta(changed=True, committed=1)
        self.assertEqual(count_commits(outcomes, delta), 1)

    def test_success_indicator_overrides_negative_body(self) -> None:
        # Per-copy success indicators are irrelevant when the observable counter
        # moved by 3; the state magnitude wins.
        outcomes = [
            _make_outcome(0, 200, "ok"),
            _make_outcome(1, 200, "ok"),
        ]
        delta = _make_state_delta(changed=True, committed=3)
        self.assertEqual(count_commits(outcomes, delta, success_indicator="ok"), 3)

    def test_no_observable_oracle_falls_back_to_per_copy_signals(self) -> None:
        outcomes = [
            _make_outcome(0, 200, "redeemed"),
            _make_outcome(1, 200, "redeemed"),
        ]
        delta = _make_state_delta(changed=False, observable=False)
        self.assertEqual(count_commits(outcomes, delta), 2)

    def test_failed_copies_do_not_count(self) -> None:
        # Observable state moved by 3; one failed copy does not affect the count.
        outcomes = [
            _make_outcome(0, 500, "error"),
            _make_outcome(1, 200, "redeemed"),
            _make_outcome(2, 200, "redeemed"),
        ]
        delta = _make_state_delta(changed=True, committed=3)
        self.assertEqual(count_commits(outcomes, delta), 3)

    def test_non_json_state_fails_safe_to_one(self) -> None:
        # No parseable counter means the magnitude is unknown; fail safe.
        baseline = _make_response(200, "balance=100")
        post_action = _make_response(200, "balance=70")
        semantic = SemanticDelta(
            pair=("baseline", "post_action"),
            status_class_delta=None,
            body_structure_delta="size_changed",
            normalized_length_delta=1,
            normalized=True,
        )
        delta = StateDelta(
            baseline=baseline,
            post_action=post_action,
            semantic_delta=semantic,
            observable=True,
        )
        outcomes = [
            _make_outcome(0, 200, "redeemed"),
            _make_outcome(1, 200, "redeemed"),
        ]
        self.assertEqual(count_commits(outcomes, delta), 1)


class TestRaceVerdictTier2PBT(TestCase):
    """Property-based invariants for the verdict + aggregator pair."""

    @given(
        n=st.integers(min_value=2, max_value=10),
        committed=st.integers(min_value=0, max_value=10),
    )
    @settings(max_examples=50, deadline=None)
    def test_single_use_enforcement(self, n: int, committed: int) -> None:
        # At most one commit should be considered safe; more than one is a race.
        outcomes = [
            _make_outcome(i, 200 if i < committed else 409, "redeemed" if i < committed else "used")
            for i in range(n)
        ]
        delta = _make_state_delta(changed=committed > 0, committed=committed)
        count = count_commits(outcomes, delta)
        if committed > 1:
            self.assertEqual(verdict(delta, count), "race")
        elif committed == 1:
            self.assertEqual(verdict(delta, count), "safe")
        else:
            self.assertEqual(verdict(delta, count), "inconclusive")

    @given(
        status_code=st.sampled_from([200, 201, 400, 409, 500]),
        body_core=st.sampled_from(["redeemed", "already used", "error"]),
        changed=st.booleans(),
    )
    @settings(max_examples=50, deadline=None)
    def test_detection_determinism(self, status_code: int, body_core: str, changed: bool) -> None:
        # Identical inputs must produce identical commit counts and verdicts.
        outcomes = [_make_outcome(0, status_code, body_core)]
        delta = _make_state_delta(changed=changed, committed=1 if changed else 0)
        count_a = count_commits(outcomes, delta)
        count_b = count_commits(outcomes, delta)
        self.assertEqual(count_a, count_b)
        self.assertEqual(verdict(delta, count_a), verdict(delta, count_b))

    @given(
        n=st.integers(min_value=2, max_value=10),
    )
    @settings(max_examples=30, deadline=None)
    def test_no_side_effect_on_safe_target(self, n: int) -> None:
        # A properly locked/idempotent target: state counter moves at most once.
        outcomes = [
            _make_outcome(0, 200, "redeemed"),
            *[_make_outcome(i, 409, "already used") for i in range(1, n)],
        ]
        delta = _make_state_delta(changed=True, committed=1)
        count = count_commits(outcomes, delta)
        self.assertLessEqual(count, 1)
        self.assertEqual(verdict(delta, count), "safe")


if __name__ == "__main__":
    import unittest

    unittest.main()

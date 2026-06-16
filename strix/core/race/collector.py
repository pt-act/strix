"""Outcome collector + P2 state diff + commit-count aggregator."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from strix.core.diff import diff
from strix.core.diff.models import SemanticDelta
from strix.core.race.aggregator import count_commits
from strix.core.race.models import StateDelta


if TYPE_CHECKING:
    from strix.core.race.models import CopyOutcome


def collect_state_delta(
    baseline: dict[str, Any] | None,
    post_action: dict[str, Any] | None,
    *,
    observable: bool = True,
) -> StateDelta:
    """Compute the P2 pairwise state delta between baseline and post-action reads.

    When ``post_action`` is ``None`` (no independent oracle available), the
    state delta is built from an empty response and ``observable`` is set to
    ``False`` so the verdict layer records the absence of the oracle.
    """
    safe_baseline = baseline or {"status_code": 0, "headers": {}, "body": ""}
    safe_post = post_action or {"status_code": 0, "headers": {}, "body": ""}

    diff_result = diff(
        [
            {"label": "baseline", "response": safe_baseline},
            {"label": "post_action", "response": safe_post},
        ]
    )
    semantic_delta = diff_result.deltas[0] if diff_result.deltas else None
    if semantic_delta is None:
        # Should never happen with two inputs, but keep the shape intact.
        semantic_delta = SemanticDelta(
            pair=("baseline", "post_action"),
            status_class_delta=None,
            body_structure_delta="same",
            normalized_length_delta=0,
            normalized=True,
        )

    return StateDelta(
        baseline=safe_baseline,
        post_action=safe_post,
        semantic_delta=semantic_delta,
        observable=observable and post_action is not None,
    )


def collect_commit_count(
    outcomes: list[CopyOutcome],
    state_delta: StateDelta,
    success_indicator: str | None = None,
    state_counter: str | None = None,
    commit_unit: float | None = None,
) -> int:
    """Reduce outcomes + state delta to a commit count via the Phase-4 aggregator."""
    return count_commits(
        outcomes,
        state_delta,
        success_indicator=success_indicator,
        state_counter=state_counter,
        commit_unit=commit_unit,
    )

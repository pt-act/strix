"""Commit-count aggregator: pure reduction over outcomes + state delta."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from strix.core.race.models import CopyOutcome, StateDelta


# Substrings that indicate a per-copy response did NOT commit a single-use action.
_NEGATIVE_COMMIT_INDICATORS = frozenset(
    {
        "error",
        "failed",
        "denied",
        "already",
        "used",
        "expired",
        "invalid",
        "rejected",
        "unauthorized",
        "forbidden",
        "conflict",
        "not allowed",
    }
)


# Status-code ranges bucketed into classes (e.g. ``2xx``).
_STATUS_RANGES = (
    (100, 200, "1xx"),
    (200, 300, "2xx"),
    (300, 400, "3xx"),
    (400, 500, "4xx"),
    (500, 600, "5xx"),
)


def _status_class(status_code: int | None) -> str:
    """Bucket a status code into its class (e.g. ``2xx``)."""
    if status_code is None:
        return "unknown"
    for lower, upper, klass in _STATUS_RANGES:
        if lower <= status_code < upper:
            return klass
    return "unknown"


def _body_text(response: dict[str, Any] | None) -> str:
    if response is None:
        return ""
    body = response.get("body")
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def _is_commit_response(
    response: dict[str, Any] | None,
    success_indicator: str | None,
) -> bool:
    """Return True when a per-copy response indicates the action committed."""
    if response is None:
        return False
    status_code = response.get("status_code")
    if status_code is None or _status_class(status_code) != "2xx":
        return False

    body_lower = _body_text(response).lower()
    if success_indicator and success_indicator.lower() in body_lower:
        return True

    # Without an explicit success indicator, require a successful status class
    # and the absence of common negative indicators.
    return not any(neg in body_lower for neg in _NEGATIVE_COMMIT_INDICATORS)


def _parse_json_counters(body: str) -> dict[str, int | float]:
    """Extract numeric fields from a JSON body, treating them as counters."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        k: v for k, v in data.items() if isinstance(v, (int, float)) and not isinstance(v, bool)
    }


def _commit_count_from_magnitude(
    magnitude: int,
    commit_unit: float | None,
) -> int:
    """Convert a raw state-delta magnitude into a commit count.

    When the per-commit unit is known, divide. When it is unknown, fail-safe to
    1 (a single successful commit) rather than guessing from response signals.
    """
    if commit_unit is None or commit_unit <= 0:
        return 1
    return max(1, round(magnitude / commit_unit))


def _state_delta_magnitude(
    state_delta: StateDelta,
    state_counter: str | None,
) -> tuple[int, int | float | None]:
    """Return (magnitude, commit_unit) for the observable state change.

    The magnitude is the absolute difference in the chosen counter. If the
    caller named a ``state_counter`` we use that field and require its unit to
    be declared. If no counter is named, we look for a field whose name clearly
    identifies it as a commit counter (e.g. ``redeem_count``); such counters
    are treated as unit-1. Non-JSON or unrecognised bodies return (0, None).
    """
    baseline_body = _body_text(state_delta.baseline)
    post_body = _body_text(state_delta.post_action)

    baseline_counters = _parse_json_counters(baseline_body)
    post_counters = _parse_json_counters(post_body)
    if not baseline_counters or not post_counters:
        return 0, None

    if state_counter is not None:
        baseline_value = baseline_counters.get(state_counter)
        post_value = post_counters.get(state_counter)
        if baseline_value is not None and post_value is not None:
            return abs(int(post_value) - int(baseline_value)), None
        return 0, None

    # Auto-detect unit-1 commit counters by field name.
    counter_suffixes = ("count", "redeem", "used", "quantity", "num", "total", "applied")
    for key in baseline_counters:
        if key in post_counters and any(suffix in key.lower() for suffix in counter_suffixes):
            return abs(int(post_counters[key]) - int(baseline_counters[key])), 1

    return 0, None


def _state_changed(state_delta: StateDelta) -> bool:
    """Return True when the observable state differs from baseline."""
    semantic = state_delta.semantic_delta
    return semantic.body_structure_delta != "same" or semantic.normalized_length_delta > 0


def count_commits(
    outcomes: list[CopyOutcome],
    state_delta: StateDelta,
    success_indicator: str | None = None,
    state_counter: str | None = None,
    commit_unit: float | None = None,
) -> int:
    """Reduce N outcomes + the P2 state-delta magnitude to a commit count.

    The aggregator is deliberately conservative and never guesses the number of
    commits from per-copy response signals when an observable state oracle is
    available:

    - If an independent observable state read exists and the state did not
      change, the result is 0 commits (no race).
    - If the state changed and we can read a reliable counter, the count is the
      magnitude divided by the declared per-commit unit. Unit-1 counters such as
      ``redeem_count`` are detected automatically.
    - If the state changed but the per-commit unit is unknown or the body is
      not a parseable JSON counter, fail-safe to 1 commit. This avoids reporting
      a false race when a single action moved a value counter (e.g. balance
      100 -> 70 with unit 30).
    - If there is no observable oracle, the count is derived from per-copy
      commit signals only, with the absence of the oracle recorded in the state
      delta.
    """
    if state_delta.observable and not _state_changed(state_delta):
        return 0

    if state_delta.observable:
        magnitude, inferred_unit = _state_delta_magnitude(state_delta, state_counter)
        if magnitude > 0:
            unit = commit_unit if commit_unit is not None else inferred_unit
            return _commit_count_from_magnitude(magnitude, unit)
        # State changed structurally but no numeric counter moved: fail-safe.
        return 1

    return sum(
        1 for outcome in outcomes if _is_commit_response(outcome.response, success_indicator)
    )

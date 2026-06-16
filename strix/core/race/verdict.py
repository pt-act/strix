"""Pure verdict function for race-harness outcomes."""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from strix.core.race.models import StateDelta, Verdict


def verdict(state_delta: StateDelta, commit_count: int) -> Verdict:  # noqa: ARG001  # state_delta is part of the pure contract even if the current heuristic uses only count
    """Return a verdict that is a pure function of observed state deltas.

    Rules (timing is never an input):

    - ``commit_count > 1`` → ``race`` (a single-use action committed more than
      once under concurrency).
    - ``commit_count == 1`` → ``safe`` (exactly one commit or an idempotent
      response; no violation).
    - ``commit_count < 1`` → ``inconclusive`` (no observable commit; a retry
      may be warranted).
    """
    if commit_count > 1:
        return "race"
    if commit_count == 1:
        return "safe"
    return "inconclusive"

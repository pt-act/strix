"""Race-condition harness core: pure models, verdict, and aggregator.

Dispatcher and harness modules are kept out of the package root because they
import the Phase 1 replay path (and transitively the Caido SDK). Import them
explicitly from their submodules when needed.
"""

from __future__ import annotations

from strix.core.race.aggregator import count_commits
from strix.core.race.models import (
    CopyOutcome,
    Precondition,
    RaceResult,
    RaceTrialSummary,
    ScopeDecision,
    ScopedRefusal,
    StateDelta,
    Verdict,
)
from strix.core.race.verdict import verdict


__all__ = [
    "CopyOutcome",
    "Precondition",
    "RaceResult",
    "RaceTrialSummary",
    "ScopeDecision",
    "ScopedRefusal",
    "StateDelta",
    "Verdict",
    "count_commits",
    "verdict",
]

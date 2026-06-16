"""Locked output shapes for the race-condition harness."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from strix.core.diff.models import SemanticDelta  # noqa: TC001


Verdict = Literal["race", "safe", "inconclusive"]


class CopyOutcome(BaseModel):
    """Per-copy result from the concurrent dispatcher."""

    copy_index: int
    status: str
    error: str | None
    elapsed_ms: int
    response: dict[str, Any] | None
    session_id: str | None

    model_config = {"extra": "forbid"}


class StateDelta(BaseModel):
    """Before/after observable state plus the P2 pairwise semantic delta."""

    baseline: dict[str, Any]
    post_action: dict[str, Any]
    semantic_delta: SemanticDelta
    observable: bool = True
    """True when an independent post-action state read was available."""

    model_config = {"extra": "forbid"}


class Precondition(BaseModel):
    """Declarative precondition used to reset the target before each trial."""

    description: str
    setup_request_id: str
    state_read_request_id: str
    identity_role: str = "user"
    success_indicator: str | None = None
    """Optional substring a per-copy response body must contain to count as a commit."""
    state_counter: str | None = None
    """Optional JSON field name in the state-read body that tracks the action count."""
    commit_unit: float | None = None
    """Optional change in ``state_counter`` per single successful commit."""

    model_config = {"extra": "forbid"}


class ScopeDecision(BaseModel):
    """Glass-box record of the pre-dispatch scope gate."""

    target_url: str
    scope_rules: list[str] | None
    in_scope: bool
    reason: str

    model_config = {"extra": "forbid"}


class RaceResult(BaseModel):
    """Complete output of one race-harness trial."""

    success: bool
    verdict: Verdict
    commit_count: int
    retry_count: int
    state_delta: StateDelta
    outcomes: list[CopyOutcome]
    scope_decision: ScopeDecision
    precondition: Precondition
    n: int
    jitter_ms: int
    error: str | None = None

    model_config = {"extra": "forbid"}


class RaceTrialSummary(BaseModel):
    """Redacted, agent-facing summary of a race trial."""

    verdict: Verdict
    commit_count: int
    retry_count: int
    n: int
    jitter_ms: int
    scope_in_scope: bool
    scope_reason: str
    precondition_description: str
    observable_oracle_used: bool
    state_delta_summary: dict[str, Any]
    outcome_table: list[dict[str, object]] = Field(default_factory=list[dict[str, object]])

    model_config = {"extra": "forbid"}


class ScopedRefusal(Exception):  # noqa: N818  # domain-specific refusal, not a generic error
    """Raised when the scope gate refuses to dispatch against a target."""

    def __init__(self, target_url: str, scope_rules: list[str] | None, reason: str) -> None:
        super().__init__(reason)
        self.target_url = target_url
        self.scope_rules = scope_rules
        self.reason = reason

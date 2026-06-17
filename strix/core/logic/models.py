"""Locked output shapes for business-logic state testing.

Every model element is agent-proposed: the proposing model provides the journey,
lifecycle, trust boundary, monetary operation, and flow hypotheses, and the
deterministic harnesses dispose. The shapes are intentionally separate from
the confirmed findings produced by the evidence gate.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


InvariantKind = Literal[
    "step-skip",
    "replay",
    "double-spend",
    "price-mismatch",
    "unauthorized-state-change",
]

FlowName = Literal[
    "approval",
    "coupon",
    "refund",
    "credit",
    "invite",
]


class _AgentProposedModel(BaseModel):
    """Base for all agent-proposed model elements."""

    source: Literal["agent-proposed"] = "agent-proposed"
    """Tag every model element as originating from the proposing agent, not the harness."""


class Step(_AgentProposedModel):
    """A single ordered step inside a journey."""

    name: str
    order: int
    request_id: str
    required_role: str | None = None
    depends_on: list[str] = Field(default_factory=list)
    """Names of previous steps that must be completed before this one."""

    model_config = {"extra": "forbid"}


class JourneyModel(_AgentProposedModel):
    """An ordered user journey the agent wants to test."""

    name: str
    steps: list[Step] = Field(default_factory=list)
    entry_role: str = "user"

    model_config = {"extra": "forbid"}


class Transition(_AgentProposedModel):
    """An allowed state transition in an object lifecycle."""

    from_state: str
    to_state: str
    request_id: str
    allowed_roles: list[str] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


class LifecycleModel(_AgentProposedModel):
    """An object lifecycle the agent wants to test."""

    name: str
    object_type: str
    states: list[str] = Field(default_factory=list)
    transitions: list[Transition] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


class TrustBoundary(_AgentProposedModel):
    """A trust boundary mapping identities to allowed steps/transitions."""

    name: str
    role: str
    allowed_step_names: list[str] = Field(default_factory=list)
    allowed_transitions: list[tuple[str, str]] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


class MonetaryRelation(_AgentProposedModel):
    """A monetary relation used to compute expected totals and per-commit units."""

    amount_param: str | None = None
    quantity_param: str | None = None
    price_param: str | None = None
    total_param: str | None = None
    commit_unit: float | None = None
    """Expected change in the chosen state counter per single successful commit."""
    state_counter: str | None = None
    """JSON field name in the state-read body that tracks this operation."""
    baseline_values: dict[str, Any] | None = None
    """Baseline values for the monetary relation (e.g. price, quantity, total)."""
    tamper_values: dict[str, Any] | None = None
    """Values to inject when testing price/quantity/amount tampering."""

    model_config = {"extra": "forbid"}


class MonetaryOperation(_AgentProposedModel):
    """A monetary operation the agent wants to protect (e.g. coupon redemption)."""

    name: str
    request_id: str
    setup_request_id: str | None = None
    """Optional request that resets the target to the pre-operation state."""
    state_read_request_id: str | None = None
    """Optional request that reads the state counter after the operation."""
    relation: MonetaryRelation
    one_time: bool = True

    model_config = {"extra": "forbid"}


class FlowModel(_AgentProposedModel):
    """A named flow binding an operation to a business-logic pattern."""

    name: str
    flow_name: FlowName
    request_id: str
    monetary_op: MonetaryOperation | None = None
    lifecycle: LifecycleModel | None = None
    journey: JourneyModel | None = None
    bound_invariants: list[InvariantKind] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


class BusinessLogicModel(_AgentProposedModel):
    """Top-level per-engagement model: the agent's hypothesis about the target."""

    engagement_id: str
    target_id: str
    journeys: dict[str, JourneyModel] = Field(default_factory=dict)
    lifecycles: dict[str, LifecycleModel] = Field(default_factory=dict)
    trust_boundaries: dict[str, TrustBoundary] = Field(default_factory=dict)
    monetary_operations: dict[str, MonetaryOperation] = Field(default_factory=dict)
    flows: dict[str, FlowModel] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


class ExecutedStep(BaseModel):
    """One executed step in a violation sequence, for reproduction."""

    request_id: str
    identity_role: str
    request_raw: str | None = None
    response: dict[str, Any] | None = None
    elapsed_ms: int = 0
    session_id: str | None = None

    model_config = {"extra": "forbid"}


class ExecutedSequence(BaseModel):
    """Full executed sequence backing a confirmed or unconfirmed hypothesis."""

    flow_name: str
    invariant_kind: InvariantKind
    steps: list[ExecutedStep] = Field(default_factory=list)
    final_state: dict[str, Any] | None = None
    artifact: Any | None = None
    artifact_type: Literal["diff", "callback", "race_result"] | None = None
    artifact_id: str | None = None

    model_config = {"extra": "forbid"}


class ViolationCandidate(BaseModel):
    """A candidate produced by a violation test before the evidence gate."""

    flow_name: str
    invariant_kind: InvariantKind
    sequence: ExecutedSequence
    reached_impossible_state: bool = False

    model_config = {"extra": "forbid"}


class ConfirmedViolation(BaseModel):
    """A violation promoted by the evidence gate."""

    flow_name: str
    invariant_kind: InvariantKind
    executed_sequence: ExecutedSequence
    reason: str

    model_config = {"extra": "forbid"}


class UnconfirmedHypothesis(BaseModel):
    """A proposed hypothesis that did not pass the evidence gate."""

    flow_name: str
    invariant_kind: InvariantKind
    reason: str

    model_config = {"extra": "forbid"}

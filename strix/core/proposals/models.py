"""Locked output shapes for the propose-dispose funnel and assembler.

The assembler is proposal-stage only: it never sets ``evidence_class``, never files
a ``vulnerability_report``, and never mutates ``ReportState``. The harness (disposer)
remains the sole owner of precision.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


VerdictKind = Literal["confirmed", "unconfirmed", "inconclusive", "error"]
EvidenceClass = Literal["diff", "callback", "reachability", "race_result", "none"]


class HarnessVerdict(BaseModel):
    """One harness run result attached to a proposal."""

    harness_name: str
    verdict: VerdictKind
    evidence_class: EvidenceClass
    cost_ms: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    model_config = {"extra": "forbid"}


class C1C8Answer(BaseModel):
    """Agent answer to one C1-C8 recall-oriented self-check question."""

    question_id: str
    question: str
    answer: Literal["yes", "no", "unknown", "na"]
    rationale: str | None = None

    model_config = {"extra": "forbid"}


class C1C8Checklist(BaseModel):
    """Fixed recall-oriented self-interrogation checklist.

    Questions target false-negative drivers (C5/C6/C7) as described in the
    Semantic Trap taxonomy (Huang et al., arXiv 2601.22655). Only the agent's
    *answers* vary; the question text is deterministic.
    """

    answers: list[C1C8Answer] = Field(default_factory=list)

    @staticmethod
    def default_questions() -> list[str]:
        return [
            "C3 delegation: does the endpoint rely on another component or "
            "downstream service to enforce a security check?",
            "C5 stateful dependency: does the bug require a specific prior "
            "state or multi-step sequence to manifest?",
            "C6 concurrency: can a race condition, time-of-check/time-of-use, "
            "or concurrent request alter the outcome?",
            "C7 trust boundary: does a parameter cross a trust boundary "
            "(user→server, server→server, or privileged→unprivileged)?",
        ]

    model_config = {"extra": "forbid"}


class InterventionFlags(BaseModel):
    """Active-intervention flag matrix for one proposal.

    Each flag is independently togglable; the assembler composes only the enabled
    streams. The matrix is recorded in the ProposalRecord for glass-box ablation.
    """

    control_path: bool = False
    knowledge_path: bool = False
    c1_c8_checklist: bool = False

    model_config = {"extra": "forbid"}


class ProposalContext(BaseModel):
    """Context assembled for the agent at proposal time.

    Carries no ``evidence_class`` and no report state. The harness disposes.
    """

    control_path_nl: str | None = None
    knowledge_path_nl: str | None = None
    c1_c8_checklist: C1C8Checklist | None = None
    active_flags: InterventionFlags = Field(default_factory=InterventionFlags)

    model_config = {"extra": "forbid"}


class ProposalRecord(BaseModel):
    """Durable, append-only record of one proposal's full lifecycle.

    Captures: endpoint/param ref, agent-declared CWE, C1-C8 answers, harnesses
    selected, every harness verdict + ``evidence_class``, timing/cost, and the
    active-intervention flag matrix. No credential or secret material is stored.
    """

    proposal_id: str = Field(default_factory=lambda: f"prop-{uuid4().hex[:8]}")
    engagement_id: str = ""
    endpoint_key: str = ""
    param_name: str | None = None
    cwe: str | None = None
    c1_c8_answers: dict[str, C1C8Answer] = Field(default_factory=dict)
    active_interventions: InterventionFlags = Field(default_factory=InterventionFlags)
    harnesses_selected: list[str] = Field(default_factory=list)
    verdicts: list[HarnessVerdict] = Field(default_factory=list)
    report_id: str | None = None
    supplied_context: ProposalContext | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    def add_verdict(self, verdict: HarnessVerdict) -> None:
        """Append a harness verdict; maintains the append-only invariant."""
        self.verdicts.append(verdict)
        self.updated_at = datetime.now(UTC).isoformat()

    def attach_report(self, report_id: str) -> None:
        """Link the final impact-gated report."""
        self.report_id = report_id
        self.updated_at = datetime.now(UTC).isoformat()

    def record_context(self, context: ProposalContext) -> None:
        """Record the exact context supplied to the agent at proposal time."""
        self.supplied_context = context
        self.updated_at = datetime.now(UTC).isoformat()

    model_config = {"extra": "forbid"}

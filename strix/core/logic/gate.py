"""Evidence gate: promote a violation only with a typed artifact and reproducible run."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from strix.core.logic.models import (
    ConfirmedViolation,
    ExecutedSequence,
    UnconfirmedHypothesis,
    ViolationCandidate,
)


ReproduceFn = Callable[[ExecutedSequence], Awaitable[bool]]


def _has_typed_artifact(candidate: ViolationCandidate) -> bool:
    artifact = candidate.sequence.artifact
    artifact_type = candidate.sequence.artifact_type
    return artifact is not None and artifact_type in {"diff", "callback", "race_result"}


async def evaluate(
    candidate: ViolationCandidate,
    *,
    reproduce: ReproduceFn | None = None,
) -> ConfirmedViolation | UnconfirmedHypothesis:
    """Promote a candidate only if it passes the evidence gate.

    The gate requires:
    1. The executed sequence reached a state the model declared impossible.
    2. A typed deterministic artifact (P2 diff, P3 callback, or Phase-4 race result)
       is attached.
    3. The violation reproduces when re-run (if a reproduce callback is provided).

    Free-text or narrative rationale is never accepted as evidence.
    """
    if not candidate.reached_impossible_state:
        return UnconfirmedHypothesis(
            flow_name=candidate.flow_name,
            invariant_kind=candidate.invariant_kind,
            reason="executed sequence did not reach a model-impossible state",
        )

    if not _has_typed_artifact(candidate):
        return UnconfirmedHypothesis(
            flow_name=candidate.flow_name,
            invariant_kind=candidate.invariant_kind,
            reason="no typed deterministic artifact attached",
        )

    if reproduce is not None and not await reproduce(candidate.sequence):
        return UnconfirmedHypothesis(
            flow_name=candidate.flow_name,
            invariant_kind=candidate.invariant_kind,
            reason="violation did not reproduce on re-run",
        )

    return ConfirmedViolation(
        flow_name=candidate.flow_name,
        invariant_kind=candidate.invariant_kind,
        executed_sequence=candidate.sequence,
        reason=(f"Reached model-impossible state with {candidate.sequence.artifact_type} artifact"),
    )

"""Fixed invariant catalog + deterministic violation tests for business logic.

The catalog is enumerable and pure: each test function executes the same logic
for a given invariant kind, regardless of which agent proposed the flow. The only
agent-driven input is the selection of (flow, invariant_kind) and the model
shapes that feed the test.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from strix.core.logic.context import ExecutionContext, record_replay
from strix.core.logic.models import (
    BusinessLogicModel,
    ExecutedSequence,
    ExecutedStep,
    FlowModel,
    InvariantKind,
    ViolationCandidate,
)
from strix.core.race.models import Precondition


ViolationTest = Callable[
    [FlowModel, BusinessLogicModel, ExecutionContext],
    Awaitable[ViolationCandidate],
]


_INVARIANTS: dict[InvariantKind, str] = {
    "step-skip": "Reach a journey step without completing its declared prerequisites.",
    "replay": "Re-submit a one-time action and observe a second successful commit.",
    "double-spend": "Concurrently redeem a single-use resource via the race harness.",
    "price-mismatch": "Tamper an amount/price/quantity param and observe a wrong total.",
    "unauthorized-state-change": "Drive a lifecycle transition the model forbids for this role.",
}


def list_invariant_kinds() -> list[InvariantKind]:
    """Return the fixed, enumerable set of business-logic violation kinds."""
    return list(_INVARIANTS)


def describe_invariant(kind: InvariantKind) -> str:
    """Return a short human-readable description of an invariant kind."""
    return _INVARIANTS.get(kind, "")


def _response_is_success(response: dict[str, Any] | None) -> bool:
    if response is None:
        return False
    status_code = response.get("status_code")
    return isinstance(status_code, int) and 200 <= status_code < 300


def _denied_response() -> dict[str, Any]:
    return {"status_code": 403, "body": "denied"}


def _role_for_flow(flow: FlowModel) -> str:
    if flow.journey is not None:
        return flow.journey.entry_role
    return "user"


async def _test_step_skip(
    flow: FlowModel,
    _model: BusinessLogicModel,
    ctx: ExecutionContext,
) -> ViolationCandidate:
    """Attempt to reach a step without its prerequisites and capture the result."""
    sequence = ExecutedSequence(
        flow_name=flow.name,
        invariant_kind="step-skip",
    )
    reached_impossible = False

    if flow.journey is None:
        return ViolationCandidate(
            flow_name=flow.name,
            invariant_kind="step-skip",
            sequence=sequence,
        )

    candidate_steps = [s for s in flow.journey.steps if s.depends_on and s.order > 0]
    if not candidate_steps:
        return ViolationCandidate(
            flow_name=flow.name,
            invariant_kind="step-skip",
            sequence=sequence,
        )

    target_step = candidate_steps[0]
    role = target_step.required_role or flow.journey.entry_role

    response = await record_replay(ctx, target_step.request_id, role)
    step = ExecutedStep(
        request_id=target_step.request_id,
        identity_role=role,
        response=response,
    )
    sequence.steps.append(step)

    if _response_is_success(response):
        reached_impossible = True
        sequence.artifact = ctx.diff([_denied_response(), response])
        sequence.artifact_type = "diff"

    return ViolationCandidate(
        flow_name=flow.name,
        invariant_kind="step-skip",
        sequence=sequence,
        reached_impossible_state=reached_impossible,
    )


async def _test_replay(
    flow: FlowModel,
    _model: BusinessLogicModel,
    ctx: ExecutionContext,
) -> ViolationCandidate:
    """Re-submit a one-time action and compare the two outcomes."""
    sequence = ExecutedSequence(
        flow_name=flow.name,
        invariant_kind="replay",
    )
    reached_impossible = False

    request_id = flow.request_id
    role = "user"

    first = await record_replay(ctx, request_id, role)
    sequence.steps.append(ExecutedStep(request_id=request_id, identity_role=role, response=first))

    second = await record_replay(ctx, request_id, role)
    sequence.steps.append(ExecutedStep(request_id=request_id, identity_role=role, response=second))

    if _response_is_success(first) and _response_is_success(second):
        reached_impossible = True
        sequence.artifact = ctx.diff([first, second])
        sequence.artifact_type = "diff"

    return ViolationCandidate(
        flow_name=flow.name,
        invariant_kind="replay",
        sequence=sequence,
        reached_impossible_state=reached_impossible,
    )


async def _test_unauthorized_transition(
    flow: FlowModel,
    _model: BusinessLogicModel,
    ctx: ExecutionContext,
) -> ViolationCandidate:
    """Drive a model-forbidden transition as a non-permitted identity."""
    sequence = ExecutedSequence(
        flow_name=flow.name,
        invariant_kind="unauthorized-state-change",
    )
    reached_impossible = False

    if flow.lifecycle is None:
        return ViolationCandidate(
            flow_name=flow.name,
            invariant_kind="unauthorized-state-change",
            sequence=sequence,
        )

    for transition in flow.lifecycle.transitions:
        allowed = set(transition.allowed_roles or [])
        if allowed and "user" not in allowed:
            response = await record_replay(ctx, transition.request_id, "user")
            sequence.steps.append(
                ExecutedStep(
                    request_id=transition.request_id,
                    identity_role="user",
                    response=response,
                )
            )
            if _response_is_success(response):
                reached_impossible = True
                sequence.artifact = ctx.diff([_denied_response(), response])
                sequence.artifact_type = "diff"
            break

    return ViolationCandidate(
        flow_name=flow.name,
        invariant_kind="unauthorized-state-change",
        sequence=sequence,
        reached_impossible_state=reached_impossible,
    )


def _extract_total(response: dict[str, Any] | None, total_param: str | None) -> float | None:
    """Extract a numeric total from a parsed response body."""
    if response is None or total_param is None:
        return None
    body = response.get("body") or ""
    if isinstance(body, dict):
        value = body.get(total_param)
        if isinstance(value, (int, float)):
            return float(value)
        return None
    if isinstance(body, str) and body.strip():
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return None
        value = data.get(total_param)
        if isinstance(value, (int, float)):
            return float(value)
    return None


async def _test_price_mismatch(
    flow: FlowModel,
    _model: BusinessLogicModel,
    ctx: ExecutionContext,
) -> ViolationCandidate:
    """Tamper amount/price/quantity and replay as the buyer to capture the charged total."""
    sequence = ExecutedSequence(
        flow_name=flow.name,
        invariant_kind="price-mismatch",
    )
    reached_impossible = False

    if flow.monetary_op is None:
        return ViolationCandidate(
            flow_name=flow.name,
            invariant_kind="price-mismatch",
            sequence=sequence,
        )

    op = flow.monetary_op
    relation = op.relation
    if not relation.tamper_values or not relation.baseline_values:
        return ViolationCandidate(
            flow_name=flow.name,
            invariant_kind="price-mismatch",
            sequence=sequence,
        )

    try:
        original = await ctx.view(op.request_id)
    except ValueError:
        return ViolationCandidate(
            flow_name=flow.name,
            invariant_kind="price-mismatch",
            sequence=sequence,
        )

    role = _role_for_flow(flow)
    body = original.get("body", "")
    headers = original.get("headers", {})
    content_type = headers.get("Content-Type", "")

    modifications: dict[str, Any]
    if "application/json" in content_type and body:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {}
        payload.update(relation.tamper_values)
        modifications = {"body": json.dumps(payload)}
    else:
        # For non-JSON requests, try to inject via query params first; the
        # replay engine will merge them with the existing URL query.
        modifications = {"params": relation.tamper_values}

    response = await record_replay(ctx, op.request_id, role, modifications=modifications)
    sequence.steps.append(
        ExecutedStep(
            request_id=op.request_id,
            identity_role=role,
            response=response,
        )
    )

    # Price-mismatch semantic: a server that trusts the client-supplied total
    # will accept a request whose charged total differs from the expected total
    # (the baseline model total). The invariant is reached when the server
    # accepts (2xx) and the charged total != expected total.
    if not _response_is_success(response):
        return ViolationCandidate(
            flow_name=flow.name,
            invariant_kind="price-mismatch",
            sequence=sequence,
        )

    baseline = relation.baseline_values or {}

    price = baseline.get(relation.price_param) if relation.price_param else None
    quantity = baseline.get(relation.quantity_param) if relation.quantity_param else None
    expected_total = baseline.get(relation.total_param) if relation.total_param else None

    if expected_total is None and isinstance(price, (int, float)):  # noqa: SIM102
        if isinstance(quantity, (int, float)):
            expected_total = float(price) * float(quantity)

    if expected_total is None:
        return ViolationCandidate(
            flow_name=flow.name,
            invariant_kind="price-mismatch",
            sequence=sequence,
        )

    actual = _extract_total(response, relation.total_param)
    if actual is not None and float(expected_total) != actual:
        reached_impossible = True
        expected_response = {
            "status_code": 200,
            "body": {relation.total_param or "total": float(expected_total)},
        }
        actual_response = {
            "status_code": response.get("status_code", 200),
            "body": {relation.total_param or "total": actual},
        }
        sequence.artifact = ctx.diff([expected_response, actual_response])
        sequence.artifact_type = "diff"

    return ViolationCandidate(
        flow_name=flow.name,
        invariant_kind="price-mismatch",
        sequence=sequence,
        reached_impossible_state=reached_impossible,
    )


async def _test_double_spend(
    flow: FlowModel,
    _model: BusinessLogicModel,
    ctx: ExecutionContext,
) -> ViolationCandidate:
    """Delegate concurrent redemption to the Phase-4 race harness."""
    sequence = ExecutedSequence(
        flow_name=flow.name,
        invariant_kind="double-spend",
    )
    reached_impossible = False

    if flow.monetary_op is None:
        return ViolationCandidate(
            flow_name=flow.name,
            invariant_kind="double-spend",
            sequence=sequence,
        )

    op = flow.monetary_op
    relation = op.relation
    role = _role_for_flow(flow)

    request_id = op.request_id
    setup_id = op.setup_request_id or request_id
    state_read_id = op.state_read_request_id or request_id

    precondition = Precondition(
        description=f"Double-spend precondition for {op.name}",
        setup_request_id=setup_id,
        state_read_request_id=state_read_id,
        identity_role=role,
        success_indicator="redeemed",
        state_counter=relation.state_counter,
        commit_unit=relation.commit_unit,
    )

    result = await ctx.race_harness(
        request_id=request_id,
        precondition=precondition,
        role=role,
        n=3,
        jitter_ms=0,
    )

    sequence.artifact = result
    sequence.artifact_type = "race_result"
    if result.verdict == "race":
        reached_impossible = True

    return ViolationCandidate(
        flow_name=flow.name,
        invariant_kind="double-spend",
        sequence=sequence,
        reached_impossible_state=reached_impossible,
    )


_CATALOG: dict[InvariantKind, ViolationTest] = {
    "step-skip": _test_step_skip,
    "replay": _test_replay,
    "double-spend": _test_double_spend,
    "price-mismatch": _test_price_mismatch,
    "unauthorized-state-change": _test_unauthorized_transition,
}


async def run_violation_test(
    kind: InvariantKind,
    flow: FlowModel,
    model: BusinessLogicModel,
    ctx: ExecutionContext,
) -> ViolationCandidate:
    """Execute the deterministic violation test for ``kind`` on ``flow``."""
    test = _CATALOG.get(kind)
    if test is None:
        raise ValueError(f"Unknown invariant kind: {kind}")
    return await test(flow, model, ctx)

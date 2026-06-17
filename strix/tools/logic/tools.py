"""Business-logic testing agent tools.

Four affordances:
- model intake (submit/read): ``propose_business_logic_model`` / ``read_business_logic_model``
- list-invariants-for-flow: ``list_flow_invariants``
- run-violation: ``run_business_logic_violation_test``
- read-gated-result: ``read_business_logic_violation_result``

"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.core.logic.models import (
    BusinessLogicModel,
    ConfirmedViolation,
    ExecutedSequence,
    UnconfirmedHypothesis,
)
from strix.core.logic.orchestrator import BusinessLogicOrchestrator
from strix.core.logic.store import BusinessLogicResultStore, BusinessLogicStore
from strix.core.paths import logic_model_path, run_dir_for
from strix.report.state import get_global_report_state
from strix.tools.reporting.tool import _do_create


def _run_dir(ctx: RunContextWrapper) -> Path:
    """Resolve the run directory from agent context or the global report state."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    run_dir_value = inner.get("run_dir")
    if isinstance(run_dir_value, str) and run_dir_value:
        return Path(run_dir_value)

    report_state = get_global_report_state()
    if report_state is not None and report_state.run_name:
        return run_dir_for(report_state.run_name)

    raise RuntimeError("No run_dir provided in context and no global report state available")


async def _report_for_violation(
    sequence: ExecutedSequence,
    target_key: str,
) -> dict[str, Any]:
    """File a vulnerability report for a confirmed business-logic violation."""
    artifact_type = sequence.artifact_type or "unknown"
    artifact = {
        "artifact_type": artifact_type,
        "mime_type": "application/json",
        "summary": f"Executed sequence produced a {artifact_type} artifact",
        "data": sequence.artifact,
    }

    description = (
        f"Business-logic violation detected: {sequence.invariant_kind} on "
        f"flow '{sequence.flow_name}' reached a state the model declared impossible."
    )
    impact = "Business logic can be bypassed, leading to unauthorized state changes or abuse."
    technical_analysis = (
        f"Flow: {sequence.flow_name}, invariant: {sequence.invariant_kind}. "
        f"Executed {len(sequence.steps)} step(s) and reached a model-impossible state."
    )
    poc_description = "Reproduce by replaying the executed sequence captured in the artifact."
    poc_script_code = "# Business-logic violation sequence is captured in the artifact."
    remediation_steps = (
        "Review the server-side state machine and enforce the modeled lifecycle, "
        "journey ordering, and authorization rules in the backend, not just the UI."
    )

    return await _do_create(
        title=f"Business-Logic Violation: {sequence.invariant_kind} on {target_key}",
        description=description,
        impact=impact,
        target=target_key,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
        cvss_breakdown={
            "attack_vector": "N",
            "attack_complexity": "L",
            "privileges_required": "L",
            "user_interaction": "N",
            "scope": "U",
            "confidentiality": "L",
            "integrity": "H",
            "availability": "N",
        },
        endpoint=sequence.steps[0].request_id if sequence.steps else "",
        method="BUSINESS_LOGIC",
        cve=None,
        cwe="CWE-841",
        code_locations=None,
        evidence_class="diff" if artifact_type == "diff" else artifact_type,
        artifacts=[artifact],
    )


@function_tool(timeout=60, strict_mode=False)
async def propose_business_logic_model(
    ctx: RunContextWrapper,
    engagement_id: str,
    target_id: str,
    model: dict[str, Any],
) -> str:
    """Persist the agent-proposed business-logic model for an engagement.

    The model contains the hypothesized journeys, lifecycles, trust boundaries,
    monetary operations, and named flows that the violation tests will exercise.
    It is scoped to the engagement and never bleeds across engagements.

    Args:
        engagement_id: Engagement identifier (per-engagement scope).
        target_id: Canonical target key (host[:port]).
        model: JSON-serializable business-logic model matching the locked schema.
    """
    run_dir = _run_dir(ctx)
    db_path = logic_model_path(run_dir, engagement_id)
    with BusinessLogicStore(db_path) as store:
        parsed = BusinessLogicModel.model_validate(model)
        parsed.engagement_id = engagement_id
        parsed.target_id = target_id
        store.save(parsed)
        invariants = [kind for flow in parsed.flows.values() for kind in flow.bound_invariants]
        return json.dumps(
            {
                "success": True,
                "engagement_id": engagement_id,
                "target_id": target_id,
                "flows": list(parsed.flows.keys()),
                "invariants": invariants,
            },
            ensure_ascii=False,
            default=str,
        )


@function_tool(timeout=60, strict_mode=False)
async def read_business_logic_model(
    ctx: RunContextWrapper,
    engagement_id: str,
) -> str:
    """Read back the previously-proposed business-logic model for an engagement.

    Args:
        engagement_id: Engagement identifier used to look up the model.
    """
    run_dir = _run_dir(ctx)
    db_path = logic_model_path(run_dir, engagement_id)
    with BusinessLogicStore(db_path) as store:
        model = store.load(engagement_id)
        if model is None:
            return json.dumps(
                {"success": False, "error": "no business-logic model found for engagement"},
                ensure_ascii=False,
            )
        return json.dumps(
            {"success": True, "model": model.model_dump()},
            ensure_ascii=False,
            default=str,
        )


@function_tool(timeout=60, strict_mode=False)
async def list_flow_invariants(
    ctx: RunContextWrapper,
    engagement_id: str,
    flow_name: str,
) -> str:
    """List the invariant kinds bound to a named flow in the engagement model.

    Args:
        engagement_id: Engagement identifier used to look up the model.
        flow_name: Name of the flow whose invariants are requested.
    """
    run_dir = _run_dir(ctx)
    db_path = logic_model_path(run_dir, engagement_id)
    with BusinessLogicStore(db_path) as store:
        model = store.load(engagement_id)
        if model is None:
            return json.dumps(
                {"success": False, "error": "no business-logic model found for engagement"},
                ensure_ascii=False,
            )
        flow = model.flows.get(flow_name)
        if flow is None:
            return json.dumps(
                {"success": False, "error": f"flow '{flow_name}' not found in model"},
                ensure_ascii=False,
            )
        return json.dumps(
            {
                "success": True,
                "engagement_id": engagement_id,
                "flow_name": flow_name,
                "invariants": flow.bound_invariants,
            },
            ensure_ascii=False,
            default=str,
        )


@function_tool(timeout=300, strict_mode=False)
async def run_business_logic_violation_test(
    ctx: RunContextWrapper,
    engagement_id: str,
    target_id: str,
    target_url: str,
    flow_name: str,
    invariant_kind: str,
    scope_rules: list[str] | None = None,
) -> str:
    """Run a deterministic business-logic violation test for a bound invariant.

    Loads the previously-proposed model, checks that the invariant is bound to
    the flow, executes the catalog test, and runs the evidence gate. A confirmed
    violation is filed as a vulnerability report with a typed artifact
    (P2 diff, P3 callback, or Phase-4 race result). The gated result is persisted
    and can be read later with ``read_business_logic_violation_result``.

    Args:
        engagement_id: Engagement identifier used to look up the model.
        target_id: Canonical target key (host[:port]) for identity lookup.
        target_url: Base URL of the target for replay/race harness.
        flow_name: Name of the flow in the model to test.
        invariant_kind: One of the fixed invariant kinds (step-skip, replay,
            double-spend, price-mismatch, unauthorized-state-change).
        scope_rules: List of allowed host patterns (e.g., ``["example.com"]``).
    """
    from strix.core.logic.catalog import list_invariant_kinds  # noqa: PLC0415

    if invariant_kind not in list_invariant_kinds():
        return json.dumps(
            {
                "success": False,
                "error": f"Unknown invariant kind: {invariant_kind}",
            },
            ensure_ascii=False,
        )

    run_dir = _run_dir(ctx)
    orchestrator = BusinessLogicOrchestrator(
        run_dir=run_dir,
        target_id=target_id,
        target_url=target_url,
        scope_rules=scope_rules,
    )
    result = await orchestrator.run(engagement_id, flow_name, invariant_kind)  # type: ignore[arg-type]
    result_id = str(uuid.uuid4())

    db_path = logic_model_path(run_dir, engagement_id)
    with BusinessLogicResultStore(db_path) as result_store:
        if isinstance(result, ConfirmedViolation):
            report = await _report_for_violation(result.executed_sequence, target_id)
            payload = {
                "verdict": "confirmed",
                "invariant_kind": result.invariant_kind,
                "flow_name": result.flow_name,
                "reason": result.reason,
                "report": report,
                "executed_sequence": result.executed_sequence.model_dump(),
            }
            result_store.save(
                result_id=result_id,
                engagement_id=engagement_id,
                flow_name=flow_name,
                invariant_kind=invariant_kind,
                verdict="confirmed",
                reason=result.reason,
                payload=payload,
            )
            return json.dumps(
                {
                    "success": True,
                    "result_id": result_id,
                    "verdict": "confirmed",
                    "invariant_kind": result.invariant_kind,
                    "flow_name": result.flow_name,
                    "reason": result.reason,
                    "report": report,
                },
                ensure_ascii=False,
                default=str,
            )

        assert isinstance(result, UnconfirmedHypothesis)
        payload = {
            "verdict": "unconfirmed",
            "invariant_kind": invariant_kind,
            "flow_name": flow_name,
            "reason": result.reason,
        }
        result_store.save(
            result_id=result_id,
            engagement_id=engagement_id,
            flow_name=flow_name,
            invariant_kind=invariant_kind,
            verdict="unconfirmed",
            reason=result.reason,
            payload=payload,
        )
        return json.dumps(
            {
                "success": True,
                "result_id": result_id,
                "verdict": "unconfirmed",
                "invariant_kind": invariant_kind,
                "flow_name": flow_name,
                "reason": result.reason,
            },
            ensure_ascii=False,
            default=str,
        )


@function_tool(timeout=60, strict_mode=False)
async def read_business_logic_violation_result(
    ctx: RunContextWrapper,
    engagement_id: str,
    result_id: str,
) -> str:
    """Read a previously persisted business-logic violation result.

    Args:
        engagement_id: Engagement identifier that owns the result.
        result_id: UUID returned by ``run_business_logic_violation_test``.
    """
    run_dir = _run_dir(ctx)
    db_path = logic_model_path(run_dir, engagement_id)
    with BusinessLogicResultStore(db_path) as result_store:
        result = result_store.load(result_id)
        if result is None:
            return json.dumps(
                {"success": False, "error": f"result '{result_id}' not found"},
                ensure_ascii=False,
            )
        return json.dumps(
            {"success": True, "result": result},
            ensure_ascii=False,
            default=str,
        )

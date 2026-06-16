"""Race-condition harness agent tool."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.core.identity.redaction import redact_headers
from strix.core.identity.store import IdentityStore, identity_store_path
from strix.core.paths import run_dir_for
from strix.core.race.harness import (
    build_trial_summary,
    target_url_from_request_id,
)
from strix.core.race.harness import (
    run_race_harness as _run_race_harness,
)
from strix.core.race.models import Precondition, RaceResult, ScopedRefusal
from strix.report.state import get_global_report_state
from strix.tools.reporting.tool import _do_create


logger = logging.getLogger(__name__)


_CVSS_RACE: dict[str, str] = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "L",
    "integrity": "H",
    "availability": "N",
}


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


def _get_store(run_dir: Path) -> IdentityStore:
    return IdentityStore(identity_store_path(run_dir))


def _build_precondition(
    raw: dict[str, Any],
    identity_role: str,
) -> Precondition:
    """Build a locked Precondition from the agent-supplied dict."""
    return Precondition(
        description=str(raw.get("description", "")),
        setup_request_id=str(raw.get("setup_request_id", "")),
        state_read_request_id=str(raw.get("state_read_request_id", "")),
        identity_role=identity_role,
        success_indicator=raw.get("success_indicator"),
        state_counter=raw.get("state_counter"),
        commit_unit=raw.get("commit_unit"),
    )


def _redact_state_delta(state_delta: dict[str, Any]) -> dict[str, Any]:
    """Redact credential-bearing headers in the raw state-delta responses."""
    redacted = dict(state_delta)
    for key in ("baseline", "post_action"):
        response = redacted.get(key)
        if isinstance(response, dict) and isinstance(response.get("headers"), dict):
            response = dict(response)
            response["headers"] = redact_headers(response["headers"])
            redacted[key] = response
    return redacted


async def _report_for_race(result: RaceResult, target_key: str) -> dict[str, Any]:
    """File a vulnerability report for a confirmed race condition."""
    state_delta = result.state_delta
    artifact = {
        "artifact_type": "state_delta",
        "mime_type": "application/json",
        "summary": "Before/after observable state delta produced by the race harness",
        "data": _redact_state_delta(state_delta.model_dump()),
    }

    description = (
        f"Concurrent execution of {result.n} copies of the same single-use request "
        f"from precondition '{result.precondition.description}' committed "
        f"{result.commit_count} times, indicating a time-of-check/time-of-use race."
    )
    impact = (
        "An attacker can abuse the race window to perform a single-use action "
        "multiple times, leading to financial loss, unauthorized access, or "
        "state corruption depending on the affected endpoint."
    )
    technical_analysis = (
        f"Precondition: {result.precondition.description}. "
        f"n={result.n}, jitter_ms={result.jitter_ms}, retries={result.retry_count}. "
        f"Commit count={result.commit_count}, state delta structure="
        f"{state_delta.semantic_delta.body_structure_delta}, "
        f"observable oracle={state_delta.observable}."
    )
    poc_description = (
        "Replay the captured request concurrently from the declared precondition. "
        "The attached state-delta artifact shows the before/after observable state."
    )
    poc_script_code = "# Race harness results are captured in the attached state_delta artifact."
    remediation_steps = (
        "Use atomic check-then-mutate operations (e.g., database row-level locks, "
        "compare-and-set, or unique transaction tokens) so the single-use action "
        "cannot commit more than once under concurrent requests."
    )

    return await _do_create(
        title=f"Race Condition on {target_key}",
        description=description,
        impact=impact,
        target=target_key,
        technical_analysis=technical_analysis,
        poc_description=poc_description,
        poc_script_code=poc_script_code,
        remediation_steps=remediation_steps,
        cvss_breakdown=_CVSS_RACE,
        endpoint=result.precondition.setup_request_id,
        method="RACE",
        cve=None,
        cwe="CWE-362",
        code_locations=None,
        evidence_class="race_result",
        artifacts=[artifact],
    )


async def _run_tool(
    ctx: RunContextWrapper,
    request_id: str,
    precondition: dict[str, Any],
    target_key: str,
    identity_role: str,
    n: int,
    jitter_ms: int,
    retry_bound: int,
    scope_rules: list[str] | None,
) -> dict[str, Any]:
    """Core race-harness tool logic, separated from the decorator for testability."""
    run_dir = _run_dir(ctx)
    store = _get_store(run_dir)
    try:
        identity = store.get_identity(target_key, identity_role)
    finally:
        store.close()

    if identity is None:
        return {
            "success": False,
            "error": f"Identity '{identity_role}' not found for target '{target_key}'",
        }

    try:
        target_url = await target_url_from_request_id(request_id)
    except Exception as exc:  # noqa: BLE001
        return {
            "success": False,
            "error": f"Failed to resolve target URL from request {request_id}: {exc}",
        }

    pre = _build_precondition(precondition, identity_role)

    try:
        result = await _run_race_harness(
            request_id,
            pre,
            identity,
            target_url,
            scope_rules,
            n,
            jitter_ms,
            retry_bound,
        )
    except ScopedRefusal as exc:
        return {
            "success": False,
            "error": f"Scoped refusal: {exc.reason}",
            "scope_in_scope": False,
            "target_url": exc.target_url,
        }

    report: dict[str, Any] | None = None
    if result.verdict == "race":
        report = await _report_for_race(result, target_key)

    summary = build_trial_summary(result)
    return {
        "success": result.success,
        "verdict": result.verdict,
        "commit_count": result.commit_count,
        "retry_count": result.retry_count,
        "n": result.n,
        "jitter_ms": result.jitter_ms,
        "scope_decision": result.scope_decision.model_dump(),
        "precondition": result.precondition.model_dump(),
        "trial_summary": summary,
        "report": report,
        "error": result.error,
    }


@function_tool(timeout=180, strict_mode=False)
async def run_race_harness(
    ctx: RunContextWrapper,
    request_id: str,
    precondition: dict[str, Any],
    target_key: str,
    identity_role: str = "user",
    n: int = 3,
    jitter_ms: int = 50,
    retry_bound: int = 1,
    scope_rules: list[str] | None = None,
) -> str:
    """Race a single-use request: fire ``n`` concurrent copies from a precondition.

    The harness drives the target to a declared precondition, fans out ``n``
    identical copies of the request over a single shared identity session,
    reads the observable state after the race, and uses the P2 differential
    engine + a new commit-count aggregator to decide whether the action
    committed more than once.

    A confirmed race is filed as a vulnerability report with
    ``evidence_class="race_result"`` and a ``state_delta`` artifact. The
    dispatch is scope-gated: out-of-scope targets are refused with zero
    requests sent.

    Args:
        request_id: Captured request ID to replay concurrently.
        precondition: Dict describing the precondition and the requests used
            to set/read it. Required keys:

            - ``description`` — human-readable state (e.g. "coupon C unredeemed").
            - ``setup_request_id`` — captured request that drives the target to
              the precondition.
            - ``state_read_request_id`` — captured request that reads the
              observable state (e.g., balance / redemption status).
            - ``success_indicator`` (optional) — substring that must appear in
              a per-copy response body to count as a successful commit.
        target_key: Canonical target key (host[:port]) for identity lookup.
        identity_role: Identity role to use for the shared session
            (default ``user``).
        n: Number of concurrent copies (default 3, capped).
        jitter_ms: Maximum per-copy timing offset in milliseconds (default 50).
        retry_bound: Maximum retries on inconclusive results (default 1, capped).
        scope_rules: List of allowed host patterns (e.g., ``["example.com"]``);
            out-of-scope targets are refused.
    """
    result = await _run_tool(
        ctx,
        request_id,
        precondition,
        target_key,
        identity_role,
        n,
        jitter_ms,
        retry_bound,
        scope_rules,
    )
    return json.dumps(result, ensure_ascii=False, default=str)

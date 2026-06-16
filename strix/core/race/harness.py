"""Race-harness orchestrator: precondition → dispatch → diff → verdict."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from strix.core.diff import normalize_response
from strix.core.identity.redaction import redact_headers
from strix.core.identity.replay import replay_as_identity
from strix.core.race.collector import collect_commit_count, collect_state_delta
from strix.core.race.dispatch import dispatch
from strix.core.race.models import Precondition, RaceResult, ScopeDecision, ScopedRefusal
from strix.core.race.precondition import reset_precondition, setup_precondition
from strix.core.race.verdict import verdict
from strix.tools.proxy import caido_api


if TYPE_CHECKING:
    from strix.core.identity.models import Identity


_MAX_RETRY = 3


async def target_url_from_request_id(request_id: str) -> str:
    """Resolve the full URL of a captured request for scope checking."""
    result = await caido_api.view_request(request_id, part="request")
    if result is None or not result.request or not result.request.raw:
        raise ValueError(f"Request {request_id} not found or has no raw request")

    original = result.request
    raw_str = original.raw.decode("utf-8", errors="replace")
    components = caido_api.parse_raw_request(raw_str)
    return caido_api.full_url_from_components(original, components, {})


async def _read_state(
    request_id: str,
    identity: Identity,
) -> dict[str, Any] | None:
    """Replay a state-read request and return the parsed response."""
    result = await replay_as_identity(request_id, identity)
    return result.get("response") if result.get("success") else None


async def _run_trial(
    request_id: str,
    precondition: Precondition,
    identity: Identity,
    target_url: str,
    scope_rules: list[str] | None,
    n: int,
    jitter_ms: int,
) -> RaceResult:
    """Execute one race trial from precondition through verdict."""
    scope_decision = ScopeDecision(
        target_url=target_url,
        scope_rules=scope_rules,
        in_scope=True,
        reason="dispatch allowed",
    )

    baseline = await setup_precondition(precondition, identity)
    if baseline is None:
        return RaceResult(
            success=False,
            verdict="inconclusive",
            commit_count=0,
            retry_count=0,
            state_delta=collect_state_delta(None, None, observable=False),
            outcomes=[],
            scope_decision=scope_decision,
            precondition=precondition,
            n=n,
            jitter_ms=jitter_ms,
            error="precondition setup failed",
        )

    try:
        outcomes = await dispatch(
            request_id,
            identity,
            n=n,
            jitter_ms=jitter_ms,
            target_url=target_url,
            scope_rules=scope_rules,
        )
    except ScopedRefusal as exc:
        return RaceResult(
            success=False,
            verdict="inconclusive",
            commit_count=0,
            retry_count=0,
            state_delta=collect_state_delta(baseline, None, observable=False),
            outcomes=[],
            scope_decision=ScopeDecision(
                target_url=exc.target_url,
                scope_rules=exc.scope_rules,
                in_scope=False,
                reason=exc.reason,
            ),
            precondition=precondition,
            n=n,
            jitter_ms=jitter_ms,
            error=f"scoped refusal: {exc.reason}",
        )

    post_action = await _read_state(precondition.state_read_request_id, identity)
    observable = post_action is not None
    state_delta = collect_state_delta(baseline, post_action, observable=observable)
    commit_count = collect_commit_count(
        outcomes,
        state_delta,
        success_indicator=precondition.success_indicator,
        state_counter=precondition.state_counter,
        commit_unit=precondition.commit_unit,
    )
    verdict_result = verdict(state_delta, commit_count)

    return RaceResult(
        success=True,
        verdict=verdict_result,
        commit_count=commit_count,
        retry_count=0,
        state_delta=state_delta,
        outcomes=outcomes,
        scope_decision=scope_decision,
        precondition=precondition,
        n=n,
        jitter_ms=jitter_ms,
    )


def _normalize_response_for_summary(response: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return a redacted, normalized response suitable for the agent-facing table."""
    if response is None:
        return None

    normalized = normalize_response(response)
    return {
        "status_code": normalized.status_code,
        "status_class": normalized.status_class,
        "body": normalized.body,
        "body_length": normalized.body_length,
        "headers": redact_headers(normalized.headers),
        "normalized_fields": normalized.normalized_fields,
    }


def build_trial_summary(result: RaceResult) -> dict[str, Any]:
    """Build a redacted, agent-facing summary of the trial."""
    outcome_table = [
        {
            "copy_index": o.copy_index,
            "status": o.status,
            "elapsed_ms": o.elapsed_ms,
            "response": _normalize_response_for_summary(o.response),
            "error": o.error,
        }
        for o in result.outcomes
    ]

    state_delta = result.state_delta
    semantic = state_delta.semantic_delta
    return {
        "verdict": result.verdict,
        "commit_count": result.commit_count,
        "retry_count": result.retry_count,
        "n": result.n,
        "jitter_ms": result.jitter_ms,
        "scope_in_scope": result.scope_decision.in_scope,
        "scope_reason": result.scope_decision.reason,
        "precondition_description": result.precondition.description,
        "observable_oracle_used": state_delta.observable,
        "state_delta_summary": {
            "baseline_status": state_delta.baseline.get("status_code"),
            "post_action_status": state_delta.post_action.get("status_code"),
            "body_structure_delta": semantic.body_structure_delta,
            "normalized_length_delta": semantic.normalized_length_delta,
            "auth_signal_delta": semantic.auth_signal_delta,
        },
        "outcome_table": outcome_table,
    }


async def run_race_harness(
    request_id: str,
    precondition: Precondition,
    identity: Identity,
    target_url: str,
    scope_rules: list[str] | None,
    n: int,
    jitter_ms: int,
    retry_bound: int,
) -> RaceResult:
    """Run the race harness with bounded retry on inconclusive results."""
    bounded_retry = max(0, min(retry_bound, _MAX_RETRY))
    last_result: RaceResult | None = None

    for attempt in range(bounded_retry + 1):
        result = await _run_trial(
            request_id,
            precondition,
            identity,
            target_url,
            scope_rules,
            n,
            jitter_ms,
        )
        last_result = result

        if result.verdict != "inconclusive":
            result.retry_count = attempt
            return result

        if attempt < bounded_retry:
            reset = await reset_precondition(precondition, identity)
            if reset is None:
                result.error = "precondition reset failed during retry"
                result.retry_count = attempt
                return result

    assert last_result is not None
    last_result.retry_count = bounded_retry
    if last_result.error is None:
        last_result.error = f"inconclusive after {bounded_retry} retries"
    return last_result

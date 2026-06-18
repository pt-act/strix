"""Centralized funnel emit-wrapper for the propose-dispose harness tools.

Spec B harness wiring (operator-approved, 2026-06-18): the funnel records **every**
harness run (confirmed *and* unconfirmed) from a single recording point — this wrapper —
while the report path (``ReportState._link_disposer_verdict_to_funnel``) is demoted to
attaching only the ``report_id``.

The wrapper is behavior-identical by construction: it calls the wrapped tool's
``on_invoke_tool`` and returns its output **unchanged**. Its only side effect is one
``record_harness_run`` per invocation, which is itself emit-only (creates no report,
changes no verdict / ``evidence_class``, never raises). Gate-neutrality (``C ⊆ P``) and the
disposer's disposition are therefore preserved.

Byte-identity of the *confirmed* end-state: when a harness confirms, it has already filed
its report via ``_do_create`` (whose return embeds the true ``evidence_class``). The wrapper
reads that exact class from ``result["report"]["evidence_class"]`` and records
``verdict="confirmed"`` with ``harness_name = _EVIDENCE_TO_HARNESS[ec]`` — exactly the
``HarnessVerdict`` the old report path used to write — so the proposal's final
``{verdict, report_id}`` end-state is unchanged. Unconfirmed runs (no report) now also emit,
with ``verdict="unconfirmed"`` / ``evidence_class="none"``.
"""

from __future__ import annotations

import copy
import json
import logging
from typing import TYPE_CHECKING, Any, cast

from strix.report.state import _EVIDENCE_TO_HARNESS, get_global_report_state


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from agents import FunctionTool


logger = logging.getLogger(__name__)

# Best-effort endpoint correlation: harness tools name their target differently. Explicit
# ``proposal_id`` (when threaded) always wins inside ``record_harness_run``; this is the fallback.
_ENDPOINT_ARG_KEYS: tuple[str, ...] = (
    "endpoint",
    "target",
    "target_url",
    "target_key",
    "request_id",
    "target_id",
)


def _coerce_dict(value: Any) -> dict[str, Any] | None:
    """Parse a tool result or args payload (JSON string or dict) into a dict, else None."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _extract_endpoint(args: dict[str, Any]) -> str | None:
    for key in _ENDPOINT_ARG_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    precondition = args.get("precondition")
    if isinstance(precondition, dict):
        setup = precondition.get("setup_request_id")
        if isinstance(setup, str) and setup.strip():
            return setup.strip()
    return None


def emit_harness_run(default_harness: str, result: Any, args_json: str) -> None:
    """Derive ``(verdict, evidence_class, endpoint)`` from a harness return and emit one run.

    Confirmed iff the return embeds a ``report`` carrying a real (non-``none``) evidence class;
    in that case the recorded ``harness_name``/``evidence_class``/``verdict`` reproduce the
    pre-refactor report-path verdict byte-for-byte. Otherwise an ``unconfirmed`` run is emitted.
    """
    result_dict = _coerce_dict(result)
    args = _coerce_dict(args_json) or {}

    evidence_class = "none"
    verdict = "unconfirmed"
    report = result_dict.get("report") if result_dict else None
    if isinstance(report, dict):
        reported_class = report.get("evidence_class")
        if isinstance(reported_class, str) and reported_class in _EVIDENCE_TO_HARNESS:
            evidence_class = reported_class
            verdict = "confirmed"

    harness_name = (
        _EVIDENCE_TO_HARNESS[evidence_class] if evidence_class != "none" else default_harness
    )
    proposal_id = args.get("proposal_id")

    state = get_global_report_state()
    if state is None:
        return

    state.record_harness_run(
        harness_name=harness_name,
        verdict=verdict,
        evidence_class=evidence_class,  # type: ignore[arg-type]
        endpoint=_extract_endpoint(args),
        proposal_id=proposal_id if isinstance(proposal_id, str) else None,
    )


def wrap_harness_tool(tool: FunctionTool, *, default_harness: str) -> FunctionTool:
    """Return a behavior-identical clone of ``tool`` that emits one funnel run per call.

    The wrapped ``on_invoke_tool`` delegates to the original, emits from its return value, and
    returns that value unchanged. Emission failures are swallowed (observability must never
    perturb the disposer).

    If ``tool`` is not a ``FunctionTool`` (e.g., the agents SDK is mocked to a raw function in
    a unit test), it has no ``on_invoke_tool`` and is returned unchanged — the wrapper is a
    production seam, exercised directly in ``tests/test_funnel_wrapper.py``.
    """
    original = getattr(tool, "on_invoke_tool", None)
    if not callable(original):
        return tool
    invoke = cast("Callable[[Any, str], Awaitable[Any]]", original)

    async def _on_invoke(ctx: Any, args_json: str) -> Any:
        result = await invoke(ctx, args_json)
        try:
            emit_harness_run(default_harness, result, args_json)
        except Exception:
            logger.exception("funnel emit-wrapper failed (non-fatal; observability only)")
        return result

    wrapped = copy.copy(tool)
    wrapped.on_invoke_tool = _on_invoke
    return wrapped

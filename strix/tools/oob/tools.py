"""OOB oracle agent tools.

These tools expose the token registry and correlator to the agent runtime. All
credential material and callback evidence are returned in structured JSON;
raw callback data is attached to reports via the report layer, not exposed here.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from agents import RunContextWrapper, function_tool

from strix.core.oob.correlator import Correlator
from strix.core.oob.registry import TokenRegistry
from strix.core.paths import oob_registry_path
from strix.runtime.oob.provider import InteractshProvider
from strix.tools.reporting.tool import _do_create


if TYPE_CHECKING:
    from strix.runtime.oob.provider import OobProvider

logger = logging.getLogger(__name__)


_CVSS_OOB_CALLBACK: dict[str, str] = {
    "attack_vector": "N",
    "attack_complexity": "L",
    "privileges_required": "N",
    "user_interaction": "N",
    "scope": "U",
    "confidentiality": "H",
    "integrity": "L",
    "availability": "N",
}


def _run_dir_from_ctx(ctx: RunContextWrapper) -> Path:
    """Return the run directory from the agent context."""
    context = cast("dict[str, Any] | None", getattr(ctx, "context", None))
    if isinstance(context, dict):
        run_dir = context.get("run_dir")
        if run_dir is not None:
            return Path(cast("str | Path", run_dir))
    raise RuntimeError("Tool context is missing 'run_dir'")


async def _oob_provider(ctx: RunContextWrapper, run_dir: Path) -> OobProvider:
    """Return the OOB provider from context, or fall back to a local spawn."""
    context = cast("dict[str, Any] | None", getattr(ctx, "context", None))
    if isinstance(context, dict):
        provider = context.get("oob_provider")
        if provider is not None:
            return cast("OobProvider", provider)

    # Fallback: spawn a local interactsh-client. This is useful for standalone
    # invocations but is not the preferred production path (container sidecar).
    provider = InteractshProvider(no_spawn=False)
    await provider.start(run_dir)
    return provider


def _to_tool_json(value: Any) -> Any:
    """Recursively convert dataclasses/Pydantic objects to tool JSON values."""
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, datetime):
        return value.isoformat()
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {str(k): _to_tool_json(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _to_tool_json(v) for k, v in value.items()}
    if isinstance(value, list | tuple | set):
        return [_to_tool_json(v) for v in value]
    return str(value)


def _dump_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


@function_tool(timeout=60)
async def mint_oob_token(
    ctx: RunContextWrapper,
    engagement_id: str,
    candidate_id: str,
    request_ref: str,
    payload_class: str = "dns",
    window_seconds: int = 300,
) -> str:
    """Mint an OOB callback token for a candidate.

    Returns the injectable host (e.g. ``<token>.oast.pro``) and the token record.
    The provider must be ready; otherwise the mint is rejected.
    """
    run_dir = _run_dir_from_ctx(ctx)
    provider = await _oob_provider(ctx, run_dir)

    registry = TokenRegistry(oob_registry_path(run_dir))
    try:
        mint = registry.mint(
            engagement_id,
            candidate_id,
            request_ref,
            base_host=provider.base_host(),
            provider_ready=provider.ready(),
            window_seconds=window_seconds,
        )
        return _dump_json(
            {
                "success": True,
                "token": mint.token,
                "injectable_host": mint.injectable_host,
                "engagement_id": mint.engagement_id,
                "candidate_id": mint.candidate_id,
                "payload_class": payload_class,
                "window_seconds": mint.window_seconds,
            },
        )
    finally:
        registry.close()


@function_tool(timeout=60)
async def poll_oob_callbacks(
    ctx: RunContextWrapper,
    engagement_id: str,
    limit: int = 100,
) -> str:
    """Poll the OOB provider and correlate hits with the engagement mint-log.

    Returns a list of CorrelationRecord statuses.
    """
    run_dir = _run_dir_from_ctx(ctx)
    provider = await _oob_provider(ctx, run_dir)

    registry = TokenRegistry(oob_registry_path(run_dir))
    try:
        hits = await provider.poll_interactions()
        hits = hits[:limit]
        correlator = Correlator(registry)
        records = [correlator.correlate(hit, engagement_id) for hit in hits]
        return _dump_json(
            {
                "success": True,
                "hits": len(hits),
                "records": [_to_tool_json(record) for record in records],
            },
        )
    finally:
        registry.close()


@function_tool(timeout=60)
async def confirm_oob_callback(
    ctx: RunContextWrapper,
    engagement_id: str,
    candidate_id: str,
) -> str:
    """Confirm whether a candidate received an OOB callback within its window.

    Returns a single ``confirmed`` or ``unconfirmed`` verdict.
    """
    run_dir = _run_dir_from_ctx(ctx)
    provider = await _oob_provider(ctx, run_dir)

    registry = TokenRegistry(oob_registry_path(run_dir))
    try:
        mint = registry.lookup_by_candidate(engagement_id, candidate_id)
        if mint is None:
            return _dump_json(
                {
                    "success": True,
                    "verdict": "unconfirmed",
                    "reason": "no token minted for candidate",
                },
            )

        hits = await provider.poll_interactions()
        correlator = Correlator(registry)
        for hit in hits:
            if hit.token != mint.token:
                continue
            record = correlator.correlate(hit, engagement_id)
            if record.status == "confirmed":
                return _dump_json(
                    {
                        "success": True,
                        "verdict": "confirmed",
                        "record": _to_tool_json(record),
                    },
                )

        return _dump_json(
            {
                "success": True,
                "verdict": "unconfirmed",
                "reason": "no correlated callback in window",
            },
        )
    finally:
        registry.close()


async def _promote_oob_candidate(
    run_dir: Path,
    provider: OobProvider,
    registry: TokenRegistry,
    engagement_id: str,
    candidate_id: str,
    *,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> dict[str, Any]:
    """Confirm an OOB callback and, if confirmed, file a report.

    A report is created only when a correlated callback is observed within the
    token window. The callback is attached as an ``oob_callback`` artifact with
    ``evidence_class="callback"``. Absence of a callback returns a clean
    ``unconfirmed`` result and no report is filed.
    """
    mint = registry.lookup_by_candidate(engagement_id, candidate_id)
    if mint is None:
        return {
            "success": True,
            "verdict": "unconfirmed",
            "reason": "no token minted for candidate",
        }

    hits = await provider.poll_interactions()
    correlator = Correlator(registry)
    for hit in hits:
        if hit.token != mint.token:
            continue
        record = correlator.correlate(hit, engagement_id)
        if record.status == "confirmed":
            artifact: dict[str, Any] = {
                "artifact_type": "oob_callback",
                "mime_type": "application/json",
                "summary": f"Correlated OOB callback for candidate {candidate_id}",
                "data": _to_tool_json(record),
            }
            report = await _do_create(
                title=title,
                description=description,
                impact=impact,
                target=target,
                technical_analysis=technical_analysis,
                poc_description=poc_description,
                poc_script_code=poc_script_code,
                remediation_steps=remediation_steps,
                cvss_breakdown=_CVSS_OOB_CALLBACK,
                endpoint=endpoint,
                method=method,
                cve=cve,
                cwe=cwe,
                code_locations=code_locations,
                agent_id=agent_id,
                agent_name=agent_name,
                evidence_class="callback",
                artifacts=[artifact],
            )
            return {
                "success": True,
                "verdict": "confirmed",
                "report": report,
                "record": _to_tool_json(record),
            }

    return {
        "success": True,
        "verdict": "unconfirmed",
        "reason": "no correlated callback in window",
    }


@function_tool(timeout=60, strict_mode=False)
async def report_oob_confirmed_candidate(
    ctx: RunContextWrapper,
    engagement_id: str,
    candidate_id: str,
    title: str,
    description: str,
    impact: str,
    target: str,
    technical_analysis: str,
    poc_description: str,
    poc_script_code: str,
    remediation_steps: str,
    endpoint: str | None = None,
    method: str | None = None,
    cve: str | None = None,
    cwe: str | None = None,
    code_locations: list[dict[str, Any]] | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
) -> str:
    """Promote an OOB candidate to a finding only if a correlated callback exists.

    This is the impact gate for blind vulnerability classes (SSRF, XXE, blind
    XSS, etc.): a candidate is reported only when the strix-owned OOB listener
    observes a real, correlated callback within the token window. The captured
    callback is attached as an ``artifact_type="oob_callback"`` evidence
    artifact and the report receives ``evidence_class="callback"``.

    If no callback is observed, the function returns an explicit
    ``unconfirmed`` verdict and does **not** file a vulnerability report.

    Args:
        engagement_id: Engagement boundary the candidate belongs to.
        candidate_id: Unique candidate identifier within the engagement.
        title: Finding title (e.g. "SSRF in image import via OOB callback").
        description: How the vulnerability was discovered and what it is.
        impact: Attacker outcome and business risk.
        target: Affected URL or domain.
        technical_analysis: Mechanism and root cause.
        poc_description: Step-by-step reproduction.
        poc_script_code: Working PoC code.
        remediation_steps: Specific, actionable fix.
        endpoint: Affected API path, when relevant.
        method: HTTP method, when relevant.
        cve: Bare CVE ID if certain, else omit.
        cwe: Most specific child CWE, when relevant.
        code_locations: White-box location objects, when available.
        agent_id: Reporting agent id.
        agent_name: Reporting agent name.
    """
    run_dir = _run_dir_from_ctx(ctx)
    provider = await _oob_provider(ctx, run_dir)

    registry = TokenRegistry(oob_registry_path(run_dir))
    try:
        result = await _promote_oob_candidate(
            run_dir,
            provider,
            registry,
            engagement_id,
            candidate_id,
            title=title,
            description=description,
            impact=impact,
            target=target,
            technical_analysis=technical_analysis,
            poc_description=poc_description,
            poc_script_code=poc_script_code,
            remediation_steps=remediation_steps,
            endpoint=endpoint,
            method=method,
            cve=cve,
            cwe=cwe,
            code_locations=code_locations,
            agent_id=agent_id,
            agent_name=agent_name,
        )
        return _dump_json(result)
    finally:
        registry.close()

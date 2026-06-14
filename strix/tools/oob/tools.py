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


if TYPE_CHECKING:
    from strix.runtime.oob.provider import OobProvider

logger = logging.getLogger(__name__)


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

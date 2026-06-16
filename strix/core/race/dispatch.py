"""Scope-gated concurrent dispatcher for race-condition copies."""

from __future__ import annotations

import asyncio
import random
from typing import TYPE_CHECKING

from strix.core.identity.replay import replay_as_identity
from strix.core.inventory.collectors._scope import host_in_scope
from strix.core.race.models import CopyOutcome, ScopedRefusal


if TYPE_CHECKING:
    from strix.core.identity.models import Identity


_MAX_N = 10
_MAX_JITTER_MS = 500


class DispatchError(Exception):
    """Raised when the dispatcher cannot fan out the requested copies."""


def _guard_bounds(n: int, jitter_ms: int) -> tuple[int, int]:
    """Clamp n and jitter to bounded defaults."""
    bounded_n = max(1, min(n, _MAX_N))
    bounded_jitter = max(0, min(jitter_ms, _MAX_JITTER_MS))
    return bounded_n, bounded_jitter


async def _copy_with_jitter(
    copy_index: int,
    request_id: str,
    identity: Identity,
    jitter_ms: int,
) -> CopyOutcome:
    """Send one copy after a bounded jitter offset."""
    if jitter_ms > 0:
        await asyncio.sleep(random.uniform(0, jitter_ms / 1000.0))  # noqa: S311  # nosec B311  # jitter is non-cryptographic timing noise

    result = await replay_as_identity(request_id, identity)
    response = result.get("response")
    return CopyOutcome(
        copy_index=copy_index,
        status=result.get("status", "ERROR"),
        error=result.get("error"),
        elapsed_ms=result.get("elapsed_ms", 0),
        response=response,
        session_id=result.get("session_id"),
    )


async def dispatch(
    request_id: str,
    identity: Identity,
    *,
    n: int,
    jitter_ms: int,
    target_url: str,
    scope_rules: list[str] | None,
) -> list[CopyOutcome]:
    """Fan out exactly ``n`` copies of ``request_id`` sharing one P1 identity.

    The scope gate runs **before** any network request is dispatched. An
    out-of-scope target raises :class:`ScopedRefusal` with zero copies sent.
    """
    bounded_n, bounded_jitter = _guard_bounds(n, jitter_ms)

    if not host_in_scope(target_url, scope_rules):
        raise ScopedRefusal(
            target_url=target_url,
            scope_rules=scope_rules,
            reason="target is outside the configured scope rules",
        )

    tasks = [
        asyncio.create_task(_copy_with_jitter(i, request_id, identity, bounded_jitter))
        for i in range(bounded_n)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    outcomes: list[CopyOutcome] = []
    for i, raw in enumerate(results):
        if isinstance(raw, CopyOutcome):
            outcomes.append(raw)
        else:
            error = str(raw) if isinstance(raw, Exception) else f"Non-exception result: {raw}"
            outcomes.append(
                CopyOutcome(
                    copy_index=i,
                    status="ERROR",
                    error=error,
                    elapsed_ms=0,
                    response=None,
                    session_id=None,
                )
            )

    return outcomes

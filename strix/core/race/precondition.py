"""Precondition + reset manager, backed by the Phase 1 identity store."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from strix.core.identity.replay import replay_as_identity


if TYPE_CHECKING:
    from strix.core.identity.models import Identity
    from strix.core.race.models import Precondition


class PreconditionError(Exception):
    """Raised when the target cannot be driven to the declared precondition."""


async def _send_as_identity(
    request_id: str,
    identity: Identity,
    modifications: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Replay a request as the supplied identity and return the parsed response."""
    result = await replay_as_identity(request_id, identity, modifications=modifications)
    if not result.get("success"):
        return None
    return result.get("response")


async def setup_precondition(
    precondition: Precondition,
    identity: Identity,
) -> dict[str, Any] | None:
    """Drive the target to the declared precondition and return the baseline read.

    Returns ``None`` when the setup request itself fails or the baseline read
    cannot be parsed. This is intentionally **inconclusive** (never ``safe``,
    never dropped) because the harness cannot race from an unknown state.
    """
    setup_response = await _send_as_identity(precondition.setup_request_id, identity)
    if setup_response is None:
        return None

    return await _send_as_identity(precondition.state_read_request_id, identity)


async def reset_precondition(
    precondition: Precondition,
    identity: Identity,
) -> dict[str, Any] | None:
    """Return the target to the declared precondition between trials/retries.

    Returns the parsed response from the setup request, or ``None`` if the
    reset could not be confirmed.
    """
    return await _send_as_identity(precondition.setup_request_id, identity)

"""Execution context protocol for business-logic violation tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable


if TYPE_CHECKING:
    from strix.core.diff.models import DiffResult
    from strix.core.race.models import Precondition, RaceResult


@runtime_checkable
class ExecutionContext(Protocol):
    """Boundary through which violation tests invoke the underlying primitives.

    Concrete implementations may be real (wiring P1/P2/P3/P4) or mock (for
    deterministic fixture-based tests). The catalog never imports the primitives
    directly; it operates only through this context.
    """

    async def replay(
        self,
        request_id: str,
        role: str,
        modifications: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Replay a captured request as the given role, optionally modified."""
        ...

    def diff(self, responses: list[dict[str, Any]]) -> DiffResult:
        """Run the P2 differential engine over labeled responses."""
        ...

    async def race_harness(
        self,
        request_id: str,
        precondition: Precondition,
        role: str,
        n: int = 3,
        jitter_ms: int = 0,
    ) -> RaceResult:
        """Delegate a concurrent double-spend test to the Phase-4 race harness."""
        ...

    async def mint_oob(self, engagement_id: str) -> str:
        """Mint an OOB token and return its injectable host."""
        ...

    async def poll_oob(self, engagement_id: str, token: str) -> list[dict[str, Any]]:
        """Poll OOB callbacks correlated with the engagement."""
        ...

    async def view(self, request_id: str) -> dict[str, Any]:
        """Return the raw captured request components (method, url_path, headers, body)."""
        ...


async def record_replay(
    ctx: ExecutionContext,
    request_id: str,
    role: str,
    modifications: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay a request and return the parsed response."""
    return await ctx.replay(request_id, role, modifications=modifications)

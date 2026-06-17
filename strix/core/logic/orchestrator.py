"""Real execution context + orchestrator for business-logic violation tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from strix.core.diff import diff as _diff
from strix.core.identity import IdentityStore, identity_store_path
from strix.core.logic.catalog import run_violation_test
from strix.core.logic.gate import evaluate
from strix.core.logic.models import (
    BusinessLogicModel,
    ConfirmedViolation,
    ExecutedSequence,
    FlowModel,
    InvariantKind,
    UnconfirmedHypothesis,
)
from strix.core.logic.store import BusinessLogicStore
from strix.core.paths import logic_model_path


if TYPE_CHECKING:
    from pathlib import Path

    from strix.core.diff.models import DiffResult
    from strix.core.logic.context import ExecutionContext
    from strix.core.race.models import Precondition, RaceResult


class RealExecutionContext:
    """Wires the Phase-5 catalog to the corrected P1/P2/P3/P4 primitives."""

    def __init__(
        self,
        run_dir: Path,
        target_id: str,
        target_url: str,
        scope_rules: list[str] | None = None,
    ) -> None:
        self.run_dir = run_dir
        self.target_id = target_id
        self.target_url = target_url
        self.scope_rules = scope_rules

    async def replay(
        self,
        request_id: str,
        role: str,
        modifications: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Replay a captured request as the identity stored for ``role``."""
        from strix.core.identity.replay import replay_as_identity  # noqa: PLC0415

        store = IdentityStore(identity_store_path(self.run_dir))
        identity = store.get_identity(self.target_id, role)
        if identity is None:
            return {
                "success": False,
                "error": f"no identity for role {role} on target {self.target_id}",
                "response": None,
            }
        result = await replay_as_identity(request_id, identity, modifications=modifications)
        # The catalog expects the parsed response payload, not the wrapper dict.
        return result.get("response", result)  # type: ignore[no-any-return]

    async def view(self, request_id: str) -> dict[str, Any]:
        """Return the raw captured request components."""
        from strix.tools.proxy import caido_api  # noqa: PLC0415

        result = await caido_api.view_request(request_id, part="request")
        if result is None or not result.request or not result.request.raw:
            raise ValueError(f"Request {request_id} not found or has no raw request")

        raw_str = result.request.raw.decode("utf-8", errors="replace")
        return caido_api.parse_raw_request(raw_str)

    def diff(self, responses: list[dict[str, Any]]) -> DiffResult:
        """Run the P2 differential engine over labeled responses."""
        labeled = [{"label": str(i), "response": r} for i, r in enumerate(responses)]
        return _diff(labeled)

    async def race_harness(
        self,
        request_id: str,
        precondition: Precondition,
        role: str,
        n: int = 3,
        jitter_ms: int = 0,
    ) -> RaceResult:
        """Delegate a concurrent double-spend test to the Phase-4 race harness."""
        from strix.core.race.harness import run_race_harness  # noqa: PLC0415

        store = IdentityStore(identity_store_path(self.run_dir))
        identity = store.get_identity(self.target_id, role)
        if identity is None:
            raise RuntimeError(f"no identity for role {role} on target {self.target_id}")
        return await run_race_harness(
            request_id=request_id,
            precondition=precondition,
            identity=identity,
            target_url=self.target_url,
            scope_rules=self.scope_rules,
            n=n,
            jitter_ms=jitter_ms,
            retry_bound=1,
        )

    async def mint_oob(self, engagement_id: str) -> str:  # noqa: ARG002
        """Mint an OOB token."""
        return ""

    async def poll_oob(
        self,
        engagement_id: str,  # noqa: ARG002
        token: str,  # noqa: ARG002
    ) -> list[dict[str, Any]]:
        """Poll OOB callbacks."""
        return []


class BusinessLogicOrchestrator:
    """Run a business-logic violation test and apply the evidence gate."""

    def __init__(
        self,
        run_dir: Path,
        target_id: str,
        target_url: str,
        scope_rules: list[str] | None = None,
    ) -> None:
        self.run_dir = run_dir
        self.target_id = target_id
        self.target_url = target_url
        self.scope_rules = scope_rules

    async def run(
        self,
        engagement_id: str,
        flow_name: str,
        kind: InvariantKind,
        ctx: ExecutionContext | None = None,
    ) -> ConfirmedViolation | UnconfirmedHypothesis:
        """Run the violation test for a flow and return a gated result."""
        model_store = BusinessLogicStore(logic_model_path(self.run_dir, engagement_id))
        model = model_store.load(engagement_id)
        if model is None:
            return UnconfirmedHypothesis(
                flow_name=flow_name,
                invariant_kind=kind,
                reason="no business-logic model found for engagement",
            )

        flow = model.flows.get(flow_name)
        if flow is None:
            return UnconfirmedHypothesis(
                flow_name=flow_name,
                invariant_kind=kind,
                reason="flow not found in model",
            )

        if kind not in flow.bound_invariants:
            return UnconfirmedHypothesis(
                flow_name=flow_name,
                invariant_kind=kind,
                reason="invariant kind not bound to this flow",
            )

        ctx = ctx or RealExecutionContext(
            self.run_dir,
            self.target_id,
            self.target_url,
            self.scope_rules,
        )
        candidate = await run_violation_test(kind, flow, model, ctx)

        async def _reproduce(sequence: ExecutedSequence) -> bool:
            return await self.reproduce(flow, kind, model, ctx, sequence)

        return await evaluate(candidate, reproduce=_reproduce)

    async def reproduce(
        self,
        flow: FlowModel,
        kind: InvariantKind,
        model: BusinessLogicModel,
        ctx: ExecutionContext,
        _sequence: ExecutedSequence,
    ) -> bool:
        """Re-run the violation test and confirm the same impossible state is reached."""
        rerun = await run_violation_test(kind, flow, model, ctx)
        return rerun.reached_impossible_state

"""Tier-1 tests for the business-logic orchestrator."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any
from unittest import IsolatedAsyncioTestCase

from strix.core.logic import BusinessLogicOrchestrator
from strix.core.logic.context import ExecutionContext
from strix.core.logic.models import (
    BusinessLogicModel,
    ConfirmedViolation,
    FlowModel,
    JourneyModel,
    Step,
    UnconfirmedHypothesis,
)
from strix.core.logic.store import BusinessLogicStore
from strix.core.paths import logic_model_path


class _MockContext(ExecutionContext):
    """In-memory execution context that injects a synthetic diff artifact."""

    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    async def replay(
        self,
        request_id: str,
        role: str,
        modifications: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.calls.append((request_id, role, modifications))
        return self.response

    def diff(self, responses: list[dict[str, Any]]) -> Any:
        return responses

    async def race_harness(
        self,
        request_id: str,  # noqa: ARG002
        precondition: Any,  # noqa: ARG002
        role: str,  # noqa: ARG002
        n: int = 3,  # noqa: ARG002
        jitter_ms: int = 0,  # noqa: ARG002
    ) -> Any:
        return {}

    async def mint_oob(self, engagement_id: str) -> str:  # noqa: ARG002
        return "token.example.com"

    async def poll_oob(
        self,
        engagement_id: str,  # noqa: ARG002
        token: str,  # noqa: ARG002
    ) -> list[dict[str, Any]]:
        return []

    async def view(self, request_id: str) -> dict[str, Any]:  # noqa: ARG002
        return {"method": "GET", "url_path": "/", "headers": {}, "body": ""}


class _FlakyMockContext(ExecutionContext):
    """Succeeds once, then denies, so the violation does not reproduce."""

    def __init__(self, success: dict[str, Any], denied: dict[str, Any]) -> None:
        self.success = success
        self.denied = denied
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []
        self._count = 0

    async def replay(
        self,
        request_id: str,
        role: str,
        modifications: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.calls.append((request_id, role, modifications))
        self._count += 1
        return self.success if self._count == 1 else self.denied

    def diff(self, responses: list[dict[str, Any]]) -> Any:
        return responses

    async def race_harness(
        self,
        request_id: str,  # noqa: ARG002
        precondition: Any,  # noqa: ARG002
        role: str,  # noqa: ARG002
        n: int = 3,  # noqa: ARG002
        jitter_ms: int = 0,  # noqa: ARG002
    ) -> Any:
        return {}

    async def mint_oob(self, engagement_id: str) -> str:  # noqa: ARG002
        return "token.example.com"

    async def poll_oob(
        self,
        engagement_id: str,  # noqa: ARG002
        token: str,  # noqa: ARG002
    ) -> list[dict[str, Any]]:
        return []

    async def view(self, request_id: str) -> dict[str, Any]:  # noqa: ARG002
        return {"method": "GET", "url_path": "/", "headers": {}, "body": ""}


class TestBusinessLogicOrchestrator(IsolatedAsyncioTestCase):
    """Tests for the orchestrator that wires model -> catalog -> gate."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name)
        self.target_id = "example.com"
        self.target_url = "https://example.com"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _store_model(self, model: BusinessLogicModel) -> None:
        with BusinessLogicStore(
            db_path=logic_model_path(self.run_dir, model.engagement_id)
        ) as store:
            store.save(model)

    def _model(self, flow: FlowModel) -> BusinessLogicModel:
        return BusinessLogicModel(
            engagement_id="eng-1",
            target_id=self.target_id,
            flows={flow.name: flow},
        )

    async def test_returns_unconfirmed_when_model_missing(self) -> None:
        orch = BusinessLogicOrchestrator(self.run_dir, self.target_id, self.target_url)
        result = await orch.run("eng-1", "checkout", "step-skip")
        self.assertIsInstance(result, UnconfirmedHypothesis)
        assert isinstance(result, UnconfirmedHypothesis)
        self.assertEqual(result.reason, "no business-logic model found for engagement")

    async def test_returns_unconfirmed_when_flow_missing(self) -> None:
        model = BusinessLogicModel(engagement_id="eng-1", target_id=self.target_id)
        self._store_model(model)
        orch = BusinessLogicOrchestrator(self.run_dir, self.target_id, self.target_url)
        result = await orch.run("eng-1", "checkout", "step-skip")
        self.assertIsInstance(result, UnconfirmedHypothesis)
        assert isinstance(result, UnconfirmedHypothesis)
        self.assertEqual(result.reason, "flow not found in model")

    async def test_returns_unconfirmed_when_invariant_not_bound(self) -> None:
        flow = FlowModel(
            name="checkout",
            flow_name="coupon",
            request_id="coupon-req",
        )
        self._store_model(self._model(flow))
        orch = BusinessLogicOrchestrator(self.run_dir, self.target_id, self.target_url)
        result = await orch.run("eng-1", "checkout", "step-skip")
        self.assertIsInstance(result, UnconfirmedHypothesis)
        assert isinstance(result, UnconfirmedHypothesis)
        self.assertEqual(result.reason, "invariant kind not bound to this flow")

    async def test_confirms_step_skip_with_artifact(self) -> None:
        flow = FlowModel(
            name="checkout",
            flow_name="coupon",
            request_id="coupon-req",
            bound_invariants=["step-skip"],
            journey=JourneyModel(
                name="checkout",
                steps=[
                    Step(name="cart", order=0, request_id="cart-req"),
                    Step(
                        name="payment",
                        order=1,
                        request_id="payment-req",
                        depends_on=["cart"],
                    ),
                ],
            ),
        )
        self._store_model(self._model(flow))
        ctx = _MockContext(response={"status_code": 200, "body": "paid"})
        orch = BusinessLogicOrchestrator(self.run_dir, self.target_id, self.target_url)

        result = await orch.run("eng-1", "checkout", "step-skip", ctx=ctx)

        self.assertIsInstance(result, ConfirmedViolation)
        assert isinstance(result, ConfirmedViolation)
        self.assertEqual(result.flow_name, "checkout")
        self.assertEqual(len(ctx.calls), 2)

    async def test_successful_response_without_impossible_state_is_unconfirmed(self) -> None:
        # Confirmation-bias guard: a successful response is not enough; the model must
        # declare the reached state impossible. A step with no dependencies is allowed.
        flow = FlowModel(
            name="checkout",
            flow_name="coupon",
            request_id="coupon-req",
            bound_invariants=["step-skip"],
            journey=JourneyModel(
                name="checkout",
                steps=[
                    Step(name="cart", order=0, request_id="cart-req"),
                ],
            ),
        )
        self._store_model(self._model(flow))
        ctx = _MockContext(response={"status_code": 200, "body": "ok"})
        orch = BusinessLogicOrchestrator(self.run_dir, self.target_id, self.target_url)

        result = await orch.run("eng-1", "checkout", "step-skip", ctx=ctx)

        self.assertIsInstance(result, UnconfirmedHypothesis)
        assert isinstance(result, UnconfirmedHypothesis)
        self.assertEqual(result.reason, "executed sequence did not reach a model-impossible state")

    async def test_rejects_non_reproducing_violation(self) -> None:
        flow = FlowModel(
            name="checkout",
            flow_name="coupon",
            request_id="coupon-req",
            bound_invariants=["step-skip"],
            journey=JourneyModel(
                name="checkout",
                steps=[
                    Step(name="cart", order=0, request_id="cart-req"),
                    Step(
                        name="payment",
                        order=1,
                        request_id="payment-req",
                        depends_on=["cart"],
                    ),
                ],
            ),
        )
        self._store_model(self._model(flow))
        ctx = _FlakyMockContext(
            success={"status_code": 200, "body": "paid"},
            denied={"status_code": 403, "body": "denied"},
        )
        orch = BusinessLogicOrchestrator(self.run_dir, self.target_id, self.target_url)

        result = await orch.run("eng-1", "checkout", "step-skip", ctx=ctx)

        self.assertIsInstance(result, UnconfirmedHypothesis)
        assert isinstance(result, UnconfirmedHypothesis)
        self.assertEqual(result.reason, "violation did not reproduce on re-run")

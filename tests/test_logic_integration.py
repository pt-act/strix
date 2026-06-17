"""Hermetic integration tests for Phase-5 business-logic composition.

These tests exercise the real catalog + orchestrator + evidence gate against an
in-memory mock of the ``benchmarks/business_logic_fixture`` target. They use a
custom ``ExecutionContext`` so the composition runs without a live proxy, Docker
container, or Caido boundary.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any
from unittest import IsolatedAsyncioTestCase

from strix.core.diff import diff as _diff
from strix.core.diff.models import DiffResult, SemanticDelta
from strix.core.logic.context import ExecutionContext
from strix.core.logic.models import (
    BusinessLogicModel,
    ConfirmedViolation,
    FlowModel,
    JourneyModel,
    MonetaryOperation,
    MonetaryRelation,
    Step,
    UnconfirmedHypothesis,
)
from strix.core.logic.orchestrator import BusinessLogicOrchestrator
from strix.core.logic.store import BusinessLogicStore
from strix.core.paths import logic_model_path
from strix.core.race.models import CopyOutcome, Precondition, RaceResult, ScopeDecision, StateDelta
from strix.core.race.verdict import verdict as _verdict


class _FixtureMockTarget:
    """In-memory mock of the dockerized business-logic fixture."""

    def __init__(self, vuln_mode: str | None) -> None:
        self.vuln_mode = vuln_mode
        self.reset()

    def reset(self) -> None:
        self.redeemed = False
        self.redeem_count = 0
        self.balance = 100

    def read_state(self) -> dict[str, Any]:
        return {
            "status_code": 200,
            "body": json.dumps({"redeem_count": self.redeem_count, "balance": self.balance}),
        }

    def redeem(self) -> dict[str, Any]:
        if self.vuln_mode == "double_spend":
            # No locking: every concurrent copy commits.
            self.redeem_count += 1
            self.balance -= 10
            return {
                "status_code": 200,
                "body": json.dumps({"status": "redeemed", "balance": self.balance}),
            }

        # Patched mode: single commit, then rejected.
        if self.redeemed:
            return {"status_code": 409, "body": json.dumps({"status": "already_used"})}
        self.redeemed = True
        self.redeem_count = 1
        self.balance -= 10
        return {
            "status_code": 200,
            "body": json.dumps({"status": "redeemed", "balance": self.balance}),
        }

    def checkout(self, payload: dict[str, Any]) -> dict[str, Any]:
        price = payload.get("price", 0)
        quantity = payload.get("quantity", 1)
        total = payload.get("total", price * quantity)
        expected = price * quantity

        if self.vuln_mode == "price_mismatch":
            # Vulnerable: computes the charged total from the tampered price but
            # accepts the request anyway, so the client sees a wrong total.
            return {"status_code": 200, "body": json.dumps({"status": "paid", "total": expected})}

        if total != expected:
            return {
                "status_code": 400,
                "body": json.dumps({"status": "rejected", "total": expected}),
            }
        return {"status_code": 200, "body": json.dumps({"status": "paid", "total": expected})}


class _MockContext(ExecutionContext):
    """Execution context that routes the catalog to the in-memory mock target."""

    def __init__(self, target: _FixtureMockTarget) -> None:
        self.target = target
        self.requests: dict[str, dict[str, Any]] = {
            "reset-req": {"method": "POST", "url_path": "/reset", "headers": {}, "body": ""},
            "state-req": {"method": "GET", "url_path": "/state", "headers": {}, "body": ""},
            "redeem-req": {
                "method": "POST",
                "url_path": "/redeem",
                "headers": {"Content-Type": "application/json"},
                "body": '{"coupon": "COUPON-1"}',
            },
            "checkout-req": {
                "method": "POST",
                "url_path": "/checkout",
                "headers": {"Content-Type": "application/json"},
                "body": '{"price": 5, "quantity": 1, "total": 5}',
            },
        }

    async def replay(
        self,
        request_id: str,
        role: str,
        modifications: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _ = role
        path = {
            "reset-req": "/reset",
            "state-req": "/state",
            "redeem-req": "/redeem",
            "checkout-req": "/checkout",
        }.get(request_id, "/")

        if path == "/reset":
            self.target.reset()
            return {"status_code": 200, "body": "reset"}
        if path == "/state":
            return self.target.read_state()
        if path == "/redeem":
            return self.target.redeem()
        if path == "/checkout":
            body = self.requests["checkout-req"]["body"]
            if modifications and "body" in modifications:
                body = modifications["body"]
            payload: dict[str, Any] = json.loads(body) if body else {}
            return self.target.checkout(payload)
        return {"success": False, "error": "unknown request_id"}

    def diff(self, responses: list[dict[str, Any]]) -> DiffResult:
        labeled = [{"label": str(i), "response": r} for i, r in enumerate(responses)]
        return _diff(labeled)

    async def view(self, request_id: str) -> dict[str, Any]:
        return self.requests.get(request_id, {})

    async def race_harness(
        self,
        request_id: str,
        precondition: Precondition,
        role: str,
        n: int = 3,
        jitter_ms: int = 0,
    ) -> RaceResult:
        _ = request_id, role, jitter_ms
        """Simplified race harness over the mock target."""
        self.target.reset()
        baseline = self.target.read_state()
        outcomes: list[CopyOutcome] = []
        for i in range(n):
            response = self.target.redeem()
            outcomes.append(
                CopyOutcome(
                    copy_index=i,
                    status="DONE",
                    error=None,
                    elapsed_ms=1,
                    response=response,
                    session_id=f"s-{i}",
                )
            )
        post_action = self.target.read_state()
        diff_result = _diff(
            [
                {"label": "baseline", "response": baseline},
                {"label": "post", "response": post_action},
            ]
        )
        semantic_delta = (
            diff_result.deltas[0]
            if diff_result.deltas
            else SemanticDelta(
                pair=("baseline", "post"),
                status_class_delta=None,
                body_structure_delta="same",
                normalized_length_delta=0,
                normalized=False,
            )
        )
        state_delta = StateDelta(
            baseline=baseline,
            post_action=post_action,
            semantic_delta=semantic_delta,
            observable=True,
        )
        commit_count = self.target.redeem_count
        verdict_result = _verdict(state_delta, commit_count)
        return RaceResult(
            success=True,
            verdict=verdict_result,
            commit_count=commit_count,
            retry_count=0,
            state_delta=state_delta,
            outcomes=outcomes,
            scope_decision=ScopeDecision(
                target_url="http://example.com",
                scope_rules=["example.com"],
                in_scope=True,
                reason="mock scope",
            ),
            precondition=precondition,
            n=n,
            jitter_ms=0,
        )

    async def mint_oob(self, engagement_id: str) -> str:
        _ = engagement_id
        return ""

    async def poll_oob(
        self,
        engagement_id: str,
        token: str,
    ) -> list[dict[str, Any]]:
        _ = engagement_id, token
        return []


class _IntegrationTestCase(IsolatedAsyncioTestCase):
    """Base that stores the model and drives the orchestrator with a mock context."""

    vuln_mode: str | None = None

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name)
        self.target_id = "example.com"
        self.target_url = "http://example.com"
        self.target = _FixtureMockTarget(vuln_mode=self.vuln_mode)
        self.ctx = _MockContext(self.target)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _store_model(self, model: BusinessLogicModel) -> None:
        with BusinessLogicStore(logic_model_path(self.run_dir, model.engagement_id)) as store:
            store.save(model)

    def _orchestrator(self) -> BusinessLogicOrchestrator:
        return BusinessLogicOrchestrator(
            run_dir=self.run_dir,
            target_id=self.target_id,
            target_url=self.target_url,
            scope_rules=["example.com"],
        )


class TestDoubleSpendVuln(_IntegrationTestCase):
    """TP: the vulnerable fixture allows a coupon to be redeemed concurrently."""

    vuln_mode = "double_spend"

    async def test_double_spend_confirmed_on_vuln_target(self) -> None:
        flow = FlowModel(
            name="coupon_flow",
            flow_name="coupon",
            request_id="redeem-req",
            monetary_op=MonetaryOperation(
                name="coupon_redeem",
                request_id="redeem-req",
                setup_request_id="reset-req",
                state_read_request_id="state-req",
                relation=MonetaryRelation(
                    state_counter="redeem_count",
                    commit_unit=1,
                ),
                one_time=True,
            ),
            journey=JourneyModel(
                name="redeem",
                steps=[Step(name="redeem", order=0, request_id="redeem-req")],
            ),
            bound_invariants=["double-spend"],
        )
        model = BusinessLogicModel(
            engagement_id="eng-1",
            target_id=self.target_id,
            flows={"coupon_flow": flow},
        )
        self._store_model(model)

        result = await self._orchestrator().run(
            "eng-1", "coupon_flow", "double-spend", ctx=self.ctx
        )

        self.assertIsInstance(result, ConfirmedViolation)
        assert isinstance(result, ConfirmedViolation)
        self.assertEqual(result.invariant_kind, "double-spend")
        self.assertEqual(result.executed_sequence.artifact_type, "race_result")


class TestDoubleSpendPatch(_IntegrationTestCase):
    """TN: the patched fixture rejects concurrent redemption; gate stays silent."""

    vuln_mode = None

    async def test_double_spend_unconfirmed_on_patched_target(self) -> None:
        flow = FlowModel(
            name="coupon_flow",
            flow_name="coupon",
            request_id="redeem-req",
            monetary_op=MonetaryOperation(
                name="coupon_redeem",
                request_id="redeem-req",
                setup_request_id="reset-req",
                state_read_request_id="state-req",
                relation=MonetaryRelation(
                    state_counter="redeem_count",
                    commit_unit=1,
                ),
                one_time=True,
            ),
            journey=JourneyModel(
                name="redeem",
                steps=[Step(name="redeem", order=0, request_id="redeem-req")],
            ),
            bound_invariants=["double-spend"],
        )
        model = BusinessLogicModel(
            engagement_id="eng-1",
            target_id=self.target_id,
            flows={"coupon_flow": flow},
        )
        self._store_model(model)

        result = await self._orchestrator().run(
            "eng-1", "coupon_flow", "double-spend", ctx=self.ctx
        )

        self.assertIsInstance(result, UnconfirmedHypothesis)


class TestPriceMismatchVuln(_IntegrationTestCase):
    """TP: the vulnerable fixture charges a tampered client total."""

    vuln_mode = "price_mismatch"

    async def test_price_mismatch_confirmed_on_vuln_target(self) -> None:
        flow = FlowModel(
            name="checkout",
            flow_name="coupon",
            request_id="checkout-req",
            monetary_op=MonetaryOperation(
                name="checkout",
                request_id="checkout-req",
                relation=MonetaryRelation(
                    price_param="price",
                    quantity_param="quantity",
                    total_param="total",
                    baseline_values={"price": 5, "quantity": 1, "total": 5},
                    tamper_values={"price": 0, "quantity": 1, "total": 5},
                ),
            ),
            journey=JourneyModel(
                name="checkout",
                steps=[Step(name="checkout", order=0, request_id="checkout-req")],
            ),
            bound_invariants=["price-mismatch"],
        )
        model = BusinessLogicModel(
            engagement_id="eng-1",
            target_id=self.target_id,
            flows={"checkout": flow},
        )
        self._store_model(model)

        result = await self._orchestrator().run("eng-1", "checkout", "price-mismatch", ctx=self.ctx)

        self.assertIsInstance(result, ConfirmedViolation)
        assert isinstance(result, ConfirmedViolation)
        self.assertEqual(result.invariant_kind, "price-mismatch")
        self.assertEqual(result.executed_sequence.artifact_type, "diff")


class TestPriceMismatchPatch(_IntegrationTestCase):
    """TN: the patched fixture rejects the tampered total; gate stays silent."""

    vuln_mode = None

    async def test_price_mismatch_unconfirmed_on_patched_target(self) -> None:
        flow = FlowModel(
            name="checkout",
            flow_name="coupon",
            request_id="checkout-req",
            monetary_op=MonetaryOperation(
                name="checkout",
                request_id="checkout-req",
                relation=MonetaryRelation(
                    price_param="price",
                    quantity_param="quantity",
                    total_param="total",
                    baseline_values={"price": 5, "quantity": 1, "total": 5},
                    tamper_values={"price": 0, "quantity": 1, "total": 5},
                ),
            ),
            journey=JourneyModel(
                name="checkout",
                steps=[Step(name="checkout", order=0, request_id="checkout-req")],
            ),
            bound_invariants=["price-mismatch"],
        )
        model = BusinessLogicModel(
            engagement_id="eng-1",
            target_id=self.target_id,
            flows={"checkout": flow},
        )
        self._store_model(model)

        result = await self._orchestrator().run("eng-1", "checkout", "price-mismatch", ctx=self.ctx)

        self.assertIsInstance(result, UnconfirmedHypothesis)

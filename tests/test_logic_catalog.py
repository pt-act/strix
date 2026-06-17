"""Tier-1 tests for the business-logic invariant catalog."""

from __future__ import annotations

from typing import Any
from unittest import IsolatedAsyncioTestCase

from strix.core.diff.models import SemanticDelta
from strix.core.logic.catalog import (
    describe_invariant,
    list_invariant_kinds,
    run_violation_test,
)
from strix.core.logic.context import ExecutionContext
from strix.core.logic.models import (
    BusinessLogicModel,
    FlowModel,
    JourneyModel,
    LifecycleModel,
    MonetaryOperation,
    MonetaryRelation,
    Step,
    Transition,
)
from strix.core.race.models import (
    CopyOutcome,
    Precondition,
    RaceResult,
    ScopeDecision,
    StateDelta,
)


class _MockContext(ExecutionContext):
    """In-memory execution context for deterministic catalog tests."""

    def __init__(
        self,
        responses: dict[str, dict[str, Any]] | None = None,
        views: dict[str, dict[str, Any]] | None = None,
        race_harness_results: dict[str, Any] | None = None,
    ) -> None:
        self.responses = responses or {}
        self.views = views or {}
        self.race_harness_results = race_harness_results or {}
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    async def replay(
        self,
        request_id: str,
        role: str,
        modifications: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.calls.append((request_id, role, modifications))
        return self.responses.get(request_id, {"status_code": 403, "body": "denied"})

    def diff(self, responses: list[dict[str, Any]]) -> Any:
        return responses

    async def race_harness(
        self,
        request_id: str,
        precondition: Any,  # noqa: ARG002
        role: str,  # noqa: ARG002
        n: int = 3,  # noqa: ARG002
        jitter_ms: int = 0,  # noqa: ARG002
    ) -> Any:
        return self.race_harness_results.get(request_id, {})

    async def mint_oob(self, engagement_id: str) -> str:  # noqa: ARG002
        return "token.example.com"

    async def poll_oob(
        self,
        engagement_id: str,  # noqa: ARG002
        token: str,  # noqa: ARG002
    ) -> list[dict[str, Any]]:
        return []

    async def view(self, request_id: str) -> dict[str, Any]:
        if request_id not in self.views:
            raise ValueError(f"no view for {request_id}")
        return self.views[request_id]


class TestInvariantCatalog(IsolatedAsyncioTestCase):
    """Focused tests for the fixed invariant catalog and violation tests."""

    def test_catalog_is_fixed_enumerable(self) -> None:
        kinds = list_invariant_kinds()
        self.assertEqual(
            sorted(kinds),
            sorted(
                [
                    "step-skip",
                    "replay",
                    "double-spend",
                    "price-mismatch",
                    "unauthorized-state-change",
                ]
            ),
        )
        self.assertIn("Reach a journey step", describe_invariant("step-skip"))

    async def test_step_skip_flags_reached_impossible_state(self) -> None:
        flow = FlowModel(
            name="checkout",
            flow_name="coupon",
            request_id="coupon-req",
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
        model = BusinessLogicModel(engagement_id="eng-1", target_id="example.com")
        ctx = _MockContext(responses={"payment-req": {"status_code": 200, "body": "paid"}})

        candidate = await run_violation_test("step-skip", flow, model, ctx)

        self.assertTrue(candidate.reached_impossible_state)
        self.assertEqual(candidate.sequence.steps[0].request_id, "payment-req")
        self.assertEqual(ctx.calls, [("payment-req", "user", None)])
        self.assertEqual(candidate.sequence.artifact_type, "diff")
        self.assertIsNotNone(candidate.sequence.artifact)

    async def test_step_skip_does_not_flag_when_step_denied(self) -> None:
        flow = FlowModel(
            name="checkout",
            flow_name="coupon",
            request_id="coupon-req",
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
        model = BusinessLogicModel(engagement_id="eng-1", target_id="example.com")
        ctx = _MockContext(responses={"payment-req": {"status_code": 403, "body": "denied"}})

        candidate = await run_violation_test("step-skip", flow, model, ctx)

        self.assertFalse(candidate.reached_impossible_state)
        self.assertIsNone(candidate.sequence.artifact)

    async def test_replay_flags_second_success(self) -> None:
        flow = FlowModel(
            name="coupon_flow",
            flow_name="coupon",
            request_id="coupon-req",
        )
        model = BusinessLogicModel(engagement_id="eng-1", target_id="example.com")
        ctx = _MockContext(
            responses={
                "coupon-req": {"status_code": 200, "body": "redeemed"},
            }
        )

        candidate = await run_violation_test("replay", flow, model, ctx)

        self.assertTrue(candidate.reached_impossible_state)
        self.assertEqual(len(candidate.sequence.steps), 2)
        self.assertEqual(ctx.calls, [("coupon-req", "user", None), ("coupon-req", "user", None)])
        self.assertEqual(candidate.sequence.artifact_type, "diff")

    async def test_unauthorized_transition_flags_success(self) -> None:
        flow = FlowModel(
            name="admin_flow",
            flow_name="approval",
            request_id="approve-req",
            lifecycle=LifecycleModel(
                name="order",
                object_type="order",
                states=["pending", "approved"],
                transitions=[
                    Transition(
                        from_state="pending",
                        to_state="approved",
                        request_id="approve-req",
                        allowed_roles=["admin"],
                    ),
                ],
            ),
        )
        model = BusinessLogicModel(engagement_id="eng-1", target_id="example.com")
        ctx = _MockContext(
            responses={
                "approve-req": {"status_code": 200, "body": "approved"},
            }
        )

        candidate = await run_violation_test("unauthorized-state-change", flow, model, ctx)

        self.assertTrue(candidate.reached_impossible_state)
        self.assertEqual(candidate.sequence.steps[0].identity_role, "user")
        self.assertEqual(candidate.sequence.artifact_type, "diff")

    async def test_double_spend_flags_race_verdict(self) -> None:
        """A race verdict from the Phase-4 harness becomes a double-spend candidate."""
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
        )
        model = BusinessLogicModel(engagement_id="eng-1", target_id="example.com")
        race_result = RaceResult(
            success=True,
            verdict="race",
            commit_count=2,
            retry_count=0,
            state_delta=StateDelta(
                baseline={"status_code": 200, "body": '{"redeem_count": 0}'},
                post_action={"status_code": 200, "body": '{"redeem_count": 2}'},
                semantic_delta=SemanticDelta(
                    pair=("baseline", "post"),
                    status_class_delta=None,
                    body_structure_delta="size_changed",
                    normalized_length_delta=1,
                    auth_signal_delta="none",
                    set_cookie_delta="none",
                    normalized=True,
                ),
            ),
            outcomes=[
                CopyOutcome(
                    copy_index=0,
                    status="DONE",
                    error=None,
                    elapsed_ms=5,
                    response={"status_code": 200, "body": "redeemed"},
                    session_id="s-1",
                ),
            ],
            scope_decision=ScopeDecision(
                target_url="https://example.com",
                scope_rules=["example.com"],
                in_scope=True,
                reason="dispatch allowed",
            ),
            precondition=Precondition(
                description="coupon unredeemed",
                setup_request_id="reset-req",
                state_read_request_id="state-req",
            ),
            n=3,
            jitter_ms=0,
        )
        ctx = _MockContext(race_harness_results={"redeem-req": race_result})

        candidate = await run_violation_test("double-spend", flow, model, ctx)

        self.assertTrue(candidate.reached_impossible_state)
        self.assertEqual(candidate.sequence.artifact_type, "race_result")
        self.assertEqual(candidate.sequence.artifact.verdict, "race")

    async def test_price_mismatch_flags_mismatched_total(self) -> None:
        """Tamper price and observe a charged total that contradicts the model."""
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
        )
        model = BusinessLogicModel(engagement_id="eng-1", target_id="example.com")
        ctx = _MockContext(
            views={
                "checkout-req": {
                    "method": "POST",
                    "url_path": "/checkout",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"price": 5, "quantity": 1, "total": 5}',
                },
            },
            responses={
                "checkout-req": {
                    "status_code": 200,
                    "body": '{"total": 0, "status": "paid"}',
                },
            },
        )

        candidate = await run_violation_test("price-mismatch", flow, model, ctx)

        self.assertTrue(candidate.reached_impossible_state)
        self.assertEqual(candidate.sequence.artifact_type, "diff")

    async def test_price_mismatch_no_flag_when_total_matches(self) -> None:
        """A patched server that charges the expected total stays unconfirmed."""
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
        )
        model = BusinessLogicModel(engagement_id="eng-1", target_id="example.com")
        ctx = _MockContext(
            views={
                "checkout-req": {
                    "method": "POST",
                    "url_path": "/checkout",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"price": 5, "quantity": 1, "total": 5}',
                },
            },
            responses={
                "checkout-req": {
                    "status_code": 200,
                    "body": '{"total": 5, "status": "paid"}',
                },
            },
        )

        candidate = await run_violation_test("price-mismatch", flow, model, ctx)

        self.assertFalse(candidate.reached_impossible_state)
        self.assertIsNone(candidate.sequence.artifact)

    async def test_double_spend_no_flag_without_monetary_op(self) -> None:
        flow = FlowModel(
            name="checkout",
            flow_name="coupon",
            request_id="checkout-req",
        )
        model = BusinessLogicModel(engagement_id="eng-1", target_id="example.com")
        ctx = _MockContext()

        candidate = await run_violation_test("double-spend", flow, model, ctx)

        self.assertFalse(candidate.reached_impossible_state)
        self.assertIsNone(candidate.sequence.artifact)

    async def test_price_mismatch_no_flag_without_tamper_values(self) -> None:
        flow = FlowModel(
            name="checkout",
            flow_name="coupon",
            request_id="checkout-req",
            monetary_op=MonetaryOperation(
                name="checkout",
                request_id="checkout-req",
                relation=MonetaryRelation(
                    price_param="price",
                    total_param="total",
                ),
            ),
        )
        model = BusinessLogicModel(engagement_id="eng-1", target_id="example.com")
        ctx = _MockContext()

        candidate = await run_violation_test("price-mismatch", flow, model, ctx)

        self.assertFalse(candidate.reached_impossible_state)
        self.assertIsNone(candidate.sequence.artifact)

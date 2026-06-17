"""Tier-1 tests for the business-logic model intake + durable store."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import TestCase

from strix.core.logic.models import (
    BusinessLogicModel,
    FlowModel,
    JourneyModel,
    LifecycleModel,
    MonetaryOperation,
    MonetaryRelation,
    Step,
    Transition,
    TrustBoundary,
)
from strix.core.logic.store import BusinessLogicStore
from strix.core.paths import logic_model_path


class TestBusinessLogicModelShapes(TestCase):
    """Ensure every model element is tagged agent-proposed and serializable."""

    def _minimal_model(self) -> BusinessLogicModel:
        coupon = MonetaryOperation(
            name="coupon_redeem",
            request_id="coupon-redeem-req",
            relation=MonetaryRelation(
                amount_param="discount",
                state_counter="redeem_count",
                commit_unit=1,
            ),
            one_time=True,
        )
        return BusinessLogicModel(
            engagement_id="eng-1",
            target_id="example.com",
            monetary_operations={"coupon_redeem": coupon},
            journeys={
                "checkout": JourneyModel(
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
            },
            lifecycles={
                "order": LifecycleModel(
                    name="order_lifecycle",
                    object_type="order",
                    states=["pending", "paid", "shipped"],
                    transitions=[
                        Transition(from_state="pending", to_state="paid", request_id="pay-req"),
                    ],
                ),
            },
            trust_boundaries={
                "buyer": TrustBoundary(
                    name="buyer",
                    role="user",
                    allowed_step_names=["cart", "payment"],
                ),
            },
            flows={
                "coupon_flow": FlowModel(
                    name="coupon_flow",
                    flow_name="coupon",
                    request_id="coupon-redeem-req",
                    monetary_op=coupon,
                    bound_invariants=["replay", "double-spend"],
                ),
            },
        )

    def test_every_element_tagged_agent_proposed(self) -> None:
        model = self._minimal_model()
        self.assertEqual(model.source, "agent-proposed")
        self.assertEqual(model.journeys["checkout"].source, "agent-proposed")
        self.assertEqual(model.journeys["checkout"].steps[0].source, "agent-proposed")
        self.assertEqual(model.lifecycles["order"].source, "agent-proposed")
        self.assertEqual(
            model.lifecycles["order"].transitions[0].source,
            "agent-proposed",
        )
        self.assertEqual(model.trust_boundaries["buyer"].source, "agent-proposed")
        self.assertEqual(model.monetary_operations["coupon_redeem"].source, "agent-proposed")
        self.assertEqual(
            model.monetary_operations["coupon_redeem"].relation.source,
            "agent-proposed",
        )
        self.assertEqual(model.flows["coupon_flow"].source, "agent-proposed")

    def test_model_references_inventory_request_ids(self) -> None:
        model = self._minimal_model()
        self.assertEqual(model.journeys["checkout"].steps[0].request_id, "cart-req")
        self.assertEqual(
            model.lifecycles["order"].transitions[0].request_id,
            "pay-req",
        )
        self.assertEqual(model.monetary_operations["coupon_redeem"].request_id, "coupon-redeem-req")


class TestBusinessLogicStore(TestCase):
    """Ensure the model store is durable, per-engagement, and round-trips."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _store(self, engagement_id: str = "eng-1") -> BusinessLogicStore:
        return BusinessLogicStore(logic_model_path(self.run_dir, engagement_id))

    def test_save_and_load_round_trip(self) -> None:
        model = BusinessLogicModel(
            engagement_id="eng-1",
            target_id="example.com",
        )
        with self._store("eng-1") as store:
            store.save(model)
            loaded = store.load("eng-1")
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.engagement_id, "eng-1")
        self.assertEqual(loaded.target_id, "example.com")
        self.assertEqual(loaded.source, "agent-proposed")

    def test_store_survives_restart(self) -> None:
        model = BusinessLogicModel(
            engagement_id="eng-2",
            target_id="example.com",
            journeys={
                "checkout": JourneyModel(
                    name="checkout",
                    steps=[Step(name="cart", order=0, request_id="cart-req")],
                ),
            },
        )
        path = logic_model_path(self.run_dir, "eng-2")
        with BusinessLogicStore(path) as store:
            store.save(model)

        with BusinessLogicStore(path) as store:
            loaded = store.load("eng-2")

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertIn("checkout", loaded.journeys)

    def test_per_engagement_isolation(self) -> None:
        with self._store("eng-a") as store:
            store.save(
                BusinessLogicModel(engagement_id="eng-a", target_id="a.com"),
            )
        with self._store("eng-b") as store:
            store.save(
                BusinessLogicModel(engagement_id="eng-b", target_id="b.com"),
            )

        with self._store("eng-a") as store:
            loaded_a = store.load("eng-a")
        with self._store("eng-b") as store:
            loaded_b = store.load("eng-b")

        self.assertIsNotNone(loaded_a)
        self.assertIsNotNone(loaded_b)
        assert loaded_a is not None
        assert loaded_b is not None
        self.assertEqual(loaded_a.target_id, "a.com")
        self.assertEqual(loaded_b.target_id, "b.com")

        with self._store("eng-a") as store:
            self.assertIsNone(store.load("eng-b"))
        with self._store("eng-b") as store:
            self.assertIsNone(store.load("eng-a"))

    def test_merge_appends_keyed_collections(self) -> None:
        with self._store("eng-3") as store:
            store.save(
                BusinessLogicModel(
                    engagement_id="eng-3",
                    target_id="example.com",
                    journeys={
                        "checkout": JourneyModel(
                            name="checkout",
                            steps=[Step(name="cart", order=0, request_id="cart-req")],
                        ),
                    },
                ),
            )
            merged = store.merge(
                BusinessLogicModel(
                    engagement_id="eng-3",
                    target_id="example.com",
                    journeys={
                        "refund": JourneyModel(
                            name="refund",
                            steps=[Step(name="refund", order=0, request_id="refund-req")],
                        ),
                    },
                ),
            )

        self.assertIn("checkout", merged.journeys)
        self.assertIn("refund", merged.journeys)

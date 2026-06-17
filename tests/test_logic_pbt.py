"""Property-based tests for the business-logic evidence gate."""

from __future__ import annotations

import asyncio
from typing import Any, cast
from unittest import TestCase

from hypothesis import given
from hypothesis import strategies as st

from strix.core.logic.gate import evaluate
from strix.core.logic.models import (
    ConfirmedViolation,
    ExecutedSequence,
    ExecutedStep,
    UnconfirmedHypothesis,
    ViolationCandidate,
)


class TestEvidenceGatePBT(TestCase):
    """PBT invariants for the evidence gate."""

    @given(
        reached=st.booleans(),
        artifact_type=st.sampled_from(["diff", "callback", "race_result", None]),
        artifact_present=st.booleans(),
    )
    def test_gate_classification_invariant(
        self,
        reached: bool,
        artifact_type: str | None,
        artifact_present: bool,
    ) -> None:
        artifact: Any = {"status_code": 200} if artifact_present else None
        candidate = ViolationCandidate(
            flow_name="checkout",
            invariant_kind="step-skip",
            reached_impossible_state=reached,
            sequence=ExecutedSequence(
                flow_name="checkout",
                invariant_kind="step-skip",
                steps=[
                    ExecutedStep(
                        request_id="payment-req",
                        identity_role="user",
                    ),
                ],
                artifact=artifact,
                artifact_type=cast("Any", artifact_type),
            ),
        )

        result = asyncio.run(evaluate(candidate))

        if reached and artifact_present and artifact_type is not None:
            self.assertIsInstance(result, ConfirmedViolation)
        else:
            self.assertIsInstance(result, UnconfirmedHypothesis)

    @given(reproduces=st.booleans())
    def test_non_reproducing_violation_never_confirms(
        self,
        reproduces: bool,
    ) -> None:
        """Reproducibility pillar: a violation that does not reproduce is unconfirmed."""
        candidate = ViolationCandidate(
            flow_name="checkout",
            invariant_kind="step-skip",
            reached_impossible_state=True,
            sequence=ExecutedSequence(
                flow_name="checkout",
                invariant_kind="step-skip",
                steps=[ExecutedStep(request_id="payment-req", identity_role="user")],
                artifact={"status_code": 200},
                artifact_type="diff",
            ),
        )

        async def _reproduce(_sequence: ExecutedSequence) -> bool:
            return reproduces

        result = asyncio.run(evaluate(candidate, reproduce=_reproduce))

        if reproduces:
            self.assertIsInstance(result, ConfirmedViolation)
        else:
            self.assertIsInstance(result, UnconfirmedHypothesis)

    @given(response_status=st.sampled_from([200, 201, 403, 500]))
    def test_no_self_confirmation_without_impossible_state(
        self,
        response_status: int,
    ) -> None:
        """A successful response alone is never self-confirming;

        the model must declare the state impossible.
        """
        candidate = ViolationCandidate(
            flow_name="checkout",
            invariant_kind="step-skip",
            reached_impossible_state=False,
            sequence=ExecutedSequence(
                flow_name="checkout",
                invariant_kind="step-skip",
                steps=[
                    ExecutedStep(
                        request_id="payment-req",
                        identity_role="user",
                        response={"status_code": response_status},
                    )
                ],
                artifact={"status_code": response_status},
                artifact_type="diff",
            ),
        )

        result = asyncio.run(evaluate(candidate))
        self.assertIsInstance(result, UnconfirmedHypothesis)

"""Tier-1 tests for the business-logic evidence gate."""

from __future__ import annotations

from unittest import IsolatedAsyncioTestCase

from strix.core.logic.gate import evaluate
from strix.core.logic.models import (
    ConfirmedViolation,
    ExecutedSequence,
    ExecutedStep,
    UnconfirmedHypothesis,
    ViolationCandidate,
)


class TestEvidenceGate(IsolatedAsyncioTestCase):
    """Mandatory negative cases for the evidence gate."""

    def _candidate(
        self,
        *,
        reached: bool,
        artifact: object | None,
        artifact_type: str | None,
    ) -> ViolationCandidate:
        return ViolationCandidate(
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
                artifact_type=artifact_type,  # type: ignore[arg-type]
            ),
        )

    async def test_confirms_with_artifact_and_impossible_state(self) -> None:
        candidate = self._candidate(
            reached=True,
            artifact={"status_code": 200},
            artifact_type="diff",
        )
        result = await evaluate(candidate)
        self.assertIsInstance(result, ConfirmedViolation)
        assert isinstance(result, ConfirmedViolation)
        self.assertEqual(result.flow_name, "checkout")
        self.assertEqual(result.invariant_kind, "step-skip")
        self.assertIn("diff artifact", result.reason)

    async def test_rejects_no_artifact(self) -> None:
        candidate = self._candidate(
            reached=True,
            artifact=None,
            artifact_type=None,
        )
        result = await evaluate(candidate)
        self.assertIsInstance(result, UnconfirmedHypothesis)
        assert isinstance(result, UnconfirmedHypothesis)
        self.assertEqual(result.reason, "no typed deterministic artifact attached")

    async def test_rejects_model_allowed_state(self) -> None:
        candidate = self._candidate(
            reached=False,
            artifact={"status_code": 200},
            artifact_type="diff",
        )
        result = await evaluate(candidate)
        self.assertIsInstance(result, UnconfirmedHypothesis)
        assert isinstance(result, UnconfirmedHypothesis)
        self.assertEqual(
            result.reason,
            "executed sequence did not reach a model-impossible state",
        )

    async def test_rejects_non_reproducing(self) -> None:
        candidate = self._candidate(
            reached=True,
            artifact={"status_code": 200},
            artifact_type="diff",
        )

        async def _never_reproduces(_seq: ExecutedSequence) -> bool:
            return False

        result = await evaluate(candidate, reproduce=_never_reproduces)
        self.assertIsInstance(result, UnconfirmedHypothesis)
        assert isinstance(result, UnconfirmedHypothesis)
        self.assertEqual(result.reason, "violation did not reproduce on re-run")

    async def test_accepts_reproducing(self) -> None:
        candidate = self._candidate(
            reached=True,
            artifact={"status_code": 200},
            artifact_type="diff",
        )

        async def _always_reproduces(_seq: ExecutedSequence) -> bool:
            return True

        result = await evaluate(candidate, reproduce=_always_reproduces)
        self.assertIsInstance(result, ConfirmedViolation)
        assert isinstance(result, ConfirmedViolation)
        self.assertEqual(result.flow_name, "checkout")

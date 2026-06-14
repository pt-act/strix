"""Tier-1 and Tier-2 tests for the semantic differential engine."""

from __future__ import annotations

from unittest import TestCase

from hypothesis import given, settings
from hypothesis import strategies as st

from strix.core.diff import diff


class TestDiffEngineTier1(TestCase):
    """Focused behaviour tests for the differential engine."""

    def test_status_class_and_auth_signal_delta_detected(self) -> None:
        responses = [
            {
                "label": "anonymous",
                "response": {"status_code": 401, "headers": {}, "body": "unauthorized"},
            },
            {
                "label": "user",
                "response": {"status_code": 200, "headers": {}, "body": "user data"},
            },
        ]
        result = diff(responses)
        self.assertEqual(len(result.deltas), 1)
        delta = result.deltas[0]
        assert delta.status_class_delta is not None
        self.assertEqual(delta.status_class_delta.a, "4xx")
        self.assertEqual(delta.status_class_delta.b, "2xx")
        self.assertEqual(delta.auth_signal_delta, "gained_access")

    def test_cross_owner_success_flags_idor(self) -> None:
        responses = [
            {
                "label": "user",
                "response": {
                    "status_code": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"id": 42, "owner": "user"}',
                },
            },
            {
                "label": "admin",
                "response": {
                    "status_code": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"id": 42, "owner": "user"}',
                },
            },
            {
                "label": "anonymous",
                "response": {
                    "status_code": 401,
                    "headers": {},
                    "body": "unauthorized",
                },
            },
        ]
        result = diff(responses)
        idor = [c for c in result.candidates if c.kind == "IDOR"]
        self.assertTrue(idor, "Expected an IDOR candidate for cross-owner success")
        self.assertIn(("user", "admin"), [c.pair for c in idor])


class TestDiffEngineTier2PBT(TestCase):
    """Property-based invariants for the differential engine."""

    @given(
        status_code=st.integers(min_value=100, max_value=599),
        body_core=st.text(min_size=0, max_size=128),
    )
    @settings(max_examples=50, deadline=None)
    def test_diff_normalization_stability(self, status_code: int, body_core: str) -> None:
        # Two responses that differ only in volatile fields must produce no deltas.
        body_a = f"{body_core} 2026-06-14T12:00:00Z nonce=abc12345"
        body_b = f"{body_core} 2026-06-15T13:01:01Z nonce=xyz98765"
        responses = [
            {
                "label": "anonymous",
                "response": {
                    "status_code": status_code,
                    "headers": {"Date": "Mon, 14 Jun 2026 12:00:00 GMT"},
                    "body": body_a,
                },
            },
            {
                "label": "user",
                "response": {
                    "status_code": status_code,
                    "headers": {"Date": "Tue, 15 Jun 2026 13:01:01 GMT"},
                    "body": body_b,
                },
            },
        ]
        result = diff(responses)
        self.assertEqual(len(result.deltas), 1)
        delta = result.deltas[0]
        self.assertIsNone(delta.status_class_delta)
        self.assertEqual(delta.body_structure_delta, "same")
        self.assertEqual(delta.normalized_length_delta, 0)
        self.assertEqual(delta.auth_signal_delta, "none")
        # Candidate flagging is a separate concern; this test only verifies deltas.
        idor = [c for c in result.candidates if c.kind == "IDOR"]
        self.assertEqual(idor, [])

    def test_identity_isolation_records_delta_for_every_pair(self) -> None:
        labels = ["anonymous", "user", "admin", "expired"]
        responses = [
            {
                "label": label,
                "response": {
                    "status_code": 200 if label != "expired" else 401,
                    "headers": {},
                    "body": f"{label} response",
                },
            }
            for label in labels
        ]
        result = diff(responses)
        expected_pairs = {
            ("anonymous", "user"),
            ("anonymous", "admin"),
            ("anonymous", "expired"),
            ("user", "admin"),
            ("user", "expired"),
            ("admin", "expired"),
        }
        actual_pairs = {d.pair for d in result.deltas}
        self.assertEqual(actual_pairs, expected_pairs)

    def test_seeded_bfla_user_gains_access_to_admin_endpoint(self) -> None:
        responses = [
            {
                "label": "anonymous",
                "response": {"status_code": 403, "headers": {}, "body": "denied"},
            },
            {
                "label": "user",
                "response": {"status_code": 403, "headers": {}, "body": "denied"},
            },
            {
                "label": "admin",
                "response": {"status_code": 200, "headers": {}, "body": "admin data"},
            },
        ]
        result = diff(responses)
        bfla = {c.pair for c in result.candidates if c.kind == "BFLA"}
        self.assertIn(("anonymous", "admin"), bfla)
        self.assertIn(("user", "admin"), bfla)

    def test_seeded_expired_authorized(self) -> None:
        responses = [
            {
                "label": "user",
                "response": {"status_code": 401, "headers": {}, "body": "unauthorized"},
            },
            {
                "label": "expired",
                "response": {"status_code": 200, "headers": {}, "body": "still authorized"},
            },
        ]
        result = diff(responses)
        expired = [c for c in result.candidates if c.kind == "expired_authorized"]
        self.assertTrue(expired)
        self.assertEqual(expired[0].pair, ("expired", "user"))
        self.assertEqual(expired[0].evidence_class, "diff")

    @given(
        owner=st.sampled_from(["user", "admin"]),
        intruder=st.sampled_from(["user", "admin"]),
    )
    @settings(max_examples=30, deadline=None)
    def test_idor_detection(self, owner: str, intruder: str) -> None:
        # Two different non-anonymous identities both succeed with the same body.
        if owner == intruder:
            # Same identity cannot produce a cross-owner finding.
            return
        body = '{"id": 42, "owner": "' + owner + '"}'
        responses = [
            {
                "label": owner,
                "response": {
                    "status_code": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": body,
                },
            },
            {
                "label": intruder,
                "response": {
                    "status_code": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": body,
                },
            },
            {
                "label": "anonymous",
                "response": {
                    "status_code": 401,
                    "headers": {},
                    "body": "unauthorized",
                },
            },
        ]
        result = diff(responses)
        idor_pairs = {c.pair for c in result.candidates if c.kind == "IDOR"}
        self.assertIn((owner, intruder), idor_pairs)


if __name__ == "__main__":
    import unittest

    unittest.main()

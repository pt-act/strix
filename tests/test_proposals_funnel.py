"""Tier-1 + PBT tests for the propose-dispose funnel."""

from __future__ import annotations

from unittest import IsolatedAsyncioTestCase, TestCase

from hypothesis import given
from hypothesis import strategies as st

from strix.core.proposals.models import (
    C1C8Answer,
    InterventionFlags,
)
from strix.report.proposals import (
    FunnelLog,
    compute_funnel_efficiency,
    compute_prec_gate,
    compute_r_e2e,
    compute_r_prop,
)


class TestFunnelLifecycle(IsolatedAsyncioTestCase):
    """A proposal flows through the funnel and records every transition."""

    def test_proposal_to_harness_to_report(self) -> None:
        log = FunnelLog()
        record = log.start_proposal(
            engagement_id="eng-1",
            endpoint_key="GET /api/users/{id}",
            param_name="id",
            cwe="CWE-639",
            c1_c8_answers={
                "C5": C1C8Answer(
                    question_id="C5",
                    question="does the bug require a specific prior state?",
                    answer="yes",
                    rationale="object ownership check",
                ),
            },
            active_interventions=InterventionFlags(
                control_path=True, knowledge_path=True, c1_c8_checklist=True
            ),
            harnesses_selected=["auth-matrix"],
        )

        log.record_harness_verdict(
            record.proposal_id,
            harness_name="auth-matrix",
            verdict="confirmed",
            evidence_class="diff",
            cost_ms=42.0,
        )
        log.record_report(record.proposal_id, "vuln-0001")

        loaded = log.get(record.proposal_id)
        assert loaded is not None
        self.assertEqual(loaded.endpoint_key, "GET /api/users/{id}")
        self.assertEqual(loaded.param_name, "id")
        self.assertEqual(loaded.cwe, "CWE-639")
        self.assertEqual(loaded.active_interventions.control_path, True)
        self.assertEqual(loaded.active_interventions.knowledge_path, True)
        self.assertEqual(loaded.active_interventions.c1_c8_checklist, True)
        self.assertEqual(len(loaded.verdicts), 1)
        self.assertEqual(loaded.verdicts[0].evidence_class, "diff")
        self.assertEqual(loaded.verdicts[0].verdict, "confirmed")
        self.assertEqual(loaded.report_id, "vuln-0001")


class TestDerivedMetrics(IsolatedAsyncioTestCase):
    """Pure functions over the funnel log."""

    def test_metrics(self) -> None:
        log = FunnelLog()
        # V = true vulnerable endpoints
        labels = {"GET /api/users/{id}", "POST /checkout"}

        p1 = log.start_proposal(
            engagement_id="eng-1",
            endpoint_key="GET /api/users/{id}",
            cwe="CWE-639",
            harnesses_selected=["auth-matrix"],
        )
        log.record_harness_verdict(p1.proposal_id, "auth-matrix", "confirmed", "diff")
        log.record_report(p1.proposal_id, "vuln-0001")

        p2 = log.start_proposal(
            engagement_id="eng-1",
            endpoint_key="POST /checkout",
            cwe="CWE-20",
            harnesses_selected=["business-logic"],
        )
        log.record_harness_verdict(p2.proposal_id, "business-logic", "unconfirmed", "none")

        # False-positive proposal (not in labels)
        p3 = log.start_proposal(
            engagement_id="eng-1",
            endpoint_key="GET /health",
            cwe="CWE-200",
            harnesses_selected=["auth-matrix"],
        )
        log.record_harness_verdict(p3.proposal_id, "auth-matrix", "confirmed", "diff")
        log.record_report(p3.proposal_id, "vuln-0002")

        records = log.list_records()
        self.assertAlmostEqual(compute_r_prop(records, labels), 1.0)
        self.assertAlmostEqual(compute_prec_gate(records, labels), 0.5)
        self.assertAlmostEqual(compute_r_e2e(records, labels), 0.5)
        # 3 harness runs / 2 confirmed findings
        self.assertAlmostEqual(compute_funnel_efficiency(records), 1.5)


class TestFunnelCompletenessPBT(TestCase):
    """Every proposal reaching a harness carries a verdict with a valid evidence_class."""

    @given(
        evidence_class=st.sampled_from(["diff", "callback", "reachability", "race_result", "none"]),
        verdict=st.sampled_from(["confirmed", "unconfirmed", "inconclusive", "error"]),
    )
    def test_completeness(self, evidence_class: str, verdict: str) -> None:
        log = FunnelLog()
        record = log.start_proposal(
            engagement_id="eng-1",
            endpoint_key="GET /api/x",
            cwe="CWE-000",
            harnesses_selected=["h"],
        )
        log.record_harness_verdict(
            record.proposal_id,
            harness_name="h",
            verdict=verdict,
            evidence_class=evidence_class,  # type: ignore[arg-type]
        )
        loaded = log.get(record.proposal_id)
        assert loaded is not None
        self.assertTrue(
            any(
                v.evidence_class in {"diff", "callback", "reachability", "race_result", "none"}
                for v in loaded.verdicts
            )
        )

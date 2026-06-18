"""M1 funnel-metric capture + cross-check (Spec B TG1.2).

Builds a synthetic funnel with a hand-computed expectation and asserts the read-only metric
harness reproduces it, that the cross-check passes on the hand values and fails on a wrong one,
and that every metric traces back to the contributing proposals (TG5.7).
"""

from __future__ import annotations

from unittest import TestCase

from strix.report.proposals import FunnelLog
from strix.research.metrics import cross_check, summarize_funnel, traceability


# Labeled-known vulnerable set V.
_LABELS = {"E1", "E2", "E3"}


def _build_funnel() -> FunnelLog:
    """Synthetic funnel (TP = in V, FP = not in V):

    - p1 E1  (in V):  confirmed + reported            -> 1 run, confirmed-TP, reported-TP
    - p2 E2  (in V):  unconfirmed, then confirmed + reported -> 2 runs, confirmed-TP, reported-TP
    - p3 X9  (not V): confirmed + reported            -> 1 run, confirmed-FP, reported-FP
    - p4 E3  (in V):  unconfirmed only                -> 1 run, proposed, not confirmed
    - p5 E5  (no cwe): no verdicts                     -> not even "proposed"
    """
    fl = FunnelLog()
    fl.start_proposal(engagement_id="e", endpoint_key="E1", cwe="CWE-1", proposal_id="p1")
    fl.record_harness_verdict("p1", "p3_oob_harness", "confirmed", "callback")
    fl.record_report("p1", "r1")

    fl.start_proposal(engagement_id="e", endpoint_key="E2", cwe="CWE-2", proposal_id="p2")
    fl.record_harness_verdict("p2", "p3_oob_harness", "unconfirmed", "none")
    fl.record_harness_verdict("p2", "p3_oob_harness", "confirmed", "callback")
    fl.record_report("p2", "r2")

    fl.start_proposal(engagement_id="e", endpoint_key="X9", cwe="CWE-3", proposal_id="p3")
    fl.record_harness_verdict("p3", "p2_diff_harness", "confirmed", "diff")
    fl.record_report("p3", "r3")

    fl.start_proposal(engagement_id="e", endpoint_key="E3", cwe="CWE-4", proposal_id="p4")
    fl.record_harness_verdict("p4", "p4_race_harness", "unconfirmed", "none")

    fl.start_proposal(engagement_id="e", endpoint_key="E5", cwe=None, proposal_id="p5")
    return fl


class TestFunnelMetrics(TestCase):
    def setUp(self) -> None:
        self.records = _build_funnel().list_records()

    def test_metrics_match_hand_computation(self) -> None:
        summary = summarize_funnel(self.records, _LABELS)
        # Hand: P∩V={E1,E2,E3}=3, |V|=3 -> 1.0; C={E1,E2,X9}, C∩V=2 -> 2/3; R same -> 2/3;
        # runs=1+2+1+1=5, |C|=3 -> 5/3.
        self.assertAlmostEqual(summary.r_prop, 1.0)
        self.assertAlmostEqual(summary.prec_gate, 2 / 3)
        self.assertAlmostEqual(summary.r_e2e, 2 / 3)
        self.assertAlmostEqual(summary.funnel_efficiency, 5 / 3)
        self.assertEqual(
            (
                summary.num_labels,
                summary.num_proposed,
                summary.num_confirmed,
                summary.num_reported,
                summary.num_harness_runs,
            ),
            (3, 4, 3, 3, 5),
        )

    def test_cross_check_passes_on_hand_values_fails_on_wrong(self) -> None:
        summary = summarize_funnel(self.records, _LABELS)
        good = cross_check(
            summary,
            {"r_prop": 1.0, "prec_gate": 2 / 3, "r_e2e": 2 / 3, "funnel_efficiency": 5 / 3},
        )
        self.assertTrue(good.agree)
        self.assertTrue(all(good.per_metric.values()))

        bad = cross_check(summary, {"prec_gate": 1.0})  # claim no false positives — wrong
        self.assertFalse(bad.agree)
        self.assertFalse(bad.per_metric["prec_gate"])

    def test_traceability_resolves_every_claim_to_endpoints(self) -> None:
        trace = traceability(self.records, _LABELS)
        self.assertEqual(trace["labels_V"], ["E1", "E2", "E3"])
        self.assertEqual(trace["prec_gate_confirmed"], ["E1", "E2", "X9"])
        self.assertEqual(trace["prec_gate_true_positives"], ["E1", "E2"])
        self.assertEqual(trace["r_e2e_reported_hits"], ["E1", "E2"])

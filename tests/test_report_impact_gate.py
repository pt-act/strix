"""Tests for the impact-gated severity policy in the report layer."""

from __future__ import annotations

import pytest

from strix.report.state import ReportState, _apply_impact_gate


class TestImpactGate:
    """Group 4 — impact-gated severity policy."""

    @pytest.mark.parametrize(
        ("evidence_class", "expected_severity", "expected_decision"),
        [
            ("none", "info", "downgraded_to_unconfirmed"),
            ("diff", "high", "kept_from_cvss"),
            ("callback", "high", "kept_from_cvss"),
            ("reachability", "high", "kept_from_cvss"),
            ("race_result", "high", "kept_from_cvss"),
        ],
    )
    def test_apply_impact_gate(
        self, evidence_class: str, expected_severity: str, expected_decision: str
    ) -> None:
        final, decision, original = _apply_impact_gate("high", evidence_class)  # type: ignore[arg-type]
        assert final == expected_severity
        assert decision == expected_decision
        assert original == "high"

    def test_invalid_evidence_class_rejected(self) -> None:
        state = ReportState(run_name="test-impact-gate")
        with pytest.raises(ValueError, match="Invalid evidence_class"):
            state.add_vulnerability_report(
                title="Bad evidence class",
                severity="high",
                evidence_class="bad",  # type: ignore[arg-type]
            )

    def test_none_evidence_downgrades_severity(self) -> None:
        state = ReportState(run_name="test-impact-gate")
        state.add_vulnerability_report(
            title="Unconfirmed finding",
            severity="high",
            cvss=8.5,
            evidence_class="none",
        )
        report = state.vulnerability_reports[-1]
        assert report["severity"] == "info"
        assert report["original_severity"] == "high"
        assert report["evidence_class"] == "none"
        assert report["impact_gate_decision"] == "downgraded_to_unconfirmed"

    def test_diff_evidence_keeps_severity(self) -> None:
        state = ReportState(run_name="test-impact-gate")
        state.add_vulnerability_report(
            title="Confirmed finding",
            severity="critical",
            cvss=9.8,
            evidence_class="diff",
        )
        report = state.vulnerability_reports[-1]
        assert report["severity"] == "critical"
        assert report["original_severity"] == "critical"
        assert report["evidence_class"] == "diff"
        assert report["impact_gate_decision"] == "kept_from_cvss"

    def test_callback_evidence_keeps_severity(self) -> None:
        state = ReportState(run_name="test-impact-gate")
        state.add_vulnerability_report(
            title="Confirmed blind finding",
            severity="high",
            cvss=7.5,
            evidence_class="callback",
        )
        report = state.vulnerability_reports[-1]
        assert report["severity"] == "high"
        assert report["evidence_class"] == "callback"

    def test_default_evidence_class_is_none(self) -> None:
        state = ReportState(run_name="test-impact-gate")
        state.add_vulnerability_report(
            title="Legacy-style finding",
            severity="medium",
        )
        report = state.vulnerability_reports[-1]
        assert report["severity"] == "info"
        assert report["evidence_class"] == "none"
        assert report["impact_gate_decision"] == "downgraded_to_unconfirmed"

    def test_downgraded_finding_stays_visible(self) -> None:
        state = ReportState(run_name="test-impact-gate")
        state.add_vulnerability_report(
            title="Noise",
            severity="high",
            evidence_class="none",
        )
        assert len(state.vulnerability_reports) == 1
        assert state.vulnerability_reports[0]["severity"] == "info"

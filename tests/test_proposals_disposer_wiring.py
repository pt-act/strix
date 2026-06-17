"""Disposer -> funnel live wiring.

These tests cover the additive link in ``ReportState.add_vulnerability_report``: when a
harness verdict reaches the report chokepoint, its ``evidence_class`` + report id are
attached to the matching ProposalRecord in the funnel. The link is glass-box only — it
never alters the report dict, the impact gate, or ``vulnerability_reports`` semantics.
"""

from __future__ import annotations

import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType
from typing import Any
from unittest import TestCase


# Mock the agents SDK before importing report-state-facing modules (mirrors the
# sibling proposal tests so the suite imports cleanly without the real SDK).
_agents: Any = ModuleType("agents")
_agents_usage: Any = ModuleType("agents.usage")


class _Usage:
    pass


_agents_usage.Usage = _Usage
_agents_usage.serialize_usage = lambda _: {}
_agents_usage.deserialize_usage = lambda _: _Usage()
_agents.RunContextWrapper = object
_agents.function_tool = lambda **_: lambda f: f
sys.modules.setdefault("agents", _agents)
sys.modules.setdefault("agents.usage", _agents_usage)

from strix.report.state import (  # noqa: E402
    ReportState,
    get_global_report_state,
    set_global_report_state,
)


_ENDPOINT = "GET /api/users/{id}"


class TestDisposerFunnelWiring(TestCase):
    def setUp(self) -> None:
        self.previous_state = get_global_report_state()
        self.tmp = TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir()
        self.report_state = ReportState(run_name=self.run_dir.name)
        self.report_state._run_dir = self.run_dir
        set_global_report_state(self.report_state)

    def tearDown(self) -> None:
        set_global_report_state(self.previous_state)
        self.tmp.cleanup()

    def _start_proposal(
        self, *, endpoint_key: str = _ENDPOINT, proposal_id: str | None = None
    ) -> str:
        record = self.report_state.funnel_log.start_proposal(
            engagement_id="demo",
            endpoint_key=endpoint_key,
            cwe="CWE-639",
            harnesses_selected=["p3_oob_harness"],
            proposal_id=proposal_id,
        )
        return record.proposal_id

    def _file_report(
        self,
        *,
        evidence_class: str,
        endpoint: str | None = _ENDPOINT,
        proposal_id: str | None = None,
    ) -> str:
        return self.report_state.add_vulnerability_report(
            title="SSRF via image import",
            severity="high",
            endpoint=endpoint,
            evidence_class=evidence_class,  # type: ignore[arg-type]
            proposal_id=proposal_id,
        )

    def test_explicit_proposal_id_links_verdict_and_report(self) -> None:
        proposal_id = self._start_proposal(proposal_id="prop-fixed")
        report_id = self._file_report(evidence_class="callback", proposal_id="prop-fixed")

        record = self.report_state.funnel_log.get(proposal_id)
        assert record is not None
        self.assertEqual(len(record.verdicts), 1)
        self.assertEqual(record.verdicts[0].verdict, "confirmed")
        self.assertEqual(record.verdicts[0].evidence_class, "callback")
        self.assertEqual(record.verdicts[0].harness_name, "p3_oob_harness")
        self.assertEqual(record.report_id, report_id)

    def test_best_effort_endpoint_match_when_no_proposal_id(self) -> None:
        proposal_id = self._start_proposal()
        self._file_report(evidence_class="race_result")  # no proposal_id supplied

        record = self.report_state.funnel_log.get(proposal_id)
        assert record is not None
        self.assertEqual(len(record.verdicts), 1)
        self.assertEqual(record.verdicts[0].evidence_class, "race_result")
        self.assertEqual(record.verdicts[0].harness_name, "p4_race_harness")
        self.assertIsNotNone(record.report_id)

    def test_evidence_class_none_records_no_verdict(self) -> None:
        proposal_id = self._start_proposal()
        self._file_report(evidence_class="none")

        record = self.report_state.funnel_log.get(proposal_id)
        assert record is not None
        self.assertEqual(record.verdicts, [])
        self.assertIsNone(record.report_id)

    def test_ambiguous_endpoint_match_links_nothing(self) -> None:
        a = self._start_proposal(proposal_id="prop-a")
        b = self._start_proposal(proposal_id="prop-b")
        # Two open proposals for the same endpoint, no proposal_id -> conservative no-op.
        self._file_report(evidence_class="callback")

        for pid in (a, b):
            record = self.report_state.funnel_log.get(pid)
            assert record is not None
            self.assertEqual(record.verdicts, [])
            self.assertIsNone(record.report_id)

    def test_already_verdicted_proposal_not_rematched(self) -> None:
        proposal_id = self._start_proposal()
        # First confirmed verdict links it.
        self._file_report(evidence_class="callback")
        # A second report for the same endpoint must not re-link the now-closed proposal.
        self._file_report(evidence_class="diff")

        record = self.report_state.funnel_log.get(proposal_id)
        assert record is not None
        self.assertEqual(len(record.verdicts), 1)
        self.assertEqual(record.verdicts[0].evidence_class, "callback")

    def test_additive_no_proposals_is_noop_and_report_unchanged(self) -> None:
        # No proposals in the funnel: report creation must succeed and stay byte-faithful.
        report_id = self._file_report(evidence_class="callback")

        self.assertEqual(self.report_state.funnel_log.list_records(), [])
        report = next(r for r in self.report_state.vulnerability_reports if r["id"] == report_id)
        self.assertEqual(report["evidence_class"], "callback")
        self.assertEqual(report["impact_gate_decision"], "kept_from_cvss")

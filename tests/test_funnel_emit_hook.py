"""Spec B Step-0 funnel-completeness emit-hook.

``ReportState.record_harness_run`` is emit-only observability: it appends a harness run
(confirmed or unconfirmed) to the matching proposal so the funnel captures *every* run,
not just the confirmed ones Spec A's report path records. It must never create a report,
never change a harness verdict / evidence_class, never touch anything outside funnel_log,
and never raise — the disposer's disposition is byte-identical with or without it.
"""

from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType
from typing import Any
from unittest import TestCase


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


_ENDPOINT = "POST /api/v1/import"


class TestFunnelEmitHook(TestCase):
    def setUp(self) -> None:
        self.previous_state = get_global_report_state()
        self.tmp = TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir()
        self.state = ReportState(run_name=self.run_dir.name)
        self.state._run_dir = self.run_dir
        set_global_report_state(self.state)

    def tearDown(self) -> None:
        set_global_report_state(self.previous_state)
        self.tmp.cleanup()

    def _start(self, *, proposal_id: str | None = None, endpoint_key: str = _ENDPOINT) -> str:
        return self.state.funnel_log.start_proposal(
            engagement_id="demo",
            endpoint_key=endpoint_key,
            cwe="CWE-918",
            harnesses_selected=["p3_oob_harness"],
            proposal_id=proposal_id,
        ).proposal_id

    def test_records_unconfirmed_run_by_explicit_id(self) -> None:
        pid = self._start(proposal_id="prop-1")
        out = self.state.record_harness_run(
            harness_name="p3_oob_harness", verdict="unconfirmed", proposal_id="prop-1"
        )
        self.assertEqual(out, pid)
        record = self.state.funnel_log.get(pid)
        assert record is not None
        self.assertEqual(len(record.verdicts), 1)
        self.assertEqual(record.verdicts[0].verdict, "unconfirmed")
        self.assertEqual(record.verdicts[0].evidence_class, "none")
        self.assertIsNone(record.report_id)  # emit-only: no report linked

    def test_multiple_runs_accumulate(self) -> None:
        pid = self._start(proposal_id="prop-1")
        self.state.record_harness_run(
            harness_name="p3_oob_harness", verdict="unconfirmed", proposal_id="prop-1"
        )
        self.state.record_harness_run(
            harness_name="p3_oob_harness",
            verdict="confirmed",
            evidence_class="callback",
            proposal_id="prop-1",
        )
        record = self.state.funnel_log.get(pid)
        assert record is not None
        self.assertEqual([v.verdict for v in record.verdicts], ["unconfirmed", "confirmed"])

    def test_best_effort_endpoint_match(self) -> None:
        pid = self._start()  # no explicit id
        out = self.state.record_harness_run(
            harness_name="p3_oob_harness", verdict="unconfirmed", endpoint=_ENDPOINT
        )
        self.assertEqual(out, pid)

    def test_no_match_is_noop(self) -> None:
        self._start(proposal_id="prop-1")
        out = self.state.record_harness_run(
            harness_name="p3_oob_harness", verdict="unconfirmed", endpoint="GET /unrelated"
        )
        self.assertIsNone(out)
        record = self.state.funnel_log.get("prop-1")
        assert record is not None
        self.assertEqual(record.verdicts, [])

    def test_ambiguous_match_is_noop(self) -> None:
        self._start(proposal_id="prop-a")
        self._start(proposal_id="prop-b")
        out = self.state.record_harness_run(
            harness_name="p3_oob_harness", verdict="unconfirmed", endpoint=_ENDPOINT
        )
        self.assertIsNone(out)

    def test_never_raises_on_bad_input(self) -> None:
        # Unknown proposal id + unknown endpoint + bogus evidence_class -> None, no exception.
        out = self.state.record_harness_run(
            harness_name="x",
            verdict="weird",
            evidence_class="not-a-class",  # type: ignore[arg-type]
            proposal_id="does-not-exist",
            endpoint="nope",
        )
        self.assertIsNone(out)

    def test_behavior_identical_touches_only_funnel(self) -> None:
        """An emit call mutates nothing outside funnel_log — reports + run_record are
        byte-identical, which is the gate-neutrality / behavior-identical guarantee.
        """
        self._start(proposal_id="prop-1")
        reports_before = deepcopy(self.state.vulnerability_reports)
        run_record_before = deepcopy(self.state.run_record)

        self.state.record_harness_run(
            harness_name="p3_oob_harness",
            verdict="confirmed",
            evidence_class="callback",
            proposal_id="prop-1",
        )

        self.assertEqual(self.state.vulnerability_reports, reports_before)
        self.assertEqual(self.state.run_record, run_record_before)

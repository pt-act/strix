"""Spec B harness wiring — the centralized funnel emit-wrapper.

Operator-approved design (2026-06-18): the funnel records **every** harness run from a single
emit point (the factory wrapper around each disposer tool), while the report path is demoted to
linking only the ``report_id``. These tests pin the three load-bearing guarantees:

1. **Behavior-identical** — the wrapped tool returns its underlying tool's output unchanged.
2. **Confirmed end-state byte-identical** — after (link-only report) + (wrapper emit), a confirmed
   proposal carries exactly the ``HarnessVerdict`` the pre-refactor report path wrote, plus its
   ``report_id`` — regardless of which runs first.
3. **Unconfirmed runs now emit** — the funnel-completeness fix that unbiases ``Prec_gate`` /
   ``funnel_efficiency``.
"""

from __future__ import annotations

import asyncio
import json
import sys
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

from strix.agents.funnel_emit import emit_harness_run, wrap_harness_tool  # noqa: E402
from strix.report.state import (  # noqa: E402
    ReportState,
    get_global_report_state,
    set_global_report_state,
)


_ENDPOINT = "POST /api/v1/import"


class _FakeFunctionTool:
    """Minimal stand-in for an agents SDK FunctionTool (has ``name`` + ``on_invoke_tool``)."""

    def __init__(self, name: str, returns: Any) -> None:
        self.name = name
        self._returns = returns
        self.calls: list[tuple[Any, str]] = []

    async def on_invoke_tool(self, ctx: Any, args_json: str) -> Any:
        self.calls.append((ctx, args_json))
        return self._returns


class TestEmitHarnessRun(TestCase):
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

    def _start(self, *, endpoint_key: str = _ENDPOINT, proposal_id: str | None = None) -> str:
        return self.state.funnel_log.start_proposal(
            engagement_id="demo",
            endpoint_key=endpoint_key,
            cwe="CWE-918",
            harnesses_selected=["p3_oob_harness"],
            proposal_id=proposal_id,
        ).proposal_id

    def _file_report(self, *, evidence_class: str, endpoint: str = _ENDPOINT) -> str:
        return self.state.add_vulnerability_report(
            title="finding",
            severity="high",
            endpoint=endpoint,
            evidence_class=evidence_class,  # type: ignore[arg-type]
        )

    def test_confirmed_end_state_byte_identical(self) -> None:
        """Report path (link-only) + wrapper emit reproduce the pre-refactor confirmed end-state:
        exactly one HarnessVerdict(p3_oob_harness, confirmed, callback) + the report_id.
        Report is filed *before* the emit — the real order inside a confirmed harness call.
        """
        pid = self._start()
        report_id = self._file_report(evidence_class="callback")  # link-only: report_id, no verdict

        emit_harness_run(
            "p3_oob_harness",
            {"verdict": "confirmed", "report": {"evidence_class": "callback"}},
            json.dumps({"endpoint": _ENDPOINT}),
        )

        record = self.state.funnel_log.get(pid)
        assert record is not None
        self.assertEqual(record.report_id, report_id)
        self.assertEqual(len(record.verdicts), 1)
        verdict = record.verdicts[0]
        self.assertEqual(verdict.harness_name, "p3_oob_harness")
        self.assertEqual(verdict.verdict, "confirmed")
        self.assertEqual(verdict.evidence_class, "callback")
        self.assertEqual(verdict.cost_ms, 0.0)

    def test_unconfirmed_run_now_emits(self) -> None:
        pid = self._start()
        emit_harness_run(
            "p3_oob_harness",
            {"verdict": "unconfirmed"},  # no report -> unconfirmed
            json.dumps({"endpoint": _ENDPOINT}),
        )
        record = self.state.funnel_log.get(pid)
        assert record is not None
        self.assertEqual(len(record.verdicts), 1)
        self.assertEqual(record.verdicts[0].verdict, "unconfirmed")
        self.assertEqual(record.verdicts[0].evidence_class, "none")
        self.assertIsNone(record.report_id)

    def test_uses_filed_evidence_class_not_default(self) -> None:
        """A confirmed run reports the *filed* class (e.g. a business-logic double-spend that used
        the race harness => race_result), so the recorded harness name follows the evidence, not
        the wrapper's per-tool default.
        """
        pid = self._start()
        emit_harness_run(
            "p2_diff_harness",  # the logic tool's default
            {"verdict": "confirmed", "report": {"evidence_class": "race_result"}},
            json.dumps({"endpoint": _ENDPOINT}),
        )
        record = self.state.funnel_log.get(pid)
        assert record is not None
        self.assertEqual(record.verdicts[0].evidence_class, "race_result")
        self.assertEqual(record.verdicts[0].harness_name, "p4_race_harness")
        self.assertEqual(record.verdicts[0].verdict, "confirmed")

    def test_emit_handles_json_string_result(self) -> None:
        pid = self._start()
        emit_harness_run(
            "p4_race_harness",
            json.dumps({"verdict": "race", "report": {"evidence_class": "race_result"}}),
            json.dumps({"target_key": _ENDPOINT}),
        )
        record = self.state.funnel_log.get(pid)
        assert record is not None
        self.assertEqual(record.verdicts[0].evidence_class, "race_result")

    def test_no_matching_proposal_is_noop(self) -> None:
        self._start(proposal_id="prop-1")
        emit_harness_run(
            "p3_oob_harness",
            {"verdict": "unconfirmed"},
            json.dumps({"endpoint": "GET /unrelated"}),
        )
        record = self.state.funnel_log.get("prop-1")
        assert record is not None
        self.assertEqual(record.verdicts, [])


class TestWrapHarnessTool(TestCase):
    def test_behavior_identical_return(self) -> None:
        """The wrapped tool returns the underlying tool's output unchanged, for both verdicts."""
        for payload in (
            {"verdict": "confirmed", "report": {"evidence_class": "callback"}},
            {"verdict": "unconfirmed"},
        ):
            tool = _FakeFunctionTool("report_oob_confirmed_candidate", payload)
            wrapped = wrap_harness_tool(tool, default_harness="p3_oob_harness")
            previous = get_global_report_state()
            tmp = TemporaryDirectory()
            try:
                run_dir = Path(tmp.name) / "run"
                run_dir.mkdir()
                state = ReportState(run_name=run_dir.name)
                state._run_dir = run_dir
                set_global_report_state(state)
                args = json.dumps({"endpoint": _ENDPOINT})
                direct = asyncio.run(tool.on_invoke_tool(None, args))
                via_wrapper = asyncio.run(wrapped.on_invoke_tool(None, args))
                self.assertEqual(via_wrapper, direct)
                self.assertEqual(via_wrapper, payload)
            finally:
                set_global_report_state(previous)
                tmp.cleanup()

    def test_non_functiontool_is_returned_unchanged(self) -> None:
        """A raw function (agents SDK mocked) has no on_invoke_tool -> wrapper is a no-op."""

        async def raw_tool(_ctx: Any, _args: str) -> str:
            return "ok"

        self.assertIs(wrap_harness_tool(raw_tool, default_harness="p3_oob_harness"), raw_tool)

    def test_wrapper_preserves_tool_name(self) -> None:
        tool = _FakeFunctionTool("run_race_harness", {"verdict": "safe"})
        wrapped = wrap_harness_tool(tool, default_harness="p4_race_harness")
        self.assertEqual(wrapped.name, "run_race_harness")

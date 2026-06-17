"""E2E integration test: proposal tool -> funnel -> downstream harness verdict."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType
from typing import Any
from unittest import IsolatedAsyncioTestCase


# Mock the agents SDK before importing any tool-facing modules.
_agents: Any = ModuleType("agents")
_agents_usage: Any = ModuleType("agents.usage")


class _Usage:
    pass


_agents_usage.Usage = _Usage
_agents_usage.serialize_usage = lambda _: {}
_agents_usage.deserialize_usage = lambda _: _Usage()


class _RunContextWrapper:
    def __init__(self, context: dict[str, Any] | None = None) -> None:
        self.context = context or {}


def _function_tool(*, timeout: int = 60, strict_mode: bool = False) -> Any:
    _ = timeout, strict_mode

    def decorator(func: Any) -> Any:
        return func

    return decorator


_agents.RunContextWrapper = _RunContextWrapper
_agents.function_tool = _function_tool
sys.modules["agents"] = _agents
sys.modules["agents.usage"] = _agents_usage

from strix.core.inventory.models import (  # noqa: E402
    Endpoint,
    Param,
    ParamClassEvidence,
    RankedSurfaceMap,
    ReachabilityAnnotation,
)
from strix.core.inventory.store import save_ranked_map  # noqa: E402
from strix.core.proposals.models import InterventionFlags  # noqa: E402
from strix.report.state import (  # noqa: E402
    ReportState,
    get_global_report_state,
    set_global_report_state,
)
from strix.tools.inventory.tools import propose_vulnerability_investigation  # noqa: E402


class _FakeContext:
    def __init__(self, run_dir: Path) -> None:
        self.context = {"run_dir": str(run_dir)}


def _ctx(run_dir: Path) -> _FakeContext:
    return _FakeContext(run_dir)


def _make_ranked_map(run_dir: Path, target_id: str) -> RankedSurfaceMap:
    endpoint = Endpoint(
        key="GET /api/users/{id}",
        method="GET",
        url="/api/users/{id}",
        reachability=ReachabilityAnnotation(status="reachable", path=["handler", "database"]),
    )
    endpoint.params["id"] = Param(
        name="id",
        location="path",
        class_evidence=ParamClassEvidence(class_name="object-id", evidence="fixture"),
    )
    ranked = RankedSurfaceMap(target_id=target_id, endpoints={endpoint.key: endpoint})
    save_ranked_map(run_dir, ranked)
    return ranked


class TestProposalsIntegration(IsolatedAsyncioTestCase):
    """Proposal tool records funnel transitions; harness verdict lands in the same record."""

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

    async def test_proposal_flow_records_context_and_verdict(self) -> None:
        _make_ranked_map(self.run_dir, "demo")
        c1_c8_answers = [
            {
                "question_id": "C5",
                "answer": "yes",
                "rationale": "object ownership check",
            }
        ]
        all_flags = InterventionFlags(control_path=True, knowledge_path=True, c1_c8_checklist=True)

        result = await propose_vulnerability_investigation(
            _ctx(self.run_dir),
            target_id="demo",
            endpoint_key="GET /api/users/{id}",
            param_name="id",
            cwe="CWE-639",
            control_path=True,
            knowledge_path=True,
            c1_c8_checklist=True,
            c1_c8_answers=c1_c8_answers,
            harnesses_selected=["auth-matrix"],
        )
        data = json.loads(result)
        self.assertTrue(data["success"])
        proposal_id = data["proposal_id"]
        self.assertIsNotNone(proposal_id)

        # Supplied context is recorded in the response.
        self.assertIn("GET /api/users/{id}", data["control_path_nl"])
        self.assertIn("IDOR", data["knowledge_path_nl"])
        self.assertEqual(data["active_flags"], all_flags.model_dump())
        self.assertIsNotNone(data["c1_c8_checklist"])
        self.assertIn("C5", [a["question_id"] for a in data["c1_c8_checklist"]["answers"]])
        self.assertIsNotNone(data["c1_c8_questions"])

        # Same record is in the funnel.
        record = self.report_state.funnel_log.get(proposal_id)
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.endpoint_key, "GET /api/users/{id}")
        self.assertEqual(record.param_name, "id")
        self.assertEqual(record.cwe, "CWE-639")
        self.assertEqual(record.active_interventions, all_flags)
        self.assertIsNotNone(record.supplied_context)
        self.assertIn("C5", record.c1_c8_answers)
        self.assertEqual(record.c1_c8_answers["C5"].answer, "yes")

        # Downstream harness verdict lands in the same record.
        self.report_state.funnel_log.record_harness_verdict(
            proposal_id, "auth-matrix", "confirmed", "diff", cost_ms=42.0
        )
        record = self.report_state.funnel_log.get(proposal_id)
        assert record is not None
        self.assertEqual(len(record.verdicts), 1)
        self.assertEqual(record.verdicts[0].evidence_class, "diff")
        self.assertEqual(record.verdicts[0].verdict, "confirmed")

        # Funnel is persisted to disk.
        self.report_state.save_run_data()
        funnel_path = self.run_dir / "funnel.json"
        self.assertTrue(funnel_path.exists())
        loaded = json.loads(funnel_path.read_text(encoding="utf-8"))
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["proposal_id"], proposal_id)
        self.assertEqual(loaded[0]["endpoint_key"], "GET /api/users/{id}")
        self.assertEqual(loaded[0]["active_interventions"], all_flags.model_dump())

    async def test_proposal_tool_without_report_state_returns_context_and_warning(self) -> None:
        set_global_report_state(None)
        _make_ranked_map(self.run_dir, "demo")

        result = await propose_vulnerability_investigation(
            _ctx(self.run_dir),
            target_id="demo",
            endpoint_key="GET /api/users/{id}",
            control_path=True,
        )
        data = json.loads(result)
        self.assertTrue(data["success"])
        self.assertIsNone(data["proposal_id"])
        self.assertIn("warning", data)
        self.assertIsNotNone(data["warning"])

"""Tier-1 tool surface tests for business-logic testing."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any, cast
from unittest import IsolatedAsyncioTestCase


# Mock cvss so the report layer can calculate severity without the real package.
_cvss: Any = ModuleType("cvss")


class _CVSS3:
    def __init__(self, vector: str) -> None:
        self._vector = vector

    def scores(self) -> tuple[float, ...]:
        return (7.5,)

    def severities(self) -> tuple[str, ...]:
        return ("HIGH",)


_cvss.CVSS3 = _CVSS3
sys.modules["cvss"] = _cvss

# Mock the Caido SDK client before importing any tool that touches proxy/caido_api.
_caido_sdk_client: Any = ModuleType("caido_sdk_client")
_caido_sdk_client.Client = object
_caido_sdk_client.TokenAuthOptions = object
_caido_sdk_client.types = ModuleType("caido_sdk_client.types")
_caido_sdk_client.types.ConnectionInfoInput = object
_caido_sdk_client.types.CreateScopeOptions = object
_caido_sdk_client.types.ReplaySendOptions = object
_caido_sdk_client.types.RequestGetOptions = object
_caido_sdk_client.types.UpdateScopeOptions = object
sys.modules["caido_sdk_client"] = _caido_sdk_client
sys.modules["caido_sdk_client.types"] = _caido_sdk_client.types

# Mock the agents SDK (and its submodules) before importing the tool modules.
_agents: Any = ModuleType("agents")
_agents.agent = ModuleType("agents.agent")
_agents.sandbox = ModuleType("agents.sandbox")
_agents.sandbox.capabilities = ModuleType("agents.sandbox.capabilities")
_agents.sandbox.errors = ModuleType("agents.sandbox.errors")
_agents.tool = ModuleType("agents.tool")
_agents_usage: Any = ModuleType("agents.usage")


class _Usage:
    pass


class _ToolsToFinalOutputResult:
    def __init__(self, is_final_output: bool, final_output: Any = None) -> None:
        self.is_final_output = is_final_output
        self.final_output = final_output


class _SandboxAgent:
    pass


class _Filesystem:
    pass


class _Shell:
    pass


class _InvalidManifestPathError(Exception):
    pass


class _CustomTool:
    pass


class _FunctionTool:
    def __init__(self, name: str) -> None:
        self.name = name


class _Tool:
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
        func.name = func.__name__
        return func

    return decorator


_agents.RunContextWrapper = _RunContextWrapper
_agents.function_tool = _function_tool
_agents.agent.ToolsToFinalOutputResult = _ToolsToFinalOutputResult
_agents.sandbox.SandboxAgent = _SandboxAgent
_agents.sandbox.capabilities.Filesystem = _Filesystem
_agents.sandbox.capabilities.Shell = _Shell
_agents.sandbox.errors.InvalidManifestPathError = _InvalidManifestPathError
_agents.tool.CustomTool = _CustomTool
_agents.tool.FunctionTool = _FunctionTool
_agents.tool.Tool = _Tool
sys.modules["agents"] = _agents
sys.modules["agents.agent"] = _agents.agent
sys.modules["agents.sandbox"] = _agents.sandbox
sys.modules["agents.sandbox.capabilities"] = _agents.sandbox.capabilities
sys.modules["agents.sandbox.errors"] = _agents.sandbox.errors
sys.modules["agents.tool"] = _agents.tool
sys.modules["agents.usage"] = _agents_usage

# Mock dedupe so the report layer can run without LLM-based duplicate checks.
_dedupe: Any = ModuleType("strix.report.dedupe")


async def _check_duplicate(_candidate: Any, _existing: Any) -> dict[str, Any]:
    return {"is_duplicate": False}


_dedupe.check_duplicate = _check_duplicate
sys.modules["strix.report.dedupe"] = _dedupe

from strix.agents.factory import _BASE_TOOLS  # noqa: E402
from strix.tools.logic.tools import (  # noqa: E402
    list_flow_invariants,
    propose_business_logic_model,
    read_business_logic_model,
    read_business_logic_violation_result,
    run_business_logic_violation_test,
)


_propose = cast("Any", propose_business_logic_model)
_read = cast("Any", read_business_logic_model)
_list = cast("Any", list_flow_invariants)
_run = cast("Any", run_business_logic_violation_test)
_read_result = cast("Any", read_business_logic_violation_result)


class TestLogicTools(IsolatedAsyncioTestCase):
    """Tool surface tests for the business-logic agent tools."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _model(self) -> dict[str, Any]:
        return {
            "engagement_id": "eng-1",
            "target_id": "example.com",
            "flows": {
                "checkout": {
                    "name": "checkout",
                    "flow_name": "coupon",
                    "request_id": "coupon-req",
                    "bound_invariants": ["step-skip"],
                    "journey": {
                        "name": "checkout",
                        "steps": [
                            {"name": "cart", "order": 0, "request_id": "cart-req"},
                            {
                                "name": "payment",
                                "order": 1,
                                "request_id": "payment-req",
                                "depends_on": ["cart"],
                            },
                        ],
                    },
                }
            },
        }

    def test_tools_registered(self) -> None:
        names = {getattr(t, "name", None) for t in _BASE_TOOLS}
        self.assertIn("propose_business_logic_model", names)
        self.assertIn("read_business_logic_model", names)
        self.assertIn("list_flow_invariants", names)
        self.assertIn("run_business_logic_violation_test", names)
        self.assertIn("read_business_logic_violation_result", names)

    async def test_propose_and_read_model_round_trip(self) -> None:
        ctx = _RunContextWrapper(context={"run_dir": str(self.run_dir)})
        model = self._model()

        propose_raw = await _propose(ctx, "eng-1", "example.com", model)
        propose_parsed = json.loads(propose_raw)
        self.assertTrue(propose_parsed["success"])

        read_raw = await _read(ctx, "eng-1")
        read_parsed = json.loads(read_raw)
        self.assertTrue(read_parsed["success"])
        bound_invariants = read_parsed["model"]["flows"]["checkout"]["bound_invariants"]
        self.assertEqual(bound_invariants, ["step-skip"])

    async def test_list_flow_invariants(self) -> None:
        ctx = _RunContextWrapper(context={"run_dir": str(self.run_dir)})
        await _propose(ctx, "eng-1", "example.com", self._model())

        list_raw = await _list(ctx, "eng-1", "checkout")
        list_parsed = json.loads(list_raw)
        self.assertTrue(list_parsed["success"])
        self.assertEqual(list_parsed["invariants"], ["step-skip"])

    async def test_list_flow_invariants_rejects_missing_flow(self) -> None:
        ctx = _RunContextWrapper(context={"run_dir": str(self.run_dir)})
        await _propose(ctx, "eng-1", "example.com", self._model())

        list_raw = await _list(ctx, "eng-1", "missing")
        list_parsed = json.loads(list_raw)
        self.assertFalse(list_parsed["success"])
        self.assertIn("not found", list_parsed["error"])

    async def test_run_tool_rejects_unknown_invariant(self) -> None:
        ctx = _RunContextWrapper(context={"run_dir": str(self.run_dir)})
        raw = await _run(
            ctx,
            engagement_id="eng-1",
            target_id="example.com",
            target_url="https://example.com",
            flow_name="checkout",
            invariant_kind="not-a-kind",
        )
        parsed = json.loads(raw)
        self.assertFalse(parsed["success"])
        self.assertIn("Unknown invariant kind", parsed["error"])

    async def test_run_and_read_unconfirmed_result(self) -> None:
        ctx = _RunContextWrapper(context={"run_dir": str(self.run_dir)})
        await _propose(ctx, "eng-1", "example.com", self._model())

        run_raw = await _run(
            ctx,
            engagement_id="eng-1",
            target_id="example.com",
            target_url="https://example.com",
            flow_name="checkout",
            invariant_kind="step-skip",
        )
        run_parsed = json.loads(run_raw)
        self.assertTrue(run_parsed["success"])
        self.assertIn("result_id", run_parsed)
        self.assertEqual(run_parsed["verdict"], "unconfirmed")

        read_raw = await _read_result(ctx, "eng-1", run_parsed["result_id"])
        read_parsed = json.loads(read_raw)
        self.assertTrue(read_parsed["success"])
        self.assertEqual(read_parsed["result"]["verdict"], "unconfirmed")

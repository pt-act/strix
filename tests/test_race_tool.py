"""Tool surface and registration tests for the race-condition harness."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any, ClassVar
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import patch


# Ensure we import race-harness modules with our mocks, not with any state
# left over from other test files.
for _stale_race in (
    "strix.core.race",
    "strix.core.race.models",
    "strix.core.race.verdict",
    "strix.core.race.aggregator",
    "strix.core.race.precondition",
    "strix.core.race.dispatch",
    "strix.core.race.collector",
    "strix.core.race.harness",
    "strix.tools.race",
    "strix.tools.race.tools",
):
    sys.modules.pop(_stale_race, None)


# Mock cvss, the agents SDK, and the Caido SDK before importing any tool modules.
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
        func.name = func.__name__
        return func

    return decorator


_agents.RunContextWrapper = _RunContextWrapper
_agents.function_tool = _function_tool
sys.modules["agents"] = _agents
sys.modules["agents.usage"] = _agents_usage

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

# Mock dedupe so the report layer can run without LLM-based duplicate checks.
_dedupe: Any = ModuleType("strix.report.dedupe")


async def _check_duplicate(_candidate: Any, _existing: Any) -> dict[str, Any]:
    return {"is_duplicate": False}


_dedupe.check_duplicate = _check_duplicate

import strix.core.race.dispatch as _dispatch_module
import strix.core.race.harness as _harness_module
import strix.core.race.precondition as _precondition_module
from strix.report.state import (
    ReportState,
    get_global_report_state,
    set_global_report_state,
)
from strix.tools.race.tools import _run_tool as _core_run_tool


if TYPE_CHECKING:
    from strix.core.identity.models import Identity


class _FakeRaceTarget:
    """In-memory target that supports both racy and locked behavior."""

    def __init__(self, locked: bool = False) -> None:
        self._balance = 100
        self._redeem_count = 0
        self._locked = locked
        self._committed = 0

    def reset(self) -> bytes:
        self._balance = 100
        self._redeem_count = 0
        self._committed = 0
        return b"HTTP/1.1 200 OK\r\n\r\nreset"

    def read_state(self) -> bytes:
        body = f'{{"balance": {self._balance}, "redeem_count": {self._redeem_count}}}'
        return b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body.encode("utf-8")

    def redeem(self) -> bytes:
        if self._locked:
            if self._committed == 0:
                self._balance -= 10
                self._redeem_count += 1
                self._committed += 1
                return b"HTTP/1.1 200 OK\r\n\r\nredeemed"
            return b"HTTP/1.1 409 Conflict\r\n\r\nalready used"
        self._balance -= 10
        self._redeem_count += 1
        return b"HTTP/1.1 200 OK\r\n\r\nredeemed"


class _MockCaido:
    def __init__(self, target: _FakeRaceTarget) -> None:
        self._target = target

    def _path_from_raw(self, raw: bytes) -> str:
        line = raw.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        parts = line.split()
        return parts[1] if len(parts) >= 2 else ""

    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        _ = part
        paths = {"setup": "/reset", "state": "/balance", "redeem": "/redeem"}
        path = paths.get(request_id, "/redeem")
        raw = f"GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
        mock = ModuleType("Request")
        mock.request = ModuleType("InnerRequest")
        mock.request.raw = raw
        mock.request.host = "example.com"
        mock.request.is_tls = True
        return mock

    async def get_client(self) -> Any:
        return ModuleType("Client")

    async def replay_send_raw(
        self,
        client: Any,
        *,
        raw: bytes,
        connection: Any,
    ) -> dict[str, Any]:
        _ = client, connection
        path = self._path_from_raw(raw)
        if path == "/reset":
            response_raw = self._target.reset()
        elif path == "/balance":
            response_raw = self._target.read_state()
        else:
            response_raw = self._target.redeem()
        return {
            "session_id": "s-1",
            "status": "DONE",
            "error": None,
            "elapsed_ms": 10,
            "response_raw": response_raw,
        }

    def parse_raw_response(self, raw: bytes | None) -> dict[str, Any] | None:
        if not raw:
            return None
        head, _, body_bytes = raw.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        if not lines:
            return None
        status_parts = lines[0].split(" ", 2)
        if len(status_parts) < 2 or not status_parts[1].isdigit():
            return None
        return {
            "status_code": int(status_parts[1]),
            "length": len(body_bytes),
            "headers": {},
            "body": body_bytes.decode("utf-8", errors="replace"),
            "body_truncated": False,
        }


def _make_replay_for_target(target: _FakeRaceTarget) -> Any:
    """Return a mock replay_as_identity that routes by request_id and drives the target."""
    caido = _MockCaido(target)

    async def _replay_as_identity(
        request_id: str,
        identity: Identity,
        *,
        modifications: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _ = modifications
        view = await caido.view_request(request_id)
        replay = await caido.replay_send_raw(
            await caido.get_client(),
            raw=view.request.raw,
            connection=None,
        )
        parsed = caido.parse_raw_response(replay["response_raw"])
        return {
            "success": replay["status"] == "DONE" and parsed is not None,
            "status": replay["status"],
            "error": replay["error"],
            "session_id": replay["session_id"],
            "elapsed_ms": replay["elapsed_ms"],
            "response": parsed,
            "identity": identity.role,
        }

    return _replay_as_identity


class _FakeContext:
    def __init__(self, run_dir: Path) -> None:
        self.context = {"run_dir": str(run_dir)}


class TestRaceToolRegistration(TestCase):
    """F-10: race harness tool must be reachable through the built agent."""

    RACE_TOOLS: ClassVar[set[str]] = {"run_race_harness"}

    def test_agent_exposes_race_harness_tool(self) -> None:
        # Minimal SDK mock required by build_strix_agent.
        _agents_model_settings: Any = ModuleType("agents.model_settings")
        _agents_model_settings.ModelSettings = type("ModelSettings", (), {})
        sys.modules["agents.model_settings"] = _agents_model_settings

        _agents_agent: Any = ModuleType("agents.agent")
        _agents_agent.ToolsToFinalOutputResult = type(
            "ToolsToFinalOutputResult", (), {"is_final_output": False, "final_output": None}
        )
        sys.modules["agents.agent"] = _agents_agent

        class _Filesystem:
            def __init__(self, configure_tools: Any = None) -> None:
                self.configure_tools = configure_tools

        class _Shell:
            def __init__(self, configure_tools: Any = None) -> None:
                self.configure_tools = configure_tools

        class _SandboxAgent:
            def __init__(self, **kwargs: Any) -> None:
                self.__dict__.update(kwargs)

        _agents_sandbox: Any = ModuleType("agents.sandbox")
        _agents_sandbox.SandboxAgent = _SandboxAgent
        _agents_sandbox.capabilities = ModuleType("agents.sandbox.capabilities")
        _agents_sandbox.capabilities.Filesystem = _Filesystem
        _agents_sandbox.capabilities.Shell = _Shell
        _agents_sandbox.errors = ModuleType("agents.sandbox.errors")
        _agents_sandbox.errors.InvalidManifestPathError = type(
            "InvalidManifestPathError", (Exception,), {}
        )
        sys.modules["agents.sandbox"] = _agents_sandbox
        sys.modules["agents.sandbox.capabilities"] = _agents_sandbox.capabilities
        sys.modules["agents.sandbox.errors"] = _agents_sandbox.errors

        _agents_tool: Any = ModuleType("agents.tool")
        _agents_tool.Tool = type("Tool", (), {})
        _agents_tool.FunctionTool = type("FunctionTool", (), {})
        _agents_tool.CustomTool = type("CustomTool", (), {})
        sys.modules["agents.tool"] = _agents_tool

        # Clear stale agent/factory namespaces so the factory re-imports from the
        # freshly mocked agents modules.
        for _stale in ("strix.agents", "strix.agents.factory"):
            sys.modules.pop(_stale, None)

        # Clear stale proxy namespace so the factory imports real strix.tools.proxy.
        for _stale in ("strix.tools.proxy", "strix.tools.proxy.caido_api"):
            sys.modules.pop(_stale, None)

        from strix.agents.factory import build_strix_agent

        def _tool_names(agent: Any) -> set[str]:
            return {str(getattr(t, "name", getattr(t, "__name__", ""))) for t in agent.tools}

        agent = build_strix_agent(is_root=True, is_whitebox=False)
        self.assertTrue(self.RACE_TOOLS.issubset(_tool_names(agent)))


class TestRaceToolEndToEnd(IsolatedAsyncioTestCase):
    """End-to-end tests for the race-harness tool surface."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir()
        self.previous_state = get_global_report_state()
        self.report_state = ReportState(run_name=self.run_dir.name)
        self.report_state._run_dir = self.run_dir
        set_global_report_state(self.report_state)
        self._dedupe_patcher = patch.dict(sys.modules, {"strix.report.dedupe": _dedupe})
        self._dedupe_patcher.start()
        self._state_patcher = patch(
            "strix.report.state.get_global_report_state",
            return_value=self.report_state,
        )
        self._state_patcher.start()

        # Seed the identity store with a user identity for the target.
        from strix.core.identity import IdentityStore, identity_store_path
        from strix.core.identity.models import Freshness, Identity

        store = IdentityStore(identity_store_path(self.run_dir))
        store.upsert_identity(
            Identity(
                target_key="example.com",
                role="user",
                cookies={"session": "user-session"},
                tokens={"Authorization": "Bearer user-token"},
                headers={"X-Custom": "user"},
                provenance="proxy_capture",
                freshness=Freshness(captured_at="2026-06-15T00:00:00Z", status="fresh"),
            )
        )
        store.close()

    def tearDown(self) -> None:
        self._state_patcher.stop()
        self._dedupe_patcher.stop()
        set_global_report_state(self.previous_state)
        self.tmp.cleanup()

    async def _run_tool(
        self,
        target: _FakeRaceTarget,
        n: int = 3,
        scope_rules: list[str] | None = None,
    ) -> dict[str, Any]:
        mock = _MockCaido(target)
        mock_replay = _make_replay_for_target(target)
        ctx = _FakeContext(self.run_dir)
        with (
            patch.object(_harness_module.caido_api, "view_request", new=mock.view_request),
            patch.object(_precondition_module, "replay_as_identity", new=mock_replay),
            patch.object(_dispatch_module, "replay_as_identity", new=mock_replay),
            patch.object(_harness_module, "replay_as_identity", new=mock_replay),
        ):
            return await _core_run_tool(
                ctx,
                request_id="redeem",
                precondition={
                    "description": "coupon C unredeemed, balance=100",
                    "setup_request_id": "setup",
                    "state_read_request_id": "state",
                    "success_indicator": "redeemed",
                },
                target_key="example.com",
                identity_role="user",
                n=n,
                jitter_ms=0,
                retry_bound=1,
                scope_rules=scope_rules,
            )

    async def test_double_redemption_finds_race_and_files_report(self) -> None:
        result = await self._run_tool(_FakeRaceTarget(locked=False), n=3)
        self.assertTrue(result["success"])
        self.assertEqual(result["verdict"], "race")
        self.assertEqual(result["commit_count"], 3)
        self.assertIsNotNone(result["report"])
        self.assertEqual(result["report"]["evidence_class"], "race_result")

        persisted = next(
            (
                r
                for r in self.report_state.vulnerability_reports
                if r["id"] == result["report"]["report_id"]
            ),
            None,
        )
        self.assertIsNotNone(persisted)
        assert persisted is not None
        self.assertEqual(persisted["evidence_class"], "race_result")
        self.assertTrue(
            any(a.get("artifact_type") == "state_delta" for a in persisted.get("artifacts", []))
        )

    async def test_locked_target_reports_safe_no_finding(self) -> None:
        result = await self._run_tool(_FakeRaceTarget(locked=True), n=3)
        self.assertTrue(result["success"])
        self.assertEqual(result["verdict"], "safe")
        self.assertEqual(result["commit_count"], 1)
        self.assertIsNone(result["report"])

        race_reports = [
            r
            for r in self.report_state.vulnerability_reports
            if r.get("evidence_class") == "race_result"
        ]
        self.assertEqual(race_reports, [])

    async def test_scope_refusal_no_requests_sent(self) -> None:
        result = await self._run_tool(
            _FakeRaceTarget(locked=False),
            n=2,
            scope_rules=["other.com"],
        )
        self.assertFalse(result["success"])
        self.assertIn("scoped refusal", result["error"].lower())


if __name__ == "__main__":
    import unittest

    unittest.main()

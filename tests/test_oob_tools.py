"""Tier-1, Tier-2, and end-to-end tests for the OOB agent tool surface."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st


# Mock cvss so _do_create can calculate a severity without requiring the real
# cvss package in the test environment.
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

# Mock the agents SDK before importing the OOB tool modules so the
# function_tool decorator becomes a no-op and RunContextWrapper is a simple
# dataclass stand-in. This keeps tests lightweight and offline.
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

from strix.core.oob.models import OobHit  # noqa: E402
from strix.report.state import (  # noqa: E402
    ReportState,
    get_global_report_state,
    set_global_report_state,
)
from strix.tools.oob.tools import (  # noqa: E402
    confirm_oob_callback,
    mint_oob_token,
    poll_oob_callbacks,
    report_oob_confirmed_candidate,
)


# Mock the dedupe module so the report layer does not invoke LLM-based
# deduplication during unit tests. We patch sys.modules per test because the
# real module imports from agents.models and is not available in the offline
# test environment.
_dedupe: Any = ModuleType("strix.report.dedupe")


async def _check_duplicate(_candidate: Any, _existing: Any) -> dict[str, Any]:
    return {"is_duplicate": False}


_dedupe.check_duplicate = _check_duplicate


_ID_ALPHABET = st.characters(whitelist_categories=("L", "N"))
_ID = st.text(min_size=1, max_size=32, alphabet=_ID_ALPHABET)


class _FakeOobProvider:
    """In-memory OOB provider for tool tests; never spawns interactsh."""

    def __init__(self, base_host: str = "abc123.oast.pro") -> None:
        self._base_host = base_host
        self._hits: list[OobHit] = []
        self._ready = True

    def ready(self) -> bool:
        return self._ready

    def set_ready(self, ready: bool) -> None:
        self._ready = ready

    def base_host(self) -> str:
        return self._base_host

    async def poll_interactions(self) -> list[OobHit]:
        return list(self._hits)

    def add_hit(self, hit: OobHit) -> None:
        self._hits.append(hit)


def _ctx(run_dir: Path, provider: _FakeOobProvider | None = None) -> _RunContextWrapper:
    inner: dict[str, Any] = {"run_dir": str(run_dir)}
    if provider is not None:
        inner["oob_provider"] = provider
    return _RunContextWrapper(context=inner)


def _report_fields() -> dict[str, Any]:
    return {
        "title": "SSRF via OOB callback",
        "description": "The image import endpoint fetched an attacker-controlled URL.",
        "impact": "Internal network enumeration and unauthorized resource access.",
        "target": "https://example.com",
        "technical_analysis": "The injected token host was resolved and requested by the server.",
        "poc_description": "Submit the OOB token URL to the image import endpoint.",
        "poc_script_code": "curl -X POST https://example.com/import -d 'url=<token-host>'",
        "remediation_steps": "Validate and sanitize all outbound URLs server-side.",
    }


class TestOobTools(IsolatedAsyncioTestCase):
    """Focused offline tests for mint/confirm/poll tools."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    async def test_mint_oob_token_returns_token_and_host(self) -> None:
        provider = _FakeOobProvider()
        ctx = _ctx(self.run_dir, provider)
        result = await mint_oob_token(ctx, "eng1", "cand1", "req1")
        payload = json.loads(result)

        self.assertTrue(payload["success"])
        self.assertIn("token", payload)
        self.assertIn("abc123.oast.pro", payload["injectable_host"])
        self.assertEqual(payload["engagement_id"], "eng1")
        self.assertEqual(payload["candidate_id"], "cand1")
        self.assertEqual(payload["payload_class"], "dns")
        self.assertEqual(payload["window_seconds"], 300)

    async def test_mint_oob_token_rejects_dead_provider(self) -> None:
        provider = _FakeOobProvider()
        provider.set_ready(False)
        ctx = _ctx(self.run_dir, provider)
        with self.assertRaises(RuntimeError):
            await mint_oob_token(ctx, "eng1", "cand1", "req1")

    async def test_poll_oob_callbacks_correlates_seeded_hit(self) -> None:
        provider = _FakeOobProvider()
        ctx = _ctx(self.run_dir, provider)
        mint_result = await mint_oob_token(ctx, "eng1", "cand1", "req1")
        token = json.loads(mint_result)["token"]

        provider.add_hit(
            OobHit(
                protocol="dns",
                token=token,
                full_fqdn=f"{token}.abc123.oast.pro",
                source_ip="1.2.3.4",
                timestamp=datetime.now(UTC),
            )
        )

        result = await poll_oob_callbacks(ctx, "eng1")
        payload = json.loads(result)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["hits"], 1)
        self.assertEqual(payload["records"][0]["status"], "confirmed")
        self.assertEqual(payload["records"][0]["token"], token)

    async def test_poll_oob_callbacks_limits_hits(self) -> None:
        provider = _FakeOobProvider()
        ctx = _ctx(self.run_dir, provider)
        mint_result = await mint_oob_token(ctx, "eng1", "cand1", "req1")
        token = json.loads(mint_result)["token"]

        for i in range(3):
            provider.add_hit(
                OobHit(
                    protocol="dns",
                    token=token,
                    full_fqdn=f"{token}.abc123.oast.pro",
                    source_ip=f"1.2.3.{i}",
                    timestamp=datetime.now(UTC),
                )
            )

        result = await poll_oob_callbacks(ctx, "eng1", limit=2)
        payload = json.loads(result)
        self.assertEqual(payload["hits"], 2)
        self.assertEqual(len(payload["records"]), 2)

    async def test_confirm_oob_callback_confirms_matching_hit(self) -> None:
        provider = _FakeOobProvider()
        ctx = _ctx(self.run_dir, provider)
        mint_result = await mint_oob_token(ctx, "eng1", "cand1", "req1")
        token = json.loads(mint_result)["token"]

        provider.add_hit(
            OobHit(
                protocol="dns",
                token=token,
                full_fqdn=f"{token}.abc123.oast.pro",
                source_ip="1.2.3.4",
                timestamp=datetime.now(UTC),
            )
        )

        result = await confirm_oob_callback(ctx, "eng1", "cand1")
        payload = json.loads(result)
        self.assertEqual(payload["verdict"], "confirmed")
        self.assertEqual(payload["record"]["status"], "confirmed")
        self.assertEqual(payload["record"]["token"], token)

    async def test_confirm_oob_callback_unconfirmed_without_hit(self) -> None:
        provider = _FakeOobProvider()
        ctx = _ctx(self.run_dir, provider)
        await mint_oob_token(ctx, "eng1", "cand1", "req1")

        result = await confirm_oob_callback(ctx, "eng1", "cand1")
        payload = json.loads(result)
        self.assertEqual(payload["verdict"], "unconfirmed")
        self.assertEqual(payload["reason"], "no correlated callback in window")

    async def test_confirm_oob_callback_unconfirmed_without_mint(self) -> None:
        provider = _FakeOobProvider()
        ctx = _ctx(self.run_dir, provider)

        result = await confirm_oob_callback(ctx, "eng1", "cand1")
        payload = json.loads(result)
        self.assertEqual(payload["verdict"], "unconfirmed")
        self.assertEqual(payload["reason"], "no token minted for candidate")

    async def test_missing_run_dir_raises(self) -> None:
        ctx = _RunContextWrapper(context={})
        with self.assertRaises(RuntimeError):
            await mint_oob_token(ctx, "eng1", "cand1", "req1")


class TestOobPromotionPBT(TestCase):
    """Property-based invariants for the OOB promotion gate."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
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

    def tearDown(self) -> None:
        self._state_patcher.stop()
        self._dedupe_patcher.stop()
        set_global_report_state(self.previous_state)
        self.tmp.cleanup()

    async def _promote_with_hit(
        self,
        engagement_id: str,
        candidate_id: str,
        source_ip: str,
    ) -> dict[str, Any]:
        set_global_report_state(self.report_state)
        provider = _FakeOobProvider()
        ctx = _ctx(self.run_dir, provider)
        mint_result = await mint_oob_token(ctx, engagement_id, candidate_id, "req-1")
        token = json.loads(mint_result)["token"]
        provider.add_hit(
            OobHit(
                protocol="dns",
                token=token,
                full_fqdn=f"{token}.abc123.oast.pro",
                source_ip=source_ip,
                timestamp=datetime.now(UTC),
            )
        )
        result = await report_oob_confirmed_candidate(
            ctx, engagement_id, candidate_id, **_report_fields()
        )
        return json.loads(result)

    @settings(max_examples=50, deadline=None)
    @given(
        engagement_id=_ID,
        candidate_id=_ID,
        source_ip=st.ip_addresses().map(str),
    )
    def test_confirmation_soundness(
        self,
        engagement_id: str,
        candidate_id: str,
        source_ip: str,
    ) -> None:
        """Invariant 2: every promoted candidate has a correlated callback."""
        payload = asyncio.run(self._promote_with_hit(engagement_id, candidate_id, source_ip))
        self.assertEqual(payload["verdict"], "confirmed")
        self.assertIn("report", payload)
        self.assertEqual(payload["report"]["evidence_class"], "callback")
        self.assertEqual(payload["report"]["impact_gate_decision"], "kept_from_cvss")

        report_id = payload["report"]["report_id"]
        persisted = next(
            (r for r in self.report_state.vulnerability_reports if r["id"] == report_id),
            None,
        )
        self.assertIsNotNone(persisted)
        assert persisted is not None
        self.assertEqual(persisted["evidence_class"], "callback")
        artifacts = persisted.get("artifacts", [])
        self.assertTrue(any(a.get("artifact_type") == "oob_callback" for a in artifacts))

    async def _promote_without_hit(
        self,
        engagement_id: str,
        candidate_id: str,
    ) -> dict[str, Any]:
        set_global_report_state(self.report_state)
        provider = _FakeOobProvider()
        ctx = _ctx(self.run_dir, provider)
        await mint_oob_token(ctx, engagement_id, candidate_id, "req-1")
        result = await report_oob_confirmed_candidate(
            ctx, engagement_id, candidate_id, **_report_fields()
        )
        return json.loads(result)

    @settings(max_examples=50, deadline=None)
    @given(
        engagement_id=_ID,
        candidate_id=_ID,
    )
    def test_no_false_confirm(
        self,
        engagement_id: str,
        candidate_id: str,
    ) -> None:
        """Invariant 3: no callback in window → candidate is not reported confirmed."""
        payload = asyncio.run(self._promote_without_hit(engagement_id, candidate_id))
        self.assertEqual(payload["verdict"], "unconfirmed")
        self.assertNotIn("report", payload)
        reports = [
            r
            for r in self.report_state.vulnerability_reports
            if r.get("evidence_class") == "callback"
        ]
        self.assertEqual(reports, [])


class TestOobEndToEnd(IsolatedAsyncioTestCase):
    """End-to-end OOB confirmation scenarios."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
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

    def tearDown(self) -> None:
        self._state_patcher.stop()
        self._dedupe_patcher.stop()
        set_global_report_state(self.previous_state)
        self.tmp.cleanup()

    async def _mint(self, provider: _FakeOobProvider, candidate_id: str) -> str:
        set_global_report_state(self.report_state)
        ctx = _ctx(self.run_dir, provider)
        mint_result = await mint_oob_token(ctx, "eng-e2e", candidate_id, "req-e2e")
        return json.loads(mint_result)["token"]

    async def _promote(self, provider: _FakeOobProvider, candidate_id: str) -> dict[str, Any]:
        set_global_report_state(self.report_state)
        ctx = _ctx(self.run_dir, provider)
        result = await report_oob_confirmed_candidate(
            ctx, "eng-e2e", candidate_id, **_report_fields()
        )
        return json.loads(result)

    def _persisted_report(self, report_id: str) -> dict[str, Any] | None:
        return next(
            (r for r in self.report_state.vulnerability_reports if r["id"] == report_id),
            None,
        )

    async def test_ssrf_token_url_fires_confirmed(self) -> None:
        provider = _FakeOobProvider()
        token = await self._mint(provider, "ssrf-candidate")
        provider.add_hit(
            OobHit(
                protocol="http",
                token=token,
                full_fqdn=f"{token}.abc123.oast.pro",
                source_ip="1.2.3.4",
                timestamp=datetime.now(UTC),
                raw_request=b"GET / HTTP/1.1",
            )
        )

        payload = await self._promote(provider, "ssrf-candidate")
        self.assertEqual(payload["verdict"], "confirmed")
        self.assertEqual(payload["report"]["evidence_class"], "callback")

        persisted = self._persisted_report(payload["report"]["report_id"])
        self.assertIsNotNone(persisted)
        assert persisted is not None
        artifacts = persisted.get("artifacts", [])
        self.assertTrue(
            any(
                a.get("artifact_type") == "oob_callback"
                and a.get("data", {}).get("status") == "confirmed"
                for a in artifacts
            )
        )

    async def test_blind_xxe_dns_entity_resolves_confirmed(self) -> None:
        provider = _FakeOobProvider()
        token = await self._mint(provider, "xxe-candidate")
        provider.add_hit(
            OobHit(
                protocol="dns",
                token=token,
                full_fqdn=f"{token}.abc123.oast.pro",
                source_ip="1.2.3.4",
                timestamp=datetime.now(UTC),
                raw_request=b"dns query for xxe entity",
            )
        )

        payload = await self._promote(provider, "xxe-candidate")
        self.assertEqual(payload["verdict"], "confirmed")
        self.assertEqual(payload["report"]["evidence_class"], "callback")

        persisted = self._persisted_report(payload["report"]["report_id"])
        self.assertIsNotNone(persisted)
        assert persisted is not None
        artifacts = persisted.get("artifacts", [])
        self.assertTrue(any(a.get("artifact_type") == "oob_callback" for a in artifacts))

    async def test_token_never_fires_stays_unconfirmed_no_finding(self) -> None:
        provider = _FakeOobProvider()
        await self._mint(provider, "silent-candidate")

        payload = await self._promote(provider, "silent-candidate")
        self.assertEqual(payload["verdict"], "unconfirmed")
        self.assertEqual(payload["reason"], "no correlated callback in window")
        self.assertNotIn("report", payload)

        callback_reports = [
            r
            for r in self.report_state.vulnerability_reports
            if r.get("evidence_class") == "callback"
        ]
        self.assertEqual(callback_reports, [])


if __name__ == "__main__":
    import unittest

    unittest.main()

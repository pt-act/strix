"""Tier-1 tests for the OOB agent tool surface."""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import IsolatedAsyncioTestCase


# Mock the agents SDK before importing the OOB tool modules so the
# function_tool decorator becomes a no-op and RunContextWrapper is a simple
# dataclass stand-in. This keeps tests lightweight and offline.
_agents: Any = ModuleType("agents")


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

from strix.core.oob.models import OobHit  # noqa: E402
from strix.tools.oob.tools import (  # noqa: E402
    confirm_oob_callback,
    mint_oob_token,
    poll_oob_callbacks,
)


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


if __name__ == "__main__":
    import unittest

    unittest.main()

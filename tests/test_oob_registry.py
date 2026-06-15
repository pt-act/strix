"""Tier-1 and Tier-2 tests for the OOB token registry."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import TestCase

from hypothesis import given, settings
from hypothesis import strategies as st

from strix.core.oob.registry import TokenRegistry


_ID_ALPHABET = st.characters(whitelist_categories=("L", "N"))
_ID = st.text(min_size=1, max_size=32, alphabet=_ID_ALPHABET)


class TestTokenRegistryTier1(TestCase):
    """Focused behaviour tests for the OOB token registry."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "oob_registry.sqlite"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_mint_yields_unique_injectable_host_bound_to_candidate(self) -> None:
        registry = TokenRegistry(self.db_path)
        try:
            mint = registry.mint(
                "eng-1",
                "candidate-A",
                "req-1",
                base_host="oast.pro",
                provider_ready=True,
                window_seconds=60,
            )
        finally:
            registry.close()

        self.assertTrue(mint.injectable_host.endswith(".oast.pro"))
        self.assertEqual(mint.engagement_id, "eng-1")
        self.assertEqual(mint.candidate_id, "candidate-A")
        self.assertEqual(mint.request_ref, "req-1")
        self.assertEqual(mint.window_seconds, 60)
        self.assertGreater(len(mint.token), 16)

    def test_mint_rejected_when_provider_not_ready(self) -> None:
        registry = TokenRegistry(self.db_path)
        try:
            with self.assertRaises(RuntimeError) as ctx:
                registry.mint(
                    "eng-1",
                    "candidate-A",
                    "req-1",
                    base_host="oast.pro",
                    provider_ready=False,
                )
            self.assertIn("not ready", str(ctx.exception).lower())
        finally:
            registry.close()

    def test_registry_survives_reopen_within_engagement(self) -> None:
        registry = TokenRegistry(self.db_path)
        try:
            mint = registry.mint(
                "eng-1",
                "candidate-A",
                "req-1",
                base_host="oast.pro",
                provider_ready=True,
            )
        finally:
            registry.close()

        reopened = TokenRegistry(self.db_path)
        try:
            looked_up = reopened.lookup(mint.token)
            self.assertIsNotNone(looked_up)
            assert looked_up is not None
            self.assertEqual(looked_up.candidate_id, "candidate-A")
            self.assertEqual(looked_up.injectable_host, mint.injectable_host)
            self.assertEqual(len(reopened.list_mints("eng-1")), 1)
            self.assertEqual(reopened.list_mints("eng-2"), [])
        finally:
            reopened.close()


class TestTokenRegistryTier2PBT(TestCase):
    """Property-based security invariants for the token registry."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "oob_registry.sqlite"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @settings(max_examples=50, deadline=None)
    @given(
        engagement_id=_ID,
        candidate_id=_ID,
    )
    def test_token_uniqueness_and_binding(self, engagement_id: str, candidate_id: str) -> None:
        registry = TokenRegistry(self.db_path)
        try:
            mint_a = registry.mint(
                engagement_id,
                candidate_id,
                "req-1",
                base_host="oast.pro",
                provider_ready=True,
            )
            mint_b = registry.mint(
                engagement_id,
                candidate_id,
                "req-2",
                base_host="oast.pro",
                provider_ready=True,
            )
            self.assertNotEqual(mint_a.token, mint_b.token)
            self.assertNotEqual(mint_a.injectable_host, mint_b.injectable_host)

            looked_up = registry.lookup(mint_a.token)
            self.assertIsNotNone(looked_up)
            assert looked_up is not None
            self.assertEqual(looked_up.token, mint_a.token)
            self.assertEqual(looked_up.candidate_id, candidate_id)
            self.assertEqual(looked_up.engagement_id, engagement_id)
        finally:
            registry.close()

    def test_live_oracle_minting(self) -> None:
        registry = TokenRegistry(self.db_path)
        try:
            with self.assertRaises(RuntimeError):
                registry.mint(
                    "eng-1",
                    "candidate-A",
                    "req-1",
                    base_host="oast.pro",
                    provider_ready=False,
                )
            # No rows should be written after a rejected mint.
            self.assertEqual(registry.list_mints("eng-1"), [])
        finally:
            registry.close()


if __name__ == "__main__":
    import unittest

    unittest.main()

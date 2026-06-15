"""Tier-1 and Tier-2 tests for the OOB correlator."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest import TestCase

from hypothesis import given, settings
from hypothesis import strategies as st

from strix.core.oob.correlator import Correlator
from strix.core.oob.models import OobHit
from strix.core.oob.registry import TokenRegistry


_ID_ALPHABET = st.characters(whitelist_categories=("L", "N"))
_ID = st.text(min_size=1, max_size=32, alphabet=_ID_ALPHABET)


class TestCorrelatorTier1(TestCase):
    """Focused behaviour tests for the OOB correlation engine."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "oob_registry.sqlite"
        self.registry = TokenRegistry(self.db_path)

    def tearDown(self) -> None:
        self.registry.close()
        self.tmp.cleanup()

    def test_minted_token_hit_confirms_candidate(self) -> None:
        mint = self.registry.mint(
            "eng-1",
            "candidate-A",
            "req-1",
            base_host="oast.pro",
            provider_ready=True,
            window_seconds=60,
        )
        hit = OobHit(
            protocol="dns",
            token=mint.token,
            full_fqdn=mint.injectable_host,
            source_ip="1.2.3.4",
            timestamp=datetime.now(UTC),
            raw_request=b"dns query",
        )
        correlator = Correlator(self.registry)
        record = correlator.correlate(hit, "eng-1")

        self.assertEqual(record.status, "confirmed")
        self.assertEqual(record.candidate_id, "candidate-A")
        self.assertEqual(record.engagement_id, "eng-1")
        self.assertEqual(record.token, mint.token)
        self.assertIn("within the token window", record.rationale)

    def test_unminted_token_hit_is_quarantined(self) -> None:
        hit = OobHit(
            protocol="dns",
            token="unminted-token-123",  # noqa: S106
            full_fqdn="unminted-token-123.oast.pro",
            source_ip="1.2.3.4",
            timestamp=datetime.now(UTC),
        )
        correlator = Correlator(self.registry)
        record = correlator.correlate(hit, "eng-1")

        self.assertEqual(record.status, "quarantined")
        self.assertIsNone(record.candidate_id)
        self.assertIsNone(record.engagement_id)
        self.assertIn("quarantined", record.rationale)

    def test_foreign_engagement_token_never_attributed(self) -> None:
        mint = self.registry.mint(
            "eng-1",
            "candidate-A",
            "req-1",
            base_host="oast.pro",
            provider_ready=True,
        )
        hit = OobHit(
            protocol="dns",
            token=mint.token,
            full_fqdn=mint.injectable_host,
            source_ip="1.2.3.4",
            timestamp=datetime.now(UTC),
        )
        correlator = Correlator(self.registry)
        record = correlator.correlate(hit, "eng-2")

        self.assertEqual(record.status, "foreign")
        self.assertIsNone(record.candidate_id)
        self.assertEqual(record.engagement_id, "eng-1")


class TestCorrelatorTier2PBT(TestCase):
    """Property-based security invariants for correlation."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "oob_registry.sqlite"
        self.registry = TokenRegistry(self.db_path)

    def tearDown(self) -> None:
        self.registry.close()
        self.tmp.cleanup()

    @settings(max_examples=50, deadline=None)
    @given(
        engagement_id=_ID,
        candidate_id=_ID,
        source_ip=st.ip_addresses().map(str),
    )
    def test_correlation_correctness(
        self,
        engagement_id: str,
        candidate_id: str,
        source_ip: str,
    ) -> None:
        mint = self.registry.mint(
            engagement_id,
            candidate_id,
            "req-1",
            base_host="oast.pro",
            provider_ready=True,
        )
        hit = OobHit(
            protocol="dns",
            token=mint.token,
            full_fqdn=mint.injectable_host,
            source_ip=source_ip,
            timestamp=datetime.now(UTC),
        )
        correlator = Correlator(self.registry)
        record = correlator.correlate(hit, engagement_id)

        self.assertEqual(record.status, "confirmed")
        self.assertEqual(record.candidate_id, candidate_id)
        self.assertEqual(record.engagement_id, engagement_id)

    def test_token_unforgeability_scoping(self) -> None:
        mint = self.registry.mint(
            "eng-1",
            "candidate-A",
            "req-1",
            base_host="oast.pro",
            provider_ready=True,
        )
        hit = OobHit(
            protocol="dns",
            token=mint.token,
            full_fqdn=mint.injectable_host,
            source_ip="1.2.3.4",
            timestamp=datetime.now(UTC),
        )
        correlator = Correlator(self.registry)
        record = correlator.correlate(hit, "eng-2")
        self.assertEqual(record.status, "foreign")

        unminted = OobHit(
            protocol="dns",
            token="forged-token",  # noqa: S106
            full_fqdn="forged-token.oast.pro",
            source_ip="1.2.3.4",
            timestamp=datetime.now(UTC),
        )
        record = correlator.correlate(unminted, "eng-1")
        self.assertEqual(record.status, "quarantined")


if __name__ == "__main__":
    import unittest

    unittest.main()

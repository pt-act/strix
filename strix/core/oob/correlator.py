"""Deterministic OOB hit-to-candidate correlation engine.

The correlator is pure over (mint-log, hit-log). It never attributes an unminted
or foreign-engagement token; such hits are returned as ``quarantined`` or
``foreign`` and must never be dropped.
"""

from __future__ import annotations

from typing import Literal

from strix.core.oob.models import CorrelationRecord, OobHit
from strix.core.oob.registry import TokenRegistry  # noqa: TC001


CorrelationStatus = Literal["confirmed", "quarantined", "foreign", "expired"]


class Correlator:
    """Attribute an inbound OOB hit to its minted candidate, if any."""

    def __init__(self, registry: TokenRegistry) -> None:
        self._registry = registry

    def correlate(self, hit: OobHit, engagement_id: str) -> CorrelationRecord:
        """Return a deterministic correlation decision for one hit.

        Args:
            hit: The captured OOB interaction.
            engagement_id: The engagement boundary; hits for tokens minted in
                another engagement are marked ``foreign``.
        """
        mint = self._registry.lookup(hit.token)
        if mint is None:
            return CorrelationRecord(
                status="quarantined",
                token=hit.token,
                hit=hit,
                candidate_id=None,
                engagement_id=None,
                latency_ms=0.0,
                rationale="Token was never minted by this registry; hit quarantined.",
            )

        if mint.engagement_id != engagement_id:
            return CorrelationRecord(
                status="foreign",
                token=hit.token,
                hit=hit,
                candidate_id=None,
                engagement_id=mint.engagement_id,
                latency_ms=0.0,
                rationale="Token belongs to a different engagement; hit never attributed here.",
            )

        latency_ms = (hit.timestamp - mint.created_at).total_seconds() * 1000.0
        if hit.timestamp > mint.expires_at():
            return CorrelationRecord(
                status="expired",
                token=hit.token,
                hit=hit,
                candidate_id=mint.candidate_id,
                engagement_id=mint.engagement_id,
                latency_ms=latency_ms,
                rationale="Hit arrived after the token window expired.",
            )

        return CorrelationRecord(
            status="confirmed",
            token=hit.token,
            hit=hit,
            candidate_id=mint.candidate_id,
            engagement_id=mint.engagement_id,
            latency_ms=latency_ms,
            rationale="Hit correlates to the minted candidate within the token window.",
        )

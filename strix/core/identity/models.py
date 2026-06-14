"""Locked identity record model for Phase 1."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field


Provenance = Literal["proxy_capture", "login_flow", "imported", "reserved"]
FreshnessStatus = Literal["fresh", "stale", "expired"]


class Freshness(BaseModel):
    """Freshness metadata for an identity."""

    captured_at: str
    expires_hint: str | None = None
    status: FreshnessStatus = "fresh"

    model_config = {"extra": "forbid"}


class Identity(BaseModel):
    """Per-target authenticated identity record.

    Fields are locked by the Phase 1 kickoff contract. Credential-bearing
    fields (``cookies``, ``tokens``, ``headers``) must be redacted before any
    agent-facing serialization.
    """

    target_key: str
    role: str
    cookies: dict[str, str] = Field(default_factory=dict)
    tokens: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    provenance: Provenance
    freshness: Freshness
    is_reserved_expired: bool = False

    model_config = {"extra": "forbid"}

    def is_authorized(self) -> bool:
        """Return whether this identity may be treated as authorized.

        The reserved ``expired`` pseudo-identity and any identity whose
        freshness is ``expired`` are never authorized.
        """
        return not self.is_reserved_expired and self.freshness.status != "expired"

    @classmethod
    def reserved_expired(cls, target_key: str) -> Identity:
        """Create the reserved ``expired`` pseudo-identity for a target."""
        return cls(
            target_key=target_key,
            role="expired",
            cookies={},
            tokens={},
            headers={},
            provenance="reserved",
            freshness=Freshness(
                captured_at=datetime.now(UTC).isoformat(),
                status="expired",
            ),
            is_reserved_expired=True,
        )

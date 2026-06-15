"""Data models for the out-of-band oracle.

All timestamp fields are timezone-aware UTC. The registry stores mints and
hits durably; the correlator produces CorrelationRecord values from those logs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal


@dataclass(frozen=True)
class OobConfig:
    """Configuration for an OOB provider.

    ``server_url`` is ``None`` for public ProjectDiscovery interactsh servers;
    a non-empty value points to a self-hosted interactsh-server instance.
    """

    server_url: str | None = None
    auth_token: str | None = None


@dataclass(frozen=True)
class OobHit:
    """A single inbound interaction captured by the OOB listener."""

    protocol: Literal["dns", "http", "https", "smtp"]
    token: str
    full_fqdn: str
    source_ip: str
    timestamp: datetime
    raw_request: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MintRecord:
    """A token minted for exactly one candidate in one engagement."""

    token: str
    engagement_id: str
    candidate_id: str
    request_ref: str
    injectable_host: str
    created_at: datetime
    window_seconds: int

    def expires_at(self) -> datetime:
        return self.created_at + timedelta(seconds=self.window_seconds)


@dataclass(frozen=True)
class CorrelationRecord:
    """The deterministic result of correlating one OobHit with the mint log."""

    status: Literal["confirmed", "quarantined", "foreign", "expired"]
    token: str
    hit: OobHit
    candidate_id: str | None
    engagement_id: str | None
    latency_ms: float
    rationale: str

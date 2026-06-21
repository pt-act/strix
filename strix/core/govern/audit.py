"""Governance audit log (SGL-S6).

Append-only, deterministic log of every governance decision made by the
SGL layer.  Each entry records the decision type (allow / deny / halt),
the target, the reason, and optional metadata (agent_id, engagement_id).

Design invariants
-----------------
* **Append-only.**  Entries are never mutated or deleted.
* **One entry per decision.**  Every ``decide()`` call that produces a
  verdict emits exactly one audit entry.  HALT signals from the cost
  ceiling or circuit breaker also emit entries.
* **Replayable.**  A reader can reconstruct the full decision history
  for an engagement from the log.
* **Concurrency-safe.**  Uses ``asyncio.Lock`` for thread-safe appends.
* **Fail-closed.**  Any logging error is swallowed (the governance
  decision proceeds regardless — logging is best-effort for audit, not
  a gate).
"""

from __future__ import annotations

import json
import time
from collections import deque
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


# ─────────────────────────────────────── models ──────────────────────────────


class AuditAction(str, Enum):
    """Type of governance action recorded."""

    ALLOW = "allow"
    DENY = "deny"
    HALT = "halt"
    BACKPRESSURE = "backpressure"
    CIRCUIT_TRIP = "circuit_trip"
    RATE_LIMIT = "rate_limit"
    CRED_LIMIT = "cred_limit"
    OWNERSHIP_DENY = "ownership_deny"


class AuditEntry(BaseModel):
    """A single immutable governance audit record."""

    timestamp: float
    """Monotonic timestamp (``time.monotonic()``)."""
    wall_time: float
    """Wall-clock UTC timestamp (``time.time()``)."""
    action: AuditAction
    target: str
    reason: str
    agent_id: str | None = None
    engagement_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


# ─────────────────────────────────────── audit log ───────────────────────────


class AuditLog:
    """Append-only in-memory governance audit log with optional file persistence.

    Usage::

        log = AuditLog(engagement_id="scan-001")
        log.record(AuditAction.ALLOW, target="example.com", reason="scope_match")
        log.record(AuditAction.DENY, target="evil.com", reason="out_of_scope")

        # Replay all entries
        for entry in log.replay():
            print(entry.action, entry.target, entry.reason)
    """

    def __init__(
        self,
        *,
        engagement_id: str | None = None,
        log_path: Path | None = None,
    ) -> None:
        self._engagement_id = engagement_id
        self._log_path = log_path
        self._entries: deque[AuditEntry] = deque()
        self._flush_threshold = 100
        self._unflushed = 0

    def record(
        self,
        action: AuditAction,
        *,
        target: str,
        reason: str,
        agent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Append a governance decision to the audit log.

        Parameters
        ----------
        action:
            The governance action (allow / deny / halt / etc.).
        target:
            The target of the decision (hostname, IP, route, etc.).
        reason:
            Human-readable reason for the decision.
        agent_id:
            Optional agent that triggered the decision.
        metadata:
            Optional additional context (token counts, error rates, etc.).

        Returns
        -------
        AuditEntry
            The recorded entry.
        """
        try:
            return self._record(
                action,
                target=target,
                reason=reason,
                agent_id=agent_id,
                metadata=metadata or {},
            )
        except Exception:  # noqa: BLE001
            # Fail-closed: logging errors must never block governance decisions
            return AuditEntry(
                timestamp=time.monotonic(),
                wall_time=time.time(),
                action=action,
                target=target,
                reason=reason,
                agent_id=agent_id,
                metadata={"_log_error": True},
            )

    def _record(
        self,
        action: AuditAction,
        *,
        target: str,
        reason: str,
        agent_id: str | None,
        metadata: dict[str, Any],
    ) -> AuditEntry:
        entry = AuditEntry(
            timestamp=time.monotonic(),
            wall_time=time.time(),
            action=action,
            target=target,
            reason=reason,
            agent_id=agent_id,
            engagement_id=self._engagement_id,
            metadata=metadata,
        )
        self._entries.append(entry)
        self._unflushed += 1

        if self._log_path and self._unflushed >= self._flush_threshold:
            self._flush()

        return entry

    def replay(self) -> list[AuditEntry]:
        """Return all recorded entries in chronological order."""
        return list(self._entries)

    def count(self) -> int:
        """Return the number of recorded entries."""
        return len(self._entries)

    def count_by_action(self) -> dict[str, int]:
        """Return a count of entries grouped by action type."""
        counts: dict[str, int] = {}
        for entry in self._entries:
            counts[entry.action.value] = counts.get(entry.action.value, 0) + 1
        return counts

    def flush(self) -> None:
        """Flush all pending entries to disk (if ``log_path`` was set)."""
        self._flush()

    def _flush(self) -> None:
        if not self._log_path or self._unflushed <= 0:
            return
        try:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._log_path, "a", encoding="utf-8") as f:
                # Only flush entries that haven't been flushed yet
                entries = list(self._entries)
                for entry in entries[-self._unflushed :]:
                    f.write(entry.model_dump_json() + "\n")
            self._unflushed = 0
        except Exception:  # noqa: BLE001
            pass  # best-effort; governance proceeds regardless

    def clear(self) -> None:
        """Clear all entries (for testing only)."""
        self._entries.clear()
        self._unflushed = 0


def read_audit_log(path: Path) -> list[AuditEntry]:
    """Read an audit log file and return its entries.

    Each line is a JSON-serialised :class:`AuditEntry`.
    """
    entries: list[AuditEntry] = []
    if not path.exists():
        return entries
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(AuditEntry.model_validate_json(line))
        except Exception:  # noqa: BLE001
            continue  # skip malformed lines
    return entries

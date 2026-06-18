"""Fail-closed scope & authorization decision service (SGL-S1).

Every egress path calls ``decide(target, ctx)`` before acting.  The only
valid outcome that permits network contact is ``Decision(verdict=ALLOW)``.
Any other outcome — DENY, internal error, no rules, expiry — blocks.

Design invariants
-----------------
* **Fail-closed by default.** No scope rules loaded → DENY.  Expired
  context → DENY.  Any internal exception → DENY.  UNKNOWN/ERROR states
  never silently pass.
* **No LLM in the decision path.** Pure deterministic code; not reachable
  or mutable from agent tools.
* **Additive.** No imports from the detection engine (proposals, oob, diff,
  race, logic).  Gate-neutral: this module only removes actions upstream of
  the engine; it never alters a disposition.
* **Generalises ``core/inventory/collectors/_scope.py``.** The old
  ``host_in_scope`` returns ``True`` when no rules are set (fail-open bug).
  This module corrects that and adds IP/CIDR matching and typed decisions.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator


# ─────────────────────────────────────── enums / literals ──────────────────


class ActionClass(str, Enum):
    RECON = "recon"
    PORT_SCAN = "port_scan"
    FINGERPRINT = "fingerprint"
    HTTP = "http"
    EXPLOIT = "exploit"
    CREDENTIAL = "credential"


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class AuthzTier(str, Enum):
    STANDARD = "standard"
    # Returned for exploit/credential actions so callers can enforce an
    # additional operator-approval step before acting.
    HIGH_IMPACT = "high_impact"


_HIGH_IMPACT_CLASSES: frozenset[ActionClass] = frozenset(
    {ActionClass.EXPLOIT, ActionClass.CREDENTIAL}
)


# ─────────────────────────────────────── models ────────────────────────────


class ScopeRule(BaseModel):
    """A single authorisation rule within an engagement scope.

    ``pattern`` may be:
    * an exact hostname (``example.com``)
    * a wildcard hostname (``*.example.com`` or ``*example.com``)
    * an exact IPv4/IPv6 address (``192.168.1.1``)
    * an IPv4/IPv6 CIDR block (``10.0.0.0/8``)

    ``allowed_actions`` narrows which :class:`ActionClass` values are
    permitted against this pattern.  ``None`` means all actions are allowed.
    """

    pattern: str
    allowed_actions: list[ActionClass] | None = None

    @field_validator("pattern")
    @classmethod
    def pattern_non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("scope rule pattern must not be empty")
        return v.strip()


class EngagementCtx(BaseModel):
    """Engagement-scoped authorisation context passed to every ``decide`` call.

    Attributes
    ----------
    rules:
        Ordered list of scope rules.  Empty list → all decisions are DENY.
    expires_at:
        Optional UTC expiry time.  After this instant every decision is DENY
        regardless of rules.  ``None`` means the context never expires.
    """

    rules: list[ScopeRule] = []
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def must_be_utc(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            raise ValueError("expires_at must be UTC-aware")
        return v


class Target(BaseModel):
    """The subject of an egress decision request."""

    host: str
    action_class: ActionClass

    @field_validator("host")
    @classmethod
    def host_non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("target host must not be empty")
        return v.strip()


class Decision(BaseModel):
    """Outcome of a single ``decide`` call.

    Consumers must treat any ``verdict`` other than ``ALLOW`` as a hard block.
    The ``reason`` field is for audit/logging only.
    """

    verdict: Verdict
    reason: str
    authz_tier: AuthzTier
    expires_at: datetime | None = None


# ─────────────────────────────────────── host helpers ──────────────────────


def _normalize_host(value: str) -> str:
    """Extract a bare hostname or IP from a URL or raw host string."""
    value = value.strip()
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
    else:
        # May be host:port — strip the port.
        host = value.split(":")[0] if ":" in value and not value.startswith("[") else value
        # IPv6 literal: [::1]:8080 → ::1
        if value.startswith("["):
            host = value[1:].split("]")[0]
    return host.lower()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _host_matches(host: str, pattern: str) -> bool:
    """Return True if ``host`` is covered by ``pattern``.

    Match order:
    1. CIDR block (pattern contains ``/``): parse host as IP and test membership.
    2. Exact IP match.
    3. Exact hostname match.
    4. Wildcard hostname (``*.example.com`` covers ``foo.example.com`` but not
       ``example.com``; ``*example.com`` covers any suffix).
    """
    pattern = pattern.strip().lower()

    # ── CIDR ──────────────────────────────────────────────────────────────
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            addr = ipaddress.ip_address(host)
            return addr in net
        except ValueError:
            return False

    # ── Exact IP ──────────────────────────────────────────────────────────
    if _is_ip(pattern):
        try:
            return ipaddress.ip_address(host) == ipaddress.ip_address(pattern)
        except ValueError:
            return False

    # ── Wildcard hostname ─────────────────────────────────────────────────
    if pattern.startswith("*."):
        # *.example.com matches sub.example.com, not example.com itself
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and host != suffix.lstrip(".")
    if pattern.startswith("*"):
        suffix = pattern[1:]  # e.g. "example.com" from "*example.com"
        return host.endswith(suffix)

    # ── Exact hostname ────────────────────────────────────────────────────
    return host == pattern


# ─────────────────────────────────────── decision service ──────────────────


def decide(target: Target, ctx: EngagementCtx) -> Decision:
    """Return an ALLOW or DENY decision.  Fail-closed: any error → DENY.

    Callers must not bypass DENY outcomes.  For HIGH_IMPACT tier decisions
    (exploit/credential) the caller should require explicit operator approval
    before acting, even on ALLOW.
    """
    try:
        return _decide(target, ctx)
    except Exception as exc:  # noqa: BLE001
        return Decision(
            verdict=Verdict.DENY,
            reason=f"internal_error: {exc}",
            authz_tier=AuthzTier.STANDARD,
        )


def _decide(target: Target, ctx: EngagementCtx) -> Decision:
    # ── Fail-closed: no rules → DENY ─────────────────────────────────────
    if not ctx.rules:
        return Decision(
            verdict=Verdict.DENY,
            reason="no_rules",
            authz_tier=AuthzTier.STANDARD,
        )

    # ── Expiry ────────────────────────────────────────────────────────────
    if ctx.expires_at is not None and datetime.now(tz=timezone.utc) >= ctx.expires_at:
        return Decision(
            verdict=Verdict.DENY,
            reason="expired",
            authz_tier=AuthzTier.STANDARD,
        )

    host = _normalize_host(target.host)

    # ── Rule evaluation (first match wins) ────────────────────────────────
    for rule in ctx.rules:
        if not _host_matches(host, rule.pattern):
            continue

        # Action-class filter within the matched rule
        if (
            rule.allowed_actions is not None
            and target.action_class not in rule.allowed_actions
        ):
            return Decision(
                verdict=Verdict.DENY,
                reason=f"action_class '{target.action_class.value}' not permitted by rule '{rule.pattern}'",
                authz_tier=AuthzTier.STANDARD,
            )

        tier = (
            AuthzTier.HIGH_IMPACT
            if target.action_class in _HIGH_IMPACT_CLASSES
            else AuthzTier.STANDARD
        )
        return Decision(
            verdict=Verdict.ALLOW,
            reason="scope_match",
            authz_tier=tier,
            expires_at=ctx.expires_at,
        )

    # ── No rule matched → DENY ────────────────────────────────────────────
    return Decision(
        verdict=Verdict.DENY,
        reason="out_of_scope",
        authz_tier=AuthzTier.STANDARD,
    )


# ─────────────────────────────────────── ingestion helper ──────────────────


def load_scope(
    entries: list[str],
    *,
    expires_at: datetime | None = None,
    action_overrides: dict[str, list[ActionClass]] | None = None,
) -> EngagementCtx:
    """Build an :class:`EngagementCtx` from a flat list of scope strings.

    Each entry may be a hostname, wildcard hostname, IP, CIDR, or full URL
    (the host part is extracted automatically).  ``action_overrides`` maps a
    pattern string to a restricted action-class list.
    """
    overrides: dict[str, list[ActionClass]] = action_overrides or {}
    rules: list[ScopeRule] = []
    for entry in entries:
        # If it looks like a URL, extract the host as the pattern.
        pattern = _normalize_host(entry) if "://" in entry else entry.strip()
        if not pattern:
            continue
        rules.append(
            ScopeRule(
                pattern=pattern,
                allowed_actions=overrides.get(pattern),
            )
        )
    return EngagementCtx(rules=rules, expires_at=expires_at)

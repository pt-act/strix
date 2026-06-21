"""Target-ownership confidence scoring (SGL-S2).

Given a target host/IP and engagement scope rules, return an
:class:`OwnershipConfidence` score.  The governance layer uses this to
gate ALLOW decisions: targets below the configurable threshold θ are
denied (resolved to **needs-approval / DENY**, not ALLOW).

Design invariants
-----------------
* **Fail-closed by default.**  No scope rules → confidence 0.  Unknown
  target → confidence 0.  Any exception → confidence 0.
* **Deterministic.**  Pure computation over static CIDR tables and the
  supplied scope rules.  No DNS, no whois, no network I/O.
* **Conservative on ambiguity.**  Shared-hosting / CDN / cloud-provider
  CIDRs produce low confidence.  When ownership is ambiguous, the
  result is DENY, never ALLOW.
* **Additive.**  No imports from the detection engine (proposals, oob,
  diff, race, logic).
"""

from __future__ import annotations

import ipaddress
from enum import Enum

from pydantic import BaseModel, Field

from strix.core.govern.scope import ScopeRule, _host_matches, _is_ip, _normalize_host


# ─────────────────────────────────────── constants ───────────────────────────

_DEFAULT_THETA: float = 0.80

# Known cloud / CDN / shared-hosting ASN-level CIDR ranges.
# If a target IP falls into one of these, the ownership confidence is
# reduced because the IP is shared across many tenants.
# These are *not* exhaustive — they cover the major providers whose
# ranges the audit-prep identified as risk vectors.
_KNOWN_SHARED_INFRASTRUCTURE: list[tuple[str, str]] = [
    # Cloudflare
    ("104.16.0.0", 13),
    ("104.24.0.0", 14),
    ("172.64.0.0", 13),
    ("173.245.48.0", 20),
    ("103.21.244.0", 22),
    ("103.22.200.0", 22),
    ("103.31.4.0", 22),
    ("141.101.64.0", 18),
    ("108.162.192.0", 18),
    ("190.93.240.0", 20),
    ("188.114.96.0", 20),
    ("197.234.240.0", 22),
    ("198.41.128.0", 17),
    ("162.158.0.0", 15),
    # AWS CloudFront
    ("13.32.0.0", 15),
    ("13.35.0.0", 16),
    ("52.84.0.0", 15),
    ("54.182.0.0", 16),
    ("54.192.0.0", 16),
    ("54.230.0.0", 16),
    ("54.239.128.0", 18),
    ("54.239.192.0", 19),
    ("99.84.0.0", 16),
    ("143.204.0.0", 16),
    ("204.246.164.0", 22),
    ("204.246.168.0", 22),
    ("205.251.200.0", 21),
    # Akamai
    ("23.0.0.0", 12),
    ("23.32.0.0", 11),
    ("23.64.0.0", 14),
    ("23.72.0.0", 13),
    ("104.64.0.0", 10),
    # Fastly
    ("151.101.0.0", 16),
    ("199.232.0.0", 16),
]

_SHARED_NETWORKS: list[ipaddress.IPv4Network] = []
for _addr, _prefix in _KNOWN_SHARED_INFRASTRUCTURE:
    try:
        _SHARED_NETWORKS.append(
            ipaddress.IPv4Network(f"{_addr}/{_prefix}", strict=False)
        )
    except ValueError:
        pass


# ─────────────────────────────────────── models ──────────────────────────────


class MatchMethod(str, Enum):
    """How the ownership check reached its confidence score."""

    EXACT_IP = "exact_ip"
    CIDR_CONTAINMENT = "cidr_containment"
    HOSTNAME_EXACT = "hostname_exact"
    HOSTNAME_WILDCARD = "hostname_wildcard"
    SHARED_INFRASTRUCTURE = "shared_infrastructure"
    NO_MATCH = "no_match"
    NO_RULES = "no_rules"
    ERROR = "error"


class OwnershipConfidence(BaseModel):
    """Result of an ownership check against scope rules."""

    score: float = Field(ge=0.0, le=1.0)
    method: MatchMethod
    reason: str
    passed: bool
    """True when ``score >= theta``."""

    model_config = {"extra": "forbid"}


# ─────────────────────────────────────── core logic ──────────────────────────


def _is_shared_infrastructure(ip_str: str) -> bool:
    """Return True if *ip_str* falls within a known CDN/hosting CIDR."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _SHARED_NETWORKS)


def _score_ip_match(ip_str: str, rules: list[ScopeRule]) -> tuple[float, MatchMethod, str]:
    """Score an IP target against scope rules.

    Returns (score, method, reason).
    """
    for rule in rules:
        pattern = rule.pattern.strip().lower()

        # CIDR rule
        if "/" in pattern:
            try:
                net = ipaddress.ip_network(pattern, strict=False)
                addr = ipaddress.ip_address(ip_str)
                if addr in net:
                    return 1.0, MatchMethod.CIDR_CONTAINMENT, (
                        f"IP {ip_str} is within scope CIDR {pattern}"
                    )
            except ValueError:
                continue

        # Exact IP rule
        if _is_ip(pattern):
            try:
                if ipaddress.ip_address(ip_str) == ipaddress.ip_address(pattern):
                    return 1.0, MatchMethod.EXACT_IP, (
                        f"IP {ip_str} exactly matches scope IP {pattern}"
                    )
            except ValueError:
                continue

    return 0.0, MatchMethod.NO_MATCH, f"IP {ip_str} matches no scope rule"


def _score_hostname_match(hostname: str, rules: list[ScopeRule]) -> tuple[float, MatchMethod, str]:
    """Score a hostname target against scope rules.

    Returns (score, method, reason).
    """
    hostname = hostname.lower()

    for rule in rules:
        if _host_matches(hostname, rule.pattern):
            pattern = rule.pattern.strip().lower()
            if pattern.startswith("*."):
                return 0.85, MatchMethod.HOSTNAME_WILDCARD, (
                    f"hostname {hostname} matches wildcard rule {pattern}"
                )
            return 1.0, MatchMethod.HOSTNAME_EXACT, (
                f"hostname {hostname} matches exact rule {pattern}"
            )

    return 0.0, MatchMethod.NO_MATCH, f"hostname {hostname} matches no scope rule"


# ─────────────────────────────────────── public API ──────────────────────────


def check_ownership(
    target_host: str,
    scope_rules: list[ScopeRule],
    *,
    theta: float = _DEFAULT_THETA,
) -> OwnershipConfidence:
    """Return an ownership-confidence score for *target_host* against *scope_rules*.

    Parameters
    ----------
    target_host:
        A hostname, IP address, or URL (the host part is extracted).
    scope_rules:
        The engagement scope rules.
    theta:
        Confidence threshold.  Scores below *theta* resolve to
        ``passed=False`` (needs-approval / DENY).

    Returns
    -------
    OwnershipConfidence
        ``passed=True`` only when ``score >= theta``.

    Design notes
    ------------
    * When no scope rules are loaded, confidence is 0 (fail-closed).
    * IP targets are scored against CIDR / exact-IP rules first; if the
      IP also falls in a known shared-infrastructure range, confidence
      is reduced to 0.30 (CDN/hosting ambiguity).
    * Hostname targets are scored via the same ``_host_matches`` logic
      that ``decide()`` uses.  Wildcard matches receive slightly lower
      confidence than exact matches.
    """
    try:
        return _check_ownership(target_host, scope_rules, theta=theta)
    except Exception as exc:  # noqa: BLE001
        return OwnershipConfidence(
            score=0.0,
            method=MatchMethod.ERROR,
            reason=f"ownership check raised {type(exc).__name__}: {exc}",
            passed=False,
        )


def _check_ownership(
    target_host: str,
    scope_rules: list[ScopeRule],
    *,
    theta: float,
) -> OwnershipConfidence:
    if not scope_rules:
        return OwnershipConfidence(
            score=0.0,
            method=MatchMethod.NO_RULES,
            reason="no scope rules loaded — ownership cannot be determined",
            passed=False,
        )

    host = _normalize_host(target_host)

    # ── IP target ────────────────────────────────────────────────────────
    if _is_ip(host):
        score, method, reason = _score_ip_match(host, scope_rules)

        # Shared-infrastructure penalty: even if the IP matches a scope
        # CIDR, it may be a CDN/hosting IP shared across tenants.
        if score > 0 and _is_shared_infrastructure(host):
            score = min(score, 0.30)
            method = MatchMethod.SHARED_INFRASTRUCTURE
            reason += " — IP is in known shared-infrastructure range (CDN/hosting)"

        return OwnershipConfidence(
            score=score,
            method=method,
            reason=reason,
            passed=score >= theta,
        )

    # ── Hostname target ──────────────────────────────────────────────────
    score, method, reason = _score_hostname_match(host, scope_rules)
    return OwnershipConfidence(
        score=score,
        method=method,
        reason=reason,
        passed=score >= theta,
    )

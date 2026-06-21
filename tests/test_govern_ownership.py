"""Tests for strix.core.govern.ownership — SGL-S2.

Tiers
-----
Tier 1 — Focused (deterministic): TG2.x covers key ownership paths.
Tier 2 — PBT (Hypothesis): SP5 ownership gating.

SP5: ``check_ownership()`` returns ``passed=True`` ONLY when the target
     matches a scope rule AND is NOT in a known shared-infrastructure
     range.  All other cases → ``passed=False``.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from strix.core.govern.ownership import (
    MatchMethod,
    OwnershipConfidence,
    check_ownership,
    _is_shared_infrastructure,
)
from strix.core.govern.scope import ScopeRule

# ══════════════════════════════════════════════════════════════════════════════
# helpers
# ══════════════════════════════════════════════════════════════════════════════

_THETA = 0.80


# ══════════════════════════════════════════════════════════════════════════════
# TG2 — Focused tests
# ══════════════════════════════════════════════════════════════════════════════

class TestOwnershipExactHostname:
    """TG2.1 — exact hostname match → high confidence."""

    def test_exact_hostname_passes(self) -> None:
        rules = [ScopeRule(pattern="example.com")]
        result = check_ownership("example.com", rules)
        assert result.passed
        assert result.score >= _THETA
        assert result.method == MatchMethod.HOSTNAME_EXACT

    def test_url_host_extraction(self) -> None:
        rules = [ScopeRule(pattern="example.com")]
        result = check_ownership("https://example.com/path?q=1", rules)
        assert result.passed
        assert result.method == MatchMethod.HOSTNAME_EXACT

    def test_case_insensitive(self) -> None:
        rules = [ScopeRule(pattern="example.com")]
        result = check_ownership("EXAMPLE.COM", rules)
        assert result.passed


class TestOwnershipWildcardHostname:
    """TG2.2 — wildcard hostname match → slightly lower confidence."""

    def test_wildcard_subdomain_passes(self) -> None:
        rules = [ScopeRule(pattern="*.example.com")]
        result = check_ownership("sub.example.com", rules)
        assert result.passed
        assert result.score == pytest.approx(0.85)
        assert result.method == MatchMethod.HOSTNAME_WILDCARD

    def test_wildcard_deep_subdomain(self) -> None:
        rules = [ScopeRule(pattern="*.example.com")]
        result = check_ownership("deep.sub.example.com", rules)
        assert result.passed
        assert result.score == pytest.approx(0.85)

    def test_wildcard_does_not_match_root(self) -> None:
        rules = [ScopeRule(pattern="*.example.com")]
        result = check_ownership("example.com", rules)
        assert not result.passed
        assert result.score == 0.0


class TestOwnershipIPMatch:
    """TG2.3 — IP targets against CIDR/exact-IP rules."""

    def test_cidr_match_passes(self) -> None:
        rules = [ScopeRule(pattern="10.0.0.0/8")]
        result = check_ownership("10.1.2.3", rules)
        assert result.passed
        assert result.score >= _THETA
        assert result.method == MatchMethod.CIDR_CONTAINMENT

    def test_exact_ip_match_passes(self) -> None:
        rules = [ScopeRule(pattern="192.168.1.1")]
        result = check_ownership("192.168.1.1", rules)
        assert result.passed
        assert result.method == MatchMethod.EXACT_IP

    def test_no_ip_match_fails(self) -> None:
        rules = [ScopeRule(pattern="192.168.1.0/24")]
        result = check_ownership("172.16.0.1", rules)
        assert not result.passed
        assert result.method == MatchMethod.NO_MATCH


class TestOwnershipSharedInfrastructure:
    """TG2.4 — CDN/hosting IPs → low confidence even with scope match."""

    def test_cloudflare_ip_penalized(self) -> None:
        """104.16.0.0/13 is Cloudflare — even if it matches a scope CIDR,
        the shared-infrastructure penalty reduces confidence."""
        rules = [ScopeRule(pattern="104.16.0.0/12")]
        result = check_ownership("104.16.132.229", rules)
        assert not result.passed  # 0.30 < 0.80
        assert result.score == pytest.approx(0.30)
        assert result.method == MatchMethod.SHARED_INFRASTRUCTURE

    def test_aws_cloudfront_ip_penalized(self) -> None:
        rules = [ScopeRule(pattern="13.32.0.0/11")]
        result = check_ownership("13.32.100.1", rules)
        assert not result.passed
        assert result.score == pytest.approx(0.30)

    def test_non_shared_ip_not_penalized(self) -> None:
        """A private IP matching a scope CIDR is not shared infra."""
        rules = [ScopeRule(pattern="10.0.0.0/8")]
        result = check_ownership("10.0.0.5", rules)
        assert result.passed
        assert result.score == 1.0


class TestOwnershipEdgeCases:
    """TG2.5 — edge cases and fail-closed behavior."""

    def test_no_rules_fail_closed(self) -> None:
        result = check_ownership("example.com", [])
        assert not result.passed
        assert result.score == 0.0
        assert result.method == MatchMethod.NO_RULES

    def test_out_of_scope_hostname(self) -> None:
        rules = [ScopeRule(pattern="example.com")]
        result = check_ownership("evil.com", rules)
        assert not result.passed
        assert result.score == 0.0

    def test_empty_host_fail_closed(self) -> None:
        rules = [ScopeRule(pattern="example.com")]
        result = check_ownership("", rules)
        assert not result.passed

    def test_custom_theta(self) -> None:
        """With theta=0.50, wildcard match (0.85) should pass."""
        rules = [ScopeRule(pattern="*.example.com")]
        result = check_ownership("sub.example.com", rules, theta=0.50)
        assert result.passed

    def test_is_shared_infrastructure_known_ranges(self) -> None:
        assert _is_shared_infrastructure("104.16.132.229")  # Cloudflare
        assert _is_shared_infrastructure("13.32.100.1")  # AWS CloudFront
        assert not _is_shared_infrastructure("10.0.0.1")  # private
        assert not _is_shared_infrastructure("8.8.8.8")  # Google DNS


# ══════════════════════════════════════════════════════════════════════════════
# Hypothesis strategies
# ══════════════════════════════════════════════════════════════════════════════

_hostnames_st = st.from_regex(
    r"[a-z][a-z0-9-]{0,12}\.(com|net|io|example)", fullmatch=True
)
_scope_rules_st = st.builds(ScopeRule, pattern=_hostnames_st)


# ══════════════════════════════════════════════════════════════════════════════
# SP5 — Ownership gating
# ══════════════════════════════════════════════════════════════════════════════

@given(_hostnames_st, st.lists(_scope_rules_st, min_size=1, max_size=10))
@settings(max_examples=500)
def test_sp5_passed_implies_rule_match(hostname: str, rules: list[ScopeRule]) -> None:
    """SP5: passed=True ⇒ host matches a scope rule and score >= theta."""
    result = check_ownership(hostname, rules, theta=_THETA)
    if not result.passed:
        return  # only constrain the passed case

    assert result.score >= _THETA, (
        f"passed=True but score {result.score} < theta {_THETA}"
    )
    assert result.method in {
        MatchMethod.HOSTNAME_EXACT,
        MatchMethod.HOSTNAME_WILDCARD,
        MatchMethod.CIDR_CONTAINMENT,
        MatchMethod.EXACT_IP,
    }, f"passed=True but method={result.method}"


@given(_hostnames_st)
@settings(max_examples=300)
def test_sp5_no_rules_always_fails(hostname: str) -> None:
    """SP5: no scope rules → ownership always fails."""
    result = check_ownership(hostname, [])
    assert not result.passed
    assert result.score == 0.0


@given(st.lists(_scope_rules_st, min_size=1, max_size=5))
@settings(max_examples=300)
def test_sp5_unknown_host_always_fails(rules: list[ScopeRule]) -> None:
    """SP5: a host that matches no rule → ownership always fails.

    Uses a host guaranteed not to match any rule in the list.
    """
    # Use a hostname that is extremely unlikely to match any generated rule.
    result = check_ownership("zzz-not-real-999.invalid", rules)
    assert not result.passed
    assert result.score == 0.0

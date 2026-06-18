"""Tests for strix.core.govern.scope — SGL-S1.

Tiers
-----
Tier 1 — Focused (deterministic): TG1.x  covers the key allow/deny paths.
Tier 2 — PBT (Hypothesis): SP1 scope soundness, SP2 fail-closed.

SP1: ``decide()`` returns ALLOW **only** when a matching rule exists, the
     context is not expired, and rules were loaded.
SP2: empty rules, expired context, non-matching host, or any forced
     error condition → ``decide()`` returns DENY and NEVER ALLOW.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from strix.core.govern.scope import (
    ActionClass,
    AuthzTier,
    Decision,
    EngagementCtx,
    ScopeRule,
    Target,
    Verdict,
    _host_matches,
    _normalize_host,
    decide,
    load_scope,
)

# ══════════════════════════════════════════════════════════════════════════════
# helpers
# ══════════════════════════════════════════════════════════════════════════════

_FUTURE = datetime.now(tz=timezone.utc) + timedelta(hours=1)
_PAST = datetime.now(tz=timezone.utc) - timedelta(seconds=1)

_IN_SCOPE_HOST = "example.com"
_OUT_OF_SCOPE_HOST = "evil.com"

_CTX = EngagementCtx(
    rules=[ScopeRule(pattern=_IN_SCOPE_HOST)],
    expires_at=_FUTURE,
)
_CTX_NO_EXPIRY = EngagementCtx(rules=[ScopeRule(pattern=_IN_SCOPE_HOST)])


def _target(host: str = _IN_SCOPE_HOST, action: ActionClass = ActionClass.HTTP) -> Target:
    return Target(host=host, action_class=action)


def _allow(d: Decision) -> bool:
    return d.verdict == Verdict.ALLOW


def _deny(d: Decision) -> bool:
    return d.verdict == Verdict.DENY


# ══════════════════════════════════════════════════════════════════════════════
# TG1 — Focused tests
# ══════════════════════════════════════════════════════════════════════════════


class TestAllowPaths:
    """TG1.1 — valid ALLOW paths."""

    def test_exact_hostname_allow(self) -> None:
        d = decide(_target(), _CTX)
        assert _allow(d)
        assert d.reason == "scope_match"

    def test_allow_without_expiry(self) -> None:
        d = decide(_target(), _CTX_NO_EXPIRY)
        assert _allow(d)

    def test_wildcard_subdomain_allow(self) -> None:
        ctx = EngagementCtx(rules=[ScopeRule(pattern="*.example.com")])
        assert _allow(decide(_target("sub.example.com"), ctx))
        assert _allow(decide(_target("deep.sub.example.com"), ctx))

    def test_cidr_allow(self) -> None:
        ctx = EngagementCtx(rules=[ScopeRule(pattern="10.0.0.0/8")])
        assert _allow(decide(_target("10.1.2.3"), ctx))
        assert _allow(decide(_target("10.255.255.255"), ctx))

    def test_exact_ip_allow(self) -> None:
        ctx = EngagementCtx(rules=[ScopeRule(pattern="192.168.1.1")])
        assert _allow(decide(_target("192.168.1.1"), ctx))

    def test_high_impact_tier(self) -> None:
        d = decide(_target(action=ActionClass.EXPLOIT), _CTX)
        assert _allow(d)
        assert d.authz_tier == AuthzTier.HIGH_IMPACT

    def test_credential_tier(self) -> None:
        d = decide(_target(action=ActionClass.CREDENTIAL), _CTX)
        assert _allow(d)
        assert d.authz_tier == AuthzTier.HIGH_IMPACT

    def test_standard_tier_for_recon(self) -> None:
        d = decide(_target(action=ActionClass.RECON), _CTX)
        assert _allow(d)
        assert d.authz_tier == AuthzTier.STANDARD

    def test_url_host_extraction(self) -> None:
        d = decide(_target("https://example.com/path?x=1"), _CTX)
        assert _allow(d)

    def test_load_scope_helper(self) -> None:
        ctx = load_scope(["example.com", "192.168.1.0/24"])
        assert _allow(decide(_target("example.com"), ctx))
        assert _allow(decide(_target("192.168.1.50"), ctx))


class TestDenyPaths:
    """TG1.2 — all DENY paths."""

    def test_out_of_scope_deny(self) -> None:
        d = decide(_target(_OUT_OF_SCOPE_HOST), _CTX)
        assert _deny(d)
        assert d.reason == "out_of_scope"

    def test_no_rules_deny(self) -> None:
        ctx = EngagementCtx(rules=[])
        d = decide(_target(), ctx)
        assert _deny(d)
        assert d.reason == "no_rules"

    def test_expired_deny(self) -> None:
        ctx = EngagementCtx(rules=[ScopeRule(pattern=_IN_SCOPE_HOST)], expires_at=_PAST)
        d = decide(_target(), ctx)
        assert _deny(d)
        assert d.reason == "expired"

    def test_action_class_not_in_rule_deny(self) -> None:
        ctx = EngagementCtx(
            rules=[ScopeRule(pattern=_IN_SCOPE_HOST, allowed_actions=[ActionClass.RECON])]
        )
        d = decide(_target(action=ActionClass.EXPLOIT), ctx)
        assert _deny(d)
        assert "action_class" in d.reason

    def test_wildcard_does_not_match_root(self) -> None:
        # *.example.com must NOT match example.com itself
        ctx = EngagementCtx(rules=[ScopeRule(pattern="*.example.com")])
        assert _deny(decide(_target("example.com"), ctx))

    def test_cidr_out_of_range_deny(self) -> None:
        ctx = EngagementCtx(rules=[ScopeRule(pattern="10.0.0.0/8")])
        assert _deny(decide(_target("192.168.1.1"), ctx))

    def test_exact_ip_different_deny(self) -> None:
        ctx = EngagementCtx(rules=[ScopeRule(pattern="192.168.1.1")])
        assert _deny(decide(_target("192.168.1.2"), ctx))

    def test_first_rule_mismatch_second_rule_allows(self) -> None:
        # Ensure rule ordering works: first non-matching, second matching.
        ctx = EngagementCtx(
            rules=[
                ScopeRule(pattern="other.com"),
                ScopeRule(pattern=_IN_SCOPE_HOST),
            ]
        )
        assert _allow(decide(_target(), ctx))


class TestErrorPaths:
    """TG1.3 — error paths must fail closed."""

    def test_internal_error_returns_deny(self) -> None:
        # Corrupt target: an object that raises on attribute access.
        class BadTarget:
            @property
            def host(self) -> str:  # type: ignore[override]
                raise RuntimeError("boom")

            action_class = ActionClass.HTTP

        # decide() must catch and return DENY, not propagate.
        d = decide(BadTarget(), _CTX)  # type: ignore[arg-type]
        assert _deny(d)
        assert "internal_error" in d.reason

    def test_invalid_pattern_in_rule_does_not_allow(self) -> None:
        # A bad CIDR pattern should not produce ALLOW.
        ctx = EngagementCtx(rules=[ScopeRule(pattern="not-a-cidr/99")])
        assert _deny(decide(_target("10.0.0.1"), ctx))


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════


class TestNormalizeHost:
    def test_strips_scheme(self) -> None:
        assert _normalize_host("https://example.com/path") == "example.com"

    def test_strips_port(self) -> None:
        assert _normalize_host("example.com:8080") == "example.com"

    def test_bare_host(self) -> None:
        assert _normalize_host("example.com") == "example.com"

    def test_ip_preserved(self) -> None:
        assert _normalize_host("192.168.1.1") == "192.168.1.1"

    def test_lowercased(self) -> None:
        assert _normalize_host("EXAMPLE.COM") == "example.com"


class TestHostMatches:
    def test_exact_hostname(self) -> None:
        assert _host_matches("example.com", "example.com")

    def test_wildcard_subdomain(self) -> None:
        assert _host_matches("a.example.com", "*.example.com")

    def test_wildcard_does_not_match_root(self) -> None:
        assert not _host_matches("example.com", "*.example.com")

    def test_cidr_match(self) -> None:
        assert _host_matches("10.1.2.3", "10.0.0.0/8")

    def test_cidr_no_match(self) -> None:
        assert not _host_matches("172.16.0.1", "10.0.0.0/8")

    def test_exact_ip(self) -> None:
        assert _host_matches("192.168.1.1", "192.168.1.1")
        assert not _host_matches("192.168.1.2", "192.168.1.1")

    def test_bad_cidr_pattern_no_match(self) -> None:
        assert not _host_matches("10.0.0.1", "bad/99")


# ══════════════════════════════════════════════════════════════════════════════
# Hypothesis strategies (shared)
# ══════════════════════════════════════════════════════════════════════════════

_hosts_st = st.from_regex(
    r"[a-z][a-z0-9-]{0,18}\.(com|net|io|internal|example)", fullmatch=True
)
_actions_st = st.sampled_from(list(ActionClass))
_targets_st = st.builds(Target, host=_hosts_st, action_class=_actions_st)

_scope_rules_st = st.builds(
    ScopeRule,
    pattern=_hosts_st,
    allowed_actions=st.one_of(st.none(), st.lists(st.sampled_from(list(ActionClass)), min_size=1, max_size=6)),
)

_ctx_with_rules_st = st.builds(
    EngagementCtx,
    rules=st.lists(_scope_rules_st, min_size=1, max_size=10),
    expires_at=st.one_of(
        st.none(),
        st.just(_FUTURE),
    ),
)


# ══════════════════════════════════════════════════════════════════════════════
# SP1 — Scope soundness
# If decide() returns ALLOW, the context had rules and was not expired,
# and the host must match one of those rules.
# ══════════════════════════════════════════════════════════════════════════════


@given(_targets_st, _ctx_with_rules_st)
@settings(max_examples=500)
def test_sp1_allow_implies_scope_match(target: Target, ctx: EngagementCtx) -> None:
    """SP1: ALLOW ⇒ rules non-empty ∧ not expired ∧ host matches a rule."""
    d = decide(target, ctx)
    if d.verdict != Verdict.ALLOW:
        return  # only constrain the ALLOW case

    # Rules must have been loaded
    assert ctx.rules, "ALLOW emitted with no rules"

    # Context must not be expired
    if ctx.expires_at is not None:
        assert datetime.now(tz=timezone.utc) < ctx.expires_at, "ALLOW on expired context"

    # The host must match at least one rule
    host = _normalize_host(target.host)
    matched = any(_host_matches(host, r.pattern) for r in ctx.rules)
    assert matched, f"ALLOW for host '{target.host}' with no matching rule in {[r.pattern for r in ctx.rules]}"


# ══════════════════════════════════════════════════════════════════════════════
# SP2 — Fail-closed
# DENY/UNKNOWN/EXPIRED/ERROR/NO_RULES ⇒ decide() never returns ALLOW.
# Tested via the three structural causes: empty rules, expired ctx, no match.
# ══════════════════════════════════════════════════════════════════════════════


@given(_targets_st)
@settings(max_examples=300)
def test_sp2_no_rules_always_deny(target: Target) -> None:
    """SP2 (no-rules): empty EngagementCtx → always DENY."""
    ctx = EngagementCtx(rules=[])
    d = decide(target, ctx)
    assert d.verdict == Verdict.DENY
    assert d.reason == "no_rules"


@given(_targets_st, _scope_rules_st)
@settings(max_examples=300)
def test_sp2_expired_always_deny(target: Target, rule: ScopeRule) -> None:
    """SP2 (expired): expired EngagementCtx → always DENY even with matching rules."""
    ctx = EngagementCtx(rules=[rule], expires_at=_PAST)
    d = decide(target, ctx)
    assert d.verdict == Verdict.DENY
    assert d.reason == "expired"


@given(_targets_st, st.lists(_scope_rules_st, min_size=1, max_size=10))
@settings(max_examples=300)
def test_sp2_no_matching_rule_deny(target: Target, rules: list[ScopeRule]) -> None:
    """SP2 (no match): decide() uses first-match-wins semantics.

    The oracle mirrors _decide exactly: find the FIRST rule whose pattern
    matches the host, then check whether the action_class is permitted by
    that rule.  A second rule with allowed_actions=None does not rescue a
    DENY issued by an earlier host-matching rule with a restricted action list.
    """
    ctx = EngagementCtx(rules=rules, expires_at=_FUTURE)
    d = decide(target, ctx)
    host = _normalize_host(target.host)

    # First rule whose pattern covers the host (mirrors _decide iteration order).
    first_host_match = next(
        (r for r in rules if _host_matches(host, r.pattern)), None
    )

    if first_host_match is None:
        # No rule covers this host → must be DENY (out_of_scope).
        assert d.verdict == Verdict.DENY, (
            f"Expected DENY for '{target.host}' (no host match) but got "
            f"{d.verdict}: {d.reason}"
        )
    elif (
        first_host_match.allowed_actions is not None
        and target.action_class not in first_host_match.allowed_actions
    ):
        # First matching rule exists but restricts this action → DENY.
        assert d.verdict == Verdict.DENY, (
            f"Expected DENY for '{target.host}' action={target.action_class.value} "
            f"(rule '{first_host_match.pattern}' allows only "
            f"{[a.value for a in first_host_match.allowed_actions]}) "
            f"but got {d.verdict}: {d.reason}"
        )
    else:
        # First matching rule permits this action → ALLOW.
        assert d.verdict == Verdict.ALLOW, (
            f"Expected ALLOW for '{target.host}' (matched rule: "
            f"'{first_host_match.pattern}') but got {d.verdict}: {d.reason}"
        )

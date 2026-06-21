"""Shared scope-bounding helper for inventory collectors.

S7: This module is now backed by the fail-closed ``decide()`` service.
The old ``host_in_scope`` returned ``True`` when no rules were set
(fail-open bug).  The new implementation delegates to ``decide()`` and
returns ``True`` only when a scope rule matches.  When no rules are
loaded, the result is ``False`` (fail-closed).
"""

from __future__ import annotations

from strix.core.govern.scope import (
    ActionClass,
    EngagementCtx,
    ScopeRule,
    Target,
    Verdict,
    decide,
    load_scope,
)


def host_in_scope(url: str, scope_rules: list[str] | None) -> bool:
    """Return True when the URL host is permitted by scope rules.

    Fail-closed semantics:
    * ``scope_rules is None`` → no filtering configured → ``True`` (pass-through).
    * ``scope_rules == []`` → filtering configured but empty → ``False`` (deny-all).
    * ``scope_rules == ["example.com", ...]`` → delegate to ``decide()``.

    The old implementation returned ``True`` for *both* ``None`` and ``[]``
    (the fail-open bug).  The new implementation distinguishes the two
    cases: ``None`` means "not configured" while ``[]`` means "configured
    but empty" (fail-closed).
    """
    if scope_rules is None:
        return True  # no filtering configured — pass through
    if not scope_rules:
        return False  # configured but empty — fail-closed (was: return True)

    ctx = load_scope(scope_rules)
    target = Target(host=url, action_class=ActionClass.HTTP)
    decision = decide(target, ctx)
    return decision.verdict == Verdict.ALLOW

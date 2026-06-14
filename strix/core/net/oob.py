"""OOB-confirmation seam for Phase 2 oracle integration."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class OOBConfirmationStrategy(Protocol):
    """Strategy for confirming an outbound interaction via OOB callback."""

    def confirm(self, target: str, token: str) -> str | None:
        """Return confirmation evidence, or ``None`` if unavailable."""
        ...


class NullOOBConfirmationStrategy:
    """Default Phase 0 implementation: no confirmation available."""

    def confirm(self, target: str, token: str) -> str | None:  # noqa: ARG002
        return None


_default_strategy: OOBConfirmationStrategy = NullOOBConfirmationStrategy()


def get_oob_confirmation_strategy() -> OOBConfirmationStrategy:
    """Return the currently installed OOB confirmation strategy."""
    return _default_strategy


def set_oob_confirmation_strategy(strategy: OOBConfirmationStrategy) -> None:
    """Install a concrete OOB confirmation strategy (used by Phase 2)."""
    global _default_strategy  # noqa: PLW0603
    _default_strategy = strategy


def confirm_oob(target: str, token: str) -> str | None:
    """Ask the installed OOB strategy to confirm an outbound interaction."""
    return _default_strategy.confirm(target, token)


__all__ = [
    "NullOOBConfirmationStrategy",
    "OOBConfirmationStrategy",
    "confirm_oob",
    "get_oob_confirmation_strategy",
    "set_oob_confirmation_strategy",
]

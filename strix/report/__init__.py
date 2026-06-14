"""Report/finding helpers."""

from __future__ import annotations


__all__ = [
    "ReportState",
    "check_duplicate",
    "get_global_report_state",
    "set_global_report_state",
]


def __getattr__(name: str) -> object:
    if name == "ReportState":
        from strix.report.state import ReportState

        return ReportState
    if name == "get_global_report_state":
        from strix.report.state import get_global_report_state

        return get_global_report_state
    if name == "set_global_report_state":
        from strix.report.state import set_global_report_state

        return set_global_report_state
    if name == "check_duplicate":
        from strix.report.dedupe import check_duplicate

        return check_duplicate
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

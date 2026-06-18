"""M1 funnel-metric capture + cross-check — research apparatus (read-only over the funnel).

Reads the four propose-dispose metrics off an instrumentation funnel log and cross-checks them
against an independent (hand / M0) computation. It **reuses** the pure metric functions in
``strix.report.proposals`` — it never re-derives them — and it is strictly read-only: it writes no
report state and sets no ``evidence_class`` (Spec B TG1.3).

- ``R_prop = |P ∩ V| / |V|`` — proposal recall over the labeled set ``V`` (recall-over-known).
- ``Prec_gate = |C ∩ V| / |C|`` — gate precision (``C`` = harness-confirmed proposals).
- ``R_e2e = |R ∩ V| / |V|`` — end-to-end recall (``R`` = reported proposals).
- ``funnel_efficiency = harness_runs / |C|`` — runs per confirmed finding.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from strix.report.proposals import (
    FunnelLog,
    compute_funnel_efficiency,
    compute_prec_gate,
    compute_r_e2e,
    compute_r_prop,
)
from strix.research.corpus import ground_truth_labels


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from strix.core.proposals.models import ProposalRecord


_METRIC_NAMES = ("r_prop", "prec_gate", "r_e2e", "funnel_efficiency")


@dataclass(frozen=True)
class MetricsSummary:
    """The four funnel metrics plus the funnel counts they derive from (for traceability)."""

    r_prop: float
    prec_gate: float
    r_e2e: float
    funnel_efficiency: float
    num_labels: int
    num_proposed: int
    num_confirmed: int
    num_reported: int
    num_harness_runs: int

    def metrics(self) -> dict[str, float]:
        return {name: float(getattr(self, name)) for name in _METRIC_NAMES}

    def as_dict(self) -> dict[str, float | int]:
        return asdict(self)


def _is_confirmed(record: ProposalRecord) -> bool:
    return any(verdict.verdict == "confirmed" for verdict in record.verdicts)


def summarize_funnel(records: Sequence[ProposalRecord], labels: set[str]) -> MetricsSummary:
    """Compute the four metrics + counts off a funnel record list (reuses the pure functions)."""
    record_list = list(records)
    return MetricsSummary(
        r_prop=compute_r_prop(record_list, labels),
        prec_gate=compute_prec_gate(record_list, labels),
        r_e2e=compute_r_e2e(record_list, labels),
        funnel_efficiency=compute_funnel_efficiency(record_list),
        num_labels=len(labels),
        num_proposed=len({r.endpoint_key for r in record_list if r.cwe}),
        num_confirmed=len({r.endpoint_key for r in record_list if _is_confirmed(r)}),
        num_reported=len({r.endpoint_key for r in record_list if r.report_id}),
        num_harness_runs=sum(len(r.verdicts) for r in record_list),
    )


@dataclass(frozen=True)
class CrossCheck:
    """Per-metric agreement between the funnel-derived value and an independent computation."""

    agree: bool
    per_metric: dict[str, bool]
    funnel: dict[str, float]
    expected: dict[str, float]
    tolerance: float


def cross_check(
    summary: MetricsSummary, expected: Mapping[str, float], tolerance: float = 1e-9
) -> CrossCheck:
    """Validate funnel-derived metrics against a hand/M0 computation (TG1.2 ground-truth check).

    ``expected`` may cover any subset of the four metric names; only supplied keys are checked.
    """
    funnel = summary.metrics()
    checked = {name: float(value) for name, value in expected.items() if name in funnel}
    per_metric = {name: abs(funnel[name] - value) <= tolerance for name, value in checked.items()}
    return CrossCheck(
        agree=all(per_metric.values()),
        per_metric=per_metric,
        funnel={name: funnel[name] for name in checked},
        expected=checked,
        tolerance=tolerance,
    )


def traceability(records: Sequence[ProposalRecord], labels: set[str]) -> dict[str, list[str]]:
    """Map each metric to the endpoints that contribute to it (claim -> artifact, TG5.7)."""
    record_list = list(records)
    proposed = {r.endpoint_key for r in record_list if r.cwe}
    confirmed = {r.endpoint_key for r in record_list if _is_confirmed(r)}
    reported = {r.endpoint_key for r in record_list if r.report_id}
    return {
        "labels_V": sorted(labels),
        "r_prop_hits": sorted(proposed & labels),
        "prec_gate_confirmed": sorted(confirmed),
        "prec_gate_true_positives": sorted(confirmed & labels),
        "r_e2e_reported_hits": sorted(reported & labels),
    }


def load_funnel(path: Path) -> FunnelLog:
    """Read-only load of a funnel.json into a FunnelLog (writes nothing)."""
    return FunnelLog.load(path)


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m strix.research.metrics")
    parser.add_argument("--funnel", required=True, type=Path, help="funnel.json to read")
    parser.add_argument(
        "--labels",
        type=Path,
        default=None,
        help="JSON list of ground-truth endpoints (V); defaults to the B-V2P corpus labels",
    )
    args = parser.parse_args(argv)

    labels = (
        set(json.loads(args.labels.read_text(encoding="utf-8")))
        if args.labels is not None
        else ground_truth_labels()
    )
    records = load_funnel(args.funnel).list_records()
    summary = summarize_funnel(records, labels)
    json.dump(
        {"summary": summary.as_dict(), "traceability": traceability(records, labels)},
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

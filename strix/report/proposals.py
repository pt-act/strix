"""Funnel log + derived metrics for the propose-dispose pipeline.

The funnel is strictly additive to ``report/state.py``. It records transitions
but does not change the impact gate or the semantics of ``vulnerability_reports``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from strix.core.proposals.models import (
    C1C8Answer,
    HarnessVerdict,
    InterventionFlags,
    ProposalContext,
    ProposalRecord,
)


if TYPE_CHECKING:
    from pathlib import Path

    from strix.report.state import EvidenceClass


class FunnelLog:
    """Append-only log of ProposalRecords per engagement.

    Records are appended, never deleted. In-memory lookup by ``proposal_id``
    speeds up transition recording without mutating the log list itself.
    """

    def __init__(self, records: list[ProposalRecord] | None = None) -> None:
        self._records: list[ProposalRecord] = []
        self._index: dict[str, ProposalRecord] = {}
        for record in records or []:
            self._add_record(record)

    def _add_record(self, record: ProposalRecord) -> None:
        self._records.append(record)
        self._index[record.proposal_id] = record

    def start_proposal(
        self,
        *,
        engagement_id: str,
        endpoint_key: str,
        param_name: str | None = None,
        cwe: str | None = None,
        c1_c8_answers: dict[str, C1C8Answer] | None = None,
        active_interventions: InterventionFlags | None = None,
        harnesses_selected: list[str] | None = None,
        supplied_context: ProposalContext | None = None,
        proposal_id: str | None = None,
    ) -> ProposalRecord:
        """Create and append a new proposal record."""
        record = ProposalRecord(
            proposal_id=proposal_id or f"prop-{datetime.now(UTC).timestamp()}",
            engagement_id=engagement_id,
            endpoint_key=endpoint_key,
            param_name=param_name,
            cwe=cwe,
            c1_c8_answers=c1_c8_answers or {},
            active_interventions=active_interventions or InterventionFlags(),
            harnesses_selected=list(harnesses_selected or []),
        )
        if supplied_context is not None:
            record.record_context(supplied_context)
        self._add_record(record)
        return record

    def record_harness_verdict(
        self,
        proposal_id: str,
        harness_name: str,
        verdict: str,
        evidence_class: EvidenceClass,
        cost_ms: float = 0.0,
    ) -> ProposalRecord | None:
        """Append a harness verdict to an existing proposal."""
        record = self._index.get(proposal_id)
        if record is None:
            return None
        record.add_verdict(
            HarnessVerdict(
                harness_name=harness_name,
                verdict=verdict,  # type: ignore[arg-type]
                evidence_class=evidence_class,
                cost_ms=cost_ms,
            )
        )
        return record

    def record_report(self, proposal_id: str, report_id: str) -> ProposalRecord | None:
        """Link the final impact-gated report to a proposal."""
        record = self._index.get(proposal_id)
        if record is None:
            return None
        record.attach_report(report_id)
        return record

    def get(self, proposal_id: str) -> ProposalRecord | None:
        return self._index.get(proposal_id)

    def list_records(self) -> list[ProposalRecord]:
        return list(self._records)

    def model_dump(self) -> list[dict[str, Any]]:
        return [r.model_dump() for r in self._records]

    @classmethod
    def model_validate(cls, data: list[dict[str, Any]]) -> FunnelLog:
        return cls(records=[ProposalRecord.model_validate(d) for d in data])

    def save(self, path: Path) -> None:
        path.write_text(
            self._json_dumps(self.model_dump()),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: Path) -> FunnelLog:
        if not path.exists():
            return cls()
        data = cls._json_loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return cls()
        return cls.model_validate(data)

    @staticmethod
    def _json_dumps(obj: Any) -> str:
        return json.dumps(obj, ensure_ascii=False, indent=2, default=str)

    @staticmethod
    def _json_loads(text: str) -> Any:
        return json.loads(text)


# ---------------------------------------------------------------------------
# Derived metrics (pure functions over the funnel log)
# ---------------------------------------------------------------------------


def compute_r_prop(records: list[ProposalRecord], labels: set[str]) -> float:
    """Proposal recall: |P ∩ V| / |V|, where V is the ground-truth label set."""
    if not labels:
        return 0.0
    proposed = {r.endpoint_key for r in records if r.cwe}
    return len(proposed & labels) / len(labels)


def compute_prec_gate(records: list[ProposalRecord], labels: set[str]) -> float:
    """Gate precision: |C ∩ V| / |C|, where C is gate-confirmed proposals."""
    confirmed = {
        r.endpoint_key for r in records if any(v.verdict == "confirmed" for v in r.verdicts)
    }
    if not confirmed:
        return 0.0
    return len(confirmed & labels) / len(confirmed)


def compute_r_e2e(records: list[ProposalRecord], labels: set[str]) -> float:
    """End-to-end recall: |R ∩ V| / |V|, where R is reported proposals."""
    if not labels:
        return 0.0
    reported = {r.endpoint_key for r in records if r.report_id}
    return len(reported & labels) / len(labels)


def compute_funnel_efficiency(records: list[ProposalRecord]) -> float:
    """Harness runs per confirmed finding: total harness runs / |C|."""
    confirmed = [r for r in records if any(v.verdict == "confirmed" for v in r.verdicts)]
    if not confirmed:
        return 0.0
    total_harness_runs = sum(len(r.verdicts) for r in records)
    return total_harness_runs / len(confirmed)

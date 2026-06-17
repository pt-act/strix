from __future__ import annotations

import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from uuid import uuid4

from strix.core.paths import run_dir_for
from strix.report.proposals import FunnelLog
from strix.report.usage import LLMUsageLedger
from strix.report.writer import (
    read_run_record,
    write_executive_report,
    write_run_record,
    write_vulnerabilities,
)
from strix.telemetry import posthog, scarf


if TYPE_CHECKING:
    from agents.usage import Usage

    from strix.core.proposals.models import ProposalRecord


logger = logging.getLogger(__name__)

EvidenceClass = Literal["diff", "callback", "reachability", "race_result", "none"]
_VALID_EVIDENCE_CLASSES: frozenset[str] = frozenset(
    {"diff", "callback", "reachability", "race_result", "none"}
)

# Maps a disposer (harness) evidence_class to the harness that produced it, used only
# to label the funnel verdict. ``"none"`` carries no harness verdict and is omitted.
_EVIDENCE_TO_HARNESS: dict[str, str] = {
    "diff": "p2_diff_harness",
    "callback": "p3_oob_harness",
    "reachability": "p3_reachability",
    "race_result": "p4_race_harness",
}


def _apply_impact_gate(
    severity: str,
    evidence_class: EvidenceClass,
) -> tuple[str, str, str]:
    """Return (final_severity, gate_decision, original_severity).

    Evidence-less findings are down-graded to ``info`` so they remain visible
    but do not crowd out evidence-backed findings. The original CVSS-derived
    severity is preserved for inspection.
    """
    original_severity = severity.lower().strip()
    if evidence_class == "none":
        return "info", "downgraded_to_unconfirmed", original_severity
    return original_severity, "kept_from_cvss", original_severity


_global_report_state: ReportState | None = None


def get_global_report_state() -> ReportState | None:
    return _global_report_state


def set_global_report_state(report_state: ReportState | None) -> None:
    global _global_report_state  # noqa: PLW0603
    _global_report_state = report_state


class ReportState:
    """Per-scan product artifact state plus artifact writer.

    The Agents SDK owns model/tool execution, tracing, and conversation
    persistence. This store keeps only Strix-owned scan artifacts and
    report metadata. Live UI projections belong to the interface layer.

    It does not consume SDK tracing processors.
    """

    def __init__(self, run_name: str | None = None):
        self.run_name = run_name
        self.run_id = run_name or f"run-{uuid4().hex[:8]}"
        self.start_time = datetime.now(UTC).isoformat()
        self.end_time: str | None = None

        self.vulnerability_reports: list[dict[str, Any]] = []
        self.final_scan_result: str | None = None
        self.funnel_log: FunnelLog = FunnelLog()

        self.scan_results: dict[str, Any] | None = None
        self.scan_config: dict[str, Any] | None = None
        self._llm_usage = LLMUsageLedger()
        self.run_record: dict[str, Any] = {
            "run_id": self.run_id,
            "run_name": self.run_name,
            "start_time": self.start_time,
            "end_time": None,
            "status": "running",
            "targets_info": [],
            "llm_usage": self._build_llm_usage_record(),
        }
        self._run_dir: Path | None = None
        self._saved_vuln_ids: set[str] = set()

        self.caido_url: str | None = None
        self.vulnerability_found_callback: Callable[[dict[str, Any]], None] | None = None

    def get_run_dir(self) -> Path:
        if self._run_dir is None:
            run_dir_name = self.run_name if self.run_name else self.run_id
            self._run_dir = run_dir_for(run_dir_name)
            self._run_dir.mkdir(parents=True, exist_ok=True)

        return self._run_dir

    def hydrate_from_run_dir(self) -> None:
        """Reload prior-scan state from ``{run_dir}/`` for resume.

        Restores:

        - ``vulnerability_reports`` from ``vulnerabilities.json`` so
          :meth:`add_vulnerability_report` doesn't allocate a colliding
          ``vuln-0001`` and overwrite the prior on-disk MD.
        - ``run_record`` from ``run.json`` so timestamps, run inputs,
          status, and final report state have one public source of truth.

        Idempotent on missing files (fresh runs land here too via the
        same code path). **Raises on corruption** — silently swallowing
        a corrupt ``vulnerabilities.json`` would let the next vuln
        allocate ``vuln-0001`` and overwrite the prior MD on disk
        (data loss). Caller is expected to fail the run loud and let
        the user inspect ``{run_dir}`` or pick a fresh ``--run-name``.
        """
        run_dir = self.get_run_dir()

        data = read_run_record(run_dir)
        if data:
            self.run_record.update(data)
            if isinstance(data.get("start_time"), str):
                self.start_time = data["start_time"]
            if isinstance(data.get("end_time"), str):
                self.end_time = data["end_time"]
            scan_results = data.get("scan_results")
            if isinstance(scan_results, dict):
                self.scan_results = scan_results
                self.final_scan_result = self._format_final_scan_result(scan_results)
            self._hydrate_llm_usage(data.get("llm_usage"))
            logger.info("report state hydrated run.json from %s", run_dir)

        json_path = run_dir / "vulnerabilities.json"
        if json_path.exists():
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    f"vulnerabilities.json at {json_path} is corrupt ({exc}); "
                    f"refusing to start fresh — that would overwrite prior "
                    f"vulnerability MDs on disk. Inspect or delete the run dir.",
                ) from exc
            if not isinstance(data, list):
                raise RuntimeError(
                    f"vulnerabilities.json at {json_path} is not a list",
                )
            self.vulnerability_reports = [r for r in data if isinstance(r, dict)]
            for r in self.vulnerability_reports:
                rid = r.get("id")
                if isinstance(rid, str):
                    self._saved_vuln_ids.add(rid)
            logger.info(
                "report state hydrated %d vulnerability report(s)",
                len(self.vulnerability_reports),
            )

        funnel_path = run_dir / "funnel.json"
        if funnel_path.exists():
            try:
                self.funnel_log = FunnelLog.load(funnel_path)
                logger.info(
                    "report state hydrated %d funnel record(s)",
                    len(self.funnel_log.list_records()),
                )
            except (OSError, RuntimeError) as exc:
                logger.warning("failed to hydrate funnel log: %s", exc)

    def add_vulnerability_report(
        self,
        title: str,
        severity: str,
        description: str | None = None,
        impact: str | None = None,
        target: str | None = None,
        technical_analysis: str | None = None,
        poc_description: str | None = None,
        poc_script_code: str | None = None,
        remediation_steps: str | None = None,
        cvss: float | None = None,
        cvss_breakdown: dict[str, str] | None = None,
        endpoint: str | None = None,
        method: str | None = None,
        cve: str | None = None,
        cwe: str | None = None,
        code_locations: list[dict[str, Any]] | None = None,
        agent_id: str | None = None,
        agent_name: str | None = None,
        evidence_class: EvidenceClass = "none",
        artifacts: list[dict[str, Any]] | None = None,
        proposal_id: str | None = None,
    ) -> str:
        if evidence_class not in _VALID_EVIDENCE_CLASSES:
            raise ValueError(
                f"Invalid evidence_class '{evidence_class}'; "
                f"must be one of: {sorted(_VALID_EVIDENCE_CLASSES)}"
            )

        final_severity, gate_decision, original_severity = _apply_impact_gate(
            severity, evidence_class
        )
        report_id = f"vuln-{len(self.vulnerability_reports) + 1:04d}"

        report: dict[str, Any] = {
            "id": report_id,
            "title": title.strip(),
            "severity": final_severity,
            "original_severity": original_severity,
            "evidence_class": evidence_class,
            "impact_gate_decision": gate_decision,
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

        if description:
            report["description"] = description.strip()
        if impact:
            report["impact"] = impact.strip()
        if target:
            report["target"] = target.strip()
        if technical_analysis:
            report["technical_analysis"] = technical_analysis.strip()
        if poc_description:
            report["poc_description"] = poc_description.strip()
        if poc_script_code:
            report["poc_script_code"] = poc_script_code.strip()
        if remediation_steps:
            report["remediation_steps"] = remediation_steps.strip()
        if cvss is not None:
            report["cvss"] = cvss
        if cvss_breakdown:
            report["cvss_breakdown"] = cvss_breakdown
        if endpoint:
            report["endpoint"] = endpoint.strip()
        if method:
            report["method"] = method.strip()
        if cve:
            report["cve"] = cve.strip()
        if cwe:
            report["cwe"] = cwe.strip()
        if code_locations:
            report["code_locations"] = code_locations
        if agent_id:
            report["agent_id"] = agent_id
        if agent_name:
            report["agent_name"] = agent_name
        if artifacts:
            report["artifacts"] = artifacts

        self.vulnerability_reports.append(report)
        logger.info(f"Added vulnerability report: {report_id} - {title}")
        posthog.finding(severity)
        scarf.finding(severity)

        if self.vulnerability_found_callback:
            self.vulnerability_found_callback(report)

        self._link_disposer_verdict_to_funnel(
            report_id=report_id,
            endpoint=endpoint,
            evidence_class=evidence_class,
            proposal_id=proposal_id,
        )

        self.save_run_data()
        return report_id

    def _link_disposer_verdict_to_funnel(
        self,
        *,
        report_id: str,
        endpoint: str | None,
        evidence_class: EvidenceClass,
        proposal_id: str | None,
    ) -> None:
        """Additively attach a disposer (harness) verdict onto its proposal record.

        Glass-box instrumentation only: records the harness verdict + report id into the
        matching ProposalRecord in the funnel. It never alters the report dict, the impact
        gate, or ``vulnerability_reports``. Evidence-less (``"none"``) findings carry no
        harness verdict and are skipped. If no proposal can be unambiguously matched, this
        is a no-op — so engagements that never used the propose tool are unaffected.
        """
        harness_name = _EVIDENCE_TO_HARNESS.get(evidence_class)
        if harness_name is None:
            return  # "none" / unknown — no disposer verdict to attach.

        record: ProposalRecord | None = None
        if proposal_id is not None:
            record = self.funnel_log.get(proposal_id)
        if record is None:
            record = self._match_open_proposal(endpoint)
        if record is None:
            return

        self.funnel_log.record_harness_verdict(
            record.proposal_id,
            harness_name,
            "confirmed",
            evidence_class,
        )
        self.funnel_log.record_report(record.proposal_id, report_id)

    def _match_open_proposal(self, endpoint: str | None) -> ProposalRecord | None:
        """Best-effort: the single open (verdict-less, unreported) proposal for an endpoint.

        Conservative by design — returns a record only on an unambiguous single match so a
        harness-filed report is never linked to the wrong proposal. Explicit ``proposal_id``
        is always preferred over this fallback.
        """
        if not endpoint:
            return None
        needle = endpoint.strip()
        if not needle:
            return None
        matches = [
            r
            for r in self.funnel_log.list_records()
            if not r.verdicts
            and r.report_id is None
            and r.endpoint_key
            and (r.endpoint_key == needle or needle in r.endpoint_key or r.endpoint_key in needle)
        ]
        return matches[0] if len(matches) == 1 else None

    def get_existing_vulnerabilities(self) -> list[dict[str, Any]]:
        return list(self.vulnerability_reports)

    def record_sdk_usage(
        self,
        *,
        agent_id: str,
        usage: Usage | None,
        agent_name: str | None = None,
        model: str | None = None,
    ) -> None:
        """Record SDK-native token usage for one completed model run/cycle."""
        if self._llm_usage.record(
            agent_id=agent_id,
            agent_name=agent_name,
            model=model,
            usage=usage,
        ):
            self.save_run_data()

    def record_observed_llm_cost(self, cost: float) -> None:
        self._llm_usage.record_observed_cost(cost)

    def get_total_llm_usage(self) -> dict[str, Any]:
        return dict(self.run_record.get("llm_usage") or self._build_llm_usage_record())

    def update_scan_final_fields(
        self,
        executive_summary: str,
        methodology: str,
        technical_analysis: str,
        recommendations: str,
    ) -> None:
        self.scan_results = {
            "scan_completed": True,
            "executive_summary": executive_summary.strip(),
            "methodology": methodology.strip(),
            "technical_analysis": technical_analysis.strip(),
            "recommendations": recommendations.strip(),
            "success": True,
        }

        self.final_scan_result = self._format_final_scan_result(self.scan_results)
        self.run_record["scan_results"] = self.scan_results

        logger.info("Updated scan final fields")
        self.save_run_data(mark_complete=True)
        posthog.end(self, exit_reason="finished_by_tool")
        scarf.end(self, exit_reason="finished_by_tool")

    def set_scan_config(self, config: dict[str, Any]) -> None:
        self.scan_config = config
        self.run_record["status"] = "running"
        self.run_record["end_time"] = None
        self.run_record.pop("scan_results", None)
        self.end_time = None
        self.scan_results = None
        self.final_scan_result = None
        self.run_record.update(
            {
                "targets_info": config.get("targets", []),
                "instruction": config.get("user_instructions", ""),
                "scan_mode": config.get("scan_mode", "deep"),
                "diff_scope": config.get("diff_scope", {"active": False}),
                "non_interactive": bool(config.get("non_interactive", False)),
                "local_sources": config.get("local_sources", []),
                "scope_mode": config.get("scope_mode", "auto"),
                "diff_base": config.get("diff_base"),
            }
        )

    def save_run_data(self, mark_complete: bool = False, status: str | None = None) -> None:
        if mark_complete:
            self.end_time = datetime.now(UTC).isoformat()
            self.run_record["end_time"] = self.end_time
            self.run_record["status"] = "completed"
        elif status and self.run_record.get("status") != "completed":
            current_status = self.run_record.get("status")
            if status == "stopped" and current_status in {"failed", "interrupted"}:
                status = str(current_status)
            if self.end_time is None:
                self.end_time = datetime.now(UTC).isoformat()
            self.run_record["end_time"] = self.end_time
            self.run_record["status"] = status

        self._sync_llm_usage_record()
        self._save_artifacts()

    def cleanup(self, status: str = "stopped") -> None:
        self.save_run_data(status=status)

    def _format_final_scan_result(self, scan_results: dict[str, Any]) -> str:
        return f"""# Executive Summary

{str(scan_results.get("executive_summary", "")).strip()}

# Methodology

{str(scan_results.get("methodology", "")).strip()}

# Technical Analysis

{str(scan_results.get("technical_analysis", "")).strip()}

# Recommendations

{str(scan_results.get("recommendations", "")).strip()}
"""

    def _save_artifacts(self) -> None:
        """Write scan artifacts under ``run_dir``."""
        run_dir = self.get_run_dir()
        try:
            run_dir.mkdir(parents=True, exist_ok=True)

            if self.final_scan_result:
                write_executive_report(run_dir, self.final_scan_result)

            if self.vulnerability_reports:
                write_vulnerabilities(run_dir, self.vulnerability_reports, self._saved_vuln_ids)

            self.funnel_log.save(run_dir / "funnel.json")

            write_run_record(run_dir, self.run_record)

            logger.info("Essential scan data saved to: %s", run_dir)
        except (OSError, RuntimeError):
            logger.exception("Failed to save scan data")

    def _sync_llm_usage_record(self) -> None:
        self.run_record["llm_usage"] = self._build_llm_usage_record()

    def _build_llm_usage_record(self) -> dict[str, Any]:
        return self._llm_usage.to_record()

    def _hydrate_llm_usage(self, raw_usage: Any) -> None:
        self._llm_usage.hydrate(raw_usage)
        self._sync_llm_usage_record()


def litellm_cost_callback(
    kwargs: Any,
    completion_response: Any,
    _start_time: Any = None,
    _end_time: Any = None,
) -> None:
    """LiteLLM ``success_callback`` adapter; forwards observed cost to the active scan."""
    cost: float | None = None
    raw = kwargs.get("response_cost") if isinstance(kwargs, dict) else None
    if isinstance(raw, int | float) and raw > 0:
        cost = float(raw)

    if cost is None:
        hidden = getattr(completion_response, "_hidden_params", None) or {}
        candidate = hidden.get("response_cost") if isinstance(hidden, dict) else None
        if isinstance(candidate, int | float) and candidate > 0:
            cost = float(candidate)
        else:
            headers = hidden.get("additional_headers") or {} if isinstance(hidden, dict) else {}
            raw = (
                headers.get("llm_provider-x-litellm-response-cost")
                if isinstance(headers, dict)
                else None
            )
            try:
                value = float(raw) if raw is not None else None
            except (TypeError, ValueError):
                value = None
            if value is not None and value > 0:
                cost = value

    if cost is None or cost <= 0:
        return
    report_state = get_global_report_state()
    if report_state is None:
        return
    try:
        report_state.record_observed_llm_cost(cost)
    except Exception:
        logger.exception("Failed to record observed LiteLLM cost")

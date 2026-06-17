"""Proposal-context assembler: three flag-gated, independently-ablatable recall streams.

The assembler is proposal-stage only. It sets no ``evidence_class``, writes no
``vulnerability_report``, and mutates no ``ReportState``. The disposer owns precision.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.core.proposals.models import C1C8Checklist, InterventionFlags, ProposalContext


if TYPE_CHECKING:
    from strix.core.inventory.models import Endpoint, Param


def _verbalize_control_path(endpoint: Endpoint) -> str | None:
    """Turn P3 reachability_seam into compact, bounded NL.

    Multi-granularity: one sentence per layer; no full-graph dump.
    """
    reachability = endpoint.reachability
    if reachability is None or reachability.status == "unknown":
        return None

    parts = [f"Route: {endpoint.method} {endpoint.url}", f"Status: {reachability.status}"]
    if reachability.path:
        path = " -> ".join(reachability.path)
        parts.append(f"Sink path: {path}")
    return " | ".join(parts)


_KNOWLEDGE_PRIORS: dict[str, str] = {
    "object-id": (
        "Object-ID parameters (id, uuid) often drive IDOR/BFLA "
        "if authorization is delegated or missing."
    ),
    "url": "URL parameters are classic SSRF / open-redirect / callback-hijacking sinks.",
    "html": (
        "HTML/content parameters are XSS / template-injection / stored-HTML injection candidates."
    ),
    "file": (
        "File parameters enable path traversal, unrestricted upload, and file-extension bypass."
    ),
    "amount": (
        "Amount/price parameters are business-logic targets: "
        "price mismatch, double-spend, overflow."
    ),
    "role": "Role/permission parameters are privilege-escalation targets (vertical/horizontal).",
    "state": (
        "State/status parameters are state-machine bypass targets (activate, approve, delete)."
    ),
    "unknown": "Unknown-class parameters need manual triage; treat as suspicious until classified.",
}


def _build_knowledge_path(param: Param | None) -> str | None:
    """Return a CWE-prior sentence keyed by the P3 parameter class."""
    if param is None or param.class_evidence is None:
        return None
    class_name = param.class_evidence.class_name
    return _KNOWLEDGE_PRIORS.get(class_name, _KNOWLEDGE_PRIORS["unknown"])


def assemble_proposal_context(
    endpoint: Endpoint,
    param: Param | None,
    flags: InterventionFlags,
    checklist: C1C8Checklist | None = None,
) -> ProposalContext:
    """Compose only enabled context streams and record the active flag matrix.

    Safe to call at proposal time: no report state is touched, no evidence_class is set.
    """
    control_path_nl = _verbalize_control_path(endpoint) if flags.control_path else None
    knowledge_path_nl = _build_knowledge_path(param) if flags.knowledge_path else None
    c1_c8 = checklist if flags.c1_c8_checklist else None

    return ProposalContext(
        control_path_nl=control_path_nl,
        knowledge_path_nl=knowledge_path_nl,
        c1_c8_checklist=c1_c8,
        active_flags=flags,
    )

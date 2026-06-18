"""Single-stage ablation mode (M4) — research baseline, quarantined off in production.

This is the propose-dispose validation study's single-stage baseline: a verdict produced
**without** the deterministic disposer, either by the proposer self-confirming
(``self_confirm``) or by a static classifier proxy (``static_proxy``). It exists only to
measure what strix's two-stage pipeline buys over a single-stage detector (E1/E2/E4).

Safety (locus-1): self-confirmation is the architecture's forbidden path — "the agent
proposes, the harness disposes." It is therefore:

- **Off by default.** ``is_single_stage_ablation_enabled()`` is False unless the exact research
  opt-in token is present in the environment; no ordinary ``STRIX_*`` setting enables it.
- **Entrypoint-gated.** Reachable only from ``python -m strix.research.ablation`` — never wired
  into the product agent factory, the runner, or the interface.
- **Incapable of touching product state.** ``SingleStageVerdict`` carries **no** ``evidence_class``
  and this module never imports ``ReportState`` / ``add_vulnerability_report`` /
  ``record_harness_run``. A single-stage verdict can never become a funnel confirmation, so
  precision is never silently handed to a model.

Every public runner calls :func:`require_single_stage_ablation`, so even a mistaken in-process
call raises unless the operator has explicitly opted in for a research run.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Literal


# Build-time / entrypoint gate. The value is an explicit, non-trivial research opt-in — not a
# "1"/"true" toggle — so it cannot be flipped by accident and reads unambiguously as a
# disposer-disabling research switch. Production deployments never set it.
ABLATION_ENV_VAR = "STRIX_RESEARCH_SINGLE_STAGE_ABLATION"
_ENABLE_SENTINEL = "enable-single-stage-self-confirm-research-only"

SingleStageMode = Literal["self_confirm", "static_proxy"]


def _empty_signals() -> dict[str, float]:
    return {}


def is_single_stage_ablation_enabled() -> bool:
    """True only when the exact research opt-in value is set. Default (production): False."""
    return os.environ.get(ABLATION_ENV_VAR) == _ENABLE_SENTINEL


def require_single_stage_ablation() -> None:
    """Guard every single-stage entry; raise unless the research opt-in is explicitly set."""
    if not is_single_stage_ablation_enabled():
        raise RuntimeError(
            "single-stage ablation (disposer-disabled / self-confirm) is a quarantined research "
            f"mode and is OFF in production. Set {ABLATION_ENV_VAR} to the research opt-in token "
            "and run via `python -m strix.research.ablation` to enable it for an experiment."
        )


@dataclass(frozen=True)
class AblationProposal:
    """A single-stage input. Research-only: no ``evidence_class``, no ReportState handle.

    ``model_confirms`` / ``model_confidence`` / ``model_rationale`` carry the proposer's captured
    self-judgment for the ``self_confirm`` baseline (in a real experiment, the LLM's recorded
    output); ``signals`` feeds the deterministic ``static_proxy`` baseline.
    """

    endpoint: str
    cwe: str | None = None
    signals: Mapping[str, float] = field(default_factory=_empty_signals)
    model_confirms: bool | None = None
    model_confidence: float = 0.0
    model_rationale: str = ""


@dataclass(frozen=True)
class SingleStageVerdict:
    """A single-stage verdict. Deliberately carries **no** ``evidence_class`` field — confirmation
    here is not backed by a deterministic harness, which is exactly the mode under measurement.
    """

    endpoint: str
    verdict: Literal["confirmed", "unconfirmed"]
    mode: SingleStageMode
    confidence: float
    rationale: str


# (confirm?, confidence, rationale) — injected so the self-confirm baseline is deterministic and
# offline-testable; a live experiment supplies the proposer model here.
ModelJudge = Callable[[AblationProposal], tuple[bool, float, str]]


def _fixture_judge(proposal: AblationProposal) -> tuple[bool, float, str]:
    return (
        bool(proposal.model_confirms),
        proposal.model_confidence,
        proposal.model_rationale or "model self-confirmation (no harness)",
    )


def run_self_confirm(
    proposal: AblationProposal, judge: ModelJudge | None = None
) -> SingleStageVerdict:
    """Harness-disabled baseline: the proposer's own judgment becomes the verdict."""
    require_single_stage_ablation()
    decide = judge or _fixture_judge
    confirms, confidence, rationale = decide(proposal)
    return SingleStageVerdict(
        endpoint=proposal.endpoint,
        verdict="confirmed" if confirms else "unconfirmed",
        mode="self_confirm",
        confidence=confidence,
        rationale=rationale,
    )


def run_static_proxy(proposal: AblationProposal, *, threshold: float = 0.5) -> SingleStageVerdict:
    """Static-proxy baseline: a deterministic score over the proposal's signals.

    Uses a continuous score (not a binary heuristic) so the baseline has dynamic range — this
    avoids the floor-effect confound the spec warns about when comparing against the pipeline.
    """
    require_single_stage_ablation()
    score = sum(value for value in proposal.signals.values() if value > 0)
    confidence = min(1.0, score)
    return SingleStageVerdict(
        endpoint=proposal.endpoint,
        verdict="confirmed" if confidence >= threshold else "unconfirmed",
        mode="static_proxy",
        confidence=confidence,
        rationale=f"static-proxy score {confidence:.3f} vs threshold {threshold:.3f}",
    )


def run_single_stage(
    proposals: list[AblationProposal],
    mode: SingleStageMode,
    *,
    judge: ModelJudge | None = None,
    threshold: float = 0.5,
) -> list[SingleStageVerdict]:
    """Run a whole fixture (e.g. a B-V2P pair) through one single-stage baseline."""
    require_single_stage_ablation()
    if mode == "self_confirm":
        return [run_self_confirm(p, judge) for p in proposals]
    return [run_static_proxy(p, threshold=threshold) for p in proposals]

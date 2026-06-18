"""Single-stage ablation mode (M4) — quarantined research baseline (see strix.research)."""

from __future__ import annotations

from strix.research.ablation.single_stage import (
    ABLATION_ENV_VAR,
    AblationProposal,
    ModelJudge,
    SingleStageMode,
    SingleStageVerdict,
    is_single_stage_ablation_enabled,
    require_single_stage_ablation,
    run_self_confirm,
    run_single_stage,
    run_static_proxy,
)


__all__ = [
    "ABLATION_ENV_VAR",
    "AblationProposal",
    "ModelJudge",
    "SingleStageMode",
    "SingleStageVerdict",
    "is_single_stage_ablation_enabled",
    "require_single_stage_ablation",
    "run_self_confirm",
    "run_single_stage",
    "run_static_proxy",
]

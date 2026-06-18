"""Research entrypoint for the single-stage ablation baseline (M4).

This is the ONLY entrypoint to the disposer-disabled / self-confirm path. It is never wired
into the product CLI. Running it still requires the explicit research opt-in token (see
``strix.research.ablation.single_stage.ABLATION_ENV_VAR``); without it, the run aborts.

    STRIX_RESEARCH_SINGLE_STAGE_ABLATION=<token> \\
        python -m strix.research.ablation --fixture pairs.json --mode static_proxy

``--fixture`` is a JSON document: ``{"proposals": [{"endpoint": ..., "signals": {...},
"model_confirms": true, "model_confidence": 0.9}, ...]}``. Verdicts are written to stdout as
JSON for downstream E1/E2/E4 aggregation.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

from strix.research.ablation.single_stage import (
    AblationProposal,
    SingleStageMode,
    require_single_stage_ablation,
    run_single_stage,
)


def _proposal_from_dict(raw: dict[str, Any]) -> AblationProposal:
    return AblationProposal(
        endpoint=str(raw["endpoint"]),
        cwe=raw.get("cwe"),
        signals={str(k): float(v) for k, v in dict(raw.get("signals", {})).items()},
        model_confirms=raw.get("model_confirms"),
        model_confidence=float(raw.get("model_confidence", 0.0)),
        model_rationale=str(raw.get("model_rationale", "")),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m strix.research.ablation")
    parser.add_argument("--fixture", required=True, type=Path, help="JSON fixture of proposals")
    parser.add_argument(
        "--mode",
        required=True,
        choices=("self_confirm", "static_proxy"),
        help="single-stage baseline to run",
    )
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args(argv)

    # Entrypoint gate: abort unless the operator explicitly opted in for a research run.
    require_single_stage_ablation()

    document = json.loads(args.fixture.read_text(encoding="utf-8"))
    proposals = [_proposal_from_dict(p) for p in document.get("proposals", [])]
    mode: SingleStageMode = args.mode

    verdicts = run_single_stage(proposals, mode, threshold=args.threshold)
    json.dump([dataclasses.asdict(v) for v in verdicts], sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

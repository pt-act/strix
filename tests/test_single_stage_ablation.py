"""M4 single-stage ablation mode — Tier-1 + Tier-2 PBT (locus-1 guardrails).

The single-stage baseline is the one piece of the validation study that touches the forbidden
self-confirm path. These tests pin its two locus-1 invariants:

- **M4 production-off** (PBT 4.4): no ordinary environment enables it, and no production entry
  module imports it — so no production entrypoint can reach the self-confirm path.
- **Gate neutrality / no self-confirm** (PBT 4.5): a single-stage verdict can never become a
  funnel confirmation (it carries no ``evidence_class`` and cannot write report state), and the
  *production* emit path only records a ``confirmed`` verdict when it carries a deterministic
  harness ``evidence_class`` (``!= none``).
"""

from __future__ import annotations

import ast
import dataclasses
import json
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import TestCase
from unittest.mock import patch

from hypothesis import assume, given
from hypothesis import strategies as st


# Mock the agents SDK before importing report-state-facing modules (mirrors the funnel tests).
_agents: Any = ModuleType("agents")
_agents_usage: Any = ModuleType("agents.usage")


class _Usage:
    pass


_agents_usage.Usage = _Usage
_agents_usage.serialize_usage = lambda _: {}
_agents_usage.deserialize_usage = lambda _: _Usage()
_agents.RunContextWrapper = object
_agents.function_tool = lambda **_: lambda f: f
sys.modules.setdefault("agents", _agents)
sys.modules.setdefault("agents.usage", _agents_usage)

from strix.agents.funnel_emit import emit_harness_run  # noqa: E402
from strix.report.state import (  # noqa: E402
    ReportState,
    get_global_report_state,
    set_global_report_state,
)
from strix.research.ablation.single_stage import (  # noqa: E402
    _ENABLE_SENTINEL,
    ABLATION_ENV_VAR,
    AblationProposal,
    SingleStageVerdict,
    is_single_stage_ablation_enabled,
    require_single_stage_ablation,
    run_self_confirm,
    run_single_stage,
    run_static_proxy,
)


# Printable, NUL-free text — values the OS will actually accept in os.environ.
_ENV_SAFE_TEXT = st.text(st.characters(min_codepoint=32, max_codepoint=126), max_size=64)
_DETERMINISTIC_EVIDENCE = {"diff", "callback", "reachability", "race_result"}
_ENDPOINT = "POST /api/v1/import"
_PRODUCTION_ENTRY_MODULES = (
    "strix/agents/factory.py",
    "strix/core/runner.py",
    "strix/interface/main.py",
    "strix/interface/cli.py",
)


def _enabled_env() -> Any:
    return patch.dict(os.environ, {ABLATION_ENV_VAR: _ENABLE_SENTINEL})


class TestSingleStageBaselines(TestCase):
    """TG4.3 — the ablation mode produces a single-stage verdict on a B-V2P fixture pair."""

    def test_self_confirm_flips_across_a_pair(self) -> None:
        vuln = AblationProposal(endpoint=_ENDPOINT, model_confirms=True, model_confidence=0.9)
        patched = AblationProposal(endpoint=_ENDPOINT, model_confirms=False, model_confidence=0.1)
        with _enabled_env():
            verdicts = run_single_stage([vuln, patched], "self_confirm")
        self.assertEqual([v.verdict for v in verdicts], ["confirmed", "unconfirmed"])
        self.assertTrue(all(v.mode == "self_confirm" for v in verdicts))

    def test_static_proxy_scores_with_dynamic_range(self) -> None:
        vuln = AblationProposal(
            endpoint=_ENDPOINT, signals={"reachable_sink": 0.8, "object_ref": 0.4}
        )
        patched = AblationProposal(endpoint=_ENDPOINT, signals={"reachable_sink": 0.1})
        with _enabled_env():
            hot = run_static_proxy(vuln)
            cold = run_static_proxy(patched)
        self.assertEqual(hot.verdict, "confirmed")
        self.assertEqual(cold.verdict, "unconfirmed")
        self.assertGreater(hot.confidence, cold.confidence)  # dynamic range, not a binary floor


class TestProductionOff(TestCase):
    """PBT 4.4 + the 4.6 off-in-prod regression guardrail."""

    def test_disabled_by_default_and_runners_refuse(self) -> None:
        # Regression (4.6): research opt-in absent -> mode OFF and every runner refuses.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(ABLATION_ENV_VAR, None)
            self.assertFalse(is_single_stage_ablation_enabled())
            with self.assertRaises(RuntimeError):
                require_single_stage_ablation()
            with self.assertRaises(RuntimeError):
                run_self_confirm(AblationProposal(endpoint=_ENDPOINT, model_confirms=True))
            with self.assertRaises(RuntimeError):
                run_static_proxy(AblationProposal(endpoint=_ENDPOINT, signals={"x": 1.0}))

    def test_no_production_entry_module_imports_the_ablation(self) -> None:
        # 4.7 (mechanized): no production entrypoint can reach the self-confirm path.
        repo_root = Path(__file__).resolve().parents[1]
        for rel in _PRODUCTION_ENTRY_MODULES:
            source = (repo_root / rel).read_text(encoding="utf-8")
            self.assertNotIn("strix.research", source, f"{rel} must not import research apparatus")

    @given(value=_ENV_SAFE_TEXT)
    def test_no_token_value_but_the_exact_one_enables(self, value: str) -> None:
        assume(value != _ENABLE_SENTINEL)
        with patch.dict(os.environ, {ABLATION_ENV_VAR: value}):
            self.assertFalse(is_single_stage_ablation_enabled())

    @given(
        extra=st.dictionaries(
            keys=st.sampled_from(
                ["STRIX_LLM", "STRIX_REASONING_EFFORT", "STRIX_IMAGE", "STRIX_TELEMETRY", "DEBUG"]
            ),
            values=_ENV_SAFE_TEXT,
            max_size=5,
        )
    )
    def test_unrelated_env_never_enables(self, extra: dict[str, str]) -> None:
        assume(ABLATION_ENV_VAR not in extra)
        with patch.dict(os.environ, extra, clear=False):
            os.environ.pop(ABLATION_ENV_VAR, None)
            self.assertFalse(is_single_stage_ablation_enabled())


class TestGateNeutrality(TestCase):
    """PBT 4.5 — the disposer never self-confirms; precision is never owned by a model."""

    def setUp(self) -> None:
        self.previous_state = get_global_report_state()

    def tearDown(self) -> None:
        set_global_report_state(self.previous_state)

    def test_single_stage_verdict_carries_no_evidence_class(self) -> None:
        # Structural: a single-stage verdict cannot masquerade as a harness-confirmed finding.
        fields = {f.name for f in dataclasses.fields(SingleStageVerdict)}
        self.assertNotIn("evidence_class", fields)

    def test_ablation_module_cannot_write_report_state(self) -> None:
        # Structural (AST, so docstrings that *name* these primitives don't count): the research
        # module imports nothing from the product report layer, so it has no handle to write.
        source = (
            Path(__file__).resolve().parents[1] / "strix/research/ablation/single_stage.py"
        ).read_text(encoding="utf-8")
        imported: set[str] = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        self.assertFalse(
            any(module.startswith("strix.report") for module in imported),
            f"ablation must not import the product report layer; imported: {sorted(imported)}",
        )

    @given(
        verdict_str=st.sampled_from(["confirmed", "unconfirmed", "race", "safe", "inconclusive"]),
        evidence_class=st.sampled_from(
            ["diff", "callback", "reachability", "race_result", "none", "bogus"]
        ),
        has_report=st.booleans(),
    )
    def test_funnel_confirmation_requires_deterministic_evidence(
        self, verdict_str: str, evidence_class: str, has_report: bool
    ) -> None:
        state = ReportState(run_name="ablation-neutrality")
        set_global_report_state(state)
        record = state.funnel_log.start_proposal(
            engagement_id="demo", endpoint_key=_ENDPOINT, cwe="CWE-918"
        )

        result: dict[str, Any] = {"verdict": verdict_str}
        if has_report:
            result["report"] = {"evidence_class": evidence_class}
        emit_harness_run("p3_oob_harness", result, json.dumps({"endpoint": _ENDPOINT}))

        recorded = state.funnel_log.get(record.proposal_id)
        assert recorded is not None
        for verdict in recorded.verdicts:
            if verdict.verdict == "confirmed":
                self.assertIn(verdict.evidence_class, _DETERMINISTIC_EVIDENCE)
                self.assertNotEqual(verdict.evidence_class, "none")

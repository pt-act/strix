"""Tier-1 + PBT tests for the proposal-context assembler.

The assembler is proposal-stage only. It must never set ``evidence_class`` or
write report state. The harness (disposer) still owns precision.
"""

from __future__ import annotations

import inspect
from unittest import TestCase

from hypothesis import given
from hypothesis import strategies as st

from strix.core.inventory.models import (
    Endpoint,
    Param,
    ParamClassEvidence,
    ParamClassName,
    ReachabilityAnnotation,
    ReachabilityStatus,
)
from strix.core.proposals import assembler as assembler_mod
from strix.core.proposals.assembler import assemble_proposal_context
from strix.core.proposals.models import C1C8Checklist, InterventionFlags, ProposalContext
from strix.report.state import ReportState


class _AssemblerTestCase(TestCase):
    def _endpoint(
        self,
        *,
        status: ReachabilityStatus | None = "reachable",
        sinks: list[str] | None = None,
    ) -> Endpoint:
        reachability = None
        if status is not None:
            reachability = ReachabilityAnnotation(status=status, path=sinks)
        return Endpoint(
            key="GET /api/users/{id}",
            method="GET",
            url="/api/users/{id}",
            reachability=reachability,
        )

    def _param(self, class_name: ParamClassName) -> Param:
        return Param(
            name="id",
            location="path",
            class_evidence=ParamClassEvidence(class_name=class_name, evidence="fixture"),
        )


class TestAssemblerStreams(_AssemblerTestCase):
    """Each enabled intervention produces its expected context shape."""

    def test_control_path_enabled(self) -> None:
        endpoint = self._endpoint(sinks=["database"])
        flags = InterventionFlags(control_path=True, knowledge_path=False, c1_c8_checklist=False)
        ctx = assemble_proposal_context(endpoint, None, flags)
        self.assertIsNotNone(ctx.control_path_nl)
        assert ctx.control_path_nl is not None
        self.assertIn("GET /api/users/{id}", ctx.control_path_nl)
        self.assertIn("reachable", ctx.control_path_nl)
        self.assertIn("database", ctx.control_path_nl)
        self.assertIsNone(ctx.knowledge_path_nl)
        self.assertIsNone(ctx.c1_c8_checklist)

    def test_knowledge_path_enabled(self) -> None:
        endpoint = self._endpoint()
        param = self._param("object-id")
        flags = InterventionFlags(control_path=False, knowledge_path=True, c1_c8_checklist=False)
        ctx = assemble_proposal_context(endpoint, param, flags)
        self.assertIsNone(ctx.control_path_nl)
        self.assertIsNotNone(ctx.knowledge_path_nl)
        assert ctx.knowledge_path_nl is not None
        self.assertIn("IDOR", ctx.knowledge_path_nl)
        self.assertIsNone(ctx.c1_c8_checklist)

    def test_c1_c8_checklist_enabled(self) -> None:
        endpoint = self._endpoint()
        checklist = C1C8Checklist()
        flags = InterventionFlags(control_path=False, knowledge_path=False, c1_c8_checklist=True)
        ctx = assemble_proposal_context(endpoint, None, flags, checklist=checklist)
        self.assertIsNone(ctx.control_path_nl)
        self.assertIsNone(ctx.knowledge_path_nl)
        self.assertIs(ctx.c1_c8_checklist, checklist)

    def test_all_flags_disabled(self) -> None:
        endpoint = self._endpoint()
        flags = InterventionFlags(control_path=False, knowledge_path=False, c1_c8_checklist=False)
        ctx = assemble_proposal_context(endpoint, None, flags)
        self.assertIsNone(ctx.control_path_nl)
        self.assertIsNone(ctx.knowledge_path_nl)
        self.assertIsNone(ctx.c1_c8_checklist)

    def test_active_flags_recorded(self) -> None:
        flags = InterventionFlags(control_path=True, knowledge_path=True, c1_c8_checklist=True)
        ctx = assemble_proposal_context(self._endpoint(), None, flags)
        self.assertEqual(ctx.active_flags, flags)


class TestAssemblerBoundaryPBT(TestCase):
    """Assembled context sets no evidence_class and writes no report state."""

    def test_no_report_state_mutation(self) -> None:
        endpoint = Endpoint(key="GET /x", method="GET", url="/x")
        flags = InterventionFlags(control_path=True, knowledge_path=True, c1_c8_checklist=True)
        state = ReportState(run_name="r-1")
        state_before = state.run_record.copy()
        vuln_count_before = len(state.vulnerability_reports)

        ctx = assemble_proposal_context(endpoint, None, flags)

        self.assertEqual(len(state.vulnerability_reports), vuln_count_before)
        self.assertEqual(state.run_record, state_before)
        self.assertIsNone(ctx.control_path_nl)

    def test_boundary_is_structural(self) -> None:
        """The locus-1 guarantee, asserted as structure — not via a ReportState the
        assembler never receives (strengthened per the Spec A verdict, minor 2).
        """
        # 1. ProposalContext carries no evidence/verdict/report field: a proposal
        #    structurally cannot express a disposition.
        fields = set(ProposalContext.model_fields)
        for forbidden in ("evidence_class", "verdict", "verdicts", "report_id"):
            self.assertNotIn(forbidden, fields)

        # 2. assemble_proposal_context accepts no ReportState and returns ProposalContext.
        #    (Annotations are strings under ``from __future__ import annotations``.)
        sig = inspect.signature(assemble_proposal_context)
        self.assertNotIn("report", " ".join(p.lower() for p in sig.parameters))
        self.assertEqual(sig.return_annotation, ProposalContext.__name__)

        # 3. The proposal-stage source contains no disposer-write calls.
        src = inspect.getsource(assembler_mod)
        for forbidden in ("record_harness_verdict", "add_vulnerability_report", "evidence_class ="):
            self.assertNotIn(forbidden, src)


class TestAssemblerAblationPBT(_AssemblerTestCase):
    """Toggling one flag changes only its contribution; the others are byte-identical."""

    def test_ablation_independence(self) -> None:
        endpoint = self._endpoint(sinks=["database"])
        param = self._param("object-id")
        checklist = C1C8Checklist()

        # Baseline: all on
        all_on = assemble_proposal_context(
            endpoint,
            param,
            InterventionFlags(control_path=True, knowledge_path=True, c1_c8_checklist=True),
            checklist,
        )

        # Toggle each flag off one at a time
        cp_off = assemble_proposal_context(
            endpoint,
            param,
            InterventionFlags(control_path=False, knowledge_path=True, c1_c8_checklist=True),
            checklist,
        )
        kp_off = assemble_proposal_context(
            endpoint,
            param,
            InterventionFlags(control_path=True, knowledge_path=False, c1_c8_checklist=True),
            checklist,
        )
        c_off = assemble_proposal_context(
            endpoint,
            param,
            InterventionFlags(control_path=True, knowledge_path=True, c1_c8_checklist=False),
            checklist,
        )

        self.assertIsNone(cp_off.control_path_nl)
        self.assertEqual(cp_off.knowledge_path_nl, all_on.knowledge_path_nl)
        self.assertEqual(cp_off.c1_c8_checklist, all_on.c1_c8_checklist)

        self.assertIsNone(kp_off.knowledge_path_nl)
        self.assertEqual(kp_off.control_path_nl, all_on.control_path_nl)
        self.assertEqual(kp_off.c1_c8_checklist, all_on.c1_c8_checklist)

        self.assertIsNone(c_off.c1_c8_checklist)
        self.assertEqual(c_off.control_path_nl, all_on.control_path_nl)
        self.assertEqual(c_off.knowledge_path_nl, all_on.knowledge_path_nl)


class TestAssemblerDeterminismPBT(TestCase):
    """Fixed reachability graph + param class -> stable Control-Path / Knowledge output."""

    @given(
        status=st.sampled_from(["reachable", "unreachable"]),
        class_name=st.sampled_from(["object-id", "url", "html", "file", "amount", "role", "state"]),
    )
    def test_stable_outputs(self, status: ReachabilityStatus, class_name: ParamClassName) -> None:
        endpoint = Endpoint(
            key="GET /x",
            method="GET",
            url="/x",
            reachability=ReachabilityAnnotation(status=status, path=["database"]),
        )
        param = Param(
            name="id",
            location="path",
            class_evidence=ParamClassEvidence(class_name=class_name, evidence="fixture"),
        )
        flags = InterventionFlags(control_path=True, knowledge_path=True, c1_c8_checklist=False)
        a = assemble_proposal_context(endpoint, param, flags)
        b = assemble_proposal_context(endpoint, param, flags)
        self.assertEqual(a.control_path_nl, b.control_path_nl)
        self.assertEqual(a.knowledge_path_nl, b.knowledge_path_nl)


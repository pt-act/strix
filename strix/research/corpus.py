"""B-V2P benchmark corpus registry (M2) — research apparatus, quarantined (see strix.research).

A Behavioral-V2P pair is the same application at a vulnerable commit and its minimal-diff
security fix, deployed live, with a ground-truth label set ``V`` (the labeled-vulnerable
endpoints). This module is the typed, importable index the experiments consume; the deployable
targets themselves live under ``benchmarks/bv2p/<fixture_dir>``.

Recall is reported as **recall-over-known**: ``V`` is the labeled set only, and every recall
number carries the unknown-unknown caveat (there may be vulnerabilities not in ``V``). The
corpus is deliberately **small-gap-biased** — the E2 primary test is a gap-stratified paired
McNemar, which needs small-gap *discordant* pairs, not breadth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal


if TYPE_CHECKING:
    from collections.abc import Sequence


Primitive = Literal["idor", "bfla", "ssrf", "xxe", "race", "business_logic"]
GapClass = Literal["small", "large"]
# Which deterministic disposer confirms the pair (mirrors report.state EvidenceClass, minus "none").
DisposerEvidence = Literal["diff", "callback", "reachability", "race_result"]


@dataclass(frozen=True)
class BV2PPair:
    """One vuln/patch pair. ``vuln_endpoint`` is the ground-truth label (an element of ``V``)."""

    pair_id: str
    primitive: Primitive
    cve: str
    title: str
    vuln_endpoint: str
    disposer_evidence: DisposerEvidence
    gap_class: GapClass
    minimal_diff: bool
    synthesized_patch: bool
    fixture_dir: str
    notes: str


# M0 seeds (Spec F-9): the discriminator (IDOR, synthesized minimal patch) and the H1/OOB
# showcase (SSRF). Both CVE IDs verified real. Race/business-logic pairs are soft-edged behind
# Phases 4/5 and are added as the corpus grows.
BV2P_CORPUS: tuple[BV2PPair, ...] = (
    BV2PPair(
        pair_id="openwebui-idor-memories",
        primitive="idor",
        cve="CVE-2024-7041",
        title="open-webui memories IDOR (missing ownership check)",
        vuln_endpoint="POST /api/v1/memories/{id}/update",
        disposer_evidence="diff",
        gap_class="small",
        minimal_diff=True,
        synthesized_patch=True,
        fixture_dir="idor_memories",
        notes=(
            "No clean public single-commit fix exists; the patch synthesizes the one-line "
            "ownership check (memory.user_id == caller). M0 discriminator."
        ),
    ),
    BV2PPair(
        pair_id="flowise-ssrf-http-node",
        primitive="ssrf",
        cve="CVE-2026-31829",
        title="Flowise HTTP-node SSRF (unvalidated URL fetch)",
        vuln_endpoint="POST /api/v1/node/http",
        disposer_evidence="callback",
        gap_class="small",
        minimal_diff=True,
        synthesized_patch=False,
        fixture_dir="ssrf_fetch",
        notes=(
            "Real fix (<=3.0.12 -> 3.0.13). Patched mode blocks internal/metadata targets via the "
            "P0 net classifier (strix.core.net.is_internal_target). H1/OOB-callback showcase."
        ),
    ),
)


def ground_truth_labels(pairs: Sequence[BV2PPair] = BV2P_CORPUS) -> set[str]:
    """The labeled vulnerable-endpoint set ``V`` (recall-over-known; unknown-unknown caveat)."""
    return {pair.vuln_endpoint for pair in pairs}


def small_gap_pairs(pairs: Sequence[BV2PPair] = BV2P_CORPUS) -> tuple[BV2PPair, ...]:
    return tuple(pair for pair in pairs if pair.gap_class == "small")


@dataclass(frozen=True)
class PowerCheck:
    """Corpus-level power readout for the gap-stratified paired McNemar (E2 primary).

    ``small_gap_count`` is the available small-gap pairs — the *ceiling* on discordant pairs; the
    actual discordant count is an experimental outcome observed at run time. ``sufficient`` is the
    honest gate against ``required_discordant``: with a tiny seed corpus it is expected to be
    False, and no tight effect size may be reported until it holds.
    """

    small_gap_count: int
    required_discordant: int
    sufficient: bool


def power_check(required_discordant: int, pairs: Sequence[BV2PPair] = BV2P_CORPUS) -> PowerCheck:
    count = len(small_gap_pairs(pairs))
    return PowerCheck(
        small_gap_count=count,
        required_discordant=required_discordant,
        sufficient=count >= required_discordant,
    )

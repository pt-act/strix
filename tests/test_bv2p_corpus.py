"""M2 B-V2P corpus — registry + per-pair exploitability (vuln side fires, patch side does not).

Disposer checks use the *real* deterministic disposers, hermetically:
- IDOR pair -> the P2 differential engine (`strix.core.diff.diff`): the attacker's cross-user
  request is 2xx on the vuln deployment and 4xx on the patch, so the engine flags ``gained_access``
  across the pair and flags nothing when both sides are patched.
- SSRF pair -> the P0 net classifier (`strix.core.net.is_internal_target`) via the fixture's
  patched guard: internal/metadata targets are blocked, externals allowed; the vuln guard allows
  everything. (Full OOB-callback confirmation is a live/Docker step, run on the operator's host.)

The fixtures' framework-free ``core`` modules are loaded by path (``benchmarks/`` is not an
installed package); the FastAPI ``app.py`` wrappers are exercised only in the live/Docker run.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest import TestCase
from unittest.mock import patch

from strix.core.diff import diff


if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType
from strix.research.corpus import (
    BV2P_CORPUS,
    ground_truth_labels,
    power_check,
    small_gap_pairs,
)


_BENCH = Path(__file__).resolve().parents[1] / "benchmarks" / "bv2p"


def _load(rel: str, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, _BENCH / rel)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {rel}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_idor = _load("idor_memories/core.py", "bv2p_idor_core")
_ssrf = _load("ssrf_fetch/core.py", "bv2p_ssrf_core")


def _response_of(call: Callable[[], dict[str, object]]) -> dict[str, Any]:
    """Run a fixture handler and shape its outcome as a diff-engine response dict."""
    try:
        body = call()
    except _idor.MemoryAccessError as exc:
        return {"status_code": exc.status_code, "headers": {}, "body": json.dumps(exc.detail)}
    return {"status_code": 200, "headers": {}, "body": json.dumps(body, default=str)}


class TestCorpusRegistry(TestCase):
    def test_seeds_present_and_well_formed(self) -> None:
        ids = {pair.pair_id for pair in BV2P_CORPUS}
        self.assertIn("openwebui-idor-memories", ids)
        self.assertIn("flowise-ssrf-http-node", ids)
        for pair in BV2P_CORPUS:
            self.assertTrue(pair.cve.startswith("CVE-"))
            self.assertTrue(pair.vuln_endpoint)
            self.assertIn(
                pair.disposer_evidence, {"diff", "callback", "reachability", "race_result"}
            )

    def test_ground_truth_is_labeled_known_set(self) -> None:
        self.assertEqual(ground_truth_labels(), {p.vuln_endpoint for p in BV2P_CORPUS})

    def test_corpus_is_small_gap_biased(self) -> None:
        self.assertEqual(set(small_gap_pairs()), set(BV2P_CORPUS))

    def test_power_check_is_honest_about_tiny_n(self) -> None:
        # The mechanism works; with the seed corpus it must report *insufficient* power for a
        # McNemar-primary discordant requirement — no tight effect size from tiny n.
        result = power_check(required_discordant=10)
        self.assertEqual(result.small_gap_count, len(small_gap_pairs()))
        self.assertFalse(result.sufficient)
        self.assertTrue(power_check(required_discordant=1).sufficient)


class TestIdorPair(TestCase):
    """P2-disposer exploitability: the attacker's cross-user request flips across the pair."""

    def _attacker_update(self) -> dict[str, object]:
        # bob updates alice-owned mem-1 — the IDOR.
        return _idor.update_memory("mem-1", "bob", "pwned")

    def test_vuln_allows_cross_user_update_patch_forbids(self) -> None:
        with patch.dict(os.environ, {"VULN_MODE": "1"}):
            _idor.reset_state()
            self.assertEqual(self._attacker_update()["user_id"], "alice")  # wrote alice's memory
        with patch.dict(os.environ, {"VULN_MODE": "0"}):
            _idor.reset_state()
            with self.assertRaises(_idor.MemoryAccessError) as ctx:
                self._attacker_update()
            self.assertEqual(ctx.exception.status_code, 403)

    def test_p2_diff_flags_gained_access_across_the_pair(self) -> None:
        with patch.dict(os.environ, {"VULN_MODE": "1"}):
            _idor.reset_state()
            vuln_resp = _response_of(self._attacker_update)
        with patch.dict(os.environ, {"VULN_MODE": "0"}):
            _idor.reset_state()
            patch_resp = _response_of(self._attacker_update)

        flipped = diff(
            [{"label": "patch", "response": patch_resp}, {"label": "vuln", "response": vuln_resp}]
        )
        self.assertTrue(
            any(d.auth_signal_delta == "gained_access" for d in flipped.deltas),
            "P2 disposer must flag gained_access on the vuln-vs-patch pair",
        )

        # Patch deployment alone: no gained_access -> the harness stays silent (no false confirm).
        same = diff(
            [{"label": "a", "response": patch_resp}, {"label": "b", "response": patch_resp}]
        )
        self.assertFalse(any(d.auth_signal_delta == "gained_access" for d in same.deltas))


class TestSsrfPair(TestCase):
    """P0-classifier exploitability: the patched guard blocks internal/metadata SSRF targets."""

    def test_vuln_allows_everything_patch_blocks_internal(self) -> None:
        internal = "http://169.254.169.254/latest/meta-data/"
        external = "http://example.com/health"
        with patch.dict(os.environ, {"VULN_MODE": "1"}):
            self.assertTrue(_ssrf.screen_fetch(internal)[0])  # SSRF: internal fetch allowed
        with patch.dict(os.environ, {"VULN_MODE": "0"}):
            self.assertFalse(_ssrf.screen_fetch(internal)[0])  # patched: blocked
            self.assertTrue(_ssrf.screen_fetch(external)[0])  # external still allowed

    def test_patch_blocks_private_ranges(self) -> None:
        with patch.dict(os.environ, {"VULN_MODE": "0"}):
            for target in ("http://127.0.0.1:8080/", "http://10.0.0.5/", "http://localhost/x"):
                self.assertFalse(_ssrf.screen_fetch(target)[0], f"{target} must be blocked")

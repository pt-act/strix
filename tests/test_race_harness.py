"""Tier-1 tests for the race-condition harness core."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, patch


# Clear race-harness modules so this test file imports them with a fresh
# caido_sdk_client mock (set up below) and no state from other test files.
for _stale_race in (
    "strix.core.race",
    "strix.core.race.models",
    "strix.core.race.verdict",
    "strix.core.race.aggregator",
    "strix.core.race.precondition",
    "strix.core.race.dispatch",
    "strix.core.race.collector",
    "strix.core.race.harness",
):
    sys.modules.pop(_stale_race, None)


# Mock the Caido SDK types before importing any race-harness modules that
# transitively import the replay engine.
class _ConnectionInfoInput:
    def __init__(self, host: str, port: int, is_tls: bool) -> None:
        self.host = host
        self.port = port
        self.is_tls = is_tls


class _ReplaySendOptions:
    def __init__(self, raw: bytes, connection: Any) -> None:
        self.raw = raw
        self.connection = connection


_caido_sdk_client: Any = ModuleType("caido_sdk_client")
_caido_sdk_client.Client = object
_caido_sdk_client.TokenAuthOptions = object
_caido_sdk_client.types = ModuleType("caido_sdk_client.types")
_caido_sdk_client.types.ConnectionInfoInput = _ConnectionInfoInput
_caido_sdk_client.types.CreateScopeOptions = object
_caido_sdk_client.types.ReplaySendOptions = _ReplaySendOptions
_caido_sdk_client.types.RequestGetOptions = object
_caido_sdk_client.types.UpdateScopeOptions = object
sys.modules["caido_sdk_client"] = _caido_sdk_client
sys.modules["caido_sdk_client.types"] = _caido_sdk_client.types

import strix.core.race.dispatch as _dispatch_module
import strix.core.race.harness as _harness_module
import strix.core.race.precondition as _precondition_module
from strix.core.identity.models import Freshness, Identity
from strix.core.race.collector import collect_commit_count, collect_state_delta
from strix.core.race.dispatch import dispatch
from strix.core.race.harness import (
    build_trial_summary,
    run_race_harness,
    target_url_from_request_id,
)
from strix.core.race.models import CopyOutcome, Precondition, ScopedRefusal
from strix.core.race.precondition import reset_precondition, setup_precondition


# Mock cvss so any report filing path can calculate severity without the real package.
_cvss: Any = ModuleType("cvss")


class _CVSS3:
    def __init__(self, vector: str) -> None:
        self._vector = vector

    def scores(self) -> tuple[float, ...]:
        return (7.5,)

    def severities(self) -> tuple[str, ...]:
        return ("HIGH",)


_cvss.CVSS3 = _CVSS3
sys.modules["cvss"] = _cvss

# Mock dedupe to avoid LLM-based duplicate checks in report tests.
_dedupe: Any = ModuleType("strix.report.dedupe")


async def _check_duplicate(_candidate: Any, _existing: Any) -> dict[str, Any]:
    return {"is_duplicate": False}


_dedupe.check_duplicate = _check_duplicate


class _FakeRaceTarget:
    """In-memory target with a deterministic check-then-mutate window."""

    def __init__(self, locked: bool = False) -> None:
        self._balance = 100
        self._redeem_count = 0
        self._locked = locked
        self._committed = 0

    def reset(self) -> bytes:
        self._balance = 100
        self._redeem_count = 0
        self._committed = 0
        return b"HTTP/1.1 200 OK\r\n\r\nreset"

    def read_state(self) -> bytes:
        body = f'{{"balance": {self._balance}, "redeem_count": {self._redeem_count}}}'
        return b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + body.encode("utf-8")

    def redeem(self) -> bytes:
        if self._locked:
            if self._committed == 0:
                self._balance -= 10
                self._redeem_count += 1
                self._committed += 1
                return b"HTTP/1.1 200 OK\r\n\r\nredeemed"
            return b"HTTP/1.1 409 Conflict\r\n\r\nalready used"
        # Unlocked/racy target: every concurrent copy sees the pre-commit state
        # and commits because the check-then-mutate window is artificially widened.
        self._balance -= 10
        self._redeem_count += 1
        return b"HTTP/1.1 200 OK\r\n\r\nredeemed"


class _MockCaido:
    """Mock Caido API primitives used by the race harness."""

    def __init__(self, target: _FakeRaceTarget) -> None:
        self._target = target

    def _path_from_raw(self, raw: bytes) -> str:
        line = raw.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        parts = line.split()
        return parts[1] if len(parts) >= 2 else ""

    async def view_request(self, request_id: str, *, part: str = "request") -> Any:
        _ = part
        paths = {
            "setup": "/reset",
            "state": "/balance",
            "redeem": "/redeem",
        }
        path = paths.get(request_id, "/redeem")
        raw = f"GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
        mock = MagicMock()
        mock.request.raw = raw
        mock.request.host = "example.com"
        mock.request.is_tls = True
        return mock

    async def get_client(self) -> Any:
        return MagicMock()

    async def replay_send_raw(
        self,
        client: Any,
        *,
        raw: bytes,
        connection: Any,
    ) -> dict[str, Any]:
        _ = client, connection
        path = self._path_from_raw(raw)
        if path == "/reset":
            response_raw = self._target.reset()
        elif path == "/balance":
            response_raw = self._target.read_state()
        else:
            response_raw = self._target.redeem()
        return {
            "session_id": "s-1",
            "status": "DONE",
            "error": None,
            "elapsed_ms": 10,
            "response_raw": response_raw,
        }

    def parse_raw_response(self, raw: bytes | None) -> dict[str, Any] | None:
        if not raw:
            return None
        head, _, body_bytes = raw.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1", errors="replace").split("\r\n")
        if not lines:
            return None
        status_parts = lines[0].split(" ", 2)
        if len(status_parts) < 2 or not status_parts[1].isdigit():
            return None
        return {
            "status_code": int(status_parts[1]),
            "length": len(body_bytes),
            "headers": {},
            "body": body_bytes.decode("utf-8", errors="replace"),
            "body_truncated": False,
        }


def _identity(target_key: str = "example.com", role: str = "user") -> Identity:
    return Identity(
        target_key=target_key,
        role=role,
        cookies={"session": "user-session"},
        tokens={"Authorization": "Bearer user-token"},
        headers={"X-Custom": "user-header"},
        provenance="proxy_capture",
        freshness=Freshness(captured_at="2026-06-15T00:00:00Z", status="fresh"),
    )


def _precondition(
    state_counter: str | None = None,
    commit_unit: float | None = None,
) -> Precondition:
    return Precondition(
        description="coupon C unredeemed, balance=100",
        setup_request_id="setup",
        state_read_request_id="state",
        identity_role="user",
        success_indicator="redeemed",
        state_counter=state_counter,
        commit_unit=commit_unit,
    )


def _make_replay_for_target(
    target: _FakeRaceTarget,
) -> Any:
    """Return a mock replay_as_identity that routes by request_id and drives the target."""
    caido = _MockCaido(target)

    async def _replay_as_identity(
        request_id: str,
        identity: Identity,
        *,
        modifications: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _ = modifications
        view = await caido.view_request(request_id)
        replay = await caido.replay_send_raw(
            await caido.get_client(),
            raw=view.request.raw,
            connection=None,
        )
        parsed = caido.parse_raw_response(replay["response_raw"])
        return {
            "success": replay["status"] == "DONE" and parsed is not None,
            "status": replay["status"],
            "error": replay["error"],
            "session_id": replay["session_id"],
            "elapsed_ms": replay["elapsed_ms"],
            "response": parsed,
            "identity": identity.role,
        }

    return _replay_as_identity


class TestRaceDispatcher(IsolatedAsyncioTestCase):
    """Focused tests for the scope-gated concurrent dispatcher."""

    async def test_dispatches_exactly_n_copies(self) -> None:
        target = _FakeRaceTarget(locked=False)
        mock_replay = _make_replay_for_target(target)

        with patch.object(_dispatch_module, "replay_as_identity", new=mock_replay):
            outcomes = await dispatch(
                "redeem",
                _identity(),
                n=5,
                jitter_ms=0,
                target_url="https://example.com/redeem",
                scope_rules=["example.com"],
            )

        self.assertEqual(len(outcomes), 5)
        self.assertTrue(all(o.status == "DONE" for o in outcomes))

    async def test_scope_refusal_out_of_scope(self) -> None:
        with self.assertRaises(ScopedRefusal):
            await dispatch(
                "redeem",
                _identity(),
                n=2,
                jitter_ms=0,
                target_url="https://evil.com/redeem",
                scope_rules=["example.com"],
            )

    async def test_no_requests_sent_on_scope_refusal(self) -> None:
        calls: list[tuple[str, Identity]] = []

        async def mock_replay(request_id: str, identity: Identity) -> dict[str, Any]:
            calls.append((request_id, identity))
            return {
                "success": True,
                "status": "DONE",
                "error": None,
                "elapsed_ms": 5,
                "response": None,
                "session_id": "s-1",
            }

        with (
            patch.object(_dispatch_module, "replay_as_identity", new=mock_replay),
            self.assertRaises(ScopedRefusal),
        ):
            await dispatch(
                "redeem",
                _identity(),
                n=3,
                jitter_ms=0,
                target_url="https://evil.com/redeem",
                scope_rules=["example.com"],
            )

        self.assertEqual(calls, [])


class TestRacePrecondition(IsolatedAsyncioTestCase):
    """Focused tests for the P1-backed precondition manager."""

    async def test_setup_reaches_baseline(self) -> None:
        target = _FakeRaceTarget(locked=False)
        mock_replay = _make_replay_for_target(target)

        with patch.object(_precondition_module, "replay_as_identity", new=mock_replay):
            baseline = await setup_precondition(_precondition(), _identity())

        assert baseline is not None
        self.assertEqual(baseline.get("status_code"), 200)
        self.assertIn("100", baseline.get("body", ""))

    async def test_reset_returns_to_precondition(self) -> None:
        target = _FakeRaceTarget(locked=False)
        target.redeem()
        mock_replay = _make_replay_for_target(target)

        with patch.object(_precondition_module, "replay_as_identity", new=mock_replay):
            await reset_precondition(_precondition(), _identity())
            baseline = await setup_precondition(_precondition(), _identity())

        assert baseline is not None
        self.assertIn("100", baseline.get("body", ""))

    async def test_unreachable_precondition_returns_none(self) -> None:
        async def failing_replay(
            _request_id: str,
            _identity: Identity,
            *,
            modifications: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            _ = modifications
            return {"success": False, "error": "timeout"}

        with patch.object(_precondition_module, "replay_as_identity", new=failing_replay):
            baseline = await setup_precondition(_precondition(), _identity())

        self.assertIsNone(baseline)


class TestRaceCollector(IsolatedAsyncioTestCase):
    """Focused tests for the outcome collector + P2 diff + commit count."""

    def _two_successful_outcomes(self) -> list[CopyOutcome]:
        return [
            CopyOutcome(
                copy_index=0,
                status="DONE",
                error=None,
                elapsed_ms=5,
                response={"status_code": 200, "headers": {}, "body": "redeemed"},
                session_id="s-1",
            ),
            CopyOutcome(
                copy_index=1,
                status="DONE",
                error=None,
                elapsed_ms=5,
                response={"status_code": 200, "headers": {}, "body": "redeemed"},
                session_id="s-2",
            ),
        ]

    def test_state_delta_detects_change(self) -> None:
        baseline = {"status_code": 200, "headers": {}, "body": "balance=100"}
        post = {"status_code": 200, "headers": {}, "body": "balance=70"}
        delta = collect_state_delta(baseline, post)
        self.assertEqual(delta.semantic_delta.body_structure_delta, "size_changed")
        self.assertTrue(delta.observable)

    def test_no_observable_oracle_recorded(self) -> None:
        baseline = {"status_code": 200, "headers": {}, "body": "balance=100"}
        delta = collect_state_delta(baseline, None, observable=False)
        self.assertFalse(delta.observable)
        self.assertEqual(delta.post_action.get("status_code"), 0)

    def test_unit_one_counter_detected_automatically(self) -> None:
        # redeem_count moves by 1; two per-copy success signals are ignored.
        delta = collect_state_delta(
            {"status_code": 200, "body": '{"redeem_count": 0, "balance": 100}'},
            {"status_code": 200, "body": '{"redeem_count": 1, "balance": 90}'},
        )
        self.assertEqual(
            collect_commit_count(self._two_successful_outcomes(), delta),
            1,
        )

    def test_value_counter_with_known_unit_reports_one_commit(self) -> None:
        # balance 100 -> 70, unit 30 -> exactly one redemption, so safe.
        delta = collect_state_delta(
            {"status_code": 200, "body": '{"balance": 100}'},
            {"status_code": 200, "body": '{"balance": 70}'},
        )
        self.assertEqual(
            collect_commit_count(
                self._two_successful_outcomes(),
                delta,
                state_counter="balance",
                commit_unit=30,
            ),
            1,
        )

    def test_value_counter_with_known_unit_reports_multiple_commits(self) -> None:
        # balance 100 -> 10, unit 30 -> three redemptions, so race.
        delta = collect_state_delta(
            {"status_code": 200, "body": '{"balance": 100}'},
            {"status_code": 200, "body": '{"balance": 10}'},
        )
        self.assertEqual(
            collect_commit_count(
                self._two_successful_outcomes(),
                delta,
                state_counter="balance",
                commit_unit=30,
            ),
            3,
        )

    def test_value_counter_without_unit_fails_safe_to_one(self) -> None:
        # balance moved but we don't know the per-commit unit; never guess from
        # per-copy responses.
        delta = collect_state_delta(
            {"status_code": 200, "body": '{"balance": 100}'},
            {"status_code": 200, "body": '{"balance": 70}'},
        )
        self.assertEqual(
            collect_commit_count(
                self._two_successful_outcomes(),
                delta,
                state_counter="balance",
                commit_unit=None,
            ),
            1,
        )

    def test_no_state_change_means_zero_commits(self) -> None:
        delta = collect_state_delta(
            {"status_code": 200, "body": '{"redeem_count": 0, "balance": 100}'},
            {"status_code": 200, "body": '{"redeem_count": 0, "balance": 100}'},
        )
        self.assertEqual(collect_commit_count(self._two_successful_outcomes(), delta), 0)

    def test_non_json_state_fails_safe_to_one(self) -> None:
        # State changed but body is not a parseable JSON counter; fail safe.
        delta = collect_state_delta(
            {"status_code": 200, "body": "balance=100"},
            {"status_code": 200, "body": "balance=70"},
        )
        self.assertEqual(
            collect_commit_count(
                self._two_successful_outcomes(),
                delta,
                success_indicator="redeemed",
            ),
            1,
        )

    def test_no_observable_oracle_falls_back_to_response_signals(self) -> None:
        # Without an observable state read, per-copy response signals are the only
        # signal available.
        delta = collect_state_delta(
            {"status_code": 200, "body": "balance=100"},
            {"status_code": 200, "body": "balance=80"},
            observable=False,
        )
        self.assertEqual(
            collect_commit_count(
                self._two_successful_outcomes(),
                delta,
                success_indicator="redeemed",
            ),
            2,
        )


class TestRaceHarnessEndToEnd(IsolatedAsyncioTestCase):
    """End-to-end race harness against a deterministic fake target."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    async def _run(self, locked: bool, n: int = 3, retry_bound: int = 1) -> dict[str, Any]:
        target = _FakeRaceTarget(locked=locked)
        mock_replay = _make_replay_for_target(target)

        with (
            patch.object(_precondition_module, "replay_as_identity", new=mock_replay),
            patch.object(_dispatch_module, "replay_as_identity", new=mock_replay),
            patch.object(_harness_module, "replay_as_identity", new=mock_replay),
        ):
            result = await run_race_harness(
                request_id="redeem",
                precondition=_precondition(),
                identity=_identity(),
                target_url="https://example.com/redeem",
                scope_rules=["example.com"],
                n=n,
                jitter_ms=0,
                retry_bound=retry_bound,
            )

        return build_trial_summary(result)

    async def test_double_redemption_reports_race(self) -> None:
        summary = await self._run(locked=False, n=3)
        self.assertEqual(summary["verdict"], "race")
        self.assertEqual(summary["commit_count"], 3)
        self.assertTrue(summary["observable_oracle_used"])

    async def test_locked_target_reports_safe(self) -> None:
        summary = await self._run(locked=True, n=3)
        self.assertEqual(summary["verdict"], "safe")
        self.assertEqual(summary["commit_count"], 1)

    async def test_inconclusive_without_state_change(self) -> None:
        # A target that never changes state and never returns a successful commit
        # should be inconclusive.
        target = _FakeRaceTarget(locked=False)
        target.redeem = lambda: b"HTTP/1.1 400 Bad Request\r\n\r\ninvalid"  # type: ignore[method-assign]
        mock_replay = _make_replay_for_target(target)

        with (
            patch.object(_precondition_module, "replay_as_identity", new=mock_replay),
            patch.object(_dispatch_module, "replay_as_identity", new=mock_replay),
            patch.object(_harness_module, "replay_as_identity", new=mock_replay),
        ):
            result = await run_race_harness(
                request_id="redeem",
                precondition=_precondition(),
                identity=_identity(),
                target_url="https://example.com/redeem",
                scope_rules=["example.com"],
                n=3,
                jitter_ms=0,
                retry_bound=1,
            )

        self.assertEqual(result.verdict, "inconclusive")
        self.assertEqual(result.retry_count, 1)

    async def test_target_url_extraction(self) -> None:
        target = _FakeRaceTarget(locked=False)
        caido = _MockCaido(target)

        with patch.object(_harness_module.caido_api, "view_request", new=caido.view_request):
            url = await target_url_from_request_id("redeem")

        self.assertEqual(url, "https://example.com/redeem")


if __name__ == "__main__":
    import unittest

    unittest.main()

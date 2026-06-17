"""Integration tests for Phase-5 business-logic composition against the Docker fixture.

These tests drive the real ``RealExecutionContext`` (live identity store + replay + race
harness) against the ``benchmarks/business_logic_fixture`` target. The Caido replay
boundary is patched to route to the live Docker container, following the same pattern
used by Phase-4 harness tests.

Tests are skipped when Docker is not available (daemon not running) so the suite stays
green in environments without Docker.
"""

from __future__ import annotations

import unittest
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, patch

import strix.core.identity.replay as _identity_replay_module
import strix.core.race.dispatch as _dispatch_module
import strix.core.race.harness as _harness_module
import strix.core.race.precondition as _precondition_module
from strix.core.identity import IdentityStore, identity_store_path
from strix.core.identity.models import Freshness, Identity
from strix.core.logic.models import (
    BusinessLogicModel,
    ConfirmedViolation,
    FlowModel,
    JourneyModel,
    MonetaryOperation,
    MonetaryRelation,
    Step,
    UnconfirmedHypothesis,
)
from strix.core.logic.orchestrator import BusinessLogicOrchestrator
from strix.core.logic.store import BusinessLogicStore
from strix.core.paths import logic_model_path
from strix.tools.proxy import caido_api as _caido_api_module


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

_dedupe: Any = ModuleType("strix.report.dedupe")


async def _check_duplicate(_candidate: Any, _existing: Any) -> dict[str, Any]:
    return {"is_duplicate": False}


_dedupe.check_duplicate = _check_duplicate
sys.modules["strix.report.dedupe"] = _dedupe


def _docker_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _DockerFixture:
    """Lifecycle manager for the business-logic fixture container."""

    def __init__(self, vuln_mode: bool) -> None:
        self.vuln_mode = "1" if vuln_mode else "0"
        self.port = _free_port()
        self.container_name = f"strix-bl-fixture-{self.port}"
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._image_built = False
        self._container_id: str | None = None

    def build(self) -> None:
        fixture_dir = Path(__file__).parent.parent.parent / "benchmarks" / "business_logic_fixture"
        subprocess.run(
            ["docker", "build", "-t", "strix-business-logic-fixture", str(fixture_dir)],
            check=True,
            capture_output=True,
            text=True,
        )
        self._image_built = True

    def start(self) -> None:
        if not self._image_built:
            self.build()
        result = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                self.container_name,
                "-p",
                f"127.0.0.1:{self.port}:8080",
                "-e",
                f"VULN_MODE={self.vuln_mode}",
                "strix-business-logic-fixture",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        self._container_id = result.stdout.strip()
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                response = subprocess.run(
                    [
                        "curl",
                        "-s",
                        "-o",
                        "/dev/null",
                        "-w",
                        "%{http_code}",
                        f"{self.base_url}/state",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=2,
                )
                if response.stdout.strip() == "200":
                    return
            except (OSError, subprocess.TimeoutExpired):
                pass
            time.sleep(0.5)
        raise RuntimeError("fixture container did not become healthy")

    def stop(self) -> None:
        if self._container_id:
            subprocess.run(
                ["docker", "stop", "-t", "5", self.container_name],
                capture_output=True,
                text=True,
                check=False,
            )
            self._container_id = None


class _DockerIntegrationTestCase(IsolatedAsyncioTestCase):
    """Base that starts the Docker fixture and patches the Caido/replay boundary."""

    vuln_mode: bool = False

    @classmethod
    def setUpClass(cls) -> None:
        if not _docker_available():
            raise unittest.SkipTest("Docker daemon not available")  # type: ignore[misc]

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name)
        self.target_id = "127.0.0.1"

        self.fixture = _DockerFixture(vuln_mode=self.vuln_mode)
        self.fixture.start()
        self.target_url = self.fixture.base_url

        self._install_patches()
        self._store_identity()

    def tearDown(self) -> None:
        self._harness_replay_patches.stop()
        self._dispatch_replay_patches.stop()
        self._precondition_replay_patches.stop()
        self._replay_patches.stop()
        self._patches.stop()
        self.fixture.stop()
        self.tmp.cleanup()

    def _store_identity(self) -> None:
        store = IdentityStore(identity_store_path(self.run_dir))
        identity = Identity(
            target_key=self.target_id,
            role="user",
            cookies={"session": "user-session"},
            tokens={"Authorization": "Bearer user-token"},
            headers={"X-Custom": "user-header"},
            provenance="proxy_capture",
            freshness=Freshness(captured_at="2026-06-15T00:00:00Z", status="fresh"),
        )
        store.upsert_identity(identity)
        store.close()

    def _route_request(
        self,
        request_id: str,
        modifications: dict[str, Any] | None,
    ) -> dict[str, Any]:
        path = {
            "reset-req": "/reset",
            "state-req": "/state",
            "redeem-req": "/redeem",
            "checkout-req": "/checkout",
        }.get(request_id, "/")

        method = "GET" if path == "/state" else "POST"
        body: str | None = None
        if path == "/checkout":
            body = self._checkout_body
            if modifications and "body" in modifications:
                body = modifications["body"]

        try:
            result = subprocess.run(
                [
                    "curl",
                    "-s",
                    "-X",
                    method,
                    f"{self.target_url}{path}",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    body or "",
                    "-w",
                    "\n%{http_code}",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            lines = result.stdout.strip().splitlines()
            status_line = lines[-1]
            body_line = lines[-2] if len(lines) > 1 else ""
            status_code = int(status_line) if status_line.isdigit() else 0
            return {
                "success": True,
                "status": "DONE",
                "response": {"status_code": status_code, "body": body_line},
            }
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"success": False, "error": str(exc)}

    async def _mock_replay_as_identity(
        self,
        request_id: str,
        identity: Identity,
        *,
        modifications: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = self._route_request(request_id, modifications)
        return {
            "success": result.get("success", False),
            "status": result.get("status", "ERROR"),
            "error": result.get("error"),
            "response": result.get("response"),
            "session_id": "s-1",
            "elapsed_ms": 5,
            "identity": identity.role,
        }

    def _install_patches(self) -> None:
        async def view_request(request_id: str, *, part: str = "request") -> Any:
            _ = request_id, part
            mock = MagicMock()
            method = "POST"
            path = "/"
            body = ""
            if request_id == "state-req":
                method = "GET"
                path = "/state"
            elif request_id == "reset-req":
                path = "/reset"
            elif request_id == "redeem-req":
                path = "/redeem"
                body = '{"coupon": "COUPON-1"}'
            elif request_id == "checkout-req":
                path = "/checkout"
                body = self._checkout_body
            raw = (
                f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
            )
            if body:
                raw += f"Content-Length: {len(body)}\r\n"
            raw += f"\r\n{body}"
            mock.request.raw = raw.encode("utf-8")
            mock.request.host = "127.0.0.1"
            mock.request.is_tls = False
            return mock

        self._patches = patch.multiple(_caido_api_module, view_request=view_request)
        self._patches.start()

        self._checkout_body = '{"price": 5, "quantity": 1, "total": 5}'

        self._replay_patches = patch.multiple(
            _identity_replay_module,
            replay_as_identity=self._mock_replay_as_identity,
        )
        self._replay_patches.start()
        self._precondition_replay_patches = patch.multiple(
            _precondition_module,
            replay_as_identity=self._mock_replay_as_identity,
        )
        self._precondition_replay_patches.start()
        self._dispatch_replay_patches = patch.multiple(
            _dispatch_module,
            replay_as_identity=self._mock_replay_as_identity,
        )
        self._dispatch_replay_patches.start()
        self._harness_replay_patches = patch.multiple(
            _harness_module,
            replay_as_identity=self._mock_replay_as_identity,
        )
        self._harness_replay_patches.start()

    def _store_model(self, model: BusinessLogicModel) -> None:
        with BusinessLogicStore(logic_model_path(self.run_dir, model.engagement_id)) as store:
            store.save(model)

    def _orchestrator(self) -> BusinessLogicOrchestrator:
        return BusinessLogicOrchestrator(
            run_dir=self.run_dir,
            target_id=self.target_id,
            target_url=self.target_url,
            scope_rules=["127.0.0.1"],
        )


class TestDoubleSpendVulnDocker(_DockerIntegrationTestCase):
    """TP: the vulnerable Docker fixture allows a coupon to be redeemed concurrently."""

    vuln_mode = True

    async def test_double_spend_confirmed(self) -> None:
        flow = FlowModel(
            name="coupon_flow",
            flow_name="coupon",
            request_id="redeem-req",
            monetary_op=MonetaryOperation(
                name="coupon_redeem",
                request_id="redeem-req",
                setup_request_id="reset-req",
                state_read_request_id="state-req",
                relation=MonetaryRelation(
                    state_counter="redeem_count",
                    commit_unit=1,
                ),
                one_time=True,
            ),
            journey=JourneyModel(
                name="redeem",
                steps=[Step(name="redeem", order=0, request_id="redeem-req")],
            ),
            bound_invariants=["double-spend"],
        )
        model = BusinessLogicModel(
            engagement_id="eng-1",
            target_id=self.target_id,
            flows={"coupon_flow": flow},
        )
        self._store_model(model)

        result = await self._orchestrator().run("eng-1", "coupon_flow", "double-spend")

        self.assertIsInstance(result, ConfirmedViolation)
        assert isinstance(result, ConfirmedViolation)
        self.assertEqual(result.invariant_kind, "double-spend")
        self.assertEqual(result.executed_sequence.artifact_type, "race_result")


class TestDoubleSpendPatchDocker(_DockerIntegrationTestCase):
    """TN: the patched Docker fixture rejects concurrent redemption; gate stays silent."""

    vuln_mode = False

    async def test_double_spend_unconfirmed(self) -> None:
        flow = FlowModel(
            name="coupon_flow",
            flow_name="coupon",
            request_id="redeem-req",
            monetary_op=MonetaryOperation(
                name="coupon_redeem",
                request_id="redeem-req",
                setup_request_id="reset-req",
                state_read_request_id="state-req",
                relation=MonetaryRelation(
                    state_counter="redeem_count",
                    commit_unit=1,
                ),
                one_time=True,
            ),
            journey=JourneyModel(
                name="redeem",
                steps=[Step(name="redeem", order=0, request_id="redeem-req")],
            ),
            bound_invariants=["double-spend"],
        )
        model = BusinessLogicModel(
            engagement_id="eng-1",
            target_id=self.target_id,
            flows={"coupon_flow": flow},
        )
        self._store_model(model)

        result = await self._orchestrator().run("eng-1", "coupon_flow", "double-spend")

        self.assertIsInstance(result, UnconfirmedHypothesis)


class TestPriceMismatchVulnDocker(_DockerIntegrationTestCase):
    """TP: the vulnerable Docker fixture charges a tampered client total."""

    vuln_mode = True

    async def test_price_mismatch_confirmed(self) -> None:
        flow = FlowModel(
            name="checkout",
            flow_name="coupon",
            request_id="checkout-req",
            monetary_op=MonetaryOperation(
                name="checkout",
                request_id="checkout-req",
                relation=MonetaryRelation(
                    price_param="price",
                    quantity_param="quantity",
                    total_param="total",
                    baseline_values={"price": 5, "quantity": 1, "total": 5},
                    tamper_values={"price": 0, "quantity": 1, "total": 5},
                ),
            ),
            journey=JourneyModel(
                name="checkout",
                steps=[Step(name="checkout", order=0, request_id="checkout-req")],
            ),
            bound_invariants=["price-mismatch"],
        )
        model = BusinessLogicModel(
            engagement_id="eng-1",
            target_id=self.target_id,
            flows={"checkout": flow},
        )
        self._store_model(model)

        result = await self._orchestrator().run("eng-1", "checkout", "price-mismatch")

        self.assertIsInstance(result, ConfirmedViolation)
        assert isinstance(result, ConfirmedViolation)
        self.assertEqual(result.invariant_kind, "price-mismatch")
        self.assertEqual(result.executed_sequence.artifact_type, "diff")


class TestPriceMismatchPatchDocker(_DockerIntegrationTestCase):
    """TN: the patched Docker fixture rejects the tampered total; gate stays silent."""

    vuln_mode = False

    async def test_price_mismatch_unconfirmed(self) -> None:
        flow = FlowModel(
            name="checkout",
            flow_name="coupon",
            request_id="checkout-req",
            monetary_op=MonetaryOperation(
                name="checkout",
                request_id="checkout-req",
                relation=MonetaryRelation(
                    price_param="price",
                    quantity_param="quantity",
                    total_param="total",
                    baseline_values={"price": 5, "quantity": 1, "total": 5},
                    tamper_values={"price": 0, "quantity": 1, "total": 5},
                ),
            ),
            journey=JourneyModel(
                name="checkout",
                steps=[Step(name="checkout", order=0, request_id="checkout-req")],
            ),
            bound_invariants=["price-mismatch"],
        )
        model = BusinessLogicModel(
            engagement_id="eng-1",
            target_id=self.target_id,
            flows={"checkout": flow},
        )
        self._store_model(model)

        result = await self._orchestrator().run("eng-1", "checkout", "price-mismatch")

        self.assertIsInstance(result, UnconfirmedHypothesis)

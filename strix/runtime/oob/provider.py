"""OOB provider abstraction backed by ProjectDiscovery interactsh.

``OobProvider`` is the minimal interface the rest of Strix consumes.
``InteractshProvider`` is the only concrete implementation. Public
ProjectDiscovery servers are used when ``server_url`` is ``None``; a
self-hosted ``interactsh-server`` is selected by providing a non-empty URL.

The adapter is intentionally thin: most of the work is delegated to the
``interactsh-client`` binary. In production the binary is started by the
container entrypoint (``containers/docker-entrypoint.sh``) and the provider
reads its log file. In standalone / test mode the provider can spawn the
client itself.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from strix.core.oob.models import OobConfig, OobHit


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)


class OobProvider(ABC):
    """Minimal interface for an OOB callback listener."""

    @abstractmethod
    async def start(self, run_dir: Path) -> None:
        """Bring up the listener sidecar and block until it is ready."""

    @abstractmethod
    def ready(self) -> bool:
        """Return whether the listener has passed its readiness probe."""

    @abstractmethod
    def base_host(self) -> str:
        """Return the token-suffix domain, e.g. ``abc123.oast.pro``."""

    @abstractmethod
    async def poll_interactions(self) -> list[OobHit]:
        """Fetch new interactions since the last poll."""

    @property
    @abstractmethod
    def config(self) -> OobConfig:
        """Return the provider configuration."""


class InteractshProvider(OobProvider):
    """interactsh-client sidecar wrapper.

    Two modes:

    - **Spawn mode** (default, local/test): the provider starts the client
      as a subprocess and extracts the generated hostname from its stdout.
    - **No-spawn mode** (container production): the client is already running
      (started by the container entrypoint). The provider waits for the
      interaction log file to appear and extracts the hostname from it.

    The public ProjectDiscovery server pool is used when ``server_url`` is
    ``None``; a self-hosted server is used when a URL is provided.
    """

    _DEFAULT_BIN = "interactsh-client"
    _HOST_RE = re.compile(r"[a-zA-Z0-9]{8,64}\.[a-zA-Z0-9\.-]+")
    _TOKEN_FROM_HOST_RE = re.compile(r"^([a-zA-Z0-9_-]+)\.")
    _STARTUP_TIMEOUT = 60.0

    def __init__(
        self,
        *,
        config: OobConfig | None = None,
        binary: str | None = None,
        poll_interval: float = 5.0,
        no_spawn: bool = False,
    ) -> None:
        self._config = config or OobConfig()
        self._binary = binary or self._DEFAULT_BIN
        self._poll_interval = poll_interval
        self._no_spawn = no_spawn
        self._proc: asyncio.subprocess.Process | None = None
        self._base_host: str | None = None
        self._ready = False
        self._run_dir: Path | None = None
        self._log_path: Path | None = None

    @property
    def config(self) -> OobConfig:
        return self._config

    async def start(self, run_dir: Path) -> None:
        """Start the provider and wait for the interactsh hostname."""
        if self._ready:
            return

        self._run_dir = run_dir
        run_dir.mkdir(parents=True, exist_ok=True)
        self._log_path = run_dir / "interactsh.log"

        if self._no_spawn:
            self._base_host = await self._wait_for_hostname_in_log()
        else:
            self._base_host = await self._spawn_and_read_hostname()

        self._ready = True
        logger.info("OOB listener ready on %s", self._base_host)

    async def _spawn_and_read_hostname(self) -> str:
        """Spawn interactsh-client and return the generated hostname."""
        cmd = self._build_start_command()
        logger.info("Starting interactsh-client: %s", " ".join(cmd))
        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert self._proc.stdout is not None
        return await self._wait_for_hostname(self._proc.stdout)

    async def _wait_for_hostname(self, stdout: asyncio.StreamReader) -> str:
        """Block until the client prints its generated hostname."""
        deadline = asyncio.get_event_loop().time() + self._STARTUP_TIMEOUT
        while asyncio.get_event_loop().time() < deadline:
            try:
                line = await asyncio.wait_for(stdout.readline(), timeout=2.0)
            except TimeoutError:
                continue
            if not line:
                continue
            text = line.decode("utf-8", errors="replace").strip()
            match = self._HOST_RE.search(text)
            if match:
                return match.group(0)
            logger.debug("interactsh-client stdout: %s", text)
        raise RuntimeError(
            f"interactsh-client did not emit a hostname within {self._STARTUP_TIMEOUT}s",
        )

    async def _wait_for_hostname_in_log(self) -> str:
        """Wait for the log file to contain a hostname line."""
        deadline = asyncio.get_event_loop().time() + self._STARTUP_TIMEOUT
        while asyncio.get_event_loop().time() < deadline:
            if self._log_path is not None and self._log_path.exists():
                text = self._log_path.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    match = self._HOST_RE.search(line)
                    if match:
                        return match.group(0)
            await asyncio.sleep(0.5)
        raise RuntimeError(
            f"interactsh-client log did not contain a hostname within {self._STARTUP_TIMEOUT}s",
        )

    def _build_start_command(self) -> list[str]:
        if self._log_path is None:
            raise RuntimeError("Provider has not been started")
        cmd = [self._binary, "-json", "-o", str(self._log_path)]
        if self._config.server_url:
            cmd.extend(["-server", self._config.server_url])
        if self._config.auth_token:
            cmd.extend(["-token", self._config.auth_token])
        return cmd

    def ready(self) -> bool:
        if not self._ready:
            return False
        if self._no_spawn:
            return True
        return self._proc is not None and self._proc.returncode is None

    def base_host(self) -> str:
        if not self._base_host:
            raise RuntimeError("OOB provider has not started")
        return self._base_host

    async def poll_interactions(self) -> list[OobHit]:
        """Poll the interactsh-client log file for new interactions."""
        if not self.ready():
            return []

        if self._log_path is None or not self._log_path.exists():
            return []

        text = self._log_path.read_text(encoding="utf-8", errors="replace")
        hits: list[OobHit] = []
        for line in text.strip().splitlines():
            hit = self._parse_json_line(line)
            if hit is not None:
                hits.append(hit)
        return hits

    def _parse_json_line(self, line: str) -> OobHit | None:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        full_fqdn = data.get("full-id", data.get("host", ""))
        if not full_fqdn:
            return None

        token = self._extract_token(full_fqdn)
        protocol = self._normalize_protocol(data.get("protocol", "dns"))
        return OobHit(
            protocol=protocol,  # type: ignore[arg-type]
            token=token,
            full_fqdn=full_fqdn,
            source_ip=data.get("remote-address", "0.0.0.0"),  # nosec B104
            timestamp=datetime.now(UTC),
            raw_request=(data.get("raw-request") or "").encode("utf-8") or None,
            metadata={"interactsh_protocol": protocol, "interactsh_data": data},
        )

    def _extract_token(self, full_fqdn: str) -> str:
        match = self._TOKEN_FROM_HOST_RE.match(full_fqdn)
        return match.group(1) if match else ""

    @staticmethod
    def _normalize_protocol(value: Any) -> str:
        proto = str(value).lower()
        if proto in {"dns", "http", "https", "smtp"}:
            return proto
        return "dns"

    async def stop(self) -> None:
        if self._proc is not None and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=10.0)
            except TimeoutError:
                self._proc.kill()
                await self._proc.wait()
        self._ready = False

    def __del__(self) -> None:
        if self._proc is not None and self._proc.returncode is None:
            with contextlib.suppress(Exception):
                self._proc.terminate()

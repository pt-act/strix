"""Bootstrap the interactsh-client OOB sidecar inside a sandbox session.

Mirrors ``strix/runtime/caido_bootstrap.py``: bring up the sidecar, wait for a
readiness signal (generated hostname), and return a host-side ``OobProvider``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from strix.core.oob.models import OobConfig  # noqa: TC001
from strix.runtime.oob.provider import InteractshProvider


if TYPE_CHECKING:
    from pathlib import Path

    from agents.sandbox.session import BaseSandboxSession

logger = logging.getLogger(__name__)


async def bootstrap_interactsh(
    _session: BaseSandboxSession,
    *,
    run_dir: Path,
    config: OobConfig | None = None,
) -> InteractshProvider:
    """Return a ready InteractshProvider reading the container-side log file.

    The interactsh-client binary is started by the container entrypoint
    (``containers/docker-entrypoint.sh``) and writes interactions to
    ``<run_dir>/interactsh.log``. We wait for that log to contain a hostname,
    then return a provider that polls it.
    """
    provider = InteractshProvider(config=config, no_spawn=True)
    await provider.start(run_dir)
    logger.info("OOB provider bootstrapped on %s", provider.base_host())
    return provider

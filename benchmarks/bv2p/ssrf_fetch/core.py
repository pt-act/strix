"""Pure SSRF guard for the Flowise HTTP-node B-V2P pair (CVE-2026-31829).

No web-framework import, so the guard is unit-testable without fastapi. ``app.py`` is the thin
FastAPI wrapper. The patched guard reuses the P0 net classifier
(``strix.core.net.is_internal_target``) — no primitive is re-implemented.
"""

from __future__ import annotations

import os

import httpx

from strix.core.net import is_internal_target


def is_vuln() -> bool:
    return os.getenv("VULN_MODE", "1") == "1"


def screen_fetch(url: str) -> tuple[bool, str]:
    """Return ``(allowed, reason)``. Patched mode (the 3.0.13 fix) blocks internal/metadata SSRF."""
    if is_vuln():
        return True, "vuln: no SSRF guard"
    if is_internal_target(url):
        return False, "patched: internal/metadata target blocked"
    return True, "patched: external target allowed"


def perform_fetch(url: str) -> int | None:
    """Live outbound fetch (the SSRF on the vuln deployment). Only called after the guard allows."""
    try:
        return httpx.get(url, timeout=5.0).status_code
    except httpx.HTTPError:
        return None

"""Capture identities from proxy traffic or explicit login flows."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from strix.core.identity.models import Freshness, Identity
from strix.core.identity.redaction import redact_headers


_AUTH_HEADER_KEYS = frozenset(
    {
        "authorization",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "auth",
        "token",
        "access-token",
        "refresh-token",
    }
)


def _extract_auth_headers(headers: dict[str, str]) -> dict[str, str]:
    """Pick out auth-bearing headers from a captured request."""
    return {
        k: v
        for k, v in headers.items()
        if k.lower() in _AUTH_HEADER_KEYS or any(token in k.lower() for token in ("token", "auth"))
    }


def _extract_cookies(cookie_header: str) -> dict[str, str]:
    """Parse a ``Cookie`` header into a dict."""
    cookies: dict[str, str] = {}
    if not cookie_header:
        return cookies
    segments = [seg.strip() for seg in cookie_header.split(";")]
    for segment in segments:
        if "=" in segment:
            key, value = segment.split("=", 1)
            cookies[key.strip()] = value.strip()
    return cookies


def _now() -> str:
    return datetime.now(UTC).isoformat()


def capture_from_proxy(
    target_key: str,
    role: str,
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str = "",
) -> Identity:
    """Create an identity by extracting auth material from a captured request.

    Args:
        target_key: Canonical target key (host[:port] or repo id).
        role: Label for this identity (``user``, ``admin``, etc.).
        method: HTTP method of the captured request.
        url: Full URL of the captured request.
        headers: Request headers.
        body: Optional request body (used to detect token leaks in logs).
    """
    _ = method, url, body  # unused except for interface completeness
    auth_headers = _extract_auth_headers(headers)
    cookie_header = headers.get("Cookie") or headers.get("cookie")
    cookies = _extract_cookies(cookie_header or "")
    tokens: dict[str, str] = {}
    if "authorization" in auth_headers:
        tokens["authorization"] = auth_headers.pop("authorization")
    return Identity(
        target_key=target_key,
        role=role,
        cookies=cookies,
        tokens=tokens,
        headers=auth_headers,
        provenance="proxy_capture",
        freshness=Freshness(captured_at=_now(), status="fresh"),
    )


def capture_from_login(
    target_key: str,
    role: str,
    *,
    response_headers: dict[str, str],
    response_cookies: dict[str, str] | None = None,
    response_body: Any = None,
) -> Identity:
    """Create an identity from a post-login response.

    Args:
        target_key: Canonical target key.
        role: Role label (``user`` or ``admin``).
        response_headers: Headers from the login response (e.g. ``Authorization``).
        response_cookies: Cookies set by the login response.
        response_body: Optional body, used only for token extraction patterns.
    """
    cookies = dict(response_cookies or {})
    headers = _extract_auth_headers(response_headers)
    tokens: dict[str, str] = {}
    if "authorization" in headers:
        tokens["authorization"] = headers.pop("authorization")
    _ = response_body  # reserved for future token extraction from JSON
    return Identity(
        target_key=target_key,
        role=role,
        cookies=cookies,
        tokens=tokens,
        headers=headers,
        provenance="login_flow",
        freshness=Freshness(captured_at=_now(), status="fresh"),
    )


def redacted_capture_summary(identity: Identity) -> dict[str, Any]:
    """Return a redacted summary safe for agent-visible logs."""
    return {
        "target_key": identity.target_key,
        "role": identity.role,
        "provenance": identity.provenance,
        "freshness": identity.freshness.model_dump(),
        "authorized": identity.is_authorized(),
        "headers_redacted": list(redact_headers(identity.headers).keys()),
        "cookies_redacted": list(identity.cookies.keys()),
        "tokens_redacted": list(identity.tokens.keys()),
    }

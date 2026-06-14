"""Credential redaction for identity records and HTTP artifacts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from strix.core.identity.models import Identity

_REDACTED = "****"


_KEYS_TO_REDACT = frozenset(
    {
        "authorization",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "auth",
        "token",
        "access_token",
        "access-token",
        "refresh_token",
        "refresh-token",
        "session",
        "sessionid",
        "session_id",
        "session-id",
        "cookie",
        "cookies",
        "jwt",
        "bearer",
        "password",
        "secret",
        "apikey",
    }
)


def _should_redact_key(key: str) -> bool:
    lowered = key.lower().strip()
    return lowered in _KEYS_TO_REDACT or any(
        token in lowered for token in ("token", "secret", "password", "apikey", "api_key")
    )


def redact_value(value: str) -> str:
    """Return a redacted placeholder for any credential value."""
    if not value:
        return value
    return _REDACTED


def redact_identity(identity: Identity) -> dict[str, Any]:
    """Return a serializable copy of ``identity`` with credential values masked."""
    return {
        "target_key": identity.target_key,
        "role": identity.role,
        "cookies": {k: redact_value(v) for k, v in identity.cookies.items()},
        "tokens": {k: redact_value(v) for k, v in identity.tokens.items()},
        "headers": {k: redact_value(v) for k, v in identity.headers.items()},
        "provenance": identity.provenance,
        "freshness": identity.freshness.model_dump(),
        "is_reserved_expired": identity.is_reserved_expired,
        "authorized": identity.is_authorized(),
    }


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact credential-bearing HTTP header values."""
    return {k: redact_value(v) if _should_redact_key(k) else v for k, v in headers.items()}


def redact_request_components(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str,
) -> dict[str, Any]:
    """Return a redacted summary of an HTTP request."""
    safe_body = body
    if any(token in body.lower() for token in ("password", "secret", "token")):
        safe_body = _REDACTED
    return {
        "method": method,
        "url": url,
        "headers": redact_headers(headers),
        "body": safe_body,
    }

"""Identity-aware replay engine."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from strix.core.identity.redaction import redact_headers
from strix.tools.proxy import caido_api


if TYPE_CHECKING:
    from strix.core.identity.models import Identity

# Auth headers that are stripped from the captured request before substitution.
_STRIP_HEADER_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "auth",
        "token",
        "access-token",
        "refresh-token",
    }
)


LADDER_ROLES = ["anonymous", "user", "admin", "expired"]


def _strip_original_auth(headers: dict[str, str]) -> dict[str, str]:
    """Remove auth-bearing headers from the captured request."""
    return {
        k: v
        for k, v in headers.items()
        if k.lower() not in _STRIP_HEADER_KEYS
        and not any(token in k.lower() for token in ("token", "auth"))
    }


def _overlay_identity_auth(
    headers: dict[str, str],
    identity: Identity,
) -> dict[str, str]:
    """Overlay an identity's cookies, tokens, and headers onto a request."""
    overlaid = dict(headers)
    overlaid.update(identity.headers)
    overlaid.update(identity.tokens)
    if identity.cookies:
        cookie_parts = [f"{k}={v}" for k, v in identity.cookies.items()]
        overlaid["Cookie"] = "; ".join(cookie_parts)
    return overlaid


async def replay_as_identity(
    request_id: str,
    identity: Identity,
    *,
    modifications: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay a captured request as the supplied identity.

    The captured request's original auth material is stripped and replaced
    with the identity's cookies, tokens, and headers. Non-auth fields are
    preserved.
    """
    mods = modifications or {}
    result = await caido_api.view_request(request_id, part="request")
    if result is None or not result.request or not result.request.raw:
        raise ValueError(f"Request {request_id} not found or has no raw request")

    original = result.request
    raw_str = original.raw.decode("utf-8", errors="replace")
    components = caido_api.parse_raw_request(raw_str)
    stripped_headers = _strip_original_auth(components["headers"])
    final_headers = _overlay_identity_auth(stripped_headers, identity)
    components["headers"] = final_headers

    full_url = caido_api.full_url_from_components(original, components, mods)
    modified = caido_api.apply_modifications(components, mods, full_url)
    connection, raw = caido_api.build_raw_request(
        method=modified["method"],
        url=modified["url"],
        headers=modified["headers"],
        body=modified["body"],
    )
    replay = await caido_api.replay_send_raw(
        await caido_api.get_client(), raw=raw, connection=connection
    )
    parsed = caido_api.parse_raw_response(replay.get("response_raw"))
    return {
        "success": replay.get("status") == "DONE" and parsed is not None,
        "status": replay.get("status"),
        "error": replay.get("error"),
        "session_id": replay.get("session_id"),
        "elapsed_ms": replay.get("elapsed_ms"),
        "response": parsed,
        "identity": identity.role,
    }


async def replay_ladder(
    request_id: str,
    identities: list[Identity],
    *,
    modifications: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay a request across every supplied identity and collect results."""
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for identity in identities:
        try:
            result = await replay_as_identity(request_id, identity, modifications=modifications)
            results.append(result)
        except Exception as exc:  # noqa: BLE001
            failures.append(
                {
                    "identity": identity.role,
                    "success": False,
                    "error": f"Replay failed: {exc}",
                }
            )
    return {
        "success": all(r.get("success") for r in results) and not failures,
        "results": results,
        "failures": failures,
        "identities": [redact_headers(i.headers) for i in identities],
    }

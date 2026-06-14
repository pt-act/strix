"""Redirect-chain revalidation with internal-target rejection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from strix.core.net.classifier import is_internal_target
from strix.core.net.normalize import normalize_url


if TYPE_CHECKING:
    from email.message import Message


class _HasHeaders(Protocol):
    headers: Message


_DEFAULT_MAX_HOPS = 10
_DEFAULT_TIMEOUT = 10


class RedirectValidationError(Exception):
    """Raised when a redirect chain lands on an internal or metadata target."""


class RedirectLoopError(RedirectValidationError):
    """Raised when the redirect chain exceeds the hop limit."""


class RedirectInternalTargetError(RedirectValidationError):
    """Raised when a redirect hop resolves to an internal target."""


def _get_redirect_url(response: _HasHeaders, base_url: str) -> str | None:
    """Extract the next URL from a 3xx response, resolving relative URLs."""
    location = response.headers.get("Location") or response.headers.get("location")
    if not location:
        return None
    location_str = str(location).strip()
    return urljoin(base_url, location_str)


def validate_redirect_chain(
    url: str,
    *,
    max_hops: int = _DEFAULT_MAX_HOPS,
    timeout: float = _DEFAULT_TIMEOUT,
    headers: dict[str, str] | None = None,
) -> list[str]:
    """Follow redirects and verify every hop is an external/public target.

    Returns the ordered chain of normalized URLs. Raises
    ``RedirectValidationError`` if the chain loops, exceeds ``max_hops``, or
    lands on an internal/metadata host at any hop.
    """
    chain: list[str] = []
    current = normalize_url(url)

    for _ in range(max_hops):
        if current in chain:
            raise RedirectLoopError(f"Redirect loop detected at {current}")
        chain.append(current)

        if is_internal_target(current):
            raise RedirectInternalTargetError(
                f"Redirect hop rejected as internal target: {current}"
            )

        req_headers = dict(headers or {})
        req_headers.setdefault("User-Agent", "strix-redirect-validator/1.0")
        req = Request(current, headers=req_headers, method="HEAD")  # noqa: S310

        try:
            with urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
                if resp.status in {301, 302, 303, 307, 308}:
                    next_url = _get_redirect_url(resp, current)
                    if next_url is None:
                        return chain
                    current = normalize_url(next_url)
                    continue
                return chain
        except HTTPError as e:
            if e.status in {301, 302, 303, 307, 308}:
                next_url = _get_redirect_url(e, current)
                if next_url is None:
                    return chain
                current = normalize_url(next_url)
                continue
            # Non-redirect HTTP errors are treated as end of chain (the target exists).
            return chain
        except (URLError, OSError, ValueError) as exc:
            # Network errors stop the chain; the caller decides whether this
            # means the target is unreachable or unsafe. We return what we have.
            raise RedirectValidationError(
                f"Redirect validation failed at {current}: {exc}"
            ) from exc

    raise RedirectLoopError(f"Redirect chain exceeded {max_hops} hops")

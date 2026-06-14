"""Tests for redirect-chain revalidation (SP-4)."""

from __future__ import annotations

import io
from typing import Any, Self
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from strix.core.net.corpus import INTERNAL_CORPUS, METADATA_CORPUS
from strix.core.net.redirect import (
    RedirectInternalTargetError,
    RedirectLoopError,
    RedirectValidationError,
    validate_redirect_chain,
)


class _MockResponse:
    """Minimal mock for the object returned by ``urllib.request.urlopen``."""

    def __init__(self, status: int, location: str | None = None) -> None:
        self.status = status
        self.headers: dict[str, str] = {}
        if location is not None:
            self.headers["Location"] = location

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


def _make_http_error(status: int, location: str | None = None) -> HTTPError:
    """Build an HTTPError that carries a Location header like a real 3xx response."""
    headers: dict[str, str] = {}
    if location is not None:
        headers["Location"] = location
    return HTTPError(
        url="http://example.com",
        code=status,
        msg="redirect",
        hdrs=headers,
        fp=io.BytesIO(b""),
    )


def test_external_to_internal_redirect_rejected() -> None:
    """A redirect from an external host to an internal target is rejected."""

    def _urlopen_side_effect(req: Any, **_: Any) -> _MockResponse:
        if req.full_url == "http://example.com/":
            return _MockResponse(302, "http://127.0.0.1/admin")
        return _MockResponse(200)

    with (
        patch("strix.core.net.redirect.urlopen", side_effect=_urlopen_side_effect),
        pytest.raises(RedirectInternalTargetError),
    ):
        validate_redirect_chain("http://example.com/")


@pytest.mark.parametrize(
    "alternate_location",
    [
        "http://2130706433/admin",  # decimal loopback
        "http://0177.0.0.1/admin",  # octal loopback
        "http://0x7f.0.0.1/admin",  # hex loopback
        "http://0x7f000001/admin",  # pure hex loopback
        "http://017700000001/admin",  # pure octal loopback
        "http://169.254.169.254/latest/meta-data",  # metadata endpoint
        "http://2852039166/latest/meta-data",  # decimal metadata
        "http://0xa9fea9fe/latest/meta-data",  # pure hex metadata
    ],
)
def test_external_to_alternate_notation_internal_redirect_rejected(
    alternate_location: str,
) -> None:
    """SP-4: redirect hop revalidation must decode alternate IP notations."""

    def _urlopen_side_effect(req: Any, **_: Any) -> _MockResponse:
        if req.full_url == "http://example.com/":
            return _MockResponse(302, alternate_location)
        return _MockResponse(200)

    with (
        patch("strix.core.net.redirect.urlopen", side_effect=_urlopen_side_effect),
        pytest.raises(RedirectInternalTargetError),
    ):
        validate_redirect_chain("http://example.com/")


@pytest.mark.parametrize("target", INTERNAL_CORPUS + METADATA_CORPUS)
def test_external_to_corpus_internal_redirect_rejected(target: str) -> None:
    """Every internal/metadata corpus entry must be rejected as a redirect target."""
    # Build a URL from the corpus entry; skip entries that are already full URLs.
    location = target if "://" in target else f"http://{target}"

    def _urlopen_side_effect(req: Any, **_: Any) -> _MockResponse:
        if req.full_url == "http://example.com/":
            return _MockResponse(302, location)
        return _MockResponse(200)

    with (
        patch("strix.core.net.redirect.urlopen", side_effect=_urlopen_side_effect),
        pytest.raises(RedirectInternalTargetError),
    ):
        validate_redirect_chain("http://example.com/")


def test_redirect_loop_detected() -> None:
    """A cycle in the redirect chain raises RedirectLoopError."""

    def _urlopen_side_effect(req: Any, **_: Any) -> _MockResponse:
        if req.full_url in ("http://example.com/a", "http://example.com/b"):
            next_loc = (
                "http://example.com/b"
                if req.full_url == "http://example.com/a"
                else "http://example.com/a"
            )
            return _MockResponse(302, next_loc)
        return _MockResponse(200)

    with (
        patch("strix.core.net.redirect.urlopen", side_effect=_urlopen_side_effect),
        pytest.raises(RedirectLoopError),
    ):
        validate_redirect_chain("http://example.com/a")


def test_external_to_external_chain_passes() -> None:
    """A clean external → external redirect chain is accepted within the hop limit."""

    def _urlopen_side_effect(req: Any, **_: Any) -> _MockResponse:
        if req.full_url == "http://example.com/":
            return _MockResponse(302, "http://github.com/destination")
        return _MockResponse(200)

    with patch("strix.core.net.redirect.urlopen", side_effect=_urlopen_side_effect):
        chain = validate_redirect_chain("http://example.com/")

    assert chain == ["http://example.com/", "http://github.com/destination"]


def test_hop_limit_enforced() -> None:
    """A chain longer than ``max_hops`` raises RedirectLoopError."""

    call_count = 0

    def _urlopen_side_effect(_req: object, **_: Any) -> _MockResponse:
        nonlocal call_count
        call_count += 1
        return _MockResponse(302, f"http://example.com/{call_count}")

    with (
        patch("strix.core.net.redirect.urlopen", side_effect=_urlopen_side_effect),
        pytest.raises(RedirectLoopError),
    ):
        validate_redirect_chain("http://example.com/", max_hops=3)


def test_non_redirect_response_ends_chain() -> None:
    """A non-3xx response terminates the chain normally."""

    def _urlopen_side_effect(_req: object, **_: Any) -> _MockResponse:
        return _MockResponse(200)

    with patch("strix.core.net.redirect.urlopen", side_effect=_urlopen_side_effect):
        chain = validate_redirect_chain("http://example.com/")

    assert chain == ["http://example.com/"]


def test_http_error_3xx_redirect_via_exception() -> None:
    """Some servers emit 3xx as an HTTPError; the Location header is still honored."""

    def _urlopen_side_effect(req: Any, **_: Any) -> _MockResponse:
        if req.full_url == "http://example.com/":
            raise _make_http_error(302, "http://github.com/destination")
        return _MockResponse(200)

    with patch("strix.core.net.redirect.urlopen", side_effect=_urlopen_side_effect):
        chain = validate_redirect_chain("http://example.com/")

    assert chain == ["http://example.com/", "http://github.com/destination"]


def test_http_error_3xx_to_internal_rejected() -> None:
    """A 3xx HTTPError pointing internal is rejected just like a regular 3xx."""

    def _urlopen_side_effect(req: Any, **_: Any) -> _MockResponse:
        if req.full_url == "http://example.com/":
            raise _make_http_error(302, "http://127.0.0.1/admin")
        return _MockResponse(200)

    with (
        patch("strix.core.net.redirect.urlopen", side_effect=_urlopen_side_effect),
        pytest.raises(RedirectInternalTargetError),
    ):
        validate_redirect_chain("http://example.com/")


def test_network_error_stops_chain_with_message() -> None:
    """A non-redirect network error is surfaced as a RedirectValidationError."""

    def _urlopen_side_effect(_req: object, **_: Any) -> _MockResponse:
        raise ConnectionError("no route to host")

    with (
        patch("strix.core.net.redirect.urlopen", side_effect=_urlopen_side_effect),
        pytest.raises(RedirectValidationError, match="no route to host"),
    ):
        validate_redirect_chain("http://example.com/")

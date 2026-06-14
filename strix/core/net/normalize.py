"""Canonical URL normalization with idempotence guarantee."""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse


_DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ssh": 22,
}


def normalize_url(url: str) -> str:
    """Return a canonical form of ``url``.

    Rules:

    - Lowercase host.
    - Strip default ports for the scheme.
    - Remove userinfo (username/password).
    - Preserve the path; collapse duplicate slashes.
    - Sort query keys for determinism.
    - Remove fragment.

    The result is idempotent: ``normalize_url(normalize_url(u)) == normalize_url(u)``.
    """
    url = url.strip()
    if not url:
        return ""

    # If no scheme is present, urlparse interprets the whole string as a path.
    if "://" not in url:
        url = f"http://{url}"

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()

    port = parsed.port
    default_port = _DEFAULT_PORTS.get(scheme)
    if default_port is not None and port == default_port:
        port = None

    # Path: keep leading slash, collapse multiple slashes.
    path = parsed.path or "/"
    while "//" in path:
        path = path.replace("//", "/")

    # Query: sort keys deterministically; strip blank values.
    query = ""
    if parsed.query:
        pairs = []
        for key, value in sorted(
            (part.split("=", 1) if "=" in part else (part, ""))
            for part in parsed.query.split("&")
            if part
        ):
            pairs.append(f"{key}={value}")
        query = "&".join(pairs)

    netloc = host
    if port is not None:
        netloc = f"{netloc}:{port}"

    return urlunparse((scheme, netloc, path, "", query, ""))

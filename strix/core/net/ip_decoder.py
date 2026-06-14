"""Decode alternate IP notations to canonical ``ipaddress`` objects."""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable


_IPV4_OCTET_RE = re.compile(r"^(0x[0-9a-fA-F]+|0[0-7]+|[0-9]+)$")


def _looks_like_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(_IPV4_OCTET_RE.match(part) for part in parts)


def _parse_int(value: str) -> int:
    """Parse a decimal, octal, or hex integer literal."""
    value = value.strip()
    if value.startswith(("0x", "0X")):
        return int(value, 16)
    if value.startswith("0") and len(value) > 1 and all(c in "01234567" for c in value[1:]):
        return int(value, 8)
    return int(value, 10)


def _decode_pure_octal_ipv4(value: str) -> ipaddress.IPv4Address | None:
    """Decode a 32-bit octal IPv4 address (e.g. ``017700000001``)."""
    if not re.fullmatch(r"0[0-7]{1,11}", value):
        return None
    try:
        return ipaddress.IPv4Address(int(value, 8))
    except ipaddress.AddressValueError:
        return None


def _decode_pure_hex_ipv4(value: str) -> ipaddress.IPv4Address | None:
    """Decode a 32-bit hex IPv4 address (e.g. ``0x7f000001``)."""
    if not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", value):
        return None
    try:
        return ipaddress.IPv4Address(int(value, 16))
    except ipaddress.AddressValueError:
        return None


def _decode_decimal_ipv4(value: str) -> ipaddress.IPv4Address | None:
    """Decode a 32-bit decimal IPv4 address (e.g. ``2130706433``)."""
    if not re.fullmatch(r"[0-9]+", value):
        return None
    try:
        num = int(value)
    except (ValueError, TypeError, AttributeError):
        return None
    if num < 0 or num > 0xFFFFFFFF:
        return None
    try:
        return ipaddress.IPv4Address(num)
    except ipaddress.AddressValueError:
        return None


def _decode_alternate_ipv4(value: str) -> ipaddress.IPv4Address | None:
    """Decode IPv4 written with mixed decimal/octal/hex octets.

    Examples: ``0177.0.0.1``, ``0x7f.0.0.1``, ``127.0.01``.
    """
    if "." not in value or not _looks_like_ipv4(value):
        return None
    parts = value.split(".")
    try:
        octets = [_parse_int(part) for part in parts]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octets):
        return None
    try:
        return ipaddress.IPv4Address(".".join(str(o) for o in octets))
    except ipaddress.AddressValueError:
        return None


def decode_ip_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Decode an IP address from canonical or alternate notation.

    Handles:

    - Canonical dotted-decimal IPv4 / compressed IPv6.
    - Pure 32-bit decimal / octal / hex IPv4.
    - Mixed octal/hex IPv4 octets.
    - IPv4-mapped IPv6 (``::ffff:127.0.0.1``).
    """
    value = value.strip()

    # Fast path: canonical forms accepted by the standard library.
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        pass

    # Order matters: octal must precede decimal because a leading-zero octal
    # literal is also a valid decimal string, but Python's int() would parse
    # it as decimal and overflow the 32-bit IPv4 space.
    decoders: list[Callable[[str], ipaddress.IPv4Address | None]] = [
        _decode_pure_octal_ipv4,
        _decode_pure_hex_ipv4,
        _decode_decimal_ipv4,
        _decode_alternate_ipv4,
    ]
    for decoder in decoders:
        result = decoder(value)
        if result is not None:
            return result

    return None

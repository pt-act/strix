"""Curated target corpora for outbound-trust validation and PBT."""

from __future__ import annotations


# Canonical + alternate-notation internal targets that must be rejected.
INTERNAL_CORPUS: list[str] = [
    # Loopback
    "127.0.0.1",
    "localhost",
    "[::1]",
    "[0:0:0:0:0:0:0:1]",
    # Decimal / octal / hex loopback
    "2130706433",
    "0177.0.0.1",
    "0x7f.0.0.1",
    "0x7f000001",
    "017700000001",
    # RFC-1918
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "172.31.255.255",
    # Link-local
    "169.254.1.1",
    "[fe80::1]",
    # CGNAT
    "100.64.0.1",
    "100.127.255.254",
    # ULA
    "[fc00::1]",
    "[fd00::1]",
    # IPv4-mapped IPv6 loopback / RFC-1918
    "[::ffff:127.0.0.1]",
    "[::ffff:192.168.1.1]",
    "[::ffff:10.0.0.1]",
]

# Cloud-metadata endpoints that must be rejected (canonical + alternate forms).
METADATA_CORPUS: list[str] = [
    "169.254.169.254",
    "[fd00:ec2::254]",
    "[::ffff:169.254.169.254]",
    # Alternate notations of the AWS metadata IP
    "2852039166",
    "0251.254.169.254",
    "0xa9fea9fe",
    "0xa9.0xfe.0xa9.0xfe",
]

# External public targets that must be accepted (control set).
EXTERNAL_PUBLIC_CORPUS: list[str] = [
    "example.com",
    "github.com",
    "8.8.8.8",
    "1.1.1.1",
    "[2001:4860:4860::8888]",
    "[2606:4700:4700::1111]",
]

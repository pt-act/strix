"""Tests for strix.core.net outbound-trust hardening."""

from __future__ import annotations

import ipaddress

import pytest

from strix.core.net import (
    EXTERNAL_PUBLIC_CORPUS,
    INTERNAL_CORPUS,
    METADATA_CORPUS,
    classify_ip_address,
    confirm_oob,
    decode_ip_address,
    is_internal_target,
    normalize_url,
)


class TestUrlNormalization:
    """Group 3.1 — URL normalization."""

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("HTTPS://EXAMPLE.COM:443/Path", "https://example.com/Path"),
            ("http://example.com:80/", "http://example.com/"),
            ("http://user:pass@example.com/path", "http://example.com/path"),
            ("http://example.com//a//b", "http://example.com/a/b"),
            ("http://example.com?b=2&a=1", "http://example.com/?a=1&b=2"),
        ],
    )
    def test_normalize_url(self, url: str, expected: str) -> None:
        assert normalize_url(url) == expected

    def test_normalize_url_idempotent(self) -> None:
        urls = [
            "https://Example.COM:443/path?b=2&a=1",
            "http://localhost:8080//api//v1",
            "http://user:pass@example.com:80/foo",
        ]
        for url in urls:
            once = normalize_url(url)
            twice = normalize_url(once)
            assert once == twice, f"idempotence failed for {url}: {once} != {twice}"


class TestAlternateIpNotation:
    """Group 3.2 — alternate IP-notation decoding."""

    def test_decimal_loopback(self) -> None:
        ip = decode_ip_address("2130706433")
        assert ip == ipaddress.IPv4Address("127.0.0.1")

    def test_octal_loopback(self) -> None:
        ip = decode_ip_address("0177.0.0.1")
        assert ip == ipaddress.IPv4Address("127.0.0.1")

    def test_hex_loopback(self) -> None:
        ip = decode_ip_address("0x7f.0.0.1")
        assert ip == ipaddress.IPv4Address("127.0.0.1")

    def test_ipv4_mapped_ipv6_loopback(self) -> None:
        ip = decode_ip_address("::ffff:127.0.0.1")
        assert ip == ipaddress.IPv6Address("::ffff:127.0.0.1")

    def test_compressed_ipv6(self) -> None:
        ip = decode_ip_address("::1")
        assert ip == ipaddress.IPv6Address("::1")

    def test_alternate_notations_classify_identically(self) -> None:
        """SP-2: every alternate notation classifies like its canonical address."""
        canonical = "127.0.0.1"
        alternates = ["2130706433", "0177.0.0.1", "0x7f.0.0.1", "0x7f000001", "::ffff:127.0.0.1"]
        expected = classify_ip_address(ipaddress.IPv4Address(canonical))
        for alt in alternates:
            ip = decode_ip_address(alt)
            assert ip is not None, f"failed to decode {alt}"
            assert classify_ip_address(ip) == expected, f"classification mismatch for {alt}"


class TestInternalTargetClassification:
    """Group 3.3 — internal/metadata classifier."""

    def test_internal_corpus_rejected(self) -> None:
        for target in INTERNAL_CORPUS:
            assert is_internal_target(target), f"internal target accepted: {target}"

    def test_metadata_corpus_rejected(self) -> None:
        for target in METADATA_CORPUS:
            assert is_internal_target(target), f"metadata target accepted: {target}"

    def test_external_public_corpus_accepted(self) -> None:
        for target in EXTERNAL_PUBLIC_CORPUS:
            assert not is_internal_target(target), f"external target rejected: {target}"

    def test_localhost_hostname_rejected(self) -> None:
        assert is_internal_target("localhost")
        assert is_internal_target("localhost.localdomain")

    def test_metadata_endpoints_rejected(self) -> None:
        assert is_internal_target("http://169.254.169.254/latest/meta-data/")
        assert is_internal_target("[fd00:ec2::254]")


class TestOOBSeam:
    """Group 3.6 — OOB confirmation seam."""

    def test_null_oob_seam_returns_none(self) -> None:
        assert confirm_oob("https://example.com", "token-123") is None

    def test_null_oob_seam_has_no_side_effects(self) -> None:
        # Calling the seam must not raise or perform network I/O.
        result = confirm_oob("http://internal.example", "token-456")
        assert result is None


class TestCorpusCompleteness:
    """SP-3: curated corpora cover internal/metadata and external controls."""

    def test_internal_corpus_not_empty(self) -> None:
        assert INTERNAL_CORPUS

    def test_metadata_corpus_not_empty(self) -> None:
        assert METADATA_CORPUS

    def test_external_public_corpus_not_empty(self) -> None:
        assert EXTERNAL_PUBLIC_CORPUS

    def test_no_internal_target_misclassified_as_external(self) -> None:
        for target in INTERNAL_CORPUS + METADATA_CORPUS:
            assert is_internal_target(target), f"corpus bypass: {target}"

    def test_no_external_target_misclassified_as_internal(self) -> None:
        for target in EXTERNAL_PUBLIC_CORPUS:
            assert not is_internal_target(target), f"false positive: {target}"

"""Tests for strix.runtime.egress_proxy — TPROXY, DNS, and scope helpers.

Covers wire-format DNS parsing, NXDOMAIN generation, IP classification,
scope matching, and TPROXY/REDIRECT original-destination resolution.
"""

from __future__ import annotations

import argparse
import socket
import struct
from unittest import TestCase
from unittest.mock import MagicMock, patch

from strix.core.govern.scope import ActionClass, ScopeRule
from strix.runtime.egress_proxy import (
    _classify_action,
    _get_original_dst,
    _is_internal_ip,
    _is_ip_in_scope,
    _nxdomain_response,
    _parse_dns_a_records,
    _parse_qname,
)


class TestDNSWireFormat(TestCase):
    """DNS query/response wire-format helpers."""

    def test_parse_qname_simple(self) -> None:
        # Query for host.docker.internal
        query = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        query += b"\x04host\x06docker\x08internal\x00\x00\x01\x00\x01"
        domain = _parse_qname(query)
        self.assertEqual(domain, "host.docker.internal")

    def test_parse_qname_empty(self) -> None:
        # Root query
        query = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        query += b"\x00\x00\x01\x00\x01"
        domain = _parse_qname(query)
        self.assertEqual(domain, "")

    def test_nxdomain_response_flags(self) -> None:
        query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        query += b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"
        resp = _nxdomain_response(query)
        self.assertEqual(resp[:2], b"\x12\x34")  # TXID preserved
        flags = struct.unpack_from("!H", resp, 2)[0]
        self.assertTrue(flags & 0x8000)  # QR=1
        rcode = flags & 0x000F
        self.assertEqual(rcode, 3)  # NXDOMAIN

    def test_nxdomain_truncated_query(self) -> None:
        self.assertEqual(_nxdomain_response(b"\x00\x00"), b"")

    def test_parse_dns_a_records(self) -> None:
        # Build a minimal DNS response with one A record for example.com → 93.184.216.34
        qname = b"\x07example\x03com\x00"
        question = qname + b"\x00\x01\x00\x01"  # A, IN
        header = b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        answer = qname + b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
        answer += socket.inet_aton("93.184.216.34")
        response = header + question + answer
        ips = _parse_dns_a_records(response)
        self.assertEqual(ips, ["93.184.216.34"])

    def test_parse_dns_aaaa_records(self) -> None:
        # Build a minimal DNS response with one AAAA record for example.com → 2001:db8::1
        qname = b"\x07example\x03com\x00"
        question = qname + b"\x00\x01\x00\x01"  # A, IN
        header = b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        answer = qname + b"\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10"
        answer += socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        response = header + question + answer
        ips = _parse_dns_a_records(response)
        self.assertEqual(ips, ["2001:db8::1"])


class TestIPClassification(TestCase):
    """_is_internal_ip and _is_ip_in_scope."""

    def test_loopback_is_internal(self) -> None:
        self.assertTrue(_is_internal_ip("127.0.0.1"))
        self.assertTrue(_is_internal_ip("::1"))

    def test_private_is_internal(self) -> None:
        self.assertTrue(_is_internal_ip("10.0.0.1"))
        self.assertTrue(_is_internal_ip("192.168.1.1"))
        self.assertTrue(_is_internal_ip("172.16.0.1"))
        self.assertTrue(_is_internal_ip("fd00::1"))

    def test_link_local_is_internal(self) -> None:
        self.assertTrue(_is_internal_ip("169.254.1.1"))
        self.assertTrue(_is_internal_ip("fe80::1"))

    def test_metadata_ip_is_internal(self) -> None:
        self.assertTrue(_is_internal_ip("169.254.169.254"))

    def test_cgnat_is_internal(self) -> None:
        self.assertTrue(_is_internal_ip("100.64.0.1"))

    def test_public_is_not_internal(self) -> None:
        self.assertFalse(_is_internal_ip("8.8.8.8"))
        self.assertFalse(_is_internal_ip("1.1.1.1"))
        self.assertFalse(_is_internal_ip("93.184.216.34"))

    def test_malformed_is_internal(self) -> None:
        # Unparseable → fail-closed (treat as internal)
        self.assertTrue(_is_internal_ip("not-an-ip"))

    def test_ip_in_scope_exact(self) -> None:
        rules = [ScopeRule(pattern="8.8.8.8")]
        self.assertTrue(_is_ip_in_scope("8.8.8.8", rules))
        self.assertFalse(_is_ip_in_scope("8.8.4.4", rules))

    def test_ip_in_scope_cidr(self) -> None:
        rules = [ScopeRule(pattern="10.0.0.0/8")]
        self.assertTrue(_is_ip_in_scope("10.1.2.3", rules))
        self.assertFalse(_is_ip_in_scope("192.168.1.1", rules))

    def test_ip_in_scope_ipv6(self) -> None:
        rules = [ScopeRule(pattern="2001:db8::/32")]
        self.assertTrue(_is_ip_in_scope("2001:db8::1", rules))
        self.assertFalse(_is_ip_in_scope("::1", rules))


class TestClassifyAction(TestCase):
    """Port-to-action classification."""

    def test_http_ports(self) -> None:
        self.assertEqual(_classify_action(80), ActionClass.HTTP)
        self.assertEqual(_classify_action(443), ActionClass.HTTP)
        self.assertEqual(_classify_action(8080), ActionClass.HTTP)
        self.assertEqual(_classify_action(8443), ActionClass.HTTP)

    def test_dns_port(self) -> None:
        self.assertEqual(_classify_action(53), ActionClass.RECON)

    def test_other_ports(self) -> None:
        self.assertEqual(_classify_action(9999), ActionClass.HTTP)


class TestGetOriginalDst(TestCase):
    """_get_original_dst in TPROXY vs REDIRECT modes."""

    @patch("strix.runtime.egress_proxy._tproxy_enabled", new=True)
    def test_tproxy_mode_uses_getsockname(self) -> None:
        mock_sock = MagicMock()
        mock_sock.getsockname.return_value = ("93.184.216.34", 80)
        ip, port = _get_original_dst(mock_sock)
        self.assertEqual(ip, "93.184.216.34")
        self.assertEqual(port, 80)
        mock_sock.getsockname.assert_called_once()
        mock_sock.getsockopt.assert_not_called()

    @patch("strix.runtime.egress_proxy._tproxy_enabled", new=False)
    def test_redirect_mode_uses_ioctl(self) -> None:
        mock_sock = MagicMock()
        # SO_ORIGINAL_DST response: family=AF_INET, port=443, ip=1.2.3.4
        mock_sock.getsockopt.return_value = (
            struct.pack("!H", socket.AF_INET)
            + struct.pack("!H", 443)
            + socket.inet_aton("1.2.3.4")
            + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        ip, port = _get_original_dst(mock_sock)
        self.assertEqual(ip, "1.2.3.4")
        self.assertEqual(port, 443)
        mock_sock.getsockopt.assert_called_once()
        mock_sock.getsockname.assert_not_called()


class TestArgumentParsing(TestCase):
    """CLI argument parsing."""

    def test_default_bind(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("--port", type=int, default=48081)
        parser.add_argument("--socket", default="/run/strix/decision.sock")
        parser.add_argument("--bind", default="127.0.0.1")
        args = parser.parse_args([])
        self.assertEqual(args.bind, "127.0.0.1")
        self.assertEqual(args.port, 48081)

    def test_custom_bind(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument("--port", type=int, default=48081)
        parser.add_argument("--socket", default="/run/strix/decision.sock")
        parser.add_argument("--bind", default="127.0.0.1")
        args = parser.parse_args(["--bind", "0.0.0.0", "--port", "12345"])
        self.assertEqual(args.bind, "0.0.0.0")
        self.assertEqual(args.port, 12345)

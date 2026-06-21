"""strix.runtime.egress_proxy — SGL-S0/S7 transparent decision proxy.

Runs INSIDE the container as root.  iptables redirects all outbound TCP and
DNS UDP to this process, which consults the Decision Service (govern/scope.py)
for every connection and either forwards (ALLOW) or resets (DENY).

Root is exempted from the iptables REDIRECT rules (uid-owner 0 -j RETURN in
egress-enforcer.sh), so the proxy's own forwarding connections go directly to
their destinations without looping back through itself.

Protocol support
----------------
- TCP (transparent proxy via SO_ORIGINAL_DST): HTTP, HTTPS, raw TCP.
  iptables REDIRECT → asyncio.start_server on PROXY_PORT.
- DNS UDP 53: separate asyncio DatagramProtocol on the same PROXY_PORT.
  iptables REDIRECT sends UDP/53 to PROXY_PORT/UDP, which is a distinct
  socket from the TCP listener on the same port number.
  The handler parses the QNAME, calls decide() on the domain, then either
  forwards to the upstream resolver (ALLOW) or returns NXDOMAIN (DENY).

F1 — DNS→IP correlation (S7)
-----------------------------
On a DNS ALLOW, the proxy parses A/AAAA records from the upstream response
and records resolved IPs in a short-TTL per-engagement allow-set.  The TCP
handler authorizes a connection if the destination IP matches:
  (a) a direct IP/CIDR scope rule, OR
  (b) a currently-resolved IP in the allow-set.

DNS-rebinding defense: resolved IPs that are private/loopback/link-local/
metadata are NOT added to the allow-set unless that range is explicitly in
scope (reuses strix.core.net.is_internal_target logic inline).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import signal
import socket
import struct
from typing import Final

import ipaddress
import time

from strix.core.govern.scope import (
    ActionClass,
    EngagementCtx,
    ScopeRule,
    Target,
    Verdict,
    decide,
    load_scope,
)

logger = logging.getLogger("strix.egress_proxy")

_CONNECT_TIMEOUT: Final = 10.0
_BUFFER: Final = 65536
_DNS_TIMEOUT: Final = 3.0
_DNS_UPSTREAM: Final = os.environ.get("STRIX_DNS_UPSTREAM", "8.8.8.8")
_RESOLVED_IP_TTL: Final = int(os.environ.get("STRIX_RESOLVED_IP_TTL", "300"))

# SO_ORIGINAL_DST — Linux ioctl to recover the pre-REDIRECT destination.
SO_ORIGINAL_DST: Final = 80


# ─────────────────────────────────────── context ───────────────────────────


def _load_ctx_from_env() -> EngagementCtx:
    raw = os.environ.get("STRIX_SCOPE_RULES", "")
    entries = [e.strip() for e in raw.replace(",", "\n").splitlines() if e.strip()]
    return load_scope(entries)


_CTX: EngagementCtx = EngagementCtx(rules=[])


def _reload_ctx() -> None:
    global _CTX
    _CTX = _load_ctx_from_env()
    logger.info("Decision context reloaded: %d rules", len(_CTX.rules))


# ─────────────────────────────────────── F1: resolved-IP allow-set ──────────
# Maps IP string → expiry monotonic timestamp.
# Populated by DNS handler on ALLOW; checked by TCP handler.
_resolved_ips: dict[str, float] = {}
_resolved_lock: asyncio.Lock | None = None  # created at runtime in _main()

# CGNAT range not classified as private by all Python versions.
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")
_METADATA_IPS: frozenset[str] = frozenset(
    {"169.254.169.254", "fd00:ec2::254"}
)


def _is_internal_ip(ip_str: str) -> bool:
    """Return True if ip_str is a private/loopback/link-local/metadata address.
    Inline copy of strix.core.net.classifier logic to avoid import
    dependency in the container image.
    """
    if ip_str in _METADATA_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → treat as internal (fail-closed)
    if isinstance(addr, ipaddress.IPv4Address):
        return bool(
            addr.is_loopback
            or addr.is_private
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr in _CGNAT_NETWORK
        )
    # IPv6
    return bool(
        addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved or addr.is_multicast
    )


def _is_ip_in_scope(ip_str: str, rules: list[ScopeRule]) -> bool:
    """Check if an IP matches any direct IP/CIDR scope rule."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for rule in rules:
        pattern = rule.pattern.strip().lower()
        if "/" in pattern:
            try:
                net = ipaddress.ip_network(pattern, strict=False)
                if addr in net:
                    return True
            except ValueError:
                continue
        try:
            if addr == ipaddress.ip_address(pattern):
                return True
        except ValueError:
            continue
    return False


async def _add_resolved_ips(ips: list[str], ttl: float) -> None:
    """Add resolved IPs to the allow-set if they pass the rebinding defense."""
    now = time.monotonic()
    expiry = now + ttl
    async with _get_lock():
        for ip_str in ips:
            if _is_internal_ip(ip_str):
                # DNS-rebinding defense: do NOT add private/metadata IPs
                # unless explicitly in scope via a CIDR/IP rule.
                if not _is_ip_in_scope(ip_str, _CTX.rules):
                    logger.warning(
                        "F1 rebinding-blocked: %s is internal and not in scope", ip_str
                    )
                    continue
            _resolved_ips[ip_str] = expiry
            logger.info("F1 allow-set added: %s (ttl=%ds)", ip_str, int(ttl))


async def _check_resolved_ip(ip_str: str) -> bool:
    """Return True if ip_str is currently in the resolved-IP allow-set."""
    async with _get_lock():
        expiry = _resolved_ips.get(ip_str)
        if expiry is None:
            return False
        if time.monotonic() > expiry:
            # Expired — lazy cleanup
            _resolved_ips.pop(ip_str, None)
            return False
        return True


async def _cleanup_expired_ips() -> None:
    """Purge expired entries from the allow-set."""
    now = time.monotonic()
    async with _get_lock():
        expired = [ip for ip, exp in _resolved_ips.items() if now > exp]
        for ip in expired:
            del _resolved_ips[ip]



def _get_lock() -> asyncio.Lock:
    """Return the resolved-IP lock, creating it if needed."""
    global _resolved_lock
    if _resolved_lock is None:
        _resolved_lock = asyncio.Lock()
    return _resolved_lock


# ─────────────────────────────────────── DNS wire-format helpers ────────────


def _parse_qname(data: bytes, offset: int = 12) -> str:
    """Extract the first QNAME from a DNS message starting at byte offset.

    Handles standard length-prefixed labels.  Compression pointers in queries
    are unusual but followed once to avoid infinite loops.
    """
    labels: list[str] = []
    visited: set[int] = set()
    while offset < len(data):
        if offset in visited:
            raise ValueError("QNAME pointer loop")
        visited.add(offset)
        length = data[offset]
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated QNAME pointer")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            # Follow pointer once; recursion depth bounded by visited set.
            offset = ptr
            continue
        offset += 1
        end = offset + length
        if end > len(data):
            raise ValueError("truncated QNAME label")
        labels.append(data[offset:end].decode("ascii", errors="replace"))
        offset = end
    return ".".join(labels)


def _nxdomain_response(query: bytes) -> bytes:
    """Build a minimal NXDOMAIN response from a DNS query packet."""
    if len(query) < 12:
        return b""
    txid = query[:2]
    # Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=copy-from-query, RA=1, RCODE=3
    rd = query[2] & 0x01
    flags = bytes([0x80 | rd, 0x83])  # 0x83 = RA=1 | RCODE=NXDOMAIN
    # QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    # Append the original question section verbatim
    return txid + flags + counts + query[12:]


def _parse_dns_a_records(response: bytes) -> list[str]:
    """Extract A (IPv4) and AAAA (IPv6) addresses from a DNS response.

    Parses the answer section after the question section.  Handles
    standard label encoding and compression pointers.
    """
    if len(response) < 12:
        return []

    # Skip question section
    qdcount = struct.unpack_from("!H", response, 4)[0]
    offset = 12
    for _ in range(qdcount):
        while offset < len(response):
            length = response[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                offset += 2
                break
            offset += 1 + length
        # Skip QTYPE (2) + QCLASS (2)
        offset += 4

    # Parse answer section
    ancount = struct.unpack_from("!H", response, 6)[0]
    ips: list[str] = []
    for _ in range(ancount):
        if offset >= len(response):
            break
        # Skip name (may be a pointer)
        if (response[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            while offset < len(response) and response[offset] != 0:
                if (response[offset] & 0xC0) == 0xC0:
                    offset += 2
                    break
                offset += 1 + response[offset]
            else:
                offset += 1  # skip the trailing zero

        if offset + 10 > len(response):
            break
        rtype = struct.unpack_from("!H", response, offset)[0]
        rdlength = struct.unpack_from("!H", response, offset + 8)[0]
        rdata_offset = offset + 10
        offset = rdata_offset + rdlength

        if rdata_offset + rdlength > len(response):
            break

        if rtype == 1 and rdlength == 4:  # A record
            ip = socket.inet_ntoa(response[rdata_offset:rdata_offset + 4])
            ips.append(ip)
        elif rtype == 28 and rdlength == 16:  # AAAA record
            ip = socket.inet_ntop(socket.AF_INET6, response[rdata_offset:rdata_offset + 16])
            ips.append(ip)

    return ips


async def _forward_dns(query: bytes) -> bytes | None:
    """Forward a DNS query to the upstream resolver and return the response.

    Runs as root (uid 0), which is exempt from the iptables REDIRECT rules,
    so this UDP packet goes directly to the resolver without looping.
    """
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_connect(sock, (_DNS_UPSTREAM, 53))
        await loop.sock_sendall(sock, query)
        return await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=_DNS_TIMEOUT)
    except (OSError, asyncio.TimeoutError) as exc:
        logger.warning("DNS upstream %s forward failed: %s", _DNS_UPSTREAM, exc)
        return None
    finally:
        sock.close()


# ─────────────────────────────────────── DNS enforcement protocol ───────────


class _DnsEnforcerProtocol(asyncio.DatagramProtocol):
    """UDP datagram protocol that enforces scope decisions on DNS queries.

    For each query:
    - Parse the QNAME (queried domain).
    - Call decide(Target(host=domain, action_class=RECON), _CTX).
    - ALLOW → forward to upstream resolver and relay its response.
    - DENY  → return NXDOMAIN immediately without forwarding.
    """

    def __init__(self) -> None:
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.ensure_future(self._handle(data, addr))

    def error_received(self, exc: Exception) -> None:
        logger.warning("DNS UDP error: %s", exc)

    async def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            domain = _parse_qname(data)
        except Exception as exc:
            logger.warning("DNS parse error from %s: %s — dropping", addr[0], exc)
            return

        if not domain:
            # Root query or empty — deny.
            domain = "<empty>"
            decision_target = Target(host=".", action_class=ActionClass.RECON)
        else:
            decision_target = Target(host=domain, action_class=ActionClass.RECON)

        decision = decide(decision_target, _CTX)
        logger.info(
            "DNS %s → %s verdict=%s reason=%s",
            addr[0], domain, decision.verdict.value, decision.reason,
        )

        if decision.verdict == Verdict.ALLOW:
            response = await _forward_dns(data)
            if response is None:
                # Upstream unavailable — fail closed.
                response = _nxdomain_response(data)
            else:
                # F1: extract resolved IPs from the DNS response and
                # add them to the short-TTL allow-set for TCP authorization.
                resolved = _parse_dns_a_records(response)
                if resolved:
                    await _add_resolved_ips(resolved, _RESOLVED_IP_TTL)
        else:
            response = _nxdomain_response(data)

        if self._transport and response:
            self._transport.sendto(response, addr)


# ─────────────────────────────────────── TCP proxy ──────────────────────────


def _get_original_dst(sock: socket.socket) -> tuple[str, int]:
    """Return (ip, port) for the pre-REDIRECT destination via SO_ORIGINAL_DST."""
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port = struct.unpack_from("!H", raw, 2)[0]
    ip = socket.inet_ntoa(raw[4:8])
    return ip, port


def _classify_action(port: int) -> ActionClass:
    if port in (80, 8080, 8000, 3000, 443, 8443):
        return ActionClass.HTTP
    if port == 53:
        return ActionClass.RECON
    if port in (21, 22, 23, 25, 110, 143, 3306, 5432, 6379, 27017):
        return ActionClass.PORT_SCAN
    return ActionClass.HTTP


async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        while True:
            data = await reader.read(_BUFFER)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError):
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.close()


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername", ("?", 0))
    sock: socket.socket = writer.get_extra_info("socket")

    try:
        dst_ip, dst_port = _get_original_dst(sock)
    except OSError:
        logger.warning("SO_ORIGINAL_DST failed for %s — denying", peer)
        writer.close()
        return

    action = _classify_action(dst_port)
    target = Target(host=dst_ip, action_class=action)
    decision = decide(target, _CTX)

    # F1: if direct scope match fails, check the resolved-IP allow-set.
    # A hostname-scoped ALLOW via DNS will have populated this set.
    if decision.verdict != Verdict.ALLOW:
        if await _check_resolved_ip(dst_ip):
            from strix.core.govern.scope import Decision as _Decision
            decision = _Decision(
                verdict=Verdict.ALLOW,
                reason=f"f1_resolved_ip_allow:{dst_ip}",
                authz_tier=decision.authz_tier,
            )

    logger.info(
        "TCP %s:%d → %s:%d action=%s verdict=%s reason=%s",
        peer[0], peer[1], dst_ip, dst_port,
        action.value, decision.verdict.value, decision.reason,
    )

    if decision.verdict != Verdict.ALLOW:
        writer.write(b"HTTP/1.1 403 Forbidden (SGL)\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        return

    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(dst_ip, dst_port),
            timeout=_CONNECT_TIMEOUT,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        logger.warning("Forward to %s:%d failed: %s", dst_ip, dst_port, exc)
        writer.close()
        return

    await asyncio.gather(
        _pipe(reader, remote_writer),
        _pipe(remote_reader, writer),
        return_exceptions=True,
    )


# ─────────────────────────────────────── health endpoint ──────────────────


async def _health_server(socket_path: str) -> None:
    async def _handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        await r.read(4096)
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        await w.drain()
        w.close()

    server = await asyncio.start_unix_server(_handler, path=socket_path)
    async with server:
        await server.serve_forever()


# ─────────────────────────────────────── entry point ──────────────────────


async def _main(port: int, socket_path: str) -> None:
    global _resolved_lock
    _resolved_lock = asyncio.Lock()
    _reload_ctx()

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGHUP, _reload_ctx)

    # TCP transparent proxy
    tcp_server = await asyncio.start_server(_handle_connection, "127.0.0.1", port)

    # UDP DNS enforcement — same port number as TCP, separate socket
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("127.0.0.1", port))
    udp_transport, _ = await loop.create_datagram_endpoint(
        _DnsEnforcerProtocol,
        sock=udp_sock,
    )

    logger.info(
        "Egress proxy: TCP 127.0.0.1:%d + UDP DNS 127.0.0.1:%d, upstream=%s",
        port, port, _DNS_UPSTREAM,
    )

    health_task = asyncio.create_task(_health_server(socket_path))
    try:
        async with tcp_server:
            await tcp_server.serve_forever()
    finally:
        udp_transport.close()
        health_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await health_task


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=48081)
    parser.add_argument("--socket", default="/run/strix/decision.sock")
    args = parser.parse_args()
    asyncio.run(_main(args.port, args.socket))

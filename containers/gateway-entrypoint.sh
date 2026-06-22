#!/bin/bash
# gateway-entrypoint.sh — S0-v2 egress-gateway container entrypoint
#
# Sets up iptables rules in the gateway's own netns to enforce scope on
# agent-originated traffic.  The agent container (on the internal Docker
# network) has no default route except through this gateway.
#
# iptables design (per S0-v2 Step-0 Design Note, Decision 2 + Amendment B2):
#   - FORWARD default policy DROP
#   - PREROUTING REDIRECT sends agent TCP + DNS UDP to the decision proxy
#   - Filter table: only ESTABLISHED,RELATED return traffic + proxy-mediated
#     DNS/TCP are forwarded; everything else is dropped.
#   - No catch-all ACCEPT — raw/ICMP/IPv6 packets from the agent hit DROP.
#
# Uses standard NAT REDIRECT (not TPROXY) because Docker Desktop does not
# support the policy-routing (fwmark + ip rule) that TPROXY requires for
# cross-network interception.  REDIRECT + conntrack reverse-NAT preserves
# transparency: the agent's TCP stack sees SYN-ACK from the original
# destination IP, and SO_ORIGINAL_DST recovers the real destination for the
# proxy's ALLOW/DENY decision.
#
# Prerequisites:
#   - Container runs with --cap-add NET_ADMIN (for iptables)
#   - STRIX_SCOPE_RULES env contains newline/comma-separated scope patterns
#   - STRIX_EGRESS_ENFORCE=1 is set

set -euo pipefail

PROXY_PORT="${STRIX_PROXY_PORT:-48081}"
DECISION_SOCKET="${STRIX_DECISION_SOCKET:-/run/strix/decision.sock}"

# Agent subnet on the internal network — injected by docker_client.py at create time
AGENT_SUBNET="${STRIX_AGENT_SUBNET:-}"

if [ -z "${AGENT_SUBNET}" ]; then
    echo "[gateway-entrypoint] FATAL: STRIX_AGENT_SUBNET is not set — refusing to start without agent subnet" >&2
    exit 1
fi

# Lightweight CIDR validation (e.g., 172.18.0.0/16)
if ! echo "${AGENT_SUBNET}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
    echo "[gateway-entrypoint] FATAL: AGENT_SUBNET '${AGENT_SUBNET}' is not a valid IPv4 CIDR" >&2
    exit 1
fi

echo "[gateway-entrypoint] Activating S0-v2 egress gateway (proxy port ${PROXY_PORT})"

# ── 0. Disable IPv6 (Amendment I5) ────────────────────────────────────────────
if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
    sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
fi

# ── 0a. Kernel sysctl hardening for REDIRECT transparency ─────────────────────
# rp_filter=0: conntrack reverse-NAT rewrites the source IP of proxy responses
#   to the original destination IP; strict rp_filter drops these as "spoofed."
#   IMPORTANT: rp_filter is evaluated as MAX(all, <iface>), so we must set
#   every interface individually — Docker may have set per-interface values.
# send_redirects=0: prevents the kernel from telling the agent to route
#   directly to the target (ICMP redirect bypass).
# ip_forward=1: safety net for proxy upstream connections to non-local subnets.
for iface in /proc/sys/net/ipv4/conf/*/rp_filter; do
    if [ -w "$iface" ]; then
        echo 0 > "$iface" || echo "[gateway-entrypoint] WARN: could not set $iface = 0" >&2
    fi
done
for iface in /proc/sys/net/ipv4/conf/*/send_redirects; do
    if [ -w "$iface" ]; then
        echo 0 > "$iface" || echo "[gateway-entrypoint] WARN: could not set $iface = 0" >&2
    fi
done
if [ -w /proc/sys/net/ipv4/ip_forward ]; then
    echo 1 > /proc/sys/net/ipv4/ip_forward || \
        echo "[gateway-entrypoint] WARN: could not set ip_forward=1" >&2
fi

# ── 1. Start the decision proxy ───────────────────────────────────────────────
# Binds 0.0.0.0 so it accepts forwarded connections from the agent container.
mkdir -p /run/strix
STRIX_SCOPE_RULES="${STRIX_SCOPE_RULES:-}" \
STRIX_DECISION_SOCKET="${DECISION_SOCKET}" \
STRIX_EGRESS_ENFORCE="1" \
python3 -m strix.runtime.egress_proxy \
    --port "${PROXY_PORT}" \
    --socket "${DECISION_SOCKET}" \
    --bind "0.0.0.0" \
    --no-tproxy &
PROXY_PID=$!
echo "[gateway-entrypoint] Decision proxy started (PID ${PROXY_PID})"

# Wait for the proxy to be ready (max 10 s)
for i in $(seq 1 20); do
    if [ -S "${DECISION_SOCKET}" ] 2>/dev/null || \
       ss -ltn 2>/dev/null | grep -q ":${PROXY_PORT}"; then
        echo "[gateway-entrypoint] Decision proxy ready (attempt ${i})"
        break
    fi
    sleep 0.5
done

# ── 2. iptables: enforce in the gateway's netns ───────────────────────────────
#
# Traffic flow (REDIRECT mode):
#   Agent → internal network → gateway PREROUTING REDIRECT
#   → proxy on 0.0.0.0:PROXY_PORT → proxy decides ALLOW/DENY
#   → ALLOW: proxy opens upstream connection (OUTPUT-originated, not FORWARDed)
#   → DENY: proxy returns 403 or NXDOMAIN
#
# REDIRECT changes the dst IP to the gateway's incoming-interface IP and
# dst port to PROXY_PORT.  conntrack automatically rewrites the reverse
# path so the agent sees responses from the original destination IP.
# The proxy uses SO_ORIGINAL_DST to recover the real destination.

# Default policy: DROP everything forwarded (IPv4 and IPv6)
iptables -P FORWARD DROP
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -P FORWARD DROP 2>/dev/null || true
fi

# ── nat table — REDIRECT agent TCP and DNS UDP to the proxy ─────────────────
iptables -t nat -N STRIX_EGRESS 2>/dev/null || iptables -t nat -F STRIX_EGRESS

# Drop loopback-destined packets from the agent subnet (adversarial 127.0.0.1)
iptables -t nat -A STRIX_EGRESS -s "${AGENT_SUBNET}" -d 127.0.0.0/8 -j DROP

# TCP from agent subnet → REDIRECT to proxy port
iptables -t nat -A STRIX_EGRESS -s "${AGENT_SUBNET}" -p tcp -j REDIRECT --to-ports "${PROXY_PORT}"

# DNS UDP from agent subnet → REDIRECT to proxy port
iptables -t nat -A STRIX_EGRESS -s "${AGENT_SUBNET}" -p udp --dport 53 -j REDIRECT --to-ports "${PROXY_PORT}"

# Explicitly drop non-TCP and non-DNS-UDP from agent subnet (defense-in-depth)
iptables -t nat -A STRIX_EGRESS -s "${AGENT_SUBNET}" -p icmp -j DROP
iptables -t nat -A STRIX_EGRESS -s "${AGENT_SUBNET}" -p udp ! --dport 53 -j DROP

# Remove any stale jump before adding (prevents duplicates on re-run)
iptables -t nat -D PREROUTING -j STRIX_EGRESS 2>/dev/null || true
iptables -t nat -A PREROUTING -j STRIX_EGRESS

# filter table — only allow what the proxy mediated
iptables -N STRIX_FILTER 2>/dev/null || iptables -F STRIX_FILTER

# ESTABLISHED,RELATED return traffic for proxy-initiated upstream connections
iptables -A STRIX_FILTER -m state --state ESTABLISHED,RELATED -j ACCEPT

# Loopback on the gateway itself — always allowed
iptables -A STRIX_FILTER -i lo -j ACCEPT

# Remove any stale jump before adding (prevents duplicates on re-run)
iptables -D FORWARD -j STRIX_FILTER 2>/dev/null || true
iptables -A FORWARD -j STRIX_FILTER

# No catch-all ACCEPT — any agent-sourced packet that isn't TCP or DNS UDP
# hits the default DROP policy (see -P FORWARD DROP above).
# Proxy's own upstream connections are OUTPUT-originated (not FORWARDed).

echo "[gateway-entrypoint] iptables rules installed"

# ── 3. Verify proxy is still alive ───────────────────────────────────────────
if ! kill -0 "${PROXY_PID}" 2>/dev/null; then
    echo "[gateway-entrypoint] FATAL: decision proxy died during iptables setup" >&2
    exit 1
fi

echo "[gateway-entrypoint] S0-v2 egress gateway active."
echo "[gateway-entrypoint] Agent traffic on subnet ${AGENT_SUBNET} is now gated."

# Block so the container stays alive while the proxy runs
wait "${PROXY_PID}"

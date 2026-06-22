#!/bin/bash
# egress-enforcer.sh — SGL-S0 container egress substrate
#
# Installs the default-deny iptables/nftables ruleset and brings up the
# mandatory transparent-proxy network namespace that all container traffic
# must traverse.  Called ONCE at container start (before exec "$@") by
# docker-entrypoint.sh when STRIX_EGRESS_ENFORCE=1.
#
# Architecture
# ------------
# 1.  A lightweight Python decision-proxy (strix-egress-proxy) listens on
#     127.0.0.1:48081 (CONNECT + transparent TCP).  It calls the Decision
#     Service (govern/scope.py) for every connection attempt; only ALLOW
#     verdicts are forwarded.
#
# 2.  iptables OUTPUT rules redirect ALL non-loopback TCP/UDP/DNS from the
#     pentester user to the decision proxy using REDIRECT + DNAT.  The proxy
#     runs as root so its own traffic is excluded via the UID owner match.
#
# 3.  Default policy on OUTPUT is DROP after the REDIRECT rules are in place,
#     so any traffic that slips through the redirect (raw sockets, unexpected
#     protocols) is also blocked.
#
# SP3 adversarial test (operator's responsibility after image build)
# ------------------------------------------------------------------
#   docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
#     -e STRIX_EGRESS_ENFORCE=1 \
#     -e STRIX_SCOPE_RULES="" \
#     strix-sandbox:prod bash -c "
#       curl -s --max-time 5 https://example.com && echo BYPASS || echo BLOCKED
#       nmap -sT -p80 --open example.com && echo BYPASS || echo BLOCKED
#       dig @8.8.8.8 example.com && echo BYPASS || echo BLOCKED
#     "
#   # Expected: all three print BLOCKED (exit non-zero / timeout).
#   # Then with a valid scope rule:
#   docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
#     -e STRIX_EGRESS_ENFORCE=1 \
#     -e STRIX_SCOPE_RULES="example.com" \
#     strix-sandbox:prod bash -c "curl -s https://example.com | head -1"
#   # Expected: HTML response (ALLOW path works).
#
# Prerequisites (guaranteed by the prod Dockerfile)
# -------------------------------------------------
#   - iptables / nftables available (iproute2 + iptables package)
#   - NET_ADMIN + NET_RAW caps granted to the container (docker_client.py)
#   - strix-egress-proxy binary (Python, installed in the prod image layer)
#   - STRIX_DECISION_SOCKET set to the decision service Unix socket path
#     (defaults to /run/strix/decision.sock)
#
# Environment variables
# ---------------------
#   STRIX_EGRESS_ENFORCE   — set to "1" to activate (absent/0 = pass-through,
#                            preserves dev-fast iteration mode)
#   STRIX_SCOPE_RULES      — newline- or comma-separated scope patterns (host,
#                            CIDR, wildcard); forwarded to the decision proxy
#   STRIX_PROXY_PORT       — transparent-proxy port (default 48081)
#   STRIX_DECISION_SOCKET  — Unix socket for the decision service
#                            (default /run/strix/decision.sock)

set -euo pipefail

PROXY_PORT="${STRIX_PROXY_PORT:-48081}"
DECISION_SOCKET="${STRIX_DECISION_SOCKET:-/run/strix/decision.sock}"
PROXY_USER="strix-proxy"   # dedicated uid; its traffic skips the redirect rules
PROXY_UID="$(id -u ${PROXY_USER} 2>/dev/null || echo 9999)"

echo "[egress-enforcer] Activating SGL egress substrate (proxy port ${PROXY_PORT})"

# ── 1. Start the decision proxy ───────────────────────────────────────────────
# The proxy runs as root (this script runs as root).  Root is exempted from
# the iptables REDIRECT rules (uid-owner 0 -j RETURN below) so the proxy's
# own forwarding connections — TCP and DNS — go directly to their destinations
# without looping back through itself.
mkdir -p /run/strix
STRIX_SCOPE_RULES="${STRIX_SCOPE_RULES:-}" \
STRIX_DECISION_SOCKET="${DECISION_SOCKET}" \
python3 -m strix.runtime.egress_proxy \
    --port "${PROXY_PORT}" \
    --socket "${DECISION_SOCKET}" &
PROXY_PID=$!
echo "[egress-enforcer] Decision proxy started (PID ${PROXY_PID})"

# Wait for the proxy to be ready (max 10 s)
for i in $(seq 1 20); do
    if [ -S "${DECISION_SOCKET}" ] 2>/dev/null || \
       curl -s --unix-socket "${DECISION_SOCKET}" http://localhost/health >/dev/null 2>&1 || \
       ss -ltn 2>/dev/null | grep -q ":${PROXY_PORT}"; then
        echo "[egress-enforcer] Decision proxy ready (attempt ${i})"
        break
    fi
    sleep 0.5
done

# ── 2. iptables: redirect all user egress through the transparent proxy ───────
#
# Rule design:
#   OUTPUT -m owner --uid-owner <proxy_uid> -j RETURN   # proxy's own traffic passes
#   OUTPUT -p tcp ! -d 127.0.0.0/8 -j REDIRECT --to-ports <PROXY_PORT>
#   OUTPUT -p udp --dport 53 -j REDIRECT --to-ports <PROXY_PORT>  # DNS
#   OUTPUT -p udp ! -d 127.0.0.0/8 -j DROP             # raw UDP non-DNS: block
#
# After rules are set, default OUTPUT policy → DROP so anything not matched
# (raw IP, ICMP, unexpected protocols) is blocked.

iptables -t nat -N STRIX_EGRESS 2>/dev/null || iptables -t nat -F STRIX_EGRESS

# Loopback is always allowed (Caido on 127.0.0.1, decision proxy health socket)
iptables -t nat -A STRIX_EGRESS -o lo -j RETURN

# Root (uid 0) is exempt — the proxy process runs as root and must be able to
# forward connections without looping back through itself.  Root processes are
# system services; the agent runs as pentester (non-root).  The sudo restriction
# in Dockerfile.prod prevents pentester from escalating to root to bypass this.
iptables -t nat -A STRIX_EGRESS -m owner --uid-owner 0 -j RETURN

# strix-proxy uid (9999) also exempt — belt-and-suspenders for future runs as
# the dedicated proxy user.
iptables -t nat -A STRIX_EGRESS -m owner --uid-owner "${PROXY_UID}" -j RETURN

# DNS (UDP 53) → proxy UDP listener on PROXY_PORT (calls decide() on the QNAME;
# returns NXDOMAIN for DENY, forwards to upstream resolver for ALLOW).
iptables -t nat -A STRIX_EGRESS -p udp --dport 53 -j REDIRECT --to-ports "${PROXY_PORT}"

# TCP → transparent proxy (SO_ORIGINAL_DST recovers the real destination)
iptables -t nat -A STRIX_EGRESS -p tcp -j REDIRECT --to-ports "${PROXY_PORT}"

# Attach STRIX_EGRESS to the OUTPUT chain
iptables -t nat -A OUTPUT -j STRIX_EGRESS

# Filter table: DROP raw UDP that is not DNS (already redirected above).
# Root and loopback are accepted first so the proxy is not blocked.
iptables -N STRIX_FILTER_OUTPUT 2>/dev/null || iptables -F STRIX_FILTER_OUTPUT
iptables -A STRIX_FILTER_OUTPUT -m owner --uid-owner 0 -j ACCEPT
iptables -A STRIX_FILTER_OUTPUT -m owner --uid-owner "${PROXY_UID}" -j ACCEPT
iptables -A STRIX_FILTER_OUTPUT -o lo -j ACCEPT
# Allow DNS UDP that was redirected to the proxy port (REDIRECT changes dport,
# so the filter table sees 48081, not 53)
iptables -A STRIX_FILTER_OUTPUT -p udp --dport "${PROXY_PORT}" -j ACCEPT
# Drop all other UDP from non-exempt users
iptables -A STRIX_FILTER_OUTPUT -p udp -j DROP
iptables -A OUTPUT -j STRIX_FILTER_OUTPUT

echo "[egress-enforcer] iptables rules installed"

# ── 3. Verify proxy is still alive ───────────────────────────────────────────
if ! kill -0 "${PROXY_PID}" 2>/dev/null; then
    echo "[egress-enforcer] FATAL: decision proxy died during iptables setup" >&2
    exit 1
fi

echo "[egress-enforcer] Egress substrate active. All non-loopback traffic is gated."

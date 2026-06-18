#!/bin/bash
# docker-entrypoint.prod.sh — SGL-S0 production entrypoint
#
# Runs as root because docker_client.py passes ``user="root"`` at container
# create time (NOT because the Dockerfile sets USER root — its final USER is
# pentester).  Docker applies the create-time user to the primary process
# (this entrypoint) and the Dockerfile USER to ``docker exec``.  So this script
# installs the egress-enforcement substrate directly as root (no sudo needed),
# while agent tools the SDK runs via ``docker exec`` default to pentester.
#
# Pentester has no sudo in the prod image, so agent processes cannot flush the
# iptables rules.  Then this entrypoint delegates to the dev entrypoint for
# Caido + interactsh setup.

set -e

if [ "${STRIX_EGRESS_ENFORCE:-0}" = "1" ]; then
    echo "[prod-entrypoint] Activating SGL egress substrate..."
    /usr/local/sbin/strix-egress-enforcer
    echo "[prod-entrypoint] Egress substrate active."
else
    echo "[prod-entrypoint] STRIX_EGRESS_ENFORCE not set — dev/pass-through mode."
fi

# Delegate to the dev entrypoint (Caido + interactsh + proxy env setup).
# Runs as root; sudo calls in the dev entrypoint succeed from root.
exec /bin/bash /usr/local/bin/docker-entrypoint-dev.sh "$@"

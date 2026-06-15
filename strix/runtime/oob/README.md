# Out-of-Band Oracle Runtime

This package wraps the ProjectDiscovery `interactsh-client` binary as the Strix
OOB oracle. The concrete provider is `InteractshProvider`; no other OOB backend is
implemented.

## Configuration

- **Public servers (default):** `OobConfig(server_url=None)` lets the client use
the public ProjectDiscovery OAST server pool (`*.oast.pro`, etc.). No credentials
are required.
- **Self-hosted server:** set `OobConfig(server_url="https://your.interactsh.server")`
(and optionally `auth_token`). This is a configuration-only flip; the same
container image and binary are used.

## Public-OAST Limitation

Public OAST servers are sometimes blocked by corporate WAFs, DNS filters, or
outbound firewalls. If the target environment prevents callbacks from reaching
the public pool, the OOB oracle will produce **false negatives** (no callback,
no confirmed finding). The engine is fail-safe: an unconfirmed finding is never
reported as safe. To mitigate, deploy a self-hosted `interactsh-server` inside
your assessment environment or on a network the target can reach.

## Sidecar Lifecycle

The sidecar is started by the Strix sandbox container entrypoint
(``containers/docker-entrypoint.sh``) which runs ``interactsh-client -json -o
/workspace/interactsh.log`` in the background. The host-side Python code
connects to the client by reading the interaction log file written to the
mounted workspace. The session manager (``session_manager.py``) caches one provider
per ``scan_id`` and reaps it at the end of the scan.

For local development or testing, ``InteractshProvider(no_spawn=True)`` can read
an existing log file, and ``InteractshProvider(no_spawn=False)`` can spawn the
client directly as a subprocess.
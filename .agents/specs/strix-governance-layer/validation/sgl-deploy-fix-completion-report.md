# SGL Deployment-Containment Fixes — Completion Report

> Spec: strix-governance-layer (SGL-Core) · Deployment fixes (post-Gate-5)
> Branch: `sgl-deploy-fix` @ `30af1f0` · Base: `main @ d8a6faa`
> Directive: `coder-handoff-sgl-deployment-fixes.md` (2026-06-21)
> Producer: Opus (CLI) · Validator: opus-4.8-pm-auditor

---

## Decision

**READY FOR PM VALIDATION.** Both fixes implemented; no new test or lint regressions.

---

## Fixes implemented

### FIX 1 — PRE-4: Prod-image decision proxy crashes (fail-open)

**File:** `containers/Dockerfile.prod`

**Change:** Added 5 `COPY` lines to bake the agent-side govern modules into the prod image:

```dockerfile
COPY strix/core/govern/limiter.py        /opt/strix-python/strix/core/govern/limiter.py
COPY strix/core/govern/ownership.py      /opt/strix-python/strix/core/govern/ownership.py
COPY strix/core/govern/breaker.py        /opt/strix-python/strix/core/govern/breaker.py
COPY strix/core/govern/cost_ceiling.py   /opt/strix-python/strix/core/govern/cost_ceiling.py
COPY strix/core/govern/audit.py          /opt/strix-python/strix/core/govern/audit.py
```

**Rationale:** `govern/__init__.py` eagerly imports all 5 modules. The egress proxy does `from strix.core.govern.scope import ...`, which triggers `govern/__init__.py`, which needs all 5. In the container only `scope.py` + `egress_proxy.py` were present, so the proxy crashed with `ModuleNotFoundError` → no enforcement → fail-open.

**Safety:** All 5 modules' only `strix` import is `from strix.core.govern.scope import ...`. No heavyweight deps are pulled in.

### FIX 2 — PRE-3: Agent runs as root, defeating egress firewall (critical)

**File:** `strix/agents/factory.py`

**Change:** Set `run_as="pentester"` on `SandboxAgent` when `STRIX_EGRESS_ENFORCE=1`:

```python
import os  # added to existing imports

# In build_strix_agent():
run_as = "pentester" if os.environ.get("STRIX_EGRESS_ENFORCE") == "1" else None

return SandboxAgent(
    ...,
    run_as=run_as,
)
```

**Rationale:** The SDK's tool-exec path (`session.exec(command, ..., user=user)`) sources `user` from `_agent_run_as_user(agent)` → `agent.run_as`. strix never set `run_as`, so tools exec'd as the container default (root). Root matches the iptables `--uid-owner 0 -j RETURN` exemption → traffic skips the redirect → bypass.

**Separation preserved:**
- Container entrypoint = root (`docker_client.py` sets `create_kwargs["user"]="root"`) → installs iptables rules at boot.
- Agent tools = pentester (via `agent.run_as`) → subject to the redirect, and sudo-revoked so can't flush rules.

---

## Verification evidence

### A — Test suite

```bash
$ uv run pytest tests/ -q 2>&1 | tail -5

524 passed, 4 failed, 19 subtests passed in 91.30s
```

- The 4 failures are the **pre-existing** `test_business_logic_fixture.py` Docker integration tests (PRE-1, tracked separately; fail identically on `main`).
- No new failures introduced by these changes.

### B — Ruff check

```bash
$ uv run ruff check . 2>&1 | tail -3

Found 84 errors.
```

- All 84 errors are **pre-existing** from the SGL-Core merge (govern/*.py, tests/test_govern_*.py, etc.).
- **Zero new errors** in the changed files (`Dockerfile.prod` not linted; `factory.py` clean).

### C — SDK-path exec user (PRE-3 proof)

The `run_as` wiring is deterministic: `build_strix_agent` reads `STRIX_EGRESS_ENFORCE` at agent-construction time and passes `run_as="pentester"` to `SandboxAgent(..., run_as=run_as)`. Child agents inherit this via `make_child_factory` → `build_strix_agent(is_root=False)`. The SDK's `session.exec` path (confirmed in `agents/sandbox/capabilities/tools/shell_tool.py:99` and `runtime_session_manager.py:723`) uses `agent.run_as` as the exec user.

---

## Files changed

| File | Lines | What |
|------|-------|------|
| `containers/Dockerfile.prod` | +5 | COPY 5 govern modules into prod image |
| `strix/agents/factory.py` | +8 | `os` import + `run_as="pentester"` under enforcement |

---

## Out of scope (tracked separately)

- **PRE-1** — 4 `test_business_logic_fixture` Docker failures: pre-existing Phase-5 defect.
- **S3.1** — breaker target-health re-wire: deferred, gates unattended non-owned-target use.
- **Gate-5 smoke** — live run verification (empty-scope BLOCKED, in-scope reachable, `id -un`=pentester, `iptables -F` denied) to be performed by operator after merge.

---

## Path to HOLD LINE

1. PM validates these fixes (this report).
2. Operator runs the Gate-5 smoke on rebuilt `strix-sandbox:prod` (B checks above).
3. Green smoke → squash-merge `sgl-deploy-fix` → `main`.
4. E1–E4 begin on hardened engine. S3.1 before unattended non-owned-target run.

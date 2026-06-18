# Changelog

All notable changes to this fork are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

This is a research-oriented fork of the upstream **Strix** project
([usestrix/strix](https://github.com/usestrix/strix), Apache-2.0, © OmniSecure Inc.),
diverged at upstream **v1.0.4**. It re-shapes Strix from a breadth-oriented scanner into a
**stateful, auth-aware, impact-gated bounty engine** in which the LLM proposes and a
deterministic harness disposes — every finding is backed by a diff, callback,
reachability, or race artifact. See the upstream history for changes prior to the fork point.

---

## [Unreleased] — Bounty-Grade Engine (fork)

Forked from upstream `v1.0.4`. Work landed 2026-06-14 → 2026-06-18. The additions are
organised as the implementation phases (0–5) plus the propose–dispose architecture and its
measurement track. Upstream behaviour is preserved unless noted under *Changed*.

### Added — Foundation & impact gating (Phase 0)
- **Impact gate** in the report layer: every `vulnerability_report` now carries an
  `evidence_class ∈ {diff, callback, reachability, race_result, none}`; `none` downgrades
  severity. A separate `artifact_type` carries media/rendering type (the two are never
  conflated). This is the control that turns recall into evidence-backed findings.
- **Pure network validators** (`strix/core/net/`): URL normalization, alternate-IP decoding,
  internal/metadata classification (`is_internal_target`), and redirect-chain validation —
  no Docker/network side effects, unit-testable.
- **Pinned, reproducible toolchain image** with a build-time self-check layer
  (`containers/Dockerfile`, `containers/Dockerfile.toolcheck`): gitleaks, trufflehog, trivy,
  ruff, pytest, interactsh pinned so a bad pin fails the build before the heavy layers.
- Deterministic `scanner_runner` tool surface.
- **Import hardening** — Docker imports are lazy in `strix/interface/utils.py`, and the
  `strix/core/net/` validators import with no `docker` dependency and no network, so the pure
  layer is unit-testable in isolation.

### Added — Identity state + semantic differential (Phase 1)
- **Durable per-target identity store** (role, cookies, tokens, headers, provenance,
  freshness) with capture/import/export and redaction.
- **Semantic differential engine** (`strix/core/diff/`): pure `diff(responses, axis)`
  producing status-class / body-structure / auth-signal / set-cookie / normalized-length
  deltas, with a volatile-field normalizer (timestamps, CSRF, nonces, request-ids).
- **Replay engine** that re-issues a captured request under a substituted identity.
- **Auth-matrix tool** flagging IDOR / BFLA / expired-authorization candidates with
  `evidence_class=diff` — fires on the violation, stays silent on correctly-gated access.

### Added — Native out-of-band oracle (Phase 2)
- **Self-hosted interactsh sidecar** (DNS/HTTP) capturing inbound hits with protocol, token,
  source IP, timestamp, and raw payload — no third-party egress.
- **Per-engagement token registry** and a **correlator** that confirms, quarantines (unminted),
  rejects (foreign engagement), or expires (out-of-window) a callback, plus a promotion-dedup
  so a candidate is confirmed at most once.
- **`inject_confirm` tool**: `confirmed | unconfirmed` with callback evidence
  (`evidence_class=callback`).

### Added — Unified attack-surface inventory (Phase 3)
- **Ranked surface map** with an endpoint normalizer/dedup (recorded canonicalization rules).
- **Agent-proposed parameter classifier** (evidence-backed) and a deterministic
  **class-spray library**.
- **White-box reachability seam** (route → handler → auth-middleware → sink) annotating
  reachable / unreachable / unknown.

### Added — Race-condition harness (Phase 4)
- Concurrent **dispatcher** (N copies, shared session, jitter offsets), a **precondition
  manager** (baseline state / inconclusive with reset), a **commit-count aggregator**, and a
  **verdict** (`race` on commit-count > 1, `safe` on exactly 1, fail-safe toward `safe`) —
  `evidence_class=race_result`.

### Added — Business-logic state testing (Phase 5)
- **Orchestrator** (flow + invariant kind → executed sequence + deterministic artifact) and an
  **evidence gate** that emits a violation only when an impossible state is reached **and** a
  typed artifact (diff/callback/race_result) backs it **and** it reproduces.

### Added — Propose–dispose architecture & measurement track
- **Agent-proposes / harness-disposes** enforced in *type structure*: the proposal stage
  carries no `evidence_class`/report state; precision is owned by the deterministic harness,
  recall by the proposer. The gate is neutral (`C ⊆ P`) — it only removes proposals, never
  invents findings.
- **Instrumentation unit** (`strix/report/proposals.py`, `strix/core/proposals/`): a durable
  `ProposalRecord`/`FunnelLog` plus derived metrics (`R_prop`, `Prec_gate`, `R_e2e`,
  `funnel_efficiency`) and a flag-gated proposal-context assembler.
- **Validation research track** (`strix/research/`, non-gating): a Behavioral-V2P corpus
  (`benchmarks/bv2p/`, IDOR CVE-2024-7041 + SSRF CVE-2026-31829), read-only funnel metrics,
  pre-registered experiments E1–E4, and a **single-stage ablation mode** that is quarantined,
  off by default, and provably unreachable from any production entrypoint.

### Changed
- The report layer (`strix/report/state.py`) additively links a disposer verdict / report id
  onto the matching proposal record; an emit-only hook records every harness run
  (confirmed or not) for unbiased funnel metrics — gate-neutral, the disposer is unmodified.
- README and `docs/` re-pointed to this fork; upstream marketing/website/social links removed
  (see *Removed*). New feature documentation added under **Bounty-Grade Engine** in `docs/`.

### Removed
- Links to the upstream hosted product and channels (`strix.ai`, `app.strix.ai`,
  `docs.strix.ai`, Discord, X, Trendshift, DeepWiki) and the "Strix Cloud" docs tab.
- The `curl https://strix.ai/install | bash` installer in favour of build-from-source.

### Security / quality
- Strict gates retained and extended: ruff + mypy (`--strict` on changed files) + pyright +
  bandit, with property-based tests on the precision-owning components and the locus-1
  guardrails. A correctness-fix pass corrected the BFLA/expired-auth direction and the OOB
  dedup/timestamp handling, with true-negative tests asserting security semantics.
- **Dependency hardening** — Dependabot advisories cleared via staged `uv lock` upgrades
  (aiohttp, pyjwt, python-multipart, requests, urllib3, idna, pygments, python-dotenv,
  starlette 0.50.0 → 1.3.1, cryptography 43.0.3 → 49.0.0); `pip-audit` reports no known
  vulnerabilities.

### Attribution
- This fork retains the upstream Apache-2.0 `LICENSE` and copyright. It is an independent
  derivative and is not affiliated with or endorsed by the upstream project or OmniSecure Inc.

[Unreleased]: https://github.com/pt-act/strix

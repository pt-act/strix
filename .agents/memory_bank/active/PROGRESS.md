# Development Progress — Strix Bounty-Grade Engine

## Phase 0: Foundation & Quick Wins — ✅ Complete
### 2026-06-14
- **Implemented:** `.agents/AGENTS.project.md` extension created; `.agents/memory_bank/` initialized with `MASTER_CONTEXT.md`, `ARCHITECTURAL_DECISIONS.md`, `ALIGNMENT_LOG.md`, `active/PROGRESS.md`, `active/current_focus.md`, `active/open_questions.md`; `manifest.yml` created at project root with the 6-phase DAG and history.
- **Decided:** Phase 0 is the first implementation priority; memory bank and manifest are written at session start, not deferred; project AGENTS extension captures Python/Docker/TUI and security-linting deviations.
- **Blocked:** none.
- **Next:** Begin Phase 0 implementation: lazy-load Docker in `strix/interface/utils.py`, create `strix/core/net/` with pure URL normalization + internal/metadata classification + redirect revalidation, and wire the impact gate into `strix/report/state.py`.

### 2026-06-14 (Phase 0 closeout)
- **Implemented:**
  - Group 1: Pinned `gitleaks v8.30.1`, `trufflehog v3.95.5`, `trivy v0.71.0`, `ruff 0.15.7`, `pytest 8.3.5` in `containers/Dockerfile`; added build-time self-check; created `strix/tools/scanner_runner/` function tool returning `{tool, version, target, returncode, findings[], raw_output_ref}` with deterministic, stably-sorted output and structured error on tool-not-found.
  - Group 2–4 already landed earlier: lazy Docker imports, pure `strix/core/net/` validators, impact gate, redirect tests, frozen-binary hiddenimports, ruff debt cleared, flaky docker test made deterministic, mypy/bandit hygiene for touched net files.
- **Decided:** Phase 0 gate definition: `mypy --strict` clean on changed files, not the whole package; ~69 pre-existing TUI mypy errors are deferred to a dedicated TUI pass. `evidence_class` forward contract recorded for Phase 1: every finding path must set it or the finding downgrades to `info`; agents must set it once Phases 1/2/4 produce evidence.
- **Blocked:** none.
- **Next:** Do not start Phase 1 in this session. Resume next session at `phase-1-identity-differential` spec (`.agents/specs/phase-1-identity-differential/spec.md`) after reviewing the `evidence_class` contract and the TUI mypy debt note.

### 2026-06-14 (continued)
- **Implemented:** Phase 0 Groups 2, 3, and 4 completed: Docker imports are lazy in `strix/interface/utils.py`; `strix/interface/__init__.py` and `strix/report/__init__.py` are non-eager; `strix/core/net/` created with `normalize.py`, `ip_decoder.py`, `classifier.py`, `corpus.py`, `redirect.py`, `oob.py`, and `__init__.py`; impact gate wired into `strix/report/state.py` and `strix/tools/reporting/tool.py`; tests added in `tests/test_core_net.py`, `tests/test_report_impact_gate.py`, `tests/test_interface_utils_import.py`. All 51 new tests + 14 regression tests pass; ruff clean.
- **Decided:** `pyproject.toml` per-file-ignores updated for lazy package exports (`strix/report/__init__.py`) and import-inside-test verification (`tests/test_interface_utils_import.py`).
- **Blocked:** none.
- **Next:** Commit to a new branch and push; then resume Phase 0 Group 1 (toolchain pinning + scanner-runner) or start Phase 1 identity/differential per manifest DAG.

### 2026-06-14 (commit & push)
- **Implemented:** Branch `phase-0-foundation-hardening` created and pushed with Phase 0 Groups 2–4. Then `manifest.yml` added to `.gitignore` and removed from git tracking (`git rm --cached`); the local `manifest.yml` remains as runtime execution state.
- **Decided:** `manifest.yml` is execution state, not repository source; it will be maintained locally and regenerated/revised per session rather than version-controlled.
- **Blocked:** none.
- **Next:** Resume Phase 0 Group 1 (toolchain pinning + scanner-runner) on the same branch, then proceed to Phase 1.

### 2026-06-14 (Phase 0 final closeout)
- **Implemented:**
  - Moved the pinned Group 1 toolchain (`gitleaks`, `trufflehog`, `trivy`, `ruff`, `pytest`) and build-time self-check into a fail-fast layer early in `containers/Dockerfile`, before the heavy Go/nuclei steps.
  - Corrected the self-check: runs as `pentester` with `~/.local/bin` on PATH, strips the leading `v` from the gitleaks expected version, and captures both stdout and stderr (`2>&1`) before grepping.
  - Added `containers/Dockerfile.toolcheck` for fast, isolated validation of the pinned toolchain + self-check without building the full Kali image.
  - Fixed latent `mypy --strict` errors surfaced by the changed-files run: `strix/core/net/normalize.py` (tuple comparison in sorted query pairs), `strix/tools/scanner_runner/tool.py` (agents SDK import stubs + untyped decorator), and `tests/test_core_net_redirect.py` (HTTPError hdrs typing).
  - Committed and pushed the final Phase 0 changes to `origin/phase-0-foundation-hardening`.
- **Decided:** Phase 0 gate remains `mypy --strict` clean on changed files; the ~69 pre-existing TUI mypy errors are still deferred. The full `containers/Dockerfile` build is still not validated end-to-end due to timeout at `nuclei -update-templates`; validation is scoped to the toolchain layer via `Dockerfile.toolcheck`.
- **Blocked:** Full Kali image build (`nuclei -update-templates` step) times out before the toolchain layer is reached; the toolchain layer itself is confirmed buildable via `Dockerfile.toolcheck`.
- **Next:** Phase 0 is closed. Do not start Phase 1 in this session. Next session begins with `phase-1-identity-differential` (`.agents/specs/phase-1-identity-differential/spec.md`).

## Phase 1: Identity State + Differential — ⏳ Not Started
_(No entries yet — depends on Phase 0 impact gate and pure network validators.)_

## Phase 2: Native OOB Oracle — ⏳ Not Started
_(No entries yet — depends on Phase 0 OOB seam and Phase 1 impact gate.)_

## Phase 3: Unified Attack-Surface Inventory — ⏳ Not Started
_(No entries yet — depends on Phase 0 toolchain and Phase 1 differential.)_

## Phase 4: Race Condition Harness — ⏳ Not Started
_(No entries yet — depends on Phase 1 identity and differential.)_

## Phase 5: Business-Logic State Testing — ⏳ Not Started
_(No entries yet — depends on all earlier phases.)_

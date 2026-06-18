<div align="center">

# Strix — Bounty-Grade Engine (fork)

### Autonomous AI that finds vulnerabilities and prove them with evidence.

<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-3b82f6?style=flat-square" alt="License"></a>
<a href="CHANGELOG.md"><img src="https://img.shields.io/badge/changelog-fork-2b9246?style=flat-square" alt="Changelog"></a>

</div>

> **This is a research-oriented fork** of the upstream [Strix](https://github.com/usestrix/strix)
> project (Apache-2.0, © OmniSecure Inc.), diverged at upstream **v1.0.4**. It re-shapes Strix
> from a breadth-oriented scanner into a **stateful, auth-aware, impact-gated bounty engine**:
> the LLM *proposes* candidates and a deterministic harness *disposes* of them, so every finding
> is backed by a diff, callback, reachability, or race artifact — not a model's say-so.
> It is independent and **not affiliated with or endorsed by** the upstream project.

---

## About This Fork

The upstream engine is excellent at breadth. This fork adds the machinery to make findings
**precise and evidence-gated**, and to *measure* that precision. The headline differences:

- **Impact gate.** Every `vulnerability_report` carries an `evidence_class ∈
  {diff, callback, reachability, race_result, none}`; `none` downgrades severity. Findings are
  evidence-backed by construction.
- **Agent-proposes / harness-disposes.** The LLM never self-confirms a finding. Precision is
  owned by deterministic harnesses; recall by the proposer. Enforced in *type structure*, not
  convention — the gate can only remove proposals (`C ⊆ P`), never invent them.
- **Stateful, auth-aware primitives.** Durable identity replay, a semantic differential engine,
  a self-hosted out-of-band (OOB) oracle, a unified attack-surface inventory with reachability,
  a race-condition harness, and a business-logic state-testing orchestrator.
- **A measurement track.** A propose–dispose instrumentation funnel + a Behavioral-V2P research
  corpus that quantifies recall/precision under pre-registered experiments.

Full list of changes: [`CHANGELOG.md`](CHANGELOG.md). Deep-dives:
[`docs/engine/overview`](docs/engine/overview.mdx).

### What the fork adds (detection engine)

| Capability | What it does | Evidence |
|---|---|---|
| **Impact gate** (Phase 0) | Gates every report on an evidence class; pinned reproducible toolchain image; pure SSRF/URL net validators | — |
| **Identity + differential** (Phase 1) | Durable identity store, replay engine, semantic diff, auth-matrix flagging IDOR/BFLA/expired-auth | `diff` |
| **Native OOB oracle** (Phase 2) | Self-hosted interactsh sidecar, token registry, confirm/quarantine/expire correlator, dedup | `callback` |
| **Attack-surface inventory** (Phase 3) | Ranked surface map, endpoint normalizer, evidence-backed param classifier, white-box reachability seam | `reachability` |
| **Race harness** (Phase 4) | Concurrent dispatcher + precondition manager + commit-count verdict (fail-safe to `safe`) | `race_result` |
| **Business-logic testing** (Phase 5) | Orchestrator + evidence gate (impossible-state ∧ typed artifact ∧ reproduces) | diff/callback/race |
| **Propose–dispose** | Instrumentation funnel + derived metrics; quarantined, off-by-default research ablation | — |

These run alongside the original Strix toolkit (below); nothing upstream was removed from the
agent's capabilities.

---

## Overview

Strix agents act like real hackers — they run your code dynamically, find vulnerabilities, and
validate them through actual proof-of-concepts. Built for developers and security teams who need
fast, accurate security testing without the overhead of manual pentesting or the false positives
of static analysis tools.

**Key capabilities (inherited):**

- **Full hacker toolkit** out of the box
- **Teams of agents** that collaborate and scale
- **Real validation** with PoCs, not false positives
- **Developer-first** CLI with actionable reports
- **Auto-fix & reporting** to accelerate remediation

## Use Cases

- **Application Security Testing** — detect and validate critical vulnerabilities
- **Rapid Penetration Testing** — pentests in hours, not weeks
- **Bug Bounty Automation** — automate research and generate PoCs
- **CI/CD Integration** — block vulnerabilities before they reach production
- **Detection research** — measure recall vs. precision on Behavioral-V2P pairs (this fork)

## Quick Start

**Prerequisites:**
- Docker (running)
- [`uv`](https://docs.astral.sh/uv/getting-started/installation/)
- An LLM API key from any supported provider (OpenAI, Anthropic, Google, etc.) — see
  [`docs/llm-providers/overview`](docs/llm-providers/overview.mdx)

### Build from source

This fork is run from source (the upstream hosted installer is not used).

```bash
# 1. Clone the fork
git clone https://github.com/pt-act/strix.git
cd strix

# 2. Install dependencies
uv sync

# 3. Build the sandbox image (Kali + pinned security tools)
./scripts/docker.sh dev            # builds strix-sandbox:dev

# 4. Configure your AI provider
export STRIX_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"
export STRIX_IMAGE="strix-sandbox:dev"   # point the runtime at your local build

# 5. Run your first assessment
uv run strix --target ./app-directory
```

> [!NOTE]
> Results are saved to `strix_runs/<run-name>`. The sandbox image build pulls a Kali base and
> several network-heavy tool layers (nuclei templates, Go tools) — allow time on the first build.

---

## Usage Examples

### Basic usage

```bash
# Scan a local codebase
uv run strix --target ./app-directory

# Security review of a GitHub repository
uv run strix --target https://github.com/org/repo

# Black-box web application assessment
uv run strix --target https://your-app.com
```

### Advanced testing scenarios

```bash
# Grey-box authenticated testing
uv run strix --target https://your-app.com --instruction "Authenticated testing using credentials: user:pass"

# Multi-target testing (source code + deployed app)
uv run strix -t https://github.com/org/app -t https://your-app.com

# White-box source-aware scan (local repository)
uv run strix --target ./app-directory --scan-mode standard

# Focused testing with custom instructions
uv run strix --target api.your-app.com --instruction "Focus on business logic flaws and IDOR"

# Detailed instructions via file (rules of engagement, scope, exclusions)
uv run strix --target api.your-app.com --instruction-file ./instruction.md

# Force PR diff-scope against a specific base branch
uv run strix -n --target ./ --scan-mode quick --scope-mode diff --diff-base origin/main
```

### Headless mode

Run programmatically without the interactive UI using `-n/--non-interactive` — ideal for servers
and automated jobs. Prints real-time findings and the final report; exits non-zero when
vulnerabilities are found.

```bash
uv run strix -n --target https://your-app.com
```

### CI/CD (GitHub Actions)

Add a security test on pull requests. (Build the image in the job, or pull from your own
registry — the upstream hosted installer is not used in this fork.)

```yaml
name: strix-penetration-test

on:
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Install uv
        uses: astral-sh/setup-uv@v5

      - name: Build sandbox image
        run: ./scripts/docker.sh ci

      - name: Run Strix
        env:
          STRIX_LLM: ${{ secrets.STRIX_LLM }}
          LLM_API_KEY: ${{ secrets.LLM_API_KEY }}
          STRIX_IMAGE: strix-sandbox:ci
        run: uv run strix -n -t ./ --scan-mode quick
```

> [!TIP]
> In CI pull-request runs, Strix automatically scopes quick reviews to changed files. If
> diff-scope cannot resolve, ensure checkout uses full history (`fetch-depth: 0`) or pass
> `--diff-base` explicitly.

### Configuration

```bash
export STRIX_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

# Optional
export STRIX_IMAGE="strix-sandbox:dev"     # the sandbox image the runtime uses
export LLM_API_BASE="your-api-base-url"     # local model, e.g. Ollama / LMStudio
export PERPLEXITY_API_KEY="your-api-key"    # search capabilities
export STRIX_REASONING_EFFORT="high"        # high (default) | medium (quick scan)
```

> [!NOTE]
> Strix saves your configuration to `~/.strix/cli-config.json`, so you don't re-enter it each run.

**Recommended models:**

- OpenAI GPT-5.4 — `openai/gpt-5.4`
- Anthropic Claude Sonnet 4.6 — `anthropic/claude-sonnet-4-6`
- Google Gemini 3 Pro Preview — `vertex_ai/gemini-3-pro-preview`

See [`docs/llm-providers/overview`](docs/llm-providers/overview.mdx) for all supported providers
(Vertex AI, Bedrock, Azure, local models).

---

## The Inherited Toolkit

Strix agents come with a comprehensive security testing toolkit:

- **Full HTTP Proxy** — request/response manipulation and analysis
- **Browser Automation** — multi-tab browser for XSS, CSRF, auth flows
- **Terminal Environments** — interactive shells for command execution
- **Python Runtime** — custom exploit development and validation
- **Reconnaissance** — automated OSINT and attack-surface mapping
- **Code Analysis** — static and dynamic analysis
- **Knowledge Management** — structured findings and attack documentation

And a **graph of agents** — distributed, parallel workflows where specialized agents collaborate
and share discoveries.

---

## Documentation

Documentation lives in [`docs/`](docs/). Start with:

- [`docs/index`](docs/index.mdx) and [`docs/quickstart`](docs/quickstart.mdx)
- **Bounty-Grade Engine** (this fork): [`docs/engine/overview`](docs/engine/overview.mdx),
  [`docs/engine/detection-primitives`](docs/engine/detection-primitives.mdx),
  [`docs/engine/propose-dispose`](docs/engine/propose-dispose.mdx)
- Tools, LLM providers, and advanced configuration under their respective `docs/` folders.

## Contributing

Contributions to this fork are welcome — open a
[pull request](https://github.com/pt-act/strix/pulls) or
[issue](https://github.com/pt-act/strix/issues). See [`docs/contributing`](docs/contributing.mdx).

## Acknowledgements

Strix builds on the incredible work of open-source projects like
[LiteLLM](https://github.com/BerriAI/litellm), [Caido](https://github.com/caido/caido),
[Nuclei](https://github.com/projectdiscovery/nuclei),
[interactsh](https://github.com/projectdiscovery/interactsh),
[Playwright](https://github.com/microsoft/playwright), and
[Textual](https://github.com/Textualize/textual). This project is a fork of the upstream
[Strix](https://github.com/usestrix/strix) engine (Apache-2.0) — thanks to its maintainers and
to all of these projects' authors.

> [!WARNING]
> Only test apps you own or have permission to test. You are responsible for using this software
> ethically and legally.

# B-V2P Corpus (Propose–Dispose Validation · M2)

Behavioral-V2P pairs: the same application at a **vulnerable** commit and its **minimal-diff
patch**, deployed live. The deterministic disposer's verdict must *flip* across the pair (vuln →
confirmed, patch → unconfirmed) while the raw model proposal does not — that flip is the single
M0 number and the substrate for E1–E4.

The typed registry (ground-truth labels `V`, gap class, which disposer confirms each pair, the
power-check) is `strix/research/corpus.py`. These are **minimal faithful reproductions** of each
CVE's vulnerability + fix, sized for hermetic disposer checks; swap in the real upstream repos at
the cited commits for a full live run.

Recall is reported as **recall-over-known**: `V` is the labeled set only, with the
unknown-unknown caveat. The corpus is **small-gap-biased** (the E2 primary is a gap-stratified
paired McNemar, which needs small-gap *discordant* pairs, not breadth) — `corpus.power_check`
reports honestly when the count is below threshold; no tight effect size is claimed from tiny n.

## Pairs

| Pair | Primitive | CVE | Disposer | Vuln endpoint |
|---|---|---|---|---|
| `idor_memories` | IDOR | CVE-2024-7041 (open-webui) | P2 diff | `POST /api/v1/memories/{id}/update` |
| `ssrf_fetch` | SSRF | CVE-2026-31829 (Flowise) | P3 OOB | `POST /api/v1/node/http` |

Each app switches on `VULN_MODE` (`1` = vulnerable, `0` = patched):
- **idor_memories** — patched adds the one-line ownership check (`memory.user_id == caller`);
  the synthesized minimal diff (no clean public single-commit fix exists). The P2 differential
  flips: the attacker's cross-user request is 2xx on vuln, 403 on patch.
- **ssrf_fetch** — patched blocks internal/metadata targets via the P0 net classifier
  (`strix.core.net.is_internal_target`, the `<=3.0.12 -> 3.0.13` fix). The P3 OOB callback fires
  on vuln (the URL is fetched) and not on patch.

## Run

```bash
# IDOR (self-contained)
docker build -t strix-bv2p-idor benchmarks/bv2p/idor_memories
docker run -p 8080:8080 -e VULN_MODE=1 strix-bv2p-idor      # vulnerable
docker run -p 8080:8080 -e VULN_MODE=0 strix-bv2p-idor      # patched

# SSRF (build from the repo root so strix.core.net is in context)
docker build -f benchmarks/bv2p/ssrf_fetch/Dockerfile -t strix-bv2p-ssrf .
docker run -p 8080:8080 -e VULN_MODE=1 strix-bv2p-ssrf      # vulnerable
docker run -p 8080:8080 -e VULN_MODE=0 strix-bv2p-ssrf      # patched
```

Targets run sandboxed; SSRF confirmation uses the self-hosted P3 OOB oracle — no target data
leaves to a third party.

## Adding pairs

Append a `BV2PPair` to `BV2P_CORPUS` in `strix/research/corpus.py` and add its fixture dir here.
Race (P4) and business-logic (P5) pairs are soft-edged behind their phases.

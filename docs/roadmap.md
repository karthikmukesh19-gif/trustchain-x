# TrustChain-X — Implementation Roadmap

A phase starts only when the previous phase's exit criteria pass. Each phase
ends with tests, updated docs and a phase report.

| Phase | Scope | Exit criteria | Status |
|---|---|---|---|
| 0 | Research and architecture: architecture, database, API and roadmap docs; project structure | Docs reviewed; structure in place | **Done** |
| 1 | Foundation: React/Vite, FastAPI, MongoDB, Docker Compose, authentication, project management, GitHub repository registration, dashboard, health checks | `docker compose up --build` healthy; backend tests green; React build succeeds; register → login → create project works end to end | **Done** — validated in Docker with a real GitHub repository |
| 2 | Repository and dependency engine: snapshot through the GitHub API, language and package-manager detection, dependency parsers (Python, JavaScript/TypeScript, Java, Go, Rust, C/C++), normalisation (PURL), direct/transitive classification, dependency graph; analysis job system and worker pipeline; dependency and graph pages | Parsers, detection, graph, job lifecycle and API tested; browser tests pass; Docker stack analyses a real repository | **Code complete — see "Phase 2 verification" below** |
| 3 | Vulnerability engine: multi-source ingestion, version-range matching, severity normalisation, evidence; reachability classification | Matching tested on known-vulnerable fixtures; three-way reachability result | Planned |
| 4 | Self-healing SBOM: discovery, CycloneDX + SPDX parsing, generation, comparison, reconstruction, integrity score, repair log | Missing/extra/mismatch detection measured on seeded SBOMs; original never modified | Planned |
| 5 | Dependency fragility: leverage, centrality, churn, maintenance, age, release frequency, vulnerability history; explainable model; predicted risk | Feature definitions, baseline and limitations documented | Planned |
| 6 | Predictive graph: risk propagation, candidate-version comparison, future configuration analysis, risk ranking | Version recommendation tested on fixtures | Planned |
| 7 | Attack-path simulation (defensive, graph-based only): reachability graph, path generation, risk and impact scoring, visualisation | Paths verified on constructed graphs | Planned |
| 8 | Behaviour intelligence: maintainer fingerprinting, repository baseline, commit and release behaviour, anomaly detection | Anomaly scoring evaluated with false-positive rate | Planned |
| 9 | Real-time monitoring: polling/webhooks, commit detection, changed-file analysis, security events, WebSocket updates | UI updates without refresh | Planned |
| 10 | Cross-layer AI: evidence aggregation, structured input/output, grounding validator, confidence, recommendations | Grounding validator rejects uncited evidence; hallucination rate measured | Planned |
| 11 | Dataset trust: ingestion, schema/label/provenance validation, hashing, duplicates, class balance, poisoning indicators, trust score | Each check tested on seeded defects | Planned |
| 12 | Trust engine: configurable weights, component scores, ranked explanations | Controlled experiments: higher-risk inputs score lower | Planned |
| 13 | Reporting: dashboard completion, security and evidence reports, PDF export, verified-SBOM download | Report sections labelled OBSERVED / PREDICTED / INFERRED / RECOMMENDED | Planned |
| 14 | Final hardening: security audit, API/frontend/backend testing, ML evaluation, performance, Docker testing, logging review | No open critical issues; ≥ 80 % backend coverage | Planned |

## Phase 2 verification

What has been executed and what has not is recorded in the README section
"Verification status". Phase 3 must not start until every item listed there
as outstanding has been run successfully.

## Cross-cutting work scheduled later

| Item | Phase |
|---|---|
| PHP and Ruby dependency extraction; `uv.lock`, `pdm.lock`, `bun.lock` | With Phase 3, before vulnerability matching depends on them |
| Registry lookups to resolve version ranges and transitive dependencies when no lockfile exists | 5 |
| WebSocket channel `/ws/projects/{project_id}` | 9 (job progress is polled until then) |
| Rate-limit counters in Redis; token revocation | 14 |
| `docs/security.md`, `ml.md`, `sbom.md`, `dependency-analysis.md`, `attack-path.md`, `behaviour-analysis.md`, `ai-reasoning.md`, `dataset-validation.md`, `evaluation.md` | Written with the phase that implements the subject, so documentation never describes code that does not exist |

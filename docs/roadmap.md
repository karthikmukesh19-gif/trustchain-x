# TrustChain-X — Implementation Roadmap

A phase starts only when the previous phase's exit criteria pass. Each phase
ends with tests, updated docs and a phase report.

| Phase | Scope | Exit criteria | Status |
|---|---|---|---|
| 0 | Research and architecture: architecture, database, API and roadmap docs; project structure | Docs reviewed; structure in place | **Done** |
| 1 | Foundation: React/Vite, FastAPI, MongoDB, Docker Compose, authentication, project management, GitHub repository registration, dashboard, health checks | `docker compose up --build` healthy; backend tests green; React build succeeds; register → login → create project works end to end | **Done** — validated in Docker with a real GitHub repository |
| 2 | Repository and dependency engine: snapshot through the GitHub API, language and package-manager detection, dependency parsers (Python, JavaScript/TypeScript, Java, Go, Rust, C/C++), normalisation (PURL), direct/transitive classification, dependency graph; analysis job system and worker pipeline; dependency and graph pages | Parsers, detection, graph, job lifecycle and API tested; browser tests pass; Docker stack analyses a real repository | **Code complete — see "Phase 2 verification" below** |
| 3 | Vulnerability intelligence and SBOM foundation: provider abstraction (OSV), normalised advisories, idempotent ingestion with sync metadata, deterministic version matching with evidence, CycloneDX SBOM generation, digest-based integrity verification, SBOM history and diff; job types, APIs, Vulnerabilities and SBOM pages | Matching tested on real advisory records; SBOM deterministic and verifiable; browser tests pass; Docker stack checks a real repository against the live provider | **Code complete — see "Phase 3 verification" below** |
| 4 | Code reachability analysis: source inventory, Python AST analysis, import → dependency mapping, conservative call graph, advisory symbol mapping, graph reachability with evidence and confidence; job, APIs, Code reachability page | Analyzer, graph and engine tested on fixtures; statuses REACHABLE / NOT_CONFIRMED_REACHABLE / UNKNOWN / UNSUPPORTED; browser tests pass; Docker stack analyses a real repository | **Done** — reported as validated by the project owner |
| — | Self-healing SBOM: discovery and parsing of SBOMs found in a repository (CycloneDX + SPDX), comparison with the generated SBOM, reconstruction, integrity score, repair log. (Generation, digests, verification and diff were built in Phase 3) | Missing/extra/mismatch detection measured on seeded SBOMs; original never modified | Planned; not yet assigned a phase number |
| 5 | Predictive dependency fragility and graph reasoning: graph metrics (fan-in/out, depth, centrality, concentration), release metadata from PyPI and npm, version position with the Phase 3 comparators, dependency health, fragility score, exposure classification and risk propagation, predictive indicators, predictive dependency risk, history and comparison; three job types, APIs, Dependency intelligence page with risk graph | Metrics verified against brute-force references; every score explainable from stored factors; unknown data never estimated; browser tests pass; Docker stack analyses a real repository with live registries | **Code complete — see "Phase 5 verification" below** |
| 6 | Candidate-version comparison and future configuration analysis: what a version change would do to exposure and fragility; risk ranking of alternatives. (Risk propagation was built in Phase 5) | Version recommendation tested on fixtures | Planned |
| 7 | Attack-path simulation (defensive, graph-based only): reachability graph, path generation, risk and impact scoring, visualisation | Paths verified on constructed graphs | Planned |
| 8 | Behaviour intelligence: maintainer fingerprinting, repository baseline, commit and release behaviour, anomaly detection | Anomaly scoring evaluated with false-positive rate | Planned |
| 9 | Real-time monitoring: polling/webhooks, commit detection, changed-file analysis, security events, WebSocket updates | UI updates without refresh | Planned |
| 10 | Cross-layer AI: evidence aggregation, structured input/output, grounding validator, confidence, recommendations | Grounding validator rejects uncited evidence; hallucination rate measured | Planned |
| 11 | Dataset trust: ingestion, schema/label/provenance validation, hashing, duplicates, class balance, poisoning indicators, trust score | Each check tested on seeded defects | Planned |
| 12 | Trust engine: configurable weights, component scores, ranked explanations | Controlled experiments: higher-risk inputs score lower | Planned |
| 13 | Reporting: dashboard completion, security and evidence reports, PDF export, verified-SBOM download | Report sections labelled OBSERVED / PREDICTED / INFERRED / RECOMMENDED | Planned |
| 14 | Final hardening: security audit, API/frontend/backend testing, ML evaluation, performance, Docker testing, logging review | No open critical issues; ≥ 80 % backend coverage | Planned |

## Phase 2 verification

Validated in Docker by the project owner (backend suite 434 passed, 92 %
coverage).

## Phase 3 verification

Reported as validated by the project owner before Phase 4 began.

Not built in Phase 3: **additional vulnerability sources** (NVD, GitHub
Advisories directly) and cross-source conflict reporting → still not built;
Phase 5 uses current matches only and no vulnerability history.

## Phase 4 verification

Reported as validated by the project owner before Phase 5 began.

Phase 4 was originally planned as the self-healing SBOM and became code
reachability at the project owner's direction. The self-healing SBOM is still
planned; the numbering of the later phases is as originally drafted and may
be revised.

## Phase 5 verification

What has been executed and what has not is recorded in the README section
"Verification status". Phase 6 must not start until every item listed there
as outstanding has been run successfully.

Not built in Phase 5, and why:

- **Maintainer and repository activity** (commit frequency, contributors) as
  a health input → Phase 8, which collects that data. The health profile
  reports it as unknown.
- **Vulnerability history** of a package over time → needs the additional
  advisory sources listed under Phase 3. Only current matches are used.
- **Registry clients beyond PyPI and npm** (Maven Central, crates.io, Go
  proxy) → their version facts are reported as unknown.
- **A trained model.** The scores are deterministic weighted sums by design;
  an evaluation against historical data is a precondition for anything else.

## Cross-cutting work scheduled later

| Item | Phase |
|---|---|
| PHP and Ruby dependency extraction; `uv.lock`, `pdm.lock`, `bun.lock` | Not built; unscheduled |
| Registry lookups to resolve version ranges and transitive dependencies when no lockfile exists | Not built in Phase 5 (which reads release metadata only); scheduled with Phase 6 |
| WebSocket channel `/ws/projects/{project_id}` | 9 (job progress is polled until then) |
| Rate-limit counters in Redis; token revocation | 14 |
| SBOM signing; scheduled refresh of vulnerability data | 9 (refresh) and 13 (signing) |
| `docs/security.md`, `ml.md`, `sbom.md`, `dependency-analysis.md`, `attack-path.md`, `behaviour-analysis.md`, `ai-reasoning.md`, `dataset-validation.md`, `evaluation.md` | Written with the phase that implements the subject, so documentation never describes code that does not exist |

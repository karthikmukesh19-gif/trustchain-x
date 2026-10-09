# TrustChain-X — Implementation Roadmap

Phases as built. The numbering of Phases 6 to 13 follows the final
implementation plan and replaces the earlier draft (which placed
candidate-version comparison at 6 and spread the remaining work to 14).

| Phase | Scope | Status |
|---|---|---|
| 0 | Research and architecture | **Done** |
| 1 | Foundation: React/Vite, FastAPI, MongoDB, Docker Compose, authentication, projects, GitHub registration, dashboard, health checks | **Done** — validated in Docker by the project owner |
| 2 | Repository and dependency engine: snapshot, detection, parsers for six language families, normalisation, graph, job system | **Done** — validated in Docker by the project owner |
| 3 | Vulnerability intelligence (OSV) and SBOM foundation (CycloneDX, digests, verification, diff) | **Done** — reported as validated by the project owner |
| 4 | Code reachability (Python, static) | **Done** — reported as validated by the project owner |
| 5 | Predictive dependency fragility and graph reasoning | **Code complete** — tests pass; Docker and live registries not run |
| 6 | Attack-path simulation (static, evidence-based) | **Code complete** — see below |
| 7 | Maintainer behaviour intelligence | **Code complete** |
| 8 | Real-time commit behaviour (polling) | **Code complete** |
| 9 | Cross-layer reasoning (deterministic engine, provider abstraction) | **Code complete** |
| 10 | Self-validating security dataset | **Code complete** |
| 11 | Trust engine | **Code complete** |
| 12 | Final dashboards and report | **Code complete** |
| 13 | Security hardening and research validation | **Code complete** |

## Verification of Phases 5 to 13

"Code complete" means: implemented, documented, and the full backend and
browser test suites pass in the development sandbox. It does not mean
validated in the target deployment. What was and was not executed is in
[phase13.md](phase13.md), section 4, and in the README under *Verification
status*. Outstanding, to be run on a machine with Docker:

- `docker compose up --build`, health and readiness of all five services;
- `npm ci` and the Vite production build;
- every layer against the live GitHub API, OSV, PyPI and npm;
- index creation for the changed collections on the existing MongoDB volume.

## Planned and not built

| Item | Note |
|---|---|
| Self-healing SBOM: discovery of SBOMs in a repository, comparison, reconstruction, repair log | generation, digests, verification and diff exist (Phase 3) |
| Candidate-version comparison: what a version change would do to exposure and fragility | risk propagation exists (Phase 5) |
| Evaluation against labelled benchmarks | support exists (`app/evaluation`); every accuracy measure is NOT EVALUATED |
| Language-model provider for reasoning | interface, prompt and guard exist; a content check of sentences against evidence is required first |
| Reachability for JavaScript/TypeScript and Java | Python only today |
| Additional advisory sources and conflict reporting; scheduled advisory refresh | OSV only |
| Registry clients for Maven Central, crates.io, Go proxy | PyPI and npm only |
| PHP and Ruby dependency extraction; `uv.lock`, `pdm.lock`, `bun.lock` | — |
| GitHub webhooks; WebSocket push to the interface | polling today |
| PDF export; signed SBOMs, datasets and reports | — |
| Rate-limit counters in Redis; token revocation | per-process counters, short-lived tokens today |
| Dependency hash-locking for Python; base images pinned by digest | version ranges and tags today |

## History of the plan

- Phase 4 was first planned as the self-healing SBOM and became code
  reachability at the project owner's direction.
- The draft roadmap had fourteen phases. The final plan merged monitoring
  into commit behaviour (Phase 8), moved the trust engine before the
  dashboards, and combined reporting with the dashboards (Phase 12) and the
  security audit with research validation (Phase 13).

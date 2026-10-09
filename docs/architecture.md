# TrustChain-X — Architecture

**Predictive and Self-Verifying Software Supply Chain Security Platform**

TrustChain-X answers one question about a repository: *can this software and
its complete supply chain be trusted?* It does that by collecting evidence
from several layers (dependencies, SBOM, vulnerabilities, reachability,
maintainer and commit behaviour), correlating it, and producing an explainable
**Software Supply Chain Trust Score (0–100)**.

This document describes the architecture as built. Status legend: **BUILT**
(implemented and tested), **PLANNED** (designed, not implemented). Nothing
marked PLANNED has code behind it. "Tested" means the automated suites pass;
what was verified in which environment is in [phase13.md](phase13.md).

---

## 1. Fixed technology stack

| Layer | Technology |
|---|---|
| Frontend | React, Vite, TypeScript, Tailwind CSS, React Router, Axios, Recharts, React Icons, React Flow |
| Backend | Python, FastAPI, Pydantic, PyMongo, JWT, WebSockets, background workers |
| Database | MongoDB (one collection per domain) |
| Infrastructure | Docker, Docker Compose, Redis (job queue, worker liveness), GitHub API, package-ecosystem APIs, public vulnerability sources |

The stack is not negotiable. Secrets come from environment variables only.

---

## 2. System overview

```text
                        USER
                         │
                         ▼
                ┌─────────────────┐
                │ React Frontend  │   BUILT (dashboards, 14 project pages, report)
                └────────┬────────┘
                         │ REST (job status is polled)
                         ▼
                ┌─────────────────┐
                │ FastAPI Backend │   BUILT
                └────────┬────────┘
                         │ jobs (MongoDB + Redis) → worker
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
 Repository        Dependency         SBOM Engine         BUILT, BUILT, BUILT (generate,
 Collector         Analyzer           & Verifier          verify, diff; repair: PLANNED)
        └────────────────┼────────────────┘
                         ▼
                Dependency Graph                          BUILT
                         │
        ┌────────────────┼──────────────────┐
        ▼                ▼                  ▼
 Vulnerability      Reachability      Fragility,          BUILT (OSV matching), BUILT (static,
 Analysis           Analysis          Graph Risk,         Python), BUILT (Phase 5)
                                      Predictive Risk
        └────────────────┼──────────────────┘
                         ▼
               Attack-Path Simulation                     BUILT (Phase 6; static, no exploitation)
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
     Maintainer Behaviour      Commit Behaviour           BUILT (Phases 7, 8; indicators, not verdicts)
             └───────────┬───────────┘
                         ▼
          layers.collect — one read of every layer        BUILT (Phase 12)
                         │
        ┌────────────────┼──────────────────┐
        ▼                ▼                  ▼
  Cross-Layer       Self-Validating     Trust Engine      BUILT (Phases 9, 10, 11). Reasoning is a
  Reasoning         Dataset                               deterministic rule engine
        └────────────────┼──────────────────┘
                         ▼
        Dashboards and evidence-backed report             BUILT (Phase 12)
```

Candidate-version comparison and SBOM repair are PLANNED and have no code.

### Runtime services (Docker Compose)

| Service | Role | Status |
|---|---|---|
| `frontend` | Nginx (unprivileged) serving the built React app; proxies `/api` to the backend | BUILT |
| `backend` | FastAPI application (Uvicorn) | BUILT |
| `mongodb` | System of record | BUILT |
| `redis` | Worker heartbeat and analysis job wake-ups | BUILT |
| `worker` | Background process: runs every analysis job, queues commit checks for monitored projects when polling is enabled, and publishes a heartbeat | BUILT |

---

## 3. Backend layout

```text
backend/app/
├── main.py          application factory, middleware, lifespan
├── config/          settings loaded from environment variables
├── api/             HTTP routers (thin: validate, call a service, shape the response)
├── auth/            JWT issue/verify, current-user dependency
├── security/        password hashing, rate limiting, URL validation, security headers
├── schemas/         Pydantic request/response models
├── models/          MongoDB connection, collection names, index definitions
├── services/        business logic: users, projects, audit log, dashboard, analysis, jobs,
│                    vulnerabilities, sbom, reachability, intelligence; runs.py (run records),
│                    layers.py (one read of every layer), attack_paths, maintainers, behaviour,
│                    reasoning, datasets, trust/ (weights, normalization, engine, explanation,
│                    history), overview, report
├── collectors/      GitHub client (metadata, trees, blobs, commits, contributors, releases,
│                    commit diffs); providers/ — vulnerability sources (OSV);
│                    registries/ — package metadata (PyPI, npm)
├── workers/         background worker process
├── analyzers/       detection, dependency parsers, normalisation, resolution;
│                    vulnerabilities/ — version ordering, CVSS, range matching;
│                    source/, reachability/ — static source analysis and path search;
│                    graph/, fragility/ — graph metrics, fragility, propagation;
│                    attack_paths/ — nodes, edges, bounded search, score, simulation;
│                    maintainers/ — activity, contributors, indicators, profile;
│                    behavior/ — diff reading, rules, baseline, anomaly score;
│                    dataset/ — integrity, provenance, quality, duplicates, balance, validation
├── ai/              evidence store and validation, context, rules, confidence, prompts,
│                    provider interface with the deterministic provider and the output guard
├── evaluation/      metric functions, catalogue of measures, command-line runner
├── graph/           dependency graph construction and path queries
├── sbom/            CycloneDX generation, canonical form and digests, diff
├── data/            bundled reference data read by the analyzers
├── ml/              empty placeholder package: no model is trained
└── websocket/       empty placeholder package: no push channel is built
```

### Design rules

1. **Routers stay thin.** Routers validate input and call services; services
   own the logic and the database access. This keeps logic testable without HTTP.
2. **Dependencies are injected.** `create_app()` accepts the Mongo client,
   Redis client and outbound HTTP transport. Production builds them from
   settings; tests pass in-memory equivalents. There is no "test mode" branch
   inside production code.
3. **Deterministic first.** Discovery, parsing, graph construction, matching,
   hashing and every score are plain deterministic code. The AI layer only
   reasons over structured evidence that deterministic code produced
   (see §7).
4. **Evidence is immutable.** Original inputs (an SBOM found in a repo, a
   vulnerability record, a commit) are stored as received with source and
   timestamp. Derived artefacts are stored separately and reference the
   original; nothing overwrites evidence.
5. **Adapters for ecosystems.** Each language/package manager is an adapter
   implementing one interface, so new ecosystems do not touch the pipeline.

---

## 4. Module dependency map

Arrows read "depends on".

```text
auth, projects, health ──────────────► models (MongoDB), security, config
repository collector ────────────────► projects, security (URL validation)
dependency adapters ─────────────────► repository collector
dependency graph ────────────────────► dependency adapters
vulnerability intelligence ──────────► dependency adapters (PURLs, versions)
reachability ────────────────────────► vulnerability intelligence, repository collector (source)
SBOM engine ─────────────────────────► dependency adapters, dependency graph
fragility, graph risk, predictive ───► dependency graph, vulnerability intelligence, reachability, registries
attack-path simulation ──────────────► dependency graph, vulnerability intelligence, reachability, (fragility)
maintainer behaviour ────────────────► repository collector (commits, contributors, releases), (commit behaviour)
commit behaviour ────────────────────► repository collector (commit diffs), its own earlier results
layers ──────────────────────────────► stored results of every layer above (reads only)
cross-layer reasoning ───────────────► layers
dataset ─────────────────────────────► stored results of the snapshot-bound layers
trust engine ────────────────────────► layers
overview, report ────────────────────► layers, trust, reasoning
```

A dependency in brackets is optional: the layer runs without it and reports
the corresponding input as unknown. Shared infrastructure used by every
analysis module: the **analysis job system** (`analysis_jobs` + worker +
Redis queue), **run records** (`analysis_runs`) and the **audit log**.

---

## 5. Analysis pipeline

Analysis never runs inside an HTTP request. A job document is created and the
worker is woken through Redis; the worker advances the job and persists its
progress to MongoDB, which the frontend polls.

**Built (Phase 2)** — `POST /api/projects/{id}/analysis/dependencies`:

```text
queued → running [REPOSITORY_SNAPSHOT → REPOSITORY_DISCOVERY → DEPENDENCY_DISCOVERY
→ GRAPH_BUILDING] → completed | failed
```

Details are in [dependency-analysis.md](dependency-analysis.md).

**Built (Phase 3)** — three further job types on the same job system
(`services/jobs.py`), one job per project at a time:

```text
vulnerability_sync      PROVIDER_QUERY → RECORD_INGESTION → MATCHING
vulnerability_analysis  MATCHING                      (stored advisories only)
sbom_generation         SBOM_GENERATION → SBOM_COMPARISON
```

The worker builds the vulnerability providers from configuration and passes
them to the job handlers; nothing in a request or a repository can change
where they connect. SBOM verification and on-demand diffs run inside the
request. Details are in [phase3.md](phase3.md).

Phase 3 reports published advisories whose affected versions contain an
observed dependency version. It does not predict exploitability, simulate
attack paths or compute any risk or trust score.

**Built (Phase 4)** — one further job type:

```text
code_reachability_analysis  SOURCE_INVENTORY → SOURCE_PARSING → GRAPH_BUILDING
                            → SYMBOL_MAPPING → REACHABILITY
```

The worker fetches the snapshot's Python files by git blob id, parses them
with `ast` (nothing is executed), builds a conservative code graph, and for
every vulnerability match decides `REACHABLE`, `NOT_CONFIRMED_REACHABLE`,
`UNKNOWN` or `UNSUPPORTED`, with the path and source locations as evidence.
Static reachability is not exploitability. Details are in
[phase4.md](phase4.md).

**Built (Phase 5)** — three further job types that share one pipeline:

```text
dependency_fragility_analysis    GRAPH_METRICS → PACKAGE_METADATA → FRAGILITY
graph_risk_analysis              GRAPH_METRICS → RISK_PROPAGATION
predictive_dependency_analysis   GRAPH_METRICS → PACKAGE_METADATA → FRAGILITY
                                 → RISK_PROPAGATION → PREDICTION
```

The worker measures the stored dependency graph, reads release metadata from
the configured package registries (PyPI and npm; cached), and combines both
with the stored vulnerability matches and reachability findings into a
fragility score, an exposure classification with graph risk, indicators and a
predictive dependency risk per dependency. All of it is deterministic and
stored with its factors and model versions; each run is kept as history. A
job may end `partial` when registry metadata is incomplete. The analyzers in
`analyzers/graph` and `analyzers/fragility` are pure; `collectors/registries`
is the only new outbound connection. Details are in [phase5.md](phase5.md).

**Phases 6 to 13** use the same job system, one job type per layer:

| Job type | Stages | Reads | Writes |
|---|---|---|---|
| `attack_path_analysis` | load evidence → search → score → store | graph, matches, reachability findings, Phase 5 rows | `analysis_runs`, `attack_paths` |
| `maintainer_analysis` | collect history → measure → indicators → store | GitHub commits, contributors, releases; commit analyses | `analysis_runs`, `maintainer_profiles`, `maintainers` |
| `commit_behaviour_analysis` | list commits → read diffs → rules → baseline → score → store | GitHub commit list and details; earlier analyses | `analysis_runs`, `commits`, `commit_analysis`, `behaviour_events`, `security_events` |
| `ai_security_analysis` | gather context → rules → validate → explain → store | `layers.collect` | `analysis_runs`, `ai_findings` |
| `dataset_validation` | build records → hash → store version → read back → validate | stored results of the snapshot | `datasets`, `dataset_records`, `dataset_quality` |
| `trust_analysis` | collect layers → normalise → compute → explain → store | `layers.collect` | `trust_scores` |

There is no single pipeline job: each layer is started on its own, in any
order its prerequisites allow, and a later layer reports an earlier one that
has not run as unknown. One job runs per project at a time. A job that could
collect only part of its input ends `partial` and says what is missing.
Overview and report are computed on request from stored results. Progress is
polled; there is no WebSocket channel.

---

## 6. Security architecture

Every imported repository is **untrusted input**. The platform never runs
repository code on the host.

| Control | Where | Status |
|---|---|---|
| Password hashing — scrypt (N=2¹⁵, r=8, p=1), per-user random salt, constant-time compare | `security/passwords.py` | BUILT |
| JWT access tokens (HS256, expiry, `jti`), secret from env; production refuses to start with a missing or short secret | `auth/tokens.py`, `config/settings.py` | BUILT |
| Login does not reveal whether an email exists (same error, same work) | `services/users.py` | BUILT |
| Rate limiting on auth endpoints (sliding window, per client address) | `security/rate_limit.py` | BUILT (in-process; see limitations) |
| Input validation — strict Pydantic models, unknown fields rejected, body size cap | `schemas/`, `security/headers.py` | BUILT |
| Repository URL validation / SSRF protection — only `https://github.com/<owner>/<repo>`; no credentials, ports, queries, redirects | `security/url_validation.py`, `collectors/github.py` | BUILT |
| Per-user data isolation — every project query is scoped to the owner | `services/projects.py` | BUILT |
| CORS allow-list from configuration (never `*` with credentials) | `main.py` | BUILT |
| Security response headers | `security/headers.py` | BUILT |
| Audit log of security-relevant actions | `services/audit.py` | BUILT |
| Containers run as non-root, no privileged mode, dropped capabilities, read-only root filesystem for the API | `Dockerfile`, `docker-compose.yml` | BUILT |
| Repository acquisition without cloning or executing anything: GitHub API only, git-blob integrity check, size / count / time limits, rate-limit handling | `collectors/github.py`, `services/analysis.py` | BUILT |
| Path validation for repository-provided paths; no shell commands built from repository content; safe XML / YAML parsing | `collectors/github.py`, `analyzers/` | BUILT |
| Vulnerability provider access — endpoint from configuration only, `https`, host allow-list, no redirects, response size caps, validated ids, bounded retries | `config/settings.py`, `collectors/providers/osv.py` | BUILT |
| Rate limit on job starts and provider health checks | `security/rate_limit.py` | BUILT (in-process) |
| SBOM integrity — canonical form, SHA-256 digests, regeneration check. Integrity-verifiable, not signed | `sbom/canonical.py`, `services/sbom.py` | BUILT |
| Source analysis without execution — files fetched by validated blob id, parsed with `ast`; bounded files, bytes, syntax nodes, lookups, edges and run time | `analyzers/source/`, `analyzers/reachability/`, `services/reachability.py` | BUILT |
| GitHub API host allow-list; outbound hosts must be public names, never addresses or internal names; placeholder token never sent | `config/settings.py` | BUILT (Phase 13) |
| Commit diffs analysed as text; secret-like values masked before storage | `analyzers/behavior/` | BUILT |
| Findings and report statements refused unless every statement cites stored evidence | `ai/evidence.py`, `services/report.py` | BUILT |
| Dataset records write-once with SHA-256 record, dataset and chain hashes | `analyzers/dataset/integrity.py` | BUILT (verifiable, not signed) |
| Reproducible frontend build from a committed lockfile with integrity hashes | `frontend/Dockerfile`, `package-lock.json` | BUILT |
| Sandboxed execution of repository code | — | Not needed: no phase executes repository code |

Full control list: [security.md](security.md).

### Known limitations today

- The rate limiter keeps its counters in process memory. With more than one
  backend process each process counts separately. Moving the counters to
  Redis is not built.
- Tokens are stateless; there is no server-side revocation list yet. Tokens
  are short-lived (60 minutes by default) to bound this.
- The frontend stores the token in `sessionStorage`. That limits lifetime to
  the tab but does not protect against XSS; a strict CSP is served to reduce
  that risk.

---

## 7. AI boundary (BUILT, Phase 9)

| Deterministic code | Reasoning layer |
|---|---|
| dependency discovery, SBOM generation, graph construction, vulnerability matching, reachability, every score, hashing, duplicate detection | cross-layer correlation, explanation, recommendations |

The reasoning layer that ships is itself deterministic: a fixed set of rules
over an evidence store in which every item has a stable id and points at a
stored record. A finding's statements cite evidence ids; a validator refuses
any finding with an uncited statement, a citation that does not resolve, or
an `OBSERVED` statement resting on evidence that is not observed. Statements
are labelled `OBSERVED`, `DERIVED`, `PREDICTED` or `RECOMMENDED`.

A provider interface exists so that a language model could phrase
explanations. It would receive only one finding's statements and cited
evidence, and its output would be kept only if a guard accepts it (every
sentence cited, citations within the finding, no claim the platform never
makes). **No language-model provider is implemented**; `AI_PROVIDER` accepts
`deterministic` only. Details: [phase9.md](phase9.md).

---

## 8. Scientific constraints

The platform **estimates, ranks, simulates and flags indicators**. It does not
claim to detect or predict zero-days, to decide exploitability, to confirm
that an attack path would succeed, to identify a malicious maintainer, to
predict future CVEs, or to certify a dataset as free of poisoning.

Every model is a deterministic, documented formula with a version string:
`attack-path-v1`, `maintainer-behaviour-v1`, `commit-behaviour-v1`,
`cross-layer-reasoning-v1`, `dataset-quality-v1`, `trust-v1`, and the Phase 5
models. Nothing is trained. The trust weights are expert-defined initial
weights and are not statistically trained. No component has been evaluated
for accuracy; measures without a benchmark are reported as NOT EVALUATED.
See [research-validation.md](research-validation.md).

---

## 9. Technical dependencies and risks

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | GitHub API rate limits (60 req/h unauthenticated) | Collection stalls | Optional `GITHUB_TOKEN`; conditional requests; cache per snapshot; back-off |
| R2 | Hostile or huge repositories | Resource exhaustion, code execution | Built: no clone; files, commits and diffs fetched as data through the GitHub API with size, count and time limits; nothing from a repository is executed |
| R3 | Resolving transitive dependencies without running package managers | Incomplete graphs | Prefer lockfiles; otherwise resolve via registry metadata APIs and mark the result `resolution: estimated` |
| R4 | Vulnerability sources disagree | Wrong matches | One source (OSV) is built, behind a provider interface; source, timestamp and raw record are kept per advisory, and a disagreement between the provider's report and the local range evaluation is stored as `CONFLICT`. Further sources: planned |
| R5 | Static reachability is undecidable in general | False confidence | Built: four statuses (`REACHABLE` / `NOT_CONFIRMED_REACHABLE` / `UNKNOWN` / `UNSUPPORTED`), no "not reachable" or "safe" result, unresolved uses recorded, confidence tied to how each edge was bound. Precision not yet measured against a benchmark |
| R10 | Advisories rarely publish affected functions (none of 11,584 PyPI entries examined did) | Most real Python findings are `UNKNOWN` | Operator mapping file with required source URL; dependency-usage evidence shown for every finding; no symbol is inferred from advisory text |
| R6 | No labelled ground truth for "risky dependency" or "anomalous commit" | Unevaluable models | Built: transparent scoring, metric functions and an evaluation catalogue. Labelled sets and baselines: not built; every accuracy measure is NOT EVALUATED |
| R7 | A reasoning provider inventing evidence | Unsupported claims | Built: evidence-id validation of every finding and a guard for provider output. No language model is integrated, so no hallucination rate exists to report; the guard does not yet check sentence content against the cited evidence |
| R8 | Trust-score weights are judgement calls | Arbitrary scores | Built: weights published with the statement that they are not statistically trained; component risks, contributions, coverage and bounds always shown; no score below a coverage minimum. Sensitivity analysis: not done |
| R9 | Multi-language scope (9 languages) | Shallow coverage | Adapter interface; lockfile-first; state per-ecosystem support level in docs |
| R10 | Secrets in configuration | Credential leak | Env-only secrets, `.env` git-ignored, `.env.example` has placeholders only |

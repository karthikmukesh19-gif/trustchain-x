# TrustChain-X — Architecture

**Predictive and Self-Verifying Software Supply Chain Security Platform**

TrustChain-X answers one question about a repository: *can this software and
its complete supply chain be trusted?* It does that by collecting evidence
from several layers (dependencies, SBOM, vulnerabilities, reachability,
maintainer and commit behaviour), correlating it, and producing an explainable
**Software Supply Chain Trust Score (0–100)**.

This document describes the target architecture and marks what exists today.
Status legend: **BUILT** (implemented and tested), **PLANNED** (designed, not
implemented). Nothing marked PLANNED has code behind it yet.

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
                │ React Frontend  │   BUILT (Phase 1 pages)
                └────────┬────────┘
                         │ REST / WebSocket
                         ▼
                ┌─────────────────┐
                │ FastAPI Backend │   BUILT (auth, projects, analysis, health)
                └────────┬────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
 Repository        Dependency         SBOM Engine         BUILT, BUILT, BUILT (generate,
 Collector         Analyzer           & Verifier          verify, diff; repair: planned)
        └────────────────┼────────────────┘
                         ▼
                Dependency Graph                          BUILT (prediction: Phase 6)
                         │
        ┌────────────────┼──────────────────┐
        ▼                ▼                  ▼
 Vulnerability      Reachability      Attack Path         BUILT (known-advisory matching),
 Analysis           Analysis          Simulation          BUILT (static, Python), PLANNED (Phase 7)
        └────────────────┼──────────────────┘
                         ▼
              Behaviour Intelligence                      PLANNED (Phases 8, 9)
             ┌───────────┴───────────┐
             ▼                       ▼
     Maintainer Behaviour      Commit Behaviour
             └───────────┬───────────┘
                         ▼
                Predictive Engine                         PLANNED (Phases 5, 6)
                         ▼
              Cross-Layer AI Engine                       PLANNED (Phase 10)
                         ▼
                Trust Score Engine                        PLANNED (Phase 12)
                         ▼
               Security Report                            PLANNED (Phase 13)
```

### Runtime services (Docker Compose)

| Service | Role | Status |
|---|---|---|
| `frontend` | Nginx serving the built React app; proxies `/api` and `/ws` to the backend | BUILT |
| `backend` | FastAPI application (Uvicorn) | BUILT |
| `mongodb` | System of record | BUILT |
| `redis` | Worker heartbeat and analysis job wake-ups | BUILT |
| `worker` | Background process: runs dependency-analysis jobs and publishes a heartbeat | BUILT |

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
├── services/        business logic (users, projects, audit log, dashboard, analysis, jobs,
│                    vulnerabilities, sbom)
├── collectors/      clients for external sources (GitHub metadata, commits, trees, blobs);
│                    providers/ — vulnerability sources behind one interface (OSV)
├── workers/         background worker process
├── analyzers/       language / package-manager detection, dependency parsers,
│                    normalisation, resolution; vulnerabilities/ — version ordering, CVSS,
│                    affected-range matching; source/ — source inventory and per-language
│                    static analyzers (Python); reachability/ — import mapping, code graph,
│                    advisory symbol mapping, path search (fragility: PLANNED)
├── graph/           dependency graph construction and path queries (propagation, attack paths: PLANNED)
├── sbom/            CycloneDX generation, canonical form and digests, diff
│                    (parsing found SBOMs, reconstruction: PLANNED, Phase 4)
├── ml/              PLANNED — models, features, evaluation
└── websocket/       PLANNED — live progress and security events
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

Arrows read "depends on". A module may only be built once everything it
points to exists — this ordering is what the roadmap follows.

```text
auth, projects, health ──────────────► models (MongoDB), security, config
repository collector ────────────────► projects, security (URL validation, sandboxed clone)
dependency adapters ─────────────────► repository collector
dependency graph ────────────────────► dependency adapters
vulnerability intelligence ──────────► dependency adapters (PURLs, versions)
reachability ────────────────────────► vulnerability intelligence, repository collector (source)
SBOM engine ─────────────────────────► dependency adapters, dependency graph
dependency fragility ────────────────► dependency graph, vulnerability intelligence, registry + repo metadata
predictive graph ────────────────────► dependency graph, fragility, vulnerability intelligence
attack-path simulation ──────────────► dependency graph, vulnerability intelligence, reachability
behaviour intelligence ──────────────► repository collector (commits, contributors, releases)
real-time monitoring ────────────────► behaviour intelligence, dependency adapters, websocket
cross-layer AI ──────────────────────► every evidence producer above
dataset trust ───────────────────────► models only (independent pipeline)
trust score engine ──────────────────► all component scores + dataset trust
reporting ───────────────────────────► trust score engine, cross-layer AI
```

Shared infrastructure used by every analysis module: the **analysis job
system** (`analysis_jobs` + worker + Redis queue) and the **audit log**.

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

**Target (later phases)** — the full pipeline extends the same job system
with these stages, and pushes transitions over `/ws/projects/{project_id}`
from Phase 9:

```text
QUEUED → CLONING → REPOSITORY_DISCOVERY → DEPENDENCY_DISCOVERY → SBOM_ANALYSIS
→ GRAPH_BUILDING → VULNERABILITY_ANALYSIS → REACHABILITY_ANALYSIS
→ BEHAVIOUR_ANALYSIS → PREDICTION → AI_REASONING → TRUST_SCORE
→ REPORT_GENERATION → COMPLETED        (any stage may end in FAILED)
```

Each stage writes its own collection(s) keyed by `project_id` and
`snapshot_id`, so a stage can be re-run and a failed job can resume.

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
| Sandboxed execution of repository code | — | Not needed so far: no phase executes repository code. Required before any that does |
| WebSocket authentication | `websocket/` | PLANNED (Phase 9) |

Full control list: [security.md](security.md).

### Known limitations today

- The rate limiter keeps its counters in process memory. With more than one
  backend process each process counts separately. Moving the counters to
  Redis is scheduled for Phase 14.
- Tokens are stateless; there is no server-side revocation list yet. Tokens
  are short-lived (60 minutes by default) to bound this.
- The frontend stores the token in `sessionStorage`. That limits lifetime to
  the tab but does not protect against XSS; a strict CSP is served to reduce
  that risk.

---

## 7. AI boundary (PLANNED, Phase 10)

| Deterministic code | AI |
|---|---|
| dependency discovery, SBOM parsing, graph construction, vulnerability matching, score calculation, hashing, duplicate detection | cross-layer reasoning, explanation, evidence correlation, summarisation, remediation recommendations |

The AI receives a structured evidence bundle in which every item has a stable
id. It must return structured findings whose `evidence` entries are ids from
that bundle. A validator rejects any finding that cites an id that was not
supplied, so the model cannot introduce evidence. Each statement is labelled
`OBSERVED`, `PREDICTED`, `INFERRED` or `RECOMMENDED`.

---

## 8. Scientific constraints

The platform **estimates, ranks, simulates and flags indicators**. It does not
claim to detect all zero-days, to know whether a maintainer is malicious, to
guarantee future CVE prediction, to guarantee attack success, or to certify a
dataset as free of poisoning. Every model ships with documented features,
training process, baseline, metrics and limitations (`docs/ml.md`, Phase 5+).

---

## 9. Technical dependencies and risks

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | GitHub API rate limits (60 req/h unauthenticated) | Collection stalls | Optional `GITHUB_TOKEN`; conditional requests; cache per snapshot; back-off |
| R2 | Cloning hostile or huge repositories | Resource exhaustion, code execution | Shallow clone in a sandbox container, size and time limits, never execute repo code |
| R3 | Resolving transitive dependencies without running package managers | Incomplete graphs | Prefer lockfiles; otherwise resolve via registry metadata APIs and mark the result `resolution: estimated` |
| R4 | Vulnerability sources disagree | Wrong matches | One source (OSV) is built, behind a provider interface; source, timestamp and raw record are kept per advisory, and a disagreement between the provider's report and the local range evaluation is stored as `CONFLICT`. Further sources: planned |
| R5 | Static reachability is undecidable in general | False confidence | Built: four statuses (`REACHABLE` / `NOT_CONFIRMED_REACHABLE` / `UNKNOWN` / `UNSUPPORTED`), no "not reachable" or "safe" result, unresolved uses recorded, confidence tied to how each edge was bound. Precision not yet measured against a benchmark |
| R10 | Advisories rarely publish affected functions (none of 11,584 PyPI entries examined did) | Most real Python findings are `UNKNOWN` | Operator mapping file with required source URL; dependency-usage evidence shown for every finding; no symbol is inferred from advisory text |
| R6 | No labelled ground truth for "risky dependency" or "anomalous maintainer" | Unevaluable models | Start with transparent scoring; build labelled sets from historical advisories and known incidents; report baselines and limits |
| R7 | LLM hallucination | Invented evidence | Evidence-id grounding validator; measure hallucination rate |
| R8 | Trust-score weights are judgement calls | Arbitrary scores | Weights configurable and published; component scores always shown; controlled experiments in evaluation |
| R9 | Multi-language scope (9 languages) | Shallow coverage | Adapter interface; lockfile-first; state per-ecosystem support level in docs |
| R10 | Secrets in configuration | Credential leak | Env-only secrets, `.env` git-ignored, `.env.example` has placeholders only |

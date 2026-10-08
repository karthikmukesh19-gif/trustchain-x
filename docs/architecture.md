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
                │ FastAPI Backend │   BUILT (auth, projects, health, dashboard)
                └────────┬────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
 Repository        Dependency         SBOM Engine         PLANNED
 Collector         Analyzer           & Verifier          (Phases 2, 4)
        └────────────────┼────────────────┘
                         ▼
                Dependency Graph                          PLANNED (Phases 2, 6)
                         │
        ┌────────────────┼──────────────────┐
        ▼                ▼                  ▼
 Vulnerability      Reachability      Attack Path         PLANNED
 Analysis           Analysis          Simulation          (Phases 3, 7)
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
| `redis` | Worker heartbeat now; analysis job queue from Phase 2 | BUILT |
| `worker` | Background process. Publishes a heartbeat today; runs the analysis pipeline from Phase 2 | BUILT (heartbeat only) |

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
├── services/        business logic (users, projects, audit log, dashboard)
├── collectors/      clients for external sources (GitHub metadata today)
├── workers/         background worker process
├── analyzers/       PLANNED — dependency, vulnerability, reachability, fragility
├── graph/           PLANNED — dependency graph, propagation, attack paths
├── sbom/            PLANNED — SBOM parse / verify / reconstruct
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

## 5. Analysis pipeline (PLANNED, Phase 2 onward)

Analysis never runs inside an HTTP request. `POST /api/projects/{id}/analyze`
creates a job document and enqueues its id; the worker advances the job
through these states, persisting progress to MongoDB and publishing each
transition to `/ws/projects/{project_id}`:

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
| Sandboxed clone and analysis (no network after clone, CPU/memory/time limits, size limits) | `collectors/`, `workers/` | PLANNED (Phase 2) |
| Command-injection and path-traversal protection for repository handling | `collectors/` | PLANNED (Phase 2) |
| WebSocket authentication | `websocket/` | PLANNED (Phase 9) |

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
| R4 | Vulnerability sources disagree | Wrong matches | Ingest more than one source (OSV, NVD, GitHub Advisories), keep source + timestamp per record, surface conflicts |
| R5 | Static reachability is undecidable in general | False confidence | Three-way result (`REACHABLE` / `NOT_REACHABLE` / `UNKNOWN`), per-language precision documented |
| R6 | No labelled ground truth for "risky dependency" or "anomalous maintainer" | Unevaluable models | Start with transparent scoring; build labelled sets from historical advisories and known incidents; report baselines and limits |
| R7 | LLM hallucination | Invented evidence | Evidence-id grounding validator; measure hallucination rate |
| R8 | Trust-score weights are judgement calls | Arbitrary scores | Weights configurable and published; component scores always shown; controlled experiments in evaluation |
| R9 | Multi-language scope (9 languages) | Shallow coverage | Adapter interface; lockfile-first; state per-ecosystem support level in docs |
| R10 | Secrets in configuration | Credential leak | Env-only secrets, `.env` git-ignored, `.env.example` has placeholders only |

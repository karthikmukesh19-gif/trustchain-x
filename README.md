# TrustChain-X

**Predictive and Self-Verifying Software Supply Chain Security Platform**

TrustChain-X asks *"how far can this software and its supply chain be
trusted, and on what evidence?"* It reads a GitHub repository as data,
analyses it in eleven layers, and combines them into an explainable
**trust score (0–100)** with its confidence, its coverage and the evidence
behind every statement.

Three rules hold everywhere:

- **Static analysis only.** Nothing from a repository is cloned, installed,
  built or executed. No exploit is attempted.
- **Every value says how it is known:** `OBSERVED`, `DERIVED`, `INFERRED`,
  `PREDICTED` or `RECOMMENDED`.
- **Unknown is never shown as safe.** A layer without results has no
  figures. When too little is known, the score reads **INSUFFICIENT DATA**.

## Project overview

| Phase | Layer | What it produces |
|---|---|---|
| 1 | Foundation | accounts, projects, GitHub repository registration, job system, worker |
| 2 | Dependency intelligence | immutable snapshot, dependency inventory and graph for Python, JavaScript/TypeScript, Java, Go, Rust, C/C++ |
| 3 | Vulnerability intelligence and SBOM | advisory matches from [OSV](https://osv.dev); CycloneDX 1.5 SBOM with SHA-256 digests, verification, history, diff |
| 4 | Code reachability | static call graph for Python; each vulnerability *Reachable*, *Not confirmed*, *Unknown* or *Unsupported* |
| 5 | Dependency fragility | graph metrics, release position from PyPI and npm, fragility, graph risk, predictive dependency risk |
| 6 | Attack-path simulation | evidence-carrying paths from the project to a matched vulnerability, scored; never "exploit confirmed" |
| 7 | Maintainer behaviour | repository-level behavioural indicators from public metadata; never a judgement about a person |
| 8 | Commit behaviour | diffs analysed as text; indicators, security events, anomaly score against the repository's own baseline |
| 9 | Cross-layer reasoning | rule-based findings in which every statement cites stored evidence |
| 10 | Self-validating dataset | versioned, hash-chained records of the results with a quality score |
| 11 | Trust engine | risk and trust score with component contributions, bounds, confidence and explanation |
| 12 | Dashboards and report | executive, technical and research dashboards; a 17-section evidence-backed report |
| 13 | Hardening and validation | security audit, evaluation support, research validation |

All thirteen phases are implemented. What has and has not been verified is
stated under [Testing](#testing).

## Architecture

```text
browser ── React + Vite + TypeScript + Tailwind (Recharts, React Flow)
              │  /api (JWT)
          FastAPI backend ──────────── MongoDB (42 collections)
              │  jobs                      │
            Redis ──── background worker ──┘
                           │  https, allow-listed hosts only, no redirects
          GitHub API · OSV · PyPI · npm registry
```

The API validates, authorises and queues; the worker runs one analysis job
per project at a time and stores results; every page reads stored results.
`services/layers.py` gives one consistent read of every layer's state to the
reasoning engine, the trust engine, the dashboards and the report.

More: [docs/architecture.md](docs/architecture.md).

## Setup

Requires Docker Desktop (or Docker Engine with Compose v2).

### Docker startup

```bash
docker compose up --build
```

- Application: <http://localhost:5173>
- API documentation: <http://localhost:8000/docs> (development mode only)
- Readiness: <http://localhost:8000/api/health/ready>

Five services start: `mongodb`, `redis`, `backend`, `worker`, `frontend`. The
databases are not published to the host; the API and the application are
bound to `127.0.0.1`.

Register an account, add a project with a `https://github.com/<owner>/<repo>`
URL, and run the analyses from the project overview in the order listed
there. Then open **Trust** and **Report**.

### Environment configuration

Everything works without configuration in development mode. For anything
else, copy `.env.example` to `.env` and set at least:

| Variable | Purpose |
|---|---|
| `APP_ENV` | `production` disables the API docs and requires the settings below |
| `JWT_SECRET` | at least 32 characters; the example file shows how to generate one |
| `MONGO_ROOT_USERNAME`, `MONGO_ROOT_PASSWORD` | database credentials |
| `GITHUB_TOKEN` | optional; raises the GitHub rate limit from 60 to 5 000 requests an hour. Use a token limited to public repositories |

**Never commit `.env`.** It is ignored by git. The example files contain
placeholders only (`GITHUB_TOKEN=your_github_token_here`); a placeholder is
treated as "no token". If a real token was ever written into a tracked or
shared file, revoke it and create a new one.

Other settings, all optional and documented in `.env.example`:

| Group | Variables |
|---|---|
| Outbound hosts | `GITHUB_ALLOWED_HOSTS`, `VULNERABILITY_ALLOWED_HOSTS`, `PACKAGE_METADATA_ALLOWED_HOSTS` and the matching `*_URL` settings. An invalid value stops start-up |
| Providers | `VULNERABILITY_PROVIDERS`, `PACKAGE_METADATA_PROVIDERS` (empty: no registry requests), `AI_PROVIDER` (`deterministic` only) |
| Limits | `ANALYSIS_*`, `REACHABILITY_*`, `INTELLIGENCE_*`, `ATTACK_PATH_*`, `MAINTAINER_*`, `COMMIT_*`, `DATASET_MAX_RECORDS` |
| Monitoring | `COMMIT_POLL_INTERVAL_MINUTES` (0: no automatic commit polling) |
| Trust | `TRUST_MIN_COVERAGE` (default 0.6): share of the model's weight that must be known before a score is given |
| Rate limits | `AUTH_RATE_LIMIT`, `JOB_RATE_LIMIT` |

### Without Docker

```bash
# backend (needs MongoDB on :27017 and Redis on :6379)
cd backend
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn app.main:app_factory --factory --reload
python -m app.workers.worker                      # in a second terminal

# frontend
cd frontend
npm ci
npm run dev                                       # http://localhost:5173, proxies /api to :8000
```

## Testing

Backend — no services or network needed; MongoDB, Redis, GitHub, OSV and the
registries are replaced by in-memory stand-ins:

```bash
docker run --rm -v "${PWD}/backend:/srv" -w /srv python:3.12-slim \
  sh -c "pip install -q -r requirements-dev.txt && pytest --cov=app"
```

Frontend — the built application in a real browser, with `/api` answered by
the tests from responses recorded from the real backend:

```bash
cd frontend
npm ci
npm run build
npm run test:install     # once: downloads Chromium for Playwright
npm test
```

End to end on a real repository without network access to the services (see
[docs/phase13.md](docs/phase13.md), section 5):

```bash
cd backend && python -m tests.real_repository_run --clone /path/to/clone --owner OWNER --name REPO
```

### Verification status

Phases 1 to 4 were validated in Docker by the project owner. Phases 5 to 13
were developed in a sandbox with no Docker daemon and no access to Docker
Hub, PyPI, the npm registry, `api.github.com` or `api.osv.dev`.

| Check | Result |
|---|---|
| Backend test suite | **1,991 passed, 0 failed**; 96 % line + branch coverage (Python 3.13, mongomock 4.3.0) |
| Frontend browser tests (Playwright, Chromium) | **158 passed, 0 failed**, against an esbuild bundle of the project source |
| TypeScript | no errors in project source |
| `docker compose config` | valid |
| Full pipeline on `karthikmukesh19-gif/ShadowWatch` (real files, commits, diffs and advisory records; GitHub and OSV endpoints served by local stand-ins; registries unreachable) | completed; three layers partial and reported as such |
| Security audit | 7 findings, all addressed ([docs/phase13.md](docs/phase13.md)) |
| `docker compose build` / `up`, container health | **NOT RUN** |
| `npm ci`, `npm run build` (Vite) | **NOT RUN** |
| Requests to the live GitHub API, OSV, PyPI, npm | **NOT RUN** for Phases 5–13 |
| Accuracy of any component (precision, recall, calibration) | **NOT EVALUATED** |

Before relying on the platform, run the three command blocks above on a
machine with Docker and confirm `docker compose ps` shows the backend and
frontend healthy.

## API

Base path `/api`; JSON; `Authorization: Bearer <token>` on everything except
health, register and login. A project that belongs to another user answers
404. Every analysis is started with a `POST` that returns 202 and a job; the
results are read with `GET`.

| Area | Endpoints under `/api/projects/{id}` |
|---|---|
| Dependencies | `analysis/dependencies`, `analysis/status`, `snapshot`, `dependencies`, `dependencies/graph` |
| Vulnerabilities, SBOM | `vulnerabilities/sync`, `vulnerabilities`, `sbom/generate`, `sbom`, `sbom/{id}/verify` |
| Reachability | `code-reachability/analyze`, `code-reachability` |
| Dependency intelligence | `predictive-risk/analyze`, `fragility`, `graph-risk`, `predictive-risk` |
| Attack paths | `attack-paths/analyze`, `attack-paths`, `attack-paths/graph`, `attack-paths/{path_id}` |
| Maintainers | `maintainers/analyze`, `maintainers`, `maintainers/{maintainer_id}` |
| Commits | `commits/analyze`, `commits/monitoring`, `commits`, `commits/{sha}`, `security-events`, `behaviour-events` |
| Reasoning | `ai-analysis`, `ai-analysis/{finding_id}` |
| Dataset | `datasets/validate`, `datasets`, `datasets/{dataset_id}`, `datasets/{dataset_id}/quality` |
| Trust | `trust/analyze`, `trust`, `trust/history`, `trust/compare`, `trust/explanation` |
| Overview, report | `overview`, `report?format=json|markdown` |

Full reference: [docs/api.md](docs/api.md).

## Research contributions

| # | Contribution | Phase |
|---|---|---|
| 1 | Predictive Dependency Fragility | 5 |
| 2 | Predictive Graph Reasoning | 5 |
| 3 | Attack-Path Simulation | 6 |
| 4 | Maintainer Behaviour Fingerprinting | 7 |
| 5 | Real-Time Security Behaviour Model | 8 |
| 6 | Cross-Layer AI Security Reasoning | 9 |
| 7 | Self-Validating Security Dataset | 10 |
| 8 | Integrated Software Trust Model | 11 |

These are contributions of this project: what was built and can now be
studied. No claim of novelty is made, no literature survey was carried out,
and no component has been evaluated for accuracy. The research problem,
algorithms, metrics, evaluation methodology, baselines, limitations and
threats to validity are in
[docs/research-validation.md](docs/research-validation.md).

## Limitations

- The analysis is static. It says nothing about run-time behaviour,
  deployment, or whether a weakness can actually be exploited.
- Only published vulnerabilities from one source (OSV) are matched. Unknown
  vulnerabilities are not detected or predicted.
- Reachability is implemented for Python only; other languages are reported
  as unsupported and counted as undecided.
- Maintainer and commit indicators are patterns in public data. They are not
  evidence of intent and never classify a person.
- The cross-layer reasoning engine is a deterministic rule set. No language
  model is integrated.
- Dataset validation detects damage, gaps, duplicates and contradictions. It
  cannot show that data is free of deliberate manipulation.
- **These weights are expert-defined initial weights and are not statistically
  trained.** The trust score is a transparent summary, not a calibrated
  probability.
- "Real time" means polling at a configurable interval; there are no
  webhooks and no push channel.
- Not built: self-healing SBOM (reconstruction), candidate-version
  comparison, PDF export, SBOM signing, a language-model provider.

## Security model

- **Untrusted input.** Every repository, advisory, registry answer and diff
  is treated as hostile data: size-capped, type-checked, length-limited,
  parsed with safe parsers, never executed.
- **Outbound requests** go only to four configured `https` hosts that must
  be on an allow-list and must be public names; redirects are not followed;
  no user input, repository content or advisory can supply a URL that is
  fetched.
- **Isolation.** Every query is scoped to the owning user; all routes
  require authentication except health, register and login.
- **Secrets.** None in git or in the frontend; the GitHub token is sent only
  to the configured API host and never logged; secret-like values found in
  commits are masked before they are stored.
- **Containers.** Non-root, `no-new-privileges`, capabilities dropped,
  read-only root filesystem for API and worker, databases not published.
- **Known gaps** are listed in [docs/security.md](docs/security.md).

## Layout

```text
backend/      FastAPI application, worker and tests
frontend/     React + Vite + TypeScript + Tailwind application and browser tests
docs/         architecture, database, API, security, roadmap, phase notes, research validation
datasets/     reserved; dataset versions are stored in MongoDB
reports/      reserved; reports are generated on request
scripts/      maintenance scripts (none yet)
```

## Documentation

- [Architecture](docs/architecture.md) · [Database](docs/database.md) · [API](docs/api.md) · [Security](docs/security.md) · [Roadmap](docs/roadmap.md)
- [Research validation](docs/research-validation.md)
- Phase notes: [dependency analysis](docs/dependency-analysis.md) ·
  [3 vulnerabilities and SBOM](docs/phase3.md) · [4 reachability](docs/phase4.md) ·
  [5 dependency intelligence](docs/phase5.md) · [6 attack paths](docs/phase6.md) ·
  [7 maintainers](docs/phase7.md) · [8 commits](docs/phase8.md) ·
  [9 reasoning](docs/phase9.md) · [10 dataset](docs/phase10.md) ·
  [11 trust](docs/phase11.md) · [12 dashboards and report](docs/phase12.md) ·
  [13 hardening and validation](docs/phase13.md)

## Claims this project does not make

TrustChain-X estimates, ranks, simulates and flags indicators. It does not
claim to detect or predict zero-day or unknown vulnerabilities, to prove that
a dependency is safe or that an SBOM is complete, to build a complete call
graph, to decide exploitability, to confirm that an attack path would
succeed, to identify a malicious maintainer, to predict future CVEs, or to
certify a dataset as free of poisoning. Its scores are explainable summaries
of stored evidence; none has been shown to predict incidents.

## Licence

MIT — see [LICENSE](LICENSE).

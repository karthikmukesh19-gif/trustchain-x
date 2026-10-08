# TrustChain-X

**Predictive and Self-Verifying Software Supply Chain Security Platform**

TrustChain-X is being built to answer *"can this software and its complete
supply chain be trusted?"* by correlating evidence from dependencies, SBOMs,
vulnerabilities, reachability, and maintainer and commit behaviour into an
explainable **Software Supply Chain Trust Score (0–100)**.

## Current state

The project is built in phases (see [docs/roadmap.md](docs/roadmap.md)).

| | |
|---|---|
| **Phase 0 — architecture** | Done |
| **Phase 1 — foundation** | Done, validated in Docker |
| **Phase 2 — repository and dependency intelligence** | Code complete; see *Verification status* below |
| Phases 3–14 — vulnerabilities, SBOM, behaviour, AI, scoring, reporting | Not started |

What works today:

- Accounts, projects and GitHub repository registration.
- **Dependency analysis** of a registered repository, run by the background
  worker: an immutable snapshot of the repository at its head commit,
  language and package-manager detection, dependency extraction for Python,
  JavaScript/TypeScript, Java, Go, Rust and C/C++, a normalised inventory with
  evidence for every entry, direct/transitive classification, and a
  dependency graph. Nothing from the repository is executed.
- Every result is labelled **OBSERVED** (read from a repository file),
  **INFERRED** (derived by a stated rule) or **UNKNOWN** (the files do not
  establish it). Versions that the files do not determine are shown as
  unresolved, never guessed.

What does **not** exist yet: vulnerability analysis, reachability, SBOM
verification, fragility, attack paths, behaviour analysis, AI reasoning,
dataset validation, and the trust score. No vulnerability, risk or trust
figures are produced or displayed.

## Run it

Requires Docker Desktop (or Docker Engine with Compose v2).

```bash
docker compose up --build
```

- App: <http://localhost:5173>
- API docs: <http://localhost:8000/docs> (development mode only)
- Health: <http://localhost:8000/api/health/ready>

This works without any configuration, in development mode. For anything
beyond local use, copy `.env.example` to `.env` and set `APP_ENV=production`,
a `JWT_SECRET` (the file shows how to generate one) and MongoDB credentials.
Never commit `.env`.

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
npm install
npm run dev                                       # http://localhost:5173, proxies /api to :8000
```

## Tests

Backend (no services or network needed — MongoDB, Redis and the GitHub API
are replaced by in-memory stand-ins):

```bash
docker run --rm -v "${PWD}/backend:/srv" -w /srv python:3.12-slim \
  sh -c "pip install -q -r requirements-dev.txt && pytest --cov=app"
```

Frontend (the built application in a real browser, with every `/api` call
answered by the tests):

```bash
cd frontend
npm install
npm run test:install     # once: downloads Chromium for Playwright
npm test
```

## Verification status

Phase 1 was validated in Docker by the project owner (all five services,
registration, project creation, real GitHub metadata).

Phase 2 was developed in a sandbox that cannot reach PyPI, the npm registry,
Docker Hub or the GitHub API. This is exactly what was and was not executed:

| Check | Result |
|---|---|
| Backend test suite (426 tests) | **Passed**, 92 % line+branch coverage. Python 3.13, dependencies taken from their GitHub sources |
| Whole pipeline on the real dependency files of `karthikmukesh19-gif/ShadowWatch` (commit `4c8057c`), served through a simulated GitHub API | **Passed** — 320 dependencies (51 direct, 269 transitive), 459 edges, depth 6 |
| Live run: Uvicorn API + worker process + real Redis + browser, same ShadowWatch content | **Passed** (MongoDB replaced by mongomock) |
| Frontend browser tests (27, Playwright + Chromium) | **Passed** against a bundle built with esbuild from the project source and React Flow's source |
| Frontend TypeScript check | **Passed** for all project source |
| `docker compose config` | **Valid** |
| `docker compose up --build` with the Phase 2 code | **Not run** |
| `npm install` / `npm run build` with `@xyflow/react` and `@playwright/test` from npm | **Not run** — versions in `package.json` unverified |
| Analysis through the real GitHub API | **Not run** (API unreachable from the sandbox) |
| Index migration on an existing Phase 1 MongoDB | **Not run** against a real server (tested on mongomock) |

**Before starting Phase 3**, run these and confirm they succeed:

```bash
docker compose up --build
# then in the app: open the ShadowWatch project → "Run dependency analysis"
# → check the Overview, Dependencies and Dependency graph tabs

docker run --rm -v "${PWD}/backend:/srv" -w /srv python:3.12-slim sh -c "pip install -q -r requirements-dev.txt && pytest --cov=app"
cd frontend && npm install && npm run test:install && npm test
```

Expected for ShadowWatch at commit `4c8057c`: 320 dependencies, 51 direct,
269 transitive, 0 unresolved, ecosystems npm (293) and PyPI (27), languages
JavaScript and Python. A newer commit may differ.

Unauthenticated GitHub access allows 60 API requests an hour (an analysis of
ShadowWatch uses 9). Set `GITHUB_TOKEN` in `.env` for regular use.

## Layout

```text
backend/      FastAPI application, worker and tests
frontend/     React + Vite + TypeScript + Tailwind application
docs/         architecture, database, API, roadmap
datasets/     dataset registry storage (Phase 11)
reports/      generated reports (Phase 13)
scripts/      maintenance scripts (none yet)
```

## Documentation

- [Architecture](docs/architecture.md) — components, module dependency map, security controls, risks
- [Dependency analysis](docs/dependency-analysis.md) — pipeline, supported files, classification rules, limits, limitations
- [Security](docs/security.md) — controls for the platform and for analysing untrusted repositories
- [Database](docs/database.md) — all 29 collections, indexes, and which phase writes each
- [API](docs/api.md) — implemented and planned endpoints
- [Roadmap](docs/roadmap.md) — phases and exit criteria

## Claims this project does not make

TrustChain-X estimates, ranks, simulates and flags indicators. It does not
claim to detect all zero-days, to know whether a maintainer is malicious, to
guarantee future CVE prediction or attack success, or to certify a dataset as
free of poisoning.

## Licence

MIT — see [LICENSE](LICENSE).

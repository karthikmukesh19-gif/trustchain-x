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
| **Phase 1 — foundation** | Code complete; see *Verification status* below |
| Phases 2–14 — analysis engine, scoring, reporting | Not started |

What works today: account registration and sign-in, project management,
GitHub repository registration with public-metadata collection, a dashboard,
health checks, and a background worker that reports liveness.

What does **not** exist yet: dependency discovery, SBOM verification,
vulnerability analysis, reachability, fragility, attack paths, behaviour
analysis, AI reasoning, dataset validation, and the trust score itself. The
UI says so wherever those results will later appear; no figures are invented.

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

```bash
cd backend
pip install -r requirements-dev.txt
pytest --cov=app
```

Or without installing Python locally:

```bash
docker run --rm -v "${PWD}/backend:/srv" -w /srv python:3.12-slim \
  sh -c "pip install -q -r requirements-dev.txt && pytest --cov=app"
```

The tests build the application through its normal factory and substitute
in-memory stand-ins for MongoDB (mongomock), Redis and the GitHub API, so they
need no services and make no network requests.

## Verification status

Phase 1 was developed in a sandbox that could not reach PyPI, the npm registry
or Docker Hub, and had no MongoDB server. This is exactly what was and was not
executed:

| Check | Result |
|---|---|
| Backend test suite (148 tests) | **Passed**, 95 % line+branch coverage. Run on Python 3.13 with dependencies taken from their GitHub sources |
| Backend served over real HTTP by Uvicorn; API exercised with curl | **Passed** (MongoDB replaced by mongomock) |
| Worker heartbeat and readiness endpoint against a real Redis server | **Passed** |
| Browser end-to-end flow in Chromium: register → create project → metadata states → dashboard → settings → sign out → sign in → delete, plus mobile width | **Passed** against the live backend, using a bundle built with esbuild in which **Recharts was replaced by a stand-in** |
| Frontend TypeScript check | **Passed** for all project source, using React 19 type definitions and a stub for Recharts' types |
| `docker compose config` | **Valid** |
| `docker compose up --build` | **Not run** — no Docker daemon or registry access |
| Anything against a real MongoDB server | **Not run** |
| `npm install` and `npm run build` (Vite, Tailwind plugin, real Recharts) | **Not run** — the dependency versions in `package.json` are unverified |
| Real GitHub API call | **Not run** (API blocked); the client was tested against simulated responses, including failures |

**Before starting Phase 2, run these three commands** and confirm they succeed:

```bash
docker compose up --build        # all five services become healthy; register and create a project in the UI
docker run --rm -v "${PWD}/backend:/srv" -w /srv python:3.12-slim sh -c "pip install -q -r requirements-dev.txt && pytest --cov=app"
cd frontend && npm install && npm run build
```

After the first successful `npm install`, commit the generated
`frontend/package-lock.json` and switch the frontend Dockerfile to `npm ci`.

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

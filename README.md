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
| **Phase 2 — repository and dependency intelligence** | Done, validated in Docker |
| **Phase 3 — vulnerability intelligence and SBOM foundation** | Code complete; see *Verification status* below |
| Phases 4–14 — SBOM repair, fragility, prediction, attack paths, behaviour, AI, scoring, reporting | Not started |

What works today:

- Accounts, projects and GitHub repository registration.
- **Dependency analysis** of a registered repository, run by the background
  worker: an immutable snapshot of the repository at its head commit,
  language and package-manager detection, dependency extraction for Python,
  JavaScript/TypeScript, Java, Go, Rust and C/C++, a normalised inventory with
  evidence for every entry, direct/transitive classification, and a
  dependency graph. Nothing from the repository is executed.
- **Known-vulnerability check**: the dependency versions of a snapshot are
  compared with advisories published by [OSV](https://osv.dev). Each finding
  shows the source record, what was observed in the repository, why the
  version is flagged, and the data behind it. Severity and CVSS are shown as
  the source publishes them, or as unknown.
- **SBOM**: a CycloneDX 1.5 document generated from the inventory, stored
  with SHA-256 digests, with history, download, comparison between versions,
  and an integrity check that also regenerates it from the snapshot.
- Every result is labelled **OBSERVED** (read from a repository file or
  published by a named source), **INFERRED** (derived by a stated rule) or
  **UNKNOWN**. Versions that the files do not determine are shown as
  unresolved, never guessed.

What a vulnerability finding means: the installed version number lies inside
the versions an advisory publishes as affected. It does **not** say the
vulnerable code is used or reachable, or how likely exploitation is. No
finding does not mean safe. The SBOM is integrity-verifiable, not signed.

What does **not** exist yet: exploitability prediction, reachability, SBOM
repair, fragility, attack paths, behaviour analysis, AI reasoning, dataset
validation, and the trust score. No risk or trust figures are produced or
displayed.

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

Phases 1 and 2 were validated in Docker by the project owner.

Phase 3 was developed in a sandbox that cannot reach PyPI, the npm registry,
Docker Hub, the GitHub API or `api.osv.dev`. This is exactly what was and was
not executed:

| Check | Result |
|---|---|
| Backend test suite (838 tests: the 434 from Phases 1–2 and 404 new) | **Passed**, 94 % line+branch coverage. Python 3.13, mongomock 4.3.0, dependencies taken from their GitHub sources |
| Matching, normalisation and provider tests on 14 real advisory records (10 from `github/advisory-database`, 4 from `pypa/advisory-database`) | **Passed** |
| Live run: Uvicorn API + worker thread + real Redis + browser, on the real dependency files of `karthikmukesh19-gif/ShadowWatch` (commit `4c8057c`), with a local stand-in for the OSV API serving real records from `github/advisory-database` | **Passed** — sync, matching, evidence, SBOM generation, verification, download, re-generation, ownership checks (MongoDB replaced by mongomock) |
| Frontend browser tests (62: 27 existing and 35 new, Playwright + Chromium) | **Passed** against a bundle built with esbuild from the project source |
| Frontend TypeScript check | **Passed** for all project source |
| Independent review of the Phase 3 change by a separate reviewer; the 7 defects it confirmed were fixed, each with a regression test | **Done** |
| `docker compose config` | **Valid** |
| A request to the real OSV API | **Not run** (unreachable from the sandbox) |
| `docker compose up --build` with the Phase 3 code | **Not run** |
| `npm install` / `npm run build` (Vite) | **Not run** |
| Index migration on the existing MongoDB volume | **Not run** against a real server (tested on mongomock) |

**Before starting Phase 4**, run these and confirm they succeed:

```bash
docker compose up --build -d
docker compose ps                                   # all five services up, backend and frontend healthy

# backend tests and coverage (expected: 838 passed, about 94 %)
docker run --rm -v "${PWD}/backend:/srv" -w /srv python:3.12-slim sh -c "pip install -q -r requirements-dev.txt && pytest --cov=app"

# frontend
cd frontend && npm install && npm run build && npm run test:install && npm test && cd ..

# live provider check: the only step that contacts the real OSV service
docker compose exec backend python -m app.collectors.providers.smoke pypi requests 2.19.1
```

Then in the app, open the ShadowWatch project:

1. **Overview → Run dependency analysis** (if the commit changed).
2. **Vulnerabilities → Check for vulnerabilities.** The job should go
   queued → running → completed, and the page should show the source (OSV),
   the synchronisation time and the findings. Open one and compare it with
   its page on osv.dev.
3. **SBOM → Generate SBOM → Verify integrity → Download.**

The findings depend on what OSV publishes on the day and on the repository's
current commit, so no expected numbers are given here. If `api.osv.dev` cannot
be reached from the worker container, the job fails with
`PROVIDER_UNREACHABLE` or `PROVIDER_TIMEOUT` and no findings are shown.

Unauthenticated GitHub access allows 60 API requests an hour (an analysis of
ShadowWatch uses 9). Set `GITHUB_TOKEN` in `.env` for regular use. OSV needs
no key.

## Layout

```text
backend/      FastAPI application, worker and tests
frontend/     React + Vite + TypeScript + Tailwind application
docs/         architecture, database, API, security, roadmap, phase notes
datasets/     dataset registry storage (Phase 11)
reports/      generated reports (Phase 13)
scripts/      maintenance scripts (none yet)
```

## Documentation

- [Architecture](docs/architecture.md) — components, module dependency map, security controls, risks
- [Dependency analysis](docs/dependency-analysis.md) — pipeline, supported files, classification rules, limits, limitations
- [Security](docs/security.md) — controls for the platform and for analysing untrusted repositories
- [Vulnerabilities and SBOM](docs/phase3.md) — providers, normalisation, matching rules, SBOM format, integrity verification, what Phase 3 does not do
- [Database](docs/database.md) — all 31 collections, indexes, and which phase writes each
- [API](docs/api.md) — implemented and planned endpoints
- [Roadmap](docs/roadmap.md) — phases and exit criteria

## Claims this project does not make

TrustChain-X estimates, ranks, simulates and flags indicators. It does not
claim to detect all zero-days or unknown vulnerabilities, to prove that a
dependency is safe or that an SBOM is complete, to know whether a maintainer is malicious, to
guarantee future CVE prediction or attack success, or to certify a dataset as
free of poisoning.

## Licence

MIT — see [LICENSE](LICENSE).

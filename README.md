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
| **Phase 3 — vulnerability intelligence and SBOM foundation** | Done |
| **Phase 4 — code reachability analysis** | Code complete; see *Verification status* below |
| Later phases — SBOM repair, fragility, prediction, attack paths, behaviour, AI, scoring, reporting | Not started |

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
- **Code reachability** (Python): the repository's source is parsed, never
  run, into a conservative call graph, and each known vulnerability gets one
  of four results — *Reachable*, *Not confirmed*, *Unknown*, *Unsupported* —
  with the path and source lines behind it.
- Every result is labelled **OBSERVED** (read from a repository file or
  published by a named source), **INFERRED** (derived by a stated rule) or
  **UNKNOWN**. Versions that the files do not determine are shown as
  unresolved, never guessed.

What a vulnerability finding means: the installed version number lies inside
the versions an advisory publishes as affected. No finding does not mean
safe. The SBOM is integrity-verifiable, not signed.

What a reachability result means: **static reachability is not
exploitability.** *Reachable* says the source text refers to functionality an
advisory identifies as affected; it does not say an attacker can trigger it.
*Not confirmed* and *Unknown* do not mean safe. Advisories for Python packages
rarely say which functions are affected, so most real findings are *Unknown*
with evidence of how the package is used; see
[docs/phase4.md](docs/phase4.md).

What does **not** exist yet: exploitability prediction, SBOM repair,
fragility, attack paths, behaviour analysis, AI reasoning, dataset
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

Phases 1 to 3 were validated in Docker by the project owner.

Phase 4 was developed in a sandbox that cannot reach PyPI, the npm registry,
Docker Hub, the GitHub API or `api.osv.dev`. This is exactly what was and was
not executed:

| Check | Result |
|---|---|
| Backend test suite (1,049 tests: the 838 from Phases 1–3 and 211 new) | **Passed**, 95 % line+branch coverage. Python 3.13, mongomock 4.3.0, dependencies taken from their GitHub sources |
| Frontend browser tests (82: 62 existing and 20 new, Playwright + Chromium) | **Passed** against a bundle built with esbuild from the project source |
| Frontend TypeScript check | **Passed** for all project source |
| Analyzer and graph builder on real repositories read from disk: ShadowWatch (38 Python files), FastAPI (1,167), PyMongo (440), pytest (274) | **Passed** — every file parsed; about 2–4 s per repository |
| Live run: Uvicorn API + worker thread + real Redis + browser, on the real files of `karthikmukesh19-gif/ShadowWatch` (commit `4c8057c`), GitHub and OSV replaced by local stand-ins serving the real repository content and real GitHub advisory records | **Passed** — 34 findings: 0 reachable, 0 not confirmed, 6 unknown (the advisories name no functions), 28 unsupported (npm). MongoDB replaced by mongomock |
| Independent review of the Phase 4 change by a separate reviewer; the 10 defects it confirmed were fixed, each with a regression test | **Done** |
| `docker compose config` | **Valid** |
| `docker compose up --build` with the Phase 4 code | **Not run** |
| Source fetched through the real GitHub API | **Not run** (unreachable from the sandbox) |
| `npm install` / `npm run build` (Vite) | **Not run** |
| Index creation for the four new collections on the existing MongoDB volume | **Not run** against a real server (tested on mongomock) |
| Accuracy of the reachability results against a labelled benchmark | **Not measured** |

**Before starting Phase 5**, run these and confirm they succeed:

```bash
docker compose up --build -d
docker compose ps                                   # all five services up, backend and frontend healthy

# backend tests and coverage (expected: 1049 passed, about 95 %)
docker run --rm -v "${PWD}/backend:/srv" -w /srv python:3.12-slim sh -c "pip install -q -r requirements-dev.txt && pytest --cov=app"

# frontend (expected: 82 passed)
cd frontend && npm install && npm run build && npm run test:install && npm test && cd ..
```

Then in the app, open the ShadowWatch project:

1. **Vulnerabilities → Check for vulnerabilities** (needed for the current snapshot).
2. **Code reachability → Start analysis.** The job should go queued →
   running → completed. Expect the Python findings (pymongo, python-jose,
   python-dotenv) as *Unknown* with a path to where the package is used, and
   the npm findings as *Unsupported*. Open one and follow a source link to GitHub.
3. **Analyse again**: it should finish quickly and report that the stored
   source was reused.

The analysis makes one GitHub request per Python file (38 for ShadowWatch).
Unauthenticated GitHub access allows 60 an hour, so set `GITHUB_TOKEN` in
`.env`; without it a second repository, or a refresh, fails with
`RATE_LIMITED` and the time the limit resets. OSV needs no key.

To see a *Reachable* or *Not confirmed* result on a real repository, an
advisory must name its affected functions. Add an entry to a mapping file and
point `REACHABILITY_SYMBOL_MAPPINGS_FILE` at it (format in
[docs/phase4.md](docs/phase4.md)); each entry needs a source URL that
justifies it.

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
- [Code reachability](docs/phase4.md) — source analysis, call graph, statuses, evidence, limits, what Phase 4 does not do
- [Database](docs/database.md) — all 35 collections, indexes, and which phase writes each
- [API](docs/api.md) — implemented and planned endpoints
- [Roadmap](docs/roadmap.md) — phases and exit criteria

## Claims this project does not make

TrustChain-X estimates, ranks, simulates and flags indicators. It does not
claim to detect all zero-days or unknown vulnerabilities, to prove that a
dependency is safe or that an SBOM is complete, to build a complete call
graph, to decide exploitability from reachability, to know whether a maintainer is malicious, to
guarantee future CVE prediction or attack success, or to certify a dataset as
free of poisoning.

## Licence

MIT — see [LICENSE](LICENSE).

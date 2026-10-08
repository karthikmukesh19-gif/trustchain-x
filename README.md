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
| **Phase 4 — code reachability analysis** | Done |
| **Phase 5 — predictive dependency fragility and graph reasoning** | Code complete; see *Verification status* below |
| Later phases — SBOM repair, candidate-version comparison, attack paths, behaviour, AI, scoring, reporting | Not started |

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
- **Dependency intelligence**: for every dependency, a *fragility* score
  (how much rests on it in the dependency graph and how far its installed
  version is behind its registry's releases), its *exposure* to packages with
  known vulnerabilities through the graph, evidence-backed *indicators*, and
  a *predictive dependency risk* that ranks dependencies for attention. Every
  score is a visible sum of factors; a factor without data is shown as
  unknown and adds nothing. These are estimates for prioritisation, not
  predictions of specific vulnerabilities or attacks.

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

Phases 1 to 4 were validated in Docker by the project owner.

Phase 5 was developed in a sandbox that cannot reach PyPI, the npm registry,
Docker Hub, the GitHub API or `api.osv.dev`. This is exactly what was and was
not executed:

| Check | Result |
|---|---|
| Backend test suite (1,442 tests: the 1,049 from Phases 1–4 and 393 new) | **Passed**, 95 % line+branch coverage. Python 3.13, mongomock 4.3.0, dependencies taken from their GitHub sources |
| Frontend browser tests (109: 82 existing and 27 new, Playwright + Chromium) | **Passed** against a bundle built with esbuild from the project source. The new tests run the page against API responses recorded from the real backend (`backend/tests/record_ui_fixture.py`) |
| Frontend TypeScript check | **Passed** for all project source |
| Graph metrics and risk propagation against brute-force reference implementations on random graphs with cycles | **Passed** |
| Live run: Uvicorn API + worker thread + real Redis + browser, on the real dependency graph of `karthikmukesh19-gif/ShadowWatch` (commit `4c8057c`: 320 packages, 408 relationships), GitHub and OSV replaced by local stand-ins serving the real repository content and real GitHub advisory records, **registries unreachable** | **Passed** — the analysis ends *partial*: structure, exposure and indicators are computed (13 packages with known vulnerabilities, 7 that require one, 11 indirectly exposed), and every version and release-age value is reported as unknown. MongoDB replaced by mongomock |
| Independent review of the Phase 5 change by a separate reviewer; the 16 findings were addressed, each fix with a regression test | **Done** |
| `docker compose config` | **Valid** |
| `docker compose up --build` with the Phase 5 code | **Not run** |
| Release metadata fetched from the real PyPI and npm registries | **Not run** (unreachable from the sandbox). The clients are tested against stand-ins that follow the registries' documented response shapes; the shapes themselves were not re-checked against the live services |
| `npm install` / `npm run build` (Vite) | **Not run** |
| Index creation for the six new collections on the existing MongoDB volume, and document-size behaviour on a real server | **Not run** against a real server (tested on mongomock) |
| Whether the scores are predictive of anything | **Not evaluated** — see [docs/phase5.md](docs/phase5.md), sections 11 and 12 |

**Before starting Phase 6**, run these and confirm they succeed:

```bash
docker compose up --build -d
docker compose ps                                   # all five services up, backend and frontend healthy

# backend tests and coverage (expected: 1442 passed, about 95 %)
docker run --rm -v "${PWD}/backend:/srv" -w /srv python:3.12-slim sh -c "pip install -q -r requirements-dev.txt && pytest --cov=app"

# frontend (expected: 109 passed)
cd frontend && npm install && npm run build && npm run test:install && npm test && cd ..
```

Then in the app, open the ShadowWatch project:

1. **Vulnerabilities → Check for vulnerabilities** (needed for the current snapshot).
2. **Dependency intelligence → Start analysis.** The job should go queued →
   running → completed in well under a minute. With the registries reachable
   the direct dependencies show a latest release with dates, transitive npm
   packages a latest release without dates, and the overview has no
   "could not be collected" note. If the job ends *Partial*, its message says
   for how many packages the registries could not be read.
3. Expand a row: the factors of both scores add up to the score, and every
   unknown value is labelled *Unknown* or *assumed* rather than shown as 0.
4. Open **Risk graph** and tick *Vulnerable*: only packages with a known
   vulnerability remain.
5. Run **Code reachability → Start analysis**, return, and **Analyse again**:
   the page first warns that newer findings exist, and the new analysis is
   listed under *Changes since the previous analysis*.

The worker makes one HTTPS request per package to `pypi.org` or
`registry.npmjs.org` (about 320 for ShadowWatch, cached for 24 hours). Only
package names are sent. To make no such request, set
`PACKAGE_METADATA_PROVIDERS=` (empty) in `.env`; version and release-age
factors are then unknown and everything else is still analysed.

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
- [Dependency intelligence](docs/phase5.md) — fragility metrics, graph model, formulas, evidence labels, limits, what Phase 5 does not claim
- [Database](docs/database.md) — all 41 collections, indexes, and which phase writes each
- [API](docs/api.md) — implemented and planned endpoints
- [Roadmap](docs/roadmap.md) — phases and exit criteria

## Claims this project does not make

TrustChain-X estimates, ranks, simulates and flags indicators. It does not
claim to detect all zero-days or unknown vulnerabilities, to prove that a
dependency is safe or that an SBOM is complete, to build a complete call
graph, to decide exploitability from reachability, to know whether a maintainer is malicious, to
guarantee future CVE prediction or attack success, or to certify a dataset as
free of poisoning. Its fragility and predictive risk figures are explainable
rankings; they have not been shown to predict incidents.

## Licence

MIT — see [LICENSE](LICENSE).

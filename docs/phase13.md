# Phase 13 — Security hardening and research validation

The final phase: an audit of the platform's own security, the controls added
as a result, the complete test run, an end-to-end run on a real repository,
and the research validation (`research-validation.md`).

## 1. Audit result

Each item was checked against the code and, where a test could express it, is
enforced by `backend/tests/test_hardening.py` or an earlier test file.

| Area | State | Enforced by |
|---|---|---|
| JWT | HS256, 60-minute expiry, secret of at least 32 characters required in production, forged and malformed tokens rejected on every route | `test_auth.py`, `test_hardening.py` |
| Password hashing | scrypt (N=2¹⁵, r=8, p=1), per-user salt, constant-time comparison | `test_auth.py` |
| Authorisation and owner isolation | every route in the OpenAPI document except health, register and login answers 401 without a token; every project route answers 404 for another user's project | `test_hardening.py` (walks all routes) |
| Rate limiting | sign-in and registration; every job-start route | `test_auth.py`, `test_hardening.py` |
| CORS and headers | configured origin only; security headers on every response including errors | `test_security.py`, `test_hardening.py` |
| Input validation | strict models, unknown fields rejected, 1 MiB body cap, ids validated, filters whitelisted | per-phase API tests |
| MongoDB injection | operators and hostile strings in ids and query parameters never reach a query as operators | `test_hardening.py` |
| SSRF | see section 3 | `test_hardening.py` |
| Path traversal | nothing is written to disk by repository path; listed paths validated | `test_analysis.py` |
| Command injection / code execution | no module under `app/` starts a process, evaluates text or imports by name; repository content is parsed as data | `test_hardening.py` (source scan) |
| Limits | repository size, file counts and sizes, syntax nodes, graph nodes and edges, attack-path depth / paths / expansions, commits, files and patch bytes per commit, dataset records, run times | per-phase tests |
| Worker isolation | the worker runs the same code as the API, as an unprivileged user, with a read-only root filesystem and no capabilities; it executes nothing from a repository | `test_hardening.py` (compose file) |
| Redis and MongoDB | not published to the host; reachable only on the compose network | `test_hardening.py` |
| Secrets | none tracked by git; none in the frontend bundle source; `.env` ignored; examples hold placeholders; the GitHub token is sent only to the configured API host and never logged; secret-like values found in commits are masked before storage | `test_hardening.py` |
| Docker | non-root users, `no-new-privileges`, capabilities dropped, API bound to loopback on the host | `test_hardening.py` |
| Error leakage | an internal error returns a generic message with no stack trace, path or query | `test_hardening.py` |
| Audit logging | every analysis request and outcome, monitoring changes, SBOM verification and report generation; no token in any entry | `test_hardening.py` |

## 2. Findings and what was done

| # | Finding | Severity | Resolution |
|---|---|---|---|
| 1 | The GitHub API base URL was configuration without a host allow-list, unlike the OSV and registry URLs. A mistaken or hostile `GITHUB_API_URL` would have received the `GITHUB_TOKEN` | Medium | `GITHUB_ALLOWED_HOSTS` (default `api.github.com`); the URL is validated at start-up like the other providers; an invalid value stops the application |
| 2 | An allow-listed host could be an IP address or an internal name, so configuration could point a collector into the deployment's own network | Medium | IP literals in any notation, single-label names, `localhost` and reserved internal suffixes are refused for every outbound provider even when listed |
| 3 | `GITHUB_TOKEN=your_github_token_here` copied from the example file would have been sent to GitHub as a token | Low | known placeholder values are treated as "no token" |
| 4 | The frontend image was built with `npm install` and no lockfile, so builds were not reproducible and integrity hashes were not checked | Medium | `package-lock.json` is committed; the image uses `npm ci`; a test checks that the lockfile matches the manifest and that every package resolves from `registry.npmjs.org` with a SHA-512 integrity hash |
| 5 | `AI_PROVIDER` accepted any string | Low | only `deterministic` is accepted; anything else stops start-up |
| 6 | A test file contained literal strings in the format of a private-key header | Low | assembled from two literals; a test now fails if any tracked file contains a credential-shaped literal |
| 7 | `backend/.env.example` had held a real token in the working tree of the owner's machine (never committed) | High if committed | the committed example files hold `GITHUB_TOKEN=your_github_token_here`; see section 6. **A token that was ever written to a file should be revoked and replaced**, whether or not it was committed |

Open, by decision (documented in `security.md`): rate-limit counters are per
process; there is no token revocation list; the browser keeps the session
token in `sessionStorage`; SBOMs and datasets are integrity-verifiable but not
signed; Python dependencies are pinned to major-version ranges without a hash
lock; base images are pinned by tag, not by digest; host-name checks do not
resolve names, so DNS that maps a public name to a private address is not
detected.

## 3. Outbound requests (SSRF)

| Destination | Setting | Allow-list | Path built from |
|---|---|---|---|
| GitHub API | `GITHUB_API_URL` | `GITHUB_ALLOWED_HOSTS` | validated owner and repository names; 40-character hex ids |
| OSV | `OSV_API_URL` | `VULNERABILITY_ALLOWED_HOSTS` | advisory ids matching a strict pattern; package data as JSON body |
| PyPI, npm | `PYPI_API_URL`, `NPM_REGISTRY_URL` | `PACKAGE_METADATA_ALLOWED_HOSTS` | package names validated against the registry's grammar, one encoded segment |

For all of them: `https` only, default port, no credentials, query or
fragment; public host names only; **redirects are never followed**, so a
response cannot send a client to another address; no API request, repository
file, advisory or commit can supply a URL that is fetched. URLs found in
repository content, advisories and diffs are stored and shown as text. A test
runs the complete pipeline and asserts that every request made went to one of
the four allow-listed hosts over `https`.

## 4. Test results

Run in the development sandbox (Python 3.13, mongomock 4.3.0, dependencies
built from their GitHub sources; Chromium with Playwright).

| Phase | Component | Tests | Result | Coverage | Status |
|---|---|---|---|---|---|
| 6 | Attack-path simulation | 85 | passed | 98 % | Complete |
| 7 | Maintainer behaviour | 52 | passed | 98 % | Complete |
| 8 | Commit behaviour | 115 | passed | 99 % | Complete |
| 9 | Cross-layer reasoning | 49 | passed | 96 % | Complete (deterministic provider only) |
| 10 | Dataset validation | 56 | passed | 97 % | Complete |
| 11 | Trust engine | 50 | passed | 98 % | Complete |
| 12 | Dashboards and report | 31 backend, 49 browser | passed | 96 % | Complete |
| 13 | Hardening and evaluation support | 116 | passed | 99 % | Complete, with the items below not run |
| — | Backend total | 1,991 | **0 failed** | 96 % line + branch | Passed |
| — | Frontend total (browser) | 158 | **0 failed** | not measured | Passed |
| — | TypeScript | project source | no errors | — | Passed (`tsc` 5.9.3) |
| — | Frontend build | esbuild bundle of the project source | built | — | **Vite build NOT RUN** |
| — | Docker | `docker compose config` | valid | — | **build, start-up, health NOT RUN** |
| — | Integration | full pipeline on a real repository (section 5) | completed | — | Passed with stand-ins; **live services NOT RUN** |
| — | Security audit | section 1 | 7 findings, all resolved | — | Complete |

Coverage per phase is that of the phase's own modules (statements and
branches), taken from the full run and rounded. Phase 12 counts the overview,
report and dashboard tests; the evaluation-support tests live in the same
file. Phase 13 counts `test_hardening.py` (111) and
`test_real_repository_run.py` (5).

Two things to know about these runs:

- One browser test from Phase 2 (`graph.spec.ts`, "deeper packages are placed
  further right") failed once in a full run that shared the machine with the
  backend coverage run, and passed in every other run, including five
  consecutive repetitions on its own. It reads four element positions one
  after another while the graph is still settling. The test was left
  unchanged; treat a single failure of it under load as a timing artefact and
  a repeated one as a defect.
- One Phase 8 test written in this work (`test_polling_queues_due_projects_once_per_interval`)
  compared against a timestamp fixed at import time and failed when the suite
  ran slowly under coverage. The test now takes the time from the clock. The
  code under test was not changed.

### Not run, and why

The sandbox has no Docker daemon and cannot reach Docker Hub, PyPI, the npm
registry, `api.github.com` or `api.osv.dev`. These were therefore **not
executed** and are not claimed:

- `docker compose build`, `docker compose up`, container health and readiness;
- `npm ci` and `npm run build` (Vite);
- any request to the live GitHub API, OSV, PyPI or npm;
- index creation for the changed collections on a real MongoDB server.

Run them on a machine with Docker:

```bash
docker compose config --quiet && docker compose up --build -d
docker compose ps                                  # five services; backend and frontend healthy
curl -s http://localhost:8000/api/health/ready     # {"status":"ok",...}

docker run --rm -v "${PWD}/backend:/srv" -w /srv python:3.12-slim \
  sh -c "pip install -q -r requirements-dev.txt && pytest --cov=app"       # expected: 0 failed of 1,991

cd frontend && npm ci && npm run build && npm run test:install && npm test  # expected: 158 passed
```

The backend image has no `git` command, so the tests that need one (the
tracked-credential scan and the five clone-runner tests) are reported as
skipped there; run `pytest` on the host as well to include them.

Then, in the application, open a project and run the layers in the order the
overview lists them; finish with **Trust → Calculate** and **Report**.

## 5. End-to-end run on a real repository

`backend/tests/real_repository_run.py` runs the unchanged platform in-process
(API, job system, worker; MongoDB replaced by mongomock) on a local git clone.
Result for `karthikmukesh19-gif/ShadowWatch` at commit `4c8057c`
(104 files, 31 commits):

| Step | Outcome |
|---|---|
| Snapshot and dependencies | completed — 320 packages |
| Vulnerability intelligence | completed — 34 advisory matches on 13 package versions (1 critical, 20 high, 12 medium, 1 low) |
| SBOM | completed — CycloneDX, 320 components |
| SBOM verification | 5 checks, none failed |
| Code reachability | completed — 0 reachable, 0 not confirmed, 6 unknown, 28 unsupported (non-Python packages) |
| Fragility, graph risk, predictive risk | **partial** — release metadata unavailable for all 316 looked-up packages; version and release-age factors unknown |
| Attack paths | completed — 34 paths: 0 supported, 0 potential, 34 unknown |
| Commit behaviour | completed — 31 commits, 36 behaviour events, 9 listed for review |
| Maintainer behaviour | **partial** — contributors and releases unavailable; 4 indicators observed, 1 unknown |
| Dataset | completed — 320 records, status `WARNING`, quality 91.9 |
| Cross-layer reasoning | completed — 4 findings; evidence grounding 1.0, unsupported-claim rate 0.0 |
| Trust | `SCORED` — trust 65.4, risk 34.6, confidence 0.8, coverage 1.0 |
| Report | 17 sections, 55 statements, 112 evidence items, 0 unsupported statements |

What was real and what was not:

- **Real:** the repository's files, its commits and their diffs (read from a
  git clone with git plumbing; nothing was checked out or executed), and 272
  reviewed advisory records from `github.com/github/advisory-database` in OSV
  format, matched to versions by the platform's own matcher.
- **Stand-ins:** the GitHub and OSV HTTP endpoints were served locally from
  that data in the services' response shapes. The live services were not
  contacted, and the response shapes were not re-checked against them.
- **Unavailable, reported as such:** GitHub logins, contributor statistics,
  releases and repository statistics (not in a clone); PyPI and npm (requests
  failed, by design of the run).

The figures describe one run of this version on this repository. They are not
an accuracy result. Every one of the 34 attack paths is `UNKNOWN_PATH`
because reachability was undecided for all 34 findings: the run produced no
evidence that any vulnerability is reachable, and none that it is not.

Reproduce:

```bash
git clone https://github.com/karthikmukesh19-gif/ShadowWatch /tmp/sw
git clone --depth 1 --filter=blob:none --sparse https://github.com/github/advisory-database /tmp/adb
git -C /tmp/adb sparse-checkout set advisories/github-reviewed
cd backend && python -m tests.real_repository_run --clone /tmp/sw --owner karthikmukesh19-gif --name ShadowWatch \
    --advisories /tmp/adb/advisories/github-reviewed
```

## 6. Credential check before the commit

`git status`, `git diff` and `git diff --cached` were inspected, and the tree
was searched (`git grep -i` for `github_token`, `api_key`, `secret`,
`password`, `private key`, and for token formats). Result:

- no tracked file contains a value in the format of a GitHub token, an AWS
  key, a private key, a Slack or Google key or a Stripe key (enforced by
  `test_no_credential_is_tracked_by_git`);
- `.env`, `backend/.env` and `frontend/.env` are ignored;
- `.env.example` and `backend/.env.example` contain
  `GITHUB_TOKEN=your_github_token_here` and no secret;
- every match of the search terms is a setting name, a placeholder, a
  synthetic test value assembled at run time, or documentation.

## 7. Evaluation support

`backend/app/evaluation/` holds the measures the research validation calls
for (precision, recall, false-positive and false-negative rate, coverage,
precision@k, nDCG, Spearman correlation, Brier score, expected calibration
error, timing and scalability) as tested functions that return `None` when a
measure is undefined, and a catalogue of which measure has been evaluated for
which component. `GET /api/dashboard/evaluation` and the Research dashboard
show that catalogue. With no benchmark supplied, every accuracy measure reads
**NOT EVALUATED**. See `research-validation.md`, sections 6 to 8.

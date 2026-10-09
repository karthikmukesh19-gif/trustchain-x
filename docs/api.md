# TrustChain-X — API Specification

Base path `/api`. JSON in, JSON out. Interactive documentation is served at
`/docs` when `APP_ENV` is not `production`.

- **Authentication:** `Authorization: Bearer <token>` on every endpoint except
  health, register and login.
- **Errors:** `{"detail": "<message>"}`. Validation failures return 422 with
  `{"detail": [{"loc": [...], "msg": "..."}]}`; the rejected value is never
  echoed back.
- **Isolation:** a project that belongs to another user is indistinguishable
  from one that does not exist (404).
- **Limits:** request bodies above 1 MiB → 413. Register and login share a
  per-client rate limit (default 10 per minute) → 429 with `Retry-After`.
  Starting a Phase 3 job or a provider health check is limited per client
  (default 30 per minute) → 429 with `Retry-After`.

## Implemented (Phase 1)

### Health

| Method | Path | Result |
|---|---|---|
| GET | `/api/health` | 200 `{status, service, version, time}` — the process is up; touches no dependency |
| GET | `/api/health/ready` | `{status, checks: {mongodb, redis, worker}, time}`. `status` is `ok`, `degraded` (Redis or the worker is missing; still 200) or `unavailable` (MongoDB is down; 503) |

### Authentication

| Method | Path | Body | Result |
|---|---|---|---|
| POST | `/api/auth/register` | `{email, password, full_name}` | 201 `{access_token, token_type, expires_in, user}`; 409 if the email is taken; 422 if invalid |
| POST | `/api/auth/login` | `{email, password}` | 200 same shape; 401 `Incorrect email or password` for every credential failure |
| GET | `/api/auth/me` | — | 200 `{id, email, full_name, role, created_at}` |

Password policy: 10–128 characters, at least one letter and one digit.

### Projects

| Method | Path | Body / query | Result |
|---|---|---|---|
| POST | `/api/projects` | `{name, repository_url, description?}` | 201 project. The URL must be `https://github.com/<owner>/<repo>`; anything else → 422. 409 if this user already registered the repository. Repository metadata is fetched from GitHub after the response is sent, so the first response usually shows `metadata_status: "PENDING"` |
| GET | `/api/projects` | `?skip=0&limit=50` (limit 1–100) | 200 `{items, total, skip, limit}`, newest first |
| GET | `/api/projects/{id}` | — | 200 project; 404 |
| POST | `/api/projects/{id}/refresh-metadata` | — | 200 project after fetching GitHub metadata again (synchronously) |
| DELETE | `/api/projects/{id}` | — | 204; 404 |

Project object:

```json
{
  "id": "…",
  "name": "FastAPI",
  "description": "",
  "repository_url": "https://github.com/fastapi/fastapi",
  "status": "ACTIVE",
  "default_branch": "master",
  "languages": [],
  "created_at": "…",
  "updated_at": "…",
  "last_analysis": null,
  "repository": {
    "host": "github.com", "owner": "fastapi", "name": "fastapi",
    "full_name": "fastapi/fastapi", "url": "https://github.com/fastapi/fastapi",
    "metadata_status": "FETCHED",
    "metadata_error": null,
    "metadata_fetched_at": "…",
    "metadata": {
      "github_id": 0, "description": "…", "default_branch": "master",
      "primary_language": "Python", "stars": 0, "forks": 0, "open_issues": 0,
      "size_kb": 0, "archived": false, "is_fork": false, "visibility": "public",
      "license": "MIT", "github_created_at": "…", "pushed_at": "…"
    }
  }
}
```

`metadata_status` is `PENDING`, `FETCHED` or `UNAVAILABLE` (with
`metadata_error` giving the reason: not found or private, moved, rate limited,
timeout, unreachable, unexpected response).

### Dashboard

| Method | Path | Result |
|---|---|---|
| GET | `/api/dashboard/summary` | `{generated_at, projects_total, projects_analysed, projects_by_status, repository_metadata, registrations_by_day[14], recent_projects[≤5], recent_activity[≤10]}` — the caller's own data only. It contains no trust, risk or vulnerability figures, because none exist until analysis is implemented |

## Implemented (Phase 2) — dependency analysis

All routes require the project's owner; any other caller gets 404.

| Method | Path | Result |
|---|---|---|
| POST | `/api/projects/{id}/analysis/dependencies` | 202 `{job}`. Queues a background analysis. 409 if one is already queued or running for the project |
| GET | `/api/projects/{id}/analysis/status` | 200 `{job, has_results, last_analysis}`. `job` is the most recent job or `null`. `job.state` is `queued`, `running`, `completed` or `failed`; `job.stage` is `QUEUED`, `REPOSITORY_SNAPSHOT`, `REPOSITORY_DISCOVERY`, `DEPENDENCY_DISCOVERY`, `GRAPH_BUILDING` or `COMPLETED`, with `stage_index` / `stage_count`, `message`, `error: {code, message}` on failure, `summary` and `snapshot_id` on completion, and `reused_snapshot` when the commit was unchanged |
| GET | `/api/projects/{id}/snapshot` | 200 latest complete snapshot: repository, branch, `commit_sha`, `tree_sha`, `committed_at`, `collected_at`, `analyzer_version`, `collection_method`, `file_count`, `total_bytes`, `languages`, `github_primary_language`, `package_managers`, `dependency_files`, `notes`, `summary`. 404 if the project has not been analysed |
| GET | `/api/projects/{id}/snapshot/files` | `?skip&limit(≤500)&q` — discovered files with size and git blob id |
| GET | `/api/projects/{id}/dependencies` | `?skip&limit(≤500)&ecosystem&relationship=DIRECT\|TRANSITIVE\|UNKNOWN&version_status=RESOLVED\|UNRESOLVED&q` → `{snapshot, summary, total, skip, limit, items}`. Each item carries its evidence |
| GET | `/api/projects/{id}/dependencies/graph` | `{snapshot, root, nodes, edges, stats}`; with `?paths_to=<node id>` also `paths` |
| GET | `/api/projects/{id}/dependencies/paths` | `?to=<node id>` → up to 20 paths from the project to that package, shortest first |

See [dependency-analysis.md](dependency-analysis.md) for field meanings,
classification rules, limits and error codes.

The project object gains `latest_snapshot_id`; `languages` and
`last_analysis` are filled in by a completed analysis. Deleting a project
deletes its jobs, snapshots, dependencies and graphs.

## Implemented (Phase 3) — vulnerabilities, SBOM, jobs

All project routes require the project's owner; any other caller gets 404.
No request accepts a URL: the provider endpoint is configuration only.

### Vulnerabilities

| Method | Path | Result |
|---|---|---|
| POST | `/api/projects/{id}/vulnerabilities/sync` | 202 `{job}`. Queues `vulnerability_sync`: query the provider, store advisories, match. Optional body `{"provider": "osv"}`. 409 without a dependency inventory, when another job is active for the project, or when no provider is enabled; 422 for an unknown provider |
| POST | `/api/projects/{id}/vulnerabilities/analyze` | 202 `{job}`. Queues `vulnerability_analysis`: re-match using advisories already stored, without contacting the provider. Same 409 rules |
| GET | `/api/projects/{id}/vulnerabilities` | `?skip&limit(≤500)&severity=CRITICAL\|HIGH\|MEDIUM\|LOW\|UNKNOWN&match_status=AFFECTED\|UNSUPPORTED\|CONFLICT&ecosystem&q` → `{job, providers, snapshot, scan, sync, total, skip, limit, items}`. `scan` is the summary of the last matching run for the latest snapshot (`null` if none): dependencies checked / unresolved / unsupported, matches by status and by severity, and the synchronisation it relied on. `sync` is the last synchronisation with its status (`completed`, `partial`, `failed`) and counts. Items are sorted by severity, then package |
| GET | `/api/projects/{id}/vulnerabilities/{match_id}` | `{match, vulnerability}` — the match with its full evidence and the normalised advisory. `?include_raw=true` adds the record as received from the source |
| GET | `/api/vulnerability-providers` | `{items}` — enabled providers: name, base URL, supported ecosystems, last synchronisation and last health check. Any signed-in user |
| POST | `/api/vulnerability-providers/{name}/health-check` | `{provider, ok, detail, code, checked_at}`. Contacts the configured provider once. 404 for an unknown provider |

A match item: `id`, `package_name`, `ecosystem`, `matched_version`,
`relationship`, `depth`, `source`, `source_id`, `aliases`, `group_key`,
`summary`, `severity`, `severity_source`, `cvss[]`, `affected_range`,
`fixed_version`, `fixed_versions`, `match_status`, `confidence`,
`confidence_meaning`, `classification`, `matched_at`. The detail adds
`evidence: {evidence_type, source, observed, match}`.

No response contains an exploitability, risk or trust figure.

### SBOM

| Method | Path | Result |
|---|---|---|
| POST | `/api/projects/{id}/sbom/generate` | 202 `{job}`. Queues `sbom_generation` from the latest snapshot. 409 without an inventory or when another job is active |
| GET | `/api/projects/{id}/sbom` | `{job, latest, history, has_inventory, latest_snapshot_id}`. `history` is every SBOM version, newest first. `latest` includes the vulnerability linkage summary |
| GET | `/api/projects/{id}/sbom/{sbom_id}` | SBOM metadata: version, format, spec version, serial number, snapshot and commit, counts, `content_digest`, `document_digest`, `completeness`, `last_verification`, vulnerability linkage |
| GET | `/api/projects/{id}/sbom/{sbom_id}/document` | The CycloneDX JSON document (`application/vnd.cyclonedx+json`, as an attachment, with the document digest in the `X-Content-Digest` header). 409 if the stored document cannot be read |
| GET | `/api/projects/{id}/sbom/{sbom_id}/components` | `?skip&limit(≤500)&q&only_vulnerable` → `{total, items}`; each component carries the vulnerability matches currently stored for it |
| POST | `/api/projects/{id}/sbom/{sbom_id}/verify` | `{sbom_id, valid, verified_at, checks[], …}` — each check has `name`, `ok`, `detail` and, where relevant, `expected` / `actual`. The result is also saved as the SBOM's `last_verification` |
| GET | `/api/projects/{id}/sbom/{sbom_id}/diff/{other_id}` | Differences from `other_id` (base) to `sbom_id` (target): `summary`, `items[]` with `change` = `ADDED` \| `REMOVED` \| `CHANGED`, `ecosystem_changes`, `document_changes`, relationship changes. 409 if either document cannot be read |

### Jobs

| Method | Path | Result |
|---|---|---|
| GET | `/api/projects/{id}/jobs` | `?type=<comma-separated job types>&limit(≤50)` → `{active, items}`. `active` is the job currently queued or running for the project, of any type, or `null`. Job types: `dependencies`, `code_reachability_analysis`, `vulnerability_sync`, `vulnerability_analysis`, `sbom_generation` |

Job documents have the Phase 2 shape (`state`, `stage`, `stage_index`,
`stage_count`, `stages`, `message`, `error: {code, message, retry_at}`,
`summary`). Error codes are listed in [phase3.md](phase3.md).

Deleting a project also deletes its vulnerability matches, synchronisation
records, SBOMs, SBOM components and SBOM diffs. Stored advisories are shared
reference data and are kept.

## Implemented (Phase 4) — code reachability

All routes require the project's owner; any other caller gets 404. No
response contains an exploitability, risk or trust figure.

| Method | Path | Result |
|---|---|---|
| POST | `/api/projects/{id}/code-reachability/analyze` | 202 `{job}`. Queues `code_reachability_analysis` for the latest snapshot. Optional body `{"refresh_source": true}` re-reads the source instead of reusing what is stored. 409 without a snapshot, without a vulnerability check for that snapshot, or when another job is active. Rate limited |
| GET | `/api/projects/{id}/code-reachability` | `?skip&limit(≤500)&status=REACHABLE\|NOT_CONFIRMED_REACHABLE\|UNKNOWN\|UNSUPPORTED&confidence=HIGH\|MEDIUM\|LOW\|NONE&ecosystem&q` → `{job, snapshot, has_vulnerability_scan, vulnerability_scan_matched_at, analysis, supported_ecosystems, statuses, total, skip, limit, items}`. `analysis` is the completed analysis of the latest snapshot or `null`; items are sorted by status (reachable first), then severity |
| GET | `/api/projects/{id}/code-reachability/{finding_id}` | One finding with `explanation`, `affected_symbols`, `observed` and `inferred` |
| GET | `/api/projects/{id}/code-reachability/{finding_id}/path` | `{status, confidence, path_kind, path, meaning}`. `path_kind` is `AFFECTED_SYMBOL` (a path to an affected name), `DEPENDENCY_USAGE` (only a path to a use of the package) or `null` |
| GET | `/api/projects/{id}/code-reachability/source/{snapshot_id}` | `?skip&limit(≤500)&parse_status&q` → `{analysis, source_available, total, items}`: the source files considered for that snapshot, how each was handled, and its import statements with their dependency mapping |

A list item: `id`, `match_id`, `advisory_id`, `aliases`, `severity`,
`ecosystem`, `dependency`, `resolved_version`, `relationship`, `status`,
`confidence`, `reason`, `symbol_mapping`, `matched_symbol`, `usage_level`,
`evidence {source_file, line, symbol, text, path[]}`, `analyzed_at`,
`analyzer_version`.

Job error codes: `NOT_ANALYSED`, `NOT_SCANNED`, `PROJECT_NOT_FOUND`,
`RATE_LIMITED` (with `retry_at`), `INTEGRITY_MISMATCH`, `TIMEOUT`,
`INTERNAL_ERROR`, and the other GitHub codes of Phase 2. Statuses, reasons and
confidence are defined in [phase4.md](phase4.md).

Deleting a project also deletes its reachability analyses, source records,
graph and findings.

## Implemented (Phase 5) — dependency intelligence

All routes require the project's owner; any other caller gets 404. The start
routes take no parameters. Scores are returned with their factors and model
version; none is a probability or the trust score.

| Method | Path | Result |
|---|---|---|
| POST | `/api/projects/{id}/fragility/analyze` | 202 `{job}`. Queues `dependency_fragility_analysis`. 409 without a snapshot or when another job is active. Rate limited |
| GET | `/api/projects/{id}/fragility` | `?skip&limit(≤500)&q&ecosystem&level=LOW\|MEDIUM\|HIGH&relationship&sort=fragility\|confidence\|name` |
| GET | `/api/projects/{id}/fragility/summary` | `{available, analysis, fragility, graph, metadata, graph_issues, meaning}` |
| GET | `/api/projects/{id}/fragility/{dependency_id}` | `{fragility, health}` |
| POST | `/api/projects/{id}/graph-risk/analyze` | 202 `{job}`. Queues `graph_risk_analysis`. Also 409 without a vulnerability check of the snapshot |
| GET | `/api/projects/{id}/graph-risk` | `?skip&limit&q&ecosystem&classification` |
| GET | `/api/projects/{id}/graph-risk/{dependency_id}` | One package's classification, risk components and exposure sources |
| POST | `/api/projects/{id}/predictive-risk/analyze` | 202 `{job}`. Queues `predictive_dependency_analysis` (all layers). Same preconditions as graph risk |
| GET | `/api/projects/{id}/predictive-risk` | `?skip&limit&q&ecosystem&level&relationship&indicator&vulnerable&reachable&sort=risk\|fragility\|centrality\|dependents\|name` |
| GET | `/api/projects/{id}/predictive-risk/history` | `?kind=fragility\|graph_risk\|predictive&limit(≤100)` → `{items}` |
| GET | `/api/projects/{id}/predictive-risk/compare` | `?base&target` (analysis ids of this project) → `{base, target, comparable, summary, items}` |
| GET | `/api/projects/{id}/predictive-risk/graph` | `{analysis, root, nodes, edges}`; 404 until a full analysis of the latest snapshot exists |
| GET | `/api/projects/{id}/predictive-risk/{dependency_id}` | `{prediction, indicators, fragility, health, graph_risk}` |

List responses are `{job, snapshot, has_vulnerability_scan, current_inputs,
analysis, total, skip, limit, items}`; `analysis` is `null` until an analysis
of the latest snapshot has completed, and then there are no items. A job can
end in the state `partial` (results stored, registry metadata incomplete).
Fields, formulas, classifications and error codes are defined in
[phase5.md](phase5.md).

Deleting a project also deletes its dependency-intelligence analyses and
their rows. Cached registry metadata is shared reference data and is kept.

## Implemented (Phases 6–13)

All routes below are under `/api/projects/{id}`, require authentication and
answer 404 for a project of another user. Every `POST …/analyze` (and
`POST …/ai-analysis`, `POST …/datasets/validate`) accepts an empty body or
`{}`, rejects unknown fields, is limited by the job rate limit, and returns
**202** `{job}`. It returns **409** when the project has no snapshot (where
one is needed), when a prerequisite layer is missing, or while another job is
queued or running for the project. Progress is read from
`GET /api/projects/{id}/jobs`. A job ends `completed`, `partial` (results
stored; part of the input could not be collected, with a code and message)
or `failed` (nothing stored).

List responses carry `{job, snapshot, analysis, total, skip, limit, items}`.
`analysis` is `null` until an analysis of the latest snapshot exists, and
then there are no items: "not analysed" is never an empty result.

### Attack paths (Phase 6) — [phase6.md](phase6.md)

| Method | Path | Notes |
|---|---|---|
| POST | `/attack-paths/analyze` | needs a snapshot and a vulnerability check |
| GET | `/attack-paths` | filters `status`, `level`, `severity`, `q`; `skip`, `limit` |
| GET | `/attack-paths/graph` | combined graph, bounded; `?without=<node id>` for the what-if; 404 until an analysis exists |
| GET | `/attack-paths/history` | earlier analyses |
| GET | `/attack-paths/{path_id}` | nodes, edges, evidence, score terms, alternatives, break points |

### Maintainer behaviour (Phase 7) — [phase7.md](phase7.md)

| Method | Path | Notes |
|---|---|---|
| POST | `/maintainers/analyze` | needs no snapshot; reads public GitHub metadata |
| GET | `/maintainers` | repository profile, indicators and contributors; `q`, `skip`, `limit` |
| GET | `/maintainers/history` | earlier analyses |
| GET | `/maintainers/{maintainer_id}` | one contributor and the repository profile |

### Commit behaviour (Phase 8) — [phase8.md](phase8.md)

| Method | Path | Notes |
|---|---|---|
| POST | `/commits/analyze` | check for new commits now |
| POST | `/commits/monitoring` | body `{"enabled": true|false}`; returns `{monitoring}` |
| GET | `/commits` | filters `level`, `indicator`, `q`; `sort=time|anomaly` |
| GET | `/commits/{sha}` | full 40-character id; findings, factors, baseline, events |
| GET | `/security-events` | filters `type`, `severity`, `sha` |
| GET | `/behaviour-events` | filters `type`, `severity`, `sha` |

### Cross-layer reasoning (Phase 9) — [phase9.md](phase9.md)

| Method | Path | Notes |
|---|---|---|
| POST | `/ai-analysis` | runs the deterministic rule engine over stored results |
| GET | `/ai-analysis` | filters `severity`, `category`, `layer` |
| GET | `/ai-analysis/history` | earlier runs with grounding metrics |
| GET | `/ai-analysis/{finding_id}` | statements, evidence, conditions, confidence terms, audit record |

### Dataset (Phase 10) — [phase10.md](phase10.md)

| Method | Path | Notes |
|---|---|---|
| POST | `/datasets/validate` | builds a version when results changed, then validates the stored records |
| GET | `/datasets` | versions, newest first |
| GET | `/datasets/{dataset_id}` | version, live hash verification, records (`suspicious`, `vulnerable`, `skip`, `limit`) |
| GET | `/datasets/{dataset_id}/quality` | factors, problems, duplicates, distributions; `history` |

### Trust (Phase 11) — [phase11.md](phase11.md)

| Method | Path | Notes |
|---|---|---|
| POST | `/trust/analyze` | combines whatever the layers have stored for the latest snapshot |
| GET | `/trust` | `{job, snapshot, trust, model_version, weights, labels, weights_statement, meaning, …}`; `trust` is `null` until calculated. `trust.status` is `SCORED` or `INSUFFICIENT_DATA`; in the latter `trust_score` and `risk_score` are `null` |
| GET | `/trust/history` | `limit` up to 200 |
| GET | `/trust/compare` | `base` and `target` are ids of stored results |
| GET | `/trust/explanation` | 404 until a result exists for the latest snapshot |

### Overview and report (Phase 12) — [phase12.md](phase12.md)

| Method | Path | Notes |
|---|---|---|
| GET | `/overview` | every layer's status, trust, distributions, top items, timeline, measured values |
| GET | `/report` | `format=json` (default) or `markdown` (attachment). 500 rather than a report with an unsupported statement |

Account level:

| Method | Path | Notes |
|---|---|---|
| GET | `/api/dashboard/summary` | now includes `trust` per project; score fields are present only when a score exists |
| GET | `/api/dashboard/evaluation` | evaluation measures and their state; unevaluated measures have no value |

Deleting a project also deletes its runs, attack paths, maintainer profiles,
commit analyses and events, findings, dataset versions and records, and trust
scores.

## Not implemented

| Method | Path | State |
|---|---|---|
| POST | `/api/projects/{id}/sbom/repair` | self-healing SBOM: not built |
| GET | `/api/projects/{id}/predictions` (candidate-version comparison) | not built |
| WS | `/ws/projects/{project_id}` | not built; progress and events are polled |
| — | PDF export of the report | not built; JSON and Markdown only |

The paths differ in places from the original plan: all dataset, trust,
commit and reasoning routes are scoped to a project
(`/api/projects/{id}/…`), which is what makes owner isolation uniform.

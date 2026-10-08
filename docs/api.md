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
| GET | `/api/projects/{id}/jobs` | `?type=<comma-separated job types>&limit(≤50)` → `{active, items}`. `active` is the job currently queued or running for the project, of any type, or `null`. Job types: `dependencies`, `vulnerability_sync`, `vulnerability_analysis`, `sbom_generation` |

Job documents have the Phase 2 shape (`state`, `stage`, `stage_index`,
`stage_count`, `stages`, `message`, `error: {code, message, retry_at}`,
`summary`). Error codes are listed in [phase3.md](phase3.md).

Deleting a project also deletes its vulnerability matches, synchronisation
records, SBOMs, SBOM components and SBOM diffs. Stored advisories are shared
reference data and are kept.

## Planned

These endpoints are part of the target API and are **not implemented**;
calling them returns 404 today. The originally planned `/analyze`, `/status`
and `/dependency-graph` paths were replaced by the Phase 2 routes above.

| Method | Path | Phase |
|---|---|---|
| GET | `/api/projects/{id}/reachability` | 7 |
| POST | `/api/projects/{id}/sbom/repair` | 4 |
| GET | `/api/projects/{id}/fragility` | 5 |
| GET | `/api/projects/{id}/predictions` | 5–6 |
| GET | `/api/projects/{id}/attack-paths` | 7 |
| GET | `/api/projects/{id}/maintainers` | 8 |
| GET | `/api/projects/{id}/maintainer-behaviour` | 8 |
| GET | `/api/projects/{id}/commits` | 8 |
| GET | `/api/projects/{id}/commit-analysis` | 9 |
| GET | `/api/projects/{id}/ai-analysis` | 10 |
| POST | `/api/datasets` | 11 |
| POST | `/api/datasets/{id}/validate` | 11 |
| GET | `/api/datasets/{id}/quality` | 11 |
| GET | `/api/projects/{id}/trust-score` | 12 |
| GET | `/api/projects/{id}/report` | 13 |
| WS | `/ws/projects/{project_id}` | 9 (job progress is polled through `analysis/status` until then) |

Two endpoints exist that were not in the original list:
`POST /api/projects/{id}/refresh-metadata` and `DELETE /api/projects/{id}`
(project management), plus `GET /api/auth/me`, `GET /api/health*` and
`GET /api/dashboard/summary`.

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

## Planned

These endpoints are part of the target API and are **not implemented**;
calling them returns 404 today.

| Method | Path | Phase |
|---|---|---|
| POST | `/api/projects/{id}/analyze` | 2 |
| GET | `/api/projects/{id}/status` | 2 |
| GET | `/api/projects/{id}/dependencies` | 2 |
| GET | `/api/projects/{id}/dependency-graph` | 2 |
| GET | `/api/projects/{id}/vulnerabilities` | 3 |
| GET | `/api/projects/{id}/reachability` | 3 |
| GET | `/api/projects/{id}/sbom` | 4 |
| POST | `/api/projects/{id}/sbom/verify` | 4 |
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
| WS | `/ws/projects/{project_id}` | 2 (job progress), 9 (security events) |

Two endpoints exist that were not in the original list:
`POST /api/projects/{id}/refresh-metadata` and `DELETE /api/projects/{id}`
(project management), plus `GET /api/auth/me`, `GET /api/health*` and
`GET /api/dashboard/summary`.

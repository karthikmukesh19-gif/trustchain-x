# Phase 7 — Maintainer behaviour intelligence

Model `maintainer-behaviour-v1`. Code: `backend/app/analyzers/maintainers/`,
`backend/app/services/maintainers.py`, `backend/app/api/maintainers.py`,
additions to `backend/app/collectors/github.py`.

## 1. What it does

Describes how a repository is maintained, from public GitHub metadata: who
commits, how often, how releases are published, and where that pattern
changed. Every output is a **behavioural indicator** with the evidence behind
it.

**None of it is a judgement about a person.** An indicator says that a
pattern was observed. It never says, and cannot show, that anyone acted with
bad intent. The platform has no classification "malicious", no per-person
trust rating, and no field that could hold one. Concentrated maintenance,
bursts of work and quiet periods are all normal in healthy projects.

## 2. Data collected

Through the configured GitHub API host only (see `security.md`):

| Data | Endpoint | Bound |
|---|---|---|
| Commits (sha, author login, times, message summary, parents) | `GET /repos/{o}/{r}/commits` | `MAINTAINER_MAX_COMMITS` (500) |
| Contributors | `GET /repos/{o}/{r}/contributors` | paged, capped |
| Releases | `GET /repos/{o}/{r}/releases` | `MAINTAINER_MAX_RELEASES` (100) |

E-mail addresses are never stored or returned as text. Where a commit has no
GitHub login, the author is grouped by a truncated hash of the address, which
serves only to tell two authors apart. Display names and logins are public
GitHub data.

## 3. Measures

`activity.py`: commit frequency, weekly series of commits and distinct
contributors, inactivity gaps, rapid clusters (many commits in a short
window), release frequency, activity pattern by hour and weekday in UTC.
`contributors.py`: one profile per contributor and the concentration of work
(top share, Herfindahl–Hirschman index, effective number of contributors,
number of contributors covering half of the commits). `change_patterns.py`: what kinds of change each contributor's
commits contained, read from Phase 8 results when they exist and reported as
unavailable otherwise.

## 4. Indicators

Each indicator is `OBSERVED`, `NOT_OBSERVED` or `UNKNOWN`. `UNKNOWN` means the
data needed to evaluate it was not available; it is never counted as "fine".

| Indicator | Weight | Observed when |
|---|---|---|
| `CONTRIBUTOR_CONCENTRATION` | 20 | one contributor authored at least 60 % of at least 10 observed commits |
| `OWNERSHIP_CONCENTRATION` | 15 | all releases with a known publisher (at least 3) come from one account, or all analysed security-sensitive commits (at least 5) from one contributor |
| `SUDDEN_ACTIVITY_CHANGE` | 15 | recent weekly activity is at least 3× the earlier median (needs 8 weeks), or a contributor who first appeared within 30 days authored at least 30 % of recent commits |
| `UNUSUAL_RELEASE_PATTERN` | 10 | the latest release interval is under a tenth or over five times the repository's own median, or several releases fall within a day (needs 4 releases) |
| `SECURITY_SENSITIVE_CHANGE` | 15 | analysed commits changed authentication, pipeline, dependency-source or secret-like content (needs Phase 8) |
| `LONG_INACTIVITY` | 15 | no commit for at least 180 days |
| `RAPID_CHANGE_CLUSTER` | 10 | 10 or more commits within 60 minutes |

## 5. Attention score

```text
attention_score = 100 × Σ(weight × strength of observed indicators) / Σ(weight of evaluated indicators)
confidence      = Σ(weight of evaluated indicators) / Σ(all weights) × history sufficiency
```

History is sufficient at 30 observed commits and scales down below that. The
score says how much of the maintenance pattern deserves a look. It is not a
measure of the trustworthiness of any person. When the history could not be
collected, every indicator is `UNKNOWN`, there is no score, and the job ends
as `partial` with the reason.

## 6. API

| Method | Path | Result |
|---|---|---|
| POST | `/api/projects/{id}/maintainers/analyze` | 202 with the job |
| GET | `/api/projects/{id}/maintainers` | `{job, analysis, profile, indicators, total, items, meaning}` |
| GET | `/api/projects/{id}/maintainers/history` | earlier analyses |
| GET | `/api/projects/{id}/maintainers/{maintainer_id}` | one contributor's activity and the repository indicators whose evidence names that account |

Every response carries `meaning`: *"A behavioural indicator describes a
pattern in public repository metadata. It is not evidence of intent or
wrongdoing, and no indicator is a judgement about a person."*

## 7. Storage

`analysis_runs` (kind `maintainers`), `maintainer_profiles` (one repository
profile per analysis), `maintainers` (one row per contributor per analysis).

## 8. Tests

`backend/tests/test_maintainers.py` — 52 tests: each measure on constructed
histories, each indicator at and around its threshold, `UNKNOWN` when history
is too short, partial collection, rate limiting, that no e-mail address is
stored or returned, API contract and isolation, and that no output contains a
judgement about a person.

## 9. Limitations

- Public metadata only. Commit authorship is whatever git records and can be
  set freely by a committer; signed-commit verification is not used.
- The observed window is the most recent commits up to the cap, not the full
  history of a large repository.
- Thresholds are stated heuristics. Whether the indicators relate to later
  incidents has not been evaluated (NOT EVALUATED).

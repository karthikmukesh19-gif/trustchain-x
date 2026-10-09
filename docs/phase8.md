# Phase 8 — Real-time commit behaviour analysis

Model `commit-behaviour-v1`. Code: `backend/app/analyzers/behavior/`,
`backend/app/services/behaviour.py`, `backend/app/api/behaviour.py`, worker
loop in `backend/app/workers/worker.py`.

## 1. What it does

Looks at what each new commit changed, **as text**: which files, and which
lines were added or removed according to the diff GitHub publishes. The
result is a set of indicators with evidence, and an anomaly score comparing
the commit with the repository's own earlier commits.

**Static analysis only.** A commit is never checked out, built, imported or
run. The diff is split into lines and matched against patterns; it is never
interpreted as code.

**An anomaly is not a verdict.** It is a departure from the usual pattern and
a reason to review a change. Most anomalies are ordinary work that happens to
be unusual. Nothing here calls a commit or its author harmful.

## 2. How commits arrive ("real time")

By polling GitHub's commit list; no webhook or inbound connection is needed.

- `POST …/commits/analyze` checks for new commits now.
- `POST …/commits/monitoring {"enabled": true}` marks a project as monitored.
  When `COMMIT_POLL_INTERVAL_MINUTES` is greater than 0, the worker queues a
  check for each monitored project whose last check is older than the
  interval (at most 20 projects per tick). The default is 0: no automatic
  polling until the operator sets an interval.

The interface refreshes by polling the job status, as in earlier phases.
There is no WebSocket channel; latency is the polling interval, not seconds.

## 3. Diff reading

`diff.py` parses unified-diff hunks into added and removed lines with line
numbers. Bounds: 20 000 lines and 2 000 characters per line per file,
`COMMIT_MAX_FILES` (300) files per commit, `COMMIT_MAX_PATCH_BYTES`
(200 000) per file, `COMMIT_ANALYSIS_MAX_COMMITS` (30) commits per run.
GitHub omits the patch for binary and very large files; such a file is
recorded as "content not inspected", not as unremarkable.

## 4. Indicators

| Indicator | Basis | Recognised from |
|---|---|---|
| `DEPENDENCY_CHANGE` | OBSERVED | a manifest, lockfile or package-source configuration was changed; a lockfile changed without a manifest; added package-source lines (extra index, alternative registry, git source, replace/patch directives) are INFERRED |
| `SECURITY_CONFIG_CHANGE` | OBSERVED | CI workflows, container files, infrastructure and server configuration, `CODEOWNERS`, `SECURITY.md`, environment-file templates |
| `AUTH_CHANGE` | OBSERVED / INFERRED | files on authentication paths; removed authentication checks; weakened token verification |
| `NETWORK_BEHAVIOUR_CHANGE` | INFERRED | a host name that appears in added lines and not in the lines they replace |
| `COMMAND_EXECUTION_PATTERN` | INFERRED | added calls that start a process or evaluate text, download-and-run pipelines |
| `SECRET_LIKE_PATTERN` | INFERRED | token formats of well-known providers, private-key headers, assigned high-entropy values that are not placeholders |
| `LARGE_CHANGESET` | OBSERVED | 50 or more files, or 2 000 or more lines |
| `UNUSUAL_CHANGE_PATTERN` | INFERRED / DERIVED | long encoded-looking runs or very long lines in added text; departures only a baseline can show (see 5) |

Severities: `INFO`, `LOW`, `MEDIUM`, `HIGH`. Tests, documentation and example
paths lower the severity of pattern matches. At most 5 findings per rule per
file and 200 per commit are kept, with the number left out noted.

**Secret-like values are never stored.** Every excerpt is masked before it
is written: a matched value is replaced by its first characters and its
length. The platform must not become a second place where a leaked credential
is kept. This is enforced by tests that scan the database and every API
response after analysing commits that contain synthetic credentials.

## 5. Baseline and anomaly score

The baseline is built from up to `COMMIT_BASELINE_COMMITS` (100) earlier
analysed commits of the project: median and median absolute deviation of
lines and files changed, known authors, hours at which commits were made.

```text
anomaly_score = 100 × Σ(weight × value of evaluated factors) / Σ(weight of evaluated factors)
```

| Factor | Weight | Needs |
|---|---|---|
| `security_signals` | 40 | — |
| `size_deviation` | 25 | 5 earlier commits |
| `breadth_deviation` | 10 | 5 earlier commits |
| `new_author` | 10 | 10 earlier commits |
| `sensitive_first_touch` | 10 | 10 earlier commits |
| `unusual_hour` | 5 | 30 earlier commits |

Deviation is a robust z-score (median/MAD); 3.5 marks an outlier. A factor
that cannot be evaluated is `UNKNOWN` and left out of both sums, and
confidence falls accordingly. A low score is not a clearance.

## 6. Events

`behaviour_events`: one event per indicator type raised by a commit.
`security_events`: the subset with severity `MEDIUM` or above. Both are
append-only and listed newest first.

## 7. API

| Method | Path | Result |
|---|---|---|
| POST | `/api/projects/{id}/commits/analyze` | 202 with the job |
| POST | `/api/projects/{id}/commits/monitoring` | `{monitoring}`; audited |
| GET | `/api/projects/{id}/commits` | analysed commits; filters `level`, `indicator`, `q`; `sort=time\|anomaly` |
| GET | `/api/projects/{id}/commits/{sha}` | one commit with findings, factors, baseline and events |
| GET | `/api/projects/{id}/security-events` | filters `type`, `severity`, `sha` |
| GET | `/api/projects/{id}/behaviour-events` | filters `type`, `severity`, `sha` |

## 8. Tests

`backend/tests/test_behaviour.py` — 115 tests: diff parsing, every rule with
positive and negative cases, masking, baseline statistics, each anomaly
factor, `UNKNOWN` with a short baseline, idempotent re-runs, polling, GitHub
failures, API contract and isolation.

## 9. Limitations

- Pattern rules over diff text. They miss what they have no pattern for
  (obfuscated or indirect code) and flag ordinary code that resembles one.
  Precision and recall have not been measured (NOT EVALUATED).
- Only the diff is seen, not the whole file or its effect at run time.
- Polling, with one request per commit for its detail; subject to the GitHub
  rate limit, which is reported and never retried in a loop.
- Force-pushed or deleted commits that were never listed are not seen.

# TrustChain-X — MongoDB Data Model

Database: `trustchain_x` (configurable through `MONGODB_DB`).

All 29 collections are declared, with their indexes, in
`backend/app/models/collections.py`; `ensure_indexes()` creates the indexes at
start-up and is safe to run repeatedly. **Declared does not mean populated.**
The "Written from" column says which phase starts writing a collection.
Field lists for collections that are not yet written are the planned shape and
may be refined when the owning phase is built.

Conventions:

- `_id` is an `ObjectId`. Documents reference each other by id; large objects
  are never duplicated across collections.
- All timestamps are timezone-aware UTC datetimes.
- Analysis outputs carry `project_id` and `snapshot_id` so every result is
  tied to the exact repository state it was computed from.
- Evidence records keep `source` and `fetched_at`/`observed_at`.

## Collections in use

### `users`

| Field | Type | Notes |
|---|---|---|
| `email` | string | lower-cased; **unique** |
| `full_name` | string | 1–100 chars |
| `password_hash` | string | `scrypt$N$r$p$salt$hash`; never returned by the API |
| `role` | string | `user` (set by the server, never by the client) |
| `is_active` | bool | inactive accounts cannot sign in or use tokens |
| `created_at`, `last_login_at` | datetime | |

Indexes: `{email: 1}` unique.

### `repositories`

One document per GitHub repository, shared by every project that registers it.

| Field | Type | Notes |
|---|---|---|
| `key` | string | `github.com/<owner>/<name>` lower-cased; **unique** |
| `host`, `owner`, `name`, `full_name`, `url` | string | from the validated URL |
| `metadata_status` | string | `PENDING` → `FETCHED` or `UNAVAILABLE` |
| `metadata_error` | string \| null | user-facing reason when `UNAVAILABLE` |
| `metadata` | object \| null | observed GitHub fields: `github_id`, `description`, `default_branch`, `primary_language`, `stars`, `forks`, `open_issues`, `size_kb`, `archived`, `is_fork`, `visibility`, `license`, `github_created_at`, `pushed_at`. Each is type-checked; anything unexpected is stored as `null`. A failed refresh keeps the last successful values. |
| `metadata_fetched_at` | datetime \| null | time of the last successful fetch |
| `created_at`, `updated_at` | datetime | |

Indexes: `{key: 1}` unique.

### `projects`

| Field | Type | Notes |
|---|---|---|
| `owner_id` | ObjectId → `users` | every query is scoped to this |
| `name`, `description` | string | |
| `repository_id` | ObjectId → `repositories` | |
| `repository_key` | string | copy of `repositories.key` for the uniqueness index |
| `repository_url` | string | canonical `https://github.com/<owner>/<name>` |
| `default_branch` | string \| null | copied from repository metadata when known |
| `languages` | string[] | detected languages from the latest analysis |
| `status` | string | `ACTIVE` |
| `last_analysis` | datetime \| null | time of the last completed dependency analysis |
| `latest_snapshot_id` | ObjectId \| null | → `repository_snapshots`; the snapshot the API serves |
| `active_job_id` | ObjectId \| null | set while a job is queued or running; claimed atomically so only one can be |
| `created_at`, `updated_at` | datetime | |

Indexes: `{owner_id: 1, repository_key: 1}` unique (a user registers a
repository once); `{owner_id: 1, created_at: -1}`; `{repository_id: 1}`.

### `audit_logs`

Append-only record of security-relevant actions.

| Field | Type | Notes |
|---|---|---|
| `timestamp` | datetime | |
| `action` | string | `auth.register`, `auth.login`, `project.create`, `project.refresh_metadata`, `project.delete`, `analysis.dependencies.request`, `analysis.dependencies.finish` |
| `outcome` | string | `success` \| `failure` |
| `actor_id` | ObjectId \| null | `null` for failed sign-ins |
| `resource_type`, `resource_id` | string, ObjectId \| null | |
| `ip`, `user_agent` | string | peer address; user agent truncated to 300 chars |
| `details` | object | never contains passwords, tokens or secrets |

Indexes: `{actor_id: 1, timestamp: -1}`; `{action: 1, timestamp: -1}`.

### `analysis_jobs`

| Field | Type | Notes |
|---|---|---|
| `project_id`, `owner_id`, `repository_id` | ObjectId | |
| `type` | string | `dependencies` |
| `state` | string | `queued` → `running` → `completed` \| `failed` |
| `stage`, `stage_index`, `stage_count`, `message` | | progress shown to the user |
| `error` | object \| null | `{code, message}` (and `retry_at` for rate limits) |
| `snapshot_id`, `summary`, `reused_snapshot` | | set on completion |
| `analyzer_version` | string | |
| `created_at`, `started_at`, `finished_at`, `updated_at` | datetime | |

Indexes: `{project_id: 1, created_at: -1}`; `{state: 1, created_at: 1}`.

### `repository_snapshots`

Immutable record of the repository at one commit, per project.

| Field | Type | Notes |
|---|---|---|
| `project_id`, `repository_id`, `job_id` | ObjectId | |
| `repository_url`, `repository_full_name`, `branch` | string | |
| `commit_sha`, `tree_sha`, `committed_at`, `commit_message` | | from the GitHub commit |
| `collected_at` | datetime | |
| `status` | string | `COLLECTED` while results are being written, then `COMPLETE`. Only `COMPLETE` snapshots are served; an incomplete one is replaced on the next run |
| `analyzer_version`, `collection_method` | string | |
| `file_count`, `total_bytes`, `rejected_paths`, `symlinks_skipped`, `submodules_skipped` | int | |
| `files` | array | `{path, size, sha}` for every discovered file (`sha` = git blob id) |
| `languages` | object | `{primary_language, languages: [{language, files, bytes, share, confidence, basis, evidence_files}]}` |
| `github_primary_language` | string \| null | what GitHub reports, kept for comparison |
| `package_managers` | array | `{package_manager, ecosystem, basis, supported, manifest_files, lock_files}` |
| `dependency_files` | array | per file: path, kind, package manager, status, error, `git_blob_sha`, `sha256`, counts, notes |
| `notes`, `summary` | | resolver notes; totals shown in the UI |
| `github_requests`, `github_rate_remaining` | int | API cost of the collection |

Indexes: `{project_id: 1, commit_sha: 1, analyzer_version: 1}` unique;
`{project_id: 1, collected_at: -1}`.

### `dependencies`

One document per package version (or per unresolved package) in a snapshot.

| Field | Type | Notes |
|---|---|---|
| `project_id`, `snapshot_id` | ObjectId | |
| `node_id` | string | `ecosystem:normalized_name@version`; id used by the graph |
| `ecosystem`, `name`, `normalized_name`, `package_managers` | | |
| `version`, `version_status`, `version_basis`, `version_reason` | | `RESOLVED` / `UNRESOLVED`; basis OBSERVED or UNKNOWN |
| `constraints` | string[] | as declared |
| `purl` | string | package URL; without a version when unresolved |
| `relationship`, `relationship_basis`, `relationship_reason` | | `DIRECT` / `TRANSITIVE` / `UNKNOWN`; OBSERVED / INFERRED / UNKNOWN; the rule applied |
| `scopes`, `optional` | | runtime, dev, test, build, optional, peer, unknown |
| `integrity` | array | `{algorithm, value}` from lockfiles |
| `source` | object \| null | registry, git, path or URL source when recorded |
| `depth`, `shortest_path_count`, `parents` | | from the graph |
| `evidence`, `evidence_count` | array, int | up to 20 occurrences: `{source_file, line, raw, kind, package_manager, scope, evidence_type, git_blob_sha, …}` |

Indexes: `{snapshot_id: 1, node_id: 1}` unique;
`{project_id: 1, snapshot_id: 1, ecosystem: 1, normalized_name: 1}`.

### `dependency_graphs`

| Field | Type | Notes |
|---|---|---|
| `project_id`, `snapshot_id`, `created_at` | | one graph per snapshot |
| `root` | object | `{id: "root", type: "application", label}` |
| `nodes` | array | dependency records without evidence and integrity |
| `edges` | array | `{source, target, relationship: "depends_on", basis, evidence_file, spec, …}` |
| `stats` | object | totals, direct, transitive, unknown, unresolved, edges, `max_depth`, `by_ecosystem`, `by_relationship_basis`, `by_depth` |

Indexes: `{snapshot_id: 1}` unique; `{project_id: 1, created_at: -1}`.

### `dependency_versions`

Shared across projects: one document per `(ecosystem, package_name, version)`
that any analysis has resolved, with its `purl`, `source` and
`first_seen_at` / `last_seen_at`. Registry facts are added in Phase 5.

Indexes: `{ecosystem: 1, package_name: 1, version: 1}` unique.

### Index changes in Phase 2

`ensure_indexes()` now also drops indexes that are no longer declared, so
databases created by Phase 1 are migrated at start-up:

| Collection | Phase 1 | Phase 2 | Why |
|---|---|---|---|

## Collections declared for later phases

| Collection | Purpose | Key fields (planned) | Indexes | Written from |
|---|---|---|---|---|
| `sboms` | Original and verified SBOM documents (kept separately; originals are never overwritten) | `project_id`, `snapshot_id`, `kind` (`ORIGINAL` \| `VERIFIED`), `format` (`CycloneDX` \| `SPDX`), `content_hash`, `integrity_score` | `{project_id, snapshot_id, kind}`; `{content_hash}` | Phase 4 |
| `sbom_components` | Components of an SBOM | `sbom_id`, `purl`, `name`, `version` | `{sbom_id, purl}` | Phase 4 |
| `sbom_differences` | Missing / extra / mismatched components and repair actions | `project_id`, `snapshot_id`, `difference_type`, `purl`, `repair_action` | `{project_id, snapshot_id, difference_type}` | Phase 4 |
| `vulnerabilities` | Normalised advisory records | `source`, `source_id`, `aliases` (CVE…), `cwe`, `cvss`, `affected[]`, `fixed_versions`, `references`, `published_at`, `modified_at`, `fetched_at` | `{source, source_id}` unique; `{aliases}`; `{affected.ecosystem, affected.package_name}` | Phase 3 |
| `vulnerability_matches` | A vulnerability affecting a dependency of a snapshot | `project_id`, `snapshot_id`, `dependency_id`, `vulnerability_id`, `severity`, evidence | `{snapshot_id, dependency_id, vulnerability_id}` unique; `{project_id, severity}` | Phase 3 |
| `code_reachability` | `REACHABLE` / `NOT_REACHABLE` / `UNKNOWN` per match | `snapshot_id`, `match_id`, `classification`, evidence | `{snapshot_id, match_id}` unique | Phase 3 |
| `attack_paths` | Simulated paths (graph-based, defensive) | `project_id`, `snapshot_id`, `nodes`, `path_risk`, `impact` | `{project_id, snapshot_id, path_risk:-1}` | Phase 7 |
| `maintainers` | Public contributor identity | `platform`, `login` | `{platform, login}` unique | Phase 8 |
| `maintainer_profiles` | Behaviour baseline per repo and maintainer | `repository_id`, `maintainer_id`, baseline statistics | `{repository_id, maintainer_id}` unique | Phase 8 |
| `behaviour_events` | Deviations from baseline | `repository_id`, `project_id`, `occurred_at`, `anomaly_score`, `confidence`, indicators | `{repository_id, occurred_at:-1}`; `{project_id, anomaly_score:-1}` | Phase 8 |
| `commits` | Commit metadata | `repository_id`, `sha`, `author`, `committed_at`, changed files | `{repository_id, sha}` unique; `{repository_id, committed_at:-1}` | Phase 8 |
| `commit_analysis` | Security classification of a commit | `commit_id`, `project_id`, `risk_level`, findings | `{commit_id}` unique; `{project_id, risk_level}` | Phase 9 |
| `security_events` | Real-time events pushed to the UI | `project_id`, `type`, `severity`, `created_at` | `{project_id, created_at:-1}` | Phase 9 |
| `predictions` | Predicted risk with confidence | `project_id`, `snapshot_id`, `subject_type`, `subject_id`, `predicted_risk`, `confidence`, model version | `{project_id, snapshot_id, subject_type, subject_id}` | Phase 5 |
| `trust_scores` | Score history with component scores and weights used | `project_id`, `trust_score`, `risk_score`, `components`, `weights`, `reasons`, `created_at` | `{project_id, created_at:-1}` | Phase 12 |
| `ai_findings` | Evidence-grounded findings | `project_id`, `snapshot_id`, `finding`, `severity`, `confidence`, `evidence` (ids), `reasoning`, `recommendation` | `{project_id, snapshot_id, severity}` | Phase 10 |
| `remediation_actions` | Recommended or applied actions | `project_id`, `action`, `status`, `created_at` | `{project_id, created_at:-1}` | Phase 10 |
| `datasets` | Dataset registry | `name`, `source`, `version`, `hash`, `license`, `language`, `label_schema`, `provenance`, `quality_score`, `duplicate_rate`, `class_distribution`, `validation_status` | `{name, version}` unique; `{owner_id}` | Phase 11 |
| `dataset_records` | Records of a dataset | `dataset_id`, `record_hash`, payload, label | `{dataset_id, record_hash}` | Phase 11 |
| `dataset_quality` | Validation results and trust score | `dataset_id`, checks, indicators, `created_at` | `{dataset_id, created_at:-1}` | Phase 11 |

## Notes

- Repository metadata is public GitHub data and is shared between users who
  register the same repository. Only public repositories are supported; if a
  `GITHUB_TOKEN` with access to private repositories were configured, their
  metadata would become visible to any user who registers them — use a token
  limited to public data.
- Deleting a project removes the project and its analysis data (jobs,
  snapshots, dependencies, graphs). The shared `repositories` and
  `dependency_versions` documents and the audit trail are kept.

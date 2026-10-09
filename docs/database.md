# TrustChain-X — MongoDB Data Model

Database: `trustchain_x` (configurable through `MONGODB_DB`).

All 42 collections are declared, with their indexes, in
`backend/app/models/collections.py`; `ensure_indexes()` creates the indexes at
start-up and is safe to run repeatedly. 41 are written by the platform; one
(`remediation_actions`) is declared and unused.

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
| `evidence`, `evidence_count` | array, int | up to 20 occurrences: `{source_file, line, declaration, file_kind, package_manager, scope, evidence_type, git_blob_sha, …}` |

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
`first_seen_at` / `last_seen_at`. Registry facts live in `package_metadata` (Phase 5).

Indexes: `{ecosystem: 1, package_name: 1, version: 1}` unique.

### Index changes in Phase 2

`ensure_indexes()` now also drops indexes that are no longer declared, so
databases created by Phase 1 are migrated at start-up:

| Collection | Phase 1 | Phase 2 | Why |
|---|---|---|---|

### `vulnerabilities` (Phase 3)

Shared reference data: one normalised advisory per `(source, source_id)`.

| Field | Notes |
|---|---|
| `source`, `source_id`, `source_url` | provider name (`osv`) and the id it publishes (`GHSA-…`, `PYSEC-…`, `CVE-…`) |
| `aliases`, `related` | other ids for the same vulnerability |
| `summary`, `details`, `cwe_ids`, `references` | as published; `null` or empty when absent |
| `severity`, `severity_source` | published label, or the rating of a computed CVSS v3 base score, or `UNKNOWN` |
| `cvss` | `[{type, vector, version, base_score, score_origin}]`; `base_score` is `null` unless computed from a v3 vector |
| `affected` | per package: `ecosystem`, `package_name`, `source_ecosystem`, `source_package_name`, `versions`, `ranges[{type, events}]`, `fixed_versions`, `source_range_note` |
| `published_at`, `modified_at`, `withdrawn_at`, `source_modified` | source timestamps |
| `raw`, `raw_stored`, `raw_sha256` | the record as received (omitted above a size limit) and its SHA-256 |
| `ingested_at`, `first_seen_at`, `last_seen_at`, `normalizer_version` | |

Indexes: `{source: 1, source_id: 1}` unique; `{aliases: 1}`;
`{affected.ecosystem: 1, affected.package_name: 1}`; `{modified_at: -1}`.

### `vulnerability_matches` (Phase 3)

One document per `(snapshot, dependency, advisory)`.

| Field | Notes |
|---|---|
| `project_id`, `repository_id`, `snapshot_id`, `job_id` | |
| `dependency_id`, `dependency_node_id`, `vulnerability_id` | references |
| `source`, `source_id`, `aliases`, `group_key`, `summary` | copied for listing; `group_key` groups aliases of one vulnerability |
| `ecosystem`, `package_name`, `normalized_name`, `matched_version`, `relationship`, `depth` | the observed dependency |
| `match_status` | `AFFECTED` \| `UNSUPPORTED` \| `CONFLICT` |
| `confidence`, `confidence_meaning` | `HIGH` \| `UNDETERMINED` \| `LOW`; describes the version comparison only |
| `classification` | `OBSERVED` or `null` |
| `severity`, `severity_source`, `severity_rank`, `cvss` | from the advisory |
| `affected_range`, `fixed_version`, `fixed_versions` | from the range that decided the match |
| `evidence` | `{evidence_type, source{…}, observed{…, declared_in[]}, match{comparator, range_type, events, introduced, fixed, last_affected, limit, provider_reported, explanation}}` |
| `matched_at`, `first_matched_at`, `matcher_version` | |

Indexes: `{snapshot_id: 1, dependency_node_id: 1, vulnerability_id: 1}`
unique; `{project_id: 1, snapshot_id: 1, match_status: 1, severity_rank: -1}`;
`{vulnerability_id: 1}`.

### `vulnerability_syncs` (Phase 3)

One document per synchronisation run: `provider`, `project_id`, `snapshot_id`,
`job_id`, `status` (`running` \| `completed` \| `partial` \| `failed`),
`started_at`, `completed_at`, `dependencies_total`, `packages_queried`,
`packages_unsupported`, `packages_unresolved`, `provider_requests`,
`records_seen` / `_inserted` / `_updated` / `_unchanged` / `_failed`,
`errors[]` (first 50), `error_summary`, and `reported` (which advisory ids the
provider reported for which package version).

Indexes: `{project_id: 1, started_at: -1}`; `{provider: 1, started_at: -1}`.

### `vulnerability_sources` (Phase 3)

One document per provider: `name`, `display_name`, `base_url`, `ecosystems`,
`normalizer_version`, `last_sync_at`, `last_sync_status`, `last_sync_id`,
`last_health`. Index: `{name: 1}` unique.

### `sboms` (Phase 3)

One document per generated SBOM version. Earlier versions are never modified,
apart from `last_verification`.

| Field | Notes |
|---|---|
| `project_id`, `repository_id`, `snapshot_id`, `commit_sha`, `branch`, `job_id` | |
| `version`, `previous_sbom_id` | 1, 2, … per project |
| `format`, `spec_version`, `media_type`, `serial_number`, `generator`, `generated_at`, `source` | `CycloneDX`, `1.5` |
| `component_count`, `relationship_count`, `unresolved_components`, `components_with_hashes`, `completeness` | |
| `digest_algorithm`, `canonicalization`, `content_digest`, `document_digest`, `document_size` | SHA-256 over canonical JSON |
| `document_zlib` | the canonical document, zlib-compressed; never returned in metadata responses |
| `last_verification` | `{valid, verified_at, failed_checks}` or `null` |

Indexes: `{project_id: 1, snapshot_id: 1, content_digest: 1}` unique;
`{project_id: 1, version: -1}`.

### `sbom_components` (Phase 3)

One row per component of an SBOM, for listing and for linking to
vulnerability matches: `sbom_id`, `project_id`, `snapshot_id`, `bom_ref`
(equal to the dependency `node_id`), `type`, `ecosystem`, `name`,
`normalized_name`, `version`, `purl`, `scope`, `relationship`, `hashes`,
`depends_on`, `component_digest`.

Indexes: `{sbom_id: 1, bom_ref: 1}` unique; `{project_id: 1, purl: 1}`.

### `sbom_differences` (Phase 3)

A stored comparison of two SBOMs of a project: `project_id`, `base_sbom_id`,
`target_sbom_id`, their versions and snapshots, `summary` (added, removed,
changed, unchanged), `items[]` (`change`, `bom_ref`, before/after fields),
`ecosystem_changes`, `document_changes`, relationship changes, `created_at`.

Index: `{project_id: 1, base_sbom_id: 1, target_sbom_id: 1}` unique.

### Other changes in Phase 3

- `projects` gains `latest_vulnerability_scan` (summary of the last matching
  run) and `latest_sbom_id`.
- `analysis_jobs` gains the job types `vulnerability_sync`,
  `vulnerability_analysis` and `sbom_generation`; the document shape is
  unchanged.
- Indexes of `sboms`, `sbom_components`, `sbom_differences`, `vulnerabilities`
  and `vulnerability_matches` differ from the ones declared (never used) in
  Phases 1–2. `ensure_indexes()` drops the obsolete ones at start-up. No
  existing document is changed or removed.

### `reachability_analyses` (Phase 4)

One document per (project, snapshot, analyzer version).

| Field | Notes |
|---|---|
| `project_id`, `repository_id`, `snapshot_id`, `commit_sha`, `branch`, `job_id` | |
| `analyzer_version`, `state` | `RUNNING` until the first run completes, then `COMPLETE` |
| `source_state` | `COMPLETE`, `REBUILDING` (stored source is being replaced; not reused if a run stops here) or `REMOVED` (a newer snapshot was analysed) |
| `source_complete`, `incomplete_reasons` | whether all application source was analysed, and why not |
| `source` | files found / analysed / parsed, by status, test files, other languages |
| `graph` | counts of modules, classes, functions, external names, edges by kind, unresolved uses by reason, and `mapping` (unmapped imports, ambiguous and shadowed dependencies) |
| `findings` | counts by status and reason |
| `operator_mappings`, `operator_mapping_problems`, `vulnerability_scan_matched_at`, `github_requests`, timestamps | |

Indexes: `{project_id: 1, snapshot_id: 1, analyzer_version: 1}` unique;
`{project_id: 1, completed_at: -1}`.

### `source_files` (Phase 4)

One row per candidate source file: `analysis_id`, `project_id`,
`repository_id`, `snapshot_id`, `path`, `language`, `file_size`,
`git_blob_sha`, `is_test`, `analysed`, `parse_status`, `parse_error`,
`module`, `discovered_symbols_count`, `discovered_imports_count`,
`discovered_usages_count`, `records_truncated`, and `imports[]` — each import
statement with line, text, resolution, dependency and resolved version.
File contents are not stored.

Indexes: `{analysis_id: 1, path: 1}` unique; `{project_id: 1, snapshot_id: 1}`.

### `source_symbols` (Phase 4)

Graph nodes: `symbol_id` (`app.client:fetch`, or `ext:requests.get` for a
dependency name), `kind` (`module` \| `class` \| `function` \| `method` \|
`external`), `name`, `qualname`, `module`, `path`, `line`, `end_line`,
`parent`, `is_test`; for external nodes `qualified`, `top_level`, `package`,
`dependency_node_ids`, `mapping_basis`.

Indexes: `{analysis_id: 1, symbol_id: 1}` unique;
`{project_id: 1, snapshot_id: 1, path: 1}`.

### `code_edges` (Phase 4)

Graph edges and unresolved uses: `kind` (`imports` \| `calls` \| `references`
\| `constructs` \| `unresolved`), `source`, `target` (`null` when unresolved),
`confidence`, `basis`, `via`, `hops`, `evidence {source_file, line, col,
end_line, text}`; unresolved rows carry `reason` and `expr`.

Indexes: `{analysis_id: 1, source: 1}`; `{analysis_id: 1, target: 1}`;
`{project_id: 1, snapshot_id: 1}`.

### `code_reachability` (Phase 4)

One finding per vulnerability match of a snapshot.

| Field | Notes |
|---|---|
| `project_id`, `repository_id`, `snapshot_id`, `analysis_id`, `job_id`, `match_id`, `vulnerability_id`, `dependency_id`, `dependency_node_id` | |
| `advisory_source`, `advisory_id`, `aliases`, `summary`, `severity` | copied from the match |
| `ecosystem`, `dependency`, `normalized_name`, `resolved_version`, `relationship` | |
| `status`, `status_rank`, `confidence`, `confidence_meaning`, `reason`, `explanation` | confidence is `null` for `UNKNOWN` and `UNSUPPORTED` |
| `symbol_mapping`, `affected_symbols`, `matched_symbol` | `ADVISORY` \| `OPERATOR_SUPPLIED` \| `SYMBOL_MAPPING_UNKNOWN`, with each symbol's origin |
| `usage_level` | `CALLED` \| `REFERENCED` \| `IMPORTED_ONLY` \| `NOT_OBSERVED` |
| `evidence` | `{source_file, line, symbol, text, path[]}` |
| `observed` | `{dependency_usage, path, usage_path, dynamic_sites}` — what the source shows |
| `inferred` | `{status, reason, notes[]}` — the conclusion and the inferences behind it |
| `analyzed_at`, `analyzer_version` | |

Indexes: `{snapshot_id: 1, match_id: 1}` unique;
`{project_id: 1, snapshot_id: 1, status_rank: -1, severity_rank: -1}`.

### Other changes in Phase 4

- `projects` gains `latest_reachability_analysis_id`.
- `analysis_jobs` gains the job type `code_reachability_analysis`.
- `code_reachability` gains a second index; the existing one is unchanged.
  No existing document is changed.

### Phase 5 collections — dependency intelligence

Field-level detail, indexes and the history rules are in
[phase5.md](phase5.md), section 9.

| Collection | Purpose | Key | Written by |
|---|---|---|---|
| `dependency_analyses` | One document per analysis run: kind, layers, state, model versions, input digest, summary | `{project_id, kind, created_at:-1}`; `{project_id, snapshot_id, layers, created_at:-1}`; `{project_id, kind, input_digest}` | the three Phase 5 jobs |
| `dependency_fragility` | Fragility score, factors and metrics per dependency and analysis | `{analysis_id, node_id}` unique | fragility and full analysis |
| `dependency_health` | Health profile per dependency and analysis | `{analysis_id, node_id}` unique | fragility and full analysis |
| `graph_risk_analysis` | Exposure classification and graph risk per package and analysis | `{analysis_id, node_id}` unique | graph-risk and full analysis |
| `predictive_indicators` | One document per indicator, with its evidence | `{analysis_id, node_id, type}` unique | full analysis |
| `predictions` | Predictive dependency risk per dependency and analysis (declared in Phase 0; two indexes added) | `{analysis_id, node_id}`; `{analysis_id, score:-1}` | full analysis |
| `package_metadata` | Cached registry answers: latest version, release list with dates, withdrawn and deprecated versions | `{ecosystem, normalized_name}` unique | any job that reads a registry |

Rows are never updated in place: a new analysis writes new rows under a new
`analysis_id`. `package_metadata` is shared reference data, like
`vulnerabilities`; it holds public registry facts and no project or user id.

### Other changes in Phase 5

- `analysis_jobs` gains three job types and the state `partial`.
- No existing collection or document is changed.

### Phases 6–13 collections

Rows written by a layer carry `analysis_id` (the `_id` of its run in
`analysis_runs`), `project_id`, `repository_id` and `created_at`; these are
not repeated below. No collection stores an e-mail address or an unmasked
secret-like value.

#### `analysis_runs` (Phases 6–9)

One document per execution of a layer. A run is visible only in state
`COMPLETE`; a run that could not be stored completely is removed with its
rows.

| Field | Notes |
|---|---|
| `kind` | `attack_paths`, `maintainers`, `commits`, `ai` |
| `state` | `RUNNING`, `COMPLETE` |
| `model_version` | for example `attack-path-v1` |
| `snapshot_id`, `commit_sha`, `branch` | for snapshot-bound kinds |
| `inputs`, `input_digest` | what the run read; SHA-256 used to recognise an unchanged input |
| `summary` | counts, distributions, data status, grounding metrics (kind `ai`), rule trace |
| `job_id`, `completed_at` | |

Indexes: `{project_id, kind, created_at:-1}`; `{project_id, kind, input_digest}`.

#### `attack_paths` (Phase 6)

| Field | Notes |
|---|---|
| `attack_path_id` | stable id derived from package and vulnerability |
| `snapshot_id` | |
| `status` | `SUPPORTED_PATH`, `POTENTIAL_PATH`, `UNKNOWN_PATH`, `OBSERVED_COMPONENT` |
| `score`, `level`, `confidence` | score 0–100; `LOW` / `MEDIUM` / `HIGH` |
| `components` | the four terms of the score and the steps that lowered confidence |
| `target`, `advisory`, `reachability` | the package, the matched vulnerability and the reachability state the path is about |
| `nodes`, `edges` | stages with evidence and basis; edge kinds with confidence |
| `evidence` | references to the stored records the path rests on |
| `route`, `alternative_routes`, `routes_truncated` | the shortest dependency chain, other chains, and whether a limit cut the search |
| `downstream`, `related` | dependents of the package; Phase 5 scores attached for context, not mixed into the score |
| `break_points` | `RECOMMENDED` changes |
| `explanation`, `exploit_confirmed` | `exploit_confirmed` is always `false` |
| `model_version` | |

Indexes: `{analysis_id, attack_path_id}` unique; `{analysis_id, score:-1}`;
`{project_id, snapshot_id}`.

#### `maintainer_profiles`, `maintainers` (Phase 7)

`maintainer_profiles` — one repository profile per analysis:
`contributor_count`, `commit_frequency`, `contributor_concentration`,
`release_frequency`, `activity_pattern`, `weekly_activity`,
`inactivity_gaps`, `rapid_clusters`, `change_patterns`,
`anomaly_indicators` (each `OBSERVED` / `NOT_OBSERVED` / `UNKNOWN` with
evidence), `attention_score`, `attention_level`, `confidence`,
`score_detail`, `data_status`, `unavailable`, `evidence`, `meaning`,
`model_version`, `as_of`. Index: `{analysis_id}` unique;
`{project_id, created_at:-1}`.

`maintainers` — one row per contributor per analysis: `maintainer_id`,
`login`, `display_name`, `identified_by`, `account_type`, `commits`, `share`,
`rank`, `first_commit_at`, `last_commit_at`, `active_days`, `recent_commits`,
`recent_share`, `merge_commits`, `verified_commits`, `change_patterns`,
`indicators`, `sample_commits`. Index: `{analysis_id, maintainer_id}` unique;
`{project_id, created_at:-1}`.

#### `commits`, `commit_analysis`, `behaviour_events`, `security_events` (Phase 8)

`commits` — commit metadata shared per repository: `repository_id`, `sha`,
author login and name, times, message summary. Indexes:
`{repository_id, sha}` unique; `{repository_id, committed_at:-1}`.

`commit_analysis` — one document per analysed commit per project:
`commit_sha`, `author_login`, `author_name`, `author_email_tag` (a hash tag,
not the address), `committed_at`, `message`, `parent_count`, `is_merge`,
`stats`, `files`, `coverage` (how much of the diff could be inspected),
`findings` (type, rule, severity, basis, confidence, file, line, masked
excerpt), `indicator_types`, `anomaly_score`, `level`, `confidence`,
`factors`, `baseline`, `meaning`, `model_version`. Indexes:
`{project_id, commit_sha}` unique; `{project_id, committed_at:-1}`;
`{project_id, anomaly_score:-1}`.

`behaviour_events` and `security_events` — append-only events:
`commit_sha`, `repository`, `changed_files`, `event_type`, `severity`,
`confidence`, `evidence`, `observed_or_inferred`, `anomaly_score`, `summary`,
`review_note`, `occurred_at`. `security_events` holds the events of severity
`MEDIUM` or above. Indexes: `{project_id, occurred_at:-1}`;
`{project_id, commit_sha}`.

#### `ai_findings` (Phase 9)

| Field | Notes |
|---|---|
| `finding_id`, `rule_id`, `category`, `severity` | |
| `subject` | what the finding is about (package, commit, project) |
| `statements` | each `{basis, text, evidence_refs}` |
| `evidence_refs`, `evidence` | ids cited, and the evidence items themselves (collection, id, summary, basis, layer) |
| `contributing_layers`, `conditions` | layers cited; which conditions held, did not, or were unknown |
| `confidence`, `confidence_detail` | the three terms |
| `explanation`, `recommendation` | recommendation is `RECOMMENDED` and cites evidence |
| `provider` | audit record: which provider phrased the explanation, whether its output was accepted |
| `model_version`, `snapshot_id` | |

Indexes: `{analysis_id, finding_id}` unique; `{project_id, snapshot_id}`.

#### `datasets`, `dataset_records`, `dataset_quality` (Phase 10)

`datasets` — one document per version: `version`, `snapshot_id`,
`commit_sha`, `schema_version`, `record_count`, `hash_algorithm`,
`canonical_form`, `dataset_hash`, `previous_dataset_id`,
`previous_dataset_hash`, `chain_hash`, `sources` (contributing layers with
references), `changes`, `truncated`, `records_pruned`, `latest_quality`,
`validations`. Indexes: `{project_id, version}` unique;
`{project_id, created_at:-1}`.

`dataset_records` — write-once: `dataset_id`, `record_id`, `identity`,
`features`, `labels`, `provenance`, `record_hash`. Indexes:
`{dataset_id, record_id}` unique; `{dataset_id, record_hash}`.

`dataset_quality` — one document per validation: `dataset_id`,
`dataset_version`, `status`, `quality_score`, `confidence`, `factors`,
`integrity`, `completeness`, `provenance`, `consistency`, `duplicates`,
`balance`, `timestamps`, `chain_intact`, `suspicious_records`, `reasons`,
`warnings`, `limitation`, `model_version`. Indexes:
`{dataset_id, created_at:-1}`; `{project_id, created_at:-1}`.

#### `trust_scores` (Phase 11)

| Field | Notes |
|---|---|
| `snapshot_id`, `commit_sha`, `branch` | |
| `status` | `SCORED` or `INSUFFICIENT_DATA` |
| `trust_score`, `risk_score`, `band` | `null` when `INSUFFICIENT_DATA` |
| `confidence`, `coverage`, `min_coverage` | |
| `risk_low`, `risk_high`, `trust_low`, `trust_high` | bounds left by unknown components |
| `components` | per component: weight, status, risk, confidence, basis, detail, inputs, contribution, layer, reference |
| `component_scores`, `unknown_components`, `known_weight`, `unknown_weight` | |
| `weights`, `weights_statement`, `model_version` | the weights used and the statement that they are not statistically trained |
| `evidence`, `explanation`, `insufficient_reason` | |
| `input_digest` | an unchanged state is not stored twice |

Index: `{project_id, created_at:-1}`.

### Other changes in Phases 6–13

- `projects` gains `commit_monitoring` (`enabled`, `last_checked_at`,
  `last_head_sha`).
- `analysis_jobs.type` gains `attack_path_analysis`, `maintainer_analysis`,
  `commit_behaviour_analysis`, `ai_security_analysis`, `dataset_validation`,
  `trust_analysis`.
- `audit_logs.action` gains the request and outcome of each new job type,
  `commits.monitoring.set` and `report.generate`.
- Reports are generated on request and not stored.

## Declared and unused

| Collection | Purpose | State |
|---|---|---|
| `remediation_actions` | recommended or applied actions as records of their own | Not written. Recommendations are stored inside the finding, path or trust result they belong to |

## Notes

- Repository metadata is public GitHub data and is shared between users who
  register the same repository. Only public repositories are supported; if a
  `GITHUB_TOKEN` with access to private repositories were configured, their
  metadata would become visible to any user who registers them — use a token
  limited to public data.
- Deleting a project removes the project and its analysis data (jobs,
  snapshots, dependencies, graphs, vulnerability matches and synchronisation
  records, SBOMs with their components and diffs, reachability analyses with
  their source records, graph and findings, dependency-intelligence analyses
  with their rows, analysis runs, attack paths, maintainer profiles, commit
  analyses and events, findings, dataset versions with their records and
  validations, and trust scores). The shared `repositories`, `dependency_versions`,
  `vulnerabilities` and `package_metadata` documents and the audit trail are
  kept.

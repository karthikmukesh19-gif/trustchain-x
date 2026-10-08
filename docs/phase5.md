# Phase 5 — Predictive dependency fragility and graph reasoning

> This system estimates dependency fragility and predictive risk indicators.
> It does not guarantee prediction of future vulnerabilities or attacks.

Everything in this phase is deterministic and explainable: each number is a
weighted sum whose terms are stored and shown. There is no trained model.

Words used with a fixed meaning throughout:

| Term | Meaning |
|---|---|
| **observed** | Read from the repository, an advisory source, a package registry or the code analysis |
| **measured** | Computed from the dependency graph by a graph algorithm (counts, depth, centrality) |
| **derived / inferred** | Computed from observed or measured facts by a rule written in this document |
| **predicted** | A model's ranking of which dependencies deserve attention first. Not a forecast of an event |
| **confidence** | The share of a model's inputs that were available. Not a probability that the result is right |

## 1. Objective

Phases 2 to 4 answer "what does the project depend on", "which of those
versions have known vulnerabilities" and "does the code statically reach the
affected functionality". Phase 5 adds three things on top of that evidence:

1. **Fragility** — how much rests on each dependency and how well it is kept
   up, as a score from 0 to 100 with its factors.
2. **Graph risk** — how a known vulnerability in one package relates to every
   package that depends on it, with the dependency path from the project.
3. **Predictive indicators and predictive dependency risk** — named,
   evidence-backed reasons to watch a dependency, and one explainable score
   that orders dependencies for attention.

It does not predict specific vulnerabilities, compromises or attacks, does not
judge maintainers, and does not produce the platform's trust score (Phase 12).

## 2. Architecture

```text
backend/app/analyzers/graph/
  graph_metrics.py      graph model, reachability closures, dominators, concentration
  centrality.py         degree and betweenness centrality
  risk_propagation.py   exposure classification and graph risk        (graph-risk-v1)
  prediction.py         indicators, predictive dependency risk, evidence
                                                (indicators-v1, dependency-risk-v1)
backend/app/analyzers/fragility/
  metrics.py            the seven fragility factors
  version_risk.py       installed version against registry releases (Phase 3 comparators)
  health.py             dependency health profile
  concentration.py      dependency concentration and single-point test
  fragility.py          DependencyFragilityAnalyzer                    (fragility-v1)
backend/app/collectors/registries/
  base.py, pypi.py, npm.py    release metadata from allow-listed registries
backend/app/services/intelligence.py    job pipeline, metadata cache, storage, history, comparison
backend/app/api/intelligence.py         owner-scoped routes
```

The analyzers are pure functions of their inputs: they take the stored graph,
the stored vulnerability matches, the stored reachability findings, registry
metadata and one timestamp, and touch neither the database nor the network.
Phase 2–4 logic is read, not repeated and not modified.

Three job types share one pipeline and run in the existing worker:

```text
dependency_fragility_analysis    GRAPH_METRICS → PACKAGE_METADATA → FRAGILITY
graph_risk_analysis              GRAPH_METRICS → RISK_PROPAGATION
predictive_dependency_analysis   GRAPH_METRICS → PACKAGE_METADATA → FRAGILITY → RISK_PROPAGATION → PREDICTION
```

Job states are `queued`, `running`, `completed`, `partial` and `failed`.
`partial` is new: the analysis finished and its results are stored, but
release metadata could not be collected for some packages. The job's `error`
carries `METADATA_INCOMPLETE` and how many packages are affected. A failed or
crashed run stores nothing.

Graph risk and the full analysis need a vulnerability check of the snapshot;
fragility alone does not. Code reachability is optional for all three.

### Release metadata

Latest version and release dates come from the package registries:

| Ecosystem | Request | What is used |
|---|---|---|
| PyPI | `GET {PYPI_API_URL}/pypi/{name}/json` | `info.version`, and per release the earliest upload time and whether every file is yanked |
| npm, direct dependencies | `GET {NPM_REGISTRY_URL}/{name}` | `dist-tags.latest`, version list, `time`, deprecation flags |
| npm, transitive dependencies | the same with `Accept: application/vnd.npm.install-v1+json` | `dist-tags.latest`, version list. **No release dates**: this form of the answer does not carry them |

When an npm package's full document is larger than the size limit, the
compact form is used instead and its release dates stay unknown.

Other ecosystems (Maven, Go, Cargo, C/C++) have no registry client: their
version and release facts are `UNKNOWN`. npm names are sent exactly as the
repository spells them, because the registry treats older mixed-case names as
separate packages.

Answers are cached in `package_metadata` for `PACKAGE_METADATA_TTL_HOURS`
(24). "No such package" is cached too; a failure is not. When an answer has
expired and cannot be refreshed, the earlier one is used and marked `stale`.
After five consecutive failures a registry is not asked again in that run.
Setting `PACKAGE_METADATA_PROVIDERS` to an empty value makes no registry
request at all.

## 3. Fragility metrics

Measured for every package from the stored dependency graph. The project
itself is the root and is not counted as a package.

| Metric | Definition |
|---|---|
| `depth` | Length of the shortest path from the project (1 = direct). `null` when no path is established |
| `fan_in` | Packages that require it directly |
| `fan_out` | Packages it requires directly |
| `dependents` | Packages that depend on it directly or through others (its ancestors) |
| `dependents_share` | `dependents / (packages − 1)` |
| `introduced` | Packages it brings in, directly or through others (its descendants) |
| `exclusive` | Packages in the project only through it (its dominated set) |
| `reached_by_direct` | Direct dependencies of the project that lead to it, itself included if it is direct |
| `degree_centrality` | `(fan_in + fan_out) / (packages − 1)` |
| `betweenness_centrality` | Brandes' algorithm on the directed graph, normalised by `(n−1)(n−2)`. Skipped (`null`) when `n × (n + edges)` exceeds 20 000 000; degree centrality is used instead and confidence is lowered |
| `relative_centrality` | The package's centrality divided by the highest in this graph |
| `in_cycle` | It can reach itself |
| `single_point` | Not a direct dependency, and at least 3 and at least half of the direct dependencies lead to it |

Graph construction counts a repeated edge once, ignores self-loops and edges
that name unknown packages (and reports how many), and handles cycles through
strongly connected components. Nothing is recursive, so depth is not limited
by the interpreter's stack.

Project-level concentration: the Herfindahl index of the fan-in distribution,
the most depended-on packages, and the largest subtrees of direct
dependencies with their share of all packages.

### Version position

The installed version is compared with the registry's latest using the Phase 3
comparators (PEP 440 for PyPI, SemVer for npm and Cargo, and so on). Nothing
is compared as text.

| `comparison_status` | When |
|---|---|
| `COMPARED` | Both versions parse under the ecosystem's rules |
| `UNSUPPORTED` | The ecosystem has no safe ordering, a version does not parse, a PEP 440 epoch is involved, or a component exceeds 10⁹ |
| `UNKNOWN` | No installed version, no registry metadata, or the registry names no latest version |

When compared: `position` (`UP_TO_DATE`, `BEHIND`, `AHEAD_OF_LATEST`),
`major_distance`, `minor_distance` (within the same major), `patch_distance`
(within the same minor), `releases_behind` (non-pre-release, non-withdrawn
versions above the installed one up to the latest; `null` if the version list
was truncated), `installed_age_days`, `latest_age_days`, `lag_days` (between
the two release dates) and `releases_last_365_days`. Every date-based value is
`null` when the registry gave no date, and when the dates are impossible (a
release dated after the analysis). No date is ever estimated.

### Health profile

Per dependency: installed version, latest release and its date, age of the
installed release, releases in the last year, known vulnerability count
(Phase 3), reachable vulnerability count (Phase 4), direct requirements,
dependents, and `metadata_confidence` (`HIGH` versions and dates, `MEDIUM`
versions only, `LOW` not comparable, `NONE` no metadata). Every field that
could not be collected is `null` and listed under `unknown` with the reason.
`repository_activity` is always `null`: it is not collected in this phase.

`reachable_vulnerability_count` is `0` only when that was established: the
package has no known vulnerability, or every finding was decided and none is
reachable. If any finding is unknown or unsupported, it is `null`.

## 4. Graph model

Model `graph-risk-v1`. Every package gets one classification:

| Classification | Meaning |
|---|---|
| `DIRECT_VULNERABILITY` | An advisory matches this package's own installed version (a Phase 3 `AFFECTED` match) |
| `DEPENDENCY_PROPAGATION` | No advisory matches it; it directly requires a package with a direct vulnerability |
| `INDIRECT_EXPOSURE` | No advisory matches it; a vulnerable package lies further down what it depends on |
| `NO_OBSERVED_PROPAGATION` | None of the above was observed |

Only the first says a package is vulnerable. For `A → B → C → D` with an
advisory on `C`: `C` is `DIRECT_VULNERABILITY`, `B` is
`DEPENDENCY_PROPAGATION`, `A` is `INDIRECT_EXPOSURE`, and `D` is
`NO_OBSERVED_PROPAGATION` — exposure travels from a package to those that
depend on it, never to what it depends on. The project gets the same
classification through its direct dependencies, and one shortest dependency
path to each vulnerable package is stored (at most 50 paths; a path longer
than 12 packages is stored with its middle left out and marked).

A vulnerable dependency is not a reachable vulnerability. Reachability is a
separate input, and "unknown", "unsupported" and "not analysed" are never
treated as "not reachable".

## 5. Predictive model

### Indicators (`indicators-v1`)

An indicator is produced only when its condition holds, and always with the
evidence that satisfied it.

| Indicator | Condition | Severity |
|---|---|---|
| `REACHABLE_VULNERABLE_DEPENDENCY` | Phase 4 found at least one `REACHABLE` finding | HIGH |
| `VULNERABILITY_CLUSTER` | 3 or more distinct known vulnerabilities on the installed version | MEDIUM; HIGH from 5 |
| `SINGLE_POINT_DEPENDENCY` | `single_point` is true | MEDIUM; HIGH when ≥ 75 % of direct dependencies lead to it |
| `HIGH_DOWNSTREAM_IMPACT` | 10 or more dependents | MEDIUM; HIGH from 25 |
| `HIGH_DEPENDENCY_CONCENTRATION` | ≥ 25 % of packages and at least 5 depend on it | MEDIUM; HIGH from 50 % |
| `HIGH_GRAPH_CENTRALITY` | Graph of 10+ packages and relative centrality ≥ 0.5 | MEDIUM; HIGH for the most central |
| `HIGH_TRANSITIVE_DEPTH` | Depth 5 or more | MEDIUM; HIGH from 8 |
| `OUTDATED_DEPENDENCY` | Compared, behind, and a major version or ≥ 365 days of lag | MEDIUM; HIGH from 2 majors or 730 days |
| `RAPID_VERSION_GAP` | ≥ 6 releases since the installed one at a rate of ≥ 12 a year | MEDIUM; HIGH from 24 releases |
| `INSUFFICIENT_METADATA` | The version comparison is not `COMPARED` | LOW |

Each has `type`, `severity`, `confidence`, `evidence[]` and `basis`
(`OBSERVED` or `DERIVED`).

### Predictive dependency risk (`dependency-risk-v1`)

A weighted sum over seven factors (section 6). It is a relative priority for
monitoring and review. It is not a probability, not a prediction of a specific
vulnerability or attack, and not the trust score. Levels on every 0–100 scale
in this phase: `LOW` below 34, `MEDIUM` below 67, `HIGH` from 67.

## 6. Formulas

Every factor has a `weight`, a `value` between 0 and 1, and a `contribution`
of `weight × value`. A score is the sum of its contributions.

A factor has one of three statuses:

- `KNOWN` — measured or observed.
- `UNKNOWN` — the data is not available. `value` is `null`, the contribution
  is 0, and confidence drops by the factor's weight. Nothing is estimated.
- `ASSUMED` — only in the predictive score, only for a package with a known
  vulnerability whose severity is not published or whose reachability is
  undecided. The model then uses a stated neutral value, labels the factor
  `ASSUMED`, and counts half its weight towards confidence. The alternative —
  contributing 0 — would rank an undecided vulnerability below one for which
  no path was found, which would treat "unknown" as "safe". This is a
  modelling choice, not a measurement, and it is shown as such.

### Fragility (`fragility-v1`)

```text
fragility_score = Σ weight × value                       (0–100)
confidence      = Σ weight of KNOWN factors / 100
```

| Factor | Weight | Value |
|---|---|---|
| `downstream_impact` | 25 | `min(1, dependents / max(10, 0.25 × packages))` |
| `fan_in` | 10 | `log2(1 + fan_in) / log2(17)`, capped at 1 |
| `introduced_dependencies` | 10 | `log2(1 + introduced) / log2(65)`, capped at 1 |
| `transitive_depth` | 10 | `(min(depth, 5) − 1) / 4`; unknown without a path |
| `graph_centrality` | 15 | `relative_centrality` |
| `version_lag` | 20 | `max(min(1, major/3), min(0.6, 0.06 × minor) if major = 0, min(1, releases_behind/20))`; unknown unless `COMPARED` |
| `release_staleness` | 10 | `(latest_age_days − 365) / 730`, clamped to 0–1; unknown without a release date |

Fragility describes structure and upkeep. It contains no vulnerability data
and is not a severity.

### Graph risk (`graph-risk-v1`)

For a package with a direct vulnerability:

```text
own_risk = vulnerability_signal × reachability_signal × centrality_signal × downstream_impact × confidence
```

| Component | Value |
|---|---|
| `vulnerability_signal` | Highest published severity: CRITICAL 100, HIGH 80, MEDIUM 55, LOW 30; not published 50 |
| `reachability_signal` | REACHABLE 1.0; UNKNOWN, UNSUPPORTED, NOT_ANALYSED 0.7; NOT_CONFIRMED_REACHABLE 0.4 |
| `centrality_signal` | `0.6 + 0.4 × relative_centrality` |
| `downstream_impact` | `0.6 + 0.4 × min(1, dependents / max(10, 0.25 × packages))` |
| `confidence` | `1.0`, minus `0.10` when the severity is not published, `0.15` when reachability is not decided, `0.10` when betweenness was not computed |

For every package:

```text
propagated_risk = max over vulnerable packages s it depends on:  own_risk(s) × 0.5 ^ distance(package, s)
graph_risk      = max(own_risk, propagated_risk)                                   (0–100)
```

`distance` is the number of dependency steps on the shortest path. The five
strongest sources are stored for each package with their distance and
influence; the count of vulnerable packages it depends on is exact.

### Predictive dependency risk (`dependency-risk-v1`)

```text
predictive_dependency_risk = Σ weight × value                                       (0–100)
confidence = (Σ weight of KNOWN factors + ½ Σ weight of ASSUMED factors
              − 20 × (1 − fragility confidence)) / 100
```

| Factor | Weight | Value |
|---|---|---|
| `vulnerability_exposure` | 30 | Vulnerable package: `vulnerability_signal / 100 × (1 + 0.1 × (min(n, 5) − 1))` for `n` distinct vulnerabilities, capped at 1 (`ASSUMED` when the severity is not published). Otherwise: its strongest `influence / 100`, or 0 |
| `reachability` | 10 | Vulnerable package: REACHABLE 1.0, NOT_CONFIRMED_REACHABLE 0.2, undecided 0.5 (`ASSUMED`). Otherwise 0 |
| `fragility` | 20 | `fragility_score / 100` |
| `downstream_impact` | 15 | as in fragility |
| `graph_centrality` | 10 | `relative_centrality` |
| `dependency_concentration` | 5 | `dependents_share` |
| `version_indicators` | 10 | the `version_lag` value; unknown unless `COMPARED` |

All thresholds and weights are modelling choices stated here; they were not
fitted to data. Changing any of them changes the model version, which is
stored with every result.

## 7. Evidence model

Every dependency's result carries evidence in four groups, and the interface
shows them under these labels:

| Label | Contents |
|---|---|
| `OBSERVED` | Installed version, depth, dependents, requirements, matched advisories, reachability findings, how application modules use it, the registry's latest version |
| `DERIVED` | Fragility factors that weigh on the score, the exposure classification, the indicators |
| `PREDICTED` | The predictive dependency risk with its level, confidence and model version |
| `RECOMMENDED` | Follow-up actions. Nothing is changed automatically |

Factors additionally carry a `basis` (`OBSERVED` or `DERIVED`) and their
inputs. A recommendation to upgrade states how many of the matched advisories
list a fixed version; it does not claim that one upgrade addresses advisories
that publish no fix.

## 8. API

All routes require the project's owner; any other caller gets 404. Start
routes take no parameters and are rate limited.

| Method | Path | Result |
|---|---|---|
| POST | `/api/projects/{id}/fragility/analyze` | 202 `{job}`. 409 without a dependency inventory or while another job is active |
| GET | `/api/projects/{id}/fragility` | `?skip&limit(≤500)&q&ecosystem&level&relationship&sort=fragility\|confidence\|name` → envelope with fragility rows |
| GET | `/api/projects/{id}/fragility/summary` | Score distribution, graph concentration, metadata coverage |
| GET | `/api/projects/{id}/fragility/{dependency_id}` | `{fragility, health}` |
| POST | `/api/projects/{id}/graph-risk/analyze` | 202 `{job}`. Also 409 without a vulnerability check of the snapshot |
| GET | `/api/projects/{id}/graph-risk` | `?skip&limit&q&ecosystem&classification` → envelope with graph-risk rows |
| GET | `/api/projects/{id}/graph-risk/{dependency_id}` | One package's classification, components and exposure sources |
| POST | `/api/projects/{id}/predictive-risk/analyze` | 202 `{job}`. Same preconditions as graph risk |
| GET | `/api/projects/{id}/predictive-risk` | `?skip&limit&q&ecosystem&level&relationship&indicator&vulnerable&reachable&sort=risk\|fragility\|centrality\|dependents\|name` |
| GET | `/api/projects/{id}/predictive-risk/history` | `?kind&limit(≤100)` → stored analyses, newest first |
| GET | `/api/projects/{id}/predictive-risk/compare` | `?base&target` → what changed between two analyses of this project |
| GET | `/api/projects/{id}/predictive-risk/graph` | Packages with their scores and the dependency edges between them, for the risk graph |
| GET | `/api/projects/{id}/predictive-risk/{dependency_id}` | `{prediction, indicators, fragility, health, graph_risk}` |

The list envelope is `{job, snapshot, has_vulnerability_scan, current_inputs,
analysis, total, skip, limit, items}`. `analysis` is the newest completed
analysis of the **latest snapshot** that contains the requested layer, or
`null`; with `null` there are no items, and nothing is reported as zero.
`current_inputs` lets a client see that a vulnerability check or reachability
analysis is newer than the analysis shown. `reachable=false` matches only
dependencies for which "none reachable" was established.

Job error codes: `NOT_ANALYSED`, `NOT_SCANNED`, `PROJECT_NOT_FOUND`,
`GRAPH_TOO_LARGE`, `TIMEOUT`, `INTERNAL_ERROR`; `METADATA_INCOMPLETE` on a
partial job.

## 9. Database schema

Six new collections; `predictions` (declared since Phase 0) is now written.
The database has 41 collections.

| Collection | One document per | Key fields |
|---|---|---|
| `dependency_analyses` | analysis run | `project_id`, `repository_id`, `snapshot_id`, `job_id`, `kind`, `layers[]`, `state`, `commit_sha`, `model_versions`, `input_digest`, `inputs`, `summary`, `created_at`, `completed_at` |
| `dependency_fragility` | dependency per analysis | `fragility_score`, `fragility_level`, `confidence`, `factors[]`, `observed_metrics`, `inferred_metrics`, `unknown_factors[]` |
| `dependency_health` | dependency per analysis | the health profile, `version`, `metadata_source`, `unknown[]` |
| `graph_risk_analysis` | package per analysis | `classification`, `components`, `own_risk`, `propagated_risk`, `graph_risk`, `exposure_sources[]`, `metrics` |
| `predictive_indicators` | indicator per dependency per analysis | `type`, `severity`, `confidence`, `evidence[]`, `basis` |
| `predictions` | dependency per analysis | `score`, `level`, `confidence`, `factors[]`, `evidence`, `indicator_types[]`, `monitoring_rank` |
| `package_metadata` | (ecosystem, package name) | `status`, `detail`, `latest_version`, `releases[]`, `withdrawn_versions`, `deprecated_versions`, `fetched_at` |

Every row of the first six carries `analysis_id`, `project_id`,
`repository_id`, `snapshot_id`, `created_at` and `model_version`.
`package_metadata` holds public registry facts and belongs to no project or
user.

Indexes:

```text
dependency_analyses    {project_id, kind, created_at:-1}
                       {project_id, snapshot_id, layers, created_at:-1}
                       {project_id, kind, input_digest}
dependency_fragility   {analysis_id, node_id} unique; {analysis_id, fragility_score:-1}; {project_id, snapshot_id}
dependency_health      {analysis_id, node_id} unique; {project_id, snapshot_id}
graph_risk_analysis    {analysis_id, node_id} unique; {analysis_id, graph_risk:-1}; {project_id, snapshot_id}
predictive_indicators  {analysis_id, node_id, type} unique; {analysis_id, type}; {project_id, snapshot_id}
predictions            {analysis_id, node_id}; {analysis_id, score:-1}     (added to the index declared earlier)
package_metadata       {ecosystem, normalized_name} unique; {fetched_at:-1}
```

**History.** Each run is stored under a new `analysis_id`; earlier runs are
not overwritten, and any two of a project can be compared. A run whose inputs
are identical to an earlier one — same snapshot, vulnerability check,
reachability analysis, registry answers, model versions and calendar day —
returns that earlier analysis instead of storing a copy. The newest
`INTELLIGENCE_HISTORY_LIMIT` (50) analyses of each kind are kept per project.
Deleting a project deletes its analyses and their rows.

No existing collection or document is changed. Job documents gain the three
job types and the `partial` state.

## 10. Security

| Threat | Control |
|---|---|
| Access to another user's results | Every route resolves the project through its owner. Rows are read by `analysis_id` together with `project_id`; analyses for comparison are looked up within the project. Foreign and malformed ids answer 404 |
| Server-side request forgery | Registry base URLs come from configuration, must be `https`, and their host must be in `PACKAGE_METADATA_ALLOWED_HOSTS`; an invalid value stops the backend from starting. No request parameter can supply a URL: the start routes accept no fields. Redirects are not followed |
| Hostile package names | A name from repository content is validated against the registry's name grammar before any request and sent as one percent-encoded path segment. Names that fail are counted as `INVALID_NAME` and never requested |
| Hostile registry answers | Size cap per answer (16 MiB), JSON only, every field type-checked, version strings and dates bounded, at most 5 000 versions kept (the newest, and always the latest), absurd version numbers not measured |
| Resource exhaustion | Limits on graph nodes (5 000) and edges (50 000), registry lookups per run (2 000), run time (600 s), stored paths and listed sources. Graph algorithms are iterative; reachability sets are bit masks; betweenness is skipped above a work bound. A failing registry stops being asked |
| Code execution | None of this phase reads repository source. No repository code is executed, imported or installed, and no shell command is run |
| Database queries | Filters are fixed fields with validated values; search text is escaped before use in a pattern; ids are parsed as ObjectIds |
| Information sent to third parties | Only public package names, to the registries. No credential, token or repository content is sent |
| Misleading results | Unknown values are `null` with a reason, never zero. A missing analysis is "not available", never "low risk". Scores are named for what they are and carry their model version |
| Abuse | Job starts are rate limited and audited (`job.<type>.request`, `job.<type>.finish` with outcome `success`, `partial` or `failure`); one job per project at a time |

## 11. Limitations

This system estimates dependency fragility and predictive risk indicators. It
does not guarantee prediction of future vulnerabilities or attacks.

- **The models are not validated.** Weights and thresholds are stated choices,
  not fitted to data. No experiment has shown that a higher score precedes
  more incidents. Scores order dependencies within a project; they are not
  comparable between projects and are not probabilities.
- **A low score is not a statement of safety**, and "none observed" means only
  that Phases 3 and 4 observed nothing.
- **Unpublished severity and undecided reachability use a neutral value** in
  the predictive score (labelled `ASSUMED`). This affects ranking; see section 6.
- **Registry coverage is PyPI and npm only.** Other ecosystems have no latest
  version or release dates. Transitive npm packages have versions but no
  dates, so their release-age factors are unknown.
- **"Latest" is what the registry says.** A package's latest may be a
  different major line that a project cannot adopt; distance is still measured.
- **No maintainer or repository-activity data** is collected (commit
  frequency, contributors, bus factor). `repository_activity` is always
  unknown. Nothing here judges a maintainer.
- **The graph is the one Phase 2 built.** Missing lockfiles mean missing
  transitive packages; metrics describe the observed graph, not the full one.
  Two npm packages that differ only in letter case are one node in Phase 2.
- **Centrality** is betweenness on shortest dependency chains; on very large
  graphs it falls back to degree centrality.
- **Version distances** are numeric differences of components. They do not
  account for ecosystem conventions such as calendar versioning.
- **Identical-input reuse is per calendar day**, because ages are measured in
  days against the time of the analysis.
- **Private registries** are supported only by replacing the registry URL and
  allow-listing its host; no credentials are sent.
- Not run against a live registry or a real MongoDB server in development; see
  the README's verification status.

## 12. Research contribution

Framed as two ideas, both modest and both testable.

**Predictive Dependency Fragility.** A per-dependency measure that combines
*where a package sits* in a project's dependency graph (dependents, depth,
centrality, what it brings in) with *how it is kept up* (version lag, release
staleness), with explicit handling of missing data: an unknown input lowers
confidence instead of being imputed.

**Predictive Graph Reasoning.** Placing observed vulnerabilities on the
dependency graph and reasoning along its edges: classifying every package by
its relationship to a vulnerable one, attenuating influence with distance,
and weighting by what is known about reachability — while keeping "vulnerable
dependency", "reachable vulnerability" and "exposed dependent" as three
separate statements.

The contribution is the **correlation of evidence layers** that are usually
reported separately: dependency structure, dependency health, vulnerability
exposure, code reachability, graph topology and downstream impact, into one
explainable ranking in which every term can be traced to its source.

What is not claimed: that the ranking predicts future vulnerabilities,
compromises or attacks; that the weights are optimal; or that the approach
outperforms existing tools. Establishing any of these needs an evaluation
that has not been done — for example, computing scores on historical
snapshots and testing whether higher-ranked dependencies were more often the
subject of later advisories, against baselines such as "most dependents" or
"oldest release". Until then the scores are a transparent prioritisation
heuristic.

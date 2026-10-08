# Repository and Dependency Analysis (Phase 2)

This layer turns a registered GitHub repository into an evidence-backed
dependency inventory and dependency graph. It produces **no** vulnerability
findings, risk figures or trust score; those belong to later phases.

## Pipeline

```text
POST /api/projects/{id}/analysis/dependencies
  → analysis_jobs document (queued)  → Redis wake-up
  → worker claims the job (running)
      REPOSITORY_SNAPSHOT    metadata, head commit, file listing
      REPOSITORY_DISCOVERY   languages, package managers, dependency files
      DEPENDENCY_DISCOVERY   read and parse each dependency file
      GRAPH_BUILDING         resolve, classify, build the graph, store
  → completed | failed (with an error code and message)
```

MongoDB holds the job state; Redis only wakes the worker, and the worker also
polls MongoDB, so a lost queue message delays a job but cannot lose it. One
job per project may be queued or running. A job left `running` by a worker
that died is failed after `ANALYSIS_STALE_JOB_SECONDS` so it can be re-run.

## Repository snapshot

Collection uses the GitHub REST API only — `repos`, `commits/{branch}`,
`git/trees/{sha}?recursive=1`, `git/blobs/{sha}`. Nothing is cloned, written
to disk or executed. A typical analysis costs 3 requests plus one per
dependency file.

A snapshot records the repository URL, branch, commit SHA, tree SHA, commit
time, collection time, every discovered file with its size and git blob id,
detected languages and package managers, the status of each dependency file,
and a summary. Each fetched file is hashed and compared with the git blob id
GitHub listed for it; a mismatch stops the analysis (`INTEGRITY_MISMATCH`).
The file's SHA-256 is stored as well.

Snapshots are immutable. Re-running an analysis when the head commit has not
changed reuses the existing snapshot (two API requests); a new commit produces
a new snapshot, and earlier ones are kept.

## Language detection

From the snapshot's file listing (paths and sizes), not from GitHub's
"primary language", which is stored separately for comparison. Vendored and
generated directories (`node_modules`, `vendor`, `dist`, `build`, `target`,
`venv`, …) are ignored.

Recognised: Python, JavaScript, TypeScript, Java, Go, Rust, C, C++, and also
PHP, Ruby, Kotlin, C#, Swift, Scala, Shell. Each language carries its file
count, bytes, share of source bytes, up to five evidence files, and a
confidence label defined by a fixed rule (not a probability):

| Confidence | Rule |
|---|---|
| HIGH | at least 3 source files, or source files plus a dependency file of the matching ecosystem |
| MEDIUM | 1–2 source files and no matching dependency file |
| LOW | only `.h` headers, whose language is ambiguous |

`.h` headers count as C++ when the repository has C++ sources and no C
sources, otherwise as C; that attribution is labelled INFERRED.

## Dependency files

| Ecosystem | Parsed | Recognised, not parsed |
|---|---|---|
| Python (pypi) | `requirements*.txt` / `.in`, `requirements/*.txt`, `pyproject.toml` (PEP 621, Poetry, dependency groups, build requirements), `setup.cfg`, `Pipfile`, `Pipfile.lock`, `poetry.lock` | `setup.py` (executable — never run), `uv.lock`, `pdm.lock` |
| JavaScript / TypeScript (npm) | `package.json`, `package-lock.json` (v1–v3), `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry), `pnpm-lock.yaml` | `bun.lock`, `bun.lockb` |
| Java (maven) | `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile` | `build.sbt` |
| Go (golang) | `go.mod`, `go.sum` | |
| Rust (cargo) | `Cargo.toml`, `Cargo.lock` | |
| C / C++ | `vcpkg.json`, `conanfile.txt`, `CMakeLists.txt` | `conanfile.py` (executable — never run) |
| Other | | Bundler, Composer, NuGet, SwiftPM, pub, Mix |

Every dependency file gets a status: `PARSED`, `ERROR` (malformed; the reason
is stored and the analysis continues with the other files), `NOT_EVALUATED`
(an executable build script that is deliberately not run), `UNSUPPORTED`, or
`SKIPPED` (over a size or count limit). Gradle and CMake files are code; they
are pattern-matched, never evaluated, and what is extracted from them is
labelled INFERRED.

## What is recorded per dependency

`name`, `normalized_name`, `ecosystem`, `package_managers`, `version`,
`version_status` (`RESOLVED` / `UNRESOLVED`), `constraints` as declared,
`purl`, `relationship` (`DIRECT` / `TRANSITIVE` / `UNKNOWN`), `scopes`
(runtime, dev, test, build, optional, peer, …), `optional`, `integrity`
hashes from lockfiles, `source` (registry, git, path, URL), `depth`,
`parents`, and `evidence`: each occurrence in a repository file with the file
path, line number where it can be located, the raw declaration, the file's
git blob id and the evidence type.

### Name normalisation

| Ecosystem | Rule |
|---|---|
| pypi | PEP 503: lower-case; runs of `-`, `_`, `.` become `-` |
| npm | lower-case, scope kept |
| cargo | lower-case; `_` and `-` equivalent |
| maven | `group:artifact`, case preserved |
| golang | module path, case preserved |
| vcpkg, conan, cmake | lower-case |

## OBSERVED, INFERRED, UNKNOWN

Every classification carries a basis and a sentence stating the rule applied.

**Version**

- Locked in a lockfile → `RESOLVED`, OBSERVED.
- Exact pin in a manifest (`==1.2.3`, `1.2.3` in npm) → `RESOLVED`, OBSERVED.
- Only a range, and no lockfile resolves it → `UNRESOLVED`. The constraint is
  kept; no version is guessed.

**Direct or transitive**

| Evidence | Result |
|---|---|
| Declared in a manifest, or listed as a root by the lockfile | DIRECT, OBSERVED |
| Listed in a `requirements` file without `pip-compile` annotations | DIRECT, INFERRED — such files can also hold transitive pins (`pip freeze`) |
| `pip-compile` `# via` annotations | DIRECT or TRANSITIVE, OBSERVED, with parent edges |
| Reachable only through edges recorded in a lockfile | TRANSITIVE, OBSERVED |
| Marked `// indirect` in `go.mod` | TRANSITIVE, OBSERVED (parent not recorded by the file) |
| In a lockfile that records no edges, and absent from the reliable manifest beside it (`Pipfile.lock`, `gradle.lockfile`) | TRANSITIVE, INFERRED |
| Anything else (for example a lockfile with no manifest) | UNKNOWN |

A dependency is never labelled transitive unless a file establishes it or one
of the stated rules applies.

## Dependency graph

One `application` root plus one node per package version. Edges are
`depends_on`, each with its basis and the file that records it. Edges exist
only where a file records the relationship; packages whose parent is not
recorded appear without an incoming edge and with `depth: null`.

Per node: `depth` (shortest path from the project; 1 = direct),
`shortest_path_count`, `parents`. Graph statistics: totals, direct,
transitive, unknown, unresolved versions, edges, maximum depth, counts by
ecosystem, by basis and by depth. `GET …/dependencies/paths?to=<node>`
returns up to 20 paths from the project to a package, shortest first.

## Limits

| Setting | Default | Effect when exceeded |
|---|---|---|
| `ANALYSIS_MAX_REPO_KB` | 2 GiB | `REPOSITORY_TOO_LARGE` |
| `ANALYSIS_MAX_FILES` | 25,000 | `TOO_MANY_FILES` (also when GitHub truncates the listing) |
| `ANALYSIS_MAX_MANIFESTS` | 300 | further dependency files are `SKIPPED` and reported |
| `ANALYSIS_MAX_MANIFEST_BYTES` | 8 MiB | that file is `SKIPPED` |
| `ANALYSIS_MAX_TOTAL_BYTES` | 64 MiB | further files are `SKIPPED` |
| `ANALYSIS_MAX_DEPENDENCIES` | 30,000 | `TOO_MANY_DEPENDENCIES` |
| `ANALYSIS_TIMEOUT_SECONDS` | 300 | `TIMEOUT` |

Other error codes: `RATE_LIMITED` (with the reset time), `NOT_FOUND`, `MOVED`,
`EMPTY_REPOSITORY`, `NO_DEFAULT_BRANCH`, `BAD_TOKEN`, `DENIED`, `UNREACHABLE`,
`BAD_RESPONSE`, `RESPONSE_TOO_LARGE`, `INTEGRITY_MISMATCH`,
`WORKER_INTERRUPTED`, `INTERNAL_ERROR`. A failed job stores nothing but the
job record.

## Known limitations

- **No registry lookups.** Versions come only from repository files. A range
  without a lockfile stays UNRESOLVED, and transitive dependencies are known
  only when a lockfile records them.
- **Build scripts are not evaluated.** `setup.py` and `conanfile.py` are
  reported, not parsed. Gradle and CMake extraction is pattern-based and can
  miss dependencies declared through variables, plugins or version catalogs.
- **Maven** versions inherited from a parent POM or an imported BOM that is
  not in the repository stay UNRESOLVED.
- **Go**: `go.mod` records which modules are indirect, not which module
  requires them, so those nodes have no parent edge.
- **Default branch only**, at its head commit. Private repositories need a
  token and are not otherwise supported.
- **Unauthenticated GitHub access is limited to 60 requests an hour.** Set
  `GITHUB_TOKEN` for regular use.
- Language detection is by file extension and size.
- `dependency_versions` catalogues each resolved version seen (PURL, first and
  last seen); registry facts (publish dates, maintainers) are added in Phase 5.

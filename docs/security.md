# Security

Controls that exist in the code today. The audit that produced the Phase 13
changes, with its findings, is in [phase13.md](phase13.md).

## Platform

| Control | Detail |
|---|---|
| Passwords | scrypt (N=2¹⁵, r=8, p=1), random per-user salt, constant-time comparison; 10–128 characters with a letter and a digit |
| Sessions | JWT access tokens (HS256, 60 minutes by default). Production refuses to start without a secret of at least 32 characters |
| Login | Identical response and work for unknown accounts and wrong passwords; rate limited per client address |
| Authorisation | Every query for project data, in every layer, is scoped to the owning user. Another user's project answers 404. A test walks every route in the OpenAPI document and checks that it requires authentication (except health, register and login) and does not reveal another user's project |
| Input | Strict Pydantic models, unknown fields rejected, 1 MiB body cap, validation errors never echo the submitted value |
| Transport hardening | CORS allow-list, security headers, API docs disabled in production |
| Audit log | Registration, sign-in, project changes, every analysis request and its outcome, SBOM verifications, provider health checks, commit-monitoring changes, report generation. No token or secret-like value is written to it |
| Job rate limit | Starting any analysis job, and provider health checks, are limited per client address (default 30 per minute) |
| Containers | Non-root users, `no-new-privileges`, all capabilities dropped and read-only root filesystem for the API and worker, databases not published to the host, API and application bound to `127.0.0.1` |
| Errors | An unexpected error returns a generic message; no stack trace, file path or query is sent to the client |
| Build | The frontend image installs from a committed lockfile with `npm ci`, which verifies integrity hashes; every package resolves from `registry.npmjs.org` |

## Repository analysis

Every repository is untrusted input.

| Threat | Control |
|---|---|
| Code execution | The repository is never cloned, installed, built or run. Files are fetched as data through the GitHub API and parsed as text. `setup.py`, `conanfile.py`, Gradle and CMake files are never evaluated; no package manager is invoked; no shell command is built from repository content |
| SSRF | Only `https://github.com/<owner>/<repo>` is accepted at registration. Every outbound request goes to the configured GitHub API host (which must be listed in `GITHUB_ALLOWED_HOSTS` and be a public host name), with a path built from the validated owner and name or from ids checked to be 40-character hex. Redirects are not followed. URLs found inside repository files are stored as text and never fetched |
| Path traversal | Nothing is written to disk. Paths from the file listing are still validated: absolute paths, `..` segments, backslashes, control characters and over-long paths are rejected and counted. `-r` includes in requirements files are resolved only inside the repository listing |
| Resource exhaustion | Limits on repository size, file count, dependency-file count and size, total bytes, dependency count and run time; capped response sizes; request timeouts; bounded retries |
| Tampered content | Each file's content is checked against its git blob id; a mismatch fails the analysis |
| Malicious XML / YAML / JSON | `defusedxml` for `pom.xml` (no entities, no external DTDs), `yaml.safe_load`, size caps before parsing |
| Hostile strings | Names, versions and raw declarations are length-limited and stripped of control characters before storage; invalid Unicode is replaced. The UI renders them as text |
| Query injection | Search text is escaped before use in a regular expression; ids are validated as ObjectIds; filters are whitelisted |
| GitHub rate limits | Detected from status and headers; the job fails with `RATE_LIMITED` and the reset time rather than waiting or retrying in a loop |
| Token exposure | `GITHUB_TOKEN` is sent only to the configured, allow-listed API host, never logged, and absent from settings output. The placeholder from the example file is treated as no token |

## Vulnerability intelligence and SBOM (Phase 3)

| Threat | Control |
|---|---|
| SSRF through the provider | The provider base URL is read from configuration at start-up and validated: `https` only, default port, no credentials, query or fragment, host in `VULNERABILITY_ALLOWED_HOSTS`. An invalid value stops the application from starting. No API request, repository file or advisory record can supply a URL that is fetched. Redirects are not followed. Reference URLs inside advisories are stored and displayed as text links, never fetched by the server |
| Injection into provider requests | Package names and versions are sent as JSON values. Advisory ids are checked against a strict pattern before being placed in a URL path |
| Hostile or oversized provider responses | Size caps per response and per record, a cap on advisories per sync, a cap on result pages, request and whole-sync timeouts, bounded retries. Records are treated as data: fields are type-checked, length-limited and stripped of control characters; a malformed record is counted as a failure |
| Provider outage or rate limiting | Detected and reported with a specific code. A sync that did not store every reported advisory is never recorded as completed |
| Misleading results | Severity and CVSS are shown as published; nothing is invented. A match states that it concerns version numbers only. Undecidable comparisons are `UNSUPPORTED`, never affected. An empty result is worded as "no published advisory matched", not as safe |
| SBOM tampering | Detected by digest and regeneration checks (see phase3.md). The SBOM is integrity-verifiable, not signed: digests live in the same database as the document |
| Hostile content in SBOM output | Component data comes from the validated Phase 2 inventory. The download is served as an attachment with `nosniff` |
| Secrets | No provider credential exists for OSV. Raw advisory records are stored; request headers and tokens are never logged |

## Code reachability (Phase 4)

| Threat | Control |
|---|---|
| Code execution | Source files are parsed with Python's `ast` module into a syntax tree. They are never compiled to run, imported, evaluated, installed or built. `setup.py`, `conftest.py` and package `__init__.py` files are read like any other file. No shell command is built from repository content |
| Path traversal | Files are fetched by git blob id (validated hex) from the snapshot's listing; nothing is read from or written to disk by path. Paths were validated when the snapshot was taken and are validated again when selecting source; they are used only as labels |
| Tampered content | Each file is checked against its git blob id; a mismatch fails the job |
| Resource exhaustion | Limits on source files, bytes per file, total bytes, syntax nodes per file, records per file, attribute-chain length, module-lookup steps, graph edges, stored evidence text and run time. Star-import chains are resolved once and cycles end. Deeply nested, huge, binary or wrongly encoded input yields a parse status, not a crash |
| Hostile strings | Names and source lines are length-limited before storage and rendered as text. Links to the repository are built from the registered repository URL and an encoded path |
| Operator mapping file | A local file path from configuration, never a URL; size-capped; every entry validated (advisory id, dotted symbol names, `https` source URL); invalid entries ignored and reported |
| Misleading results | Four explicit statuses; none means "safe" or "exploitable". A missing path becomes `UNKNOWN` whenever source was not fully analysed, dynamic code could reach the package, or the import cannot be attributed. Only an exact match of a published affected name is `REACHABLE` |
| Authorisation | Findings, paths and source inventories are scoped to the owning project; another user's ids answer 404 |
| Abuse of GitHub quota | Job starts are rate limited; parsed source is reused for a snapshot, so re-runs make no GitHub requests |

## Dependency intelligence (Phase 5)

| Threat | Control |
|---|---|
| Server-side request forgery | The registry URLs are configuration, `https` only, on hosts listed in `PACKAGE_METADATA_ALLOWED_HOSTS`; an invalid value stops start-up. Requests cannot name a URL (the start routes accept no fields). Redirects are not followed |
| Hostile package names | Names come from repository content. Each is validated against the registry's name grammar and sent as one percent-encoded path segment; anything else is counted as invalid and never requested |
| Hostile registry answers | Size cap, JSON only, every field type-checked and bounded; at most 5,000 versions kept; version numbers too large to be real are not measured. The cache is keyed by ecosystem and name, so one project's dependencies cannot change what another project is told about a different package |
| Resource exhaustion | Limits on graph nodes and edges, registry lookups per run, run time, stored paths and listed sources. Iterative graph algorithms; a failing registry stops being asked after five consecutive failures |
| Code execution | This phase reads no repository source and runs nothing from it |
| Authorisation | Every route is scoped to the owning project; rows are read by analysis and project together; foreign and malformed ids answer 404 |
| Data sent to third parties | Public package names only, to PyPI and npm. No token or repository content. Can be switched off with an empty `PACKAGE_METADATA_PROVIDERS` |
| Misleading results | Unknown is `null` with a reason, never zero; a missing analysis is "not available"; an undecided reachability is never counted as "not reachable"; scores carry their model version and the statement that they are not probabilities |

## Outbound requests (all phases)

The platform contacts four services and nothing else.

| Rule | Applies to |
|---|---|
| The base URL is configuration, validated at start-up; an invalid value stops the application | GitHub, OSV, PyPI, npm |
| `https` only, default port, no credentials, no query or fragment | all |
| The host must be on the service's allow-list (`GITHUB_ALLOWED_HOSTS`, `VULNERABILITY_ALLOWED_HOSTS`, `PACKAGE_METADATA_ALLOWED_HOSTS`) | all |
| The host must be a public name: IP literals in any notation, single-label names, `localhost` and reserved internal suffixes are refused **even when listed** | all |
| Redirects are never followed | all |
| Paths are built from validated identifiers; no request field, repository file, advisory, commit or diff can supply a URL that is fetched | all |

A test runs the complete pipeline and asserts that every request went to one
of the four expected hosts over `https`. The host check is on the name; names
are not resolved, so a public name that resolves to a private address is not
detected (see *Known gaps*).

## Attack paths (Phase 6)

| Threat | Control |
|---|---|
| Active exploitation | None is possible: the simulation reads stored evidence only. It contacts nothing, runs nothing and generates no exploit input |
| Misleading results | Four statuses, none meaning "exploitable"; `exploit_confirmed` is always `false`; unknown reachability gives `UNKNOWN_PATH`, never a cleared path; the score is stated not to be a probability |
| Resource exhaustion | Iterative breadth-first and depth-first search with cycle protection and limits on depth, paths, alternatives, expansions and graph-view nodes; truncation is recorded |
| Authorisation | Paths are read by analysis and project together; malformed and foreign ids answer 404 |

## Maintainer behaviour (Phase 7)

| Threat | Control |
|---|---|
| Harm to individuals | No output classifies a person. Indicators describe the repository's pattern, carry a statement that they are not evidence of intent, and tests reject wording that judges a person |
| Personal data | Only public GitHub metadata. E-mail addresses are never stored or returned; an author without a login is grouped by a truncated hash |
| Fabricated history | When GitHub data cannot be collected the indicators that need it are `UNKNOWN` and the job is `partial`; nothing is estimated |
| GitHub quota | Bounded pages and commits; rate limiting reported with its reset time, never retried in a loop |

## Commit behaviour (Phase 8)

| Threat | Control |
|---|---|
| Code execution | A commit is never checked out, built, imported or run. The diff is split into lines and matched against patterns |
| The platform becoming a store of leaked credentials | Every excerpt is masked before storage: a secret-like value is replaced by its first characters and its length. Tests analyse commits containing synthetic credentials and scan the database, the audit log and every API response for them |
| Hostile diffs | Limits on commits per run, files per commit, bytes per file, lines and line length, findings per rule and per commit. Patterns are bounded and applied per line |
| Hostile paths | Paths from the commit are validated like paths from the file listing; rejected paths are counted |
| Misleading results | An anomaly is stated to be a departure from the usual pattern, not a verdict; a factor without enough history is `UNKNOWN`; a file whose content GitHub did not provide is recorded as not inspected |
| Unattended polling | Off by default; bounded projects per tick; one job per project at a time |

## Cross-layer reasoning (Phase 9)

| Threat | Control |
|---|---|
| Invented evidence | A finding is stored only if every statement cites evidence items that exist in the run's evidence store, which is built from stored records |
| Presenting inference as fact | Statements are labelled; an `OBSERVED` statement that rests on non-observed evidence is refused |
| Data leaving the platform | None: the only provider is deterministic and local. `AI_PROVIDER` accepts no other value |
| Untrusted provider output (for a future provider) | A guard refuses text with an uncited sentence, a citation outside the finding, an over-claim, or excessive length. It does not yet verify sentence content against the cited evidence; that is required before a model provider is enabled |
| Prompt injection through repository content (for a future provider) | The prompt would contain only the finding's statements and evidence summaries produced by the platform's own analyzers, never raw repository text |

## Dataset (Phase 10)

| Threat | Control |
|---|---|
| Silent alteration of stored results | SHA-256 record, dataset and chain hashes over a canonical form; validation reads records back from storage; `GET` recomputes the hashes at request time |
| Rewriting history | Versions are write-once and chained; an altered or removed earlier version is detectable from a later one |
| Over-trust | Every status carries the statement that the checks cannot establish freedom from deliberate manipulation. Hashes are not signatures |
| Resource exhaustion | Record cap; batched writes; older versions' records pruned while their hashes are kept |

## Trust engine, overview and report (Phases 11–12)

| Threat | Control |
|---|---|
| A reassuring score from missing evidence | Unknown components have no risk value; coverage and bounds are always shown; below the coverage minimum the result is `INSUFFICIENT_DATA` with no score |
| Opaque scoring | Weights, component risks, confidences, contributions and formulas are returned and stored with every result, together with the statement that the weights are not statistically trained |
| Unsupported statements in a report | The report is served only when every statement and table row cites evidence in its index; otherwise the endpoint fails |
| Stale results presented as current | A score of an earlier snapshot is history; the current view states whether the layers changed since it was calculated |
| Injection through report content | Markdown is served as an attachment with `nosniff`; the interface renders all values as text |

## Known gaps

- Rate-limit counters are per backend process; counters in Redis are not built.
- No token revocation list; tokens are short-lived.
- The browser stores the token in `sessionStorage`; a strict CSP limits the XSS exposure.
- SBOMs, datasets and reports are integrity-verifiable, not cryptographically signed: digests live in the same database as the data.
- Host allow-lists check names, not resolved addresses. A DNS answer that maps a public name to a private address is not detected. Redirects are refused, which removes the common route to that, but not DNS rebinding.
- Python dependencies are pinned to major-version ranges without a hash lock; container base images are pinned by tag, not by digest.
- Git authorship is taken as recorded; commit signatures are not verified.
- Commit rules are textual and can be evaded by obfuscation; they also flag ordinary code. Their precision and recall are not measured.
- No component has been measured against a labelled benchmark (see research-validation.md).
- Registry and advisory answers are trusted as published over TLS; they are not cross-checked against a second source.
- One vulnerability source; no scheduled refresh of advisory data.
- Repository metadata and analysis use one platform-wide `GITHUB_TOKEN`. Use
  a token restricted to public repositories, otherwise private repository
  data would be readable by any user who registers that repository.
- The Phase 5 to 13 code has not been run in Docker or against the live
  external services by its developer (see phase13.md).

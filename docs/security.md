# Security

Controls that exist in the code today. Planned controls are listed in
`architecture.md`.

## Platform

| Control | Detail |
|---|---|
| Passwords | scrypt (N=2¹⁵, r=8, p=1), random per-user salt, constant-time comparison; 10–128 characters with a letter and a digit |
| Sessions | JWT access tokens (HS256, 60 minutes by default). Production refuses to start without a secret of at least 32 characters |
| Login | Identical response and work for unknown accounts and wrong passwords; rate limited per client address |
| Authorisation | Every project, snapshot, dependency, graph, job, vulnerability-match and SBOM query is scoped to the owning user. Another user's project answers 404. There is no unauthenticated endpoint that returns project security data |
| Input | Strict Pydantic models, unknown fields rejected, 1 MiB body cap, validation errors never echo the submitted value |
| Transport hardening | CORS allow-list, security headers, API docs disabled in production |
| Audit log | Registration, sign-in, project changes, analysis requests and their outcomes, vulnerability and SBOM job requests, SBOM verifications, provider health checks |
| Job rate limit | Starting a vulnerability or SBOM job, and provider health checks, are limited per client address (default 30 per minute) |
| Containers | Non-root users, `no-new-privileges`, all capabilities dropped and read-only root filesystem for the API and worker, databases not published to the host |

## Repository analysis

Every repository is untrusted input.

| Threat | Control |
|---|---|
| Code execution | The repository is never cloned, installed, built or run. Files are fetched as data through the GitHub API and parsed as text. `setup.py`, `conanfile.py`, Gradle and CMake files are never evaluated; no package manager is invoked; no shell command is built from repository content |
| SSRF | Only `https://github.com/<owner>/<repo>` is accepted at registration. Every outbound request goes to the configured GitHub API host, with a path built from the validated owner and name or from ids checked to be 40-character hex. Redirects are not followed. URLs found inside repository files are stored as text and never fetched |
| Path traversal | Nothing is written to disk. Paths from the file listing are still validated: absolute paths, `..` segments, backslashes, control characters and over-long paths are rejected and counted. `-r` includes in requirements files are resolved only inside the repository listing |
| Resource exhaustion | Limits on repository size, file count, dependency-file count and size, total bytes, dependency count and run time; capped response sizes; request timeouts; bounded retries |
| Tampered content | Each file's content is checked against its git blob id; a mismatch fails the analysis |
| Malicious XML / YAML / JSON | `defusedxml` for `pom.xml` (no entities, no external DTDs), `yaml.safe_load`, size caps before parsing |
| Hostile strings | Names, versions and raw declarations are length-limited and stripped of control characters before storage; invalid Unicode is replaced. The UI renders them as text |
| Query injection | Search text is escaped before use in a regular expression; ids are validated as ObjectIds; filters are whitelisted |
| GitHub rate limits | Detected from status and headers; the job fails with `RATE_LIMITED` and the reset time rather than waiting or retrying in a loop |
| Token exposure | `GITHUB_TOKEN` is sent only to the configured API host, never logged, and absent from settings output |

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

## Known gaps

- Rate-limit counters are per backend process (Redis-backed counters: Phase 14).
- SBOMs are not cryptographically signed.
- The reachability analysis has not been measured against a labelled benchmark; see its limitations in phase4.md.
- The fragility and predictive risk models are stated heuristics; they have not been evaluated against historical incidents (phase5.md, section 11).
- Registry answers are trusted as published over TLS; they are not cross-checked against a second source.
- One vulnerability source; no scheduled refresh of advisory data.
- No token revocation list; tokens are short-lived.
- The browser stores the token in `sessionStorage`; a strict CSP limits the XSS exposure.
- Repository metadata and analysis use one platform-wide `GITHUB_TOKEN`. Use
  a token restricted to public repositories, otherwise private repository
  data would be readable by any user who registers that repository.
